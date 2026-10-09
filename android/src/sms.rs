use crate::error::AndroidError;
use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags, Row};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct SmsRecord {
    pub address: String,
    pub timestamp: i64,
    pub body: String,
    pub direction: String,
}

/// mmssms.db 의 sms 테이블에서 메시지를 읽는다 (date 내림차순).
/// 파싱할 수 없는 행(date 가 NULL/비정수 등)은 건너뛰고 개수를 stderr 로 경고한다.
pub fn read_sms(db_path: &Path) -> Result<Vec<SmsRecord>, AndroidError> {
    let (records, skipped) = read_sms_inner(db_path)?;
    if skipped > 0 {
        eprintln!(
            "[경고] sms: 파싱 불가 행 {skipped}건 건너뜀 ({})",
            db_path.display()
        );
    }
    Ok(records)
}

pub(crate) fn read_sms_inner(db_path: &Path) -> Result<(Vec<SmsRecord>, usize), AndroidError> {
    let conn = open_immutable(db_path)?;
    require_columns(&conn, "sms", &["address", "date", "body", "type"])?;

    let mut stmt = conn
        .prepare("SELECT address, date, body, type FROM sms ORDER BY date DESC")
        .map_err(sqlite_err)?;
    let mut rows = stmt.query([]).map_err(sqlite_err)?;

    let mut records = Vec::new();
    let mut skipped = 0usize;
    while let Some(row) = rows.next().map_err(sqlite_err)? {
        match parse_sms_row(row) {
            Some(r) => records.push(r),
            None => skipped += 1,
        }
    }
    Ok((records, skipped))
}

fn parse_sms_row(row: &Row<'_>) -> Option<SmsRecord> {
    let address = value_to_string(row.get::<_, Value>(0).ok()?);
    let date_ms = value_to_i64(row.get::<_, Value>(1).ok()?)?;
    let body = value_to_string(row.get::<_, Value>(2).ok()?);
    let msg_type = value_to_i64(row.get::<_, Value>(3).ok()?);
    Some(SmsRecord {
        address,
        timestamp: ms_to_secs(date_ms),
        body,
        direction: sms_direction(msg_type),
    })
}

/// Telephony.TextBasedSmsColumns.TYPE 값을 문자열로 변환한다.
pub(crate) fn sms_direction(msg_type: Option<i64>) -> String {
    match msg_type {
        Some(1) => "received".into(),
        Some(2) => "sent".into(),
        Some(3) => "draft".into(),
        Some(4) => "outbox".into(),
        Some(5) => "failed".into(),
        Some(6) => "queued".into(),
        Some(n) => format!("unknown({n})"),
        None => "unknown(null)".into(),
    }
}

// ---- SQLite 공통 헬퍼 (calls.rs 와 공유) ----

/// 증거 무결성을 위해 `file:<path>?immutable=1` URI 로 읽기 전용 오픈한다.
/// immutable 모드에서는 잠금·저널·-wal/-shm 파일을 만들거나 수정하지 않는다.
pub(crate) fn open_immutable(db_path: &Path) -> Result<Connection, AndroidError> {
    let meta = std::fs::metadata(db_path).map_err(|e| AndroidError::OpenFailed {
        path: db_path.display().to_string(),
        source: e,
    })?;
    if !meta.is_file() {
        return Err(AndroidError::OpenFailed {
            path: db_path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "일반 파일이 아님"),
        });
    }

    let uri = immutable_uri(db_path)?;
    Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| AndroidError::SqliteError(format!("{}: {e}", db_path.display())))
}

fn immutable_uri(db_path: &Path) -> Result<String, AndroidError> {
    let s = db_path.to_str().ok_or_else(|| {
        AndroidError::UnsupportedFormat(format!(
            "UTF-8 이 아닌 경로는 지원하지 않음: {}",
            db_path.display()
        ))
    })?;
    let mut p = s.replace('\\', "/");
    // Windows 드라이브 경로(C:/...)는 file:///C:/... 형태가 되어야 한다.
    if p.len() >= 2 && p.as_bytes()[1] == b':' {
        p.insert(0, '/');
    }
    let mut uri = String::from("file:");
    for b in p.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                uri.push(b as char)
            }
            _ => uri.push_str(&format!("%{b:02X}")),
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

/// 테이블과 필수 컬럼의 존재를 확인한다. 없으면 SchemaMismatch.
pub(crate) fn require_columns(
    conn: &Connection,
    table: &str,
    columns: &[&str],
) -> Result<(), AndroidError> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .map_err(sqlite_err)?;
    let existing: Vec<String> = stmt
        .query_map([table], |r| r.get::<_, String>(0))
        .map_err(sqlite_err)?
        .collect::<Result<_, _>>()
        .map_err(sqlite_err)?;

    if existing.is_empty() {
        return Err(AndroidError::SchemaMismatch(format!(
            "'{table}' 테이블이 없음"
        )));
    }
    let missing: Vec<&str> = columns
        .iter()
        .copied()
        .filter(|c| !existing.iter().any(|e| e.eq_ignore_ascii_case(c)))
        .collect();
    if !missing.is_empty() {
        return Err(AndroidError::SchemaMismatch(format!(
            "'{table}' 테이블에 필수 컬럼 없음: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

pub(crate) fn sqlite_err(e: rusqlite::Error) -> AndroidError {
    AndroidError::SqliteError(e.to_string())
}

/// NULL 은 빈 문자열로 보존, 그 외 타입은 문자열로 변환한다.
pub(crate) fn value_to_string(v: Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Text(s) => s,
        Value::Blob(b) => String::from_utf8_lossy(&b).into_owned(),
    }
}

/// 정수 또는 정수 형태의 텍스트만 허용한다. NULL/실수/BLOB 등은 None.
pub(crate) fn value_to_i64(v: Value) -> Option<i64> {
    match v {
        Value::Integer(i) => Some(i),
        Value::Text(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Unix milliseconds → Unix seconds (음수도 내림).
pub(crate) fn ms_to_secs(ms: i64) -> i64 {
    ms.div_euclid(1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_mapping() {
        assert_eq!(sms_direction(Some(1)), "received");
        assert_eq!(sms_direction(Some(2)), "sent");
        assert_eq!(sms_direction(Some(3)), "draft");
        assert_eq!(sms_direction(Some(4)), "outbox");
        assert_eq!(sms_direction(Some(5)), "failed");
        assert_eq!(sms_direction(Some(6)), "queued");
        assert_eq!(sms_direction(Some(0)), "unknown(0)");
        assert_eq!(sms_direction(Some(99)), "unknown(99)");
        assert_eq!(sms_direction(None), "unknown(null)");
    }

    #[test]
    fn ms_conversion() {
        assert_eq!(ms_to_secs(1_700_000_000_123), 1_700_000_000);
        assert_eq!(ms_to_secs(999), 0);
        assert_eq!(ms_to_secs(-1), -1);
    }

    #[test]
    fn uri_escapes_special_chars() -> Result<(), AndroidError> {
        let uri = immutable_uri(Path::new("/tmp/a b?#%.db"))?;
        assert_eq!(uri, "file:/tmp/a%20b%3F%23%25.db?immutable=1");
        Ok(())
    }

    #[test]
    fn skipped_rows_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("mmssms.db");
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(
                "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, body TEXT, type INTEGER);
                 INSERT INTO sms (address, date, body, type) VALUES ('010', 1700000000000, 'ok', 1);
                 INSERT INTO sms (address, date, body, type) VALUES ('011', NULL, 'no date', 1);
                 INSERT INTO sms (address, date, body, type) VALUES ('012', 1.5, 'real date', 2);",
            )?;
        }
        let (records, skipped) = read_sms_inner(&path)?;
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 2);
        Ok(())
    }
}
