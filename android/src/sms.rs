use crate::error::AndroidError;
use rusqlite::types::Value;
use rusqlite::{Connection, Row};
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

pub(crate) fn open_immutable(db_path: &Path) -> Result<Connection, AndroidError> {
    Ok(common::sqlite::open_immutable(db_path)?)
}

pub(crate) fn require_columns(
    conn: &Connection,
    table: &str,
    columns: &[&str],
) -> Result<(), AndroidError> {
    Ok(common::sqlite::require_columns(conn, table, columns)?)
}

pub(crate) fn sqlite_err(e: rusqlite::Error) -> AndroidError {
    AndroidError::SqliteError(e.to_string())
}

pub(crate) use common::sqlite::{value_to_i64, value_to_string};

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
