use crate::error::IosError;
use common::apple::COREDATA_EPOCH_OFFSET;
use rusqlite::types::Value;
use rusqlite::{Connection, Row};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct IosSmsRecord {
    pub address: String,
    pub timestamp: i64,
    pub text: String,
    pub direction: String,
}

/// sms.db 의 message 테이블에서 메시지를 읽는다 (date 내림차순).
/// handle 이 없는 메시지(handle_id=0 등)도 address 를 빈 문자열로 두고 포함한다.
/// 파싱할 수 없는 행(date 가 NULL/비숫자 등)은 건너뛰고 개수를 stderr 로 경고한다.
pub fn read_sms(db_path: &Path) -> Result<Vec<IosSmsRecord>, IosError> {
    let (records, skipped) = read_sms_inner(db_path)?;
    if skipped > 0 {
        eprintln!(
            "[경고] sms: 파싱 불가 행 {skipped}건 건너뜀 ({})",
            db_path.display()
        );
    }
    Ok(records)
}

pub(crate) fn read_sms_inner(db_path: &Path) -> Result<(Vec<IosSmsRecord>, usize), IosError> {
    let conn = open_immutable(db_path)?;
    require_columns(
        &conn,
        "message",
        &["handle_id", "date", "text", "is_from_me"],
    )?;
    require_columns(&conn, "handle", &["ROWID", "id"])?;

    // attributedBody 는 iOS 버전에 따라 없을 수 있으므로 선택 컬럼으로 처리한다.
    let has_attributed =
        common::sqlite::require_columns(&conn, "message", &["attributedBody"]).is_ok();
    let body_col = if has_attributed {
        "m.attributedBody"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT h.id, m.date, m.text, m.is_from_me, {body_col}
         FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID
         ORDER BY m.date DESC"
    );

    let mut stmt = conn.prepare(&sql).map_err(sqlite_err)?;
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

fn parse_sms_row(row: &Row<'_>) -> Option<IosSmsRecord> {
    let address = value_to_string(row.get::<_, Value>(0).ok()?);
    let timestamp = coredata_to_unix(row.get::<_, Value>(1).ok()?)?;
    let text = match row.get::<_, Value>(2).ok()? {
        Value::Null => match row.get::<_, Value>(4).ok()? {
            Value::Blob(b) => extract_attributed_text(&b).unwrap_or_default(),
            _ => String::new(),
        },
        v => value_to_string(v),
    };
    let is_from_me = value_to_i64(row.get::<_, Value>(3).ok()?);
    Some(IosSmsRecord {
        address,
        timestamp,
        text,
        direction: sms_direction(is_from_me),
    })
}

/// message.is_from_me 값을 방향 문자열로 변환한다.
pub(crate) fn sms_direction(is_from_me: Option<i64>) -> String {
    match is_from_me {
        Some(1) => "sent".into(),
        Some(0) => "received".into(),
        Some(n) => format!("unknown({n})"),
        None => "unknown(null)".into(),
    }
}

/// 이 값보다 절대값이 크면 나노초로 본다 (iOS 11+). 초 단위로는 약 3만 년에 해당한다.
const NANOS_THRESHOLD: f64 = 1e12;

/// CoreData epoch 기준 날짜(초 또는 나노초, 정수/실수/숫자 텍스트)를 Unix 초로 변환한다.
/// NULL/BLOB/NaN/범위 초과 등 변환할 수 없으면 None.
pub(crate) fn coredata_to_unix(v: Value) -> Option<i64> {
    let secs = match v {
        Value::Integer(i) => {
            if (i as f64).abs() > NANOS_THRESHOLD {
                i.div_euclid(1_000_000_000)
            } else {
                i
            }
        }
        Value::Real(f) => real_to_secs(f)?,
        Value::Text(s) => {
            let t = s.trim();
            match t.parse::<i64>() {
                Ok(i) => return coredata_to_unix(Value::Integer(i)),
                Err(_) => real_to_secs(t.parse::<f64>().ok()?)?,
            }
        }
        Value::Null | Value::Blob(_) => return None,
    };
    secs.checked_add(COREDATA_EPOCH_OFFSET)
}

fn real_to_secs(f: f64) -> Option<i64> {
    if !f.is_finite() {
        return None;
    }
    let secs = if f.abs() > NANOS_THRESHOLD {
        (f / 1e9).floor()
    } else {
        f.floor()
    };
    // i64 범위를 넘으면 as 변환이 포화되므로 명시적으로 거른다.
    if secs.abs() >= 9.0e18 {
        return None;
    }
    Some(secs as i64)
}

/// attributedBody(NSArchiver typedstream) BLOB 에서 첫 NSString 본문을 추출한다.
/// 구조: ... "NSString" 0x01 0x94 0x84 0x01 '+' <len> <utf8 bytes> ...
/// len 은 1바이트, 0x81 이면 뒤 2바이트(LE), 0x82 이면 뒤 4바이트(LE) 길이.
pub(crate) fn extract_attributed_text(blob: &[u8]) -> Option<String> {
    const MARKER: &[u8] = b"NSString";
    let start = blob.windows(MARKER.len()).position(|w| w == MARKER)? + MARKER.len();
    // 마커 뒤 짧은 범위 안에서 '+'(C 문자열 타입 태그)를 찾는다.
    let window_end = blob.len().min(start + 16);
    let plus = blob
        .get(start..window_end)?
        .iter()
        .position(|&b| b == b'+')?;
    let mut pos = start + plus + 1;

    let first = *blob.get(pos)?;
    pos += 1;
    let len = match first {
        0x81 => {
            let b = blob.get(pos..pos + 2)?;
            pos += 2;
            u16::from_le_bytes([b[0], b[1]]) as usize
        }
        0x82 => {
            let b = blob.get(pos..pos + 4)?;
            pos += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        n if n < 0x80 => n as usize,
        _ => return None,
    };
    let end = pos.checked_add(len)?;
    let bytes = blob.get(pos..end)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

// ---- SQLite 공통 헬퍼 (calls.rs 와 공유) ----

pub(crate) fn open_immutable(db_path: &Path) -> Result<Connection, IosError> {
    Ok(common::sqlite::open_immutable(db_path)?)
}

pub(crate) fn require_columns(
    conn: &Connection,
    table: &str,
    columns: &[&str],
) -> Result<(), IosError> {
    Ok(common::sqlite::require_columns(conn, table, columns)?)
}

pub(crate) fn sqlite_err(e: rusqlite::Error) -> IosError {
    IosError::SqliteError(e.to_string())
}

pub(crate) use common::sqlite::{value_to_i64, value_to_string};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direction_mapping() {
        assert_eq!(sms_direction(Some(1)), "sent");
        assert_eq!(sms_direction(Some(0)), "received");
        assert_eq!(sms_direction(Some(7)), "unknown(7)");
        assert_eq!(sms_direction(None), "unknown(null)");
    }

    #[test]
    fn date_seconds_and_nanos() {
        // 2023-11-14T22:13:20Z = Unix 1_700_000_000 = CoreData 721_692_800
        let core = 1_700_000_000 - COREDATA_EPOCH_OFFSET;
        let unix = Some(1_700_000_000);
        assert_eq!(coredata_to_unix(Value::Integer(core)), unix);
        assert_eq!(coredata_to_unix(Value::Integer(core * 1_000_000_000)), unix);
        assert_eq!(
            coredata_to_unix(Value::Integer(core * 1_000_000_000 + 999_999_999)),
            unix
        );
        assert_eq!(coredata_to_unix(Value::Real(core as f64 + 0.75)), unix);
        assert_eq!(coredata_to_unix(Value::Real(core as f64 * 1e9)), unix);
        assert_eq!(coredata_to_unix(Value::Text(core.to_string())), unix);
        assert_eq!(
            coredata_to_unix(Value::Integer(0)),
            Some(COREDATA_EPOCH_OFFSET)
        );
        // 2001 이전 (음수) 나노초
        assert_eq!(
            coredata_to_unix(Value::Integer(-2_000_000_000_000)),
            Some(COREDATA_EPOCH_OFFSET - 2_000)
        );
    }

    #[test]
    fn date_invalid() {
        assert_eq!(coredata_to_unix(Value::Null), None);
        assert_eq!(coredata_to_unix(Value::Blob(vec![1])), None);
        assert_eq!(coredata_to_unix(Value::Real(f64::NAN)), None);
        assert_eq!(coredata_to_unix(Value::Real(f64::INFINITY)), None);
        assert_eq!(coredata_to_unix(Value::Real(1e300)), None);
        assert_eq!(coredata_to_unix(Value::Text("abc".into())), None);
        // 나노초로 판정되지 않는 i64 극단값의 오버플로
        assert_eq!(
            coredata_to_unix(Value::Integer(i64::MAX)),
            Some(i64::MAX / 1_000_000_000 + COREDATA_EPOCH_OFFSET)
        );
    }

    fn typedstream(text: &[u8], long: bool) -> Vec<u8> {
        let mut v = b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x84\x84\x08NSObject\x00\x85\x92\x84\x84\x84\x08NSString\x01\x94\x84\x01+".to_vec();
        if long {
            v.push(0x81);
            v.extend_from_slice(&(text.len() as u16).to_le_bytes());
        } else {
            v.push(text.len() as u8);
        }
        v.extend_from_slice(text);
        v.extend_from_slice(b"\x86\x84\x02iI\x01");
        v
    }

    #[test]
    fn attributed_body_extraction() {
        let short = "안녕 hello".as_bytes();
        assert_eq!(
            extract_attributed_text(&typedstream(short, false)).as_deref(),
            Some("안녕 hello")
        );
        let long = "x".repeat(300);
        assert_eq!(
            extract_attributed_text(&typedstream(long.as_bytes(), true)).as_deref(),
            Some(long.as_str())
        );
    }

    #[test]
    fn attributed_body_malformed() {
        assert_eq!(extract_attributed_text(b""), None);
        assert_eq!(extract_attributed_text(b"no marker"), None);
        assert_eq!(extract_attributed_text(b"NSString\x01\x94\x84\x01+"), None);
        // 길이가 남은 바이트보다 큼
        assert_eq!(
            extract_attributed_text(b"NSString\x01\x94\x84\x01+\x50abc"),
            None
        );
        assert_eq!(
            extract_attributed_text(b"NSString\x01\x94\x84\x01+\x81\xff"),
            None
        );
    }

    #[test]
    fn skipped_rows_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sms.db");
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(
                "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
                 CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, date INTEGER, text TEXT, is_from_me INTEGER);
                 INSERT INTO message (handle_id, date, text, is_from_me) VALUES (0, 700000000, 'ok', 0);
                 INSERT INTO message (handle_id, date, text, is_from_me) VALUES (0, NULL, 'no date', 0);
                 INSERT INTO message (handle_id, date, text, is_from_me) VALUES (0, X'00', 'blob date', 1);",
            )?;
        }
        let (records, skipped) = read_sms_inner(&path)?;
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 2);
        Ok(())
    }
}
