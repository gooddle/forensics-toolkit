use crate::error::AndroidError;
use crate::sms::{
    ms_to_secs, open_immutable, require_columns, sqlite_err, value_to_i64, value_to_string,
};
use rusqlite::Row;
use rusqlite::types::Value;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct CallRecord {
    pub number: String,
    pub timestamp: i64,
    pub duration_secs: i64,
    pub call_type: String,
}

/// contacts2.db(구형) 또는 calllog.db(최신 기기)의 calls 테이블에서 통화 기록을 읽는다 (date 내림차순).
/// 파싱할 수 없는 행(date 가 NULL/비정수 등)은 건너뛰고 개수를 stderr 로 경고한다.
pub fn read_calls(db_path: &Path) -> Result<Vec<CallRecord>, AndroidError> {
    let (records, skipped) = read_calls_inner(db_path)?;
    if skipped > 0 {
        eprintln!(
            "[경고] calls: 파싱 불가 행 {skipped}건 건너뜀 ({})",
            db_path.display()
        );
    }
    Ok(records)
}

pub(crate) fn read_calls_inner(db_path: &Path) -> Result<(Vec<CallRecord>, usize), AndroidError> {
    let conn = open_immutable(db_path)?;
    require_columns(&conn, "calls", &["number", "date", "duration", "type"])?;

    let mut stmt = conn
        .prepare("SELECT number, date, duration, type FROM calls ORDER BY date DESC")
        .map_err(sqlite_err)?;
    let mut rows = stmt.query([]).map_err(sqlite_err)?;

    let mut records = Vec::new();
    let mut skipped = 0usize;
    while let Some(row) = rows.next().map_err(sqlite_err)? {
        match parse_call_row(row) {
            Some(r) => records.push(r),
            None => skipped += 1,
        }
    }
    Ok((records, skipped))
}

fn parse_call_row(row: &Row<'_>) -> Option<CallRecord> {
    let number = value_to_string(row.get::<_, Value>(0).ok()?);
    let date_ms = value_to_i64(row.get::<_, Value>(1).ok()?)?;
    // duration 이 NULL 이면 Android 기본값과 같은 0 으로 본다.
    let duration_secs = value_to_i64(row.get::<_, Value>(2).ok()?).unwrap_or(0);
    let call_type = value_to_i64(row.get::<_, Value>(3).ok()?);
    Some(CallRecord {
        number,
        timestamp: ms_to_secs(date_ms),
        duration_secs,
        call_type: call_type_name(call_type),
    })
}

/// CallLog.Calls.TYPE 값을 문자열로 변환한다.
pub(crate) fn call_type_name(call_type: Option<i64>) -> String {
    match call_type {
        Some(1) => "incoming".into(),
        Some(2) => "outgoing".into(),
        Some(3) => "missed".into(),
        Some(4) => "voicemail".into(),
        Some(5) => "rejected".into(),
        Some(6) => "blocked".into(),
        Some(n) => format!("unknown({n})"),
        None => "unknown(null)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn call_type_mapping() {
        assert_eq!(call_type_name(Some(1)), "incoming");
        assert_eq!(call_type_name(Some(2)), "outgoing");
        assert_eq!(call_type_name(Some(3)), "missed");
        assert_eq!(call_type_name(Some(4)), "voicemail");
        assert_eq!(call_type_name(Some(5)), "rejected");
        assert_eq!(call_type_name(Some(6)), "blocked");
        assert_eq!(call_type_name(Some(7)), "unknown(7)");
        assert_eq!(call_type_name(None), "unknown(null)");
    }

    #[test]
    fn skipped_rows_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("calllog.db");
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(
                "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER);
                 INSERT INTO calls (number, date, duration, type) VALUES ('010', 1700000000000, 30, 1);
                 INSERT INTO calls (number, date, duration, type) VALUES ('011', NULL, 10, 2);
                 INSERT INTO calls (number, date, duration, type) VALUES ('012', X'00', 10, 2);",
            )?;
        }
        let (records, skipped) = read_calls_inner(&path)?;
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 2);
        Ok(())
    }
}
