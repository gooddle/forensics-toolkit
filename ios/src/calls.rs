use crate::error::IosError;
use crate::sms::{
    coredata_to_unix, open_immutable, require_columns, sqlite_err, value_to_i64, value_to_string,
};
use rusqlite::Row;
use rusqlite::types::Value;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct IosCallRecord {
    pub address: String,
    pub duration_secs: f64,
    pub timestamp: i64,
    pub originated: bool,
}

/// CallHistory.storedata 의 ZCALLRECORD 테이블에서 통화 기록을 읽는다 (ZDATE 내림차순).
/// 파싱할 수 없는 행(ZDATE 가 NULL/비숫자 등)은 건너뛰고 개수를 stderr 로 경고한다.
pub fn read_calls(db_path: &Path) -> Result<Vec<IosCallRecord>, IosError> {
    let (records, skipped) = read_calls_inner(db_path)?;
    if skipped > 0 {
        eprintln!(
            "[경고] calls: 파싱 불가 행 {skipped}건 건너뜀 ({})",
            db_path.display()
        );
    }
    Ok(records)
}

pub(crate) fn read_calls_inner(db_path: &Path) -> Result<(Vec<IosCallRecord>, usize), IosError> {
    let conn = open_immutable(db_path)?;
    require_columns(
        &conn,
        "ZCALLRECORD",
        &["ZADDRESS", "ZDURATION", "ZDATE", "ZORIGINATED"],
    )?;

    let mut stmt = conn
        .prepare(
            "SELECT ZADDRESS, ZDURATION, ZDATE, ZORIGINATED FROM ZCALLRECORD ORDER BY ZDATE DESC",
        )
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

fn parse_call_row(row: &Row<'_>) -> Option<IosCallRecord> {
    // ZADDRESS 는 일부 iOS 버전에서 BLOB 으로 저장되므로 value_to_string 으로 보존한다.
    let address = value_to_string(row.get::<_, Value>(0).ok()?);
    let duration_secs = duration_value(row.get::<_, Value>(1).ok()?);
    let timestamp = coredata_to_unix(row.get::<_, Value>(2).ok()?)?;
    let originated = value_to_i64(row.get::<_, Value>(3).ok()?) == Some(1);
    Some(IosCallRecord {
        address,
        duration_secs,
        timestamp,
        originated,
    })
}

/// ZDURATION(실수 초). NULL/비숫자/비유한값은 0.0 으로 본다.
pub(crate) fn duration_value(v: Value) -> f64 {
    let d = match v {
        Value::Real(f) => f,
        Value::Integer(i) => i as f64,
        Value::Text(s) => s.trim().parse().unwrap_or(0.0),
        Value::Null | Value::Blob(_) => 0.0,
    };
    if d.is_finite() { d } else { 0.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn duration_conversion() {
        assert_eq!(duration_value(Value::Real(12.5)), 12.5);
        assert_eq!(duration_value(Value::Integer(30)), 30.0);
        assert_eq!(duration_value(Value::Text(" 4.25 ".into())), 4.25);
        assert_eq!(duration_value(Value::Null), 0.0);
        assert_eq!(duration_value(Value::Real(f64::NAN)), 0.0);
    }

    #[test]
    fn skipped_rows_are_counted() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("CallHistory.storedata");
        {
            let conn = Connection::open(&path)?;
            conn.execute_batch(
                "CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS, ZDURATION FLOAT, ZDATE TIMESTAMP, ZORIGINATED INTEGER);
                 INSERT INTO ZCALLRECORD (ZADDRESS, ZDURATION, ZDATE, ZORIGINATED) VALUES ('010', 3.0, 700000000.5, 1);
                 INSERT INTO ZCALLRECORD (ZADDRESS, ZDURATION, ZDATE, ZORIGINATED) VALUES ('011', 1.0, NULL, 0);
                 INSERT INTO ZCALLRECORD (ZADDRESS, ZDURATION, ZDATE, ZORIGINATED) VALUES ('012', 1.0, X'00', 0);",
            )?;
        }
        let (records, skipped) = read_calls_inner(&path)?;
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 2);
        Ok(())
    }
}
