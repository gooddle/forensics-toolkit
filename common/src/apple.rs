//! macOS / iOS 가 공유하는 Apple 아티팩트 파서 (KnowledgeC, Quarantine).

use crate::sqlite::{SqliteError, open_immutable, require_columns, value_to_i64, value_to_string};
use crate::timestamp::format_unix_ts;
use rusqlite::Connection;
use rusqlite::types::Value;
use serde::Serialize;
use std::path::Path;

/// CoreData epoch(2001-01-01T00:00:00Z) 과 Unix epoch 의 차이(초).
pub const COREDATA_EPOCH_OFFSET: i64 = 978_307_200;

#[derive(Debug, Clone, Serialize)]
pub struct AppUsageEntry {
    pub bundle_id: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_secs: f64,
    pub device: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QuarantineEvent {
    pub identifier: String,
    pub timestamp: String,
    pub agent_bundle_id: String,
    pub agent_name: String,
    pub data_url: String,
    pub sender_name: String,
    pub sender_address: String,
    pub type_number: i64,
}

/// KnowledgeC DB 의 /app/inFocus 앱 사용 이력. limit 0 = 전체.
/// 시작 시각이 없거나 숫자가 아닌 행은 건너뛰고 개수를 stderr 로 경고한다.
pub fn read_knowledgec(db_path: &Path, limit: usize) -> Result<Vec<AppUsageEntry>, SqliteError> {
    let (entries, skipped) = read_knowledgec_with_skipped(db_path, limit)?;
    if skipped > 0 {
        eprintln!(
            "[경고] knowledgec: 파싱 불가 행 {skipped}건 건너뜀 ({})",
            db_path.display()
        );
    }
    Ok(entries)
}

/// [`read_knowledgec`] 와 같지만 경고 대신 건너뛴 행 수를 함께 돌려준다.
///
/// 기기 식별자는 스키마에 따라 `ZOBJECT.ZDEVICEID`, `ZSOURCE.ZDEVICEID`(ZOBJECT.ZSOURCE 조인)
/// 중 존재하는 것을 사용하며, 둘 다 없으면 빈 문자열이다.
pub fn read_knowledgec_with_skipped(
    db_path: &Path,
    limit: usize,
) -> Result<(Vec<AppUsageEntry>, usize), SqliteError> {
    let conn = open_immutable(db_path)?;
    require_columns(
        &conn,
        "ZOBJECT",
        &["ZSTREAMNAME", "ZVALUESTRING", "ZSTARTDATE", "ZENDDATE"],
    )?;

    let obj_cols = table_columns(&conn, "ZOBJECT")?;
    let src_cols = table_columns(&conn, "ZSOURCE")?;
    let obj_device = has_col(&obj_cols, "ZDEVICEID");
    let src_join = has_col(&obj_cols, "ZSOURCE")
        && has_col(&src_cols, "Z_PK")
        && has_col(&src_cols, "ZDEVICEID");

    let device_expr = match (obj_device, src_join) {
        (true, true) => "COALESCE(o.ZDEVICEID, s.ZDEVICEID)",
        (true, false) => "o.ZDEVICEID",
        (false, true) => "s.ZDEVICEID",
        (false, false) => "NULL",
    };
    let join = if src_join {
        "LEFT JOIN ZSOURCE s ON o.ZSOURCE = s.Z_PK"
    } else {
        ""
    };
    let sql = format!(
        "SELECT o.ZVALUESTRING, o.ZSTARTDATE, o.ZENDDATE, {device_expr}
         FROM ZOBJECT o {join}
         WHERE o.ZSTREAMNAME = '/app/inFocus'
         ORDER BY o.ZSTARTDATE DESC"
    );

    let mut stmt = conn.prepare(&sql).map_err(sqlite_err)?;
    let mut rows = stmt.query([]).map_err(sqlite_err)?;

    let mut entries = Vec::new();
    let mut skipped = 0usize;
    while limit == 0 || entries.len() < limit {
        let Some(row) = rows.next().map_err(sqlite_err)? else {
            break;
        };
        match parse_knowledgec_row(row) {
            Some(e) => entries.push(e),
            None => skipped += 1,
        }
    }
    Ok((entries, skipped))
}

fn parse_knowledgec_row(row: &rusqlite::Row<'_>) -> Option<AppUsageEntry> {
    let bundle_id = value_to_string(row.get::<_, Value>(0).ok()?);
    let start = value_to_f64(row.get::<_, Value>(1).ok()?)?;
    let end = value_to_f64(row.get::<_, Value>(2).ok()?);
    let device = value_to_string(row.get::<_, Value>(3).ok()?);

    Some(AppUsageEntry {
        bundle_id,
        start_time: coredata_to_rfc3339(start),
        end_time: end.map(coredata_to_rfc3339).unwrap_or_default(),
        duration_secs: end.map(|e| e - start).unwrap_or(0.0),
        device,
    })
}

/// LaunchServices QuarantineEventsV2 DB 의 다운로드 기록.
/// 시각이 NULL 인 행은 timestamp 를 빈 문자열로 보존하고, 읽을 수 없는 행은 건너뛰어
/// 개수를 stderr 로 경고한다.
pub fn read_quarantine_db(db_path: &Path) -> Result<Vec<QuarantineEvent>, SqliteError> {
    let (events, skipped) = read_quarantine_db_with_skipped(db_path)?;
    if skipped > 0 {
        eprintln!(
            "[경고] quarantine: 파싱 불가 행 {skipped}건 건너뜀 ({})",
            db_path.display()
        );
    }
    Ok(events)
}

const QUARANTINE_OPTIONAL: [&str; 6] = [
    "LSQuarantineAgentBundleIdentifier",
    "LSQuarantineAgentName",
    "LSQuarantineDataURLString",
    "LSQuarantineSenderName",
    "LSQuarantineSenderAddress",
    "LSQuarantineTypeNumber",
];

/// [`read_quarantine_db`] 와 같지만 경고 대신 건너뛴 행 수를 함께 돌려준다.
/// 선택 컬럼(에이전트·URL·발신자·타입)이 없는 스키마는 빈 값/0 으로 채운다.
pub fn read_quarantine_db_with_skipped(
    db_path: &Path,
) -> Result<(Vec<QuarantineEvent>, usize), SqliteError> {
    let conn = open_immutable(db_path)?;
    require_columns(
        &conn,
        "LSQuarantineEvent",
        &["LSQuarantineEventIdentifier", "LSQuarantineTimeStamp"],
    )?;
    let cols = table_columns(&conn, "LSQuarantineEvent")?;
    let optional: Vec<&str> = QUARANTINE_OPTIONAL
        .iter()
        .map(|c| if has_col(&cols, c) { *c } else { "NULL" })
        .collect();

    let sql = format!(
        "SELECT LSQuarantineEventIdentifier, LSQuarantineTimeStamp, {}
         FROM LSQuarantineEvent
         ORDER BY LSQuarantineTimeStamp DESC",
        optional.join(", ")
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_err)?;
    let mut rows = stmt.query([]).map_err(sqlite_err)?;

    let mut events = Vec::new();
    let mut skipped = 0usize;
    while let Some(row) = rows.next().map_err(sqlite_err)? {
        match parse_quarantine_row(row) {
            Some(e) => events.push(e),
            None => skipped += 1,
        }
    }
    Ok((events, skipped))
}

fn parse_quarantine_row(row: &rusqlite::Row<'_>) -> Option<QuarantineEvent> {
    let s = |i: usize| row.get::<_, Value>(i).ok().map(value_to_string);
    Some(QuarantineEvent {
        identifier: s(0)?,
        timestamp: value_to_f64(row.get::<_, Value>(1).ok()?)
            .map(coredata_to_rfc3339)
            .unwrap_or_default(),
        agent_bundle_id: s(2)?,
        agent_name: s(3)?,
        data_url: s(4)?,
        sender_name: s(5)?,
        sender_address: s(6)?,
        type_number: value_to_i64(row.get::<_, Value>(7).ok()?).unwrap_or(0),
    })
}

/// CoreData 초(소수 가능) → RFC3339 UTC. 범위를 벗어나면 "invalid timestamp".
fn coredata_to_rfc3339(secs: f64) -> String {
    let floored = secs.floor();
    // i64 범위를 넘는 값은 chrono 범위도 넘으므로 invalid 처리.
    if !(-9.0e15..=9.0e15).contains(&floored) {
        return format_unix_ts(i64::MAX);
    }
    format_unix_ts((floored as i64).saturating_add(COREDATA_EPOCH_OFFSET))
}

/// 정수·실수·숫자 텍스트를 f64 로. NULL/BLOB/비숫자/비유한값은 None.
fn value_to_f64(v: Value) -> Option<f64> {
    let f = match v {
        Value::Integer(i) => i as f64,
        Value::Real(f) => f,
        Value::Text(s) => s.trim().parse().ok()?,
        _ => return None,
    };
    f.is_finite().then_some(f)
}

/// 테이블 컬럼 목록. 테이블이 없으면 빈 목록.
fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>, SqliteError> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .map_err(sqlite_err)?;
    stmt.query_map([table], |r| r.get::<_, String>(0))
        .map_err(sqlite_err)?
        .collect::<Result<_, _>>()
        .map_err(sqlite_err)
}

fn has_col(cols: &[String], name: &str) -> bool {
    cols.iter().any(|c| c.eq_ignore_ascii_case(name))
}

fn sqlite_err(e: rusqlite::Error) -> SqliteError {
    SqliteError::Sqlite(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coredata_conversion() {
        assert_eq!(coredata_to_rfc3339(0.0), "2001-01-01T00:00:00+00:00");
        assert_eq!(coredata_to_rfc3339(1.9), "2001-01-01T00:00:01+00:00");
        assert_eq!(coredata_to_rfc3339(-0.5), "2000-12-31T23:59:59+00:00");
        assert_eq!(coredata_to_rfc3339(1e300), "invalid timestamp");
    }

    #[test]
    fn f64_conversion() {
        assert_eq!(value_to_f64(Value::Integer(3)), Some(3.0));
        assert_eq!(value_to_f64(Value::Text(" 1.5 ".into())), Some(1.5));
        assert_eq!(value_to_f64(Value::Text("abc".into())), None);
        assert_eq!(value_to_f64(Value::Null), None);
        assert_eq!(value_to_f64(Value::Real(f64::NAN)), None);
    }
}
