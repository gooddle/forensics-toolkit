use crate::error::MacosError;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::path::{Path, PathBuf};

const DEFAULT_DB: &str =
    "Library/Application Support/Knowledge/knowledgeC.db";

#[derive(Debug, Serialize)]
pub struct AppUsageEntry {
    pub bundle_id: String,
    pub start_time: String,
    pub end_time: String,
    pub duration_secs: f64,
    pub device: String,
}

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(DEFAULT_DB)
}

pub fn read_app_usage(path: Option<&Path>, limit: usize) -> Result<Vec<AppUsageEntry>, MacosError> {
    let db_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_db_path);

    if !db_path.exists() {
        return Err(MacosError::PathNotFound(db_path.display().to_string()));
    }

    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MacosError::SqliteError(e.to_string()))?;

    let limit_clause = if limit > 0 {
        format!("LIMIT {limit}")
    } else {
        String::new()
    };

    let sql = format!(
        "SELECT
            ZOBJECT.ZVALUESTRING,
            datetime(ZOBJECT.ZSTARTDATE + 978307200, 'unixepoch') as start_time,
            datetime(ZOBJECT.ZENDDATE   + 978307200, 'unixepoch') as end_time,
            ZOBJECT.ZENDDATE - ZOBJECT.ZSTARTDATE,
            COALESCE(ZOBJECT.ZDEVICEID, '')
         FROM ZOBJECT
         WHERE ZOBJECT.ZSTREAMNAME = '/app/inFocus'
           AND ZOBJECT.ZVALUESTRING IS NOT NULL
         ORDER BY ZOBJECT.ZSTARTDATE DESC
         {limit_clause}"
    );

    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| MacosError::SqliteError(e.to_string()))?;

    let entries = stmt
        .query_map([], |row| {
            Ok(AppUsageEntry {
                bundle_id: row.get(0)?,
                start_time: row.get(1)?,
                end_time: row.get(2)?,
                duration_secs: row.get(3)?,
                device: row.get(4)?,
            })
        })
        .map_err(|e| MacosError::SqliteError(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(entries)
}
