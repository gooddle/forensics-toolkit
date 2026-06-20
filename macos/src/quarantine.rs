use crate::error::MacosError;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::path::{Path, PathBuf};

const DEFAULT_DB: &str =
    "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";

#[derive(Debug, Serialize)]
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

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(DEFAULT_DB)
}

pub fn read_quarantine(path: Option<&Path>) -> Result<Vec<QuarantineEvent>, MacosError> {
    let db_path = path
        .map(Path::to_path_buf)
        .unwrap_or_else(default_db_path);

    if !db_path.exists() {
        return Err(MacosError::PathNotFound(db_path.display().to_string()));
    }

    let conn = Connection::open_with_flags(&db_path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MacosError::SqliteError(e.to_string()))?;

    let mut stmt = conn
        .prepare(
            "SELECT LSQuarantineEventIdentifier,
                    datetime(LSQuarantineTimeStamp + 978307200, 'unixepoch') as ts,
                    COALESCE(LSQuarantineAgentBundleIdentifier, ''),
                    COALESCE(LSQuarantineAgentName, ''),
                    COALESCE(LSQuarantineDataURLString, ''),
                    COALESCE(LSQuarantineSenderName, ''),
                    COALESCE(LSQuarantineSenderAddress, ''),
                    COALESCE(LSQuarantineTypeNumber, 0)
             FROM LSQuarantineEvent
             ORDER BY LSQuarantineTimeStamp DESC",
        )
        .map_err(|e| MacosError::SqliteError(e.to_string()))?;

    let events = stmt
        .query_map([], |row| {
            Ok(QuarantineEvent {
                identifier: row.get(0)?,
                timestamp: row.get(1)?,
                agent_bundle_id: row.get(2)?,
                agent_name: row.get(3)?,
                data_url: row.get(4)?,
                sender_name: row.get(5)?,
                sender_address: row.get(6)?,
                type_number: row.get(7)?,
            })
        })
        .map_err(|e| MacosError::SqliteError(e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    Ok(events)
}
