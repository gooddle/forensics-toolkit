use crate::error::MacosError;
use std::path::{Path, PathBuf};

pub use common::apple::QuarantineEvent;

const DEFAULT_DB: &str = "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2";

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(DEFAULT_DB)
}

/// Quarantine 다운로드 기록. path 가 None 이면
/// `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`.
pub fn read_quarantine(path: Option<&Path>) -> Result<Vec<QuarantineEvent>, MacosError> {
    let db_path = path.map(Path::to_path_buf).unwrap_or_else(default_db_path);

    if !db_path.exists() {
        return Err(MacosError::PathNotFound(db_path.display().to_string()));
    }

    Ok(common::apple::read_quarantine_db(&db_path)?)
}
