use crate::error::MacosError;
use std::path::{Path, PathBuf};

pub use common::apple::AppUsageEntry;

const DEFAULT_DB: &str = "Library/Application Support/Knowledge/knowledgeC.db";

fn default_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(DEFAULT_DB)
}

/// KnowledgeC 앱 사용 이력. path 가 None 이면 `~/Library/Application Support/Knowledge/knowledgeC.db`.
/// limit 0 = 전체.
pub fn read_app_usage(path: Option<&Path>, limit: usize) -> Result<Vec<AppUsageEntry>, MacosError> {
    let db_path = path.map(Path::to_path_buf).unwrap_or_else(default_db_path);

    if !db_path.exists() {
        return Err(MacosError::PathNotFound(db_path.display().to_string()));
    }

    Ok(common::apple::read_knowledgec(&db_path, limit)?)
}
