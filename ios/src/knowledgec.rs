use crate::error::IosError;
use std::path::Path;

pub use common::apple::AppUsageEntry;

/// iOS knowledgeC.db (보통 /private/var/mobile/Library/CoreDuet/Knowledge/knowledgeC.db).
pub fn read_app_usage(db_path: &Path, limit: usize) -> Result<Vec<AppUsageEntry>, IosError> {
    Ok(common::apple::read_knowledgec(db_path, limit)?)
}
