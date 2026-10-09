use crate::error::IosError;
use std::path::Path;

pub use common::apple::QuarantineEvent;

/// iOS 기기에는 QuarantineEventsV2 가 없으므로, 동기화한 Mac 의 DB 경로를 받아 분석한다.
pub fn read_quarantine(db_path: &Path) -> Result<Vec<QuarantineEvent>, IosError> {
    Ok(common::apple::read_quarantine_db(db_path)?)
}
