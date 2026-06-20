use crate::error::DiskError;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct DeletedEntry {
    pub original_name: String,
    pub size_bytes: u32,
    pub first_cluster: u32,
    pub modified_at: Option<String>,
    pub is_recoverable: bool,
}

pub fn find_deleted_fat32(
    _path: &Path,
    _partition_offset_bytes: u64,
) -> Result<Vec<DeletedEntry>, DiskError> {
    Ok(vec![])
}
