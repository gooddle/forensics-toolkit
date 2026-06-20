use crate::error::DiskError;
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u32,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub cluster: u32,
}

pub fn list_fat32(
    _path: &Path,
    _partition_offset_bytes: u64,
    _max_depth: usize,
) -> Result<Vec<FileEntry>, DiskError> {
    Ok(vec![])
}
