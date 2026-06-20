use crate::error::DiskError;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub enum PartitionScheme {
    Mbr(Vec<MbrPartition>),
    Gpt(Vec<GptPartition>),
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct MbrPartition {
    pub index: u8,
    pub partition_type: u8,
    pub type_name: String,
    pub bootable: bool,
    pub start_lba: u32,
    pub size_sectors: u32,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct GptPartition {
    pub index: usize,
    pub type_guid: String,
    pub type_name: String,
    pub name: String,
    pub start_lba: u64,
    pub end_lba: u64,
    pub size_bytes: u64,
}

pub fn parse_partitions(_path: &std::path::Path) -> Result<PartitionScheme, DiskError> {
    Ok(PartitionScheme::Unknown)
}
