use crate::error::DiskError;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const DELETED_MARKER: u8 = 0xE5;
const DIR_ENTRY_SIZE: usize = 32;
const ATTR_VOLUME_ID: u8 = 0x08;
const ATTR_LONG_NAME: u8 = 0x0F;

#[derive(Debug, Serialize)]
pub struct DeletedEntry {
    pub original_name: String,
    pub size_bytes: u32,
    pub first_cluster: u32,
    pub modified_at: Option<String>,
    pub is_recoverable: bool,
}

fn parse_fat_name(raw: &[u8; 11]) -> String {
    let name = raw[..8].iter().map(|&b| if b == 0x20 { ' ' } else { b as char }).collect::<String>().trim_end().to_string();
    let ext = raw[8..11].iter().map(|&b| if b == 0x20 { ' ' } else { b as char }).collect::<String>().trim_end().to_string();
    if ext.is_empty() { name } else { format!("{}.{}", name, ext) }
}

fn parse_fat_datetime(date: u16, time: u16) -> String {
    let year = 1980 + ((date >> 9) & 0x7F);
    let month = (date >> 5) & 0x0F;
    let day = date & 0x1F;
    let hour = (time >> 11) & 0x1F;
    let min = (time >> 5) & 0x3F;
    let sec = (time & 0x1F) * 2;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00", year, month, day, hour, min, sec)
}

fn parse_entry(buf: &[u8; DIR_ENTRY_SIZE]) -> Option<DeletedEntry> {
    if buf[0] != DELETED_MARKER {
        return None;
    }

    let attr = buf[11];
    if attr == ATTR_LONG_NAME || attr & ATTR_VOLUME_ID != 0 {
        return None;
    }

    let mut name_raw = [0u8; 11];
    name_raw.copy_from_slice(&buf[0..11]);
    name_raw[0] = b'?';
    let original_name = parse_fat_name(&name_raw);

    let first_cluster_hi = u16::from_le_bytes([buf[20], buf[21]]) as u32;
    let first_cluster_lo = u16::from_le_bytes([buf[26], buf[27]]) as u32;
    let first_cluster = (first_cluster_hi << 16) | first_cluster_lo;

    let size_bytes = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);
    let mod_date = u16::from_le_bytes([buf[24], buf[25]]);
    let mod_time = u16::from_le_bytes([buf[22], buf[23]]);
    let modified_at = if mod_date == 0 { None } else { Some(parse_fat_datetime(mod_date, mod_time)) };

    let is_recoverable = first_cluster > 1 && size_bytes > 0;

    Some(DeletedEntry {
        original_name,
        size_bytes,
        first_cluster,
        modified_at,
        is_recoverable,
    })
}

pub fn find_deleted_fat32(
    path: &Path,
    partition_offset_bytes: u64,
) -> Result<Vec<DeletedEntry>, DiskError> {
    let mut file = File::open(path).map_err(|e| DiskError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    // BPB에서 루트 디렉토리 위치 계산
    file.seek(SeekFrom::Start(partition_offset_bytes))?;
    let mut bpb = [0u8; 512];
    file.read_exact(&mut bpb)?;

    let mut cursor = std::io::Cursor::new(&bpb[11..]);
    let bytes_per_sector = cursor.read_u16::<LittleEndian>()? as u64;
    let sectors_per_cluster = bpb[13] as u64;
    let reserved_sectors = u16::from_le_bytes([bpb[14], bpb[15]]) as u64;
    let num_fats = bpb[16] as u64;
    let root_entry_count = u16::from_le_bytes([bpb[17], bpb[18]]) as u64;
    let fat_size_16 = u16::from_le_bytes([bpb[22], bpb[23]]) as u64;
    let fat_size_32 = u32::from_le_bytes([bpb[36], bpb[37], bpb[38], bpb[39]]) as u64;
    let fat_size = if fat_size_16 != 0 { fat_size_16 } else { fat_size_32 };

    let root_dir_sectors = (root_entry_count * 32).div_ceil(bytes_per_sector);
    let first_data_sector = reserved_sectors + num_fats * fat_size + root_dir_sectors;
    let is_fat32 = root_entry_count == 0;

    let root_start = if is_fat32 {
        let root_cluster = u32::from_le_bytes([bpb[44], bpb[45], bpb[46], bpb[47]]) as u64;
        partition_offset_bytes
            + (first_data_sector + (root_cluster - 2) * sectors_per_cluster) * bytes_per_sector
    } else {
        partition_offset_bytes + (reserved_sectors + num_fats * fat_size) * bytes_per_sector
    };

    let root_size = if is_fat32 {
        sectors_per_cluster * bytes_per_sector
    } else {
        root_entry_count * DIR_ENTRY_SIZE as u64
    };

    file.seek(SeekFrom::Start(root_start))?;
    let mut raw = vec![0u8; root_size as usize];
    file.read_exact(&mut raw)?;

    let mut entries = Vec::new();
    for chunk in raw.chunks_exact(DIR_ENTRY_SIZE) {
        if chunk[0] == 0x00 {
            break;
        }
        let mut buf = [0u8; DIR_ENTRY_SIZE];
        buf.copy_from_slice(chunk);
        if let Some(entry) = parse_entry(&buf) {
            entries.push(entry);
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(first_byte: u8, name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0] = first_byte;
        buf[1..11].copy_from_slice(&name[1..]);
        buf[11] = attr;
        buf[20] = ((cluster >> 16) & 0xFF) as u8;
        buf[21] = ((cluster >> 24) & 0xFF) as u8;
        buf[26] = (cluster & 0xFF) as u8;
        buf[27] = ((cluster >> 8) & 0xFF) as u8;
        buf[28..32].copy_from_slice(&size.to_le_bytes());
        buf
    }

    #[test]
    fn test_deleted_entry_detected() {
        let name = b"TESTFILE TXT";
        let mut name11 = [0u8; 11];
        name11.copy_from_slice(&name[..11]);
        let buf = make_entry(DELETED_MARKER, &name11, 0x20, 100, 1024);
        let entry = parse_entry(&buf).unwrap();
        assert!(entry.original_name.starts_with('?'));
        assert_eq!(entry.size_bytes, 1024);
        assert_eq!(entry.first_cluster, 100);
        assert!(entry.is_recoverable);
    }

    #[test]
    fn test_active_entry_skipped() {
        let name = b"ACTIVEFIL TXT";
        let mut name11 = [0u8; 11];
        name11.copy_from_slice(&name[..11]);
        let buf = make_entry(b'A', &name11, 0x20, 50, 512);
        assert!(parse_entry(&buf).is_none());
    }

    #[test]
    fn test_volume_id_skipped() {
        let name = b"VOLUME     ";
        let mut name11 = [0u8; 11];
        name11.copy_from_slice(name);
        let buf = make_entry(DELETED_MARKER, &name11, ATTR_VOLUME_ID, 0, 0);
        assert!(parse_entry(&buf).is_none());
    }

    #[test]
    fn test_zero_cluster_not_recoverable() {
        let name = b"GONE    TXT";
        let mut name11 = [0u8; 11];
        name11.copy_from_slice(name);
        let buf = make_entry(DELETED_MARKER, &name11, 0x20, 0, 512);
        let entry = parse_entry(&buf).unwrap();
        assert!(!entry.is_recoverable);
    }
}
