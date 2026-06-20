use crate::error::DiskError;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

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

fn partition_type_name(ptype: u8) -> &'static str {
    match ptype {
        0x00 => "Empty",
        0x01 => "FAT12",
        0x04 => "FAT16 <32MB",
        0x05 => "Extended",
        0x06 => "FAT16",
        0x07 => "NTFS/HPFS",
        0x0B => "FAT32",
        0x0C => "FAT32 (LBA)",
        0x0E => "FAT16 (LBA)",
        0x0F => "Extended (LBA)",
        0x11 => "Hidden FAT12",
        0x14 => "Hidden FAT16 <32MB",
        0x16 => "Hidden FAT16",
        0x17 => "Hidden NTFS",
        0x1B => "Hidden FAT32",
        0x1C => "Hidden FAT32 (LBA)",
        0x82 => "Linux Swap",
        0x83 => "Linux",
        0x85 => "Linux Extended",
        0x8E => "Linux LVM",
        0xA5 => "FreeBSD",
        0xA8 => "macOS",
        0xAF => "macOS HFS+",
        0xEE => "GPT Protective MBR",
        0xEF => "EFI System",
        0xFB => "VMware VMFS",
        0xFC => "VMware VMKCORE",
        _ => "Unknown",
    }
}

fn parse_mbr(sector: &[u8; 512]) -> Result<PartitionScheme, DiskError> {
    let mut partitions = Vec::new();

    for i in 0u8..4 {
        let base = 446 + (i as usize) * 16;
        let status = sector[base];
        let ptype = sector[base + 4];

        if ptype == 0x00 {
            continue;
        }

        let mut cursor = std::io::Cursor::new(&sector[base + 8..base + 16]);
        let start_lba = cursor.read_u32::<LittleEndian>()?;
        let size_sectors = cursor.read_u32::<LittleEndian>()?;

        partitions.push(MbrPartition {
            index: i,
            partition_type: ptype,
            type_name: partition_type_name(ptype).to_string(),
            bootable: status == 0x80,
            start_lba,
            size_sectors,
            size_bytes: size_sectors as u64 * 512,
        });
    }

    Ok(PartitionScheme::Mbr(partitions))
}

fn parse_gpt(path: &Path) -> Result<PartitionScheme, DiskError> {
    let cfg = gpt::GptConfig::new().writable(false);
    let disk = cfg
        .open(path)
        .map_err(|e| DiskError::GptParseFailed(e.to_string()))?;

    let lb = gpt::disk::LogicalBlockSize::Lb512;
    let partitions = disk
        .partitions()
        .iter()
        .enumerate()
        .map(|(i, (_, p))| {
            let size_bytes = p.bytes_len(lb).unwrap_or(0);
            GptPartition {
                index: i,
                type_guid: p.part_type_guid.guid.to_string(),
                type_name: format!("{:?}", p.part_type_guid.os),
                name: p.name.clone(),
                start_lba: p.first_lba,
                end_lba: p.last_lba,
                size_bytes,
            }
        })
        .collect();

    Ok(PartitionScheme::Gpt(partitions))
}

pub fn parse_partitions(path: &Path) -> Result<PartitionScheme, DiskError> {
    let mut f = File::open(path).map_err(|e| DiskError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut sector = [0u8; 512];
    f.seek(SeekFrom::Start(0))?;

    if f.read(&mut sector)? < 512 {
        return Ok(PartitionScheme::Unknown);
    }

    let sig = u16::from_le_bytes([sector[510], sector[511]]);
    if sig != 0x55AA {
        return Err(DiskError::InvalidMbrSignature(sig));
    }

    if sector[446] == 0xEE {
        return parse_gpt(path);
    }

    parse_mbr(&sector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mbr(partitions: &[(u8, u8, u32, u32)]) -> [u8; 512] {
        let mut sector = [0u8; 512];
        sector[510] = 0x55;
        sector[511] = 0xAA;
        for (i, (status, ptype, start, size)) in partitions.iter().enumerate() {
            let base = 446 + i * 16;
            sector[base] = *status;
            sector[base + 4] = *ptype;
            sector[base + 8..base + 12].copy_from_slice(&start.to_le_bytes());
            sector[base + 12..base + 16].copy_from_slice(&size.to_le_bytes());
        }
        sector
    }

    #[test]
    fn test_mbr_single_fat32_partition() {
        let sector = make_mbr(&[(0x00, 0x0B, 2048, 204800)]);
        let scheme = parse_mbr(&sector).unwrap();
        if let PartitionScheme::Mbr(parts) = scheme {
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].partition_type, 0x0B);
            assert_eq!(parts[0].type_name, "FAT32");
            assert_eq!(parts[0].start_lba, 2048);
            assert_eq!(parts[0].size_sectors, 204800);
            assert!(!parts[0].bootable);
        } else {
            panic!("Expected MBR");
        }
    }

    #[test]
    fn test_mbr_bootable_partition() {
        let sector = make_mbr(&[(0x80, 0x07, 2048, 102400)]);
        let scheme = parse_mbr(&sector).unwrap();
        if let PartitionScheme::Mbr(parts) = scheme {
            assert!(parts[0].bootable);
            assert_eq!(parts[0].type_name, "NTFS/HPFS");
        } else {
            panic!("Expected MBR");
        }
    }

    #[test]
    fn test_mbr_empty_partitions_skipped() {
        let sector = make_mbr(&[(0x00, 0x00, 0, 0), (0x00, 0x0B, 2048, 204800)]);
        let scheme = parse_mbr(&sector).unwrap();
        if let PartitionScheme::Mbr(parts) = scheme {
            assert_eq!(parts.len(), 1);
            assert_eq!(parts[0].index, 1);
        } else {
            panic!("Expected MBR");
        }
    }

    #[test]
    fn test_invalid_mbr_signature() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 512]).unwrap();
        let result = parse_partitions(tmp.path());
        assert!(matches!(result, Err(DiskError::InvalidMbrSignature(_))));
    }

    #[test]
    fn test_partition_type_names() {
        assert_eq!(partition_type_name(0x0B), "FAT32");
        assert_eq!(partition_type_name(0x07), "NTFS/HPFS");
        assert_eq!(partition_type_name(0x83), "Linux");
        assert_eq!(partition_type_name(0xEE), "GPT Protective MBR");
    }
}
