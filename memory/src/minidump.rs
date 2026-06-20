use crate::error::MemoryError;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Seek, SeekFrom};
use std::path::Path;

const MDMP_SIGNATURE: u32 = 0x504D_444D; // "MDMP"
const MDMP_VALID_VERSION: u16 = 0xA793;

#[derive(Debug, Serialize)]
pub struct MinidumpInfo {
    pub path: String,
    pub version: u16,
    pub stream_count: u32,
    pub stream_directory_rva: u32,
    pub checksum: u32,
    pub timestamp: u32,
    pub flags: u64,
    pub streams: Vec<StreamEntry>,
}

#[derive(Debug, Serialize)]
pub struct StreamEntry {
    pub stream_type: u32,
    pub type_name: String,
    pub data_size: u32,
    pub rva: u32,
}

fn stream_type_name(t: u32) -> &'static str {
    match t {
        0 => "UnusedStream",
        1 => "ReservedStream0",
        2 => "ReservedStream1",
        3 => "ThreadListStream",
        4 => "ModuleListStream",
        5 => "MemoryListStream",
        6 => "ExceptionStream",
        7 => "SystemInfoStream",
        8 => "ThreadExListStream",
        9 => "Memory64ListStream",
        10 => "CommentStreamA",
        11 => "CommentStreamW",
        12 => "HandleDataStream",
        13 => "FunctionTableStream",
        14 => "UnloadedModuleListStream",
        15 => "MiscInfoStream",
        16 => "MemoryInfoListStream",
        17 => "ThreadInfoListStream",
        18 => "HandleOperationListStream",
        19 => "TokenStream",
        0x8000 => "ceStreamNull",
        0xFFFF => "LastReservedStream",
        _ => "UnknownStream",
    }
}

pub fn parse_minidump(path: &Path) -> Result<MinidumpInfo, MemoryError> {
    let file = File::open(path).map_err(|e| MemoryError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut r = BufReader::new(file);

    let sig = r.read_u32::<LittleEndian>()?;
    if sig != MDMP_SIGNATURE {
        return Err(MemoryError::InvalidMinidumpSignature(sig));
    }

    let version = r.read_u16::<LittleEndian>()?;
    let _impl_version = r.read_u16::<LittleEndian>()?;
    let stream_count = r.read_u32::<LittleEndian>()?;
    let stream_directory_rva = r.read_u32::<LittleEndian>()?;
    let checksum = r.read_u32::<LittleEndian>()?;
    let timestamp = r.read_u32::<LittleEndian>()?;
    let flags = r.read_u64::<LittleEndian>()?;

    if version != MDMP_VALID_VERSION {
        return Err(MemoryError::UnsupportedFormat(format!(
            "MINIDUMP_HEADER version 0x{version:04X}"
        )));
    }

    r.seek(SeekFrom::Start(stream_directory_rva as u64))?;

    let mut streams = Vec::with_capacity(stream_count as usize);
    for _ in 0..stream_count {
        let stream_type = r.read_u32::<LittleEndian>()?;
        let data_size = r.read_u32::<LittleEndian>()?;
        let rva = r.read_u32::<LittleEndian>()?;
        streams.push(StreamEntry {
            type_name: stream_type_name(stream_type).to_string(),
            stream_type,
            data_size,
            rva,
        });
    }

    Ok(MinidumpInfo {
        path: path.display().to_string(),
        version,
        stream_count,
        stream_directory_rva,
        checksum,
        timestamp,
        flags,
        streams,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;
    use tempfile::Builder;

    fn write_le32(buf: &mut Vec<u8>, v: u32) {
        buf.write_u32::<LittleEndian>(v).unwrap();
    }
    fn write_le16(buf: &mut Vec<u8>, v: u16) {
        buf.write_u16::<LittleEndian>(v).unwrap();
    }
    fn write_le64(buf: &mut Vec<u8>, v: u64) {
        buf.write_u64::<LittleEndian>(v).unwrap();
    }

    fn make_minidump_bytes(stream_count: u32) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        // Signature
        write_le32(&mut buf, MDMP_SIGNATURE);
        // Version (valid) + impl version
        write_le16(&mut buf, MDMP_VALID_VERSION);
        write_le16(&mut buf, 0);
        // stream_count
        write_le32(&mut buf, stream_count);
        // stream_directory_rva (points right after 32-byte header)
        write_le32(&mut buf, 32);
        // checksum
        write_le32(&mut buf, 0);
        // timestamp
        write_le32(&mut buf, 0x6856_0000);
        // flags
        write_le64(&mut buf, 0x0000_0002_0000_0000);
        // pad to 32 bytes
        buf.resize(32, 0);
        // stream directory entries (12 bytes each)
        for i in 0..stream_count {
            write_le32(&mut buf, 3 + i); // ThreadListStream etc.
            write_le32(&mut buf, 64);
            write_le32(&mut buf, 0x200 + i * 64);
        }
        buf
    }

    #[test]
    fn test_parse_valid_minidump() {
        let bytes = make_minidump_bytes(2);
        let mut tmp = Builder::new().suffix(".dmp").tempfile().unwrap();
        tmp.write_all(&bytes).unwrap();
        let info = parse_minidump(tmp.path()).unwrap();
        assert_eq!(info.stream_count, 2);
        assert_eq!(info.streams.len(), 2);
        assert_eq!(info.streams[0].type_name, "ThreadListStream");
    }

    #[test]
    fn test_invalid_signature() {
        let mut tmp = Builder::new().suffix(".dmp").tempfile().unwrap();
        tmp.write_all(&[0u8; 64]).unwrap();
        let result = parse_minidump(tmp.path());
        assert!(matches!(result, Err(MemoryError::InvalidMinidumpSignature(_))));
    }
}
