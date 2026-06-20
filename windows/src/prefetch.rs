use crate::error::WindowsError;
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

const SCCA_SIGNATURE: u32 = 0x4143_4353; // "SCCA" LE

// FILETIME epoch offset: 100-ns ticks from 1601-01-01 to 1970-01-01
const FILETIME_EPOCH_DIFF_SECS: i64 = 11_644_473_600;

#[derive(Debug, Serialize)]
pub struct PrefetchInfo {
    pub path: String,
    pub version: u32,
    pub executable_name: String,
    pub prefetch_hash: String,
    pub run_count: u32,
    pub last_run_time: String,
    pub referenced_files: Vec<String>,
}

fn filetime_to_unix(ft: u64) -> i64 {
    (ft / 10_000_000) as i64 - FILETIME_EPOCH_DIFF_SECS
}

fn read_utf16le_name(buf: &[u8]) -> String {
    let words: Vec<u16> = buf
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&w| w != 0)
        .collect();
    String::from_utf16_lossy(&words).to_owned()
}

pub fn parse_prefetch(path: &Path) -> Result<PrefetchInfo, WindowsError> {
    let file = File::open(path).map_err(|e| WindowsError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut r = BufReader::new(file);

    let version = r.read_u32::<LittleEndian>()?;
    let signature = r.read_u32::<LittleEndian>()?;

    if signature != SCCA_SIGNATURE {
        return Err(WindowsError::InvalidPrefetchSignature);
    }

    match version {
        17 | 23 | 26 => {}
        v => return Err(WindowsError::UnsupportedPrefetchVersion(v)),
    }

    let _unknown = r.read_u32::<LittleEndian>()?;
    let _file_size = r.read_u32::<LittleEndian>()?;

    // Executable name: 60 bytes UTF-16LE at offset 0x10
    let mut name_buf = [0u8; 60];
    r.read_exact(&mut name_buf)?;
    let executable_name = read_utf16le_name(&name_buf);

    let prefetch_hash = r.read_u32::<LittleEndian>()?;

    // File metrics info (offsets and counts) — at 0x54 for all supported versions
    r.seek(SeekFrom::Start(0x54))?;
    let metrics_offset = r.read_u32::<LittleEndian>()?;
    let metrics_count = r.read_u32::<LittleEndian>()?;
    let _trace_chains_offset = r.read_u32::<LittleEndian>()?;
    let _trace_chains_count = r.read_u32::<LittleEndian>()?;
    let filenames_offset = r.read_u32::<LittleEndian>()?;
    let filenames_size = r.read_u32::<LittleEndian>()?;

    // Last run time + run count — version-specific offsets
    let (last_run_offset, run_count_offset) = match version {
        17 => (0x78u64, 0x90u64),
        23 => (0x78u64, 0x98u64),
        26 => (0x80u64, 0xD0u64),
        _ => unreachable!(),
    };

    r.seek(SeekFrom::Start(last_run_offset))?;
    let last_run_ft = r.read_u64::<LittleEndian>()?;
    let last_run_unix = filetime_to_unix(last_run_ft);
    let last_run_time = common::format_unix_ts(last_run_unix);

    r.seek(SeekFrom::Start(run_count_offset))?;
    let run_count = r.read_u32::<LittleEndian>()?;

    // Referenced filenames string block
    let referenced_files = if filenames_size > 0 && filenames_offset > 0 {
        r.seek(SeekFrom::Start(filenames_offset as u64))?;
        let mut buf = vec![0u8; filenames_size as usize];
        r.read_exact(&mut buf)?;
        // Null-separated UTF-16LE strings (double-null terminated entries)
        parse_filename_block(&buf, metrics_count as usize)
    } else {
        Vec::new()
    };

    // suppress unused variable warning
    let _ = metrics_offset;

    Ok(PrefetchInfo {
        path: path.display().to_string(),
        version,
        executable_name,
        prefetch_hash: format!("{prefetch_hash:08X}"),
        run_count,
        last_run_time,
        referenced_files,
    })
}

fn parse_filename_block(buf: &[u8], max: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut pos = 0usize;

    while pos + 1 < buf.len() && result.len() < max {
        if buf[pos] == 0 && buf[pos + 1] == 0 {
            pos += 2;
            continue;
        }
        let start = pos;
        while pos + 1 < buf.len() {
            if buf[pos] == 0 && buf[pos + 1] == 0 {
                break;
            }
            pos += 2;
        }
        let s = read_utf16le_name(&buf[start..pos]);
        if !s.is_empty() {
            result.push(s);
        }
        pos += 2;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::WriteBytesExt;
    use std::io::Write;
    use tempfile::Builder;

    fn make_prefetch_v23() -> Vec<u8> {
        let mut buf = vec![0u8; 0x200];

        // version = 23 at offset 0
        (&mut buf[0..4]).write_u32::<LittleEndian>(23).unwrap();
        // signature "SCCA" at offset 4
        (&mut buf[4..8]).copy_from_slice(b"SCCA");
        // file size at offset 12
        (&mut buf[12..16]).write_u32::<LittleEndian>(0x200).unwrap();

        // executable name at offset 16 (UTF-16LE "CMD.EXE")
        let name: Vec<u16> = "CMD.EXE".encode_utf16().collect();
        for (i, &w) in name.iter().enumerate() {
            (&mut buf[16 + i * 2..16 + i * 2 + 2])
                .write_u16::<LittleEndian>(w)
                .unwrap();
        }

        // prefetch hash at offset 76
        (&mut buf[76..80]).write_u32::<LittleEndian>(0xDEADBEEF).unwrap();

        // metrics offset/count, etc. at 0x54
        (&mut buf[0x54..0x58]).write_u32::<LittleEndian>(0).unwrap(); // metrics offset
        (&mut buf[0x58..0x5C]).write_u32::<LittleEndian>(0).unwrap(); // metrics count
        (&mut buf[0x5C..0x60]).write_u32::<LittleEndian>(0).unwrap(); // trace offset
        (&mut buf[0x60..0x64]).write_u32::<LittleEndian>(0).unwrap(); // trace count
        (&mut buf[0x64..0x68]).write_u32::<LittleEndian>(0).unwrap(); // filenames offset
        (&mut buf[0x68..0x6C]).write_u32::<LittleEndian>(0).unwrap(); // filenames size

        // last run time at 0x78 — FILETIME for 2024-01-01 00:00:00 UTC
        // 2024-01-01 = Unix 1704067200 -> FILETIME = (1704067200 + 11644473600) * 10000000
        let ft: u64 = (1_704_067_200u64 + 11_644_473_600u64) * 10_000_000;
        (&mut buf[0x78..0x80]).write_u64::<LittleEndian>(ft).unwrap();

        // run count at 0x98 (v23)
        (&mut buf[0x98..0x9C]).write_u32::<LittleEndian>(42).unwrap();

        buf
    }

    #[test]
    fn test_parse_prefetch_v23() {
        let mut tmp = Builder::new().suffix(".pf").tempfile().unwrap();
        tmp.write_all(&make_prefetch_v23()).unwrap();
        let info = parse_prefetch(tmp.path()).unwrap();
        assert_eq!(info.version, 23);
        assert_eq!(info.executable_name, "CMD.EXE");
        assert_eq!(info.run_count, 42);
        assert_eq!(info.prefetch_hash, "DEADBEEF");
    }

    #[test]
    fn test_invalid_signature() {
        let buf = vec![0u8; 256];
        let mut tmp = Builder::new().suffix(".pf").tempfile().unwrap();
        tmp.write_all(&buf).unwrap();
        assert!(matches!(
            parse_prefetch(tmp.path()),
            Err(WindowsError::InvalidPrefetchSignature)
        ));
    }
}
