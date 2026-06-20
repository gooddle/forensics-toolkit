use crate::error::MemoryError;
use regex::bytes::Regex;
use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const CHUNK_SIZE: usize = 1024 * 1024;
const OVERLAP: usize = 256;

#[derive(Debug, Serialize)]
pub struct ScanMatch {
    pub offset: u64,
    pub pattern: String,
    pub matched: String,
}

pub fn scan_pattern(
    path: &Path,
    pattern: &str,
) -> Result<Vec<ScanMatch>, MemoryError> {
    let re = Regex::new(pattern)
        .map_err(|e| MemoryError::InvalidPattern(e.to_string()))?;

    let file = File::open(path).map_err(|e| MemoryError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = BufReader::new(file);
    let mut matches = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE + OVERLAP];
    let mut global_offset: u64 = 0;
    let mut leftover = 0usize;

    loop {
        let n = reader.read(&mut buf[leftover..])?;
        if n == 0 {
            break;
        }
        let total = leftover + n;

        for m in re.find_iter(&buf[..total]) {
            let offset = global_offset + m.start() as u64;
            let matched = String::from_utf8_lossy(m.as_bytes())
                .chars()
                .take(128)
                .collect();
            matches.push(ScanMatch {
                offset,
                pattern: pattern.to_string(),
                matched,
            });
        }

        // 청크 경계 걸친 매칭을 위해 끝부분 유지
        if total > OVERLAP {
            buf.copy_within(total - OVERLAP..total, 0);
            leftover = OVERLAP;
            global_offset += (total - OVERLAP) as u64;
        } else {
            leftover = total;
            global_offset += total as u64;
        }
    }

    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_scan_finds_ipv4() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"connect to 192.168.1.1 failed").unwrap();
        let matches = scan_pattern(tmp.path(), r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched, "192.168.1.1");
    }

    #[test]
    fn test_scan_invalid_pattern_error() {
        let tmp = NamedTempFile::new().unwrap();
        let result = scan_pattern(tmp.path(), r"[invalid");
        assert!(matches!(result, Err(MemoryError::InvalidPattern(_))));
    }

    #[test]
    fn test_scan_offset_correct() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"AAAA cmd.exe BBBB").unwrap();
        let matches = scan_pattern(tmp.path(), r"cmd\.exe").unwrap();
        assert_eq!(matches[0].offset, 5);
    }
}
