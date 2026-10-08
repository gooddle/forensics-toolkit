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

pub fn scan_pattern(path: &Path, pattern: &str) -> Result<Vec<ScanMatch>, MemoryError> {
    let re = Regex::new(pattern).map_err(|e| MemoryError::InvalidPattern(e.to_string()))?;

    let file = File::open(path).map_err(|e| MemoryError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    scan_reader(BufReader::new(file), &re, pattern, CHUNK_SIZE, OVERLAP)
}

// 청크 단위 스캔. 각 매칭은 시작 오프셋 기준으로 정확히 한 번만 보고한다:
// 청크 끝 overlap 구간에서 시작한 매칭은 그 구간이 다음 청크 앞부분으로
// 이어질 때(또는 EOF 에서) 보고한다.
fn scan_reader<R: Read>(
    mut reader: R,
    re: &Regex,
    pattern: &str,
    chunk_size: usize,
    overlap: usize,
) -> Result<Vec<ScanMatch>, MemoryError> {
    let mut matches = Vec::new();
    let mut buf = vec![0u8; chunk_size + overlap];
    let mut global_offset: u64 = 0;
    let mut leftover = 0usize;
    // 이미 보고한 마지막 매칭의 전역 끝 오프셋 (비중첩 매칭 의미 유지)
    let mut reported_until: u64 = 0;

    loop {
        let n = reader.read(&mut buf[leftover..])?;
        let eof = n == 0;
        if eof && leftover == 0 {
            break;
        }
        let total = leftover + n;
        // EOF 가 아니면 끝 overlap 구간에서 시작하는 매칭은 다음 청크로 미룬다
        let cutoff = if eof {
            total
        } else {
            total.saturating_sub(overlap)
        };

        for m in re.find_iter(&buf[..total]) {
            if m.start() >= cutoff {
                break;
            }
            let offset = global_offset + m.start() as u64;
            if offset < reported_until {
                continue;
            }
            reported_until = global_offset + m.end() as u64;
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

        if eof {
            break;
        }

        // 청크 경계 걸친 매칭을 위해 끝부분 유지
        buf.copy_within(cutoff..total, 0);
        leftover = total - cutoff;
        global_offset += cutoff as u64;
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

    fn scan_bytes(data: &[u8], pattern: &str, chunk: usize, overlap: usize) -> Vec<ScanMatch> {
        let re = Regex::new(pattern).unwrap();
        scan_reader(std::io::Cursor::new(data), &re, pattern, chunk, overlap).unwrap()
    }

    #[test]
    fn test_scan_match_in_overlap_reported_once() {
        // chunk 16 + overlap 8: 첫 청크 24B 중 끝 8B(16..24) 안에 매칭
        let mut data = vec![0u8; 64];
        data[17..20].copy_from_slice(b"abc");
        let m = scan_bytes(&data, "abc", 16, 8);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 17);
    }

    #[test]
    fn test_scan_match_spanning_boundary_found() {
        let mut data = vec![0u8; 64];
        data[22..27].copy_from_slice(b"hello");
        let m = scan_bytes(&data, "hello", 16, 8);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 22);
    }

    #[test]
    fn test_scan_every_offset_reported_once() {
        let mut data = vec![b'.'; 200];
        let positions = [0usize, 13, 16, 21, 24, 47, 95, 197];
        for &p in &positions {
            data[p..p + 3].copy_from_slice(b"XYZ");
        }
        let m = scan_bytes(&data, "XYZ", 16, 8);
        let got: Vec<u64> = m.iter().map(|x| x.offset).collect();
        let want: Vec<u64> = positions.iter().map(|&p| p as u64).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn test_scan_match_at_eof_in_overlap() {
        let mut data = vec![0u8; 30];
        data[27..30].copy_from_slice(b"end");
        let m = scan_bytes(&data, "end", 16, 8);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].offset, 27);
    }

    #[test]
    fn test_scan_offset_correct() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"AAAA cmd.exe BBBB").unwrap();
        let matches = scan_pattern(tmp.path(), r"cmd\.exe").unwrap();
        assert_eq!(matches[0].offset, 5);
    }
}
