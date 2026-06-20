use crate::error::MemoryError;
use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

const MIN_LENGTH: usize = 4;
const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Debug, Serialize)]
pub struct StringEntry {
    pub offset: u64,
    pub kind: String,
    pub value: String,
}

fn is_printable_ascii(b: u8) -> bool {
    (0x20..0x7F).contains(&b)
}

pub fn extract_strings(
    path: &Path,
    min_length: usize,
    unicode: bool,
) -> Result<Vec<StringEntry>, MemoryError> {
    let file = File::open(path).map_err(|e| MemoryError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut global_offset: u64 = 0;
    let min_len = min_length.max(MIN_LENGTH);

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }

        // ASCII 문자열 추출
        let mut start: Option<usize> = None;
        for (i, &b) in buf[..n].iter().enumerate() {
            if is_printable_ascii(b) {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                let len = i - s;
                if len >= min_len {
                    let value = String::from_utf8_lossy(&buf[s..i]).into_owned();
                    entries.push(StringEntry {
                        offset: global_offset + s as u64,
                        kind: "ASCII".to_string(),
                        value,
                    });
                }
            }
        }
        // 청크 끝에서 미완성 문자열 처리
        if let Some(s) = start {
            let len = n - s;
            if len >= min_len {
                let value = String::from_utf8_lossy(&buf[s..n]).into_owned();
                entries.push(StringEntry {
                    offset: global_offset + s as u64,
                    kind: "ASCII".to_string(),
                    value,
                });
            }
        }

        // Unicode(UTF-16LE) 문자열 추출
        if unicode && n >= 2 {
            let mut u_start: Option<usize> = None;
            let mut i = 0;
            while i + 1 < n {
                let lo = buf[i];
                let hi = buf[i + 1];
                if is_printable_ascii(lo) && hi == 0x00 {
                    if u_start.is_none() {
                        u_start = Some(i);
                    }
                    i += 2;
                } else {
                    if let Some(s) = u_start.take() {
                        let char_count = (i - s) / 2;
                        if char_count >= min_len {
                            let words: Vec<u16> = buf[s..i]
                                .chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect();
                            let value = String::from_utf16_lossy(&words);
                            entries.push(StringEntry {
                                offset: global_offset + s as u64,
                                kind: "UTF-16LE".to_string(),
                                value,
                            });
                        }
                    }
                    i += 1;
                }
            }
        }

        global_offset += n as u64;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_extract_ascii_strings() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"\x00\x00hello world\x00\x00test\x00").unwrap();
        let entries = extract_strings(tmp.path(), 4, false).unwrap();
        assert!(entries.iter().any(|e| e.value.contains("hello world")));
        assert!(entries.iter().any(|e| e.value == "test"));
    }

    #[test]
    fn test_min_length_filter() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"abc\x00abcdefgh\x00").unwrap();
        let entries = extract_strings(tmp.path(), 6, false).unwrap();
        assert!(!entries.iter().any(|e| e.value == "abc"));
        assert!(entries.iter().any(|e| e.value == "abcdefgh"));
    }

    #[test]
    fn test_offset_tracking() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"\x00\x00\x00hello\x00").unwrap();
        let entries = extract_strings(tmp.path(), 4, false).unwrap();
        assert_eq!(entries[0].offset, 3);
    }
}
