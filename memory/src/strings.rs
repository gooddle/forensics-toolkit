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

    extract_from_reader(BufReader::new(file), min_length, unicode, CHUNK_SIZE)
}

// 청크 경계를 넘어 진행 중인 문자열 상태
#[derive(Default)]
struct Run<T> {
    start: Option<u64>,
    data: Vec<T>,
}

fn flush_ascii(run: &mut Run<u8>, min_len: usize, entries: &mut Vec<StringEntry>) {
    if let Some(start) = run.start.take()
        && run.data.len() >= min_len
    {
        entries.push(StringEntry {
            offset: start,
            kind: "ASCII".to_string(),
            value: String::from_utf8_lossy(&run.data).into_owned(),
        });
    }
    run.data.clear();
}

fn flush_utf16(run: &mut Run<u16>, min_len: usize, entries: &mut Vec<StringEntry>) {
    if let Some(start) = run.start.take()
        && run.data.len() >= min_len
    {
        entries.push(StringEntry {
            offset: start,
            kind: "UTF-16LE".to_string(),
            value: String::from_utf16_lossy(&run.data),
        });
    }
    run.data.clear();
}

fn extract_from_reader<R: Read>(
    mut reader: R,
    min_length: usize,
    unicode: bool,
    chunk_size: usize,
) -> Result<Vec<StringEntry>, MemoryError> {
    let mut entries = Vec::new();
    // buf[0] 은 이전 청크에서 짝을 못 이룬 UTF-16 바이트 1개를 이어받는 자리
    let mut buf = vec![0u8; chunk_size + 1];
    let min_len = min_length.max(MIN_LENGTH);
    let mut ascii = Run::default();
    let mut utf16 = Run::default();
    // buf[0] 의 전역 오프셋과 이어받은 바이트 수(0 또는 1)
    let mut base_offset: u64 = 0;
    let mut carry = 0usize;

    loop {
        let n = reader.read(&mut buf[carry..])?;
        if n == 0 {
            break;
        }
        let total = carry + n;

        // ASCII 문자열 추출 (이어받은 바이트는 이전 청크에서 이미 처리됨)
        for (i, &b) in buf[carry..total].iter().enumerate() {
            if is_printable_ascii(b) {
                if ascii.start.is_none() {
                    ascii.start = Some(base_offset + (carry + i) as u64);
                }
                ascii.data.push(b);
            } else {
                flush_ascii(&mut ascii, min_len, &mut entries);
            }
        }

        // Unicode(UTF-16LE) 문자열 추출
        let mut i = 0;
        if unicode {
            while i + 1 < total {
                let lo = buf[i];
                let hi = buf[i + 1];
                if is_printable_ascii(lo) && hi == 0x00 {
                    if utf16.start.is_none() {
                        utf16.start = Some(base_offset + i as u64);
                    }
                    utf16.data.push(u16::from(lo));
                    i += 2;
                } else {
                    flush_utf16(&mut utf16, min_len, &mut entries);
                    i += 1;
                }
            }
        } else {
            i = total;
        }

        // 짝을 못 이룬 마지막 바이트는 다음 청크 앞으로 이어받는다
        carry = total - i;
        if carry > 0 {
            buf[0] = buf[i];
        }
        base_offset += i as u64;
    }

    // 파일 끝에서 끝나는 문자열 flush
    flush_ascii(&mut ascii, min_len, &mut entries);
    flush_utf16(&mut utf16, min_len, &mut entries);

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

    fn extract_bytes(data: &[u8], unicode: bool, chunk: usize) -> Vec<StringEntry> {
        extract_from_reader(std::io::Cursor::new(data), 4, unicode, chunk).unwrap()
    }

    fn utf16(s: &str) -> Vec<u8> {
        s.bytes().flat_map(|b| [b, 0]).collect()
    }

    #[test]
    fn test_ascii_string_across_chunk_boundary() {
        // chunk 8: "abcdefghij" 가 6..16 에 걸쳐 두 청크로 나뉨
        let mut data = vec![0u8; 6];
        data.extend_from_slice(b"abcdefghij");
        data.push(0);
        let e = extract_bytes(&data, false, 8);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].value, "abcdefghij");
        assert_eq!(e[0].offset, 6);
    }

    #[test]
    fn test_ascii_string_at_eof_flushed() {
        let mut data = vec![0u8; 3];
        data.extend_from_slice(b"tailstring");
        let e = extract_bytes(&data, false, 4);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].value, "tailstring");
        assert_eq!(e[0].offset, 3);
    }

    #[test]
    fn test_utf16_string_at_eof_flushed() {
        let mut data = vec![0xFFu8; 2];
        data.extend_from_slice(&utf16("hello"));
        let e = extract_bytes(&data, true, 1024);
        let u: Vec<_> = e.iter().filter(|x| x.kind == "UTF-16LE").collect();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].value, "hello");
        assert_eq!(u[0].offset, 2);
    }

    #[test]
    fn test_utf16_string_across_chunk_boundary() {
        // 짝수/홀수 정렬 모두: 경계가 문자 쌍 사이 또는 쌍 가운데에 걸리도록
        for chunk in [5usize, 6, 7, 8] {
            for prefix in [1usize, 2, 3] {
                let mut data = vec![0xFFu8; prefix];
                data.extend_from_slice(&utf16("forensic"));
                data.push(0xFF);
                let e = extract_bytes(&data, true, chunk);
                let u: Vec<_> = e.iter().filter(|x| x.kind == "UTF-16LE").collect();
                assert_eq!(u.len(), 1, "chunk={chunk} prefix={prefix} {e:?}");
                assert_eq!(u[0].value, "forensic");
                assert_eq!(u[0].offset, prefix as u64);
            }
        }
    }

    #[test]
    fn test_chunked_matches_single_pass() {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x00alpha beta\x00\x01");
        data.extend_from_slice(&utf16("widestring"));
        data.extend_from_slice(b"\x02gamma");
        let one = extract_bytes(&data, true, 4096);
        for chunk in 1..=9 {
            let many = extract_bytes(&data, true, chunk);
            let a: Vec<_> = one.iter().map(|x| (x.offset, &x.kind, &x.value)).collect();
            let mut b: Vec<_> = many.iter().map(|x| (x.offset, &x.kind, &x.value)).collect();
            let mut a_sorted = a.clone();
            a_sorted.sort();
            b.sort();
            assert_eq!(a_sorted, b, "chunk={chunk}");
        }
    }

    #[test]
    fn test_offset_tracking() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"\x00\x00\x00hello\x00").unwrap();
        let entries = extract_strings(tmp.path(), 4, false).unwrap();
        assert_eq!(entries[0].offset, 3);
    }
}
