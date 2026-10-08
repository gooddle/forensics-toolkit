use memory::{extract_strings, parse_minidump, scan_pattern};
use std::io::Write;
use tempfile::NamedTempFile;

const MB: usize = 1024 * 1024;

fn temp_with(bytes: &[u8]) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(bytes).unwrap();
    tmp.flush().unwrap();
    tmp
}

#[test]
fn scan_match_in_overlap_reported_once_at_real_chunk_size() {
    // 첫 read 는 CHUNK+OVERLAP 바이트를 채우므로 매칭을 그 끝 256B 안에 둔다
    let mut data = vec![0u8; 3 * MB];
    let pos = MB + 100;
    data[pos..pos + 7].copy_from_slice(b"cmd.exe");
    let tmp = temp_with(&data);
    let m = scan_pattern(tmp.path(), r"cmd\.exe").unwrap();
    assert_eq!(
        m.len(),
        1,
        "offsets: {:?}",
        m.iter().map(|x| x.offset).collect::<Vec<_>>()
    );
    assert_eq!(m[0].offset, pos as u64);
}

#[test]
fn ascii_string_across_real_chunk_boundary() {
    let mut data = vec![0u8; 2 * MB];
    let s = b"abcdefghij";
    let pos = MB - 2;
    data[pos..pos + s.len()].copy_from_slice(s);
    let tmp = temp_with(&data);
    let e = extract_strings(tmp.path(), 4, false).unwrap();
    assert_eq!(e.len(), 1, "{e:?}");
    assert_eq!(e[0].value, "abcdefghij");
    assert_eq!(e[0].offset, pos as u64);
}

#[test]
fn utf16_string_at_eof_flushed() {
    let mut data = vec![0u8; 8];
    for c in b"hello" {
        data.extend_from_slice(&[*c, 0]);
    }
    let tmp = temp_with(&data);
    let e = extract_strings(tmp.path(), 4, true).unwrap();
    assert!(
        e.iter().any(|x| x.kind == "UTF-16LE" && x.value == "hello"),
        "{e:?}"
    );
}

#[test]
fn minidump_huge_stream_count_does_not_allocate() {
    let mut b = Vec::new();
    b.extend_from_slice(&0x504D_444Du32.to_le_bytes());
    b.extend_from_slice(&0xA793u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&u32::MAX.to_le_bytes());
    b.extend_from_slice(&32u32.to_le_bytes());
    b.resize(32, 0);
    for i in 0..2u32 {
        b.extend_from_slice(&(3 + i).to_le_bytes());
        b.extend_from_slice(&64u32.to_le_bytes());
        b.extend_from_slice(&0x200u32.to_le_bytes());
    }
    let tmp = temp_with(&b);
    let info = parse_minidump(tmp.path()).unwrap();
    assert_eq!(info.stream_count, u32::MAX);
    assert_eq!(info.streams.len(), 2);
    assert_eq!(info.streams_missing, u32::MAX - 2);
}
