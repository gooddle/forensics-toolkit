use crate::error::NetworkError;
use common::{format_unix_ts, hash_file};
use pcap_file::pcap::PcapReader;
use serde::Serialize;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct PcapInfo {
    pub path: String,
    pub size_bytes: u64,
    pub md5: String,
    pub sha256: String,
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub datalink: String,
    pub packet_count: u64,
    pub first_ts: String,
    pub last_ts: String,
    pub analyzed_at: String,
}

pub fn analyze_pcap(path: &Path) -> Result<PcapInfo, NetworkError> {
    let hash = hash_file(path).map_err(NetworkError::Other)?;

    let file = File::open(path).map_err(|e| NetworkError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = PcapReader::new(file)
        .map_err(|e| NetworkError::ParseFailed(e.to_string()))?;

    let header = reader.header();
    let datalink = format!("{:?}", header.datalink);
    let version_major = header.version_major;
    let version_minor = header.version_minor;
    let snaplen = header.snaplen;

    let mut packet_count: u64 = 0;
    let mut first_secs: Option<u64> = None;
    let mut last_secs: u64 = 0;

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| NetworkError::ParseFailed(e.to_string()))?;
        let secs = pkt.timestamp.as_secs();
        if first_secs.is_none() {
            first_secs = Some(secs);
        }
        last_secs = secs;
        packet_count += 1;
    }

    let first_ts = first_secs
        .map(|s| format_unix_ts(s as i64))
        .unwrap_or_else(|| "-".to_string());
    let last_ts = if packet_count > 0 {
        format_unix_ts(last_secs as i64)
    } else {
        "-".to_string()
    };

    Ok(PcapInfo {
        path: path.display().to_string(),
        size_bytes: hash.size_bytes,
        md5: hash.md5,
        sha256: hash.sha256,
        version_major,
        version_minor,
        snaplen,
        datalink,
        packet_count,
        first_ts,
        last_ts,
        analyzed_at: format_unix_ts(chrono::Utc::now().timestamp()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::Builder;

    fn minimal_pcap() -> Vec<u8> {
        // global header (24 bytes) + one tiny packet (16 + 14 bytes)
        let mut v: Vec<u8> = Vec::new();
        // magic LE
        v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes()); // major
        v.extend_from_slice(&4u16.to_le_bytes()); // minor
        v.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        // packet record
        v.extend_from_slice(&1700000001u32.to_le_bytes()); // ts_sec
        v.extend_from_slice(&0u32.to_le_bytes()); // ts_frac
        let data = vec![0u8; 14];
        v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // incl_len
        v.extend_from_slice(&(data.len() as u32).to_le_bytes()); // orig_len
        v.extend_from_slice(&data);
        v
    }

    #[test]
    fn test_analyze_pcap_basic() {
        let mut tmp = Builder::new().suffix(".pcap").tempfile().unwrap();
        tmp.write_all(&minimal_pcap()).unwrap();
        let info = analyze_pcap(tmp.path()).unwrap();
        assert_eq!(info.packet_count, 1);
        assert_eq!(info.version_major, 2);
        assert_eq!(info.version_minor, 4);
        assert_eq!(info.datalink, "ETHERNET");
    }
}
