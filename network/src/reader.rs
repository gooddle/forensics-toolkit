use crate::error::NetworkError;
use pcap_file::pcap::{PcapHeader, PcapPacket, PcapReader};
use serde::Serialize;
use std::fs::File;
use std::path::Path;

/// 추출 결과와 손상으로 건너뛴 패킷 수
#[derive(Debug, Serialize)]
pub struct Extraction<T> {
    pub records: Vec<T>,
    /// 손상(레코드 헤더 오류, 링크/IP 계층 파싱 실패, 프로토콜 파싱 실패)으로 건너뛴 패킷 수
    pub skipped_packets: u64,
}

/// 패킷 순회 결과 요약
#[derive(Debug)]
pub(crate) struct ScanSummary {
    pub header: PcapHeader,
    /// 레코드 헤더가 손상되어 건너뛴 패킷 수 (잘린 꼬리 레코드 포함)
    pub skipped: u64,
}

/// PCAP 파일의 모든 패킷을 순회한다.
///
/// 파일 열기 실패·글로벌 헤더 손상은 에러로 반환한다.
/// 개별 레코드가 손상된 경우(incl_len > snaplen 등)는 해당 레코드만 건너뛰고,
/// 레코드 경계를 더 이상 신뢰할 수 없는 경우(잘린 파일 등)는 순회를 멈춘다.
/// 두 경우 모두 `skipped`에 반영된다.
// @MX:ANCHOR: [AUTO] 모든 패킷 분석 루프(info/connections/dns/http)의 공통 진입점
// @MX:REASON: 손상 레코드 처리 정책(건너뛰기 vs 중단)이 이 함수 한 곳에서 결정됨
pub(crate) fn scan_packets<F>(path: &Path, mut on_packet: F) -> Result<ScanSummary, NetworkError>
where
    F: FnMut(&PcapPacket<'_>),
{
    let file = File::open(path).map_err(|e| NetworkError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = PcapReader::new(file).map_err(|e| NetworkError::ParseFailed(e.to_string()))?;
    let header = reader.header();
    let mut skipped: u64 = 0;

    while let Some(raw) = reader.next_raw_packet() {
        // 원시 레코드 읽기 실패 시 리더 위치가 전진하지 않으므로 계속 읽으면 무한 루프가 된다.
        // 레코드 경계를 잃은 상태이므로 남은 데이터를 손상 1건으로 집계하고 중단한다.
        let Ok(raw) = raw else {
            skipped += 1;
            break;
        };
        // 원시 레코드는 이미 소비됐으므로 검증 실패 시 이 레코드만 건너뛸 수 있다.
        match raw.try_into_pcap_packet(header.ts_resolution, header.snaplen) {
            Ok(pkt) => on_packet(&pkt),
            Err(_) => skipped += 1,
        }
    }

    Ok(ScanSummary { header, skipped })
}

#[cfg(test)]
pub(crate) mod test_util {
    /// 테스트용 PCAP 글로벌 헤더 (LE, v2.4, snaplen 65535, ETHERNET)
    pub fn pcap_header() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v
    }

    /// 패킷 레코드 하나를 덧붙인다 (incl_len/orig_len을 직접 지정 가능)
    pub fn push_record(v: &mut Vec<u8>, data: &[u8], incl_len: u32, orig_len: u32) {
        v.extend_from_slice(&1700000001u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&incl_len.to_le_bytes());
        v.extend_from_slice(&orig_len.to_le_bytes());
        v.extend_from_slice(data);
    }

    /// 정상 패킷 레코드
    pub fn push_packet(v: &mut Vec<u8>, data: &[u8]) {
        let len = data.len() as u32;
        push_record(v, data, len, len);
    }

    /// Ethernet + IPv4 + (TCP|UDP) 프레임 생성
    pub fn ipv4_frame(
        proto: u8,
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let transport: Vec<u8> = if proto == 17 {
            let mut u = Vec::new();
            u.extend_from_slice(&src_port.to_be_bytes());
            u.extend_from_slice(&dst_port.to_be_bytes());
            u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            u.extend_from_slice(&0u16.to_be_bytes());
            u.extend_from_slice(payload);
            u
        } else {
            let mut t = Vec::new();
            t.extend_from_slice(&src_port.to_be_bytes());
            t.extend_from_slice(&dst_port.to_be_bytes());
            t.extend_from_slice(&1u32.to_be_bytes()); // seq
            t.extend_from_slice(&0u32.to_be_bytes()); // ack
            t.push(0x50); // data offset 5
            t.push(0x18); // PSH|ACK
            t.extend_from_slice(&65535u16.to_be_bytes()); // window
            t.extend_from_slice(&0u16.to_be_bytes()); // checksum
            t.extend_from_slice(&0u16.to_be_bytes()); // urgent
            t.extend_from_slice(payload);
            t
        };
        let mut ip = vec![0x45, 0];
        ip.extend_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, proto, 0, 0]);
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(&transport);

        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&[0x08, 0x00]);
        eth.extend_from_slice(&ip);
        eth
    }
}

#[cfg(test)]
mod tests {
    use super::test_util::*;
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tmp(bytes: &[u8]) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(bytes).unwrap();
        tmp
    }

    #[test]
    fn test_scan_skips_invalid_record_and_continues() {
        let mut v = pcap_header();
        push_packet(&mut v, &[0u8; 14]);
        // incl_len > orig_len: 레코드 검증 실패 → 이 레코드만 건너뜀
        push_record(&mut v, &[0u8; 14], 14, 10);
        push_packet(&mut v, &[0u8; 14]);
        let tmp = write_tmp(&v);

        let mut count = 0;
        let summary = scan_packets(tmp.path(), |_| count += 1).unwrap();
        assert_eq!(count, 2);
        assert_eq!(summary.skipped, 1);
    }

    #[test]
    fn test_scan_truncated_tail_stops_without_error() {
        let mut v = pcap_header();
        push_packet(&mut v, &[0u8; 14]);
        // 선언 길이 100이지만 실제 데이터는 5바이트뿐인 잘린 레코드
        push_record(&mut v, &[0u8; 5], 100, 100);
        let tmp = write_tmp(&v);

        let mut count = 0;
        let summary = scan_packets(tmp.path(), |_| count += 1).unwrap();
        assert_eq!(count, 1);
        assert_eq!(summary.skipped, 1);
    }

    #[test]
    fn test_scan_bad_global_header_is_error() {
        let tmp = write_tmp(b"not a pcap file at all, definitely");
        assert!(matches!(
            scan_packets(tmp.path(), |_| {}),
            Err(NetworkError::ParseFailed(_))
        ));
    }

    #[test]
    fn test_scan_missing_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.pcap");
        assert!(matches!(
            scan_packets(&path, |_| {}),
            Err(NetworkError::OpenFailed { .. })
        ));
    }
}
