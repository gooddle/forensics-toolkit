use crate::error::NetworkError;
use crate::reader::{Extraction, scan_packets};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::Serialize;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct DnsEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub transaction_id: u16,
    pub is_response: bool,
    pub questions: Vec<String>,
    pub answers: Vec<String>,
    /// 형식 오류로 건너뛴 응답 레코드 수
    pub malformed_answers: usize,
}

/// DNS 이름 최대 길이 (와이어 포맷 기준, RFC 1035 §2.3.4)
const MAX_NAME_LEN: usize = 255;
/// 압축 포인터 최대 점프 횟수 (역방향 강제로 이미 유한하지만 비용 상한을 둔다)
const MAX_POINTER_JUMPS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
enum DnsNameError {
    /// 데이터 경계를 벗어남
    OutOfBounds,
    /// 포인터가 현재 구간 시작보다 앞쪽(작은 오프셋)을 가리키지 않음 (자기참조/순환 포함)
    ForwardPointer,
    /// 포인터 점프 횟수 초과
    TooManyJumps,
    /// 이름 총 길이 255 초과
    NameTooLong,
    /// 라벨 길이 상위 2비트가 예약값(01/10)
    ReservedLabelType,
}

fn parse_dns_name(data: &[u8], offset: usize) -> Result<(String, usize), DnsNameError> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    // 현재 읽는 구간의 시작 오프셋. 포인터는 이보다 앞쪽만 가리킬 수 있어 순환이 불가능하다.
    let mut segment_start = offset;
    let mut jumps = 0usize;
    let mut end_pos: Option<usize> = None;
    // 와이어 포맷 길이: 각 라벨(길이 바이트 + 내용) + 종료 0 바이트
    let mut wire_len = 1usize;

    loop {
        let len = *data.get(pos).ok_or(DnsNameError::OutOfBounds)? as usize;
        match len & 0xC0 {
            0x00 => {}
            0xC0 => {
                let lo = *data.get(pos + 1).ok_or(DnsNameError::OutOfBounds)? as usize;
                if end_pos.is_none() {
                    end_pos = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsNameError::TooManyJumps);
                }
                let ptr = ((len & 0x3F) << 8) | lo;
                if ptr >= segment_start {
                    return Err(DnsNameError::ForwardPointer);
                }
                pos = ptr;
                segment_start = ptr;
                continue;
            }
            _ => return Err(DnsNameError::ReservedLabelType),
        }
        if len == 0 {
            let end = end_pos.unwrap_or(pos + 1);
            return Ok((labels.join("."), end));
        }
        wire_len += len + 1;
        if wire_len > MAX_NAME_LEN {
            return Err(DnsNameError::NameTooLong);
        }
        let label = data
            .get(pos + 1..pos + 1 + len)
            .ok_or(DnsNameError::OutOfBounds)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "?",
    }
}

/// rdata 범위 [start, start+rdlen) 안에서 끝나는 이름을 파싱한다 (압축 포인터는 메시지 전체 기준)
fn parse_rdata_name(payload: &[u8], start: usize, rd_end: usize) -> Option<String> {
    let (name, end) = parse_dns_name(payload, start).ok()?;
    (end <= rd_end).then_some(name)
}

/// 응답 레코드 rdata 해석. 형식이 잘못되면 None (해당 레코드만 건너뜀)
fn parse_rdata(payload: &[u8], rtype: u16, start: usize, rdlen: usize) -> Option<String> {
    let rd_end = start + rdlen;
    let rdata = payload.get(start..rd_end)?;
    match rtype {
        1 => {
            let arr: [u8; 4] = rdata.try_into().ok()?;
            Some(IpAddr::from(arr).to_string())
        }
        28 => {
            let arr: [u8; 16] = rdata.try_into().ok()?;
            Some(IpAddr::from(arr).to_string())
        }
        2 | 5 | 12 => parse_rdata_name(payload, start, rd_end),
        15 => {
            // MX: preference(2) + exchange 이름
            let pref = u16::from_be_bytes([*rdata.first()?, *rdata.get(1)?]);
            let exchange = parse_rdata_name(payload, start + 2, rd_end)?;
            Some(format!("{pref} {exchange}"))
        }
        16 => {
            // TXT: 하나 이상의 <길이 1바이트><문자열>
            if rdata.is_empty() {
                return None;
            }
            let mut parts = Vec::new();
            let mut i = 0usize;
            while i < rdata.len() {
                let n = rdata[i] as usize;
                let s = rdata.get(i + 1..i + 1 + n)?;
                parts.push(format!("\"{}\"", String::from_utf8_lossy(s)));
                i += 1 + n;
            }
            Some(parts.join(" "))
        }
        _ => Some(format!("<{} {rdlen} bytes>", type_name(rtype))),
    }
}

/// 파싱된 DNS 메시지
#[derive(Debug)]
struct DnsMessage {
    txid: u16,
    is_response: bool,
    questions: Vec<String>,
    answers: Vec<String>,
    /// 형식 오류로 건너뛴 응답 레코드 수
    malformed_answers: usize,
}

fn parse_dns(payload: &[u8]) -> Option<DnsMessage> {
    if payload.len() < 12 {
        return None;
    }

    let txid = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let is_response = (flags & 0x8000) != 0;
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let ancount = u16::from_be_bytes([payload[6], payload[7]]) as usize;

    let mut questions = Vec::new();
    let mut pos = 12usize;

    for _ in 0..qdcount {
        // 질의 이름이 깨지면 이후 레코드 위치를 알 수 없으므로 메시지를 손상으로 본다
        let (name, next) = parse_dns_name(payload, pos).ok()?;
        pos = next;
        if pos + 4 > payload.len() {
            break;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        questions.push(format!("{name} ({})", type_name(qtype)));
        pos += 4;
    }

    let mut answers = Vec::new();
    let mut malformed_answers = 0usize;
    for parsed in 0..ancount {
        // 이름 또는 고정 필드가 깨지면 다음 레코드 경계를 알 수 없으므로
        // 남은 레코드 전체를 손상으로 집계하고 지금까지 파싱한 결과는 유지한다
        let Ok((name, next)) = parse_dns_name(payload, pos) else {
            malformed_answers += ancount - parsed;
            break;
        };
        pos = next;
        if pos + 10 > payload.len() {
            malformed_answers += ancount - parsed;
            break;
        }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let rdlen = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > payload.len() {
            malformed_answers += ancount - parsed;
            break;
        }
        // rdata 길이를 알고 있으므로 이 레코드만 건너뛰고 다음 레코드를 계속 파싱한다
        match parse_rdata(payload, rtype, pos, rdlen) {
            Some(val) => answers.push(format!("{name} -> {val}")),
            None => malformed_answers += 1,
        }
        pos += rdlen;
    }

    Some(DnsMessage {
        txid,
        is_response,
        questions,
        answers,
        malformed_answers,
    })
}

pub fn extract_dns(path: &Path) -> Result<Extraction<DnsEntry>, NetworkError> {
    let mut entries = Vec::new();
    let mut malformed: u64 = 0;

    let summary = scan_packets(path, |pkt| {
        let Ok(sliced) = SlicedPacket::from_ethernet(&pkt.data) else {
            malformed += 1;
            return;
        };

        let (src_ip, dst_ip) = match &sliced.net {
            Some(NetSlice::Ipv4(ip)) => {
                let h = ip.header();
                (
                    IpAddr::from(h.source()).to_string(),
                    IpAddr::from(h.destination()).to_string(),
                )
            }
            _ => return,
        };

        let udp_payload = match &sliced.transport {
            Some(TransportSlice::Udp(u)) if u.source_port() == 53 || u.destination_port() == 53 => {
                u.payload()
            }
            _ => return,
        };

        match parse_dns(udp_payload) {
            Some(msg) => entries.push(DnsEntry {
                src_ip,
                dst_ip,
                transaction_id: msg.txid,
                is_response: msg.is_response,
                questions: msg.questions,
                answers: msg.answers,
                malformed_answers: msg.malformed_answers,
            }),
            None => malformed += 1,
        }
    })?;

    Ok(Extraction {
        records: entries,
        skipped_packets: summary.skipped + malformed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_name_simple() {
        // \x07example\x03com\x00
        let data = b"\x07example\x03com\x00";
        let (name, end) = parse_dns_name(data, 0).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, data.len());
    }

    #[test]
    fn test_parse_dns_query() {
        let mut payload: Vec<u8> = Vec::new();
        payload.extend_from_slice(&0xabcdu16.to_be_bytes()); // txid
        payload.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: query
        payload.extend_from_slice(&0x0001u16.to_be_bytes()); // qdcount
        payload.extend_from_slice(&0x0000u16.to_be_bytes()); // ancount
        payload.extend_from_slice(&0x0000u16.to_be_bytes()); // nscount
        payload.extend_from_slice(&0x0000u16.to_be_bytes()); // arcount
        payload.extend_from_slice(b"\x07example\x03com\x00");
        payload.extend_from_slice(&0x0001u16.to_be_bytes()); // qtype A
        payload.extend_from_slice(&0x0001u16.to_be_bytes()); // qclass IN

        let msg = parse_dns(&payload).unwrap();
        assert_eq!(msg.txid, 0xabcd);
        assert!(!msg.is_response);
        assert_eq!(msg.questions[0], "example.com (A)");
    }

    /// 헤더 + example.com/A 질의 1개, 응답 레코드 수 지정
    fn response_header(ancount: u16) -> Vec<u8> {
        let mut p: Vec<u8> = Vec::new();
        p.extend_from_slice(&0x1234u16.to_be_bytes());
        p.extend_from_slice(&0x8180u16.to_be_bytes()); // 응답
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&ancount.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(&0u16.to_be_bytes());
        p.extend_from_slice(b"\x07example\x03com\x00"); // offset 12
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    /// 이름 = 포인터(0xC00C, example.com) 인 응답 레코드
    fn push_answer(p: &mut Vec<u8>, rtype: u16, rdata: &[u8]) {
        p.extend_from_slice(&[0xC0, 0x0C]);
        p.extend_from_slice(&rtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // class IN
        p.extend_from_slice(&300u32.to_be_bytes()); // TTL
        p.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        p.extend_from_slice(rdata);
    }

    #[test]
    fn test_name_self_pointer_is_error() {
        // 오프셋 12에 자기 자신을 가리키는 포인터(C0 0C) → 무한 루프 대신 에러
        let mut data = vec![0u8; 12];
        data.extend_from_slice(&[0xC0, 0x0C]);
        assert_eq!(parse_dns_name(&data, 12), Err(DnsNameError::ForwardPointer));
    }

    #[test]
    fn test_name_pointer_cycle_is_error() {
        // 0: \x01a + 포인터→4, 4: 포인터→0 (서로 가리키는 순환)
        let data = [0x01, b'a', 0xC0, 0x04, 0xC0, 0x00];
        assert!(parse_dns_name(&data, 0).is_err());
        assert!(parse_dns_name(&data, 4).is_err());
    }

    #[test]
    fn test_name_pointer_into_own_label_is_error() {
        // 10: \x03abc + 포인터→12 (현재 구간 내부를 가리켜 순환 가능) → 에러
        let mut data = vec![0u8; 10];
        data.extend_from_slice(&[0x03, b'a', b'b', b'c', 0xC0, 0x0C]);
        assert_eq!(parse_dns_name(&data, 10), Err(DnsNameError::ForwardPointer));
    }

    #[test]
    fn test_name_backward_pointer_chain_ok() {
        // 0: \x03com\x00, 5: \x07example + 포인터→0, 15: \x03www + 포인터→5
        let mut data = b"\x03com\x00\x07example".to_vec();
        data.extend_from_slice(&[0xC0, 0x00]);
        data.extend_from_slice(b"\x03www");
        data.extend_from_slice(&[0xC0, 0x05]);
        let (name, end) = parse_dns_name(&data, 15).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!(end, data.len());
    }

    #[test]
    fn test_name_too_long_is_error() {
        // 63바이트 라벨 4개 = 와이어 길이 4*64+1 = 257 > 255
        let mut data = Vec::new();
        for _ in 0..4 {
            data.push(63);
            data.extend_from_slice(&[b'a'; 63]);
        }
        data.push(0);
        assert_eq!(parse_dns_name(&data, 0), Err(DnsNameError::NameTooLong));
    }

    #[test]
    fn test_name_reserved_label_bits_are_error() {
        for first in [0x40u8, 0x80u8] {
            let data = [first, b'a', 0x00];
            assert_eq!(
                parse_dns_name(&data, 0),
                Err(DnsNameError::ReservedLabelType)
            );
        }
    }

    #[test]
    fn test_bad_record_skipped_others_kept() {
        let mut p = response_header(3);
        push_answer(&mut p, 1, &[93, 184, 216, 34]);
        push_answer(&mut p, 1, &[1, 2, 3]); // A 레코드인데 rdlen=3 → 이 레코드만 건너뜀
        push_answer(&mut p, 28, &[0u8; 16]);
        let msg = parse_dns(&p).unwrap();
        assert_eq!(
            msg.answers,
            vec!["example.com -> 93.184.216.34", "example.com -> ::"]
        );
        assert_eq!(msg.malformed_answers, 1);
    }

    #[test]
    fn test_broken_record_name_keeps_previous_answers() {
        let mut p = response_header(2);
        push_answer(&mut p, 1, &[10, 0, 0, 1]);
        p.extend_from_slice(&[0xC0, 0xFF]); // 전방 포인터 → 이후 경계 불명
        let msg = parse_dns(&p).unwrap();
        assert_eq!(msg.answers, vec!["example.com -> 10.0.0.1"]);
        assert_eq!(msg.malformed_answers, 1);
    }

    #[test]
    fn test_mx_rdata() {
        let mut p = response_header(1);
        let mut rdata = 10u16.to_be_bytes().to_vec();
        rdata.extend_from_slice(b"\x04mail");
        rdata.extend_from_slice(&[0xC0, 0x0C]);
        push_answer(&mut p, 15, &rdata);
        let msg = parse_dns(&p).unwrap();
        assert_eq!(msg.answers, vec!["example.com -> 10 mail.example.com"]);
        assert_eq!(msg.malformed_answers, 0);
    }

    #[test]
    fn test_txt_rdata_multiple_strings() {
        let mut p = response_header(1);
        push_answer(&mut p, 16, b"\x0bv=spf1 -all\x03foo");
        let msg = parse_dns(&p).unwrap();
        assert_eq!(msg.answers, vec!["example.com -> \"v=spf1 -all\" \"foo\""]);
    }

    #[test]
    fn test_txt_rdata_overrun_is_skipped() {
        let mut p = response_header(2);
        push_answer(&mut p, 16, b"\x09short"); // 길이 9 선언, 실제 5
        push_answer(&mut p, 1, &[1, 1, 1, 1]);
        let msg = parse_dns(&p).unwrap();
        assert_eq!(msg.answers, vec!["example.com -> 1.1.1.1"]);
        assert_eq!(msg.malformed_answers, 1);
    }

    #[test]
    fn test_extract_dns_counts_malformed_packets() {
        use crate::reader::test_util::*;
        use std::io::Write;

        let mut good = response_header(1);
        push_answer(&mut good, 1, &[8, 8, 8, 8]);
        let mut v = pcap_header();
        push_packet(
            &mut v,
            &ipv4_frame(17, [8, 8, 8, 8], [10, 0, 0, 2], 53, 5555, &good),
        );
        // 12바이트 미만 DNS 페이로드 → 손상 패킷
        push_packet(
            &mut v,
            &ipv4_frame(17, [8, 8, 8, 8], [10, 0, 0, 2], 53, 5555, &[1, 2]),
        );
        // 질의 이름이 자기참조 포인터인 패킷도 루프 없이 손상으로 처리
        let mut looped = response_header(0);
        looped.truncate(12);
        looped.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1]);
        push_packet(
            &mut v,
            &ipv4_frame(17, [8, 8, 8, 8], [10, 0, 0, 2], 53, 5555, &looped),
        );
        push_packet(
            &mut v,
            &ipv4_frame(17, [8, 8, 8, 8], [10, 0, 0, 2], 53, 5555, &good),
        );

        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&v).unwrap();
        let result = extract_dns(tmp.path()).unwrap();
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.skipped_packets, 2);
        assert_eq!(result.records[0].answers, vec!["example.com -> 8.8.8.8"]);
    }
}
