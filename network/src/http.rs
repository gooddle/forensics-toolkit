use crate::error::NetworkError;
use crate::reader::{Extraction, scan_packets};
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use serde::Serialize;
use std::net::IpAddr;
use std::path::Path;

const HTTP_PORTS: [u16; 2] = [80, 8080];
const HTTP_METHODS: [&str; 7] = [
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ",
];

#[derive(Debug, Serialize)]
pub struct HttpRequest {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub method: String,
    pub path: String,
    pub host: String,
    pub user_agent: String,
}

fn parse_http_request(payload: &[u8]) -> Option<(String, String, String, String)> {
    // 본문(바이너리일 수 있음)은 무시하고 헤더 영역만 디코딩한다.
    // 헤더 종료(\r\n\r\n)가 없으면(세그먼트 분할) 페이로드 전체를 헤더 후보로 본다.
    let head_end = payload
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(payload.len());
    let head = String::from_utf8_lossy(&payload[..head_end]);

    let method = HTTP_METHODS.iter().find(|&&m| head.starts_with(m))?;
    let method_str = method.trim_end().to_string();

    let mut lines = head.split("\r\n");
    let first_line = lines.next()?;
    // "GET /path HTTP/1.1"
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let path = parts[1].to_string();

    let mut host = String::new();
    let mut user_agent = String::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.eq_ignore_ascii_case("host") && host.is_empty() {
            host = value.trim().to_string();
        } else if name.eq_ignore_ascii_case("user-agent") && user_agent.is_empty() {
            user_agent = value.trim().to_string();
        }
    }

    Some((method_str, path, host, user_agent))
}

pub fn extract_http(path: &Path) -> Result<Extraction<HttpRequest>, NetworkError> {
    let mut requests = Vec::new();
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

        let (src_port, dst_port, tcp_payload) = match &sliced.transport {
            Some(TransportSlice::Tcp(t))
                if HTTP_PORTS.contains(&t.source_port())
                    || HTTP_PORTS.contains(&t.destination_port()) =>
            {
                (t.source_port(), t.destination_port(), t.payload())
            }
            _ => return,
        };

        if tcp_payload.is_empty() {
            return;
        }

        // 요청이 아닌 세그먼트(응답, 본문 조각)는 손상이 아니므로 집계하지 않는다
        if let Some((method, req_path, host, user_agent)) = parse_http_request(tcp_payload) {
            requests.push(HttpRequest {
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                method,
                path: req_path,
                host,
                user_agent,
            });
        }
    })?;

    Ok(Extraction {
        records: requests,
        skipped_packets: summary.skipped + malformed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get() {
        let payload =
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.0\r\n\r\n";
        let (method, path, host, ua) = parse_http_request(payload).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/index.html");
        assert_eq!(host, "example.com");
        assert_eq!(ua, "curl/7.0");
    }

    #[test]
    fn test_parse_http_post() {
        let payload = b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n{\"user\":\"test\"}";
        let (method, path, ..) = parse_http_request(payload).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/api/login");
    }

    #[test]
    fn test_parse_non_http_returns_none() {
        let payload = b"\x00\x01\x02\x03binary data";
        assert!(parse_http_request(payload).is_none());
    }

    #[test]
    fn test_parse_http_binary_body_still_parsed() {
        // 본문에 UTF-8이 아닌 바이트가 있어도 헤더만 디코딩하므로 요청을 놓치지 않는다
        let mut payload =
            b"POST /upload HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: x\r\n\r\n".to_vec();
        payload.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80, 0xc3]);
        let (method, path, host, ua) = parse_http_request(&payload).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/upload");
        assert_eq!(host, "evil.example");
        assert_eq!(ua, "x");
    }

    #[test]
    fn test_parse_http_header_case_and_spacing() {
        let payload = b"GET / HTTP/1.1\r\nhost:example.com\r\nUSER-AGENT:   Wget/1.21  \r\n\r\n";
        let (_, _, host, ua) = parse_http_request(payload).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(ua, "Wget/1.21");
    }

    #[test]
    fn test_parse_http_without_header_terminator() {
        // 헤더가 세그먼트 경계에서 잘린 경우에도 있는 만큼 파싱
        let payload = b"GET /a HTTP/1.1\r\nHost: h.example\r\nUser-Ag";
        let (_, path, host, ua) = parse_http_request(payload).unwrap();
        assert_eq!(path, "/a");
        assert_eq!(host, "h.example");
        assert_eq!(ua, "");
    }

    #[test]
    fn test_extract_http_skips_corrupt_record() {
        use crate::reader::test_util::*;
        use std::io::Write;

        let req = b"GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n";
        let frame = ipv4_frame(6, [10, 0, 0, 2], [10, 0, 0, 1], 40000, 80, req);
        let mut v = pcap_header();
        push_packet(&mut v, &frame);
        push_record(&mut v, &frame, frame.len() as u32, 1); // incl_len > orig_len
        push_packet(&mut v, &frame);
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&v).unwrap();

        let result = extract_http(tmp.path()).unwrap();
        assert_eq!(result.records.len(), 2);
        assert_eq!(result.skipped_packets, 1);
        assert_eq!(result.records[0].host, "a.example");
    }
}
