use crate::error::NetworkError;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use serde::Serialize;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;

const HTTP_PORTS: [u16; 2] = [80, 8080];
const HTTP_METHODS: [&str; 7] = ["GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "];

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
    let text = std::str::from_utf8(payload).ok()?;

    let method = HTTP_METHODS.iter().find(|&&m| text.starts_with(m))?;
    let method_str = method.trim_end().to_string();

    let first_line_end = text.find('\r')?;
    let first_line = &text[..first_line_end];
    // "GET /path HTTP/1.1"
    let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return None;
    }
    let path = parts[1].to_string();

    let host = extract_header(text, "Host").unwrap_or_default();
    let user_agent = extract_header(text, "User-Agent").unwrap_or_default();

    Some((method_str, path, host, user_agent))
}

fn extract_header(text: &str, name: &str) -> Option<String> {
    let search = format!("\r\n{name}: ");
    let start = text.find(&search)?;
    let value_start = start + search.len();
    let value_end = text[value_start..].find('\r')? + value_start;
    Some(text[value_start..value_end].to_string())
}

pub fn extract_http(path: &Path) -> Result<Vec<HttpRequest>, NetworkError> {
    let file = File::open(path).map_err(|e| NetworkError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = PcapReader::new(file)
        .map_err(|e| NetworkError::ParseFailed(e.to_string()))?;

    let mut requests = Vec::new();

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| NetworkError::ParseFailed(e.to_string()))?;
        let Ok(sliced) = SlicedPacket::from_ethernet(&pkt.data) else {
            continue;
        };

        let (src_ip, dst_ip) = match &sliced.net {
            Some(NetSlice::Ipv4(ip)) => {
                let h = ip.header();
                (
                    IpAddr::from(h.source()).to_string(),
                    IpAddr::from(h.destination()).to_string(),
                )
            }
            _ => continue,
        };

        let (src_port, dst_port, tcp_payload) = match &sliced.transport {
            Some(TransportSlice::Tcp(t))
                if HTTP_PORTS.contains(&t.source_port())
                    || HTTP_PORTS.contains(&t.destination_port()) =>
            {
                (t.source_port(), t.destination_port(), t.payload())
            }
            _ => continue,
        };

        if tcp_payload.is_empty() {
            continue;
        }

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
    }

    Ok(requests)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_http_get() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.0\r\n\r\n";
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
}
