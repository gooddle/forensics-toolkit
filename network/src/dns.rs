use crate::error::NetworkError;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use serde::Serialize;
use std::fs::File;
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
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut jumped = false;
    let mut end_pos = offset;

    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos] as usize;
        if len == 0 {
            if !jumped {
                end_pos = pos + 1;
            }
            break;
        }
        // pointer compression
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                end_pos = pos + 2;
            }
            let ptr = ((len & 0x3F) << 8) | data[pos + 1] as usize;
            pos = ptr;
            jumped = true;
            continue;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&data[pos..pos + len]).into_owned());
        pos += len;
    }

    Some((labels.join("."), end_pos))
}

fn parse_dns(payload: &[u8]) -> Option<(u16, bool, Vec<String>, Vec<String>)> {
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
        let (name, next) = parse_dns_name(payload, pos)?;
        pos = next;
        if pos + 4 > payload.len() {
            break;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let type_str = match qtype {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            15 => "MX",
            28 => "AAAA",
            33 => "SRV",
            255 => "ANY",
            _ => "?",
        };
        questions.push(format!("{name} ({type_str})"));
        pos += 4;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (name, next) = parse_dns_name(payload, pos)?;
        pos = next;
        if pos + 10 > payload.len() {
            break;
        }
        let rtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let rdlen = u16::from_be_bytes([payload[pos + 8], payload[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > payload.len() {
            break;
        }
        let rdata = &payload[pos..pos + rdlen];
        let val = if rtype == 1 && rdlen == 4 {
            IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]).to_string()
        } else if rtype == 28 && rdlen == 16 {
            let arr: [u8; 16] = rdata.try_into().ok()?;
            IpAddr::from(arr).to_string()
        } else {
            parse_dns_name(payload, pos)
                .map(|(n, _)| n)
                .unwrap_or_else(|| format!("<{rdlen} bytes>"))
        };
        answers.push(format!("{name} -> {val}"));
        pos += rdlen;
    }

    Some((txid, is_response, questions, answers))
}

pub fn extract_dns(path: &Path) -> Result<Vec<DnsEntry>, NetworkError> {
    let file = File::open(path).map_err(|e| NetworkError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = PcapReader::new(file)
        .map_err(|e| NetworkError::ParseFailed(e.to_string()))?;

    let mut entries = Vec::new();

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

        let udp_payload = match &sliced.transport {
            Some(TransportSlice::Udp(u))
                if u.source_port() == 53 || u.destination_port() == 53 =>
            {
                u.payload()
            }
            _ => continue,
        };

        if let Some((txid, is_response, questions, answers)) = parse_dns(udp_payload) {
            entries.push(DnsEntry {
                src_ip,
                dst_ip,
                transaction_id: txid,
                is_response,
                questions,
                answers,
            });
        }
    }

    Ok(entries)
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

        let (txid, is_resp, questions, _) = parse_dns(&payload).unwrap();
        assert_eq!(txid, 0xabcd);
        assert!(!is_resp);
        assert_eq!(questions[0], "example.com (A)");
    }
}
