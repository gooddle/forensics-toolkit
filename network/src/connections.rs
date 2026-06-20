use crate::error::NetworkError;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::pcap::PcapReader;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::File;
use std::net::IpAddr;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct Connection {
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Hash, Eq, PartialEq)]
struct ConnKey {
    protocol: u8,
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
}

pub fn extract_connections(path: &Path) -> Result<Vec<Connection>, NetworkError> {
    let file = File::open(path).map_err(|e| NetworkError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = PcapReader::new(file)
        .map_err(|e| NetworkError::ParseFailed(e.to_string()))?;

    let mut map: HashMap<ConnKey, (u64, u64)> = HashMap::new();

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt.map_err(|e| NetworkError::ParseFailed(e.to_string()))?;
        let Ok(sliced) = SlicedPacket::from_ethernet(&pkt.data) else {
            continue;
        };

        let (src_ip4, dst_ip4, proto) = match &sliced.net {
            Some(NetSlice::Ipv4(ip)) => {
                let h = ip.header();
                (h.source(), h.destination(), h.protocol().0)
            }
            _ => continue,
        };

        let (src_port, dst_port) = match &sliced.transport {
            Some(TransportSlice::Tcp(t)) => (t.source_port(), t.destination_port()),
            Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port()),
            _ => continue,
        };

        let key = ConnKey {
            protocol: proto,
            src_ip: src_ip4,
            dst_ip: dst_ip4,
            src_port,
            dst_port,
        };
        let entry = map.entry(key).or_insert((0, 0));
        entry.0 += 1;
        entry.1 += pkt.data.len() as u64;
    }

    let mut connections: Vec<Connection> = map
        .into_iter()
        .map(|(k, (packets, bytes))| Connection {
            protocol: match k.protocol {
                6 => "TCP".to_string(),
                17 => "UDP".to_string(),
                1 => "ICMP".to_string(),
                n => format!("{n}"),
            },
            src_ip: IpAddr::from(k.src_ip).to_string(),
            dst_ip: IpAddr::from(k.dst_ip).to_string(),
            src_port: k.src_port,
            dst_port: k.dst_port,
            packets,
            bytes,
        })
        .collect();

    connections.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    Ok(connections)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn pcap_with_udp_packet() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // ETHERNET

        let payload = b"hello";
        let udp: Vec<u8> = {
            let mut u = Vec::new();
            u.extend_from_slice(&12345u16.to_be_bytes()); // src port
            u.extend_from_slice(&53u16.to_be_bytes());    // dst port
            u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
            u.extend_from_slice(&0u16.to_be_bytes()); // checksum
            u.extend_from_slice(payload);
            u
        };
        let ip: Vec<u8> = {
            let mut i = Vec::new();
            let ip_len = (20 + udp.len()) as u16;
            i.push(0x45); i.push(0);
            i.extend_from_slice(&ip_len.to_be_bytes());
            i.extend_from_slice(&0u16.to_be_bytes()); // ID
            i.extend_from_slice(&0u16.to_be_bytes()); // flags+frag
            i.push(64); i.push(17); // TTL, proto=UDP
            i.extend_from_slice(&0u16.to_be_bytes()); // checksum
            i.extend_from_slice(&[192, 168, 1, 1]); // src
            i.extend_from_slice(&[8, 8, 8, 8]);     // dst
            i.extend_from_slice(&udp);
            i
        };
        let eth: Vec<u8> = {
            let mut e = vec![0u8; 6]; // dst mac
            e.extend_from_slice(&[0u8; 6]); // src mac
            e.extend_from_slice(&[0x08, 0x00]); // IPv4
            e.extend_from_slice(&ip);
            e
        };

        v.extend_from_slice(&1700000001u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(eth.len() as u32).to_le_bytes());
        v.extend_from_slice(&(eth.len() as u32).to_le_bytes());
        v.extend_from_slice(&eth);
        v
    }

    #[test]
    fn test_extract_udp_connection() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&pcap_with_udp_packet()).unwrap();
        let conns = extract_connections(tmp.path()).unwrap();
        assert_eq!(conns.len(), 1);
        assert_eq!(conns[0].protocol, "UDP");
        assert_eq!(conns[0].src_ip, "192.168.1.1");
        assert_eq!(conns[0].dst_ip, "8.8.8.8");
        assert_eq!(conns[0].dst_port, 53);
    }
}
