use clap::{Parser, Subcommand};
use network::{analyze_pcap, extract_connections, extract_dns, extract_http};
use prettytable::{row, Table};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "network", about = "IR 네트워크 포렌식 툴 (PCAP 분석)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// PCAP 파일 기본 정보 출력 (버전, 링크타입, 패킷 수, 시간 범위)
    Info {
        #[arg(help = "PCAP 파일 경로")]
        path: PathBuf,
        #[arg(short, long, help = "JSON 형식으로 출력")]
        json: bool,
    },
    /// TCP/UDP 연결 목록 추출 (5-tuple 집계)
    Connections {
        path: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
    /// DNS 쿼리/응답 추출 (UDP port 53)
    Dns {
        path: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
    /// HTTP 요청 추출 (TCP port 80/8080)
    Http {
        path: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    common::init_logging();
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { path, json } => {
            let info = analyze_pcap(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["항목", "값"]);
                table.add_row(row!["경로", info.path]);
                table.add_row(row!["크기", format!("{} bytes", info.size_bytes)]);
                table.add_row(row!["버전", format!("{}.{}", info.version_major, info.version_minor)]);
                table.add_row(row!["링크 타입", info.datalink]);
                table.add_row(row!["Snaplen", info.snaplen]);
                table.add_row(row!["패킷 수", info.packet_count]);
                table.add_row(row!["첫 패킷", info.first_ts]);
                table.add_row(row!["마지막 패킷", info.last_ts]);
                table.add_row(row!["MD5", info.md5]);
                table.add_row(row!["SHA256", info.sha256]);
                table.add_row(row!["분석 시각", info.analyzed_at]);
                table.printstd();
            }
        }
        Commands::Connections { path, json } => {
            let conns = extract_connections(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&conns)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["프로토콜", "출발지 IP", "출발지 포트", "목적지 IP", "목적지 포트", "패킷", "바이트"]);
                for c in &conns {
                    table.add_row(row![
                        c.protocol,
                        c.src_ip,
                        c.src_port,
                        c.dst_ip,
                        c.dst_port,
                        c.packets,
                        c.bytes
                    ]);
                }
                println!("[연결 목록] {} 개", conns.len());
                table.printstd();
            }
        }
        Commands::Dns { path, json } => {
            let entries = extract_dns(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["TXID", "방향", "출발지", "목적지", "질의", "응답"]);
                for e in &entries {
                    let direction = if e.is_response { "응답" } else { "질의" };
                    table.add_row(row![
                        format!("0x{:04X}", e.transaction_id),
                        direction,
                        e.src_ip,
                        e.dst_ip,
                        e.questions.join(", "),
                        e.answers.join(", ")
                    ]);
                }
                println!("[DNS 레코드] {} 개", entries.len());
                table.printstd();
            }
        }
        Commands::Http { path, json } => {
            let requests = extract_http(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&requests)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["출발지", "목적지", "메서드", "Host", "경로"]);
                for r in &requests {
                    table.add_row(row![
                        format!("{}:{}", r.src_ip, r.src_port),
                        format!("{}:{}", r.dst_ip, r.dst_port),
                        r.method,
                        r.host,
                        r.path
                    ]);
                }
                println!("[HTTP 요청] {} 개", requests.len());
                table.printstd();
            }
        }
    }

    Ok(())
}
