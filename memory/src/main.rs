use clap::{Parser, Subcommand};
use memory::{
    analyze_memory_image, extract_strings, parse_minidump, scan_pattern,
};
use prettytable::{row, Table};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "memory", about = "IR 메모리 포렌식 툴")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 메모리 이미지 기본 정보 출력 (크기, 포맷, 해시)
    Info {
        #[arg(help = "메모리 이미지 경로 (.dmp, .vmem, .lime, .raw)")]
        path: PathBuf,
        #[arg(short, long, help = "JSON 형식으로 출력")]
        json: bool,
    },
    /// ASCII/Unicode 문자열 추출
    Strings {
        path: PathBuf,
        #[arg(short, long, default_value = "4", help = "최소 문자열 길이")]
        min_length: usize,
        #[arg(short, long, help = "UTF-16LE 문자열도 추출")]
        unicode: bool,
        #[arg(short, long)]
        json: bool,
    },
    /// 정규식 패턴 스캔
    Scan {
        path: PathBuf,
        #[arg(short, long, help = "정규식 패턴 (예: \\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})")]
        pattern: String,
        #[arg(short, long)]
        json: bool,
    },
    /// Windows Minidump 헤더 파싱
    Minidump {
        #[arg(help = "Minidump 파일 경로 (.dmp)")]
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
            let info = analyze_memory_image(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["항목", "값"]);
                table.add_row(row!["경로", info.path]);
                table.add_row(row!["크기", format!("{} bytes", info.size_bytes)]);
                table.add_row(row!["포맷", info.format]);
                table.add_row(row!["MD5", info.md5]);
                table.add_row(row!["SHA256", info.sha256]);
                table.add_row(row!["분석 시각", info.analyzed_at]);
                table.printstd();
            }
        }
        Commands::Strings { path, min_length, unicode, json } => {
            let entries = extract_strings(&path, min_length, unicode)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["오프셋", "종류", "값"]);
                for e in &entries {
                    let preview: String = e.value.chars().take(80).collect();
                    table.add_row(row![
                        format!("0x{:08X}", e.offset),
                        e.kind,
                        preview
                    ]);
                }
                println!("[문자열 추출] {} 개", entries.len());
                table.printstd();
            }
        }
        Commands::Scan { path, pattern, json } => {
            let matches = scan_pattern(&path, &pattern)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&matches)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["오프셋", "패턴", "매칭"]);
                for m in &matches {
                    table.add_row(row![
                        format!("0x{:08X}", m.offset),
                        m.pattern,
                        m.matched
                    ]);
                }
                println!("[패턴 스캔] {} 개 매칭", matches.len());
                table.printstd();
            }
        }
        Commands::Minidump { path, json } => {
            let info = parse_minidump(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["항목", "값"]);
                table.add_row(row!["경로", info.path]);
                table.add_row(row!["버전", format!("0x{:04X}", info.version)]);
                table.add_row(row!["스트림 수", info.stream_count]);
                table.add_row(row!["디렉토리 RVA", format!("0x{:08X}", info.stream_directory_rva)]);
                table.add_row(row!["체크섬", format!("0x{:08X}", info.checksum)]);
                table.add_row(row!["타임스탬프", info.timestamp]);
                table.add_row(row!["플래그", format!("0x{:016X}", info.flags)]);
                println!("[Minidump 헤더]");
                table.printstd();

                if !info.streams.is_empty() {
                    let mut st = Table::new();
                    st.add_row(row!["#", "타입 ID", "타입 이름", "데이터 크기", "RVA"]);
                    for (i, s) in info.streams.iter().enumerate() {
                        st.add_row(row![
                            i,
                            format!("0x{:04X}", s.stream_type),
                            s.type_name,
                            format!("{} bytes", s.data_size),
                            format!("0x{:08X}", s.rva)
                        ]);
                    }
                    println!("[스트림 디렉토리]");
                    st.printstd();
                }
            }
        }
    }

    Ok(())
}
