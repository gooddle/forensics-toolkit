use clap::{Parser, Subcommand};
use prettytable::{row, Table};
use std::path::PathBuf;
use windows::{extract_run_keys, parse_evtx, parse_prefetch};

#[derive(Parser)]
#[command(name = "windows", about = "IR Windows 아티팩트 분석 툴")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Prefetch 파일 파싱 (.pf, 프로그램 실행 기록)
    Prefetch {
        #[arg(help = "Prefetch 파일 경로 (.pf)")]
        path: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
    /// Windows 이벤트 로그 파싱 (.evtx)
    Evtx {
        #[arg(help = "이벤트 로그 파일 경로 (.evtx)")]
        path: PathBuf,
        #[arg(short, long, default_value = "100", help = "최대 레코드 수 (0=전체)")]
        limit: usize,
        #[arg(short, long, help = "특정 Event ID만 필터")]
        event_id: Option<u64>,
        #[arg(short, long)]
        json: bool,
    },
    /// 레지스트리 하이브에서 자동 실행 항목 추출
    Registry {
        #[arg(help = "레지스트리 하이브 파일 경로 (NTUSER.DAT, SOFTWARE 등)")]
        path: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    common::init_logging();
    let cli = Cli::parse();

    match cli.command {
        Commands::Prefetch { path, json } => {
            let info = parse_prefetch(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["항목", "값"]);
                table.add_row(row!["경로", info.path]);
                table.add_row(row!["버전", info.version]);
                table.add_row(row!["실행 파일", info.executable_name]);
                table.add_row(row!["Prefetch Hash", info.prefetch_hash]);
                table.add_row(row!["실행 횟수", info.run_count]);
                table.add_row(row!["마지막 실행", info.last_run_time]);
                table.add_row(row!["참조 파일 수", info.referenced_files.len()]);
                println!("[Prefetch]");
                table.printstd();

                if !info.referenced_files.is_empty() {
                    let mut ft = Table::new();
                    ft.add_row(row!["#", "파일 경로"]);
                    for (i, f) in info.referenced_files.iter().enumerate() {
                        ft.add_row(row![i + 1, f]);
                    }
                    println!("[참조 파일 목록]");
                    ft.printstd();
                }
            }
        }
        Commands::Evtx { path, limit, event_id, json } => {
            let mut records = parse_evtx(&path, limit)?;
            if let Some(eid) = event_id {
                records.retain(|r| r.event_id == eid);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["RecordID", "Timestamp", "EventID", "Level", "Channel", "Computer"]);
                for r in &records {
                    table.add_row(row![
                        r.record_id,
                        r.timestamp,
                        r.event_id,
                        r.level,
                        r.channel,
                        r.computer
                    ]);
                }
                println!("[이벤트 로그] {} 건", records.len());
                table.printstd();
            }
        }
        Commands::Registry { path, json } => {
            let entries = extract_run_keys(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["키 경로", "이름", "값"]);
                for e in &entries {
                    table.add_row(row![e.key_path, e.name, e.value]);
                }
                println!("[자동 실행 항목] {} 개", entries.len());
                table.printstd();
            }
        }
    }

    Ok(())
}
