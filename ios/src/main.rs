use clap::{Parser, Subcommand};
use common::format_unix_ts;
use ios::{read_app_usage, read_calls, read_quarantine, read_sms};
use prettytable::{Table, row};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ios", about = "IR iOS 아티팩트 분석 툴")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// sms.db 에서 SMS/iMessage 기록 조회
    Sms {
        #[arg(help = "sms.db 경로")]
        db: PathBuf,
        #[arg(short, long, default_value = "100", help = "출력 건수 (0=전체)")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// CallHistory.storedata 에서 통화 기록 조회
    Calls {
        #[arg(help = "CallHistory.storedata 경로")]
        db: PathBuf,
        #[arg(short, long, default_value = "100", help = "출력 건수 (0=전체)")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// knowledgeC.db 에서 앱 사용 이력 조회
    Knowledgec {
        #[arg(help = "knowledgeC.db 경로")]
        db: PathBuf,
        #[arg(short, long, default_value = "100", help = "출력 건수 (0=전체)")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// (동기화한 Mac 의) QuarantineEventsV2 DB 에서 다운로드 기록 조회
    Quarantine {
        #[arg(help = "QuarantineEventsV2 경로")]
        db: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
}

fn main() {
    common::init_logging();
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("오류: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Sms { db, limit, json } => {
            let mut records = read_sms(&db)?;
            if limit > 0 {
                records.truncate(limit);
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["시각(UTC)", "방향", "주소", "본문"]);
                for r in &records {
                    let text: String = r.text.chars().take(60).collect();
                    table.add_row(row![
                        format_unix_ts(r.timestamp),
                        r.direction,
                        r.address,
                        text
                    ]);
                }
                println!("[SMS] {} 건", records.len());
                table.printstd();
            }
        }
        Commands::Calls { db, limit, json } => {
            let mut records = read_calls(&db)?;
            if limit > 0 {
                records.truncate(limit);
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["시각(UTC)", "방향", "주소", "통화 시간(초)"]);
                for r in &records {
                    table.add_row(row![
                        format_unix_ts(r.timestamp),
                        if r.originated { "발신" } else { "수신" },
                        r.address,
                        format!("{:.1}", r.duration_secs)
                    ]);
                }
                println!("[통화 기록] {} 건", records.len());
                table.printstd();
            }
        }
        Commands::Knowledgec { db, limit, json } => {
            let entries = read_app_usage(&db, limit)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["번들 ID", "시작", "종료", "사용 시간(초)", "기기"]);
                for e in &entries {
                    table.add_row(row![
                        e.bundle_id,
                        e.start_time,
                        e.end_time,
                        format!("{:.0}", e.duration_secs),
                        e.device
                    ]);
                }
                println!("[앱 사용 이력] {} 건", entries.len());
                table.printstd();
            }
        }
        Commands::Quarantine { db, json } => {
            let events = read_quarantine(&db)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["시각", "에이전트", "URL", "송신자"]);
                for e in &events {
                    let url: String = e.data_url.chars().take(60).collect();
                    table.add_row(row![e.timestamp, e.agent_name, url, e.sender_name]);
                }
                println!("[Quarantine] {} 건", events.len());
                table.printstd();
            }
        }
    }

    Ok(())
}
