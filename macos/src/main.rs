use clap::{Parser, Subcommand};
use macos::{
    parse_launch_plist, read_all_histories, read_app_usage, read_history, read_quarantine,
    scan_launch_entries,
};
use prettytable::{row, Table};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "macos", about = "IR macOS 아티팩트 분석 툴")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// LaunchAgents/LaunchDaemons 자동 실행 항목 스캔
    LaunchAgents {
        #[arg(short, long, help = "추가 검색 디렉토리")]
        dir: Option<PathBuf>,
        #[arg(short, long, help = "단일 plist 파일 경로 지정")]
        file: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
    },
    /// Shell 히스토리 파싱 (~/.zsh_history, ~/.bash_history)
    History {
        #[arg(short, long, help = "히스토리 파일 직접 지정")]
        file: Option<PathBuf>,
        #[arg(short, long, default_value = "auto", help = "셸 종류 (zsh/bash/auto)")]
        shell: String,
        #[arg(short, long, default_value = "100")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// Quarantine DB에서 다운로드 파일 기록 조회
    Quarantine {
        #[arg(short, long, help = "DB 파일 직접 지정")]
        file: Option<PathBuf>,
        #[arg(short, long)]
        json: bool,
    },
    /// KnowledgeC DB에서 앱 사용 이력 조회
    Knowledgec {
        #[arg(short, long, help = "DB 파일 직접 지정")]
        file: Option<PathBuf>,
        #[arg(short, long, default_value = "100")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    common::init_logging();
    let cli = Cli::parse();

    match cli.command {
        Commands::LaunchAgents { dir, file, json } => {
            let entries = if let Some(f) = file {
                vec![parse_launch_plist(&f)?]
            } else {
                scan_launch_entries(dir.as_deref())?
            };

            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["Label", "Program", "RunAtLoad", "KeepAlive", "Disabled", "경로"]);
                for e in &entries {
                    let prog = if e.program.is_empty() {
                        e.program_arguments.first().cloned().unwrap_or_default()
                    } else {
                        e.program.clone()
                    };
                    table.add_row(row![
                        e.label,
                        prog,
                        if e.run_at_load { "Y" } else { "N" },
                        if e.keep_alive { "Y" } else { "N" },
                        if e.disabled { "Y" } else { "N" },
                        e.plist_path
                    ]);
                }
                println!("[LaunchAgents/Daemons] {} 개", entries.len());
                table.printstd();
            }
        }
        Commands::History { file, shell, limit, json } => {
            let mut entries = if let Some(f) = file {
                let shell_name = if shell == "auto" { "zsh" } else { &shell };
                read_history(&f, shell_name)?
            } else {
                read_all_histories()?
            };
            if limit > 0 {
                entries.truncate(limit);
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["#", "Shell", "Timestamp", "Command"]);
                for e in &entries {
                    table.add_row(row![
                        e.line_number,
                        e.shell,
                        e.timestamp.as_deref().unwrap_or("-"),
                        e.command
                    ]);
                }
                println!("[Shell History] {} 건", entries.len());
                table.printstd();
            }
        }
        Commands::Quarantine { file, json } => {
            let events = read_quarantine(file.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["Timestamp", "Agent", "URL", "Sender"]);
                for e in &events {
                    let url: String = e.data_url.chars().take(60).collect();
                    table.add_row(row![e.timestamp, e.agent_name, url, e.sender_name]);
                }
                println!("[Quarantine Events] {} 건", events.len());
                table.printstd();
            }
        }
        Commands::Knowledgec { file, limit, json } => {
            let entries = read_app_usage(file.as_deref(), limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["Bundle ID", "시작 시각", "종료 시각", "사용 시간(초)"]);
                for e in &entries {
                    table.add_row(row![
                        e.bundle_id,
                        e.start_time,
                        e.end_time,
                        format!("{:.1}", e.duration_secs)
                    ]);
                }
                println!("[앱 사용 이력] {} 건", entries.len());
                table.printstd();
            }
        }
    }

    Ok(())
}
