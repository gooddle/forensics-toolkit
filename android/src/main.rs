use android::{analyze_apk, parse_packages, read_calls, read_sms};
use clap::{Parser, Subcommand};
use common::format_unix_ts;
use prettytable::{Table, row};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "android", about = "IR Android 아티팩트 분석 툴")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// mmssms.db 에서 SMS 기록 조회
    Sms {
        #[arg(help = "mmssms.db 경로")]
        db: PathBuf,
        #[arg(short, long, default_value = "100", help = "출력 건수 (0=전체)")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// contacts2.db / calllog.db 에서 통화 기록 조회
    Calls {
        #[arg(help = "contacts2.db 또는 calllog.db 경로")]
        db: PathBuf,
        #[arg(short, long, default_value = "100", help = "출력 건수 (0=전체)")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// packages.xml 에서 설치 패키지 목록 조회
    Packages {
        #[arg(help = "packages.xml 경로")]
        xml: PathBuf,
        #[arg(short, long, default_value = "100", help = "출력 건수 (0=전체)")]
        limit: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// APK 의 AndroidManifest.xml 권한 분석
    Apk {
        #[arg(help = "APK 파일 경로")]
        apk: PathBuf,
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
                    let body: String = r.body.chars().take(60).collect();
                    table.add_row(row![
                        format_unix_ts(r.timestamp),
                        r.direction,
                        r.address,
                        body
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
                table.add_row(row!["시각(UTC)", "유형", "번호", "통화 시간(초)"]);
                for r in &records {
                    table.add_row(row![
                        format_unix_ts(r.timestamp),
                        r.call_type,
                        r.number,
                        r.duration_secs
                    ]);
                }
                println!("[통화 기록] {} 건", records.len());
                table.printstd();
            }
        }
        Commands::Packages { xml, limit, json } => {
            let mut packages = parse_packages(&xml)?;
            if limit > 0 {
                packages.truncate(limit);
            }

            if json {
                println!("{}", serde_json::to_string_pretty(&packages)?);
            } else {
                let mut table = Table::new();
                table.add_row(row![
                    "패키지",
                    "시스템",
                    "최초 설치(UTC)",
                    "최근 업데이트(UTC)",
                    "경로"
                ]);
                for p in &packages {
                    table.add_row(row![
                        p.name,
                        if p.is_system { "Y" } else { "N" },
                        format_unix_ts(p.first_install),
                        format_unix_ts(p.last_update),
                        p.code_path
                    ]);
                }
                println!("[설치 패키지] {} 개", packages.len());
                table.printstd();
            }
        }
        Commands::Apk { apk, json } => {
            let result = analyze_apk(&apk)?;

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["권한", "위험"]);
                for perm in &result.all_permissions {
                    let dangerous = result.dangerous_permissions.contains(perm);
                    table.add_row(row![perm, if dangerous { "Y" } else { "" }]);
                }
                println!(
                    "[APK] {} — 권한 {} 개 (위험 {} 개)",
                    result.package_name,
                    result.all_permissions.len(),
                    result.dangerous_permissions.len()
                );
                table.printstd();
            }
        }
    }

    Ok(())
}
