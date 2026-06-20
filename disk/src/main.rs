use clap::{Parser, Subcommand};
use disk::{analyze_image, find_deleted_fat32, list_fat32, parse_partitions, PartitionScheme};
use prettytable::{row, Table};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "disk", about = "IR 디스크 포렌식 툴")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 이미지 파일 기본 정보 출력 (크기, 섹터 수, 해시)
    Info {
        #[arg(help = "디스크 이미지 경로 (.img, .dd)")]
        path: PathBuf,
        #[arg(short, long, help = "JSON 형식으로 출력")]
        json: bool,
    },
    /// 파티션 테이블 파싱 (MBR/GPT 자동 감지)
    Partitions {
        path: PathBuf,
        #[arg(short, long)]
        json: bool,
    },
    /// FAT32 파일 목록 탐색
    Files {
        path: PathBuf,
        #[arg(short, long, default_value = "0", help = "파티션 시작 오프셋 (바이트)")]
        offset: u64,
        #[arg(short, long, default_value = "5", help = "최대 탐색 깊이")]
        depth: usize,
        #[arg(short, long)]
        json: bool,
    },
    /// 삭제된 파일 탐지
    Deleted {
        path: PathBuf,
        #[arg(short, long, default_value = "0")]
        offset: u64,
        #[arg(short, long)]
        json: bool,
    },
}

fn main() -> anyhow::Result<()> {
    common::init_logging();
    let cli = Cli::parse();

    match cli.command {
        Commands::Info { path, json } => {
            let info = analyze_image(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["항목", "값"]);
                table.add_row(row!["경로", info.path]);
                table.add_row(row!["크기", format!("{} bytes", info.size_bytes)]);
                table.add_row(row!["섹터 수", info.sector_count]);
                table.add_row(row!["섹터 크기", format!("{} bytes", info.sector_size)]);
                table.add_row(row!["MD5", info.md5]);
                table.add_row(row!["SHA256", info.sha256]);
                table.add_row(row!["분석 시각", info.analyzed_at]);
                table.printstd();
            }
        }
        Commands::Partitions { path, json } => {
            let scheme = parse_partitions(&path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&scheme)?);
            } else {
                match scheme {
                    PartitionScheme::Mbr(parts) => {
                        let mut table = Table::new();
                        table.add_row(row!["#", "타입", "이름", "부팅", "시작LBA", "섹터수", "크기"]);
                        for p in parts {
                            table.add_row(row![
                                p.index,
                                format!("0x{:02X}", p.partition_type),
                                p.type_name,
                                if p.bootable { "Y" } else { "N" },
                                p.start_lba,
                                p.size_sectors,
                                format!("{} MB", p.size_bytes / 1024 / 1024)
                            ]);
                        }
                        println!("[MBR 파티션 테이블]");
                        table.printstd();
                    }
                    PartitionScheme::Gpt(parts) => {
                        let mut table = Table::new();
                        table.add_row(row!["#", "이름", "타입", "시작LBA", "끝LBA", "크기"]);
                        for p in parts {
                            table.add_row(row![
                                p.index,
                                p.name,
                                p.type_name,
                                p.start_lba,
                                p.end_lba,
                                format!("{} MB", p.size_bytes / 1024 / 1024)
                            ]);
                        }
                        println!("[GPT 파티션 테이블]");
                        table.printstd();
                    }
                    PartitionScheme::Unknown => println!("파티션 테이블을 인식할 수 없습니다."),
                }
            }
        }
        Commands::Files { path, offset, depth, json } => {
            let files = list_fat32(&path, offset, depth)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&files)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["이름", "타입", "크기", "수정시각"]);
                for f in &files {
                    table.add_row(row![
                        f.name,
                        if f.is_dir { "DIR" } else { "FILE" },
                        format!("{} bytes", f.size_bytes),
                        f.modified_at.as_deref().unwrap_or("-")
                    ]);
                }
                println!("[FAT32 파일 목록] {} 개", files.len());
                table.printstd();
            }
        }
        Commands::Deleted { path, offset, json } => {
            let entries = find_deleted_fat32(&path, offset)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                let mut table = Table::new();
                table.add_row(row!["추정 이름", "크기", "첫 클러스터", "수정시각", "복구 가능"]);
                for e in &entries {
                    table.add_row(row![
                        e.original_name,
                        format!("{} bytes", e.size_bytes),
                        e.first_cluster,
                        e.modified_at.as_deref().unwrap_or("-"),
                        if e.is_recoverable { "Y" } else { "N" }
                    ]);
                }
                println!("[삭제된 파일] {} 개 발견", entries.len());
                table.printstd();
            }
        }
    }

    Ok(())
}
