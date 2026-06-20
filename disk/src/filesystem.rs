use crate::error::DiskError;
use fatfs::{Dir, FileSystem, FsOptions, ReadWriteSeek};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub name: String,
    pub is_dir: bool,
    pub size_bytes: u32,
    pub created_at: Option<String>,
    pub modified_at: Option<String>,
    pub cluster: u32,
}

/// 파티션 이미지 내 특정 오프셋부터 읽는 슬라이스 래퍼
struct PartitionSlice {
    file: File,
    base: u64,
    pos: u64,
    len: u64,
}

impl PartitionSlice {
    fn new(file: File, base: u64, len: u64) -> Self {
        Self { file, base, pos: 0, len }
    }
}

impl Read for PartitionSlice {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.len.saturating_sub(self.pos) as usize;
        let to_read = buf.len().min(remaining);
        if to_read == 0 {
            return Ok(0);
        }
        self.file.seek(SeekFrom::Start(self.base + self.pos))?;
        let n = self.file.read(&mut buf[..to_read])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PartitionSlice {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(n) => n,
            SeekFrom::Current(n) => (self.pos as i64 + n) as u64,
            SeekFrom::End(n) => (self.len as i64 + n) as u64,
        };
        self.pos = new_pos.min(self.len);
        Ok(self.pos)
    }
}

impl Write for PartitionSlice {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "read-only"))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn collect_entries<T: ReadWriteSeek>(
    dir: Dir<T>,
    prefix: &str,
    depth: usize,
    max_depth: usize,
    entries: &mut Vec<FileEntry>,
) {
    if depth > max_depth {
        return;
    }

    for entry in dir.iter().flatten() {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }

        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", prefix, name)
        };

        let fmt_dt = |dt: fatfs::DateTime| -> String {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
                dt.date.year, dt.date.month, dt.date.day,
                dt.time.hour, dt.time.min, dt.time.sec,
            )
        };

        let modified_at = Some(fmt_dt(entry.modified()));
        let created_at = Some(fmt_dt(entry.created()));

        if entry.is_dir() {
            entries.push(FileEntry {
                path: path.clone(),
                name: name.clone(),
                is_dir: true,
                size_bytes: 0,
                created_at,
                modified_at,
                cluster: 0,
            });
            let sub = entry.to_dir();
            collect_entries(sub, &path, depth + 1, max_depth, entries);
        } else {
            entries.push(FileEntry {
                path: path.clone(),
                name,
                is_dir: false,
                size_bytes: entry.len() as u32,
                created_at,
                modified_at,
                cluster: 0,
            });
        }
    }
}

pub fn list_fat32(
    path: &Path,
    partition_offset_bytes: u64,
    max_depth: usize,
) -> Result<Vec<FileEntry>, DiskError> {
    let file = File::open(path).map_err(|e| DiskError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let file_len = file.metadata()?.len();
    let partition_len = file_len.saturating_sub(partition_offset_bytes);
    let slice = PartitionSlice::new(file, partition_offset_bytes, partition_len);

    let fs = FileSystem::new(slice, FsOptions::new())
        .map_err(|e| DiskError::UnsupportedFilesystem(e.to_string()))?;

    let root = fs.root_dir();
    let mut entries = Vec::new();
    collect_entries(root, "", 0, max_depth, &mut entries);

    Ok(entries)
}
