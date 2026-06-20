use crate::error::MacosError;
use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct HistoryEntry {
    pub shell: String,
    pub line_number: usize,
    pub timestamp: Option<String>,
    pub command: String,
}

fn default_history_paths() -> Vec<(String, PathBuf)> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![
        ("zsh".into(), PathBuf::from(format!("{home}/.zsh_history"))),
        ("bash".into(), PathBuf::from(format!("{home}/.bash_history"))),
    ]
}

// zsh extended history format: ": <unix_ts>:<elapsed>;<command>"
fn parse_zsh_extended(line: &str) -> Option<(Option<String>, String)> {
    if !line.starts_with(": ") {
        return None;
    }
    let rest = &line[2..];
    let semi = rest.find(';')?;
    let meta = &rest[..semi];
    let command = rest[semi + 1..].to_string();
    let ts = meta.split(':').next()?;
    let unix: i64 = ts.trim().parse().ok()?;
    Some((Some(common::format_unix_ts(unix)), command))
}

pub fn read_history(path: &Path, shell: &str) -> Result<Vec<HistoryEntry>, MacosError> {
    let file = File::open(path).map_err(|e| MacosError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut line_number = 0usize;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        line_number += 1;

        if line.trim().is_empty() {
            continue;
        }

        let (timestamp, command) = if shell == "zsh" {
            parse_zsh_extended(&line)
                .unwrap_or_else(|| (None, line.clone()))
        } else {
            (None, line.clone())
        };

        entries.push(HistoryEntry {
            shell: shell.to_string(),
            line_number,
            timestamp,
            command,
        });
    }

    Ok(entries)
}

pub fn read_all_histories() -> Result<Vec<HistoryEntry>, MacosError> {
    let mut all = Vec::new();
    for (shell, path) in default_history_paths() {
        if !path.exists() {
            continue;
        }
        let mut entries = read_history(&path, &shell)?;
        all.append(&mut entries);
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_bash_history() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"ls -la\ncd /tmp\npwd\n").unwrap();
        let entries = read_history(tmp.path(), "bash").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "ls -la");
        assert!(entries[0].timestamp.is_none());
    }

    #[test]
    fn test_read_zsh_extended_history() {
        let content = b": 1700000000:0;ls -la\n: 1700000001:0;cd /tmp\n";
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(content).unwrap();
        let entries = read_history(tmp.path(), "zsh").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "ls -la");
        assert!(entries[0].timestamp.is_some());
    }
}
