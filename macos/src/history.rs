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

// bash HISTTIMEFORMAT 타임스탬프 줄: "#<unix_ts>"
fn parse_bash_timestamp(line: &str) -> Option<String> {
    let digits = line.strip_prefix('#')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let unix: i64 = digits.parse().ok()?;
    Some(common::format_unix_ts(unix))
}

pub fn read_history(path: &Path, shell: &str) -> Result<Vec<HistoryEntry>, MacosError> {
    let file = File::open(path).map_err(|e| MacosError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let mut reader = BufReader::new(file);
    let mut entries = Vec::new();
    let mut line_number = 0usize;
    let mut raw = Vec::new();
    // bash: 직전 "#<epoch>" 줄의 시각은 다음 명령에 적용
    let mut pending_ts: Option<String> = None;

    loop {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0 {
            break;
        }
        // UTF-8 이 아닌 줄도 번호를 유지하도록 손실 변환으로 보존
        line_number += 1;
        while matches!(raw.last(), Some(b'\n' | b'\r')) {
            raw.pop();
        }
        let line = String::from_utf8_lossy(&raw);

        if line.trim().is_empty() {
            continue;
        }

        if shell == "bash"
            && let Some(ts) = parse_bash_timestamp(&line)
        {
            pending_ts = Some(ts);
            continue;
        }

        let (timestamp, command) = if shell == "zsh" {
            parse_zsh_extended(&line).unwrap_or_else(|| (None, line.to_string()))
        } else {
            (pending_ts.take(), line.to_string())
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

    #[test]
    fn test_non_utf8_line_preserves_numbering() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"ls\necho \xff\xfe bad\npwd\n").unwrap();
        let entries = read_history(tmp.path(), "bash").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].line_number, 2);
        assert!(entries[1].command.starts_with("echo "));
        assert_eq!(entries[2].command, "pwd");
        assert_eq!(entries[2].line_number, 3);
    }

    #[test]
    fn test_bash_epoch_timestamp_applied_to_next_command() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"#1700000000\nls -la\n#1700000060\r\ncd /tmp\r\nwhoami\n")
            .unwrap();
        let entries = read_history(tmp.path(), "bash").unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].command, "ls -la");
        assert_eq!(entries[0].line_number, 2);
        assert_eq!(
            entries[0].timestamp.as_deref(),
            Some(common::format_unix_ts(1_700_000_000).as_str())
        );
        assert_eq!(entries[1].command, "cd /tmp");
        assert_eq!(entries[1].line_number, 4);
        assert_eq!(
            entries[1].timestamp.as_deref(),
            Some(common::format_unix_ts(1_700_000_060).as_str())
        );
        assert!(entries[2].timestamp.is_none());
        assert_eq!(entries[2].line_number, 5);
    }

    #[test]
    fn test_bash_comment_not_numeric_is_command() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"# just a note\n#12ab\n").unwrap();
        let entries = read_history(tmp.path(), "bash").unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].command, "# just a note");
        assert!(entries[0].timestamp.is_none());
    }
}
