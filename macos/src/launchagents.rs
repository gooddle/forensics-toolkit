use crate::error::MacosError;
use plist::Value;
use serde::Serialize;
use std::path::{Path, PathBuf};

// Standard LaunchAgents/Daemons search paths
const SEARCH_PATHS: &[&str] = &[
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "/System/Library/LaunchAgents",
    "/System/Library/LaunchDaemons",
];

#[derive(Debug, Serialize)]
pub struct LaunchEntry {
    pub plist_path: String,
    pub label: String,
    pub program: String,
    pub program_arguments: Vec<String>,
    pub run_at_load: bool,
    pub keep_alive: bool,
    pub disabled: bool,
}

fn user_launch_agents() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    vec![PathBuf::from(format!("{home}/Library/LaunchAgents"))]
}

fn extract_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

fn parse_plist(path: &Path) -> Result<LaunchEntry, MacosError> {
    let v = Value::from_file(path)
        .map_err(|e| MacosError::PlistParseFailed(e.to_string()))?;

    let dict = match &v {
        Value::Dictionary(d) => d,
        _ => return Err(MacosError::PlistParseFailed("루트가 Dictionary가 아님".into())),
    };

    let label = dict
        .get("Label")
        .map(extract_string)
        .unwrap_or_default();

    let program = dict
        .get("Program")
        .map(extract_string)
        .unwrap_or_default();

    let program_arguments = dict
        .get("ProgramArguments")
        .and_then(|v| if let Value::Array(a) = v { Some(a) } else { None })
        .map(|a| a.iter().map(extract_string).collect())
        .unwrap_or_default();

    let run_at_load = dict
        .get("RunAtLoad")
        .and_then(|v| if let Value::Boolean(b) = v { Some(*b) } else { None })
        .unwrap_or(false);

    let keep_alive = match dict.get("KeepAlive") {
        Some(Value::Boolean(b)) => *b,
        Some(Value::Dictionary(_)) => true, // conditional KeepAlive
        _ => false,
    };

    let disabled = dict
        .get("Disabled")
        .and_then(|v| if let Value::Boolean(b) = v { Some(*b) } else { None })
        .unwrap_or(false);

    Ok(LaunchEntry {
        plist_path: path.display().to_string(),
        label,
        program,
        program_arguments,
        run_at_load,
        keep_alive,
        disabled,
    })
}

pub fn scan_launch_entries(extra_path: Option<&Path>) -> Result<Vec<LaunchEntry>, MacosError> {
    let mut search_dirs: Vec<PathBuf> = SEARCH_PATHS.iter().map(PathBuf::from).collect();
    search_dirs.extend(user_launch_agents());
    if let Some(p) = extra_path {
        search_dirs.push(p.to_path_buf());
    }

    let mut entries = Vec::new();

    for dir in &search_dirs {
        if !dir.exists() {
            continue;
        }
        let rd = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("plist")
                && let Ok(la) = parse_plist(&path)
            {
                entries.push(la);
            }
        }
    }

    Ok(entries)
}

pub fn parse_launch_plist(path: &Path) -> Result<LaunchEntry, MacosError> {
    parse_plist(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::Builder;

    #[test]
    fn test_parse_xml_plist() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.example.test</string>
    <key>Program</key>
    <string>/usr/local/bin/test</string>
    <key>RunAtLoad</key>
    <true/>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/test</string>
        <string>--daemon</string>
    </array>
</dict>
</plist>"#;

        let mut tmp = Builder::new().suffix(".plist").tempfile().unwrap();
        tmp.write_all(xml.as_bytes()).unwrap();
        let entry = parse_plist(tmp.path()).unwrap();
        assert_eq!(entry.label, "com.example.test");
        assert_eq!(entry.program, "/usr/local/bin/test");
        assert!(entry.run_at_load);
        assert_eq!(entry.program_arguments.len(), 2);
    }

    #[test]
    fn test_invalid_plist_returns_error() {
        let mut tmp = Builder::new().suffix(".plist").tempfile().unwrap();
        tmp.write_all(b"not a plist").unwrap();
        assert!(parse_plist(tmp.path()).is_err());
    }
}
