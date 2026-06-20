use crate::error::WindowsError;
use nt_hive::Hive;
use serde::Serialize;
use std::fs;
use std::path::Path;

// Autorun key paths checked in both SOFTWARE and NTUSER hives
const RUN_KEYS: &[&str] = &[
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
];

#[derive(Debug, Serialize)]
pub struct RunEntry {
    pub hive_path: String,
    pub key_path: String,
    pub name: String,
    pub value: String,
}

pub fn extract_run_keys(path: &Path) -> Result<Vec<RunEntry>, WindowsError> {
    let bytes = fs::read(path).map_err(|e| WindowsError::OpenFailed {
        path: path.display().to_string(),
        source: e,
    })?;

    let hive = Hive::without_validation(bytes.as_slice())
        .map_err(|e| WindowsError::HiveParseFailed(e.to_string()))?;

    let root = hive
        .root_key_node()
        .map_err(|e| WindowsError::HiveParseFailed(e.to_string()))?;

    let mut entries = Vec::new();
    let hive_path = path.display().to_string();

    for key_path in RUN_KEYS {
        let node = match root.subpath(key_path) {
            Some(Ok(n)) => n,
            _ => continue,
        };

        let values = match node.values() {
            Some(Ok(v)) => v,
            _ => continue,
        };

        for val in values {
            let val = match val {
                Ok(v) => v,
                Err(_) => continue,
            };

            let name = val
                .name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
                .to_owned();

            let value = val
                .string_data()
                .unwrap_or_else(|_| "(binary)".to_string());

            entries.push(RunEntry {
                hive_path: hive_path.clone(),
                key_path: key_path.to_string(),
                name,
                value,
            });
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_invalid_hive_returns_error() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 512]).unwrap();
        let result = extract_run_keys(tmp.path());
        assert!(result.is_err());
    }
}
