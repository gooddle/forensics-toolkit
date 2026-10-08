use crate::error::WindowsError;
use nt_hive::Hive;
use serde::Serialize;
use std::fs;
use std::path::Path;

// Autorun key paths, relative to the hive's software root.
const RUN_KEYS: &[&str] = &[
    "Microsoft\\Windows\\CurrentVersion\\Run",
    "Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "Microsoft\\Windows\\CurrentVersion\\RunServices",
    "Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
];

// The SOFTWARE hive is rooted at HKLM\Software (keys start at "Microsoft\..."),
// while NTUSER.DAT is rooted at HKCU (keys start at "Software\Microsoft\...").
const HIVE_ROOT_PREFIXES: &[&str] = &["", "Software\\"];

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

    let candidates = HIVE_ROOT_PREFIXES
        .iter()
        .flat_map(|prefix| RUN_KEYS.iter().map(move |key| format!("{prefix}{key}")));

    for key_path in candidates {
        let node = match root.subpath(&key_path) {
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
                key_path: key_path.clone(),
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

    /// Minimal in-memory regf hive builder (nk / li / vk cells only).
    /// Data offsets are relative to the end of the 4096-byte base block.
    struct HiveBuilder {
        data: Vec<u8>,
    }

    impl HiveBuilder {
        fn new() -> Self {
            // Reserve 0x20 bytes where a real hive has its hbin header.
            Self {
                data: vec![0u8; 0x20],
            }
        }

        fn alloc(&mut self, content: &[u8]) -> u32 {
            let offset = self.data.len() as u32;
            let size = (4 + content.len()).div_ceil(8) * 8;
            self.data.extend_from_slice(&(-(size as i32)).to_le_bytes());
            self.data.extend_from_slice(content);
            self.data.resize(offset as usize + size, 0);
            offset
        }

        fn string_value(&mut self, name: &str, data: &str) -> u32 {
            let mut utf16: Vec<u8> = data.encode_utf16().flat_map(u16::to_le_bytes).collect();
            utf16.extend_from_slice(&[0, 0]);
            let data_offset = self.alloc(&utf16);

            let mut vk = Vec::new();
            vk.extend_from_slice(b"vk");
            vk.extend_from_slice(&(name.len() as u16).to_le_bytes());
            vk.extend_from_slice(&(utf16.len() as u32).to_le_bytes());
            vk.extend_from_slice(&data_offset.to_le_bytes());
            vk.extend_from_slice(&1u32.to_le_bytes()); // REG_SZ
            vk.extend_from_slice(&1u16.to_le_bytes()); // VALUE_COMP_NAME
            vk.extend_from_slice(&0u16.to_le_bytes());
            vk.extend_from_slice(name.as_bytes());
            self.alloc(&vk)
        }

        /// `subkeys` must already be sorted by upper-cased name (binary search order).
        fn key(&mut self, name: &str, subkeys: &[u32], values: &[u32]) -> u32 {
            let subkeys_list = if subkeys.is_empty() {
                u32::MAX
            } else {
                let mut li = Vec::new();
                li.extend_from_slice(b"li");
                li.extend_from_slice(&(subkeys.len() as u16).to_le_bytes());
                for off in subkeys {
                    li.extend_from_slice(&off.to_le_bytes());
                }
                self.alloc(&li)
            };
            let values_list = if values.is_empty() {
                u32::MAX
            } else {
                let list: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
                self.alloc(&list)
            };

            let mut nk = Vec::new();
            nk.extend_from_slice(b"nk");
            nk.extend_from_slice(&0x0020u16.to_le_bytes()); // KEY_COMP_NAME
            nk.extend_from_slice(&0u64.to_le_bytes()); // timestamp
            nk.extend_from_slice(&0u32.to_le_bytes()); // spare
            nk.extend_from_slice(&0u32.to_le_bytes()); // parent
            nk.extend_from_slice(&(subkeys.len() as u32).to_le_bytes());
            nk.extend_from_slice(&0u32.to_le_bytes()); // volatile subkey count
            nk.extend_from_slice(&subkeys_list.to_le_bytes());
            nk.extend_from_slice(&u32::MAX.to_le_bytes()); // volatile subkeys list
            nk.extend_from_slice(&(values.len() as u32).to_le_bytes());
            nk.extend_from_slice(&values_list.to_le_bytes());
            nk.extend_from_slice(&u32::MAX.to_le_bytes()); // security
            nk.extend_from_slice(&u32::MAX.to_le_bytes()); // class name
            for _ in 0..5 {
                nk.extend_from_slice(&0u32.to_le_bytes()); // max lengths + work var
            }
            nk.extend_from_slice(&(name.len() as u16).to_le_bytes());
            nk.extend_from_slice(&0u16.to_le_bytes()); // class name length
            nk.extend_from_slice(name.as_bytes());
            self.alloc(&nk)
        }

        /// Builds `Microsoft\Windows\CurrentVersion\<run_key>` holding one value.
        fn microsoft_chain(&mut self, run_key: &str, value_name: &str, data: &str) -> u32 {
            let value = self.string_value(value_name, data);
            let run = self.key(run_key, &[], &[value]);
            let cv = self.key("CurrentVersion", &[run], &[]);
            let win = self.key("Windows", &[cv], &[]);
            self.key("Microsoft", &[win], &[])
        }

        fn finish(self, root: u32) -> Vec<u8> {
            let mut bytes = vec![0u8; 4096];
            bytes[0..4].copy_from_slice(b"regf");
            bytes[0x24..0x28].copy_from_slice(&root.to_le_bytes());
            bytes[0x28..0x2C].copy_from_slice(&(self.data.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&self.data);
            bytes
        }
    }

    fn write_hive(bytes: &[u8]) -> NamedTempFile {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(bytes).unwrap();
        tmp
    }

    #[test]
    fn test_ntuser_run_key_found_under_software_prefix() {
        // NTUSER.DAT layout: root -> Software -> Microsoft -> ... -> Run
        let mut b = HiveBuilder::new();
        let ms = b.microsoft_chain("Run", "Updater", "C:\\evil\\upd.exe");
        let software = b.key("Software", &[ms], &[]);
        let root = b.key("ROOT", &[software], &[]);
        let tmp = write_hive(&b.finish(root));

        let entries = extract_run_keys(tmp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].key_path,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        );
        assert_eq!(entries[0].name, "Updater");
        assert_eq!(entries[0].value, "C:\\evil\\upd.exe");
    }

    #[test]
    fn test_software_hive_run_keys_including_wow6432node() {
        // SOFTWARE hive layout: root -> Microsoft / Wow6432Node -> ... -> Run / RunOnce
        let mut b = HiveBuilder::new();
        let ms = b.microsoft_chain("Run", "SecurityHealth", "C:\\health.exe");
        let wow_ms = b.microsoft_chain("RunOnce", "Setup32", "C:\\setup32.exe");
        let wow = b.key("Wow6432Node", &[wow_ms], &[]);
        let root = b.key("ROOT", &[ms, wow], &[]);
        let tmp = write_hive(&b.finish(root));

        let entries = extract_run_keys(tmp.path()).unwrap();
        let found: Vec<(&str, &str)> = entries
            .iter()
            .map(|e| (e.key_path.as_str(), e.name.as_str()))
            .collect();
        assert_eq!(
            found,
            vec![
                ("Microsoft\\Windows\\CurrentVersion\\Run", "SecurityHealth"),
                (
                    "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "Setup32"
                ),
            ]
        );
    }

    #[test]
    fn test_ntuser_wow6432node_run_key() {
        let mut b = HiveBuilder::new();
        let wow_ms = b.microsoft_chain("Run", "Agent32", "C:\\agent32.exe");
        let wow = b.key("Wow6432Node", &[wow_ms], &[]);
        let software = b.key("Software", &[wow], &[]);
        let root = b.key("ROOT", &[software], &[]);
        let tmp = write_hive(&b.finish(root));

        let entries = extract_run_keys(tmp.path()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].key_path,
            "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
        );
        assert_eq!(entries[0].value, "C:\\agent32.exe");
    }

    #[test]
    fn test_invalid_hive_returns_error() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 512]).unwrap();
        let result = extract_run_keys(tmp.path());
        assert!(result.is_err());
    }
}
