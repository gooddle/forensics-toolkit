use crate::error::MemoryError;
use common::{format_unix_ts, hash_file};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct MemoryImageInfo {
    pub path: String,
    pub size_bytes: u64,
    pub format: String,
    pub md5: String,
    pub sha256: String,
    pub analyzed_at: String,
}

fn detect_format(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("dmp") => "Windows Memory Dump",
        Some("vmem") => "VMware Memory Image",
        Some("lime") => "LiME (Linux Memory Extractor)",
        Some("raw") | Some("mem") | Some("bin") => "Raw Memory Image",
        _ => "Unknown",
    }
}

pub fn analyze_memory_image(path: &Path) -> Result<MemoryImageInfo, MemoryError> {
    let hash = hash_file(path).map_err(MemoryError::Other)?;
    let now = chrono::Utc::now().timestamp();

    Ok(MemoryImageInfo {
        path: path.display().to_string(),
        size_bytes: hash.size_bytes,
        format: detect_format(path).to_string(),
        md5: hash.md5,
        sha256: hash.sha256,
        analyzed_at: format_unix_ts(now),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::Builder;

    #[test]
    fn test_analyze_dmp_file() {
        let mut tmp = Builder::new().suffix(".dmp").tempfile().unwrap();
        tmp.write_all(&[0u8; 512]).unwrap();
        let info = analyze_memory_image(tmp.path()).unwrap();
        assert_eq!(info.size_bytes, 512);
        assert_eq!(info.format, "Windows Memory Dump");
    }

    #[test]
    fn test_detect_vmem_format() {
        let mut tmp = Builder::new().suffix(".vmem").tempfile().unwrap();
        tmp.write_all(&[0u8; 64]).unwrap();
        let info = analyze_memory_image(tmp.path()).unwrap();
        assert_eq!(info.format, "VMware Memory Image");
    }
}
