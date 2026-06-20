use crate::error::DiskError;
use common::{format_unix_ts, hash_file};
use serde::Serialize;
use std::path::Path;

#[derive(Debug, Serialize)]
pub struct ImageInfo {
    pub path: String,
    pub size_bytes: u64,
    pub sector_count: u64,
    pub sector_size: u64,
    pub md5: String,
    pub sha256: String,
    pub analyzed_at: String,
}

pub fn analyze_image(path: &Path) -> Result<ImageInfo, DiskError> {
    let hash = hash_file(path).map_err(DiskError::Other)?;
    let size_bytes = hash.size_bytes;
    let now = chrono::Utc::now().timestamp();

    Ok(ImageInfo {
        path: path.display().to_string(),
        size_bytes,
        sector_count: size_bytes / 512,
        sector_size: 512,
        md5: hash.md5,
        sha256: hash.sha256,
        analyzed_at: format_unix_ts(now),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_analyze_empty_image() {
        let tmp = NamedTempFile::new().unwrap();
        let info = analyze_image(tmp.path()).unwrap();
        assert_eq!(info.size_bytes, 0);
        assert_eq!(info.sector_count, 0);
        assert_eq!(info.md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_analyze_512_byte_image() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&[0u8; 512]).unwrap();
        let info = analyze_image(tmp.path()).unwrap();
        assert_eq!(info.size_bytes, 512);
        assert_eq!(info.sector_count, 1);
    }
}
