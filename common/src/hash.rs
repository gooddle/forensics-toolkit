use anyhow::Result;
use hex::encode;
use md5::{Digest as _, Md5};
use sha2::Sha256;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

pub struct HashResult {
    pub md5: String,
    pub sha256: String,
    pub size_bytes: u64,
}

pub fn hash_file(path: &Path) -> Result<HashResult> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut md5 = Md5::new();
    let mut sha256 = Sha256::new();
    let mut buf = vec![0u8; 65536];
    let mut size_bytes = 0u64;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha256.update(&buf[..n]);
        size_bytes += n as u64;
    }

    Ok(HashResult {
        md5: encode(md5.finalize()),
        sha256: encode(sha256.finalize()),
        size_bytes,
    })
}

pub fn hash_bytes(data: &[u8]) -> HashResult {
    let md5 = encode(Md5::digest(data));
    let sha256 = encode(Sha256::digest(data));
    HashResult {
        md5,
        sha256,
        size_bytes: data.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_bytes_empty() {
        let r = hash_bytes(&[]);
        assert_eq!(r.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            r.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(r.size_bytes, 0);
    }

    #[test]
    fn test_hash_bytes_hello() {
        let r = hash_bytes(b"hello");
        assert_eq!(r.md5, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(
            r.sha256,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
