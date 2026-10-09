//! 증거 SQLite DB 를 변경 없이 읽기 위한 공통 헬퍼.

use rusqlite::types::Value;
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SqliteError {
    #[error("파일을 열 수 없음: {path}")]
    OpenFailed {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("UTF-8 이 아닌 경로는 지원하지 않음: {0}")]
    NonUtf8Path(String),

    #[error("SQLite 오류: {0}")]
    Sqlite(String),

    #[error("스키마 불일치: {0}")]
    SchemaMismatch(String),
}

/// 증거 무결성을 위해 `file:<path>?immutable=1` URI 로 읽기 전용 오픈한다.
/// immutable 모드에서는 잠금·저널·-wal/-shm 파일을 만들거나 수정하지 않는다.
pub fn open_immutable(db_path: &Path) -> Result<Connection, SqliteError> {
    let meta = std::fs::metadata(db_path).map_err(|e| SqliteError::OpenFailed {
        path: db_path.display().to_string(),
        source: e,
    })?;
    if !meta.is_file() {
        return Err(SqliteError::OpenFailed {
            path: db_path.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "일반 파일이 아님"),
        });
    }

    let uri = immutable_uri(db_path)?;
    Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|e| SqliteError::Sqlite(format!("{}: {e}", db_path.display())))
}

fn immutable_uri(db_path: &Path) -> Result<String, SqliteError> {
    let s = db_path
        .to_str()
        .ok_or_else(|| SqliteError::NonUtf8Path(db_path.display().to_string()))?;
    let mut p = s.replace('\\', "/");
    // Windows 드라이브 경로(C:/...)는 file:///C:/... 형태가 되어야 한다.
    if p.len() >= 2 && p.as_bytes()[1] == b':' {
        p.insert(0, '/');
    }
    let mut uri = String::from("file:");
    for b in p.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                uri.push(b as char)
            }
            _ => uri.push_str(&format!("%{b:02X}")),
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

/// 테이블과 필수 컬럼의 존재를 확인한다. 없으면 SchemaMismatch.
pub fn require_columns(
    conn: &Connection,
    table: &str,
    columns: &[&str],
) -> Result<(), SqliteError> {
    let mut stmt = conn
        .prepare("SELECT name FROM pragma_table_info(?1)")
        .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
    let existing: Vec<String> = stmt
        .query_map([table], |r| r.get::<_, String>(0))
        .map_err(|e| SqliteError::Sqlite(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

    if existing.is_empty() {
        return Err(SqliteError::SchemaMismatch(format!(
            "'{table}' 테이블이 없음"
        )));
    }
    let missing: Vec<&str> = columns
        .iter()
        .copied()
        .filter(|c| !existing.iter().any(|e| e.eq_ignore_ascii_case(c)))
        .collect();
    if !missing.is_empty() {
        return Err(SqliteError::SchemaMismatch(format!(
            "'{table}' 테이블에 필수 컬럼 없음: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

/// NULL 은 빈 문자열로 보존, 그 외 타입은 문자열로 변환한다.
pub fn value_to_string(v: Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Integer(i) => i.to_string(),
        Value::Real(f) => f.to_string(),
        Value::Text(s) => s,
        Value::Blob(b) => String::from_utf8_lossy(&b).into_owned(),
    }
}

/// 정수 또는 정수 형태의 텍스트만 허용한다. NULL/실수/BLOB 등은 None.
pub fn value_to_i64(v: Value) -> Option<i64> {
    match v {
        Value::Integer(i) => Some(i),
        Value::Text(s) => s.trim().parse().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uri_escapes_special_chars() -> Result<(), SqliteError> {
        let uri = immutable_uri(Path::new("/tmp/a b?#%.db"))?;
        assert_eq!(uri, "file:/tmp/a%20b%3F%23%25.db?immutable=1");
        Ok(())
    }

    #[test]
    fn value_conversions() {
        assert_eq!(value_to_string(Value::Null), "");
        assert_eq!(value_to_i64(Value::Text(" 42 ".into())), Some(42));
        assert_eq!(value_to_i64(Value::Real(1.5)), None);
    }
}
