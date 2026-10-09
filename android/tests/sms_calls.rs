use android::{AndroidError, read_calls, read_sms};
use rusqlite::Connection;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn make_db(dir: &Path, name: &str, sql: &str) -> Result<PathBuf, rusqlite::Error> {
    let path = dir.join(name);
    let conn = Connection::open(&path)?;
    conn.execute_batch(sql)?;
    Ok(path)
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

const SMS_SCHEMA: &str = "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, body TEXT, type INTEGER);";
const CALLS_SCHEMA: &str = "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER);";

#[test]
fn sms_converts_ms_and_maps_types() -> TestResult {
    let dir = tempfile::tempdir()?;
    let sql = format!(
        "{SMS_SCHEMA}
         INSERT INTO sms (address, date, body, type) VALUES ('+821011112222', 1700000000123, 'hello', 1);
         INSERT INTO sms (address, date, body, type) VALUES ('+821033334444', 1700000100999, 'bye', 2);
         INSERT INTO sms (address, date, body, type) VALUES ('a', 1700000001000, 'd', 3);
         INSERT INTO sms (address, date, body, type) VALUES ('b', 1700000002000, 'o', 4);
         INSERT INTO sms (address, date, body, type) VALUES ('c', 1700000003000, 'f', 5);
         INSERT INTO sms (address, date, body, type) VALUES ('d', 1700000004000, 'q', 6);
         INSERT INTO sms (address, date, body, type) VALUES ('e', 1700000005000, 'x', 42);"
    );
    let path = make_db(dir.path(), "mmssms.db", &sql)?;

    let records = read_sms(&path)?;
    assert_eq!(records.len(), 7);
    // date DESC 정렬
    assert_eq!(records[0].address, "+821033334444");
    assert_eq!(records[0].timestamp, 1_700_000_100);
    assert_eq!(records[0].direction, "sent");
    let last = &records[6];
    assert_eq!(last.address, "+821011112222");
    assert_eq!(last.timestamp, 1_700_000_000);
    assert_eq!(last.direction, "received");
    assert_eq!(last.body, "hello");

    let dirs: Vec<&str> = records.iter().map(|r| r.direction.as_str()).collect();
    for expected in ["draft", "outbox", "failed", "queued", "unknown(42)"] {
        assert!(dirs.contains(&expected), "{expected} 누락: {dirs:?}");
    }
    Ok(())
}

#[test]
fn sms_null_address_and_body_preserved() -> TestResult {
    let dir = tempfile::tempdir()?;
    let sql = format!(
        "{SMS_SCHEMA}
         INSERT INTO sms (address, date, body, type) VALUES (NULL, 1700000000000, NULL, 1);
         INSERT INTO sms (address, date, body, type) VALUES ('x', 1700000000000, 'y', NULL);"
    );
    let path = make_db(dir.path(), "mmssms.db", &sql)?;

    let records = read_sms(&path)?;
    assert_eq!(records.len(), 2);
    let null_row = records
        .iter()
        .find(|r| r.address.is_empty())
        .ok_or("NULL 행이 보존되지 않음")?;
    assert_eq!(null_row.body, "");
    assert_eq!(null_row.direction, "received");
    assert!(records.iter().any(|r| r.direction == "unknown(null)"));
    Ok(())
}

#[test]
fn sms_missing_table_is_schema_mismatch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = make_db(dir.path(), "mmssms.db", "CREATE TABLE other (x INTEGER);")?;
    assert!(matches!(
        read_sms(&path),
        Err(AndroidError::SchemaMismatch(_))
    ));
    Ok(())
}

#[test]
fn sms_missing_column_is_schema_mismatch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = make_db(
        dir.path(),
        "mmssms.db",
        "CREATE TABLE sms (_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, type INTEGER);",
    )?;
    match read_sms(&path) {
        Err(AndroidError::SchemaMismatch(msg)) => assert!(msg.contains("body"), "{msg}"),
        other => panic!("SchemaMismatch 기대, 실제: {other:?}"),
    }
    Ok(())
}

#[test]
fn sms_missing_file_is_open_failed() {
    let res = read_sms(Path::new("/nonexistent/dir/mmssms.db"));
    assert!(matches!(res, Err(AndroidError::OpenFailed { .. })));
}

#[test]
fn sms_non_sqlite_file_is_error() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("mmssms.db");
    std::fs::write(
        &path,
        b"this is not a sqlite database at all, just garbage bytes....",
    )?;
    assert!(read_sms(&path).is_err());
    Ok(())
}

#[test]
fn calls_converts_ms_and_maps_types() -> TestResult {
    let dir = tempfile::tempdir()?;
    let sql = format!(
        "{CALLS_SCHEMA}
         INSERT INTO calls (number, date, duration, type) VALUES ('111', 1700000000500, 65, 1);
         INSERT INTO calls (number, date, duration, type) VALUES ('222', 1700000010000, 0, 2);
         INSERT INTO calls (number, date, duration, type) VALUES ('333', 1700000020000, 0, 3);
         INSERT INTO calls (number, date, duration, type) VALUES ('444', 1700000030000, 5, 4);
         INSERT INTO calls (number, date, duration, type) VALUES ('555', 1700000040000, 0, 5);
         INSERT INTO calls (number, date, duration, type) VALUES ('666', 1700000050000, 0, 6);
         INSERT INTO calls (number, date, duration, type) VALUES (NULL, 1700000060000, NULL, 9);"
    );
    let path = make_db(dir.path(), "calllog.db", &sql)?;

    let records = read_calls(&path)?;
    assert_eq!(records.len(), 7);
    let types: Vec<&str> = records.iter().map(|r| r.call_type.as_str()).collect();
    assert_eq!(
        types,
        [
            "unknown(9)",
            "blocked",
            "rejected",
            "voicemail",
            "missed",
            "outgoing",
            "incoming"
        ]
    );
    assert_eq!(records[0].number, "");
    assert_eq!(records[0].duration_secs, 0);
    let first = &records[6];
    assert_eq!(first.number, "111");
    assert_eq!(first.timestamp, 1_700_000_000);
    assert_eq!(first.duration_secs, 65);
    Ok(())
}

#[test]
fn calls_missing_table_is_schema_mismatch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = make_db(
        dir.path(),
        "contacts2.db",
        "CREATE TABLE contacts (x INTEGER);",
    )?;
    assert!(matches!(
        read_calls(&path),
        Err(AndroidError::SchemaMismatch(_))
    ));
    Ok(())
}

#[test]
fn calls_missing_column_is_schema_mismatch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = make_db(
        dir.path(),
        "contacts2.db",
        "CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, type INTEGER);",
    )?;
    match read_calls(&path) {
        Err(AndroidError::SchemaMismatch(msg)) => assert!(msg.contains("duration"), "{msg}"),
        other => panic!("SchemaMismatch 기대, 실제: {other:?}"),
    }
    Ok(())
}

/// WAL 모드 DB 를 일반 read-only 로 열면 -shm/-wal 이 생성되지만,
/// immutable URI 로 열면 어떤 사이드카 파일도 생기지 않고 원본도 변하지 않아야 한다.
#[test]
fn immutable_open_creates_no_wal_or_shm() -> TestResult {
    let dir = tempfile::tempdir()?;
    let sms_sql = format!(
        "PRAGMA journal_mode=WAL; {SMS_SCHEMA}
         INSERT INTO sms (address, date, body, type) VALUES ('1', 1700000000000, 'b', 1);"
    );
    let calls_sql = format!(
        "PRAGMA journal_mode=WAL; {CALLS_SCHEMA}
         INSERT INTO calls (number, date, duration, type) VALUES ('1', 1700000000000, 1, 1);"
    );
    let sms_path = make_db(dir.path(), "mmssms.db", &sms_sql)?;
    let calls_path = make_db(dir.path(), "calllog.db", &calls_sql)?;

    for p in [&sms_path, &calls_path] {
        assert!(!sidecar(p, "-wal").exists(), "사전 조건: -wal 없음");
        assert!(!sidecar(p, "-shm").exists(), "사전 조건: -shm 없음");
    }
    let sms_before = std::fs::read(&sms_path)?;
    let calls_before = std::fs::read(&calls_path)?;

    assert_eq!(read_sms(&sms_path)?.len(), 1);
    assert_eq!(read_calls(&calls_path)?.len(), 1);

    for p in [&sms_path, &calls_path] {
        assert!(!sidecar(p, "-wal").exists(), "-wal 생성됨: {}", p.display());
        assert!(!sidecar(p, "-shm").exists(), "-shm 생성됨: {}", p.display());
        assert!(!sidecar(p, "-journal").exists(), "-journal 생성됨");
    }
    assert_eq!(std::fs::read(&sms_path)?, sms_before, "mmssms.db 변경됨");
    assert_eq!(
        std::fs::read(&calls_path)?,
        calls_before,
        "calllog.db 변경됨"
    );
    Ok(())
}

#[test]
fn path_with_special_chars_opens() -> TestResult {
    let dir = tempfile::tempdir()?;
    let sql = format!(
        "{SMS_SCHEMA}
         INSERT INTO sms (address, date, body, type) VALUES ('1', 1700000000000, 'b', 1);"
    );
    let path = make_db(dir.path(), "증거 #1?%.db", &sql)?;
    assert_eq!(read_sms(&path)?.len(), 1);
    Ok(())
}
