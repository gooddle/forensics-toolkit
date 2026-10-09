use common::apple::COREDATA_EPOCH_OFFSET;
use ios::{IosError, read_calls, read_sms};
use rusqlite::{Connection, params};
use std::path::{Path, PathBuf};

const UNIX: i64 = 1_700_000_000;
const CORE: i64 = UNIX - COREDATA_EPOCH_OFFSET;

fn sms_db(dir: &Path) -> Result<PathBuf, rusqlite::Error> {
    let path = dir.join("sms.db");
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
         CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, date INTEGER,
                               text TEXT, is_from_me INTEGER, attributedBody BLOB);
         INSERT INTO handle (ROWID, id) VALUES (1, '+821012345678');
         INSERT INTO handle (ROWID, id) VALUES (2, NULL);",
    )?;
    let mut ins = conn.prepare(
        "INSERT INTO message (handle_id, date, text, is_from_me, attributedBody) VALUES (?1, ?2, ?3, ?4, ?5)",
    )?;
    // iOS 11+ 나노초, 수신
    ins.execute(params![
        1,
        CORE * 1_000_000_000,
        "나노초",
        0,
        None::<Vec<u8>>
    ])?;
    // iOS 10 이하 초, 발신
    ins.execute(params![1, CORE - 10, "초", 1, None::<Vec<u8>>])?;
    // handle_id = 0 (handle 없음)
    ins.execute(params![0, CORE - 20, "no handle", 1, None::<Vec<u8>>])?;
    // handle 이 가리키는 행이 없음 + text NULL + attributedBody 도 NULL
    ins.execute(params![99, CORE - 30, None::<String>, 0, None::<Vec<u8>>])?;
    // handle.id NULL, text NULL 이지만 attributedBody 에 본문
    let mut blob =
        b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x08NSString\x01\x94\x84\x01+"
            .to_vec();
    let body = "attributed 본문".as_bytes();
    blob.push(body.len() as u8);
    blob.extend_from_slice(body);
    blob.extend_from_slice(b"\x86\x84");
    ins.execute(params![2, CORE - 40, None::<String>, 0, blob])?;
    Ok(path)
}

#[test]
fn sms_basic() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = sms_db(dir.path())?;
    let recs = read_sms(&path)?;
    assert_eq!(recs.len(), 5, "handle 없는 메시지도 포함");

    assert_eq!(recs[0].timestamp, UNIX);
    assert_eq!(recs[0].text, "나노초");
    assert_eq!(recs[0].address, "+821012345678");
    assert_eq!(recs[0].direction, "received");

    assert_eq!(recs[1].timestamp, UNIX - 10);
    assert_eq!(recs[1].direction, "sent");

    assert_eq!(recs[2].address, "");
    assert_eq!(recs[2].text, "no handle");

    assert_eq!(recs[3].address, "");
    assert_eq!(recs[3].text, "");

    assert_eq!(recs[4].address, "");
    assert_eq!(recs[4].text, "attributed 본문");
    Ok(())
}

#[test]
fn sms_without_attributed_body_column() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sms.db");
    {
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
             CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, date INTEGER, text TEXT, is_from_me INTEGER);
             INSERT INTO message (handle_id, date, text, is_from_me) VALUES (0, 0, NULL, 1);",
        )?;
    }
    let recs = read_sms(&path)?;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].timestamp, COREDATA_EPOCH_OFFSET);
    assert_eq!(recs[0].text, "");
    Ok(())
}

#[test]
fn sms_schema_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("sms.db");
    {
        let conn = Connection::open(&path)?;
        conn.execute_batch(
            "CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT);
             CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, text TEXT);",
        )?;
    }
    assert!(matches!(read_sms(&path), Err(IosError::SchemaMismatch(_))));

    let other = dir.path().join("empty.db");
    Connection::open(&other)?.execute_batch("CREATE TABLE foo (a);")?;
    assert!(matches!(read_sms(&other), Err(IosError::SchemaMismatch(_))));
    Ok(())
}

fn calls_db(dir: &Path) -> Result<PathBuf, rusqlite::Error> {
    let path = dir.join("CallHistory.storedata");
    let conn = Connection::open(&path)?;
    conn.execute_batch(
        "CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS, ZDURATION FLOAT,
                                   ZDATE TIMESTAMP, ZORIGINATED INTEGER);",
    )?;
    let mut ins = conn.prepare(
        "INSERT INTO ZCALLRECORD (ZADDRESS, ZDURATION, ZDATE, ZORIGINATED) VALUES (?1, ?2, ?3, ?4)",
    )?;
    ins.execute(params!["01012345678", 65.5, CORE as f64 + 0.9, 1])?;
    ins.execute(params![b"+82105555".to_vec(), 3.0, (CORE - 100) as f64, 0])?;
    ins.execute(params![
        None::<String>,
        None::<f64>,
        (CORE - 200) as f64,
        None::<i64>
    ])?;
    Ok(path)
}

#[test]
fn calls_basic() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = calls_db(dir.path())?;
    let recs = read_calls(&path)?;
    assert_eq!(recs.len(), 3);

    assert_eq!(recs[0].timestamp, UNIX);
    assert_eq!(recs[0].address, "01012345678");
    assert_eq!(recs[0].duration_secs, 65.5);
    assert!(recs[0].originated);

    assert_eq!(recs[1].timestamp, UNIX - 100);
    assert_eq!(recs[1].address, "+82105555", "BLOB 주소 보존");
    assert!(!recs[1].originated);

    assert_eq!(recs[2].address, "", "NULL 주소는 빈 문자열");
    assert_eq!(recs[2].duration_secs, 0.0);
    assert!(!recs[2].originated);
    Ok(())
}

#[test]
fn calls_schema_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("CallHistory.storedata");
    Connection::open(&path)?
        .execute_batch("CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, ZADDRESS, ZDATE);")?;
    assert!(matches!(
        read_calls(&path),
        Err(IosError::SchemaMismatch(_))
    ));
    Ok(())
}

#[test]
fn missing_file() {
    let p = Path::new("/nonexistent/dir/sms.db");
    assert!(matches!(read_sms(p), Err(IosError::OpenFailed { .. })));
    assert!(matches!(read_calls(p), Err(IosError::OpenFailed { .. })));
}

#[test]
fn not_a_database() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("garbage.db");
    std::fs::write(
        &path,
        b"this is not sqlite at all, just garbage bytes......",
    )?;
    assert!(read_sms(&path).is_err());
    assert!(read_calls(&path).is_err());
    Ok(())
}

#[test]
fn immutable_open_creates_no_sidecars() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let sms = sms_db(dir.path())?;
    let calls = calls_db(dir.path())?;
    // WAL 모드 DB 에서도 사이드카 파일을 만들지 않아야 한다.
    for p in [&sms, &calls] {
        let conn = Connection::open(p)?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.close().map_err(|(_, e)| e)?;
    }
    let sidecar = |p: &Path, suffix: &str| {
        let mut s = p.as_os_str().to_owned();
        s.push(suffix);
        PathBuf::from(s)
    };
    for p in [&sms, &calls] {
        assert!(!sidecar(p, "-wal").exists());
        assert!(!sidecar(p, "-shm").exists());
    }
    let before_sms = std::fs::read(&sms)?;
    read_sms(&sms)?;
    read_calls(&calls)?;
    for p in [&sms, &calls] {
        assert!(!sidecar(p, "-wal").exists(), "{}-wal 생성됨", p.display());
        assert!(!sidecar(p, "-shm").exists(), "{}-shm 생성됨", p.display());
    }
    assert_eq!(std::fs::read(&sms)?, before_sms, "원본 변경 없음");
    Ok(())
}
