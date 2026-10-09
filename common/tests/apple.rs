use common::apple::{
    COREDATA_EPOCH_OFFSET, read_knowledgec, read_knowledgec_with_skipped, read_quarantine_db,
    read_quarantine_db_with_skipped,
};
use common::sqlite::SqliteError;
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// tempfile 의존성 없이 테스트마다 고유한 임시 디렉터리를 만든다.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> std::io::Result<Self> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("common-apple-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn make_db(dir: &TempDir, name: &str, sql: &str) -> Result<PathBuf, rusqlite::Error> {
    let path = dir.path().join(name);
    let conn = Connection::open(&path)?;
    conn.execute_batch(sql)?;
    Ok(path)
}

// 2023-11-14T22:13:20Z == unix 1_700_000_000
const T0: i64 = 1_700_000_000 - COREDATA_EPOCH_OFFSET;

/// macOS 형: ZOBJECT 에 ZDEVICEID 없음, ZSOURCE 조인으로 기기 정보.
fn macos_knowledgec(dir: &TempDir) -> Result<PathBuf, rusqlite::Error> {
    make_db(
        dir,
        "knowledgeC.db",
        &format!(
            "CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZBUNDLEID TEXT, ZDEVICEID TEXT);
             CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
                 ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZSOURCE INTEGER);
             INSERT INTO ZSOURCE VALUES (1, 'x', 'DEV-MAC');
             INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', 'com.apple.Safari', {T0}, {T0} + 60.5, 1);
             INSERT INTO ZOBJECT VALUES (2, '/app/inFocus', 'com.apple.Terminal', {T0} - 100, {T0} - 40, NULL);
             INSERT INTO ZOBJECT VALUES (3, '/app/usage', 'com.other', {T0}, {T0} + 1, 1);"
        ),
    )
}

#[test]
fn knowledgec_macos_schema_with_zsource_join() -> TestResult {
    let dir = TempDir::new()?;
    let path = macos_knowledgec(&dir)?;
    let (entries, skipped) = read_knowledgec_with_skipped(&path, 0)?;
    assert_eq!(skipped, 0);
    assert_eq!(entries.len(), 2);

    let e = &entries[0];
    assert_eq!(e.bundle_id, "com.apple.Safari");
    assert_eq!(e.start_time, "2023-11-14T22:13:20+00:00");
    assert_eq!(e.end_time, "2023-11-14T22:14:20+00:00");
    assert!((e.duration_secs - 60.5).abs() < 1e-9);
    assert_eq!(e.device, "DEV-MAC");

    assert_eq!(entries[1].bundle_id, "com.apple.Terminal");
    assert_eq!(entries[1].device, "");
    Ok(())
}

#[test]
fn knowledgec_ios_schema_without_deviceid() -> TestResult {
    let dir = TempDir::new()?;
    // iOS 형: ZOBJECT.ZDEVICEID 없음, ZSOURCE 테이블도 없음.
    let path = make_db(
        &dir,
        "knowledgeC.db",
        &format!(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
                 ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP);
             INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', 'com.apple.mobilesafari', {T0}, {T0} + 5);"
        ),
    )?;
    let entries = read_knowledgec(&path, 0)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].device, "");
    assert_eq!(entries[0].start_time, "2023-11-14T22:13:20+00:00");
    Ok(())
}

#[test]
fn knowledgec_zobject_deviceid_preferred() -> TestResult {
    let dir = TempDir::new()?;
    let path = make_db(
        &dir,
        "knowledgeC.db",
        &format!(
            "CREATE TABLE ZSOURCE (Z_PK INTEGER PRIMARY KEY, ZDEVICEID TEXT);
             CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
                 ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP, ZSOURCE INTEGER, ZDEVICEID TEXT);
             INSERT INTO ZSOURCE VALUES (1, 'DEV-SRC');
             INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', 'a', {T0}, {T0} + 1, 1, 'DEV-OBJ');
             INSERT INTO ZOBJECT VALUES (2, '/app/inFocus', 'b', {T0} - 1, {T0}, 1, NULL);"
        ),
    )?;
    let entries = read_knowledgec(&path, 0)?;
    assert_eq!(entries[0].device, "DEV-OBJ");
    assert_eq!(entries[1].device, "DEV-SRC");
    Ok(())
}

#[test]
fn knowledgec_null_handling() -> TestResult {
    let dir = TempDir::new()?;
    let path = make_db(
        &dir,
        "knowledgeC.db",
        &format!(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
                 ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP);
             INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', NULL, {T0}, NULL);
             INSERT INTO ZOBJECT VALUES (2, '/app/inFocus', 'no.start', NULL, {T0});
             INSERT INTO ZOBJECT VALUES (3, '/app/inFocus', 'bad.start', 'abc', {T0});"
        ),
    )?;
    let (entries, skipped) = read_knowledgec_with_skipped(&path, 0)?;
    // 시작 시각이 없거나 숫자가 아닌 행만 건너뛴다.
    assert_eq!(skipped, 2);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].bundle_id, "");
    assert_eq!(entries[0].end_time, "");
    assert_eq!(entries[0].duration_secs, 0.0);
    Ok(())
}

#[test]
fn knowledgec_limit() -> TestResult {
    let dir = TempDir::new()?;
    let path = macos_knowledgec(&dir)?;
    let entries = read_knowledgec(&path, 1)?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].bundle_id, "com.apple.Safari");
    assert_eq!(read_knowledgec(&path, 0)?.len(), 2);
    assert_eq!(read_knowledgec(&path, 100)?.len(), 2);
    Ok(())
}

#[test]
fn knowledgec_schema_mismatch() -> TestResult {
    let dir = TempDir::new()?;
    let path = make_db(
        &dir,
        "k.db",
        "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT);",
    )?;
    assert!(matches!(
        read_knowledgec(&path, 0),
        Err(SqliteError::SchemaMismatch(_))
    ));

    let path = make_db(&dir, "empty.db", "CREATE TABLE other (x INTEGER);")?;
    assert!(matches!(
        read_knowledgec(&path, 0),
        Err(SqliteError::SchemaMismatch(_))
    ));
    Ok(())
}

#[test]
fn knowledgec_missing_file() {
    assert!(matches!(
        read_knowledgec(Path::new("/nonexistent/knowledgeC.db"), 0),
        Err(SqliteError::OpenFailed { .. })
    ));
}

#[test]
fn immutable_open_creates_no_wal_or_shm() -> TestResult {
    let dir = TempDir::new()?;
    let path = dir.path().join("knowledgeC.db");
    {
        let conn = Connection::open(&path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.execute_batch(&format!(
            "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT,
                 ZSTARTDATE TIMESTAMP, ZENDDATE TIMESTAMP);
             INSERT INTO ZOBJECT VALUES (1, '/app/inFocus', 'a', {T0}, {T0} + 1);"
        ))?;
    }
    let wal = dir.path().join("knowledgeC.db-wal");
    let shm = dir.path().join("knowledgeC.db-shm");
    assert!(!wal.exists() && !shm.exists(), "정리 후 시작해야 함");

    assert_eq!(read_knowledgec(&path, 0)?.len(), 1);
    assert!(!wal.exists(), "-wal 생성됨");
    assert!(!shm.exists(), "-shm 생성됨");
    Ok(())
}

const QUARANTINE_SCHEMA: &str = "CREATE TABLE LSQuarantineEvent (
    LSQuarantineEventIdentifier TEXT PRIMARY KEY NOT NULL,
    LSQuarantineTimeStamp REAL,
    LSQuarantineAgentBundleIdentifier TEXT,
    LSQuarantineAgentName TEXT,
    LSQuarantineDataURLString TEXT,
    LSQuarantineSenderName TEXT,
    LSQuarantineSenderAddress TEXT,
    LSQuarantineTypeNumber INTEGER,
    LSQuarantineOriginTitle TEXT,
    LSQuarantineOriginURLString TEXT,
    LSQuarantineOriginAlias BLOB);";

#[test]
fn quarantine_v2_schema() -> TestResult {
    let dir = TempDir::new()?;
    let path = make_db(
        &dir,
        "QuarantineEventsV2",
        &format!(
            "{QUARANTINE_SCHEMA}
             INSERT INTO LSQuarantineEvent VALUES ('ID-1', {T0}.75, 'com.google.Chrome', 'Chrome',
                 'https://example.com/a.dmg', 'Sender', 'a@b', 0, NULL, NULL, NULL);
             INSERT INTO LSQuarantineEvent VALUES ('ID-2', {T0} - 10, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
             INSERT INTO LSQuarantineEvent VALUES ('ID-3', NULL, 'x', 'X', NULL, NULL, NULL, 5, NULL, NULL, NULL);"
        ),
    )?;
    let (events, skipped) = read_quarantine_db_with_skipped(&path)?;
    assert_eq!(skipped, 0);
    assert_eq!(events.len(), 3);

    let e = &events[0];
    assert_eq!(e.identifier, "ID-1");
    assert_eq!(e.timestamp, "2023-11-14T22:13:20+00:00");
    assert_eq!(e.agent_bundle_id, "com.google.Chrome");
    assert_eq!(e.agent_name, "Chrome");
    assert_eq!(e.data_url, "https://example.com/a.dmg");
    assert_eq!(e.sender_name, "Sender");
    assert_eq!(e.sender_address, "a@b");
    assert_eq!(e.type_number, 0);

    // NULL 필드는 빈 값/0 으로 보존.
    assert_eq!(events[1].identifier, "ID-2");
    assert_eq!(events[1].agent_name, "");
    assert_eq!(events[1].type_number, 0);

    // 시각 NULL 행도 버리지 않는다(정렬상 마지막).
    assert_eq!(events[2].identifier, "ID-3");
    assert_eq!(events[2].timestamp, "");
    assert_eq!(events[2].type_number, 5);
    Ok(())
}

#[test]
fn quarantine_missing_optional_columns() -> TestResult {
    let dir = TempDir::new()?;
    let path = make_db(
        &dir,
        "q.db",
        &format!(
            "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, LSQuarantineTimeStamp REAL);
             INSERT INTO LSQuarantineEvent VALUES ('ID-1', {T0});"
        ),
    )?;
    let events = read_quarantine_db(&path)?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].data_url, "");
    assert_eq!(events[0].type_number, 0);
    Ok(())
}

#[test]
fn quarantine_schema_mismatch() -> TestResult {
    let dir = TempDir::new()?;
    let path = make_db(
        &dir,
        "q.db",
        "CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT);",
    )?;
    assert!(matches!(
        read_quarantine_db(&path),
        Err(SqliteError::SchemaMismatch(_))
    ));
    let path = make_db(&dir, "q2.db", "CREATE TABLE other (x INTEGER);")?;
    assert!(matches!(
        read_quarantine_db(&path),
        Err(SqliteError::SchemaMismatch(_))
    ));
    Ok(())
}
