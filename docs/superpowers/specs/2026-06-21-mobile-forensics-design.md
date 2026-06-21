# Mobile Forensics (Android & iOS) Design

## Goal

Add two independent workspace crates — `android/` and `ios/` — to forensics-toolkit, following the same structure as the existing `macos/`, `windows/`, `disk/` modules. Each crate is a standalone CLI binary that parses mobile device artifacts from local files only (no network).

## Architecture

Two new Cargo workspace members:

```
forensics-toolkit/
├── android/
│   └── src/
│       ├── main.rs       — CLI entry point (subcommands: sms, calls, packages, apk)
│       ├── lib.rs
│       ├── error.rs
│       ├── sms.rs        — mmssms.db (SQLite)
│       ├── calls.rs      — contacts2.db / calls table (SQLite)
│       ├── packages.rs   — /data/system/packages.xml (XML)
│       └── apk.rs        — APK ZIP → AndroidManifest.xml binary XML (AXML)
└── ios/
    └── src/
        ├── main.rs       — CLI entry point (subcommands: sms, calls, knowledgec, quarantine)
        ├── lib.rs
        ├── error.rs
        ├── sms.rs        — sms.db (SQLite, CoreData epoch)
        ├── calls.rs      — CallHistory.storedata (SQLite, CoreData epoch)
        ├── knowledgec.rs — same logic as macos/knowledgec.rs, path as parameter
        └── quarantine.rs — same logic as macos/quarantine.rs, path as parameter
```

`Cargo.toml` workspace members에 `"android"`, `"ios"` 추가.

## Global Constraints

- 네트워크 코드 없음 — 모든 분석은 로컬 파일 입력 기준
- 출력 형식: JSON (기본) 또는 테이블 (`--table` 플래그)
- 에러 처리: 파일 없음 / 스키마 불일치 → stderr에 명확한 메시지, exit code 1
- 기존 모듈 패턴 준수: `Error` enum in `error.rs`, pub functions in feature files, `main.rs`에서 조합
- 테스트: 수동 생성 SQLite / 샘플 파일로 단위 테스트, `tests/` 디렉터리에 통합 테스트

---

## Android Module

### `sms.rs` — mmssms.db

**입력**: `mmssms.db` 파일 경로

**쿼리**:
```sql
SELECT address, date, body, type FROM sms ORDER BY date DESC
```

**필드 변환**:
- `date`: Unix milliseconds → `/1000` → Unix seconds
- `type`: 1 = 수신, 2 = 발신

**출력 구조체**:
```rust
pub struct SmsRecord {
    pub address: String,
    pub timestamp: i64,       // Unix seconds
    pub body: String,
    pub direction: String,    // "received" | "sent"
}
```

---

### `calls.rs` — contacts2.db

**입력**: `contacts2.db` 파일 경로

**쿼리**:
```sql
SELECT number, date, duration, type FROM calls ORDER BY date DESC
```

**필드 변환**:
- `date`: Unix milliseconds → `/1000`
- `type`: 1 = 수신, 2 = 발신, 3 = 부재중
- `duration`: 초 단위 그대로

**출력 구조체**:
```rust
pub struct CallRecord {
    pub number: String,
    pub timestamp: i64,
    pub duration_secs: i64,
    pub call_type: String,    // "incoming" | "outgoing" | "missed"
}
```

---

### `packages.rs` — packages.xml

**입력**: `packages.xml` 파일 경로 (보통 `/data/system/packages.xml`)

**파싱 대상**: `<package>` 태그의 속성
- `name`: 패키지 이름 (예: `com.evil.app`)
- `codePath`: 설치 경로 (`/data/` = 사용자 앱, `/system/` = 시스템 앱)
- `firstInstallTime`: 16진수 milliseconds → Unix seconds
- `lastUpdateTime`: 동일

**출력 구조체**:
```rust
pub struct PackageInfo {
    pub name: String,
    pub code_path: String,
    pub is_system: bool,          // codePath.starts_with("/system/")
    pub first_install: i64,
    pub last_update: i64,
}
```

---

### `apk.rs` — APK Binary XML (AXML)

**입력**: `.apk` 파일 경로

**처리 흐름**:
1. APK를 ZIP으로 열기 (`zip` 크레이트)
2. `AndroidManifest.xml` 항목 추출 (바이너리 AXML 포맷)
3. AXML 파싱: magic `0x00080003`, 문자열 풀(string pool) → `uses-permission` 태그에서 권한 이름 추출
4. 위험 권한 목록과 대조 → 위험 권한만 필터링 출력

**위험 권한 상수** (코드 내 `const DANGEROUS_PERMISSIONS`):
```
android.permission.READ_SMS
android.permission.SEND_SMS
android.permission.RECEIVE_SMS
android.permission.READ_CONTACTS
android.permission.WRITE_CONTACTS
android.permission.READ_CALL_LOG
android.permission.RECORD_AUDIO
android.permission.CAMERA
android.permission.ACCESS_FINE_LOCATION
android.permission.ACCESS_COARSE_LOCATION
android.permission.READ_EXTERNAL_STORAGE
android.permission.WRITE_EXTERNAL_STORAGE
android.permission.GET_ACCOUNTS
android.permission.USE_BIOMETRIC
```

**출력 구조체**:
```rust
pub struct ApkPermissions {
    pub package_name: String,
    pub all_permissions: Vec<String>,
    pub dangerous_permissions: Vec<String>,
}
```

---

## iOS Module

### epoch 변환 공통

모든 날짜 필드: CoreData epoch (2001-01-01 기준, 초 단위 f64)  
Unix timestamp = `value as i64 + 978_307_200`

---

### `sms.rs` — sms.db

**입력**: `sms.db` 파일 경로

**쿼리**:
```sql
SELECT h.id as address, m.date, m.text, m.is_from_me
FROM message m
JOIN handle h ON m.handle_id = h.ROWID
ORDER BY m.date DESC
```

**출력 구조체**:
```rust
pub struct IosSmsRecord {
    pub address: String,
    pub timestamp: i64,
    pub text: String,
    pub direction: String,    // "received" | "sent"
}
```

---

### `calls.rs` — CallHistory.storedata

**입력**: `CallHistory.storedata` 파일 경로 (SQLite)

**쿼리**:
```sql
SELECT ZADDRESS, ZDURATION, ZDATE, ZORIGINATED FROM ZCALLRECORD
ORDER BY ZDATE DESC
```

**필드 변환**:
- `ZDATE`: CoreData epoch → `+978_307_200`
- `ZORIGINATED`: 0 = 수신, 1 = 발신

**출력 구조체**:
```rust
pub struct IosCallRecord {
    pub address: String,
    pub duration_secs: f64,
    pub timestamp: i64,
    pub originated: bool,     // true = 발신
}
```

---

### `knowledgec.rs` — KnowledgeC

기존 `macos/src/knowledgec.rs`와 동일 로직.  
함수 시그니처: `pub fn analyze(db_path: &Path) -> Result<Vec<AppUsage>>`  
경로를 파라미터로 받으므로 iOS 경로(`/private/var/db/CoreData/knowledgec.db`)도 그대로 적용.

---

### `quarantine.rs` — Quarantine DB

기존 `macos/src/quarantine.rs`와 동일 로직.  
iOS 기기 자체에는 QuarantineEventsV2가 없으므로, iTunes 동기화 Mac의 `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`를 경로 파라미터로 전달하는 시나리오. 경로를 인자로 받으므로 코드 변경 없이 그대로 재사용 가능.

---

## 테스트 전략

- 각 파서 함수에 대해 `tests/` 디렉터리에 샘플 파일 포함
- Android: `tests/fixtures/mmssms.db`, `contacts2.db`, `packages.xml`, `sample.apk` (최소 스키마)
- iOS: `tests/fixtures/sms.db`, `CallHistory.storedata` (최소 스키마)
- 각 fixture는 `rusqlite`로 코드 내에서 생성하거나 커밋 포함
- CoreData epoch 변환, millisecond 변환 단위 테스트 필수

## 크레이트 의존성

| 크레이트 | 용도 |
|---|---|
| `rusqlite` | SQLite 파싱 (sms, calls, knowledgec, quarantine) |
| `quick-xml` | packages.xml 파싱 |
| `zip` | APK 압축 해제 |
| `serde_json` | JSON 출력 |
| `clap` | CLI 서브커맨드 |
