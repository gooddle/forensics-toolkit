# forensics-toolkit

Rust 기반 인시던트 리스폰스(IR)용 포렌식 툴킷. 디스크/메모리/네트워크/윈도우 아티팩트 분석.

## 스택
- Rust 1.92+
- Cargo 워크스페이스 (멀티 크레이트)
- common: 공통 유틸 (해시, 로깅, 타임스탬프)
- disk: 디스크/파일시스템 포렌식
- memory: 메모리 포렌식
- network: 네트워크 포렌식
- windows: 윈도우 아티팩트 분석

## 빌드 & 실행
```bash
# 전체 빌드
cargo build

# 빌드 체크 (빠름)
cargo check

# 특정 모듈 실행
cargo run -p disk
cargo run -p memory
cargo run -p network
cargo run -p windows

# 전체 테스트
cargo test

# 포맷
cargo fmt

# 린트
cargo clippy
```

## 코딩 규칙

### 구조
- 공통 로직은 반드시 `common/` 에 작성
- 각 모듈은 독립 실행 가능한 CLI 바이너리
- 비즈니스 로직은 `lib.rs` 에, 진입점은 `main.rs` 에 분리

### 코드 품질
- `unwrap()` / `expect()` 사용 금지 → `?` 연산자 또는 명시적 에러 처리
- 모든 public 함수는 에러 타입 명시
- `cargo clippy` 경고 0개 유지
- `cargo fmt` 통과 필수

### 보안
- 하드코딩된 경로/시크릿 금지
- 분석 대상 파일(.img, .dmp, .pcap 등) 절대 커밋 금지 (.gitignore 적용됨)
- 환경변수는 `.env` 사용 (커밋 금지)

### 테스트
- 파싱 로직은 반드시 단위 테스트 작성
- 테스트용 샘플 파일은 `tests/fixtures/` 에 관리

## 환경 변수 (.env)
- `LOG_LEVEL` - 로그 레벨 (debug/info/warn/error)
- `OUTPUT_DIR` - 분석 결과 출력 경로

## 디렉토리 구조
```
forensics-toolkit/
├── Cargo.toml         # 워크스페이스 루트
├── CLAUDE.md
├── .gitignore
├── README.md
├── common/            # 공통 유틸 라이브러리
│   └── src/lib.rs
├── disk/              # 디스크/파일시스템 포렌식
│   └── src/main.rs
├── memory/            # 메모리 포렌식
│   └── src/main.rs
├── network/           # 네트워크 포렌식
│   └── src/main.rs
└── windows/           # 윈도우 아티팩트 분석
    └── src/main.rs
```

## 문서화 규칙
- 기능 추가/변경 시 `docs/YYYY-MM-DD.md` 파일에 기록
- 형식: `## feat|fix|refactor: 기능명` + 변경 내용 bullet
