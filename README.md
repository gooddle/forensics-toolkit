# forensics-toolkit

Rust 기반 인시던트 리스폰스(IR)용 포렌식 툴킷

## 모듈 구조

| 모듈 | 설명 |
|------|------|
| `common` | 공통 유틸 (해시, 로깅, 타임스탬프) |
| `disk` | 디스크/파일시스템 포렌식 (이미지 파싱, 삭제 파일 복구) |
| `memory` | 메모리 포렌식 (덤프 분석, 프로세스/네트워크 추출) |
| `network` | 네트워크 포렌식 (PCAP 분석, 트래픽 재조합) |
| `windows` | 윈도우 아티팩트 분석 (이벤트 로그, 레지스트리, Prefetch) |

## 실행

```bash
# 전체 빌드
cargo build

# 각 모듈 실행
cargo run -p disk
cargo run -p memory
cargo run -p network
cargo run -p windows
```

## 환경변수

`.env` 파일을 루트에 생성 (`.gitignore`에 포함됨):

```env
# 예시
LOG_LEVEL=debug
OUTPUT_DIR=./output
```
