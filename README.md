# forensics-toolkit

Rust 기반 인시던트 리스폰스(IR)용 포렌식 툴킷.

## 모듈 구조

| 모듈 | 설명 |
|------|------|
| `disk` | 디스크 이미지 파싱, MBR/GPT 파티션, FAT32 파일 목록, 삭제 파일 탐지 |
| `memory` | 메모리 덤프 분석, 문자열 추출, 정규식 패턴 스캔, Minidump 파싱 |
| `network` | PCAP 분석, TCP/UDP 연결 추출, DNS/HTTP 재조합 |
| `windows` | Prefetch 실행 기록, EVTX 이벤트 로그, 레지스트리 자동 실행 항목 |
| `macos` | LaunchAgents 스캔, 터미널 히스토리, 다운로드 기록, 앱 사용 이력 |
| `common` | 해시(MD5/SHA256), 로깅, 타임스탬프 공통 유틸 |

## 빌드

```bash
git clone https://github.com/gooddle/forensics-toolkit
cd forensics-toolkit
cargo build --release
```

---

## disk — 디스크/파일시스템 포렌식

분석 대상: `.img`, `.dd`, `.raw` 등 디스크 이미지

```bash
# 이미지 기본 정보 + MD5/SHA256
cargo run -p disk -- info disk.img

# 파티션 테이블 파싱 (MBR/GPT 자동 감지)
cargo run -p disk -- partitions disk.img

# FAT32 파일 목록 탐색 (파티션 오프셋 지정)
cargo run -p disk -- files disk.img --offset 1048576 --depth 5

# 삭제된 파일 탐지
cargo run -p disk -- deleted disk.img --offset 1048576

# JSON 출력
cargo run -p disk -- partitions disk.img --json
```

**Windows에서 디스크 이미지 수집:**
```powershell
# FTK Imager 또는 dd (관리자 권한)
dd if=\\.\PhysicalDrive0 of=D:\usb\disk.img bs=512
```

---

## memory — 메모리 포렌식

분석 대상: `.dmp`, `.vmem`, `.lime`, `.raw`, `.mem`

```bash
# 파일 기본 정보 + 해시
cargo run -p memory -- info memory.dmp

# ASCII/Unicode 문자열 추출
cargo run -p memory -- strings memory.dmp --min-length 6
cargo run -p memory -- strings memory.dmp --unicode   # UTF-16LE 포함

# 정규식 패턴 스캔
cargo run -p memory -- scan memory.dmp --pattern '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
cargo run -p memory -- scan memory.dmp --pattern 'password'
cargo run -p memory -- scan memory.dmp --pattern 'https?://[^\x00-\x1f ]+'

# Windows Minidump 헤더 파싱
cargo run -p memory -- minidump crash.dmp
```

**Windows에서 메모리 덤프 수집:**
```powershell
# DumpIt (USB에 넣어두고 실행)
DumpIt.exe /O D:\usb\memory.dmp

# WinPmem
winpmem_mini_x64_rc2.exe D:\usb\memory.raw
```

---

## network — 네트워크 포렌식

분석 대상: `.pcap`, `.pcapng`

```bash
# PCAP 기본 정보 (버전, 링크타입, 패킷 수, 시간 범위)
cargo run -p network -- info capture.pcap

# TCP/UDP 연결 목록 (5-tuple, 바이트 순 정렬)
cargo run -p network -- connections capture.pcap

# DNS 쿼리/응답 추출
cargo run -p network -- dns capture.pcap

# HTTP 요청 추출 (Method, Host, Path, User-Agent)
cargo run -p network -- http capture.pcap

# JSON으로 뽑아서 필터링
cargo run -p network -- dns capture.pcap --json | jq '.[] | select(.is_response == false)'
cargo run -p network -- connections capture.pcap --json | jq '.[] | select(.dst_port == 443)'
```

**PCAP 수집 방법:**
```bash
# tcpdump
tcpdump -i eth0 -w capture.pcap
```

---

## windows — Windows 아티팩트 분석

분석 대상: Windows PC에서 USB로 복사해온 파일

**파일 수집 (Windows 관리자 PowerShell):**
```powershell
# Prefetch (바로 복사 가능)
Copy-Item "C:\Windows\Prefetch\*" D:\usb\prefetch\

# 이벤트 로그
wevtutil epl Security D:\usb\Security.evtx
wevtutil epl System D:\usb\System.evtx

# 레지스트리 하이브
reg save HKLM\SOFTWARE D:\usb\SOFTWARE
reg save HKCU D:\usb\NTUSER.DAT
```

**분석:**
```bash
# Prefetch — 프로그램 실행 기록
cargo run -p windows -- prefetch prefetch/CMD.EXE-XXXXXXXX.pf

# 이벤트 로그
cargo run -p windows -- evtx Security.evtx --limit 100
cargo run -p windows -- evtx Security.evtx --event-id 4624   # 로그인 성공
cargo run -p windows -- evtx Security.evtx --event-id 4625   # 로그인 실패
cargo run -p windows -- evtx Security.evtx --event-id 4688   # 프로세스 생성

# 레지스트리 자동 실행 항목 (Run, RunOnce 키)
cargo run -p windows -- registry NTUSER.DAT
cargo run -p windows -- registry SOFTWARE
```

**주요 Event ID:**
| ID | 의미 |
|----|------|
| 4624 | 로그인 성공 |
| 4625 | 로그인 실패 |
| 4688 | 프로세스 생성 |
| 4698 | 스케줄된 작업 생성 |
| 7045 | 새 서비스 설치 |

---

## macos — macOS 아티팩트 분석

파일 지정 없이 실행하면 현재 Mac 경로에서 자동으로 읽습니다.

```bash
# LaunchAgents/LaunchDaemons 자동 실행 항목 스캔
# (/Library, /System/Library, ~/Library 전체)
cargo run -p macos -- launchagents

# 단일 plist 파일 분석
cargo run -p macos -- launchagents --file /Library/LaunchAgents/com.example.plist

# 터미널 히스토리 (~/.zsh_history, ~/.bash_history)
cargo run -p macos -- history
cargo run -p macos -- history --limit 500

# 다운로드 파일 기록 (Quarantine DB)
cargo run -p macos -- quarantine

# 앱 사용 이력 (KnowledgeC DB)
cargo run -p macos -- knowledgec --limit 200

# JSON 출력 + 서드파티 자동실행 항목만 필터
cargo run -p macos -- launchagents --json \
  | jq '.[] | select(.run_at_load == true) | select(.label | startswith("com.apple") | not)'
```

---

## 공통 옵션

모든 서브커맨드에 `--json` 플래그를 붙이면 JSON으로 출력됩니다.

```bash
cargo run -p network -- connections capture.pcap --json > result.json
```

## 환경변수

`.env` 파일을 루트에 생성 (`.gitignore`에 포함됨):

```env
LOG_LEVEL=debug   # debug / info / warn / error
```
