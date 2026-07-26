# APEX Forensic Core Engine

APEX는 **Python·Native 하이브리드 분석 엔진**, **한국어 기반 사용자 환경**, **Built-in MCP 연동 구조**를 기반으로 디지털 증거 분석의 접근성과 자동화를 높이는 디지털 포렌식 플랫폼입니다.

본 저장소의 Forensic Core Engine은 대용량 Evidence를 읽기 전용으로 분석하고, GUI·Backend·MCP Adapter가 공통으로 사용할 수 있는 버전화된 JSON 결과를 제공합니다.

APEX는 다음 프로젝트의 장점을 참고합니다.

- X-Ways Forensics의 빠른 Evidence 탐색 철학
- Autopsy의 Case·Artifact 중심 분석 Workflow와 사용자 경험
- MCP 기반 AI Agent 연동 방식

단, Autopsy의 Java 코드나 NetBeans 애플리케이션 구조를 기반으로 구현하지 않습니다. APEX의 주 개발 언어는 Python이며, 성능에 민감한 영역은 Native Adapter로 분리하는 독자적인 구조를 사용합니다.

> 현재 Forensic Core Engine은 **Phase 3 Windows Artifact Analysis MVP 구현 완료** 상태입니다.
> Case·Evidence 관리, Streaming Hash와 무결성 검증, SQLite Repository, Append-only Chain of Custody, Job·Progress·Cancellation, Logical File System Indexing, Windows Registry `.reg`, exported Event XML, minimal Prefetch metadata, Artifact Query, JSON Schema 검증, CLI 및 Unit·Integration Test가 구현되었습니다.
>
> Disk image 내부 File System parsing, live Windows 수집, credential/secret 추출, Event Message DLL rendering, Timeline·Search, GUI, MCP, AI, OCR/STT 및 PDF·HTML Report Renderer는 이후 단계에서 구현합니다.

---

## 핵심 차별점

### 1. 한국어 기반 디지털 포렌식 환경

APEX는 한국어 사용자를 우선 고려합니다.

- 기본 Locale: `ko-KR`
- 기본 Timezone: `Asia/Seoul`
- 기본 Encoding: UTF-8
- 한국어 사용자 인터페이스
- Artifact와 분석 결과의 한국어 설명
- 한국어 자연어 기반 AI 질의
- 한국어 Keyword Search
- 한국어 Report Template
- 한글 파일명과 경로의 손실 없는 처리
- 원본 Timestamp와 표시 Timezone의 명확한 구분

UI 문자열은 Resource Key 기반으로 관리하며, Forensic Engine은 언어에 종속되지 않는 오류 코드와 구조화된 결과를 반환합니다.

### 2. Built-in MCP 기반 AI 분석 보조

사용자에게 배포되는 APEX Desktop Distribution에는 MCP 기반 AI 기능이 기본 포함될 수 있습니다.

다만 Forensic Engine 내부에는 MCP SDK, LLM SDK, Prompt, API Key 또는 특정 AI Provider 의존성을 포함하지 않습니다.

```text
APEX Desktop Distribution
├── Frontend GUI
├── Backend / Session Context
├── Forensic Core Engine
└── Built-in MCP Adapter
    └── AI / LLM Provider
```

AI는 포렌식 엔진을 대체하지 않습니다.

GUI에서 이미 수행된 분석 결과와 현재 Context를 재사용하여 다음 작업을 보조합니다.

- 분석 결과 요약
- AI Keyword 추천
- 의심 행위 후보 설명
- Artifact 간 관계 분석
- Timeline 흐름 정리
- 추가 분석 항목 추천
- Citation 기반 답변
- 한국어 보고서 초안 작성

### 3. Progressive Indexing 기반 분석 최적화

APEX의 성능 목표는 단순히 Parser 실행 시간을 줄이는 데 그치지 않습니다.

전체 Index가 완료되기 전에도 File Tree와 Partial Result를 확인하고, 사용자가 선택한 범위를 우선 분석할 수 있도록 설계합니다.

```text
Evidence 등록
    ↓
Header / Partition / File System 기본 정보 확인
    ↓
최소 Metadata 우선 수집
    ↓
File Tree와 Partial Result 표시
    ↓
사용자 선택 Scope 우선 분석
    ↓
Background Index 및 Artifact 분석
```

검증되지 않은 제품 간 성능 우위는 주장하지 않습니다. 성능 결과는 동일한 Hardware, Evidence, 분석 범위 및 Cache 조건을 사용한 Benchmark 이후에만 문서화합니다.

---

## 설계 산출물

| 산출물 | 문서 |
|---|---|
| 전체 Architecture 및 품질 속성 | [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md) |
| 제안 Directory Structure | [`docs/DIRECTORY_STRUCTURE.md`](./DIRECTORY_STRUCTURE.md) |
| Module 역할 및 의존성 | [`docs/MODULE_RESPONSIBILITIES.md`](./MODULE_RESPONSIBILITIES.md) |
| Database Schema | [`docs/DATABASE_SCHEMA.md`](./DATABASE_SCHEMA.md) |
| API Interface | [`docs/API_INTERFACE.md`](./API_INTERFACE.md) |
| JSON Schema 규칙 | [`docs/JSON_SCHEMAS.md`](./JSON_SCHEMAS.md) |
| 단계별 Implementation Roadmap | [`docs/IMPLEMENTATION_ROADMAP.md`](./IMPLEMENTATION_ROADMAP.md) |
| Requirements Traceability | [`docs/REQUIREMENTS_TRACEABILITY.md`](./REQUIREMENTS_TRACEABILITY.md) |

기계 판독용 데이터 계약은 [`schemas/v1/`](../schemas/v1)에 있으며, 설계 검증 도구는 [`tools/`](../tools)에 있습니다.

---

## 제품과 Engine 경계

### Forensic Core Engine 담당 범위

- Case 및 Evidence 관리
- Evidence Hash와 무결성 검증
- File System 분석
- Artifact 분석
- Progressive Indexing
- Timeline 생성
- Search, Index 및 Cache
- Analysis Job과 Progress 관리
- Analysis Result Database
- Timezone 정규화
- GUI 및 Analysis Context Snapshot
- Analyst Annotation 및 Tag
- Citation과 Raw Locator
- Chain of Custody Ledger
- Report 상태와 승인 규칙
- Machine-extracted Candidate 계약
- GUI와 MCP Adapter가 사용하는 공통 Application Interface
- 버전화된 JSON Schema 결과
- Provider-neutral `AIEnrichmentPort`
- Provider-neutral `KeywordRecommendationPort`
- Provider-neutral `ReportDraftPort`
- Provider-neutral `MachineExtractionPort`

### Forensic Core Engine 비담당 범위

- MCP Server 구현
- MCP Tool 정의
- MCP SDK 의존성
- LLM Provider SDK 및 API 연동
- Prompt Engineering
- Agent Loop 및 AI Workflow
- API Key 및 Credential 관리
- AI Token 과금
- Provider별 사용량 집계
- 실제 OCR/STT Provider 실행
- 실제 PDF/HTML Renderer 구현
- AI 결과를 Observed Fact로 확정하는 동작
- Evidence 원본 수정

Built-in MCP Adapter는 Engine의 공개 Port 또는 API만 사용합니다.

제품에 MCP가 기본 포함된다는 요구사항은 Engine 내부에 MCP 또는 LLM 의존성을 추가하는 근거가 되지 않습니다.

---

## Python-Native 하이브리드 구조

APEX의 주 개발 언어는 Python입니다.

Python은 Application 및 Orchestration Layer를 담당하며, 성능 핵심 경로는 Native Library 또는 Native Tool을 Adapter 형태로 연결합니다.

```text
Python Application / Orchestration Layer
├── Case / Evidence Management
├── Job Scheduling
├── Analysis Workflow
├── Result Aggregation
├── Timeline / Context
├── API / JSON Schema
├── GUI / MCP Interface
└── Report Workflow
          │
          ▼
Native Analysis Adapter Layer
├── Disk Image Reader
├── File System Parser
├── Hash Provider
├── Search Index Provider
├── Binary Scanner
└── Multimedia Processor
```

검토 가능한 Native 기술 후보:

- Sleuth Kit 및 `libtsk`
- `pytsk3` 또는 유지보수 가능한 Python Binding
- E01 처리를 위한 `libewf` 또는 `pyewf`
- VHD/VHDX 처리를 위한 `libvhdi`
- SQLite FTS5 또는 동등한 Search Index
- Python `hashlib`가 사용하는 Native Hash 구현
- FFmpeg 또는 ffprobe
- YARA 및 `yara-python`
- `mmap` 기반 Random Access
- 병목 구간용 Rust, C 또는 C++ Extension

구체적인 Library는 다음 기준을 확인한 후 확정합니다.

- Windows 지원 여부
- Python 버전 호환성
- Evidence 형식 및 File System 지원 범위
- 삭제 파일 지원 여부
- Process 및 Thread 안전성
- 유지보수 상태
- License
- 오류 처리 방식
- Packaging 난이도
- Benchmark 결과

### 병렬 처리

CPU 집약적인 분석은 Process Pool을 사용하고, I/O 집약적인 처리는 Async I/O 또는 제한된 Thread Pool을 사용합니다.

```text
Registry Worker ─────┐
Event Log Worker ────┤
Prefetch Worker ─────┼──> Bounded Result Queue ──> Single DB Writer
Media Worker ────────┘
```

여러 Analyzer가 SQLite에 직접 동시에 기록하지 않습니다.

분석 결과는 Bounded Queue를 통해 Case별 Single DB Writer에 전달하고 Batch Insert로 저장합니다.

### 대용량 Evidence 처리

대용량 Evidence 전체를 메모리에 적재하지 않습니다.

- Chunk 단위 Streaming
- 필요한 Offset만 선택적으로 조회
- Lazy Loading
- Cursor Pagination
- Memory Mapping 적용 검토
- Bounded Queue를 통한 Backpressure
- Checkpoint 및 Resume
- Evidence Fingerprint 기반 중복 분석 방지
- Analyzer Version과 Option을 포함한 Cache Key
- 기존 GUI 분석 결과 재사용

Benchmark 결과 Python 계층에서 실제 병목이 확인된 경우에만 해당 구간을 Rust, C 또는 C++ Accelerator로 교체할 수 있도록 설계합니다.

---

## 전체 Architecture

```text
사용자
  │
  ▼
Frontend GUI
  │
  │ 분석 실행 및 현재 선택 상태 전달
  ▼
Backend / Application Interface
  │
  ▼
Forensic Core Engine
  │
  ├── Analysis Result Database
  ├── Timeline / Search / Artifact Result
  ├── Progressive Indexing
  ├── Session Context
  └── Context Snapshot
          │
          ▼
    Built-in MCP Adapter
          │
          ▼
       AI Agent
```

GUI와 MCP Adapter는 서로 다른 분석 로직을 구현하지 않습니다.

두 계층은 동일한 Engine Interface와 JSON Schema를 사용합니다.

---

## 기존 분석 결과 재사용

APEX의 AI는 Evidence를 무조건 처음부터 다시 분석하지 않습니다.

```text
GUI에서 분석 실행
    ↓
Forensic Engine Job
    ↓
Analysis Result Database 저장
    ↓
GUI Context 구성
    ↓
Analysis Context Snapshot 생성
    ↓
Built-in MCP Adapter 조회
    ↓
AI 해석 / Keyword 추천 / 추가 분석 제안 / Report Draft
```

이를 통해 다음 효과를 기대할 수 있습니다.

- 동일 Evidence 중복 분석 방지
- GUI 분석 결과와 AI 답변의 일관성 유지
- AI 입력 근거 추적
- 분석 과정과 Report 생성 과정 재현
- 분석자의 선택과 판단 보존
- AI 추론과 실제 Evidence의 명확한 분리

---

## Progressive Indexing

### Analysis Profile

| Profile | 목적 | 대표 범위 |
|---|---|---|
| Quick Triage | 첫 화면과 최근 활동 후보를 빠르게 제공 | Partition, 경로, 이름, 크기, 형식, 기본 시간, 삭제 여부, 우선 Artifact |
| Selected Scope | 분석자가 선택한 범위만 우선 처리 | 선택 Evidence, File, Artifact, Time Range, Analyzer |
| Full Analysis | 전체 재현 가능한 분석 | 전체 Hash, Metadata, Text Index, Artifact, Timeline, Media, Browser |
| Custom Profile | Analyzer와 Option을 조합 | Artifact Enable/Disable, Hash, Index, Worker 정책 |

### Index Job 기능

- Background Indexing
- 사용자 선택 Scope Priority Queue
- Analyzer별 Enable/Disable
- Pause
- Resume
- Cancel
- Checkpoint 및 Resume
- 처리 Item 수
- 추정 전체 Item 수
- 처리량
- 경과 시간
- 추정 잔여 시간
- ETA Confidence
- 현재 Analyzer
- Worker 수
- Cache Hit/Miss
- Partial Result 조회

ETA는 확정값이 아닌 추정치로 표시합니다.

전체 Index 완료 전에도 다음 기능을 제공합니다.

- File Tree 조회
- 현재까지 발견된 Artifact 조회
- 현재까지 생성된 Timeline 조회
- 현재까지 생성된 Index 범위 내 Search
- Partial Result 여부 및 미완료 범위 표시

---

## Timezone 자동화

원본 Timestamp는 절대 재작성하지 않습니다.

- 원본 Timestamp 보존
- 내부 정규화 Timestamp는 UTC 사용
- 화면과 Report는 Case Timezone 사용
- 기본 Case Timezone은 `Asia/Seoul`
- IANA Timezone ID 사용
- DST 처리
- Timezone 출처와 Confidence 기록
- 자동 탐지 결과에 대한 분석자 확인
- Timezone 해석 변경 Audit
- UTC와 Case Timezone 동시 표시
- 서로 다른 Timezone Artifact의 통합 Timeline

Timezone 후보 출처:

- Case 설정
- Evidence 운영체제 설정
- Windows Registry `TimeZoneInformation`
- Linux `/etc/localtime`
- Browser Profile
- Application 설정
- Artifact 자체 Offset
- 분석자 수동 지정

신뢰도:

- `CONFIRMED`
- `HIGH`
- `MEDIUM`
- `LOW`
- `UNKNOWN`

자동 탐지가 불확실한 경우 AI가 Timezone을 임의로 확정하지 않습니다.

---

## GUI Context와 Analysis Context

### GUI Context

GUI Context는 현재 사용자의 분석 상태를 표현하는 Session 단위 임시 데이터입니다.

포함 가능한 정보:

- 현재 Case
- 현재 Evidence
- 현재 화면
- 선택된 File
- 선택된 Artifact
- 선택된 Timeline Event
- 선택된 Search Result
- 활성 Filter
- Timeline 시간 범위
- Tag 및 주요 Evidence
- Locale 및 Timezone

Live GUI Context는 Session Store에서 관리합니다.

Audit, AI 요청 또는 Report 재현이 필요한 경우에만 불변 Context Snapshot으로 저장합니다.

### Scope별 Analysis Context

AI Context는 하나의 거대한 Bundle로 모든 결과를 혼합하지 않습니다.

지원 Scope:

- `case`
- `evidence`
- `filesystem`
- `registry`
- `eventlog`
- `prefetch`
- `browser`
- `media`
- `timeline`
- `keyword_search`
- `report`
- `chain_of_custody`

각 Scope는 다음 정보를 포함할 수 있습니다.

- Context Revision
- 포함 Result ID
- Analyzer Version
- Filter 및 Time Range
- Partial Result 여부
- Citation
- Context 생성 시점
- 실제 AI 요청에 전달된 Scope

상위 Case Context는 필요한 Scope만 선택하여 결합합니다.

---

## AI 결과 분류

APEX는 Engine이 추출한 사실과 AI가 생성한 내용을 구분합니다.

### Observed Fact

Forensic Engine이 Evidence에서 직접 추출한 사실입니다.

예:

- File Path
- Hash
- Timestamp
- Registry Value
- Event ID
- Browser URL

### Analyst Annotation

분석자가 작성한 설명, 판단 또는 Tag입니다.

### Machine-extracted Candidate

OCR, STT 또는 자동 Text Extraction을 통해 얻은 검토 전 후보입니다.

### AI Inference

AI가 Observed Fact와 Context를 기반으로 만든 추론입니다.

### AI Recommendation

AI가 제안하는 추가 분석 절차 또는 대응 방안입니다.

AI는 다음 동작을 수행할 수 없습니다.

- 침해 사실을 단독 확정
- Citation 없이 사실 단정
- Partial Result를 전체 분석 결과처럼 표현
- Scope 외 결과 임의 혼합
- 원본 Artifact 수정
- AI Inference를 Observed Fact로 승격
- 분석자가 승인하지 않은 Keyword 자동 실행

---

## AI Keyword Recommendation

AI는 조사 범위를 줄이기 위한 Keyword Candidate를 제안할 수 있습니다.

```text
Case 배경 정보
+
선택 Scope
+
기존 File / Artifact / Timeline / Search Result
        ↓
Keyword Candidate 생성
        ↓
Reason / Scope / Confidence / Citation 표시
        ↓
분석자 검토
        ↓
승인된 Keyword만 검색 실행
        ↓
Keyword Set과 Search Result 저장
```

Keyword Candidate 유형:

- File Name
- Process Name
- Account
- Email
- Domain
- URL
- IP Address
- Registry Path
- Command
- Path
- Document Term
- Hash
- Regex
- Related Term
- Transliteration
- Typo Variant

필수 원칙:

- AI 추천 Keyword 자동 실행 금지
- 분석자 승인 후 Search 실행
- 추천 이유와 Citation 필수
- Scope와 Confidence 표시
- 중복 Keyword 제거
- Keyword Set Version 관리
- Search Option 저장
- Time Range와 Evidence Scope 저장
- 0건 결과도 보존
- 동일 검색 재실행 지원
- 분석자 수동 Keyword도 같은 방식으로 관리

---

## Simple / Detailed / Raw View

동일 Finding을 세 단계로 확인할 수 있도록 설계합니다.

| View | 제공 내용 |
|---|---|
| Simple | 한국어 설명, 주요 발견 후보, AI 요약, 추천 분석, 핵심 Timeline |
| Detailed | 전체 Artifact Field, Parser/Version, Source, Timezone 해석, Confidence, Citation, Filter |
| Raw | 원본 Field/Value, Byte Offset/Length, Encoding, Hex/Text, 원본 Timestamp, Raw Snippet |

원칙:

- 동일 Finding에서 View 전환
- AI 설명과 원본 Fact 시각적 분리
- Raw Locator와 Citation 연결
- 최대 Read Length 제한
- 필요한 Offset만 읽기
- 대용량 파일 전체 로딩 금지
- 원본 Evidence 읽기 전용 유지
- Raw View 권한 정책 검토

---

## Chain of Custody

Chain of Custody는 일반 Report 문장이 아니라 Evidence 관리의 독립적인 Append-only Ledger입니다.

지원 Custody Event 예시:

- `ACQUISITION`
- `RECEIVED`
- `TRANSFERRED`
- `STORED`
- `OPENED`
- `MOUNTED`
- `ANALYZED`
- `HASH_VERIFIED`
- `COPIED`
- `EXPORTED`
- `RETURNED`
- `RELEASED`
- `ARCHIVED`
- `DISPOSED`
- `CORRECTION`

설계 원칙:

- 기존 Custody Event 직접 수정·삭제 금지
- 오류 수정은 `CORRECTION` Event 추가
- Append-only Ledger
- Event Hash Chain 적용 검토
- Evidence 최초 Hash와 재검증 Hash 기록
- Hash 불일치 경고
- 사용자·역할·승인자 기록
- 이동·접근·분석·Export 이력 보존
- Export 시 Custody Snapshot 생성
- Report Version과 Custody Snapshot 연결

이 설계는 법적 증거능력을 보장하지 않습니다.

관할 법률, 조직 정책, Actor Identity 및 전자서명 방식은 Backend·운영·법무 담당자의 최종 검토가 필요합니다.

---

## Multimedia 분석

### Media MVP

현재 구현:

- Image / Video / Audio File 후보 분류
- JPEG / PNG / GIF / BMP / TIFF / WEBP Header Metadata와 JPEG EXIF / GPS Candidate
- MP4 Container Duration / Codec Metadata 및 Optional `ffprobe` 기반 Video / Audio Metadata
- `ffprobe` 미설치 또는 실패 시 `CAPABILITY_UNAVAILABLE` / Warning을 기록하고 가짜 성공 금지
- Decompression Bomb, 손상 File, Read Limit, File Size Limit 보호
- Timezone 없는 EXIF / Media Timestamp를 UTC로 임의 확정하지 않음
- Source Revision, Raw Locator, Citation, Search / Timeline Projection, Stable Cursor 조회
- Hash 검증 가능한 Thumbnail Derivative Metadata를 `cache_entries`와 `thumbnail_records`에 저장

현재 제한:

- Pixel 자동 회전, 원본 Media 수정, Reverse Geocoding, 자동 대량 Thumbnail Rendering은 구현하지 않음
- Video 전체 Frame Sampling, Subtitle 추출, OCR/STT 실행은 구현하지 않음

### Machine-extracted Candidate

OCR 및 STT 결과는 Observed Fact가 아니라 `Machine-extracted Candidate`로 분류합니다.
Provider Port와 Candidate Review Workflow는 구현되어 있으며 기본 OCR/STT Provider는
`CAPABILITY_UNAVAILABLE`을 반환합니다. 실제 OCR/STT Engine은 실행하지 않습니다.

Review 상태:

- `UNREVIEWED`
- `ACCEPTED`
- `REJECTED`
- `CORRECTED`

Candidate에는 다음 정보를 포함합니다.

- Confidence
- Language
- Engine 및 Version
- Frame Number
- Timestamp Offset
- Source Region
- Raw Locator
- Citation
- Analyst Review Status

AI는 검토되지 않은 Candidate를 확정 사실로 표현할 수 없습니다.

---

## Browser Communications MVP

현재 구현:

- File System Index 기반 Chromium / Firefox Profile 후보 발견
- Windows / Linux Path Allowlist, Unicode Path 보존, Profile 중복 방지
- Profile 발견과 Browser 사용 확정을 분리하고 `user_candidate`는 후보로만 보존
- Chromium `History` SQLite의 방문, 검색어, 다운로드 추출
- Firefox `places.sqlite` 방문 및 Download Annotation Candidate 추출
- 원본 DB를 직접 수정하지 않는 `/tmp` Snapshot Reader와 WAL / SHM 조합 보존
- Source Fingerprint, Snapshot Hash, Profile / DB / Table / Row Logical Raw Locator 기록
- Raw Timestamp Semantics, UTC 정규화 근거, Case Timezone 표시 분리
- Stable Cursor 기반 조회, Search / Timeline Projection, Checkpoint / Resume / Pause / Cancel

현재 제한:

- Password / Secret / Cookie 복호화, Cache Body 복원, 삭제 Record Carving, Incognito 복원,
  Cloud Sync 분석은 구현하지 않음
- Firefox Search Term은 재현 가능한 Source가 없으면 완료 기능으로 표시하지 않음
- Firefox `moz_inputhistory`는 URL-bar 입력 Candidate로 보존하며, 확인된 Search Term이나
  Browser Search Timeline Event로 투영하지 않음
- `danger_type` 등 다운로드 상태 값만으로 악성 여부를 확정하지 않음

후순위 Plugin 범위:

- Email
- Discord
- Telegram
- KakaoTalk
- 기타 Messenger

후순위 기능은 초기 구현 완료 항목으로 표시하지 않습니다.

---

## AI Report와 Human Review

AI가 생성한 Report는 즉시 최종 결과로 확정하지 않습니다.

```text
AI Draft
    ↓
Human Review
    ↓
Approval
    ↓
PDF / HTML Export
```

Report 상태:

- `DRAFT`
- `GENERATING`
- `REVIEW_REQUIRED`
- `APPROVED`
- `REJECTED`
- `EXPORTING`
- `EXPORTED`
- `FAILED`

승인된 특정 Report Version만 Export할 수 있습니다.

승인 후 내용이 변경되면 기존 승인은 무효화되고 다시 검토해야 합니다.

Report에 포함 가능한 항목:

1. 사건 개요
2. 분석 목적
3. 분석 대상
4. Evidence 정보
5. Hash 및 무결성 정보
6. Chain of Custody
7. 분석 환경
8. Analysis Profile 및 완료 범위
9. Timezone 및 변환 정책
10. 주요 발견 사항
11. File System 분석 결과
12. Artifact 분석 결과
13. Images / Videos 분석 결과
14. Browser Communications 분석 결과
15. Timeline
16. Keyword Set 및 Search Options
17. AI 분석 요약
18. Raw Citation
19. Machine-extracted Candidate와 검토 상태
20. 결론
21. 대응 권고
22. 분석 범위와 제외 범위
23. 증거 출처 및 Citation
24. 분석 한계

지원 예정 Export:

- PDF
- HTML

---

## 주요 Engine 모듈

### Case Manager

- Case 생성 및 조회
- Locale 및 Timezone 관리
- Case 상태 관리
- Evidence 및 분석 결과 연결

### Evidence Manager

- Disk Image 및 Logical Evidence 등록
- Metadata 추출
- Hash 계산
- 무결성 검증
- Evidence Fingerprint 관리
- Custody 기본 Event 생성

지원 예정 형식:

- E01
- RAW
- DD
- IMG
- VHD
- VHDX
- Directory Evidence

### Progressive Indexing Coordinator

- Analysis Profile 적용
- Background Index 관리
- Priority Queue
- Pause / Resume / Cancel
- Partial Result
- Progress 및 ETA
- Checkpoint 및 Resume

### File System Analyzer

- Directory Tree
- File 및 Folder 목록
- Metadata
- 삭제 File
- File Type 분류
- Cursor Pagination
- Lazy Loading
- Raw Locator

### Artifact Analyzer

초기 지원 대상:

- Windows Registry
- Windows Event Log
- Windows Prefetch
- Browser History
- Search History
- Download History
- Recent Activity
- Image Metadata
- Video Metadata
- Audio Metadata

### Timeline Engine

- File MAC Time
- Registry Timestamp
- Event Log Timestamp
- Browser Activity
- Program Execution Time
- Timezone 정규화
- Event Type 및 Time Range Filter
- Citation 가능한 Timeline Event

### Search Engine

- File Name Search
- Keyword Search
- Regex Search
- Metadata Search
- Artifact Search
- 한국어 Search
- FTS5 또는 동등한 Index
- Cursor Pagination
- Search Result Cache
- Keyword Set
- Search Reproduction

### Context Module

- Live GUI Context
- Scope별 Context Revision
- Analysis Context Bundle
- Partial Result 표시
- 재현용 Context Snapshot

### Chain of Custody Module

- Append-only Custody Event
- Correction Event
- Hash Verification
- Ledger Integrity
- Custody Snapshot
- Report Version 연결

### Report Module

- Template 관리
- Evidence / Finding / Timeline 선택
- Citation 관리
- AI Draft Port
- Human Review
- Approval
- Export 상태 관리

---

## Data Contract

APEX는 JSON Schema Draft 2020-12 기반 데이터 계약을 사용합니다.

주요 Schema:

- Case
- Evidence
- File
- Artifact
- Timeline Event
- Search Result
- Job
- API Response
- UI Context
- Analysis Context
- AI Enrichment
- Citation
- Report
- Analysis Profile
- Keyword Recommendation 및 Keyword Set
- Chain of Custody
- Machine-extracted Candidate

Schema 원칙:

- 명시적인 `required`
- 명시적인 `additionalProperties`
- 일관된 ID 형식
- ISO 8601 Timestamp
- IANA Timezone
- 로컬 `$ref`
- Schema Version
- Partial Result 표시
- Confidence와 Review Status 구분
- Observed Fact와 AI 결과 분리
- 순환 참조 방지

---

## 현재 저장소 구조

```text
APEX/
├── README.md
├── pyproject.toml
│
├── docs/
│   ├── API_INTERFACE.md
│   ├── ARCHITECTURE.md
│   ├── DATABASE_SCHEMA.md
│   ├── DIRECTORY_STRUCTURE.md
│   ├── IMPLEMENTATION_ROADMAP.md
│   ├── JSON_SCHEMAS.md
│   ├── MODULE_RESPONSIBILITIES.md
│   └── REQUIREMENTS_TRACEABILITY.md
│
├── src/
│   └── apex_forensic/
│       ├── domain/
│       ├── application/
│       ├── ports/
│       ├── adapters/
│       ├── jobs/
│       ├── cli/
│       └── config/
│
├── schemas/
│   └── v1/
│       ├── ai-enrichment.schema.json
│       ├── analysis-context.schema.json
│       ├── analysis-profile.schema.json
│       ├── api-response.schema.json
│       ├── artifact.schema.json
│       ├── case.schema.json
│       ├── chain-of-custody.schema.json
│       ├── citation.schema.json
│       ├── common.schema.json
│       ├── evidence.schema.json
│       ├── file.schema.json
│       ├── job.schema.json
│       ├── keyword-recommendation.schema.json
│       ├── machine-extraction.schema.json
│       ├── report.schema.json
│       ├── search.schema.json
│       ├── timeline-event.schema.json
│       └── ui-context.schema.json
│
└── tools/
    ├── validate_design.mjs
    ├── validate_design_basic.py
    └── validate_design.sh

tests/
├── unit/
├── integration/
└── conftest.py
```

---

## 개발 진행 상태

### 설계 완료

- [x] Core Architecture
- [x] Database Schema
- [x] API Interface
- [x] JSON Schema v1
- [x] Module Responsibility
- [x] Requirements Traceability
- [x] Implementation Roadmap
- [x] Python-Native 하이브리드 구조
- [x] GUI Context
- [x] Scope별 Analysis Context
- [x] Citation 및 Raw Locator
- [x] Provider-neutral AI 경계
- [x] Report Human Review 및 Approval
- [x] 한국어 및 Localization
- [x] Progressive Indexing 및 Analysis Profile
- [x] Timezone 탐지·정규화·Audit
- [x] AI Keyword Recommendation
- [x] Search Reproduction
- [x] Append-only Chain of Custody
- [x] Simple / Detailed / Raw View
- [x] Browser Communications MVP
- [x] Media Metadata MVP
- [x] OCR/STT Machine-extracted Candidate 계약
- [x] 외부 전문가 검증 계획
- [x] 설계 검증 도구

### 구현 예정

- [x] Phase 1 Core Foundation
- [x] Project Skeleton 및 공통 Infrastructure
- [x] Case / Evidence / Hash 관리
- [x] Chain of Custody Ledger 및 검증 Service
- [x] SQLite Repository 기반 저장
- [x] CLI Smoke Test Interface
- [x] Unit / Integration Test
- [ ] Progressive File System 및 Indexing
- [ ] Registry / Event Log / Prefetch Analyzer
- [ ] Timeline / Search / Keyword Set
- [ ] Timezone Resolver 및 Timestamp Normalizer
- [x] Browser Communications Analyzer
- [x] Images / Videos / Audio Analyzer
- [x] OCR/STT Provider Port 및 Candidate Review
- [ ] GUI Context 및 Scope별 Analysis Context
- [ ] Simple / Detailed / Raw View
- [ ] MCP Adapter용 공개 Interface
- [ ] AI Keyword Recommendation 및 Citation Workflow
- [ ] Report Review / Approval / PDF·HTML Export
- [ ] 한국어 Search 및 Localization
- [ ] 성능 Benchmark 및 외부 전문가 검토
- [ ] Windows Desktop Packaging

### 별도 담당

- [ ] Built-in MCP Adapter — MCP 담당
- [ ] LLM Provider / Prompt / Agent Workflow — MCP·AI 담당
- [ ] Identity / Approval / Billing — Backend 담당
- [ ] 한국어 GUI 및 View 구현 — Frontend 담당

---

## Implementation Roadmap

### Phase 0 — 설계 및 기술 Spike

- Schema 및 문서 정합성 검증
- Native Provider 기술 검토
- Progressive Index Prototype
- Timezone Fixture
- Chain of Custody Event Model
- Keyword Recommendation Contract
- Raw Range Reader 제한
- OCR/STT Provider 기술 검토
- External Validation Plan

### Phase 1 — Core Foundation

- Project Skeleton
- Case Manager
- Evidence Manager
- Hash 및 무결성 검증
- Custody 기본 Event
- Timezone 기본 설정
- Job 및 Progress 기본 구조
- JSON Schema 기반 출력 검증
- CLI Smoke Test Interface

### Phase 2 — Progressive File System

- File System Analyzer
- Quick Triage
- File Tree 우선 표시
- Background Index
- Priority Queue
- Pause / Resume / Cancel
- Partial Result
- Lazy Loading
- Cursor Pagination

### Phase 3 — Windows Artifact

- Registry
- Event Log
- Prefetch
- Raw Locator

### Phase 3 — Windows Artifact Analysis MVP — 구현 완료

Phase 3 implements offline, read-only analysis of Windows artifacts already represented by the Phase
2 file system index. The engine does not collect from a live Windows host and does not apply Registry
exports to the host system.

Supported Registry behavior:

- `.reg` export text with UTF-16LE/UTF-8 BOM detection.
- Key/value artifacts for string, expand string, DWORD, QWORD, binary, and safe multi-string values.
- Autorun candidates from Run/RunOnce keys with machine/user scope and 32-bit view candidates.
- USBSTOR device candidates with vendor/product/serial fields and confidence warnings when
  observation times cannot be correlated.
- TimeZoneInformation values with optional Windows-to-IANA mapping candidates.
- UserAssist ROT13 names and safe counter ranges only.

Supported Event Log behavior:

- Exported Event XML with namespace-safe extraction of System, EventData, UserData, raw XML, and
  normalized UTC SystemTime.
- Optional EVTX parsing through `python-evtx` when installed; otherwise
  `CAPABILITY_UNAVAILABLE`/`UNSUPPORTED` is reported.
- No Message DLL rendering and no automatic maliciousness conclusion.

Supported Prefetch behavior:

- Minimal `.pf` metadata for tested versions 17, 23, 26, and 30.
- Executable name, Prefetch hash, file size, run count, and safe last-run FILETIME extraction.
- Unknown versions and MAM compression are explicit unsupported parse states.

Raw locators and citations are attached to every emitted artifact. Logical Registry/Event locators use
null byte offsets with limitations; Prefetch header fields use bounded byte ranges. Artifact query
supports type/subtype, analyzer, source node, event ID, registry path, executable name, time range,
parse status, warning flag, and opaque stable cursors.

### Phase 4 — Search 및 Timeline

- Search Index
- Keyword Set
- Search Reproduction
- Timezone Normalization
- Timeline 통합
- Cache 및 Parallel Job

### Phase 5 — Browser와 Media

- Browser Communications MVP
- Image / Video / Audio Metadata
- OCR/STT Contract
- Machine-extracted Candidate

### Phase 6 — GUI Context 및 View

- GUI Context
- Scope별 Analysis Context
- Simple / Detailed / Raw View
- MCP Adapter용 공개 Interface

### Phase 7 — AI Assistance

- Keyword Recommendation
- Scope Summary
- Citation
- Partial Result 경고
- Human Verification

### Phase 8 — Report 및 Chain of Custody

- AI Draft
- Human Review
- Approval
- Chain of Custody Section
- PDF / HTML Export

### Phase 9 — Benchmark 및 배포

- 동일 조건 기반 내부 Benchmark
- Progressive Indexing 및 Cache Cold/Warm 비교
- Timezone 정확성과 Timeline 재현성 검증
- Chain of Custody 무결성 검증
- AI Citation 및 Keyword 추천 유용성 평가
- 공개 또는 Synthetic Evidence 기반 외부 전문가 검토
- 전문가 피드백 반영 및 재검증
- Native Dependency Packaging 검증
- Windows Desktop Packaging
- 최종 문서 및 Release 준비

---

## 외부 전문가 검증 계획

APEX는 내부 Benchmark와 함께 디지털 포렌식 및 사이버 작전 실무 경험을 보유한 외부 전문가의 자문을 통해 성능과 Workflow 적합성을 검증할 예정입니다.

현재 상태는 `PLANNED`입니다.

검증 데이터 원칙:

- 공개 DFIR Dataset
- 직접 제작한 Synthetic Evidence
- 법적으로 사용 가능한 Test Image
- 비공개 작전 자료 사용 금지
- 개인정보 및 기밀정보 사용 금지
- 외부 공개 시 Dataset과 조건 명시

검증 항목:

- Evidence 등록 시간
- E01 최초 열기 시간
- 첫 File Tree 표시 시간
- Quick Triage 완료 시간
- Full Index 완료 시간
- Artifact별 분석 시간
- Keyword Search 응답 시간
- AI Keyword 추천 유용성
- Cache Cold/Warm 성능
- Index Pause/Resume
- Timezone 정확성
- Timeline 재현성
- Report 작성 시간 절감
- Chain of Custody 완전성
- CPU, Memory 및 Disk I/O
- GUI 사용성
- Raw View 검증 가능성
- AI Citation 정확성
- 실제 조사 Workflow 적합성

공식 승인이나 협력이 확정되지 않은 기관명은 인증 또는 협력 기관으로 표시하지 않습니다.

---

## Phase 1 실행 방법

현재 실행 구현은 Phase 1 Core Foundation에 한정됩니다. Evidence 원본은 읽기 전용으로 열고,
Directory Evidence는 Metadata 등록만 지원하며 Directory 전체 Hash는 아직 지원하지 않습니다.

### 가상환경 생성 및 Dependency 설치

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

### 테스트 실행

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy src
```

### Database 초기화

```bash
.venv/bin/apex-forensic init --db ./apex.db
```

### CLI 예시

```bash
.venv/bin/apex-forensic --db ./apex.db case create \
  --name "테스트 사건" \
  --investigator "권태욱" \
  --description "Phase 1 Test" \
  --json

.venv/bin/apex-forensic --db ./apex.db evidence add \
  --case-id <case_id> \
  --path ./sample.bin \
  --json

.venv/bin/apex-forensic --db ./apex.db evidence hash \
  --evidence-id <evidence_id> \
  --algorithm sha256 \
  --json

.venv/bin/apex-forensic --db ./apex.db evidence verify \
  --evidence-id <evidence_id> \
  --json

.venv/bin/apex-forensic --db ./apex.db custody list \
  --evidence-id <evidence_id> \
  --json
```

### 현재 지원되는 Evidence 범위

- 일반 File / Logical File byte stream 등록
- E01, RAW, DD, IMG, VHD, VHDX 파일의 Metadata 등록과 byte stream hash
- Directory Evidence Metadata 등록
- MD5, SHA-1, SHA-256 Streaming Hash
- 저장 Hash 재검증과 `HASH_VERIFIED` Custody Event

### 현재 지원되지 않는 기능

- E01 / RAW / VHD 내부 File System Parsing
- Registry, Event Log, Prefetch, Browser, Media Artifact Parser
- Progressive Indexing 전체 기능과 Full Text Index
- GUI, Backend Web Server, MCP Server/Tool, LLM/Prompt/Agent Loop
- OCR/STT, FFmpeg, YARA, PDF/HTML Renderer, 전자서명, Benchmark

### 설계 검증 명령

```bash
python3 -X utf8 tools/validate_design_basic.py
node tools/validate_design.mjs
bash ../tools/validate_design.sh
```

Ajv CLI가 로컬에 설치되어 있지 않으면 Shell Wrapper는 Ajv Strict 검증을 생략하고 사유를
출력합니다.

---

## 설계 검증

### Python 기본 검증

Node 또는 Ajv가 없는 환경에서도 기본 검증을 실행할 수 있습니다.

```powershell
python -X utf8 .\tools\validate_design_basic.py
```

### Node 기반 전체 검증

Node가 설치된 환경:

```powershell
node .\tools\validate_design.mjs
```

### Linux / WSL / CI 검증

```bash
bash ../tools/validate_design.sh
```

검증 범위:

- JSON Syntax
- JSON Schema Draft 2020-12
- Ajv Strict Mode
- 로컬 `$ref`
- 순환 참조
- Markdown Link
- Requirement ID 중복
- API Endpoint 중복
- API와 Schema 대응 관계
- Database Table과 Module Owner
- Partial Result 필드
- Timezone 계약
- Keyword Candidate의 Reason 및 Citation
- Machine Extraction의 Confidence 및 Review Status
- Custody Event Enum과 Report Section 일치
- MCP 및 LLM 실행 코드 미포함 여부

Node 또는 Ajv가 없는 경우 기본 검증을 수행하고, 생략된 검증 항목과 이유를 출력합니다.

---

## 참고 프로젝트

- [X-Ways 스타일 포렌식 엔진](https://github.com/tagalston101/x-way-forensics-tool)
- [Autopsy](https://github.com/sleuthkit/autopsy)
- [X-Ways Forensics MCP](https://github.com/joyooosama/x-ways-forensics-mcp)

| 참고 프로젝트 | 참고 영역 |
|---|---|
| X-Ways 스타일 포렌식 엔진 | 빠른 Evidence 탐색 및 대용량 처리 철학 |
| Autopsy | Case 기반 Workflow, Artifact 구조, Timeline, Report 및 사용자 경험 |
| X-Ways Forensics MCP | GUI 결과와 포렌식 기능을 MCP Context로 연결하는 방식 |

APEX는 위 프로젝트의 구조와 Workflow를 참고하지만 특정 제품을 그대로 복제하는 것을 목표로 하지 않습니다.

외부 소스 코드를 직접 사용하는 경우 각 프로젝트의 License와 저작권 조건을 확인합니다.

---

## 개발 목적 및 주의사항

APEX는 합법적인 디지털 포렌식 조사, 보안 연구 및 교육을 목적으로 개발합니다.

AI가 생성한 분석 결과와 Report는 분석 보조 자료이며, 최종 판단은 분석자가 원본 Evidence와 근거를 검토한 후 내려야 합니다.

모든 분석 과정은 다음 원칙을 따릅니다.

- Evidence 무결성 유지
- 원본 Evidence 읽기 전용 처리
- 분석 과정 Audit
- Citation 기반 근거 추적
- AI 결과와 Observed Fact 분리
- 분석 결과 재현 가능성 확보
- Chain of Custody Event 불변성 유지
- 검증되지 않은 성능 또는 법적 효력 주장 금지

## Phase 2 구현 업데이트

Phase 2는 Directory Evidence와 일반 Logical File Evidence를 대상으로 하는 Progressive File System & Indexing 기반을 구현한다. 구현된 범위는 read-only metadata index, Logical Directory Provider, provider capability contract, SQLite-backed priority queue/checkpoint/coverage, stable cursor pagination, CLI E2E 흐름, JSON Schema 계약 및 회귀 테스트다.

지원 범위는 다음과 같다.

- Directory Evidence는 `os.scandir()` 기반으로 원본 이름과 상대 경로를 손실 없이 보존하며 metadata만 수집한다.
- 일반 logical file evidence는 하나의 root/file node로 표현한다.
- Quick Triage는 기본 깊이 제한으로 빠른 partial tree를 제공하고, Full Analysis는 전체 directory metadata tree를 완료한다.
- Selected Scope는 선택된 directory/node를 background scope보다 우선 queue에 배치한다.
- item budget은 deterministic partial result와 checkpoint/resume 재현에 사용한다.
- pause, resume, cancel은 batch/checkpoint 경계에서 cooperative 방식으로 동작하며 partial 결과를 보존한다.
- symlink 및 reparse point는 기본적으로 따라가지 않고 entry 자체만 가능한 metadata로 기록한다.
- metadata indexing 중 file body를 읽지 않고 automatic hash를 수행하지 않는다. Hash는 기존 Evidence Hash Service의 명시 호출에서만 수행한다.
- File tree 조회는 opaque stable cursor를 사용하며 query option과 cursor fingerprint 불일치를 검증한다.

Phase 2 비지원 범위는 E01/RAW/DD/IMG/VHD/VHDX 내부 filesystem parsing, NTFS/FAT/exFAT/ext 직접 parser, deleted file recovery, slack/unallocated 분석, FTS5/full text search, artifact parser, timeline 통합, GUI, web server, MCP/LLM/OCR/STT/report renderer 실행 코드다. 해당 내부 탐색 요청은 `CAPABILITY_UNAVAILABLE`로 표현한다.

## Phase 4 Search, Keyword Set, Timeline 구현

Forensic Core Engine은 Phase 4에서 저장된 metadata와 artifact field만 대상으로 하는 Search와
Timeline projection을 제공한다. Search Index Coordinator는 기존 Job/Progress/Checkpoint를
재사용하고 background daemon 없이 batch 단위로 동작한다. SQLite FTS5가 runtime capability로
확인되지 않으면 Search Index/Query는 `CAPABILITY_UNAVAILABLE`을 반환한다.

Search Document source는 `FILE_SYSTEM_NODE`, `WINDOWS_ARTIFACT`, `TIMELINE_EVENT`이며 document
type은 file/directory/registry/event log/prefetch/timeline/other로 분리된다. Index field는
allowlist 기반이고 대용량 JSON 전체 또는 원본 file body를 하나의 문자열로 넣지 않는다. Query는
TERM, PHRASE, PREFIX, EXACT, 제한된 `REGEX_METADATA`를 지원한다. Regex는 case/evidence/type/path/time
candidate를 먼저 제한한 뒤 structured metadata에 post-filter한다.

Keyword Set은 수동/외부 입력 keyword만 관리하며 AI recommendation 실행 코드는 없다. Active set
수정은 새 version을 생성하고 이전 version을 보존한다. Search Reproduction은 query option,
keyword set version, backend/version, index revision, source revision, 0건 결과와 partial 상태를
불변 실행 기록으로 저장한다.

Timeline Generator는 filesystem created/modified/accessed/changed, registry observed facts,
Event Log SystemTime, Prefetch last run candidate를 event로 변환한다. Raw/UTC/case time을 분리하고
timezone source/confidence, semantics, precision, raw locator, citation, partial flag를 보존한다.
Event ID나 Prefetch만으로 악성 여부 또는 사용자 실행 사실을 확정하지 않는다.

## Phase 6 Runtime Notes

The executable Phase 6 layer stores live GUI session contexts separately from immutable analysis snapshots. Session contexts carry route, selection, filter, time range, keyword/search/timeline references, schema version, revision, TTL, and actor fields; snapshot creation resolves selected resources into case-scoped bundles with deterministic fingerprints and previous-snapshot linkage.

View projection is split into Simple, Detailed, and Raw modes. Simple mode returns compact finding-oriented fields, Detailed mode preserves technical payload and provenance, and Raw mode exposes only validated locator metadata plus bounded read entry points. The public engine interface reports schema/API versions, supported tools, limits, and structured success/error responses for adapter consumers.

## Phase 7 AI Assistance Runtime Notes

Phase 7 implements the engine-side AI Assistance contract only. The engine can create immutable, snapshot-based assistance requests and can ingest externally generated keyword recommendations or scope summaries after validating schema shape, size limits, forbidden prompt/secret/raw-body fields, case ownership, snapshot membership, citations, resource revisions, partial state, stale state, and coverage warnings.

AI results are stored separately from observed facts and are marked as `NOT_OBSERVED_FACT`. Human verification is append-only and hash chained; corrections create review events and effective projections without overwriting the original AI result. A keyword recommendation can be promoted only after an accepted or corrected review state, and promotion creates a new draft keyword-set version without running search or activating the set.

The default AI provider boundary reports `CAPABILITY_UNAVAILABLE`. Core still contains no MCP server, MCP SDK, LLM SDK, prompt template, API key handling, chain-of-thought storage, runtime provider call, or network AI workflow.

## Phase 8 Report Contract Runtime Notes

Phase 8 implements the engine-side Report contract. `ReportService` stores a mutable `ReportRecord` aggregate header and immutable `ReportVersion` rows with deterministic content fingerprints, previous-version links, stable section ordering, source kind, citations, context snapshot IDs, evidence IDs, search/timeline/AI references, partial/stale/coverage metadata, limitations, and analyzer/source revision metadata.

Draft text is always externally supplied. Analyst drafts use `ANALYST_DRAFT`; externally generated AI drafts use `AI_DRAFT` and are ingested only after case, assistance request, context snapshot, AI result, citation, size, script/base64, and forbidden prompt/secret/raw-body checks. Report text is not promoted into observed facts and does not modify Evidence, Artifact, Search, Timeline, Context, AI, or Custody source records.

Review and approval are append-only. Review events and approval records carry sequential revisions and hash-chain fields; approval is bound to one report version and content fingerprint. New versions do not inherit approval and move the report back to `REVIEW_REQUIRED`. Revoke appends a `REVOKED` approval record rather than mutating the original approval.

Report custody snapshots reference existing custody event IDs, ledger head hashes, and verification status without copying or editing the custody ledger. Invalid or missing custody verification blocks approval by default.

Export is contract-only. The engine creates render packages, export manifests, renderer capability snapshots, rendered artifact metadata, and export audit events. The default renderer port returns `CAPABILITY_UNAVAILABLE`. Test fake renderers exercise orchestration only; the core still has no PDF library, HTML renderer/template, browser renderer, shell adapter, network renderer, GUI preview, LLM, prompt, MCP SDK, or runtime AI provider.
