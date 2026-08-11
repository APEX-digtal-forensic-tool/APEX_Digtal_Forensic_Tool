# APEX Digital Forensic Tool

APEX는 **Python·Native 하이브리드 분석 엔진**, **한국어 사용자 환경**, **Built-in MCP 기반 AI 분석 보조 기능**을 결합하는 것을 목표로 하는 디지털 포렌식 분석 플랫폼입니다.

기존 디지털 포렌식 도구는 강력한 분석 기능을 제공하지만 높은 비용, 복잡한 사용 환경, 영어 중심의 인터페이스, 대용량 데이터 처리 지연, 전문 지식 요구 등의 한계가 있습니다.

APEX는 다음 프로젝트의 장점을 참고하여 디지털 포렌식 분석의 접근성과 자동화를 개선하는 것을 목표로 합니다.

- X-Ways Forensics의 빠른 Evidence 탐색 철학
- Autopsy의 Case·Artifact 중심 Workflow와 사용자 친화적 UI
- MCP 기반 AI Agent 연동 구조

APEX는 Autopsy의 Java 코드나 NetBeans 기반 애플리케이션 구조를 기반으로 구현하지 않습니다. 주 개발 언어는 Python이며, 성능에 민감한 영역은 Native Adapter로 분리하는 독립적인 구조를 사용합니다.

> 현재 프로젝트의 Forensic Core Engine은 **Phase 1~8 기반 기능, Core Runtime 확장 및 Release Hardening 경로를 구현한 Goal-scope Feature Complete Candidate** 상태입니다.
> 기존 Case·Evidence·Hash·SQLite·Chain of Custody, Progressive Indexing, Windows Artifact, Search·Timeline, Browser·Media, Context, AI Assistance Contract 및 Report Contract에 더해 RAW·DD·IMG·E01·VHD·VHDX Reader, MBR·GPT·Extended Partition, `pytsk3` 기반 Image File System, 삭제 파일·Unallocated·Slack 처리, Registry Transaction Replay, Prefetch MAM, Windows Event Message Rendering, Browser Cache·삭제 Candidate, Communication Analyzer, 실제 Thumbnail 및 제한된 Video Frame Sampling을 구현했습니다.
>
> Linux Release Hardening에서는 합성 Fixture 기반 Runtime·Recovery·보안·Benchmark·Doctor·CLI 검증을 수행합니다. Windows 전용 DPAPI/NSS Host Smoke와 Event Message Rendering은 현재 Linux 결과에서 `HOST_VERIFICATION_REQUIRED`로 유지하며, OCR/STT 또는 Image Runtime Dependency가 없으면 `CAPABILITY_UNAVAILABLE`로 보고합니다. KakaoTalk Windows 2.0.8.990은 명시적 Offline Root 탐색, PE Version 검증 및 외부 Key 기반 합성 AES Contract 복호화까지만 구현했으며, 자동 Key 획득과 실제 KakaoTalk Fixture 검증은 `BLOCKED_EXTERNAL_FIXTURE`입니다. X-Ways·Autopsy 대비 성능 우위는 주장하지 않습니다.

---

## 프로젝트 한 줄 소개

> APEX는 Python·Native 하이브리드 엔진과 한국어 UI, Built-in MCP를 기반으로 Progressive Indexing, AI Keyword 추천, Timezone 자동화, 근거 중심 분석, Report 및 Chain of Custody 자동화를 제공하는 것을 목표로 하는 디지털 포렌식 플랫폼입니다.

---

## 핵심 차별점

### 1. 한국어 기반 디지털 포렌식 환경

APEX는 한국어 사용자를 우선 고려합니다.

기본 설정:

- Locale: `ko-KR`
- Timezone: `Asia/Seoul`
- Encoding: UTF-8

지원 목표:

- 한국어 사용자 인터페이스
- Artifact와 분석 결과의 한국어 설명
- 한국어 자연어 기반 AI 질의
- 한국어 Keyword Search
- 한국어 Report Template
- 분석 결과와 위험도 후보의 한국어 해설
- 한글 파일명과 경로의 손실 없는 처리
- Case별 Locale 및 Timezone 설정
- UTC와 Case Timezone 동시 표시

UI 문자열은 Resource Key 기반으로 관리합니다.

Forensic Engine은 언어에 종속되지 않는 오류 코드와 구조화된 결과를 반환하고, Frontend가 해당 코드에 맞는 한국어 메시지를 표시합니다.

---

### 2. Built-in MCP 기반 AI Forensic Assistant

APEX Desktop Distribution에는 MCP 기반 AI 기능이 기본 포함될 수 있습니다.

다만 Forensic Engine 내부에는 다음 항목을 포함하지 않습니다.

- MCP SDK
- LLM SDK
- Prompt
- Agent Loop
- API Key
- 특정 AI Provider 의존성

```text
APEX Desktop Distribution
├── Frontend GUI
├── Backend / Session Context
├── Forensic Core Engine
└── Built-in MCP Adapter
    └── AI / LLM Provider
```

사용자 관점에서는 AI 기능이 APEX에 기본 포함되지만, 개발 구조에서는 Engine, MCP, AI Provider를 독립적으로 개발하고 교체할 수 있도록 설계합니다.

AI는 포렌식 엔진을 대체하지 않습니다.

GUI에서 이미 수행된 분석 결과와 현재 Context를 재사용하여 다음 작업을 보조합니다.

- 기존 분석 결과 요약
- AI Keyword 추천
- 선택된 Artifact 설명
- 의심 행위 후보 제시
- Artifact 간 관계 분석
- Timeline 흐름 정리
- 추가 분석 항목 추천
- Citation 기반 답변
- 한국어 Report 초안 작성

---

### 3. Progressive Indexing 기반 분석 최적화

APEX의 성능 목표는 Parser 실행 시간만 줄이는 것이 아닙니다.

전체 Index가 완료되기 전에도 File Tree와 Partial Result를 확인하고, 사용자가 선택한 범위를 Background 작업보다 우선 분석할 수 있도록 설계합니다.

```text
Evidence 등록
    ↓
Header / Partition / File System 기본 정보 확인
    ↓
최소 Metadata 우선 수집
    ↓
File Tree 및 Partial Result 표시
    ↓
사용자 선택 Scope 우선 분석
    ↓
Background Index 및 Artifact 분석
```

현재 Directory·Logical File Evidence와 지원되는 Disk Image File System에서 사용하는 Analysis Profile:

| Profile | 목적 | 현재 구현 범위 |
|---|---|---|
| Quick Triage | 첫 File Tree를 빠르게 제공 | Root와 제한된 Depth·Item Budget의 Metadata 우선 수집, Partial Result 표시 |
| Selected Scope | 사용자가 선택한 Directory 또는 Node를 우선 처리 | 선택 Scope를 Background Queue보다 높은 우선순위로 처리 |
| Full Analysis | 전체 Directory Metadata Tree를 완성 | Checkpoint를 재사용하여 전체 Node를 Index하고 Coverage를 COMPLETE로 변경 |
| Custom Profile | 안전한 Option으로 Index 범위를 조정 | Max Depth, Item Budget, Batch Size, Include·Exclude Pattern, Link Policy |

현재 구현된 Index Job 기능:

- Priority Queue
- Selected Scope 우선 처리
- Cooperative Pause·Resume·Cancel
- Checkpoint 및 Resume
- Partial Result와 Coverage 상태
- 처리·발견·건너뜀 Item 수
- Warning 및 Error 수
- 현재 처리 경로
- 경과 시간과 처리량
- 근거가 충분한 경우의 ETA 및 ETA Confidence
- SQLite Batch 저장
- Opaque Stable Cursor Pagination

ETA는 확정 시간이 아닌 추정치로 표시하며, 계산 근거가 부족하면 `null` 또는 `UNKNOWN`으로 반환합니다.

APEX는 현재 X-Ways 또는 Autopsy보다 빠르다고 단정하지 않습니다. 성능 결과는 동일한 Hardware, Evidence, 분석 범위, Cache 상태 및 Index 설정을 사용한 Benchmark 이후에만 문서화합니다.

---

### 4. 검증 가능한 AI 및 자동 문서화

APEX는 AI가 분석 결과를 단독으로 확정하는 구조를 사용하지 않습니다.

AI는 다음 작업을 지원합니다.

- Scope별 결과 요약
- Keyword 후보 생성
- 근거 및 Citation 제시
- 추가 분석 절차 추천
- Timeline 설명
- Report 초안 작성

최종 판단과 Report 승인은 분석자가 수행합니다.

```text
AI Draft
    ↓
Human Review
    ↓
Approval
    ↓
PDF / HTML Export
```

Chain of Custody는 Report 문장만 생성하는 것이 아니라 별도의 Append-only Ledger로 관리합니다.

---

## 전체 시스템 구조

```text
                           사용자
                              │
                              ▼
                    한국어 기반 Forensic GUI
                              │
                              ▼
                   Backend / Application Layer
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
      Forensic Core Engine             Session Context
              │                               │
              ├── Progressive Indexing        │
              ├── Analysis Result DB          │
              ├── Timeline / Search           │
              ├── Chain of Custody            │
              └── Context Snapshot            │
                              │               │
                              └───────┬───────┘
                                      ▼
                              Built-in MCP Adapter
                                      │
                                      ▼
                               AI / LLM Provider
```

GUI와 MCP Adapter는 서로 다른 분석 로직을 구현하지 않습니다.

두 계층 모두 Forensic Engine이 제공하는 동일한 Application Interface와 버전화된 JSON Schema를 사용합니다.

---

## Python·Native 하이브리드 구조

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

현재 적용하거나 선택적으로 연결하는 Native 기술:

- `pytsk3` 기반 Disk Image File System Provider
- E01·EWF 처리를 위한 `libewf-python`
- VHD 처리를 위한 `libvhdi-python`
- VHDX 처리를 위한 외부 `qemu-img`
- SQLite FTS5 Search Index
- Python `hashlib`가 사용하는 Native Hash 구현
- Pillow 기반 Image Parsing·Raster Thumbnail
- FFmpeg·ffprobe 기반 Media Metadata·제한된 Frame Sampling
- Windows Event Message Rendering을 위한 `pywin32`

YARA, `mmap`, Rust·C·C++ Accelerator는 현재 구현 완료 범위가 아니며 Benchmark와 실제 병목 근거를 확인한 뒤 검토합니다.

Native Library와 Tool은 다음 기준으로 선택·유지합니다.

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

### 병렬 처리 구조

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
- Bounded Queue 기반 Backpressure
- Checkpoint 및 Resume
- Evidence Fingerprint 기반 중복 분석 방지
- Analyzer Version과 Option을 포함한 Cache Key
- 기존 GUI 분석 결과 재사용

실제 Benchmark에서 Python 계층의 병목이 확인된 경우에만 해당 구간을 Rust, C 또는 C++ Accelerator로 교체할 수 있도록 설계합니다.

---

## 기존 GUI 분석 결과 재사용

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

AI가 활용할 수 있는 정보:

- 현재 Case
- 현재 Evidence
- 현재 GUI 화면
- 선택된 File
- 선택된 Artifact
- 선택된 Timeline Event
- 선택된 Search Result
- 활성 Filter
- Timeline 시간 범위
- Analyst Annotation
- Tag 및 주요 Evidence
- 기존 분석 결과
- 기존 AI 분석 결과

이를 통해 다음 효과를 기대할 수 있습니다.

- 동일 Evidence 중복 분석 방지
- GUI 분석 결과와 AI 답변의 일관성 유지
- AI 입력 근거 추적
- Report 생성 과정 재현
- 분석자의 선택과 판단 보존
- AI 추론과 실제 Evidence의 구분

---

## GUI Context 및 Scope별 Analysis Context

### Live GUI Session Context

GUI Context는 현재 사용자의 분석 상태를 나타내는 Session 단위 임시 데이터입니다.

현재 저장 가능한 정보:

- 현재 Case와 활성 Evidence
- 현재 화면 및 View Mode
- 선택된 File·Artifact·Timeline Event·Search Result
- 활성 Filter와 Sort
- Timeline 시간 범위
- Tag 및 주요 Evidence
- Locale 및 Timezone
- 활성 Search·Timeline·Analyzer Revision
- Session 생성·수정·만료 시각

Live GUI Session Context는 `context_revision` 기반 Optimistic Lock과 TTL을 적용합니다.

- Client가 전달한 Revision과 현재 Revision이 다르면 구조화된 Conflict Error 반환
- 만료된 Session은 정상 Context처럼 재사용하지 않음
- Case와 Evidence 소속 관계 검증
- Cross-case Resource 혼합 방지
- Context 변경 시 새 Revision 생성
- 원본 분석 결과와 GUI 선택 상태를 분리

Audit, MCP·AI 요청 또는 Report 재현이 필요한 시점에는 Live Session 상태를 불변 Analysis Context Snapshot으로 고정합니다.

### Immutable Analysis Context Snapshot

Analysis Context Snapshot은 Session 상태 전체를 대용량 Payload로 복사하지 않고 Resource ID와 Source Revision 중심으로 저장합니다.

현재 구현 원칙:

- Append-only Snapshot
- 기존 Snapshot Update·Delete 방지
- `previous_snapshot_id`를 통한 Refresh 계보 보존
- Case·Evidence·Resource 소속 검증
- Keyword Set ID·Version 보존
- Search Execution·Index Revision 보존
- Timeline Revision 보존
- Filter·Sort·Time Range 보존
- Analyzer·Source Revision 보존
- Deterministic Content Fingerprint
- Scope별 `partial`, `stale`, Coverage 및 Revision State
- Repository 재개방 후 동일 Snapshot 조회

Snapshot Refresh는 기존 Snapshot을 수정하지 않고 새 Snapshot을 생성하며, 재현 메타데이터를 유지한 상태에서 현재 Source Revision과 Stale 여부를 다시 계산합니다.

### Scope별 Analysis Context

Analysis Context는 모든 분석 결과를 하나의 거대한 Context로 혼합하지 않습니다.

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

각 Scope는 별도 Row와 Stable Cursor Page로 저장·조회하며 다음 정보를 포함할 수 있습니다.

- Context Revision
- Resource ID와 Resource Type
- Analyzer·Source Revision
- Filter·Sort·Time Range
- Result Count와 Included Count
- Partial·Stale·Coverage 상태
- Citation 및 Raw Locator
- Context 생성 시점
- 실제 Adapter 또는 AI 요청에 전달된 Scope

Artifact는 실제 `artifact_type`에 따라 Registry·Event Log·Prefetch·Browser·Media Scope로 분류하며, Generic Artifact가 관련 없는 Scope에 중복 포함되지 않도록 검증합니다.

Evidence Scope는 활성 Evidence와 Case 내 Evidence 목록을 Stable Cursor로 조회하고, 다른 Case의 Evidence가 포함되면 거부합니다.

상위 Case Context는 필요한 Scope만 선택하여 결합합니다.

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

## 현재 구현 범위

### Phase 1 — Core Foundation

- Case 및 Evidence 관리
- MD5·SHA-1·SHA-256 Streaming Hash와 무결성 검증
- SQLite Repository
- Append-only Chain of Custody 및 Hash Chain
- Job·Progress·Cancellation
- JSON Schema 검증
- `apex-forensic` CLI
- Unit·Integration Test

### Phase 2 — Progressive File System & Indexing

- Directory Evidence의 read-only Metadata Index
- Logical Directory / Logical File Provider
- Quick Triage / Selected Scope / Full Analysis
- Priority Queue와 SQLite Batch 저장
- Partial Result 및 Coverage
- Checkpoint·Resume
- Cooperative Pause·Cancel
- Opaque Stable Cursor Pagination
- 한글·Unicode 경로 보존
- Symlink 및 Reparse Point 기본 미추적
- Metadata Index 중 File Body 미열람 및 자동 Hash 미실행

### Phase 3 — Windows Artifact Analysis MVP

- 공통 Artifact Domain Model과 Provider-neutral Analyzer Port
- Phase 2 File System Index를 재사용하는 Artifact Discovery
- Windows Registry Export Text (`.reg`) 분석
- Autorun, USBSTOR, TimeZoneInformation 및 UserAssist Artifact 추출
- Exported Windows Event XML 분석
- 주요 Security·System·Sysmon Event의 Subtype 후보 제공
- Prefetch `.pf` Version 17·23·26·30의 최소 Metadata 분석
- Optional `python-registry` 기반 Offline Binary Hive Capability
- Optional `python-evtx` 기반 Binary EVTX Capability
- SQLite Artifact Persistence
- Checkpoint·Resume 및 Cooperative Pause·Cancel
- Stable Cursor 기반 Artifact Query
- Raw Locator 및 Citation
- Artifact CLI와 Unit·Integration Test

현재 확장 상태:

- Binary Registry Hive와 EVTX 분석은 `windows-artifacts` Optional Dependency가 필요
- `regipy` 기반 Registry Transaction Log Replay와 Replayed View를 지원
- Registry Export Directive·Replay 기반 삭제 Candidate를 제공하지만 Binary Deleted-cell Carving은 미지원
- `dissect.util` 기반 Prefetch MAM 압축 해제와 Size Limit을 지원
- Windows·`pywin32` 환경에서 Host 등록 Provider Metadata 기반 Event Message Rendering을 지원
- Live Windows Artifact Acquisition, Remote Registry, SAM Hash·SECURITY Secret 추출은 미지원
- Artifact Search와 Registry·Event Log·Prefetch Timeline Projection·Query는 Phase 4에서 구현되었으며 Phase 6 Context Snapshot·View Projection에서 재사용합니다.
- Disk Image Reader·File System Parsing·삭제 복구는 아래 Core Runtime 확장에서 구현되었습니다.

### Phase 4 — Search, Keyword Set 및 Timeline

Phase 4에서는 기존 `fs_nodes`, `artifacts`, `jobs`, `cases`, `evidence` SQLite 구조를 재사용해
Metadata/Artifact Search, 수동 Keyword Set, Search Reproduction/Cache, Timeline Projection/Query를
구현했습니다. Search Index는 SQLite FTS5 Capability를 실행 시 확인하며 FTS5가 없으면
`CAPABILITY_UNAVAILABLE`를 반환하고 성공처럼 대체 검색을 수행하지 않습니다.

Search 대상 Field는 파일명, 상대/표시 경로, 확장자, MIME 후보, 안전한 provider metadata,
artifact title/summary/type/subtype/source path, registry path/value, Event provider/channel/ID,
EventData/UserData, Prefetch executable name과 referenced path candidate, Media metadata,
Browser URL/Search/Download/Profile provenance입니다. 파일 본문 전체, PDF/DOCX/OCR/STT 추출물,
unallocated/slack, deleted file body는 인덱싱하지 않습니다.

Keyword Set은 `DRAFT`, `ACTIVE`, `ARCHIVED` 상태와 immutable version을 보존합니다. 활성 Set을
수정하면 새 version이 생성되고 이전 version은 검색 재현을 위해 유지됩니다. Search Execution은
원본 query, scope, keyword set version, backend/version, index revision, source revision
fingerprint, option fingerprint, 0건 결과, partial/stale warning, result count를 저장합니다.

Search Cache key는 case, evidence scope, query fingerprint, keyword set version, index revision,
source revision fingerprint, time range, filters, sort, limit, opaque cursor를 반영합니다. Cache는
내부적으로 `limit + 1`개를 조회해 페이지를 자르기 전에 `has_more`와 `next_cursor`를 계산합니다.
Index 또는 source revision이 변하면 기존 cache는 무효화되며 원본 evidence, filesystem node,
artifact는 삭제하지 않습니다. 기본 TTL은 없습니다. 같은 option 재실행은 새 reproduction
record를 남기며 cache는 그 기록을 대체하지 않습니다.

Timeline은 filesystem timestamps, Registry/Event Log/Prefetch artifacts를 `timeline_events`로
투영합니다. Raw timestamp와 raw timezone은 보존하고, UTC normalized timestamp와 case timezone
display time은 별도 필드에 저장합니다. 기본 case timezone은 `Asia/Seoul`이며 IANA timezone과
Windows 환경의 `tzdata` fallback을 사용합니다. Naive timestamp는 UTC로 임의 확정하지 않고 불명확하면
`normalized_utc = null`을 허용합니다. Timezone source/confidence와 timestamp semantics를 기록하고,
Windows TimeZoneKeyName은 제한된 candidate로만 취급합니다.

Search Index와 Timeline Build Job은 Checkpoint·Resume, Cooperative Pause·Cancel을 지원하며,
조회 결과에는 Opaque Stable Cursor Pagination을 적용합니다.

추가 CLI:

- `apex-forensic search index|index-status|resume|cancel|query|show|history|rerun|cache-status|rebuild`
- `apex-forensic keyword-set create|list|show|add|remove|activate|archive|version`
- `apex-forensic timeline build|status|resume|cancel|list|show`

Phase 4 비지원 범위는 File Body Full-text Indexing, Office·PDF Extraction, OCR·STT, YARA,
실제 AI Keyword 생성, LLM·Agent Loop, GUI·Web·MCP Server, 실제 Report Renderer,
Unallocated Raw Content Search, Live Acquisition, DPAPI·NSS 자동 복호화, 광범위한
Windows Timezone 자동 확정, 침해 자동 확정 및 Benchmark 우위 주장입니다.

### Phase 5 — Browser Communications & Media Metadata MVP

Phase 5에서는 기존 File System Index, Artifact, Search, Timeline, Job 및 SQLite 구조를 재사용해
오프라인 Browser Communications와 Media Metadata 분석을 구현했습니다.

Browser 구현 범위:

- File System Index 기반 Chromium·Firefox Profile 후보 Discovery
- Windows·Linux Path Allowlist, Unicode Path 보존 및 중복 Profile 방지
- Chromium `History`의 방문·검색어·다운로드 분석
- Firefox `places.sqlite` 방문 및 Download Annotation Candidate 분석
- Main DB·WAL·SHM을 함께 보존하는 읽기 전용 SQLite Snapshot
- Main DB·WAL·SHM Component Hash 기반 Source Fingerprint 및 Revision
- 플랫폼 임시 디렉터리 사용과 Windows-safe SQLite File URI
- SQLite Connection을 Snapshot Cleanup 전에 명시적으로 Close
- DB·Table·Row 기반 Logical Raw Locator
- Item Budget 기반 Bounded Extraction
- Source별 Checkpoint·Resume 및 Cooperative Pause·Cancel
- Repository 재오픈 후 Resume
- Browser Artifact Stable Cursor Query
- Browser Search Index 및 Timeline Projection
- Case Timezone 기반 `displayed_case_time` 변환
- Firefox `moz_inputhistory`를 확정 Search가 아닌 URL-bar Input Candidate로 분리

Media 구현 범위:

- Image·Video·Audio Candidate 분류
- JPEG·PNG·GIF·BMP·TIFF·WEBP Metadata
- JPEG EXIF·GPS·Orientation·Camera Make·Model Candidate
- MP4 최소 Container Metadata
- Optional `ffprobe` 기반 Video·Audio Metadata
- `Z` 및 명시적 UTC Offset을 지원하는 Media Timestamp 정규화
- Timezone 없는 Timestamp의 UTC 임의 확정 금지
- Decompression Bomb·손상 File·Read Limit 보호
- argv 기반 `ffprobe` 실행, `shell=True` 금지, Timeout 및 Streaming Output Size Limit
- Windows·Linux 공통 동작을 위한 동시 stdout·stderr Reader
- Hash 검증 가능한 Thumbnail Derived Metadata Contract
- Media Search Index 및 Timeline Projection
- Media Artifact Stable Cursor Query

Machine Extraction 구현 범위:

- Machine-extracted Candidate Domain과 Provider-neutral OCR·STT Port
- `UNREVIEWED`, `ACCEPTED`, `REJECTED`, `CORRECTED` Review 상태
- Append-only Candidate Review History
- Candidate와 Observed Fact의 명시적 분리
- 기본 OCR·STT Provider의 `CAPABILITY_UNAVAILABLE` 처리
- Optional RapidOCR/ONNX Runtime 및 faster-whisper Adapter와 실제 Fixture Verifier

현재 Browser·Media 확장에서는 외부 Key 기반 Chromium AES-GCM, Browser Cache,
WAL·Freelist 삭제 Candidate, Private-mode Candidate, Pillow Raster Thumbnail 및 제한된
FFmpeg Frame Sampling, 합성 입력 기반 Offline DPAPI, Firefox NSS Adapter 및 HTML/PDF Renderer를
지원합니다. KakaoTalk 자동 Key 획득·실제 암호화 DB Fixture 검증, Cloud Sync, Video 전체 Frame 분석,
Reverse Geocoding, 얼굴·객체·내용 분석, GUI·MCP 실행은 미지원입니다. OCR·STT와 외부 AI는
Runtime Dependency, Model 또는 외부 설정이 없으면 명시적으로 사용할 수 없는 상태를 반환합니다.


### Phase 6 — GUI Context, Analysis Snapshot 및 View Runtime

- Live GUI Session Context와 `context_revision` 기반 Optimistic Lock
- Session TTL·만료 상태 및 Case·Evidence 소속 검증
- 불변 Analysis Context Snapshot과 `previous_snapshot_id` 기반 Refresh 계보
- Keyword Set·Search Execution·Search Index·Timeline·Analyzer·Source Revision 보존
- Case·Evidence·File System·Registry·Event Log·Prefetch·Browser·Media·Timeline·Keyword Search 등 Scope별 Context
- Scope별 Partial·Stale·Coverage·Revision State 및 Stable Cursor Pagination
- Artifact Type 기반 Scope 격리와 Cross-case·Cross-evidence Resource 검증
- 동일 Resource와 Source Revision을 유지하는 Simple·Detailed·Raw Projection
- Indexed Source Node 기반 Safe Raw Range Reader
- Evidence Root Containment, Offset·Length·Maximum Read Limit 및 EOF 검증
- Raw Read Append-only Audit Record
- JSON-friendly Public Engine Interface Envelope와 Capability·Tool Descriptor
- Canonical Operation Name과 Structured Request Error
- `context`, `view`, `interface` CLI Command Group
- Phase 6 JSON Schema와 Unit·Integration Test
- Windows·Linux Runtime 회귀 검증

현재 제한:

- 실제 Desktop GUI와 Frontend View 미포함
- Web Server 및 REST·GraphQL Transport 미포함
- MCP Server·SDK·Tool Registration 미포함
- LLM Provider·Prompt·Agent Loop·API Key 미포함
- LLM 기반 Keyword Recommendation과 Scope Summary 생성 미포함
- Report Review·Approval Engine Contract는 Phase 8에서 구현되었으며 실제 PDF·HTML Renderer와 GUI Preview는 미구현
- 임의 Local Path 직접 읽기 금지
- Disk Image Raw Range·File System·삭제·Slack 경로는 Evidence·Node·Offset·Length·Provider 검증 후에만 접근
- Role 기반 Raw View 권한 정책은 Backend·Frontend 통합 단계에서 구현

### Phase 7 — AI Assistance Engine Contract

- Snapshot 기반 `AiAssistanceRequest` 생성과 TTL·Fingerprint·Current Revision 검증
- 외부 Keyword Recommendation Batch Ingest 및 Schema/Size/Forbidden Field 검증
- 외부 Scope Summary Ingest와 Script/Base64/Scope/Citation 검증
- AI 결과의 `NOT_OBSERVED_FACT` 분류와 Citation·Partial·Stale·Coverage Warning 보존
- Human Verification Append-only Event Hash Chain
- Accepted/Corrected Keyword Candidate만 기존 Keyword Set DRAFT Version으로 Promotion
- Promotion은 Search 실행이나 Keyword Set Activation을 자동 수행하지 않음
- Public Engine Interface와 `ai` CLI Command Group
- Provider-neutral Port와 기본 `CAPABILITY_UNAVAILABLE` 응답
- MCP SDK, LLM SDK, Prompt Template, API Key, Chain-of-thought, Runtime Network 호출 미포함

### Phase 8 — Report Review, Approval 및 Export Engine Contract

- `ReportRecord`, Immutable `ReportVersion`, Stable `ReportSection` 구조
- Analyst Draft·외부 AI Draft·Imported Draft·System-assembled Data의 Source Kind 분리
- Context Snapshot·Evidence·Search Execution·Timeline Revision·AI Result·Citation Provenance 검증
- Partial·Stale·Coverage·Limitations 보존
- Report Version Update·Delete 방지와 `previous_version_id` 기반 Version 계보
- Append-only Human Review·Approval·Reject·Revoke Event Hash Chain
- 승인된 특정 Version과 Content Fingerprint만 Export 허용
- 새 Report Version 생성 시 기존 Approval을 승계하지 않고 재검토 요구
- 기존 Chain of Custody Ledger를 수정하지 않는 불변 Custody Snapshot과 Ledger 검증
- JSON-friendly Render Package, Export Manifest, Export Audit 및 Rendered Artifact Metadata 계약
- Provider-neutral Renderer Port와 기본 `CAPABILITY_UNAVAILABLE`
- HTML 및 Optional ReportLab PDF Renderer와 Unicode/Korean Runtime Verifier
- Export Filename의 Path Traversal·Absolute Path·Drive Prefix·UNC·Windows Reserved Name 차단
- Derived Output Root 밖 Reference 거부와 Overwrite 기본 금지
- Export Prepare 멱등성 및 Manifest 상태 전이 검증
- `report` CLI와 Public Engine Interface Report Operation 제공

현재 제한:

- 실제 AI Report Draft 생성 미지원
- 실제 LLM·Prompt·MCP Server·Tool Registration 미지원
- GUI Report Preview와 Network Renderer 미지원
- 전자서명·실제 사용자 인증·RBAC·Billing 미지원
- Rendered Output은 Original Evidence가 아닌 Derived Data Metadata로만 관리

### Core Runtime Feature Completion — 완료

Phase 1~8 기반 위에 다음 Runtime을 추가했습니다.

- RAW·DD·IMG Reader와 Bounded Random Read
- Optional `libewf-python` 기반 E01·EWF Reader
- Optional `libvhdi-python` 기반 VHD Reader
- 외부 `qemu-img` 기반 VHDX Read-only 변환 경로
- MBR·GPT·Extended Partition·Protective MBR·Superfloppy 분석
- `pytsk3` 기반 NTFS·FAT·exFAT·ext 계열 Image File System Tree
- 삭제 File Recovery, Unallocated Range, File Slack Read·Export
- Registry Transaction Log Replay와 Original·Replayed View 분리
- Prefetch MAM 압축 해제와 Corrupt·Size-limit 방어
- Windows Host Event Message Rendering
- Browser AES-GCM 외부 Key 복호화, Cache, WAL·Freelist·Private-mode Candidate
- Email·Discord·Telegram Communication Analyzer와 KakaoTalk 암호화 Store Discovery
- Pillow Raster Thumbnail과 제한된 FFmpeg Frame Sampling
- NFC·Casefold·Path·한글 자모·영문·숫자 혼합 Search 정규화
- Recovery 실패 시 Partial·Temp Output 정리 및 외부 Process Error 노출 방어

현재 명시적 미지원 경계:

- Live Profile Credential 자동 획득
- KakaoTalk 자동 Key 획득과 실제 KakaoTalk 암호화 DB Fixture 검증
- 형태소 기반 한국어 검색
- MCP·LLM Agent Runtime과 Desktop GUI
- 설치되지 않은 OCR·STT·E01·VHD·VHDX Runtime은 `CAPABILITY_UNAVAILABLE`

### Phase 1~8 통합 감사 및 회귀 검증

Phase 1~8 통합 감사에서 발견된 2 High, 2 Medium, 2 Low Finding과 Core Runtime 완료 감사에서 추가 발견된 3 Medium Finding을 모두 수정했습니다.

- Read 전용 Interface가 Mutation Operation을 실행하지 못하도록 Descriptor의 `mutates_state` 경계 강제
- 인덱싱 이후 Source Path가 Symlink·Junction·Reparse Point로 교체된 경우 Artifact 분석 차단
- Windows Reserved Device Name, Trailing Dot·Space, Drive Prefix 및 UNC를 포함한 Export Filename 검증 강화
- 유효하지 않은 Export Manifest 상태에서 Renderer Result로 완료 처리하는 경로 차단
- 같은 Export 요청의 반복 Prepare에서 Render Package가 중복 생성되지 않도록 멱등 처리
- AI Revision 검증에서 예상하지 못한 Resolver Exception을 숨기지 않도록 예외 범위 축소
- Browser AES-GCM 실패 시 Backend Exception 문자열 노출 차단
- ffmpeg·ffprobe Raw stderr 반사를 Hash·Length·Return code 진단으로 교체
- 삭제 File Recovery 실패 시 Partial·Temp Output 정리
- Windows Event Message Renderer의 실제 PyHANDLE 전달 경로와 Host 검증 추가
- 수정 사항별 집중 Regression Test 추가
- 현재 Release Hardening 회귀 검증은 Linux에서 수행하며 Windows 전용 결과를 별도 상태로 유지

Release Hardening Bandit 감사는 High 0건, Medium 43건의 `B608` Finding을 보고합니다.
43건은 모두 고정 SQL Fragment, 생성된 Placeholder 또는 명시적 Identifier Allowlist 경로로
검토되어 `FALSE_POSITIVE_WITH_JUSTIFICATION`으로 분류했으며, Bandit Clean으로 표현하지 않습니다.
분류는 `tools/security_findings.json`에 기록되고 Release Gate가 Scanner 결과와 일치하는지 확인합니다.

---

## 주요 기능

### Case Management

- 신규 Case 생성
- 기존 Case 불러오기
- 사건명, 분석자 및 사건 설명 관리
- Case Locale 및 Timezone 관리
- Evidence 및 분석 결과 연결
- Timeline 및 Report 관리
- 분석 작업 상태 저장 및 복원

### Evidence Management

등록 가능한 Evidence 형식:

- E01·EWF
- RAW
- DD
- IMG
- VHD
- VHDX
- Logical File
- Directory Evidence

기능:

- Evidence 등록과 형식 식별
- Metadata 확인
- MD5·SHA-1·SHA-256 Hash 계산
- 무결성 검증
- Analysis Profile 지정
- Evidence Fingerprint 기반 중복 분석 방지
- 원본 Evidence Read-only 처리
- Chain of Custody 기본 Event 생성
- Bounded Raw Range Read·Export
- MBR·GPT·Extended Partition·Protective MBR·Superfloppy 열거
- Partition-level Unallocated Range 열거
- Reader·Provider Capability와 Version 기록

Reader 조건:

- RAW·DD·IMG: 기본 Runtime
- E01·EWF: Optional `libewf-python`
- VHD: Optional `libvhdi-python`
- VHDX: 외부 `qemu-img` 기반 Read-only 변환 경로
- Image File System: `pytsk3`

### File System Analysis

현재 구현:

- Directory Evidence와 Logical File Evidence의 Read-only Metadata 탐색
- RAW·DD·IMG 및 지원 Dependency가 있는 E01·VHD·VHDX 내부 File System Tree
- `pytsk3` 기반 NTFS·FAT·exFAT·ext 계열 Provider
- Root·Parent·Child·Node 상세 조회
- Quick Triage Partial File Tree
- Selected Scope 우선 처리
- Full Metadata Index
- Priority Queue와 SQLite Batch 저장
- Checkpoint·Resume
- Cooperative Pause·Cancel
- Partial Result와 Coverage 상태
- Opaque Stable Cursor Pagination
- 한글·Unicode 경로 보존
- Symlink·Reparse Point 기본 미추적
- 권한·변경 오류 Warning
- Extension·표준 `mimetypes` 기반 MIME Candidate
- Image 내부 Extent·Raw Locator
- 삭제 Node 표시와 제한된 File Recovery
- Unallocated Range 조회·Read·Export
- File Slack 조회·Export
- Recovery Output Hash·Partial·Provenance 기록

현재 제한:

- File System 지원 범위는 `pytsk3`와 연결된 Native Provider가 실제로 인식하는 Format으로 제한
- 손상·Overwrite된 삭제 File을 완전 복구로 표시하지 않음
- Directory Evidence Manifest Hash 미지원
- File Content 전체 Magic·YARA·Office·PDF Full-text 분석 미지원
- VHDX는 `qemu-img`가 없으면 `CAPABILITY_UNAVAILABLE`

### Windows Artifact Analysis

현재 구현은 오프라인 Windows Artifact를 읽기 전용으로 분석합니다.

#### Registry

현재 구현:

- Windows Registry Export Text (`.reg`)
- UTF-16LE·UTF-8 BOM 처리
- String·Expand String·DWORD·QWORD·Binary·Multi String의 안전한 범위
- Run·RunOnce Autorun
- USBSTOR 기반 USB Device History
- TimeZoneInformation
- UserAssist ROT13과 알려진 Count 구조의 안전한 범위
- Optional `python-registry` 기반 SYSTEM·SOFTWARE·NTUSER.DAT·USRCLASS.DAT Offline Hive Parse
- Optional `regipy` 기반 Transaction Log Replay
- Original View와 Replayed View 분리
- Export Directive·Replay 기반 삭제 Candidate
- Parser Backend·Version·Source Revision·Raw Locator·Citation 기록

현재 제한:

- SAM Password Hash·SECURITY Secret 추출 미지원
- HBIN Free Cell·Slack 직접 Carving과 삭제 `nk`·`vk`·`sk` 관계 복원 미지원
- Live·Remote Registry 미지원
- Optional Dependency가 없으면 해당 Capability는 `CAPABILITY_UNAVAILABLE`

#### Event Log

현재 구현:

- Exported Windows Event XML
- XML Namespace 안전 처리
- Channel·Provider·Event ID·Record ID·Computer·User SID·Process ID·Thread ID 보존
- EventData·UserData·Raw XML 보존
- 주요 Security·System·Sysmon Event ID의 Subtype·Title Candidate
- Optional `python-evtx` 기반 Binary `.evtx` Iterator
- Windows·`pywin32` 기반 Host 등록 Provider Metadata Message Rendering
- EvtQuery·EvtNext 원본 PyHANDLE을 사용하는 검증된 Event-handle 경로
- Item Budget·Cancellation·Partial Result
- Record 기반 Raw Locator·Citation

보안 경계:

- 분석 Evidence의 Message DLL을 로드하거나 실행하지 않음
- Windows Host에 정상 등록된 Provider Metadata만 사용
- Event ID만으로 침해·악성 여부를 확정하지 않음
- Windows 또는 `pywin32`가 없으면 Message Rendering은 `CAPABILITY_UNAVAILABLE`

#### Prefetch

현재 구현:

- `.pf` Version 17·23·26·30 Metadata Parser
- Executable Name
- Prefetch Hash
- Format Version
- File Size
- Run Count
- 안전하게 확인 가능한 Last Run Time
- Bounds Check와 손상 입력 처리
- Field Offset·Length 기반 Raw Locator
- MAM Compression 감지
- Optional `dissect.util` 기반 MAM 압축 해제
- Corrupt Stream 처리와 Decompressed Size Limit
- Referenced Path Candidate

현재 제한:

- 알 수 없는 Version은 `UNSUPPORTED`
- Prefetch만으로 사용자가 직접 프로그램을 실행했다고 단정하지 않음
- Volume·Referenced File Path는 안전하게 파싱 가능한 범위만 제공

### Browser Communications MVP

현재 구현:

- File System Index 기반 Chromium·Firefox Profile Candidate Discovery
- Windows·Linux Path Allowlist, Unicode Path 보존, Profile 중복 방지
- Chromium History SQLite의 Visit·Search·Download 분석
- Firefox `places.sqlite` Visit와 Download Annotation Candidate
- Main DB·WAL·SHM을 함께 보존하는 Read-only SQLite Snapshot
- Component Hash 기반 Source Fingerprint·Revision
- 플랫폼 임시 Directory와 Windows-safe SQLite File URI
- Source별 Checkpoint·Resume·Pause·Cancel
- DB·Table·Row Logical Raw Locator
- Browser Artifact Stable Cursor·Search·Timeline Projection
- Cookie·Credential 구조화 Candidate
- Browser Cache Artifact
- WAL·Freelist 기반 삭제 Record Candidate
- Private-mode 흔적 Candidate
- 외부 Key 기반 Chromium AES-GCM 복호화
- Key 부재·인증 실패·Redaction 경계

현재 제한:

- Windows DPAPI Master Key 자동 획득 미지원
- 사용자 SID·Password·NT Hash·Domain Backup Key 기반 Offline DPAPI 복구 미지원
- Firefox NSS `key4.db` 자동 복호화 미지원
- Live Host Credential Store를 암묵적으로 사용하지 않음
- 복호화된 Password·Cookie를 일반 Log나 Error Message에 출력하지 않음
- WAL·Freelist·Private-mode 결과는 확정 복구가 아니라 Candidate로 보존
- Cloud Sync 분석 미지원

Communication Analyzer:

- Email
- Discord
- Telegram
- KakaoTalk 암호화 Store Discovery

KakaoTalk Windows Desktop 2.0.8.990에 한해 명시적 Offline Root 아래의 `chatLogs*.edb`
후보를 bounded/read-only 방식으로 탐색하고, `KakaoTalk.exe` PE Fixed File Version을 검증합니다.
외부 KPRAGMA+nonce 또는 AES DB Key+IV를 사용한 AES-128-CBC 복호화, SQLite
`quick_check(1)`, `chatLogs` Schema 검증과 column-aware 추출은 합성 Contract Fixture로
검증했습니다. 자동 KPRAGMA 획득 경로와 실제 KakaoTalk Fixture는 재현 가능한 근거가 없어
`BLOCKED_EXTERNAL_FIXTURE`이며 `real_kakaotalk_fixture_verified=false`입니다.

### Timeline Analysis

현재 구현:

- File System Timestamp와 Registry·Event Log·Prefetch·Browser·Media·Communication Artifact Timestamp Projection
- Raw Timestamp·Raw Timezone 보존
- UTC 정규화와 Case Timezone 표시
- Timezone Source·Confidence·Timestamp Semantics
- IANA Timezone과 Windows TimeZoneKeyName Candidate
- DST, Ambiguous·Nonexistent Local Time 경계
- Analyst Override
- Event Type·Time Range Filter
- Opaque Stable Cursor Pagination
- Raw Locator와 Citation 가능한 Timeline Event
- Build Job Checkpoint·Resume·Pause·Cancel

현재 제한:

- 불명확한 Naive Timestamp를 UTC로 임의 확정하지 않음
- Timezone Candidate가 불충분하면 분석자 확인 필요
- AI 기반 사건 흐름 요약은 외부 AI Layer 담당

### Search & Discovery

현재 구현:

- File Name·Path·Metadata·Artifact Field 대상 SQLite FTS5 Keyword Search
- Case·Evidence Scope와 Filter 기반 조회
- Opaque Stable Cursor Pagination
- Search Result Cache와 Revision 기반 무효화
- Keyword Set과 Immutable Versioning
- Search Reproduction·History·Rerun
- Index Job Checkpoint·Resume·Pause·Cancel
- NFC·Casefold·Path 정규화
- 한글 완성형·자모·영문·숫자·경로 혼합 Fixture
- Canonical-equivalent Query Cache 일치
- File System·Artifact·Browser·Media·Communication·Timeline Projection 검색

현재 제한:

- 형태소 분석 지원을 주장하지 않음
- Office·PDF·OCR·STT Full-text Extraction 미지원
- Unallocated Raw Content Full-text Search 미지원
- YARA와 실제 AI Keyword 생성은 별도 Runtime

## AI Keyword Recommendation

AI는 조사 범위를 줄이기 위한 Keyword Candidate를 제안할 수 있습니다.

> 현재 Engine은 AI Provider를 실행하지 않고, 외부 Adapter가 제출한 Keyword Recommendation을 검증·저장·검토·승격하는 Phase 7 계약을 제공합니다.

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
승인된 Keyword만 Search 실행
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
- Keyword Set Version 관리
- Search Option 저장
- Time Range와 Evidence Scope 저장
- 0건 결과 보존
- 동일 검색 재실행 지원
- 분석자 수동 Keyword도 동일하게 관리

---

## AI 분석 결과 구분

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

OCR, STT 또는 자동 Text Extraction으로 얻은 검토 전 후보입니다.

### AI Inference

AI가 Observed Fact와 Context를 기반으로 생성한 추론입니다.

### AI Recommendation

AI가 제안하는 추가 분석 절차 또는 대응 방안입니다.

AI는 다음 동작을 수행할 수 없습니다.

- 침해 사실 단독 확정
- Citation 없이 사실 단정
- Partial Result를 전체 결과처럼 표현
- Scope 외 데이터 임의 혼합
- 원본 Artifact 수정
- AI Inference를 Observed Fact로 승격
- 미승인 Keyword 자동 실행

---

## Simple / Detailed / Raw View

Phase 6에서는 동일 Resource를 세 단계 Projection으로 조회할 수 있습니다.

| View | 현재 Engine 제공 내용 |
|---|---|
| Simple | Resource ID, 핵심 표시 Field, 요약용 값, Partial·Stale 상태 및 주요 Citation |
| Detailed | 전체 Artifact·Context Field, Parser·Analyzer Version, Source Revision, Timezone 해석, Confidence 및 Citation |
| Raw | 검증된 Raw Locator, Byte Offset·Length, Encoding, Hex·Text Preview, 원본 Timestamp 및 Logical Locator 정보 |

현재 구현 원칙:

- 동일 `resource_id`와 Source Revision을 유지한 상태에서 View 전환
- 기존 Observed Fact를 수정하지 않는 Projection DTO
- Simple·Detailed·Raw 결과의 JSON-friendly Envelope
- AI 설명과 원본 Fact가 혼합되지 않도록 별도 계층 유지
- Raw Locator와 Citation 연결
- 등록된 Evidence와 Indexed Source Node 검증
- Caller가 전달한 임의 `relative_path`만으로 File Read 금지
- Evidence Root 밖으로 벗어나는 Path 거부
- Offset·Length·EOF·Maximum Read Length 검증
- 필요한 Byte Range만 선택적으로 읽기
- 대용량 File 전체 Memory Loading 금지
- Raw Read 결과에 Audit Record 추가
- 원본 Evidence 읽기 전용 유지

한국어 설명, AI 요약 및 추천 분석은 Phase 7 AI Layer 또는 Frontend에서 이 Projection을 기반으로 제공하며, Phase 6 Engine 자체는 LLM을 실행하지 않습니다. 사용자 역할별 Raw View 접근 정책은 Backend·Frontend 통합 단계에서 구현합니다.

---

## Images / Videos 및 Machine Extraction

### Media MVP

현재 구현:

- Image·Video·Audio File Candidate 분류
- JPEG·PNG·GIF·BMP·TIFF·WEBP Header Metadata
- JPEG EXIF·GPS·Orientation·Camera Make·Model Candidate
- MP4 기본 Container Metadata
- Optional `ffprobe` 기반 Video·Audio Metadata
- Pillow 기반 실제 Raster Thumbnail
- Thumbnail Hash·Source Revision·Derived Metadata
- Optional `ffmpeg` 기반 제한된 Video Frame Sampling
- `Z`, 명시적 UTC Offset, Fractional Second Timestamp 정규화
- Timezone 없는 Media Timestamp의 UTC 임의 확정 금지
- argv 기반 외부 Process 실행, `shell=True` 금지
- Timeout·Streaming Output Size Limit·Process Cleanup
- Decompression Bomb·손상 File·Read Limit 보호
- Search·Timeline Projection과 Stable Cursor

현재 제한:

- 원본 Media 수정 미지원
- Reverse Geocoding, 얼굴·객체·내용 분석 미지원
- Video 전체 Frame 분석, Subtitle 추출, Audio Transcription 미지원
- `ffmpeg`·`ffprobe`·Pillow가 없으면 해당 기능은 `CAPABILITY_UNAVAILABLE`

### Machine-extracted Candidate

OCR 및 STT 결과는 Observed Fact가 아니라 `Machine-extracted Candidate`로 분류합니다.
Provider Port와 Candidate Review Workflow는 구현되어 있으며 기본 OCR·STT Provider는
`CAPABILITY_UNAVAILABLE`을 반환합니다. 실제 OCR·STT Engine은 실행하지 않습니다.

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

## Chain of Custody

Chain of Custody는 일반 Report 문장이 아니라 독립적인 Append-only Ledger입니다.

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
- Event Hash Chain 적용 및 Repository 재개방 후 검증
- 최초 Hash와 재검증 Hash 기록
- Hash 불일치 경고
- 사용자·역할·승인자 기록
- 이동·접근·분석·Export 이력 보존
- Export 시 Custody Snapshot 생성
- Report Version과 Custody Snapshot 연결

이 기능은 법적 증거능력을 보장하지 않습니다.

관할 법률, 조직 정책, Actor Identity 및 전자서명 방식은 Backend·운영·법무 담당자의 최종 검토가 필요합니다.

---

## Report Review, Approval 및 Export Contract

Forensic Core Engine은 보고서 문장을 직접 생성하거나 PDF·HTML을 직접 렌더링하지 않습니다.

외부 MCP·AI Layer 또는 Analyst가 작성한 Draft를 검증하여 Immutable Report Version으로 저장하고, Human Review·Approval·Custody Snapshot·Export 계약을 관리합니다.

```text
외부 AI Draft / Analyst Draft
    ↓
Engine Validation 및 Immutable Report Version
    ↓
Human Review / Request Changes
    ↓
Approval 또는 Reject
    ↓
Custody Snapshot 및 Render Package
    ↓
외부 PDF / HTML Renderer
    ↓
Rendered Artifact Metadata 검증·저장
```

현재 Report 상태:

- `DRAFT`
- `REVIEW_REQUIRED`
- `APPROVED`
- `REJECTED`
- `EXPORT_PREPARING`
- `EXPORT_READY`
- `EXPORTED`
- `EXPORT_FAILED`
- `ARCHIVED`

핵심 원칙:

- Report Content는 Immutable Version으로 저장
- 특정 Version과 Content Fingerprint에만 Approval 부여
- 승인 후 수정은 기존 Version을 변경하지 않고 새 Version 생성
- 새 Version은 이전 Approval을 승계하지 않음
- Review·Approval·Reject·Revoke는 Append-only Event로 보존
- AI Draft와 Analyst Draft의 Source Kind 및 Provider Provenance 분리
- Report 문장을 Artifact·Timeline Event·Search Result·Observed Fact로 승격하지 않음
- Cross-case Evidence·Snapshot·Citation·AI Result 연결 금지
- Partial·Stale·Coverage·Limitations를 숨기지 않음
- Invalid Custody Ledger는 기본 정책에서 Approval 차단
- APPROVED Version만 Export Manifest 생성 가능
- Export Filename과 Derived Output Root 경계 검증
- 실제 Renderer가 없으면 `CAPABILITY_UNAVAILABLE`
- Failed Renderer Result를 Completed 상태로 기록하지 않음
- 동일 Export Prepare 요청은 멱등 처리

Report에 포함 가능한 Section:

1. 사건 개요
2. 분석 목적
3. 분석 대상
4. Evidence 정보
5. Hash 및 무결성 정보
6. Chain of Custody
7. 분석 환경
8. Analysis Profile 및 완료 범위
9. Partial·Stale·Coverage Warning
10. Timezone 및 변환 정책
11. 주요 발견 사항
12. File System 분석 결과
13. Windows Artifact 분석 결과
14. Images / Videos / Audio 분석 결과
15. Browser Communications 분석 결과
16. Timeline
17. Keyword Set 및 Search Options
18. AI Assistance Result
19. Raw Citation
20. Machine-extracted Candidate와 검토 상태
21. 결론
22. 대응 권고
23. 분석 범위와 제외 범위
24. 증거 출처 및 Citation
25. 분석 한계 및 Known Limitations

지원하는 Export 계약:

- PDF
- HTML

현재는 Render Package·Export Manifest·Renderer Port·Output Metadata 검증까지만 구현되어 있으며 실제 PDF·HTML 파일 생성은 별도 Renderer 담당입니다.

---

## Evidence 분석 원칙

APEX는 다음 원칙에 따라 디지털 증거를 처리합니다.

- 원본 Evidence 읽기 전용 처리
- Evidence 원본 수정 금지
- 등록 시 Hash 계산
- 분석 전후 무결성 검증
- 원본 데이터와 파생 데이터 분리
- 분석 작업 Audit 기록
- AI 결과와 Observed Fact 분리
- Citation 기반 분석 근거 추적
- 분석 과정 재현 가능성 확보
- Chain of Custody Event 불변성 유지

---

## 역할 및 책임

### Forensic Engine

담당:

- Case 및 Evidence
- Hash 및 무결성
- Progressive Indexing
- Evidence Reader·Partition·File System 분석
- 삭제 File·Unallocated·Slack Recovery·Export
- Artifact 분석
- Timeline 및 Timezone 정규화
- Search, Keyword Set 및 Index
- Cache와 Analysis Job
- Analysis Result Database
- Context Snapshot
- Citation과 Raw Locator
- Chain of Custody
- Machine-extracted Candidate 계약
- AI Assistance Request·Result Ingest·Human Verification·Keyword Promotion 계약
- Report Aggregate·Immutable Version·Review·Approval·Custody Snapshot 계약
- Render Package·Export Manifest·Rendered Artifact Metadata 계약
- GUI와 MCP Adapter용 공개 Interface

비담당:

- MCP SDK 및 Tool
- LLM SDK
- Prompt
- Agent Loop
- API Key
- AI Token 과금
- 실제 OCR/STT Provider
- 실제 PDF/HTML Renderer

### MCP / AI Layer

담당:

- Built-in MCP Adapter
- MCP Server 및 Tool
- Engine API Wrapping
- GUI Context 전달
- LLM Provider 연결
- Prompt Engineering
- Scope Summary
- AI Keyword Candidate 생성
- AI 분석 Workflow
- Report Draft 요청

### Frontend

담당:

- 한국어 GUI
- Case Explorer
- Evidence 및 File System View
- Artifact View
- Timeline UI
- Progressive Indexing Progress
- Timezone 확인
- Keyword 승인
- Simple / Detailed / Raw View
- Images / Videos UI
- Communications UI
- AI Assistant UI
- Chain of Custody 입력 및 검토
- Report Preview
- GUI Context 생성

### Backend

담당:

- Case 및 사용자 데이터 관리
- Session Context Store
- Actor Identity 및 Role
- Analysis Job 상태
- API 및 Service Layer
- 결과 저장 및 조회
- Approval Identity
- Report File 관리
- AI Token 사용량 및 Billing
- 외부 검증 결과 공개 범위 관리

---

## 저장소 구조

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
│   ├── FORENSIC_ENGINE.md
│   ├── IMPLEMENTATION_DECISIONS.md
│   ├── IMPLEMENTATION_ROADMAP.md
│   ├── JSON_SCHEMAS.md
│   ├── MODULE_RESPONSIBILITIES.md
│   └── REQUIREMENTS_TRACEABILITY.md
│
├── src/apex_forensic/
│   ├── adapters/
│   │   ├── artifacts/
│   │   │   ├── browser.py
│   │   │   ├── media.py
│   │   │   ├── communication/
│   │   │   └── windows/
│   │   ├── evidence/
│   │   │   ├── ewf.py
│   │   │   ├── partitions.py
│   │   │   ├── raw.py
│   │   │   └── virtual_disk.py
│   │   ├── filesystem/
│   │   │   └── pytsk.py
│   │   ├── hashing/
│   │   ├── persistence/sqlite/
│   │   │   └── repository.py
│   │   └── schema/
│   ├── application/services/
│   │   ├── ai_assistance.py
│   │   ├── artifact_analysis.py
│   │   ├── context.py
│   │   ├── evidence_image.py
│   │   ├── file_system_index.py
│   │   ├── machine_extraction.py
│   │   ├── report.py
│   │   ├── search.py
│   │   └── timeline.py
│   ├── cli/
│   │   ├── commands.py
│   │   └── parser.py
│   ├── config/
│   ├── domain/
│   ├── jobs/
│   └── ports/
│       ├── ai_assistance.py
│       ├── artifact_analyzer.py
│       ├── browser_analyzer.py
│       ├── evidence_reader.py
│       ├── filesystem_provider.py
│       ├── machine_extraction.py
│       ├── media_analyzer.py
│       ├── raw_reader.py
│       ├── report_renderer.py
│       ├── search_index.py
│       └── timeline_repository.py
│
├── schemas/v1/
├── tests/
│   ├── fixtures/registry/
│   ├── integration/
│   └── unit/
│       ├── test_communication_artifacts.py
│       ├── test_evidence_readers.py
│       ├── test_image_filesystem_provider.py
│       ├── test_phase5_media_browser.py
│       ├── test_phase6_context_views.py
│       ├── test_phase7_ai_assistance.py
│       ├── test_phase8_report_contract.py
│       └── test_windows_artifacts.py
│
└── tools/
    ├── validate_design.mjs
    ├── validate_design_basic.py
    ├── validate_design.sh
    └── verify_windows_event_message_renderer.py
```

## 설계 문서

| 산출물 | 문서 |
|---|---|
| 전체 Architecture 및 품질 속성 | [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) |
| Forensic Core Engine 구현 및 사용법 | [`docs/FORENSIC_ENGINE.md`](./docs/FORENSIC_ENGINE.md) |
| 구현 결정 기록 | [`docs/IMPLEMENTATION_DECISIONS.md`](./docs/IMPLEMENTATION_DECISIONS.md) |
| Directory Structure | [`docs/DIRECTORY_STRUCTURE.md`](./docs/DIRECTORY_STRUCTURE.md) |
| Module 역할 및 의존성 | [`docs/MODULE_RESPONSIBILITIES.md`](./docs/MODULE_RESPONSIBILITIES.md) |
| Database Schema | [`docs/DATABASE_SCHEMA.md`](./docs/DATABASE_SCHEMA.md) |
| API Interface | [`docs/API_INTERFACE.md`](./docs/API_INTERFACE.md) |
| JSON Schema 규칙 | [`docs/JSON_SCHEMAS.md`](./docs/JSON_SCHEMAS.md) |
| Implementation Roadmap | [`docs/IMPLEMENTATION_ROADMAP.md`](./docs/IMPLEMENTATION_ROADMAP.md) |
| Requirements Traceability | [`docs/REQUIREMENTS_TRACEABILITY.md`](./docs/REQUIREMENTS_TRACEABILITY.md) |

---

## 개발 진행 상태

### 설계 완료

- [x] 전체 System Architecture
- [x] Python-Native 하이브리드 구조
- [x] Forensic Core Engine Architecture
- [x] Module Responsibility
- [x] Database Schema
- [x] API Interface
- [x] JSON Schema v1
- [x] Requirements Traceability
- [x] Implementation Roadmap
- [x] GUI Context
- [x] Scope별 Analysis Context
- [x] Citation 및 Raw Locator
- [x] Provider-neutral AI 경계
- [x] MCP Integration Boundary
- [x] Progressive Indexing 및 Analysis Profile
- [x] Timezone 탐지·정규화·Audit 설계
- [x] AI Keyword Recommendation 계약
- [x] Search Reproduction 설계
- [x] Append-only Chain of Custody 설계
- [x] Simple / Detailed / Raw View 설계
- [x] Browser Communications MVP 설계
- [x] Images / Videos / Audio MVP 설계
- [x] OCR/STT Machine-extracted Candidate 계약
- [x] Report Human Review 및 Approval 설계
- [x] 한국어 및 Localization 설계
- [x] 외부 전문가 검증 계획
- [x] 설계 검증 도구

### 구현 완료

- [x] Phase 1 Core Foundation
- [x] Project Skeleton 및 공통 Infrastructure
- [x] Case / Evidence / Hash 관리
- [x] SQLite Repository
- [x] Chain of Custody Ledger 및 Hash Chain 검증
- [x] Job / Progress / Cancellation 기본 구조
- [x] CLI 및 JSON Schema 검증
- [x] Unit / Integration Test
- [x] Phase 2 Progressive File System 및 Indexing
- [x] Logical Directory / Logical File Provider
- [x] Quick Triage / Selected Scope / Full Analysis
- [x] Partial Result 및 Coverage
- [x] Priority Queue / Checkpoint / Resume
- [x] Cooperative Pause / Cancel
- [x] Stable Cursor Pagination
- [x] 한글 및 Unicode Path Round Trip
- [x] Phase 3 Windows Artifact Analysis MVP
- [x] 공통 Artifact Domain 및 Analyzer Port
- [x] File System Index 기반 Artifact Discovery
- [x] Registry `.reg` 및 Optional Binary Hive Capability
- [x] Exported Event XML 및 Optional Binary EVTX Capability
- [x] Prefetch 최소 Metadata Parser
- [x] Artifact SQLite Persistence 및 Query
- [x] Artifact Checkpoint / Resume / Pause / Cancel
- [x] Artifact Raw Locator 및 Citation
- [x] Artifact CLI 및 Unit / Integration Test
- [x] Phase 4 Search, Keyword Set 및 Timeline
- [x] SQLite FTS5 Metadata / Artifact Search Index
- [x] Keyword Set 및 Immutable Versioning
- [x] Search Reproduction / History / Rerun
- [x] Search Cache 및 Revision 기반 무효화
- [x] File System / Registry / Event Log / Prefetch Timeline Projection
- [x] Raw Timestamp·Timezone 보존 및 UTC·Case Timezone 표시
- [x] Search / Timeline Opaque Stable Cursor Pagination
- [x] Search Index / Timeline Build Checkpoint / Resume / Pause / Cancel
- [x] Search / Keyword Set / Timeline CLI·Schema·Test
- [x] Phase 5 Browser Communications & Media Metadata MVP
- [x] Chromium / Firefox Profile Discovery
- [x] Chromium Visit / Search Term / Download 분석
- [x] Firefox Visit / Download Candidate 및 URL-bar Input Candidate 분리
- [x] Browser SQLite Main DB / WAL / SHM Snapshot과 Source Revision
- [x] Browser Source Checkpoint / Resume / Pause / Cancel
- [x] Browser Stable Cursor / Search / Timeline 연동
- [x] Image Metadata / JPEG EXIF / GPS Candidate
- [x] Video / Audio Metadata 및 Optional ffprobe Capability
- [x] Bounded Cross-platform Subprocess와 Windows Snapshot Cleanup
- [x] Thumbnail Derived Metadata 계약
- [x] Machine-extracted Candidate Domain 및 Append-only Review History
- [x] OCR / STT Provider Port와 `CAPABILITY_UNAVAILABLE` 기본 동작
- [x] Browser / Media / Candidate CLI·Schema·Test
- [x] Windows·Linux Runtime 회귀 검증
- [x] Phase 6 GUI Context, Analysis Snapshot 및 View Runtime
- [x] Live GUI Session Context Revision·TTL·Optimistic Lock
- [x] Immutable Analysis Context Snapshot 및 Refresh 계보
- [x] Keyword·Search·Timeline·Analyzer·Source Revision 보존
- [x] Scope별 Context, Partial·Stale·Coverage 및 Stable Cursor
- [x] Evidence Scope와 Cross-case·Cross-evidence Validation
- [x] Artifact Type 기반 Scope 격리
- [x] Simple / Detailed / Raw View Projection
- [x] Indexed Source 기반 Safe Raw Range Read와 Append-only Audit
- [x] Public Engine Interface, Capability 및 Tool Descriptor
- [x] `context` / `view` / `interface` CLI
- [x] Phase 6 JSON Schema 및 Unit·Integration Test
- [x] Windows·Linux Runtime 회귀 검증
- [x] Phase 7 AI Assistance Engine Contract
- [x] Snapshot 기반 AI Assistance Request와 TTL/Fingerprint 검증
- [x] 외부 Keyword Recommendation·Scope Summary Ingest 검증
- [x] Citation, Partial, Stale, Coverage Warning 보존
- [x] Append-only Human Verification Hash Chain
- [x] Accepted/Corrected Keyword Promotion과 Search 자동 실행 차단
- [x] `ai` CLI 및 Public Engine Interface AI Tool Descriptor
- [x] Phase 7 JSON Schema 및 Unit·Integration Test
- [x] Phase 8 Report Aggregate와 Immutable Version
- [x] Analyst/AI Draft Ingest, Section/Citation/Snapshot/Evidence 검증
- [x] Append-only Report Review/Approval Hash Chain
- [x] Chain of Custody Snapshot과 Ledger Verification Metadata
- [x] Render Package, Export Manifest, Renderer Port 기본 `CAPABILITY_UNAVAILABLE`
- [x] `report` CLI, Public Engine Interface Report Tool Descriptor, JSON Schema 및 Test
- [x] Phase 1~8 통합 보안·기능 감사
- [x] Read Interface / Mutation Operation 경계 강화
- [x] Post-index Symlink·Reparse Point 교체 방어
- [x] Windows-safe Export Filename 및 Derived Root 검증
- [x] Export Manifest 상태 전이와 Prepare 멱등성 검증
- [x] AI Revision Resolver 예외 처리 강화
- [x] 수정 사항 Linux Regression Test와 Windows Host-required 분리
- [x] RAW·DD·IMG·E01·VHD·VHDX Reader와 Partition 분석
- [x] `pytsk3` 기반 Image File System Tree
- [x] 삭제 File Recovery, Unallocated Range 및 Slack Export
- [x] Registry Transaction Log Replay와 삭제 Candidate
- [x] Prefetch MAM 압축 해제와 Windows Event Message Rendering
- [x] Browser AES-GCM 외부 Key 복호화, Cache·삭제·Private-mode Candidate
- [x] Email·Discord·Telegram Communication Analyzer
- [x] Raster Thumbnail과 제한된 Video Frame Sampling
- [x] 한국어 NFC·Casefold·Path·자모 Search 정규화
- [x] Windows Event Message Renderer Semantic Verifier (`HOST_VERIFICATION_REQUIRED` on Linux)
- [x] Offline DPAPI·Firefox NSS Adapter와 Synthetic Runtime Verification
- [x] Registry Binary Deleted-cell Carving
- [x] HTML 및 Optional PDF Renderer
- [x] Runtime Doctor와 Quick/Full Synthetic Benchmark Harness
- [x] Recovery/Fault-injection 및 Bandit Finding Disposition Gate
- [x] 재현 가능한 `tools/verify_engine_release.py` Release Gate

### 구현 예정

- [x] Windows 2.0.8.990 KakaoTalk 외부 Key 합성 Contract 복호화와 Offline Discovery
- [ ] KakaoTalk 자동 Key 획득 및 실제 KakaoTalk Fixture 검증
- [ ] 형태소 기반 한국어 Search 검토
- [ ] OCR·STT Runtime/Model 배포와 실제 Host Fixture Matrix
- [ ] 외부 AI Adapter 품질 평가와 실제 Provider 통합 검증
- [ ] GUI Report Preview
- [ ] 실제 Evidence 성능·정확성 Benchmark 및 외부 전문가 검토
- [ ] Windows Desktop Packaging과 CI Matrix

### 별도 담당

- [ ] Built-in MCP Adapter — MCP 담당
- [ ] LLM Provider / Prompt / Agent Workflow — MCP·AI 담당
- [ ] Identity / Approval / Billing — Backend 담당
- [ ] 한국어 GUI 및 View — Frontend 담당

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

### Phase 1 — Core Foundation — 완료

- [x] Project Skeleton
- [x] Case Manager
- [x] Evidence Manager
- [x] Hash 및 무결성 검증
- [x] Custody 기본 Event 및 Hash Chain
- [x] Timezone 기본 설정
- [x] Job / Progress / Cancellation 기본 구조
- [x] JSON Schema 기반 출력 검증
- [x] CLI Smoke Test Interface
- [x] Unit / Integration Test

### Phase 2 — Progressive File System — 완료

- [x] File System Domain Model 및 Provider Port
- [x] Logical Directory / Logical File Provider
- [x] Quick Triage
- [x] Selected Scope Priority
- [x] Full Metadata Index
- [x] Priority Queue
- [x] Cooperative Pause / Resume / Cancel
- [x] Partial Result 및 Coverage
- [x] Checkpoint / Resume
- [x] SQLite Batch Persistence
- [x] Stable Cursor Pagination
- [x] CLI 및 JSON Schema 확장
- [x] Unit / Integration Test

### Phase 3 — Windows Artifact Analysis — 완료

- [x] 공통 Artifact Domain Model
- [x] Provider-neutral Analyzer Port
- [x] File System Index 기반 Artifact Discovery
- [x] Registry Export Text (`.reg`) 분석
- [x] Autorun / USBSTOR / TimeZoneInformation / UserAssist
- [x] Optional `python-registry` Binary Hive Capability
- [x] Exported Windows Event XML 분석
- [x] Optional `python-evtx` Binary EVTX Capability
- [x] Prefetch Version 17·23·26·30 최소 Metadata 분석
- [x] MAM Compression 감지 및 Unsupported 상태 구분
- [x] Artifact SQLite Persistence
- [x] Checkpoint / Resume / Pause / Cancel
- [x] Stable Cursor Query
- [x] Raw Locator 및 Citation
- [x] Artifact CLI
- [x] Unit / Integration Test

### Phase 4 — Search, Keyword Set 및 Timeline — 완료

- [x] SQLite FTS5 Search Index
- [x] Metadata / Artifact Search
- [x] Keyword Set 및 Immutable Versioning
- [x] Search Reproduction / History / Rerun
- [x] Search Cache 및 Revision 기반 무효화
- [x] Timestamp Normalization
- [x] Timeline Projection / Query
- [x] Opaque Stable Cursor Pagination
- [x] Checkpoint / Resume / Pause / Cancel
- [x] CLI / JSON Schema / Unit·Integration Test

### Phase 5 — Browser Communications & Media Metadata — 완료

- [x] Chromium / Firefox Profile Discovery
- [x] Chromium History / Search Term / Download
- [x] Firefox Visit / Download Candidate
- [x] Firefox URL-bar Input Candidate 분리
- [x] Read-only Browser SQLite Snapshot
- [x] Main DB / WAL / SHM Source Fingerprint와 Reanalysis
- [x] Source Checkpoint / Resume / Pause / Cancel
- [x] Browser Stable Cursor / Search / Timeline 연동
- [x] Image Header Metadata / JPEG EXIF / GPS Candidate
- [x] Decompression Bomb / Corrupt File 보호
- [x] Video / Audio Metadata와 Optional ffprobe Capability
- [x] Cross-platform Bounded Subprocess / Timeout / Output Limit
- [x] Thumbnail Derived Metadata 계약
- [x] Machine-extracted Candidate / Append-only Review History
- [x] OCR / STT Provider Port와 Unavailable Capability
- [x] Browser / Media / Candidate CLI
- [x] JSON Schema / Unit·Integration Test
- [x] Windows·Linux Runtime 검증

### Phase 6 — GUI Context 및 View — 완료

- [x] Live GUI Session Context
- [x] Context Revision·TTL·Optimistic Lock
- [x] Immutable Analysis Context Snapshot
- [x] Snapshot Refresh 및 Previous Snapshot 계보
- [x] Scope별 Analysis Context
- [x] Partial·Stale·Coverage·Revision State
- [x] Evidence Scope 및 Stable Cursor Pagination
- [x] Artifact Type 기반 Scope Isolation
- [x] Simple / Detailed / Raw View Projection
- [x] Safe Raw Range Reader 및 Audit
- [x] Public Engine Interface와 Tool Descriptor
- [x] Structured Request Error 및 Canonical Operation Name
- [x] CLI / JSON Schema / Unit·Integration Test
- [x] Windows·Linux Runtime 검증

### Phase 7 — AI Assistance — 완료

- [x] Snapshot 기반 AI Assistance Request
- [x] 외부 Keyword Recommendation과 Scope Summary 검증·저장
- [x] Citation, Partial Result, Stale Source, Coverage Warning 보존
- [x] Human Verification Event Hash Chain
- [x] 승인/수정된 Keyword Candidate의 Keyword Set Promotion
- [x] Runtime LLM/MCP/Prompt/Provider 실행 코드 제외

### Phase 8 — Report 및 Chain of Custody — 완료

- [x] Analyst Draft와 외부 AI Draft Ingest
- [x] ReportRecord / Immutable ReportVersion / ReportSection
- [x] Source Kind, Citation, Context Snapshot, Evidence, Search, Timeline, AI Result Provenance
- [x] Partial / Stale / Coverage / Limitations 보존
- [x] Human Review, Section Review, Approval, Reject, Revoke Event Hash Chain
- [x] 승인 후 새 Version 생성과 재승인 요구
- [x] Chain of Custody Snapshot / Verification Metadata
- [x] Export Render Package / Manifest / Audit / Rendered Artifact Metadata 계약
- [x] Provider-neutral Renderer Port와 기본 `CAPABILITY_UNAVAILABLE`
- [x] 실제 AI Draft 생성, LLM/Prompt/MCP, GUI Preview, PDF/HTML Rendering 제외

### Phase 9 — Advanced Recovery, Benchmark 및 배포

- [x] DPAPI·NSS Offline Secret Recovery Adapter와 Synthetic Verification
- [x] Registry Binary Deleted-cell Carving
- [x] Windows 2.0.8.990 KakaoTalk 외부 Key 합성 Contract 복호화와 Schema 검증
- [ ] KakaoTalk 자동 Key 획득 및 실제 암호화 DB Fixture 검증
- [x] 동일 조건 기반 Synthetic Quick/Full Benchmark Harness
- [x] Progressive Indexing 및 Cache Cold·Warm 측정
- [x] Evidence Reader·File System·Recovery Fault-injection 검증
- Timezone 정확성과 Timeline 재현성 검증
- Chain of Custody 무결성 검증
- 공개 또는 Synthetic Evidence 기반 외부 전문가 검토
- 전문가 피드백 반영 및 재검증
- Native Dependency Packaging·CI Matrix 검증
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
- 결과 공개 시 Dataset과 측정 조건 명시

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

## 설계 및 회귀 검증

Release Hardening의 단일 재현 경로는 다음 명령입니다.

```bash
python3 tools/verify_engine_release.py --json
```

이 Gate는 `pytest`, Ruff, mypy, `git diff --check`, Python·Node Design Validator, Runtime
Semantic Verifier, Doctor, Recovery Test, Bandit Disposition, Benchmark Smoke, CLI 및 한글/Unicode
동작, Evidence Read-only Invariant를 구분된 상태로 보고합니다. 현재 Linux Host에서 Windows 전용
실행은 `HOST_VERIFICATION_REQUIRED`, 설치되지 않은 Optional Dependency는
`CAPABILITY_UNAVAILABLE`, 외부 AI 설정은 `EXTERNAL_CONFIGURATION_REQUIRED`로 유지합니다.

개별 진단과 Benchmark는 다음 명령으로 실행합니다.

```bash
python3 -m apex_forensic doctor --json
python3 -m apex_forensic benchmark --runs 1 --search-iterations 2 --json
```

### Python 기본 검증

Node 또는 Ajv가 없는 환경에서도 기본 검증을 실행할 수 있습니다.

```powershell
python -X utf8 .\tools\validate_design_basic.py
```

### Node 기반 전체 검증

```powershell
node .\tools\validate_design.mjs
```

### Windows Event Message Renderer 검증

```powershell
python .\tools\verify_windows_event_message_renderer.py --require-rendered
```

정상 결과는 `message_rendered: true`와 `WINDOWS_ADAPTER_RENDERED`입니다.

### Linux / WSL / CI 검증

```bash
bash ./tools/validate_design.sh
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
- API와 Schema 대응
- Database Table과 Module Owner
- Partial Result 필드
- Timezone 계약
- Keyword Candidate의 Reason 및 Citation
- Machine Extraction의 Confidence 및 Review Status
- Custody Event Enum과 Report Section
- MCP 및 LLM 실행 코드 미포함 여부

Node 또는 Ajv가 없는 경우 기본 검증을 수행하고, 생략된 항목과 이유를 출력합니다.

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
