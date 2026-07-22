# 단계별 구현 Roadmap

현재 단계는 **Phase 0: 설계 정합성 검토**다. 설계 완료와 코드 구현 완료를 구분하며, 각
Phase는 Acceptance Gate 통과 후 다음 단계로 진행한다. MCP Server와 LLM Provider 구현은
별도 담당자의 Roadmap이며 이 Core 저장소에서 구현하지 않는다.

## Phase 0. 설계 정합성, Schema와 테스트 기반

범위:

- Architecture, Module, DB, API, Context/Report/Citation 계약 정합성 검토
- JSON Schema Draft 2020-12와 로컬 `$ref` 검증
- 한국어/Timezone, MCP 경계, Communications/Media 범위 확정
- Contract/Fixture/성능 Test 전략과 Library 기술 Spike 목록 작성

완료 Gate:

- 모든 요구사항이 Architecture, API, DB, Schema, Phase와 검증 방법에 연결됨
- JSON Syntax, Ajv Strict, `$ref`와 순환 참조, Markdown Link 검증 통과
- Core/Backend/Frontend/MCP/AI/Billing 책임 경계가 명확함
- 설계 문서가 미구현 기능을 구현 완료로 표시하지 않음

## Phase 1. Project Skeleton, Case와 Evidence

구현:

- Python Package와 Domain/Application/Port/Adapter 의존성 Rule
- Case Manager, Case별 SQLite Migration과 Workspace Catalog
- `locale=ko-KR`, `timezone=Asia/Seoul` 기본 정책
- Directory Evidence Reader, Format Probe, SHA-256/MD5 Streaming Hash
- Job State Machine, Case별 단일 Writer, Audit Event

현재 구현 상태:

- `src/apex_forensic` 기반 Python 패키지와 CLI Entry Point 구현
- Case/Evidence/Hash/Verification/Custody/Job Phase 1 서비스 구현
- Phase 1 SQLite Table, WAL/Foreign Key 설정, Custody Append-only Trigger 구현
- MD5, SHA-1, SHA-256 Streaming Hash와 변경 감지, 취소, Progress 구현
- Case/Evidence/Job/Custody JSON Schema 검증 테스트 구현
- Phase 2 이후 File System Parsing, Artifact Parser, Progressive Indexing 전체 기능은 미구현

Acceptance Gate:

- Evidence를 쓰기 모드로 열지 않음을 Test로 검증
- 동일 Fixture Hash가 기준값과 일치
- UTF-8 API와 한글 Case/Evidence 표시명이 손실 없이 Round-trip
- API Fixture가 Case/Evidence/Job Schema를 통과

## Phase 2. Progressive File System, Lazy Loading와 기본 Index

구현:

- RAW/DD, E01 Reader와 Partition/File System 열거, VHD/VHDX Spike
- Object/File/Extent Batch 저장과 삭제 항목 Capability
- Cursor Pagination, Lazy Directory Tree, Evidence Streaming
- 원본 파일명/경로 Raw 표현과 검색용 Unicode 정규화 사본 분리
- 기본 Metadata/경로 Index

Acceptance Gate:

- 공인 또는 재현 가능한 Fixture의 File Count/Path/Offset 비교
- 한글 완성형/자모/혼합 경로가 원본과 표시 값에서 손실 없음
- 손상/누락 E01이 명시적 오류를 반환
- 100만 File Metadata Fixture에서 Memory가 Page 크기에 의해 제한됨

## Phase 3. Registry, Event Log와 Prefetch

구현 순서:

1. Windows Registry
2. Windows Event Log
3. Windows Prefetch

각 Analyzer는 Manifest, 후보 탐색, 독립 Parser, Artifact Payload Schema, 손상 Fixture와
Resource Key를 제공한다.

Acceptance Gate:

- 정상/손상/부분 파일에서 Worker Process Crash 없음
- 모든 Artifact가 Evidence/Object/Offset/Analyzer Run으로 역추적됨
- Analyzer 하나의 실패가 다른 결과를 Rollback하지 않음
- Artifact 표시명/설명이 한국어 Resource Key로 Resolve됨

## Phase 4. Search, Timeline, Timezone, Cache와 병렬 Job

구현:

- File/Artifact Timeline Projector와 UTC/원본 시간 분리
- SQLite FTS5 또는 동등 Index, 한국어 Normalization/Tokenizer Profile
- Keyword/Exact/제한된 Regex Search와 고정 Search Result
- Content-addressed Cache, Quota, LRU와 Hash 검증
- Process Pool, Async I/O, 병렬 Artifact Task, Checkpoint/Resume
- 입력 Fingerprint 기반 동일 Evidence/Analyzer 중복 실행 방지

Acceptance Gate:

- 같은 입력/버전으로 결정적 Timeline/Dedup Key 생성
- 한글 Keyword/자모/영문 혼합 검색 Fixture 통과
- Regex Timeout/후보/Pattern Limit 동작
- Worker 종료 후 Checkpoint 재개 시 중복 Fact 없음
- Cache 전체 삭제 후 영구 Fact 손실 없이 재생성

## Phase 5. Images/Videos와 Browser Communications MVP

Images/Videos:

- 이미지/영상 분류, EXIF/GPS, Thumbnail, Codec, Duration
- 생성/수정 시간과 삭제된 Multimedia File 표시
- Thumbnail을 Hash 검증 가능한 Cache 파생물로 저장

Browser Communications:

- Browser Profile, 방문 URL/History, Search History, Download History/File
- Profile/DB/Table/Row Provenance와 시간 기준 조회

Email, Discord, Telegram, KakaoTalk 및 기타 Messenger는 후순위 Plugin이며 이 Phase의 완료
조건이 아니다.

Acceptance Gate:

- GPS/시간 원본 값과 정규화 값을 동시 보존
- AI 없이도 Media/Browser 결과를 JSON으로 완전히 조회 가능
- 손상 Media/Browser DB가 전체 Job을 중단하지 않음

## Phase 6. GUI Context, View와 MCP Adapter Interface

구현:

- Backend Session Context Port와 Revision 기반 UI Context DTO
- UI Context Snapshot과 Analysis Context Builder
- 선택 File/Artifact/Timeline/Search Result/Tag/Annotation Resolve
- Citation 생성, 같은 Case 소속 검증, Canonical Content Hash
- MCP Adapter가 소비할 공개 Context/Analysis Bundle API

Acceptance Gate:

- Live UI Context는 Session 만료 시 폐기되고 기본적으로 Case DB에 쓰이지 않음
- Snapshot은 생성 후 불변이며 같은 입력에서 동일 Content Hash 생성
- 다른 Case ID 또는 삭제된 ID를 포함한 Bundle 생성 거부
- 공개 API만 사용하는 Fake MCP Consumer Contract Test 통과

MCP Server/Tool과 GUI-to-MCP 전달 구현 자체는 별도 MCP 담당자가 수행한다.

## Phase 7. AI Assistance, Citation과 한국어 결과

Core 구현 범위:

- `AIEnrichmentPort`, Provider-neutral Request/Result DTO와 Null/Fake Adapter
- Observed Fact, Analyst Annotation, AI Inference, AI Recommendation 분리
- Citation/Confidence/Limitation 검증과 별도 AI 결과 저장
- Case Locale에 따른 `output_locale` 전달

금지 범위:

- LLM Provider SDK/API, 모델 선택, Credential
- Prompt Template/Agent Loop
- AI 결과로 Core Artifact Update

Acceptance Gate:

- AI Adapter 없이 모든 Core 기능과 Test 통과
- Fake Adapter 결과의 한국어/Category/Citation Schema 검증
- Citation 없는 Inference/Recommendation 거부
- Adapter 실패가 Ingest/Timeline/Search를 변경하지 않음

## Phase 8. Report, Chain of Custody와 Human Review

구현:

- 한국어 Report Template과 17개 Section Type
- Evidence/Artifact/Timeline/Search Result/Tag Selector
- Provider-neutral `ReportDraftPort`
- `DRAFT -> GENERATING -> REVIEW_REQUIRED -> APPROVED` 상태와 반려/재검토
- 승인 Version/Content Hash 고정, PDF/HTML Export와 Export Hash

Acceptance Gate:

- AI Draft가 직접 `APPROVED` 또는 `EXPORTED`로 전환할 수 없음
- 사람 Identity와 기대 Version/Hash가 없는 승인 요청 거부
- 승인 후 수정하면 Version 증가 및 재검토 필요
- 모든 주요 발견/AI 문장의 Citation Source가 실제 Case 결과로 Resolve됨
- PDF/HTML이 같은 승인 Version, Locale, Timezone과 Citation을 표현

## Phase 9. Benchmark, 외부 검증, 안정성 및 Packaging

구현/검증:

- 고정 Hardware/Evidence/Analyzer Scope의 재현 가능한 Benchmark
- 처리량, P95 Query, Peak RSS, DB Batch, Cache Hit 측정
- Process Kill, Disk Full, DB Lock, 손상 Cache, 취소/재개 Test
- Path Traversal, Regex DoS, Decompression Bomb와 권한 Test
- Frontend, Backend, Core, Built-in MCP Adapter의 Desktop Packaging 경계 검증

Acceptance Gate:

- 성능 수치에 Hardware, Fixture, Version과 측정 방법이 동반됨
- 설치되지 않은 Reader/Plugin은 Capability로 정확히 표시됨
- MCP/AI Component 장애 시 Core 분석/조회는 독립적으로 동작
- Packaging에 Core 금지 의존성, API Key 또는 Secret이 포함되지 않음

APEX는 “Autopsy보다 빠르다” 또는 “X-Ways와 동일하다”는 표현을 Benchmark 없이 사용하지
않는다. X-Ways의 빠른 분석 철학을 참고하여 대용량 Evidence 처리 최적화를 목표로 한다.

## 공통 검증 Matrix

| 종류 | 최소 검증 |
| --- | --- |
| Unit | Domain 상태, Projector, Query Parser, Canonical Hash, Report 전이 |
| Contract | Reader/Analyzer/Repository/Context/AI/Report Port, JSON Schema |
| Integration | Case DB, Worker/Writer, Snapshot, Report API |
| Forensic Fixture | 정상·삭제·손상·부분 이미지와 기대 Artifact |
| Localization | 한글 경로/검색/오류 Key/시간/Report Template |
| Property | Bounds, Path, Offset, Timestamp, Parser 비정상 입력 |
| Performance | 처리량, P95 Query, Peak RSS, Cache Hit, DB Batch |
| Security | Path Traversal, Regex DoS, 권한, Export Content Sanitization |
| Recovery | Process Kill, Disk Full, DB Lock, Cache 손상, 재개 |

## 구현 전 기술 Spike

| 주제 | 확인할 결정 |
| --- | --- |
| File System Library | pytsk3/Binding 대안의 Python/Windows/삭제 파일 지원 |
| E01/VHD | Random Read, Process 안전성, 읽기 전용 배포 가능성 |
| 한국어 FTS | FTS5 Tokenizer/Trigram/외부 Index의 정확도·크기·속도 |
| Unicode | NFKC/Case Folding과 Raw 경로의 무손실 Round-trip |
| Regex | Timeout과 Linear-time 보장 Engine |
| Canonical JSON | RFC 8785 구현의 숫자/Unicode 처리 |
| PDF/HTML | 한글 Font 포함, Citation Link, 결정적 Export Hash |
| Desktop 경계 | Backend Session Store와 Built-in MCP Adapter Process 모델 |

## Python-Native Provider 기술 검증

### Phase 0~1 기술 Spike

- `libtsk` 및 `pytsk3`의 Windows 호환성 검토
- E01 Provider 후보 검토
- VHD/VHDX Provider 후보 검토
- Native Hash Provider Benchmark
- SQLite FTS5 한국어 검색 검증
- FFmpeg 및 ffprobe Packaging 검토
- YARA Process 안전성 검토
- Native Library License 검토
- Windows Desktop 배포 가능성 검토
- Process Pool 및 Single DB Writer Prototype 검증

### Provider 선정 기준

- Windows 지원 여부
- 지원 Python 버전
- Evidence 형식 및 File System 지원 범위
- 삭제 파일 지원 여부
- Process 및 Thread 안전성
- 유지보수 상태
- License
- 오류 처리 방식
- Packaging 난이도
- Benchmark 결과

### Phase 9 검증

- Native Provider별 성능 Benchmark
- Native Dependency Packaging 검증
- 설치 환경별 실행 검증
- Cache Cold/Warm 성능 비교
- 최대 Memory 및 Disk I/O 측정
- Worker 수에 따른 Scalability 측정

## 외부 요구사항 반영 Phase 보강

기존 Phase 0~9의 순서와 Acceptance Gate를 유지하면서 다음 설계·구현 항목을 각 Phase에
추가한다. 아래 항목은 Roadmap이며 현재 구현 완료 상태가 아니다.

| Phase | 추가 범위 | 추가 Acceptance/Validation |
|---|---|---|
| 0 | Progressive Index Prototype, Timezone Dataset/Fixture, Custody Event Model, Keyword Contract, Raw Range 제한, OCR/STT Provider 기술 검토, External Validation Plan | Schema/DB/API/Owner 추적, DST/부분 결과/Custody Hash Fixture 설계 |
| 1 | Custody 기본 Event, Evidence Fingerprint, Case Timezone 기본 Decision | Event Update/Delete 부재, 원본 Timestamp 불변, Actor Identity 계약 |
| 2 | Quick Triage, File Tree 우선 표시, Background Index, Pause/Resume/Cancel, Priority Queue, Partial Result | 첫 File Tree 시간, Partial 표시, Checkpoint 재개와 사용자 Scope 우선순위 |
| 3 | Registry/Event Log/Prefetch Raw Locator | Artifact에서 제한된 원본 Range와 Citation Resolve |
| 4 | Keyword Set, Search Reproduction, Timezone Normalization, Timeline 표시 전환 | 0건 Keyword 기록, 동일 Options 재실행, DST/다중 Timezone 재현 |
| 5 | OCR/STT Contract와 Machine-extracted Candidate | Confidence/Engine/Locator, Accept/Reject/Correct Review |
| 6 | Scope별 Context, Simple/Detailed/Raw View | Scope Revision/Partial 전파, 최대 Raw Length와 읽기 전용 접근 |
| 7 | AI Keyword Recommendation, Scope Summary, Partial 경고, Human Verification | 승인 전 검색 차단, Citation 없는 결과 거부, Scope 외 데이터 거부 |
| 8 | Custody Snapshot/Hash History, 확장 Report Provenance | Report Version 연결, 다섯 결과 분류, 승인 후 불변성 |
| 9 | 내부 Benchmark와 외부 DFIR·사이버 작전 실무 전문가 자문, 사용성 평가, 재검증 | 공개/Synthetic Dataset, 동일 조건, `PLANNED` 상태와 기관명 미표기 |

### Phase 0 기술 Spike 추가

- Progressive Index Queue의 사용자 선택 Scope 선점 정책과 Background 기아 방지
- ETA 표본 수, 신뢰도 하향 조건과 알 수 없는 전체 Item 처리
- IANA tzdb Version, Windows/Linux Timezone 매핑과 DST 경계 Fixture
- Custody Canonicalization/Hash Chain Algorithm과 Correction 규칙
- Keyword Variant, 중복 정규화와 민감 Context 최소화
- Raw Hex/Text 1 MiB 제한, Chunk Cursor와 Audit
- OCR/STT Candidate Contract 및 Provider Packaging 비교
- External Validation Dataset, 동의와 공개 정책

### Phase 9 검증 항목 추가

Evidence 등록, E01 최초 열기, 첫 File Tree, Quick Triage, Full Index, Artifact별 시간,
Keyword Search/추천 유용성, Cache Cold/Warm, Pause/Resume, Timezone 정확성, Timeline
재현성, Report 시간, Custody 완전성, CPU/Memory/Disk I/O, 취소 응답, GUI/Raw View,
AI Citation·한계 표시와 실제 조사 Workflow 적합성을 측정한다.

비교는 동일 Hardware, Evidence, 분석 범위, Hash/Index 옵션, Cache 상태, Worker 수와
Storage에서만 수행한다. 외부 검증은 공개 DFIR Dataset, Synthetic Evidence와 법적으로 사용
가능한 Test Image만 사용하며 비공개 작전 자료, 개인정보와 기밀정보를 사용하지 않는다.
외부 전문가 검증 상태는 구현·평가가 끝날 때까지 `PLANNED`다.

## Phase 2 Completion Note

Phase 2 Progressive File System & Indexing is implemented for Directory Evidence and ordinary Logical File Evidence. It includes the provider port, logical directory provider, progressive coordinator, SQLite persistence, partial/checkpoint/resume, cooperative pause/cancel, stable cursor queries, CLI commands, schemas, and tests.

## Phase 3 Completion Note

Phase 3 Windows Artifact Analysis MVP is implemented for offline sources represented by the Phase 2
filesystem index.

- Registry: `.reg` parsing, key/value artifacts, autorun, USBSTOR, timezone, safe UserAssist parsing,
  and optional `python-registry` binary hive capability reporting.
- Event Log: exported Event XML parsing, namespace-safe field extraction, raw XML preservation,
  subtype/title candidates for common Security/System/Sysmon IDs, and optional `python-evtx` EVTX
  capability reporting.
- Prefetch: minimal `.pf` metadata parser for versions 17/23/26/30, unsupported version separation,
  and MAM compression detection without decompression.
- Coordinator: discovery from `fs_nodes`, selected scope/include/exclude filters, item budget at
  source boundaries, batch persistence, checkpoint/resume, cooperative pause/cancel, partial coverage,
  duplicate source/analyzer/options prevention, and stable cursor queries.
- SQLite/Schema/CLI/Tests/Docs: Phase 3 tables, JSON Schema updates, artifact CLI commands, synthetic
  fixtures, SQLite reopen/resume coverage, and design validation support.

Deferred to later phases: timeline integration, FTS/search engine, parallel workers/cache, raw byte
view API, GUI, MCP, OCR/STT, LLM/AI flows, browser/media analyzers, and report rendering.

The next phase should connect native/disk-image providers through the existing provider port and add artifact/timeline/search integrations. E01/RAW/DD/IMG/VHD/VHDX internal parsing, deleted file recovery, FTS/full text search, and artifact parser execution remain intentionally out of scope.
