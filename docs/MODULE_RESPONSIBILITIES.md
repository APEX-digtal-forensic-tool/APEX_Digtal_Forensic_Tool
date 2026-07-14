# 모듈 역할 정의

## 1. 상위 모듈

| 모듈 | 책임 | 입력 | 출력 | 소유하지 않는 책임 |
| --- | --- | --- | --- | --- |
| Domain | Entity, Value Object, 상태 규칙, 오류 코드 | 순수 Python 값 | Domain 객체/이벤트 | DB, HTTP, 파일 형식 파싱 |
| Application | Use Case 조정, 권한/정책, Transaction 경계 | Command/Query DTO | Result DTO, Job ID | 형식별 Evidence 읽기 |
| Evidence Manager | Case/Evidence 등록, 형식 판별, Hash, 무결성 | Evidence URI, 등록 옵션 | Evidence Metadata, Hash Result | 파일 시스템 Artifact 해석 |
| File System Analyzer | Volume/FS/Object/File 계층, Metadata, 삭제 항목 | Evidence Reader | File/Object Batch | Registry/Event Log 해석 |
| Artifact Analyzer | 형식별 Fact 추출과 정규화 | 후보 File/Object Stream | Artifact Batch | Timeline 표시 정책 |
| Timeline Engine | 여러 Fact를 공통 시간 이벤트로 투영 | Artifact/File Metadata | Timeline Event | 원본 Fact 수정 |
| Search Engine | 문서화, Keyword/Regex/Index Search | File/Artifact/Timeline | Search Hit | Evidence 원본 변경 |
| Index/Cache | 재검색/재분석 비용 절감 | 정규화 문서, 파생 Blob | Index Result, Cache Handle | 영구 Fact의 유일 저장소 |
| Job Orchestrator | 예약, 진행률, 취소, 재시도, Checkpoint | Job Specification | Job/Task 상태 | Analyzer 내부 해석 로직 |
| Context Service | Live UI DTO 검증, Result Resolve, 불변 Snapshot | GUI 선택/필터, Result ID | UI/Analysis Context | GUI Widget 상태, MCP Tool |
| Annotation/Tag | 사람의 해석과 주요 증거 분류 | Target ID, 사용자 입력 | Annotation, Tagged Item | Engine Fact 생성 |
| Report Module | 선택, AI Draft Port, Review/Approval, Export | Context, Citation, 분석자 Action | Report/Export | LLM 호출, 자동 승인 |
| Localization | Locale/Timezone 정책, Resource Key, 검색 정규화 | 원본 문자열/Case 설정 | 표시 Key, 검색 사본 | GUI 번역 Rendering |
| API Interface | 인증 경계, DTO 검증, 직렬화, 오류 매핑 | HTTP/내부 호출 | Versioned JSON | Domain 규칙 구현 |
| AI Layer | 선택적 외부 보강 Port와 DTO | Analysis Bundle | Enrichment Result | Provider 호출, Prompt, Core Fact 변경 |
| Observability | 구조화 로그, Metric, Trace, Audit 연계 | Domain/Application Event | 운영 Telemetry | Evidence 내용 로깅 |

## 2. Domain 계약

### Case

- Case 생명주기와 저장 위치를 식별한다.
- Case의 Timezone과 생성 도구 버전을 보존한다.
- 기본 `locale=ko-KR`, `timezone=Asia/Seoul`을 적용하고 명시적으로 변경 가능하게 한다.
- 삭제 대신 `CLOSED` 상태 전환을 기본으로 한다.

### Evidence

- 원본 위치, 형식, 논리/물리 크기, Reader Capability를 보존한다.
- `REGISTERED -> HASHING -> READY` 또는 `FAILED` 상태를 가진다.
- Hash 값은 알고리즘별 별도 레코드이며 같은 Evidence에 여러 계산 실행을 기록할 수 있다.

### Object/File

- `objects`의 Parent/Child 구조가 Evidence, Volume, File System, Directory, File을 연결한다.
- 파일의 이름, 경로, 시간, 크기, Allocation/Deletion 상태는 정규화 컬럼으로 저장한다.
- 원본 바이트 위치와 File System ID를 통해 재현 가능한 읽기를 제공한다.

### Artifact

- Parser가 관찰한 불변 Fact다.
- Artifact Type과 Schema Version이 Payload 의미를 결정한다.
- 모든 Fact는 Source Object와 Analyzer Run으로 역추적할 수 있어야 한다.
- 표시용 요약과 검색용 텍스트는 파생 값이며 Payload를 대체하지 않는다.

### Timeline Event

- File 또는 Artifact에서 파생된 시간축 Projection이다.
- 동일 Source의 동일 시간/행위를 `dedup_key`로 중복 억제할 수 있다.
- UTC 정규화 값과 원본 시간 표현을 모두 보존한다.

## 3. Evidence Adapter

| Adapter | 1차 지원 | Capability 예시 | 검증 항목 |
| --- | --- | --- | --- |
| Directory | 일반 파일/폴더, Symlink 정책 | `LIST_FILES`, `READ_STREAM` | 경로 탈출, 권한 오류, 순환 Link |
| RAW/DD | Random Read, Partition 열거 | `READ_AT`, `VOLUMES` | 크기, Sector, Partition Bounds |
| E01 | Segment, 압축 Stream, 저장 Hash | `READ_AT`, `EMBEDDED_HASH` | Segment 누락, 저장 Hash 비교 |
| VHD/VHDX | Virtual Disk Stream | `READ_AT`, `VOLUMES`, `SPARSE` | Parent Disk, Sparse Range, 암호화 |

`EvidenceReaderPort`는 Bytes를 제공할 뿐 Artifact 의미를 해석하지 않는다. Adapter별 외부
Library 객체가 Domain이나 API DTO로 누출되면 안 된다.

## 4. Analyzer Plugin 계약

각 Analyzer 패키지는 다음 정보를 제공한다.

| 항목 | 설명 |
| --- | --- |
| `analyzer_id` | 영구적으로 안정적인 식별자, 예: `windows.registry` |
| `version` | Parser/정규화 동작 버전 |
| `input_predicates` | 경로, Magic, MIME, File System 조건 |
| `required_capabilities` | Stream, Random Read 등 필요한 Reader 기능 |
| `artifact_types` | 출력 가능한 Type과 Payload Schema |
| `config_schema` | 실행 옵션 JSON Schema |
| `resource_profile` | CPU/I/O/Memory 분류와 권장 Batch 크기 |

Lifecycle:

| 단계 | 역할 | 실패 정책 |
| --- | --- | --- |
| Discover | Index에서 후보 Object 선택 | 조건 오류는 Analyzer 시작 실패 |
| Prepare | Read-only Context와 설정 검증 | 필수 Capability 부족 시 명시적 Skip |
| Analyze | Batch 단위 Parse/Normalize | 대상별 오류 기록 후 계속 |
| Emit | Artifact와 Provenance Batch 생성 | Batch Transaction Rollback/재시도 |
| Checkpoint | 마지막 처리 Cursor 저장 | 실패 시 이전 Checkpoint 유지 |
| Finalize | 통계와 Run 상태 확정 | 결과는 `PARTIAL` 가능 |

## 5. 우선 Artifact Analyzer

| Analyzer | 주요 입력 | 대표 Artifact | 핵심 Provenance |
| --- | --- | --- | --- |
| Registry | SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT 등 Hive | Key/Value, User, Installed Program, USB, Run Key | Hive 경로, Key 경로, Value, Cell Offset |
| Event Log | Windows `.evtx` | Event Record | File 경로, Record ID, Channel, Provider |
| Prefetch | Windows `.pf` | Program Execution | File 경로, Format Version, Run Count |
| Browser Communications | SQLite/JSON/Cache DB | Visit, Search, Download, URL, Profile | Profile, DB/Table/Row ID |
| Media | 이미지/영상 | EXIF, GPS, Thumbnail, Codec, Duration, 삭제 상태 | File 경로, Metadata Tag/Offset |

Analyzer는 특정 조사 결론을 생성하지 않는다. 관찰한 Fact와 제한된 정규화 결과만 생성한다.
Email과 Messenger는 MVP가 아니며 별도 Plugin Analyzer로만 추가한다.

## 6. Timeline Engine

Timeline Builder는 등록된 `TimelineProjector`를 Artifact Type별로 실행한다.

```text
Artifact/File -> Projector -> normalized event -> deduplicate -> persist/index
```

필수 필드:

- `timestamp_utc`, `timestamp_raw`, `timezone_offset_minutes`
- `event_type`, `source_kind`, `source_id`
- `title`, `description`, `actor`, `path`
- `evidence_id`, `confidence`, `dedup_key`

시간 해석이 불가능하면 Artifact는 유지하되 Timeline에 억지로 삽입하지 않고 Warning을 남긴다.

## 7. Search Engine

| 검색 유형 | 1차 구현 | 동작 |
| --- | --- | --- |
| Keyword | SQLite FTS5 | Token 기반 순위와 Highlight |
| Exact | 정규화 컬럼/Index | Hash, 경로, Event ID 등 정확 일치 |
| Regex | 후보 축소 후 제한된 Regex 실행 | Timeout, 최대 Scan 크기 적용 |
| Filter | SQL 조건 | Evidence, Artifact Type, 날짜, 경로 |

외부 Index가 도입되더라도 `SearchQuery`와 `SearchHit` 계약은 바꾸지 않는다. Regex를 모든
Evidence Byte에 무제한 적용하지 않으며, Scope와 Resource Limit을 필수로 둔다.

원본 Unicode Text/경로는 수정하지 않는다. 검색용 사본은 Versioned Normalization Profile로
NFKC/Case Folding을 적용하고, 한국어 Tokenizer/Trigram 전략은 한글 Fixture Benchmark로
결정한다. Context/Report가 참조한 Hit에는 안정적인 `search_result_id`를 부여한다.

## 8. Job Orchestrator

| 구성 요소 | 역할 |
| --- | --- |
| Scheduler | 우선순위, 의존성, Case별 동시성 정책 |
| Task Planner | Job을 재시도 가능한 Task/Batch로 분할 |
| Worker Pool | CPU와 I/O 작업 분리 실행 |
| Result Writer | Case별 단일 Writer로 Batch 저장 |
| Progress Aggregator | 처리/전체 단위, Byte, 대상 수 집계 |
| Cancellation | 취소 Token 전달과 Batch 경계 확인 |
| Recovery | Checkpoint에서 재개, 고아 `RUNNING` 작업 복구 |

## 9. API Interface

API는 Application Command/Query를 Transport-neutral Interface로 먼저 정의한다. HTTP Adapter는
그 위에 `/api/v1`을 제공한다. 향후 CLI, Desktop UI, MCP Adapter는 같은 Application 계약을
사용하며 Analyzer를 직접 호출하지 않는다.

## 10. AI Layer

AI Layer에 허용되는 계약은 다음 세 가지다.

| 계약 | 목적 |
| --- | --- |
| `AnalysisContext` | 선택한 File/Artifact/Timeline/Search Result와 Citation 묶음 |
| `AIEnrichmentPort.enrich` | 공급자 비종속 비동기 보강 요청 |
| `EnrichmentResult` | Summary, Finding, Citation, 제한/오류 반환 |

AI Layer에는 Provider 선택, Credential, Prompt Template, Agent Loop를 구현하지 않는다. 외부
구현체가 반환한 결과도 별도 `ai_enrichments` 영역에 저장하며 `artifacts`를 Update하지 않는다.

AI 결과 Item은 다음 Type을 혼합하지 않는다.

| Type | 작성 주체 | 의미 | 원본 Fact 변경 가능 여부 |
| --- | --- | --- | --- |
| Observed Fact | Engine Analyzer | 직접 추출된 사실의 인용 | 불가 |
| Analyst Annotation | 사람 | 분석자의 설명/판단 | Artifact와 분리 |
| AI Inference | 외부 AI Adapter | Citation 기반 추론 | 불가 |
| AI Recommendation | 외부 AI Adapter | 추가 분석/대응 제안 | 불가 |

## 11. Context Service

| 구성 요소 | 책임 |
| --- | --- |
| UI Context Validator | 화면, 선택 ID, Filter, 시간 범위, Locale/Timezone DTO 검증 |
| Session Context Port | Backend Session Store의 Revision 기반 읽기/쓰기 계약 |
| Snapshot Service | Audit/AI/Report용 Canonical JSON과 Hash 생성 |
| Analysis Context Builder | 기존 DB 결과 Resolve, Citation 생성, 같은 Case 소속 검증 |

Live UI Context는 가변 Session Data이며 Case DB Repository의 책임이 아니다. Snapshot은 생성 후
Update하지 않는다. MCP Adapter는 Context Service 내부가 아니라 공개 API를 통해 결과를 읽는다.

## 12. Annotation과 Tag

Annotation/Tag Service는 Target Type과 ID가 현재 Case에 존재하는지 검증한다. Annotation은
Analyst의 작성물이며 Analyzer가 추출한 Artifact와 동일 Table에 저장하지 않는다. Tag는 File,
Artifact, Timeline, Search Result 등 여러 종류를 연결하되 Report에 사용된 연결은 Version별로
고정한다.

## 13. Report Module

| 구성 요소 | 책임 |
| --- | --- |
| Template Manager | `ko-KR` 기본 Section/Resource Key와 Template Version 관리 |
| Evidence/Finding/Timeline Selector | Case 소속과 Citation 가능 여부 검증 |
| `ReportDraftPort` | 외부 AI Draft Adapter에 Analysis Context를 전달하는 계약 |
| Review Manager | Section별 검토/변경 요청과 사람 Identity 기록 |
| Approval Manager | 상태 전이, Version/Hash 고정, AI 자동 승인 차단 |
| Exporter | 승인된 동일 Version을 PDF/HTML로 Render하고 Hash 기록 |

Report Domain은 LLM/MCP SDK를 Import하지 않는다. Draft Adapter 실패는 Report를 `FAILED`로
표시할 수 있지만 기존 Analysis Result나 Context Snapshot을 수정하지 않는다.

## 14. Localization

Engine은 Error Code, `message_key`, Artifact `display_name_key`와 `description_key`를 반환한다.
한국어 실제 문구는 Frontend Resource Bundle이 소유한다. Report Template은 Locale별 Resource를
사용한다. Timestamp의 정본은 UTC/원본 값이며 `Asia/Seoul` 변환은 GUI/Report 표시 단계에서
수행한다.

## Native Analysis Adapter 책임

Native Analysis Adapter는 외부 Native Library와 APEX Domain 사이의 경계를 담당한다.

### 담당 책임

- Native Library 호출
- Native 결과를 APEX Domain DTO로 변환
- 지원 기능 및 Capability 확인
- Native 오류를 Engine 오류 코드로 변환
- File Handle 및 Native Resource 정리
- Process 및 Thread 안전성 격리
- 취소 요청 및 Progress 전달
- Native Library 이름과 버전 기록

### 담당하지 않는 책임

- Case 정책
- Artifact 의미 해석
- AI 판단
- GUI 표시
- MCP Tool 정의
- Report 문장 생성
- 사용자 권한 및 Billing

Domain 및 Application Module은 구체적인 Native Library가 아니라 Port에만 의존한다.
