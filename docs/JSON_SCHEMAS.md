# JSON Schema 설계

## 1. 목적

`schemas/v1`은 API Client, Desktop UI, 향후 MCP Adapter와 선택적 AI Adapter가 APEX 결과를
추측 없이 해석하도록 하는 기계 판독 계약이다. JSON Schema Draft 2020-12를 사용한다.

## 2. Schema 목록

| 파일 | Root 정의 | 용도 |
| --- | --- | --- |
| `common.schema.json` | Error, Locale, ResourceKey, PageInfo 등 | 공통 값 |
| `api-response.schema.json` | SuccessResponse, ErrorResponse | 공통 HTTP Envelope |
| `case.schema.json` | Case | Case 응답 |
| `ui-context.schema.json` | UIContext | GUI Session 화면/선택/Filter |
| `analysis-context.schema.json` | AnalysisContext | MCP/AI/Report용 불변 Result Bundle |
| `citation.schema.json` | Citation | Evidence부터 Search Result까지 원본 Locator |
| `report.schema.json` | Report, ReportSection, ReportExport | Draft/Review/Approval/Export |
| `evidence.schema.json` | Evidence, EvidenceHash | 등록/무결성 결과 |
| `file.schema.json` | FileEntry | Lazy File Tree |
| `artifact.schema.json` | Artifact | 정규화 Fact와 Provenance |
| `timeline-event.schema.json` | TimelineEvent | 통합 시간 이벤트 |
| `search.schema.json` | SearchQuery, SearchHit, SearchResult | 검색 입력/출력 |
| `job.schema.json` | Job, JobError | 비동기 작업 상태 |
| `ai-enrichment.schema.json` | EnrichmentRequest, EnrichmentResult | Provider-neutral 선택 경계 |

| `analysis-profile.schema.json` | AnalysisProfile | Quick/Selected/Full/Custom Profile |
| `keyword-recommendation.schema.json` | KeywordCandidate, KeywordSet, KeywordApproval | AI/수동 Keyword 검토와 Set Version |
| `chain-of-custody.schema.json` | CustodyEvent, HashVerification, CustodySnapshot, CustodyApproval | Append-only Evidence Custody Ledger |
| `machine-extraction.schema.json` | MachineExtraction, ExtractionReview | 기존 Machine Extraction 계약 |
| `browser-profile.schema.json` | BrowserProfile | Browser Profile 후보와 Source Revision / Locator |
| `browser-artifact.schema.json` | BrowserArtifact | Browser History / Search / Download Projection |
| `media-artifact.schema.json` | MediaArtifact | Image / Video / Audio Metadata Projection |
| `machine-extracted-candidate.schema.json` | MachineExtractedCandidate, CandidateReviewEvent | Phase 5 OCR/STT Candidate와 Review 이력 |
| `provider-capability.schema.json` | ProviderCapability | Optional OCR/STT / ffprobe / ffmpeg Capability 상태 |
| `thumbnail.schema.json` | ThumbnailRecord | Hash 검증 가능한 Thumbnail Derivative Metadata |

## 3. 공통 규칙

1. `schema_version`은 Semantic Version 문자열이며 API Envelope에 항상 포함한다.
2. ID는 UUID, 시간은 UTC RFC 3339 `date-time`, Hash는 소문자 Hex로 표현한다.
   Phase 1 실행 구현은 MD5, SHA-1, SHA-256을 지원한다.
3. 큰 정수 Offset/Size는 JSON 정수로 정의한다. JavaScript Client는 Safe Integer 검사를 한다.
4. Enum은 안정적 대문자 `SNAKE_CASE`를 사용한다.
5. 알 수 없음과 값 없음은 `null`로 명시하며 빈 문자열로 대체하지 않는다.
6. Artifact `payload`는 Type별 Schema가 검증한다. 공통 Schema는 Object임을 보장한다.
7. Provenance/Citation에는 최소 `evidence_id`, `source_kind`, `source_id`가 포함된다.
8. Binary Data는 Base64 Payload가 아니라 Content API 또는 Cache Reference로 전달한다.
9. 기본 Locale은 `ko-KR`, 기본 Timezone은 `Asia/Seoul`이며 Case에서 명시한다.
10. Error/Warning은 번역 문장 대신 안정적인 `code`와 `message_key`를 반환한다.
11. 원본 경로/Text와 검색 정규화 사본을 구분하고 Schema에는 원본 표시 값을 전달한다.

## 4. Canonical JSON

Hash/Fingerprint/Audit Chain을 계산할 때는 다음 정규화를 사용한다.

- UTF-8
- Object Key 사전순
- 불필요한 공백 없음
- 숫자의 결정적 직렬화
- Unicode 문자열은 의미를 바꾸는 임의 정규화를 하지 않음
- Hash 대상에서 전송 전용 `request_id` 등 비결정 필드를 제외

`AnalysisContext.content_sha256`은 해당 필드 자체를 제외한 Context Projection을 Hash한다.
`Report.approved_content_sha256`은 승인 대상 Version의 Section, 선택 Link, Citation, Locale,
Timezone과 Template Version을 Hash하며 승인/Export 시각, Export 목록과 Hash 필드 자체는
제외한다. 이 제외 규칙도 Canonicalization Profile Version에 포함한다.

구현 단계에서는 RFC 8785 JSON Canonicalization Scheme 적용 가능성을 검증한다.

## 5. Artifact Type 확장

새 Analyzer는 다음을 함께 제공해야 한다.

1. 안정적인 `artifact_type`
2. Payload JSON Schema와 Version
3. Timeline Projector 여부
4. Search Document Mapper
5. 실제/손상 Fixture 기반 Contract Test

Phase 5는 Browser, Media, Thumbnail, Provider Capability, Machine-extracted Candidate를 별도
Schema로 분리한다. 이 Schema들은 Raw Timestamp / UTC / Case Time을 구분하고, Source Revision과
Provider Version을 요구하며, Unsupported Capability를 성공 결과처럼 표현하지 않는다. 기존
`artifact.schema.json`과 `timeline-event.schema.json`은 `MEDIA_AUDIO`, `AUDIO_FILE`, Browser
Download/Media Metadata Timeline Event를 포함하도록 확장한다.

예를 들어 `windows.eventlog.record@1.0.0` Payload는 Event ID, Provider, Channel, Record ID,
Computer, Event Data를 정의하며 공통 `Artifact`의 `payload`에 들어간다.

## 6. Context와 Citation

`ui-context`는 Session에서 갱신되는 가변 상태이며 `revision`과 만료 시각을 가진다.
`analysis-context`는 기존 분석 결과 ID를 Resolve하고 Citation과 Content Hash를 고정한 불변
Bundle이다. 두 Schema를 합치지 않는 이유는 Live GUI 상태를 Audit 보존 대상으로 오해하지
않고, MCP/AI/Report 입력의 재현성을 보장하기 위해서다.

`citation`은 공통 `source_kind/source_id`와 함께 `evidence_id`, `file_id`, `artifact_id`,
`timeline_event_id`, `search_result_id`, 경로, Offset/Reference, Excerpt, Content Hash를 명시한다.
존재하지 않거나 다른 Case의 Source를 가리키는 Citation은 Application Validation에서 거부한다.

## 7. AI 결과 분리

`ai-enrichment.schema.json`은 Provider-neutral 결과 교환용일 뿐 Core Fact Schema가 아니다.
`observed_facts`, `analyst_annotations`, `inferences`, `recommendations`을 별도 배열로 구분한다.
Inference와 Recommendation은 Citation, Confidence/우선순위, Limitation을 포함하며 AI 요약이나
추론은 `artifacts.payload`를 변경할 수 없다. Provider/모델/Prompt/Credential 필드는 없다.

## 8. Report

`report.schema.json` 하나가 Report Aggregate와 `$defs/reportSection`, `$defs/reportExport`를
정의한다. 별도 파일로 나누지 않아 Report Version/Status/Locale/Citation 계약이 흩어지는 것을
막는다. `APPROVED` Version의 Canonical Hash가 Export 대상 Version과 일치해야 한다는 상태
규칙은 Domain과 API Contract Test가 검증한다.

## 9. 검증 Gate

구현 CI는 다음을 실패 조건으로 둔다.

- 모든 Schema JSON Parsing 실패
- 해결되지 않는 로컬 `$ref`
- API Fixture의 Schema 불일치
- 같은 Version에서 호환성을 깨는 필수 필드/타입 변경
- Artifact Payload가 등록된 Type Schema와 불일치
- Schema 파일 간 순환 `$ref`
- API Resource에 대응하는 Schema 누락
- Context/AI/Report Citation의 다른 Case Source 참조

## 10. 기존 Schema 확장 결정

요구사항과 역할이 겹치는 구조는 새 파일을 만들지 않았다.

| 요구사항 | 확장 Schema | 이유 |
|---|---|---|
| Timestamp/Timezone | `common.schema.json` | 모든 File/Artifact/Timeline/Report가 공유 |
| Case Timezone 후보/Decision | `case.schema.json` | Case 설정 Aggregate |
| Evidence Fingerprint | `evidence.schema.json` | Evidence 중복 분석 방지 Identity |
| File 시간 해석 | `file.schema.json` | 기존 UTC 시간과 구조화 Interpretation 병행 |
| Artifact Raw/시간 Provenance | `artifact.schema.json` | 기존 Artifact Provenance 확장 |
| Progressive Progress/ETA | `job.schema.json` | Job 상태·Checkpoint 계약 확장 |
| Search Options/Execution | `search.schema.json` | 검색 재현 정보가 Search Aggregate 소유 |
| Scope별 Context | `analysis-context.schema.json` | 기존 불변 Context Snapshot 확장 |
| Raw Locator | `citation.schema.json` | Citation과 Byte/Record Locator 연결 |
| AI Partial/Scope/Human Gate | `ai-enrichment.schema.json` | Provider-neutral 결과 경계 유지 |
| Report Provenance/Section | `report.schema.json` | 승인 Version Aggregate 내부 일관성 |
| Simple/Detailed/Raw 상태 | `ui-context.schema.json` | Live GUI 선택 상태 |

## 11. 신규 Schema 분리 근거

`analysis-profile`은 실행 Job과 별개로 Versioned 분석 의도를 소유한다.
`keyword-recommendation`은 AI/분석자 Candidate, Human Review와 Keyword Set 생명주기를
소유한다. `chain-of-custody`는 일반 Audit와 다른 Evidence 중심 Append-only Ledger와 Snapshot을
소유한다. `machine-extraction`은 Artifact Fact가 아닌 Machine Candidate와 Review를 소유한다.
따라서 네 계약은 기존 Schema에 억지로 중첩하지 않고 독립 Aggregate로 분리했다.

모든 신규 Root DTO는 `schema_version=1.0.0`을 포함하며 모든 파일은 Draft 2020-12 `$schema`,
`/v1/` `$id`, 명시적 `required`와 `additionalProperties`를 사용한다. ID는 기존 UUID 규칙,
시간은 RFC 3339, Timezone은 IANA ID를 사용한다.

## 12. Timestamp와 Partial Result

`common.timestampInterpretation`은 다음 필드를 분리한다.

- `raw_timestamp`와 `raw_timezone`
- `normalized_utc`
- `display_timestamp`와 `display_timezone`
- `timezone_source`와 `timezone_confidence`
- `dst_status`와 `ambiguity`

원본 Timestamp는 수정하지 않으며 정규화 실패 시 UTC가 `null`일 수 있다. IANA ID의 실제
유효성은 Regex만으로 확정하지 않고 Runtime tzdb와 Fixture로 검증한다.

`common.partialResult`은 `is_partial`, `as_of`, 완료/대기 Scope, 사용 가능한 Item 수와 Warning을
제공한다. Job, Search, UI Context, Analysis Context와 Report Provenance가 같은 정의를 참조해
전체 Index 완료 전 결과라는 사실을 AI와 사용자에게 전달한다.

## 13. Custody Event Enum

Schema와 문서가 공유하는 Canonical Enum은 다음과 같다.

```text
ACQUISITION
RECEIVED
TRANSFERRED
STORED
OPENED
MOUNTED
ANALYZED
HASH_VERIFIED
COPIED
EXPORTED
RETURNED
RELEASED
ARCHIVED
DISPOSED
CORRECTION
```

`CORRECTION`은 `correction_of_event_id`가 필수다. Event는 `immutable_revision`,
`previous_event_hash`, `event_hash`, `ledger_algorithm`과 `ledger_version`을 가진다. Update나
Delete 계약은 없다.

## 14. Report Section Enum

기존 Section을 유지하고 다음 Section을 추가한다.

```text
INDEXING_SCOPE
TIMEZONE_POLICY
KEYWORD_SEARCH
CHAIN_OF_CUSTODY
HASH_VERIFICATION
MACHINE_EXTRACTION
EXTERNAL_VALIDATION
```

Report Statement는 `OBSERVED_FACT`, `ANALYST_ANNOTATION`,
`MACHINE_EXTRACTED_CANDIDATE`, `AI_INFERENCE`, `AI_RECOMMENDATION` 중 하나로 분류한다.
Candidate와 AI 결과를 Observed Fact로 직렬화하지 않는다.

## 15. Keyword와 Machine Candidate 검증

AI `keywordCandidate`는 `reason`, 하나 이상의 `citations`, `scope`, `confidence`와
`PENDING_REVIEW` 상태를 요구한다. `ANALYST` Candidate는 Confidence가 null일 수 있지만 같은
Keyword Set Version 계약을 사용한다.

`machineExtraction`은 `confidence`, `engine_id`, `engine_version`, `source_locator`,
`citations`와 `analyst_status`를 요구한다. Review 상태는
`UNREVIEWED/ACCEPTED/REJECTED/CORRECTED`이며 Correction은 원 Candidate Text를 변경하지 않는다.

## 16. 검증 Gate 보강

설계 검증은 다음을 실패 조건으로 추가한다.

- Requirement ID 또는 Method+API Path 중복
- API-to-Schema Mapping 누락
- 신규 DB Table의 Module Owner 누락
- Custody Event Enum의 문서/Schema 불일치
- Report Section Enum의 문서/Schema 불일치
- IANA Timezone 정책 문서 누락
- AI Keyword의 Reason/Citation 필수 계약 누락
- Machine Candidate의 Confidence/Review/Locator 누락
- Job/Search/Context의 Partial Result 계약 누락
- Phase 1 범위를 벗어난 `mcp`, `prompts` 또는 MCP/LLM/OCR/STT/PDF 실행 구현 추가
- MCP/LLM/Prompt/OCR/STT/PDF 실행 의존성 추가

Node/Ajv가 없는 환경에서는 Python 기본 검증으로 JSON Syntax, 파일, Markdown Link,
Requirement 중복과 로컬 `$ref` 파일을 검사한다. Node가 있으면 구조/순환 참조 검사를 추가하고,
로컬 Ajv가 설치된 경우에만 Strict Compile을 실행한다. Ajv가 없으면 기본 검증 성공을 유지하고
생략 이유를 출력한다.

## Phase 2 Schema Contracts

Phase 2 extends existing Draft 2020-12 schemas rather than weakening validation.

- `file.schema.json` now accepts legacy `fileEntry`, Phase 2 `fileSystemNode`, and `fileTreePage` contracts.
- `job.schema.json` includes `INDEX`, pause/resume statuses, job revision, index revision, and filesystem progress counters.
- `evidence.schema.json` includes DD and IMG format metadata registration.
- `analysis-profile.schema.json` accepts the Phase 2 `CUSTOM` profile spelling while preserving `CUSTOM_PROFILE` compatibility.

Filesystem nodes explicitly require provider id/version, original path strings, comparison path, node type, metadata, raw timestamp values, UTC-normalized timestamps, raw locator, partial flag, and index revision. Unsupported provider capability is represented as an error response, not as a successful result.

## Phase 3 Schema Contracts

`artifact.schema.json` now defines the concrete Windows, Media, and Browser artifact DTO. It requires
`artifact_id`, `case_id`, `evidence_id`, `source_file_node_id`, artifact type/subtype,
analyzer/backend IDs and versions, raw and UTC observed timestamps, timezone source/confidence,
fields, raw locator, citations, warnings, parse status, confidence, partial flag, index revision,
created/updated timestamps, and dedup key.

Artifact type enum values are:

- `REGISTRY_KEY`
- `REGISTRY_VALUE`
- `REGISTRY_AUTORUN`
- `REGISTRY_USB_DEVICE`
- `REGISTRY_TIMEZONE`
- `REGISTRY_USERASSIST`
- `EVENT_LOG_RECORD`
- `PREFETCH_EXECUTION`
- `MEDIA_IMAGE`
- `MEDIA_VIDEO`
- `BROWSER_PROFILE`
- `BROWSER_VISIT`
- `BROWSER_SEARCH`
- `BROWSER_DOWNLOAD`
- `UNKNOWN_WINDOWS_ARTIFACT`

Parse status enum values are `SUCCESS`, `PARTIAL`, `UNSUPPORTED`, `CORRUPT`, and `FAILED`. Unsupported
binary parser dependencies, Prefetch versions, and MAM compression are not represented as successful
facts.

`citation.schema.json` raw locators now allow logical locators with `offset: null` and `length: null`.
The `locator_type`, `limitations`, and `details` fields make the difference between logical
Registry/Event provenance and actual byte ranges explicit. This prevents non-existent byte offsets
from being fabricated while preserving raw/source references for future raw views.

## Phase 4 Schema Updates

`search.schema.json` now represents:

- Search Document, Search Query, Search Result, Search Execution, Search Cache
- Keyword Set and Keyword version DTOs for manual keyword management
- Search Result Page with cursor page metadata and runtime FTS5 capability state

`timeline-event.schema.json` now represents:

- Timeline Event with raw timestamp/timezone, UTC normalized timestamp, case timezone display,
  timezone source/confidence, precision, source revision, raw locator, citations, and partial flag
- Timestamp Normalization DTO
- Timezone Candidate DTO
- Timeline Page with cursor page metadata

`job.schema.json` accepts `SEARCH_INDEX` jobs. `keyword-recommendation.schema.json` keeps AI
recommendation contracts but its enum set also includes Phase 4 manual keyword status values
`ACTIVE`/`ARCHIVED` and keyword type `OTHER`. All updated schemas remain Draft 2020-12 with explicit
`additionalProperties` and no circular `$ref`.

## 6. Phase 6 Schemas

| 파일 | Root 정의 | 용도 |
| --- | --- | --- |
| `gui-session-context.schema.json` | GuiSessionContext | TTL과 Revision을 가진 Live GUI Context |
| `analysis-context-snapshot.schema.json` | AnalysisContextSnapshot | Append-only 분석 Snapshot과 Fingerprint |
| `analysis-scope-context.schema.json` | AnalysisScopeContext | Scope별 Resource Bundle과 Cursor |
| `context-revision-state.schema.json` | RevisionState | Source Revision, Partial, Stale Reason |
| `view-projection.schema.json` | ViewProjection | Simple/Detailed View Projection |
| `raw-view.schema.json` | RawViewProjection | Raw Locator와 제한 정보 |
| `raw-read-request.schema.json` | RawReadRequest | Bounded Raw Range 입력 |
| `raw-read-response.schema.json` | RawReadResponse | Raw Chunk, EOF, Hash, Audit ID |
| `engine-interface.schema.json` | EngineInterfaceVersion | Adapter용 Engine Version/Limit/Capability |
| `engine-tool-descriptor.schema.json` | EngineToolDescriptor | Public Tool Descriptor와 Limit |

Phase 6 schemas keep object extensibility explicit with `additionalProperties`, reject unbounded binary payload transfer, and carry warning/citation arrays so partial or stale context can be represented without inventing facts.
