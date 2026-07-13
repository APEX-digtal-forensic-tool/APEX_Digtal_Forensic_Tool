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

## 3. 공통 규칙

1. `schema_version`은 Semantic Version 문자열이며 API Envelope에 항상 포함한다.
2. ID는 UUID, 시간은 UTC RFC 3339 `date-time`, Hash는 소문자 Hex로 표현한다.
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
