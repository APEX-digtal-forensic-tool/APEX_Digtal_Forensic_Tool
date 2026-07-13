# JSON Schema 설계

## 1. 목적

`schemas/v1`은 API Client, Desktop UI, 향후 MCP Adapter와 선택적 AI Adapter가 APEX 결과를
추측 없이 해석하도록 하는 기계 판독 계약이다. JSON Schema Draft 2020-12를 사용한다.

## 2. Schema 목록

| 파일 | Root 정의 | 용도 |
| --- | --- | --- |
| `common.schema.json` | Error, Citation, PageInfo 등 | 공통 값 |
| `api-response.schema.json` | SuccessResponse, ErrorResponse | 공통 HTTP Envelope |
| `case.schema.json` | Case | Case 응답 |
| `evidence.schema.json` | Evidence, EvidenceHash | 등록/무결성 결과 |
| `file.schema.json` | FileEntry | Lazy File Tree |
| `artifact.schema.json` | Artifact | 정규화 Fact와 Provenance |
| `timeline-event.schema.json` | TimelineEvent | 통합 시간 이벤트 |
| `search.schema.json` | SearchQuery, SearchHit, SearchResult | 검색 입력/출력 |
| `job.schema.json` | Job, JobError | 비동기 작업 상태 |
| `ai-enrichment.schema.json` | AnalysisBundle, EnrichmentResult | Provider-neutral 선택 경계 |

## 3. 공통 규칙

1. `schema_version`은 Semantic Version 문자열이며 API Envelope에 항상 포함한다.
2. ID는 UUID, 시간은 UTC RFC 3339 `date-time`, Hash는 소문자 Hex로 표현한다.
3. 큰 정수 Offset/Size는 JSON 정수로 정의한다. JavaScript Client는 Safe Integer 검사를 한다.
4. Enum은 안정적 대문자 `SNAKE_CASE`를 사용한다.
5. 알 수 없음과 값 없음은 `null`로 명시하며 빈 문자열로 대체하지 않는다.
6. Artifact `payload`는 Type별 Schema가 검증한다. 공통 Schema는 Object임을 보장한다.
7. Provenance/Citation에는 최소 `evidence_id`, `source_kind`, `source_id`가 포함된다.
8. Binary Data는 Base64 Payload가 아니라 Content API 또는 Cache Reference로 전달한다.

## 4. Canonical JSON

Hash/Fingerprint/Audit Chain을 계산할 때는 다음 정규화를 사용한다.

- UTF-8
- Object Key 사전순
- 불필요한 공백 없음
- 숫자의 결정적 직렬화
- Unicode 문자열은 의미를 바꾸는 임의 정규화를 하지 않음
- Hash 대상에서 전송 전용 `request_id` 등 비결정 필드를 제외

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

## 6. AI 결과 분리

`ai-enrichment.schema.json`은 Provider-neutral 결과 교환용일 뿐 Core Fact Schema가 아니다.
`EnrichmentResult.findings[].citations`가 원본 Artifact/Timeline/Search Hit를 참조해야 하며,
AI 요약이나 추론은 `artifacts.payload`를 변경할 수 없다.

## 7. 검증 Gate

구현 CI는 다음을 실패 조건으로 둔다.

- 모든 Schema JSON Parsing 실패
- 해결되지 않는 로컬 `$ref`
- API Fixture의 Schema 불일치
- 같은 Version에서 호환성을 깨는 필수 필드/타입 변경
- Artifact Payload가 등록된 Type Schema와 불일치
