# API Interface 설계

## 1. 계약 원칙

APEX는 Application Service Interface를 기준 계약으로 삼고 HTTP는 첫 번째 Adapter로 제공한다.
향후 Desktop UI, CLI, MCP Adapter는 같은 Command/Query와 JSON Schema를 사용한다.

| 항목 | 규칙 |
| --- | --- |
| Base Path | `/api/v1` |
| Content Type | `application/json` |
| 시간 | UTC RFC 3339, 예: `2026-07-13T12:34:56Z` |
| ID | UUID 문자열 |
| Pagination | 불투명 Cursor, 기본 100, 최대 1,000 |
| 장시간 작업 | `202 Accepted` + `Job` |
| 중복 방지 | Command에 선택적 `Idempotency-Key` Header |
| 상관관계 | `X-Request-ID`, 없으면 Server 생성 |
| Schema | 응답의 `schema_version`, 공개 JSON Schema URI |
| 오류 | 안정적 `code`/`message_key`, 진단용 `developer_message`, 구조화 `details` |
| Locale | Case 기본 `ko-KR`, 전송 시 BCP 47 문자열 |
| Timezone | 저장/전송은 UTC, 표시 기준은 Case `Asia/Seoul` 기본값 |

Evidence 원본 내용과 Host 절대 경로는 권한이 없는 Client에 그대로 노출하지 않는다. 파일
Content 조회는 별도 권한과 Byte Range 제한을 적용한다.

Engine 오류는 번역된 문장을 계약으로 사용하지 않는다. `code`와 `message_key`는 언어
중립적이며 Frontend Resource Bundle이 한국어 메시지를 표시한다. `developer_message`는 운영
진단용 선택 정보로 사용자 표시 문구가 아니다.

## 2. 공통 응답

성공:

```json
{
  "schema_version": "1.0.0",
  "request_id": "4f49c228-d61e-45af-8653-2a73095aa3a8",
  "data": {},
  "page": null,
  "warnings": []
}
```

실패:

```json
{
  "schema_version": "1.0.0",
  "request_id": "4f49c228-d61e-45af-8653-2a73095aa3a8",
  "errors": [
    {
      "code": "CAPABILITY_UNAVAILABLE",
      "message_key": "error.evidence.capability_unavailable",
      "developer_message": "The reader does not expose deleted entries.",
      "target": "include_deleted",
      "retryable": false,
      "details": {
        "required_capability": "DELETED_FILES"
      }
    }
  ]
}
```

## 3. Case API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `POST` | `/cases` | Case 생성 | `201 Case` |
| `GET` | `/cases` | Case 목록 | `200 Case[]` |
| `GET` | `/cases/{case_id}` | Case 상세 | `200 Case` |
| `PATCH` | `/cases/{case_id}` | 이름/설명/상태 변경 | `200 Case` |
| `GET` | `/cases/{case_id}/capabilities` | 현재 Adapter/Analyzer 기능 | `200 Capability[]` |

Case 생성 요청:

```json
{
  "name": "INC-2026-0713",
  "description": "Endpoint triage",
  "locale": "ko-KR",
  "timezone": "Asia/Seoul"
}
```

Case 삭제는 기본 API 범위에 없다. 증거 및 감사 기록 폐기는 별도 관리 정책이 필요하다.

## 4. Evidence API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `POST` | `/cases/{case_id}/evidence` | Evidence 등록/Probe | `201 Evidence` |
| `GET` | `/cases/{case_id}/evidence` | Evidence 목록 | `200 Evidence[]` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}` | Metadata/Capability/Hash | `200 Evidence` |
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/hash-jobs` | Hash 작업 | `202 Job` |
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/ingest-jobs` | Ingest Pipeline | `202 Job` |

등록 요청:

```json
{
  "display_name": "Laptop image",
  "source_uri": "file:///evidence/laptop.E01",
  "format_hint": "E01",
  "acquired_at": "2026-07-13T01:15:00Z",
  "metadata": {
    "examiner_reference": "ITEM-001"
  }
}
```

Ingest 요청:

```json
{
  "stages": ["FILESYSTEM", "ARTIFACTS", "TIMELINE", "INDEX"],
  "analyzers": [
    "windows.registry",
    "windows.eventlog",
    "windows.prefetch"
  ],
  "options": {
    "include_deleted": true,
    "file_hashing": "ON_DEMAND"
  }
}
```

Server는 지원 Capability를 검증한 후 Job을 만든다. 일부 옵션만 미지원일 경우 명시적 거부
또는 Client가 허용한 경우에만 Warning과 함께 축소 실행한다.

## 5. Job API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `GET` | `/cases/{case_id}/jobs` | 상태/종류별 목록 | `200 Job[]` |
| `GET` | `/cases/{case_id}/jobs/{job_id}` | 진행률/Task 요약 | `200 Job` |
| `POST` | `/cases/{case_id}/jobs/{job_id}/cancel` | 협력적 취소 요청 | `202 Job` |
| `POST` | `/cases/{case_id}/jobs/{job_id}/retry` | 실패 Task 재시도 | `202 Job` |
| `GET` | `/cases/{case_id}/jobs/{job_id}/events` | 진행 Event Stream | `200 text/event-stream` |

`SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED`은 종료 상태다. `PARTIAL`은 일부 결과가 유효하며
`warnings`와 실패 Task를 반드시 확인해야 함을 뜻한다.

## 6. File System API

| Method | Path | Query | 성공 |
| --- | --- | --- | --- |
| `GET` | `/cases/{case_id}/files` | `evidence_id`, `parent_id`, `deleted`, `mime`, `cursor`, `limit` | `200 File[]` |
| `GET` | `/cases/{case_id}/files/{file_id}` | 없음 | `200 File` |
| `GET` | `/cases/{case_id}/files/{file_id}/children` | `cursor`, `limit` | `200 File[]` |
| `GET` | `/cases/{case_id}/files/{file_id}/content` | HTTP `Range` | `206 application/octet-stream` |
| `POST` | `/cases/{case_id}/files/{file_id}/hash-jobs` | 알고리즘 | `202 Job` |

Directory Tree는 전체 Tree를 한 번에 반환하지 않는다. Root 또는 `parent_id`의 직접 자식만
Cursor로 조회한다. `content`는 기본 최대 Range와 총 추출량 제한을 두고 Audit Event를 남긴다.

## 7. Artifact API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `GET` | `/cases/{case_id}/artifact-types` | 활성 Type/Schema 목록 | `200 ArtifactType[]` |
| `GET` | `/cases/{case_id}/artifacts` | Type/Evidence/Source/시간 Filter | `200 Artifact[]` |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}` | Payload와 Provenance | `200 Artifact` |
| `POST` | `/cases/{case_id}/artifact-jobs` | Analyzer 선택 실행 | `202 Job` |

조회 예:

```http
GET /api/v1/cases/{case_id}/artifacts?artifact_type=windows.eventlog.record&evidence_id={evidence_id}&limit=100
```

## 8. Timeline API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `GET` | `/cases/{case_id}/timeline` | 기간/Type/Evidence/Actor/Path Filter | `200 TimelineEvent[]` |
| `POST` | `/cases/{case_id}/timeline-jobs` | Projection 재생성 | `202 Job` |

Timeline 정렬은 `(timestamp_utc ASC, id ASC)`이며 Cursor가 마지막 Tuple을 암호화/서명된
불투명 값으로 보존한다.

## 9. Search API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `POST` | `/cases/{case_id}/search` | Keyword/Exact/Regex 검색 | `200 SearchResult` 또는 `202 Job` |
| `GET` | `/cases/{case_id}/search-jobs/{job_id}/results` | 비동기 검색 결과 | `200 SearchResult` |
| `GET` | `/cases/{case_id}/search-results` | Context/Report용 고정 결과 목록 | `200 SearchHit[]` |
| `GET` | `/cases/{case_id}/search-results/{search_result_id}` | 고정 Query/Hit와 Source | `200 SearchHit` |
| `POST` | `/cases/{case_id}/index-jobs` | 전체/증분 재색인 | `202 Job` |

검색 요청:

```json
{
  "mode": "KEYWORD",
  "query": "powershell download",
  "scope": ["ARTIFACT", "TIMELINE"],
  "filters": {
    "evidence_ids": [],
    "artifact_types": ["windows.eventlog.record"],
    "time_from": "2026-07-01T00:00:00Z",
    "time_to": "2026-07-14T00:00:00Z"
  },
  "cursor": null,
  "limit": 100
}
```

짧은 Index Query는 동기 `200`을 반환한다. 대규모 Regex/Raw Scan은 `202` Job으로 전환한다.
Regex 요청에는 Server 측 Timeout, 최대 후보 수, Pattern 길이 제한을 적용한다.

검색 입력은 UTF-8로 받으며 원본 Query를 보존한다. Index Adapter가 정의한 Versioned
Normalization Profile로 검색 사본을 생성한다. 한글 완성형/자모/영문 혼합 결과는 Profile별
Contract Test로 검증한다. Context나 Report에서 선택한 Hit는 안정적 `search_result_id`로
고정한다.

## 10. GUI Context와 Analysis Context API

Live UI Context Endpoint는 APEX Backend의 Session Store가 구현한다. Forensic Engine은 해당
DTO와 Snapshot/Analysis Bundle Application Interface를 제공하며 GUI Framework 객체를 직접
받지 않는다.

| Method | Path | 동작 | 성공/Schema |
| --- | --- | --- | --- |
| `PUT` | `/sessions/{session_id}/ui-context` | 현재 화면/선택/필터 원자적 갱신 | `200 ui-context` |
| `GET` | `/sessions/{session_id}/ui-context` | Live Context 조회 | `200 ui-context` |
| `POST` | `/cases/{case_id}/context-snapshots` | `UI` 또는 `ANALYSIS` 불변 Snapshot 생성 | `201 ui-context/analysis-context` |
| `GET` | `/cases/{case_id}/context-snapshots/{snapshot_id}` | Snapshot 종류와 Hash 조회 | `200 ui-context/analysis-context` |
| `GET` | `/cases/{case_id}/analysis-bundle` | Snapshot ID로 Resolve된 전달 Bundle 조회 | `200 analysis-context` |

`PUT`은 `If-Match: {revision}`을 받아 다른 GUI Update를 덮어쓰지 않는다. Live Context는 Session
만료 시 폐기한다. Snapshot 생성 요청은 `reason`, `purpose`, `ui_context_revision`을 받고 선택된
모든 ID가 같은 Case에 존재하는지 검증한 후 Citation과 `content_sha256`을 생성한다.

Analysis Bundle은 다음을 포함할 수 있다.

- 현재 Case/Evidence, 화면, 선택 파일/Artifact/Timeline/Search Result
- 현재 검색 조건, Filter, 날짜/시간 범위, Locale/Timezone
- Analyst Annotation, Tag, 기존 Analysis Result와 AI Enrichment
- Report 포함 후보와 실제 Source Citation

MCP Adapter는 이 API만 사용해 이미 완료된 GUI 분석 결과를 읽는다. Evidence 재분석은 별도의
명시적 Job 요청이 없는 한 발생하지 않는다.

## 11. Annotation과 Tag API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `POST` | `/cases/{case_id}/annotations` | 대상에 분석자 Annotation 추가 | `201` |
| `GET` | `/cases/{case_id}/annotations` | 대상/작성자별 조회 | `200` |
| `PATCH` | `/cases/{case_id}/annotations/{annotation_id}` | Annotation 수정 | `200` |
| `POST` | `/cases/{case_id}/tags` | Case Tag 생성 | `201` |
| `GET` | `/cases/{case_id}/tags` | Tag 목록 | `200` |
| `PUT` | `/cases/{case_id}/tags/{tag_id}/items/{target_type}/{target_id}` | Tag 지정 | `204` |
| `DELETE` | `/cases/{case_id}/tags/{tag_id}/items/{target_type}/{target_id}` | Tag 해제 | `204` |

Annotation은 사람이 작성한 내용으로 `ANALYST_ANNOTATION`으로 표시한다. AI 결과나 Engine
Artifact로 저장하지 않는다.

## 12. Report API

| Method | Path | 동작 | 성공/Schema |
| --- | --- | --- | --- |
| `POST` | `/cases/{case_id}/reports` | 선택 항목으로 Report 생성 | `201 report` |
| `GET` | `/cases/{case_id}/reports` | 상태별 Report 목록 | `200 report[]` |
| `GET` | `/cases/{case_id}/reports/{report_id}` | Section/Citation/Export 조회 | `200 report` |
| `PATCH` | `/cases/{case_id}/reports/{report_id}` | Draft Section/선택 수정 | `200 report` |
| `POST` | `/cases/{case_id}/reports/{report_id}/generate-draft` | AI Draft Port용 Job 생성 | `202 Job` |
| `POST` | `/cases/{case_id}/reports/{report_id}/request-review` | `REVIEW_REQUIRED` 전환 | `200 report` |
| `POST` | `/cases/{case_id}/reports/{report_id}/approve` | 분석자 승인 및 Hash 고정 | `200 report` |
| `POST` | `/cases/{case_id}/reports/{report_id}/reject` | 사유와 함께 반려 | `200 report` |
| `POST` | `/cases/{case_id}/reports/{report_id}/export` | 승인 Version PDF/HTML Job | `202 Job` |
| `GET` | `/cases/{case_id}/reports/{report_id}/exports` | Export 상태/Hash 목록 | `200 reportExport[]` |

생성 Workflow:

```text
DRAFT -> GENERATING -> REVIEW_REQUIRED -> APPROVED -> EXPORTING -> EXPORTED
                         |                  |
                         -> REJECTED        -> FAILED
```

`generate-draft`는 `ReportDraftPort`에 검증된 Analysis Context를 전달할 준비만 한다. Engine은
LLM을 호출하지 않는다. `approve`는 `expected_version`, `expected_content_sha256`, Analyst
Identity를 요구한다. AI/시스템 Identity는 승인자로 허용하지 않는다. `export`는 승인된 동일
Version만 허용하며 Format은 `PDF` 또는 `HTML`이다.

## 13. 선택적 AI Layer Interface

AI Layer는 별도 Component/Feature Flag로 노출한다. APEX 제품의 Built-in MCP Adapter가 이
Port를 연결할 수 있지만 Engine API 자체는 Provider를 알지 않는다.

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `POST` | `/enrichments` | `analysis-context` 기반 보강 요청 | `202` |
| `GET` | `/enrichments/{id}` | 구분된 AI 결과와 Citation 조회 | `200` |

결과는 `observed_facts`, `analyst_annotations`, `inferences`, `recommendations`, `citations`,
`confidence`, `limitations`을 구분한다. `output_locale`은 Case Locale을 기본으로 한다. Provider,
모델, Prompt, Credential 필드를 공개 Core 계약에 포함하지 않는다. Adapter 부재 시
`501 AI_ADAPTER_UNAVAILABLE`을 반환한다.

## 14. Schema와 운영 API

| Method | Path | 동작 | 성공 |
| --- | --- | --- | --- |
| `GET` | `/schemas/v1` | Schema 목록 | `200` |
| `GET` | `/schemas/v1/{name}.schema.json` | JSON Schema | `200 application/schema+json` |
| `GET` | `/health/live` | Process 생존 | `200` |
| `GET` | `/health/ready` | DB/Writer/Worker 준비 | `200` 또는 `503` |
| `GET` | `/api/v1/system/capabilities` | 설치된 Reader/Analyzer/Index | `200` |

Health 응답에 Evidence 경로, Case 이름, Credential 등 민감정보를 포함하지 않는다.

## 15. 오류 코드

| HTTP | 코드 | 의미 |
| --- | --- | --- |
| `400` | `VALIDATION_ERROR` | DTO/Schema/Query 오류 |
| `404` | `CASE_NOT_FOUND`, `EVIDENCE_NOT_FOUND`, `OBJECT_NOT_FOUND` | 대상 없음 |
| `409` | `STATE_CONFLICT`, `IDEMPOTENCY_CONFLICT` | 상태/중복 충돌 |
| `409` | `CONTEXT_REVISION_CONFLICT`, `REPORT_NOT_APPROVED` | Context/Report 상태 충돌 |
| `413` | `RESOURCE_LIMIT_EXCEEDED` | Range/검색/업로드 제한 |
| `422` | `UNSUPPORTED_EVIDENCE_FORMAT` | 판별됐으나 지원하지 않음 |
| `423` | `CASE_WRITE_LOCKED` | Case Writer/관리 잠금 |
| `429` | `WORK_QUEUE_FULL` | Backpressure로 수락 불가 |
| `500` | `INTERNAL_ERROR` | 예상하지 못한 오류, 상세 내부 은닉 |
| `501` | `CAPABILITY_UNAVAILABLE`, `AI_ADAPTER_UNAVAILABLE` | 기능/Adapter 미설치 |
| `503` | `SERVICE_NOT_READY` | DB/Worker 준비 실패 |

## 16. API와 Schema 대응

| API 영역 | JSON Schema |
| --- | --- |
| 공통 응답/오류 | `api-response.schema.json`, `common.schema.json` |
| Case | `case.schema.json` |
| Evidence/File/Artifact/Timeline/Search/Job | 각 동명 Schema |
| GUI Context | `ui-context.schema.json` |
| Analysis Bundle/Snapshot | `analysis-context.schema.json` |
| AI 근거 | `citation.schema.json` |
| AI Enrichment | `ai-enrichment.schema.json` |
| Annotation/Tag | `analysis-context.schema.json`의 공용 `$defs` |
| Report/Section/Export | `report.schema.json`의 `$defs` |

## 17. 호환성 정책

- `/api/v1` 안에서는 필드 추가만 허용하고 기존 필드의 의미/타입을 변경하지 않는다.
- 필수 필드 추가, Enum 제거, 타입 변경은 `/api/v2` 대상이다.
- Artifact Payload는 `artifact_type + schema_version`으로 독립 Versioning한다.
- Client는 모르는 선택 필드를 무시하되, Schema 검증기는 해당 버전에 맞춰 검증한다.
- API Contract Test는 예시 응답이 `schemas/v1`을 통과하는지 확인한다.
