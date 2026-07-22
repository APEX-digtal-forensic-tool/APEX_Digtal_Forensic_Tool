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
| Evidence/File/Artifact/Timeline/Search/Job | `evidence.schema.json`, `file.schema.json`, `artifact.schema.json`, `timeline-event.schema.json`, `search.schema.json`, `job.schema.json` |
| GUI Context | `ui-context.schema.json` |
| Analysis Bundle/Snapshot | `analysis-context.schema.json` |
| AI 근거 | `citation.schema.json` |
| AI Enrichment | `ai-enrichment.schema.json` |
| Annotation/Tag | `analysis-context.schema.json`의 공용 `$defs` |
| Report/Section/Export | `report.schema.json`의 `$defs` |

### 확장 API와 Schema 대응

| Analysis Profile | `analysis-profile.schema.json` |
| Progressive Job/Partial Result | `job.schema.json`, `common.schema.json` |
| Timezone Candidate/Decision | `case.schema.json`, `common.schema.json` |
| Keyword Recommendation/Set | `keyword-recommendation.schema.json` |
| Search Execution/Reproduction | `search.schema.json` |
| Chain of Custody | `chain-of-custody.schema.json` |
| Raw Locator/Range | `citation.schema.json` |
| Machine Extraction/Review | `machine-extraction.schema.json` |

## 17. 호환성 정책

- `/api/v1` 안에서는 필드 추가만 허용하고 기존 필드의 의미/타입을 변경하지 않는다.
- 필수 필드 추가, Enum 제거, 타입 변경은 `/api/v2` 대상이다.
- Artifact Payload는 `artifact_type + schema_version`으로 독립 Versioning한다.
- Client는 모르는 선택 필드를 무시하되, Schema 검증기는 해당 버전에 맞춰 검증한다.
- API Contract Test는 예시 응답이 `schemas/v1`을 통과하는지 확인한다.

## 18. Analysis Profile과 Progressive Indexing API

Profile은 분석 의도와 Analyzer 설정의 Versioned 계약이고 Job은 실행 상태다. 기존
`POST /cases/{case_id}/index-jobs`가 Profile 기반 실행 Command를 담당하며 아래 Query와
상태 Command를 추가한다.

| Method | Path | 동작 | 성공/Schema |
|---|---|---|---|
| `POST` | `/cases/{case_id}/analysis-profiles` | Quick/Selected/Full/Custom Profile 생성 | `201 analysis-profile` |
| `GET` | `/cases/{case_id}/analysis-profiles` | Profile 목록과 Revision 조회 | `200 analysis-profile[]` |
| `GET` | `/cases/{case_id}/analysis-profiles/{profile_id}` | Profile/Analyzer/Scope 상세 | `200 analysis-profile` |
| `GET` | `/cases/{case_id}/index-jobs` | 상태/Profile/Evidence별 Index Job 목록 | `200 job[]` |
| `GET` | `/cases/{case_id}/index-jobs/{job_id}` | Index Job과 Checkpoint 가능 여부 | `200 job` |
| `POST` | `/cases/{case_id}/index-jobs/{job_id}/pause` | Batch 경계 Pause 요청 | `202 job` |
| `POST` | `/cases/{case_id}/index-jobs/{job_id}/resume` | Profile/Fingerprint 확인 후 Resume | `202 job` |
| `POST` | `/cases/{case_id}/index-jobs/{job_id}/cancel` | 협력적 Cancel 요청 | `202 job` |
| `PATCH` | `/cases/{case_id}/index-jobs/{job_id}/priority` | 사용자 Scope Priority 변경 | `200 job` |
| `GET` | `/cases/{case_id}/index-jobs/{job_id}/progress` | 처리량, ETA, Analyzer, Worker, Cache | `200 job progress` |
| `GET` | `/cases/{case_id}/partial-results` | 완료 Batch의 File/Artifact/Timeline/Index 범위 | `200 partial result` |

Profile 생성 예:

```json
{
  "name": "Quick Triage",
  "profile_type": "QUICK_TRIAGE",
  "stages": [
    "EVIDENCE_HEADER",
    "PARTITION",
    "FILESYSTEM_METADATA",
    "ARTIFACT"
  ],
  "hashing_mode": "ON_DEMAND",
  "priority_policy": "USER_SELECTED_FIRST",
  "background_indexing": true,
  "analyzers": [
    {
      "analyzer_id": "windows.prefetch",
      "enabled": true,
      "version_constraint": null,
      "options": {}
    }
  ],
  "scope": {
    "evidence_ids": [],
    "file_ids": [],
    "paths": [],
    "artifact_types": [],
    "time_from": null,
    "time_to": null
  }
}
```

Progress 응답은 ETA를 보장값으로 표현하지 않는다.

```json
{
  "processed_items": 450000,
  "estimated_total_items": 1200000,
  "progress_percent": 37.5,
  "throughput_items_per_second": 820,
  "elapsed_seconds": 548,
  "estimated_remaining_seconds": 915,
  "estimate_confidence": "MEDIUM",
  "current_analyzer": "windows.prefetch",
  "worker_count": 4,
  "cache_hits": 14020,
  "cache_misses": 812,
  "partial_results_available": true,
  "status": "RUNNING"
}
```

Pause는 Checkpoint 저장이 끝나기 전 `PAUSING`일 수 있다. Resume은
`evidence_fingerprint + profile_revision + analyzer_version + options_hash`가 일치하지 않으면
`409 STATE_CONFLICT`를 반환한다. Partial Result에는 `is_partial=true`, `as_of`, 완료 Scope,
대기 Scope, 현재 검색 가능한 Index 범위와 Warning을 포함한다.

## 19. Timezone API

| Method | Path | 동작 | 성공/Schema |
|---|---|---|---|
| `POST` | `/cases/{case_id}/timezone/detect` | Evidence/OS/Application 기반 후보 탐지 Job | `202 Job` |
| `GET` | `/cases/{case_id}/timezone/candidates` | IANA 후보, 출처, Confidence, Citation 조회 | `200 case timezoneCandidate[]` |
| `PUT` | `/cases/{case_id}/timezone` | 분석자 확인 Decision과 Case 표시 Timezone 설정 | `200 case timezoneDecision` |
| `GET` | `/cases/{case_id}/timezone` | 현재 Decision과 이전 Decision 조회 | `200 case timezoneDecision` |
| `GET` | `/cases/{case_id}/timestamp-interpretations` | Source/시간 범위별 원본·UTC·표시 해석 조회 | `200 common timestampInterpretation[]` |

`PUT`은 IANA Time Zone Database ID만 받고 `If-Match` Decision Revision을 사용한다. 변경은
표시 Projection과 향후 Report 정책을 갱신하지만 원본 Timestamp와 기존 UTC 값은 수정하지
않는다. 자동 후보의 출처와 Confidence를 보존하고 `LOW/UNKNOWN` 후보를 시스템이나 AI가
자동 확정하지 않는다. DST 중복/불가능 Local Time은 구조화 Warning을 반환하며 Decision 변경은
Audit Event를 만든다.

## 20. AI Keyword Recommendation과 Search Reproduction API

| Method | Path | 동작 | 성공/Schema |
|---|---|---|---|
| `POST` | `/cases/{case_id}/keyword-recommendations` | Scope Context로 Provider-neutral 추천 Job 요청 | `202 Job` |
| `GET` | `/cases/{case_id}/keyword-recommendations` | Scope/상태별 Candidate 조회 | `200 keywordCandidate[]` |
| `POST` | `/cases/{case_id}/keyword-recommendations/{recommendation_id}/approve` | 분석자 승인 기록 | `201 keywordApproval` |
| `POST` | `/cases/{case_id}/keyword-recommendations/{recommendation_id}/reject` | 분석자 거부 기록 | `201 keywordApproval` |
| `POST` | `/cases/{case_id}/keyword-sets` | AI/수동 Keyword의 Versioned Set 생성 | `201 keywordSet` |
| `GET` | `/cases/{case_id}/keyword-sets` | Version/상태별 Set 조회 | `200 keywordSet[]` |
| `POST` | `/cases/{case_id}/keyword-sets/{keyword_set_id}/execute` | 승인된 Set 검색 실행 | `202 searchExecution` |
| `POST` | `/cases/{case_id}/search-executions/{execution_id}/rerun` | 동일 Options와 현재/고정 Index 정책으로 재실행 | `202 searchExecution` |

추천 요청은 `analysis_context_id`, `scope`, `scope_revision`과 민감정보 최소화 정책을 포함한다.
Engine은 실제 LLM을 호출하지 않고 `KeywordRecommendationPort`에 전달할 Job/DTO만 만든다.
Adapter가 없으면 `501 AI_ADAPTER_UNAVAILABLE`이다.

AI Candidate에는 Keyword, Type, Reason, Scope, Confidence와 최소 1개 Citation이 필요하다.
추천 직후 상태는 `PENDING_REVIEW`이며 승인 전 `execute`가 참조하면 `409 STATE_CONFLICT`다.
수동 Keyword는 `source_kind=ANALYST`로 같은 Set에 저장한다. 실행에는 대소문자, Regex,
Encoding, Time Range, Evidence/Source Scope, Normalization Profile, Index Version, 실행자와
실행 시각을 고정하고 결과가 없었던 Keyword ID도 보존한다.

## 21. Chain of Custody API

| Method | Path | 동작 | 성공/Schema |
|---|---|---|---|
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/custody-events` | Append-only Custody Event 추가 | `201 custodyEvent` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/custody-events` | 순서/Cursor별 Ledger 조회 | `200 custodyEvent[]` |
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/hash-verifications` | Evidence Hash 재검증 Job/Result 생성 | `202 Job` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/hash-verifications` | Hash 검증 이력 조회 | `200 hashVerification[]` |
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/custody-snapshots` | Event 범위와 Head Hash Snapshot 생성 | `201 custodySnapshot` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/custody-snapshots/{snapshot_id}` | Snapshot/무결성/Report Link 조회 | `200 custodySnapshot` |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/custody-export` | 승인 Snapshot 기반 부록 데이터 Export | `200 application/json` |

Custody Event에는 `ACQUISITION`, `RECEIVED`, `TRANSFERRED`, `STORED`, `OPENED`,
`MOUNTED`, `ANALYZED`, `HASH_VERIFIED`, `COPIED`, `EXPORTED`, `RETURNED`, `RELEASED`,
`ARCHIVED`, `DISPOSED`, `CORRECTION`을 사용한다.

Event Update/Delete Endpoint는 제공하지 않는다. 오류 정정은 원 Event를
`correction_of_event_id`로 참조하는 `CORRECTION` Event만 허용한다. Server는 Canonical Event
Hash, 이전 Event Hash, Ledger Algorithm/Version과 단조 Revision을 검증한다. Hash 불일치는
삭제하지 않고 `MISMATCH` Result와 Warning으로 기록한다. Actor Identity/Role과 Approval
권한은 Backend가 검증한다. 이 API는 법적 증거능력을 보장하지 않는다.

## 22. Simple, Detailed와 Raw View API

Simple/Detailed View는 기존 File/Artifact/Timeline 응답과 `view_mode`를 사용한다. Raw View는
별도 제한된 Query다.

| Method | Path | 동작 | 성공/Schema |
|---|---|---|---|
| `GET` | `/cases/{case_id}/files/{file_id}/raw` | File Raw Byte/Text Chunk 조회 | `206 rawLocator + chunk` |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/raw` | Artifact Source Raw Chunk 조회 | `206 rawLocator + chunk` |
| `GET` | `/cases/{case_id}/raw-ranges` | 검증된 Raw Locator 범위 조회 | `206 rawLocator + chunk` |

Query는 `offset`, `length`, `encoding`, `view_type=HEX|TEXT`를 받는다. 기본 최대
`length=1048576`이며 더 큰 범위는 Cursor/Chunk로 나눈다. Range는 Evidence Bounds와
Citation Source를 검증하고 접근 행위를 Audit에 기록한다. 원본 Evidence는 읽기 전용 Handle로
열며 대용량 파일 전체를 메모리에 적재하거나 Raw Snippet Export로 우회하지 않는다. Raw 권한은
Backend User/Role 정책과 합의한다.

## 23. Media Extraction Candidate API

| Method | Path | 동작 | 성공/Schema |
|---|---|---|---|
| `POST` | `/cases/{case_id}/media-extraction-jobs` | OCR/STT Port용 Job 계약 생성 | `202 Job` |
| `GET` | `/cases/{case_id}/media-extraction-jobs/{job_id}` | Candidate 생성 Progress 조회 | `200 Job` |
| `GET` | `/cases/{case_id}/machine-extractions` | Type/Review/언어/File별 Candidate 목록 | `200 machineExtraction[]` |
| `GET` | `/cases/{case_id}/machine-extractions/{extraction_id}` | Text/Confidence/Engine/Locator 상세 | `200 machineExtraction` |
| `POST` | `/cases/{case_id}/machine-extractions/{extraction_id}/accept` | 분석자 Accept Review 추가 | `201 extractionReview` |
| `POST` | `/cases/{case_id}/machine-extractions/{extraction_id}/reject` | 분석자 Reject Review 추가 | `201 extractionReview` |
| `PATCH` | `/cases/{case_id}/machine-extractions/{extraction_id}/correct` | 원 Candidate 유지 + Correction Review | `201 extractionReview` |

실제 OCR/STT 실행 코드는 이 저장소 범위가 아니다. Candidate는 Observed Fact가 아니며
`UNREVIEWED/ACCEPTED/REJECTED/CORRECTED` 상태, Confidence, Engine ID/Version, Frame/Audio
Offset, Region, Raw Locator와 Citation을 반환한다. Correct는 원 Text를 Update하지 않고 Review
행에 수정 Text를 저장한다. Search/AI/Report는 Review 상태를 함께 표시해야 한다.

## 24. Validation Interface 결정

Benchmark 실행은 공개 사용자 API로 확정하지 않는다. 초기에는 내부 Tool/Application Port로
설계하고 원격 다중 사용자 운영이 결정된 뒤 Admin API 필요성을 재검토한다. Endpoint와 Result에
특정 기관명을 넣지 않는다. Benchmark Run은 Dataset Provenance, Hardware, Evidence, Scope,
Hash/Index, Cache, Worker, Storage, Tool/Analyzer Version과 측정값을 기록한다. 외부 검증 상태는
`PLANNED`이며 전문가 Identity 공개는 별도 동의를 요구한다.

## 25. 추가 오류 코드

| HTTP | 코드 | 의미 |
|---|---|---|
| `409` | `PROFILE_REVISION_CONFLICT` | Resume 대상 Profile/Fingerprint 불일치 |
| `409` | `KEYWORD_NOT_APPROVED` | 미승인 Keyword 실행 시도 |
| `409` | `CUSTODY_CHAIN_CONFLICT` | 이전 Event Hash/Revision 불일치 |
| `416` | `RAW_RANGE_NOT_SATISFIABLE` | Evidence Bounds 또는 최대 Range 위반 |
| `422` | `TIMEZONE_AMBIGUOUS` | 확인이 필요한 DST/Timezone 해석 |
| `422` | `CITATION_REQUIRED` | AI Candidate/Statement에 근거 누락 |
| `501` | `MACHINE_EXTRACTION_ADAPTER_UNAVAILABLE` | OCR/STT Adapter 미설치 |

## Phase 2 CLI/Application Interface

Phase 2 exposes the implemented filesystem indexing workflow through the application service and CLI, not through a new web server.

CLI-equivalent commands:

```text
apex-forensic evidence index --case-id <id> --evidence-id <id> --profile QUICK_TRIAGE|SELECTED_SCOPE|FULL_ANALYSIS|CUSTOM
apex-forensic evidence index-status --job-id <id>
apex-forensic evidence index-resume --job-id <id>
apex-forensic evidence index-cancel --job-id <id>
apex-forensic fs roots --evidence-id <id>
apex-forensic fs list --evidence-id <id> [--parent-node-id <id>] [--cursor <opaque>] [--limit <n>]
apex-forensic fs show --node-id <id>
apex-forensic fs prioritize --job-id <id> --node-id <id>
```

All commands keep `--db` and `--json`. File tree pagination uses an opaque cursor containing a query fingerprint and last stable sort key; changing filter/scope options invalidates the cursor with a structured validation error. Disk image internal traversal returns `CAPABILITY_UNAVAILABLE` rather than a successful empty tree.

## Phase 3 CLI/Application Interface

Phase 3 exposes Windows artifact analysis through the application service and CLI. No backend web
server is added.

CLI-equivalent commands:

- `apex-forensic artifact discover --case-id CASE --evidence-id EVIDENCE`
- `apex-forensic artifact analyze --case-id CASE --evidence-id EVIDENCE`
- `apex-forensic artifact status --job-id JOB`
- `apex-forensic artifact resume --job-id JOB`
- `apex-forensic artifact cancel --job-id JOB`
- `apex-forensic artifact list --case-id CASE [--evidence-id EVIDENCE]`
- `apex-forensic artifact show --artifact-id ARTIFACT`
- `apex-forensic artifact warnings [--job-id JOB] [--artifact-id ARTIFACT]`
- `apex-forensic artifact registry autoruns|usb|timezone|userassist`
- `apex-forensic artifact eventlog list|show`
- `apex-forensic artifact prefetch list|show`

Supported command options include `--json`, `--profile`, `--item-budget`, `--batch-size`,
`--analyzer`, `--artifact-type`, `--selected-path`, `--selected-node-id`, `--include`, `--exclude`,
`--cursor`, `--limit`, time range filters, parse status, event ID, registry path, executable name,
source node, and warning filters.

Artifact list queries use opaque stable cursors bound to the query fingerprint and explicit
`observed_or_created_at, artifact_id` ordering. Cursor/query mismatches return structured validation
errors. Capability gaps such as missing `python-registry`, missing `python-evtx`, unsupported Prefetch
versions, and MAM compression are reported as warnings or unsupported parse status, not successful
facts.
