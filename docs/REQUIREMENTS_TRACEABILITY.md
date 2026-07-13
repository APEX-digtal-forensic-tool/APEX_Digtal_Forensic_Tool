# 요구사항 추적표

각 요구사항은 Architecture Component, API, Database, JSON Schema, 구현 Phase와 검증 근거에
연결한다. `-`는 해당 Layer에 영속 상태나 공개 계약이 필요하지 않다는 뜻이다.

## 1. Core

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CORE-001 | Case/Evidence와 Hash를 관리한다 | Evidence Manager | Case/Evidence API | `cases`, `evidence_*` | case, evidence | 1 | Known Hash/Reader Contract |
| CORE-002 | Evidence는 읽기 전용이다 | Evidence Reader | Content Range | `read_only` | evidence | 1 | Write Attempt Test |
| CORE-003 | File Tree/Metadata/삭제 항목을 조회한다 | FS Analyzer | File API | `objects`, `files`, `extents` | file | 2 | FS Fixture/Capability |
| CORE-004 | Registry/Event Log/Prefetch를 독립 분석한다 | Artifact Analyzers | Artifact API | `artifacts`, `analyzer_runs` | artifact | 3 | 손상/정상 Fixture |
| CORE-005 | Timeline과 Search를 제공한다 | Timeline/Search | Timeline/Search API | `timeline_events`, `search_*` | timeline, search | 4 | Projection/Query Test |
| CORE-006 | 장시간 작업을 취소/재개한다 | Job Orchestrator | Job API | `ingest_jobs`, `ingest_tasks` | job | 1-4 | Kill/Resume/Cancel |

## 2. GUI 및 Analysis Context

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| CTX-001 | 선택 Artifact와 현재 Filter를 Context로 전달한다 | Context Service | `PUT/GET /sessions/.../ui-context` | Live 상태는 저장 안 함 | ui-context | 6 | Session Contract |
| CTX-002 | File/Timeline/Search/Tag와 시간 범위를 전달한다 | Context Service | UI Context API | Live 상태는 저장 안 함 | ui-context | 6 | DTO Fixture |
| CTX-003 | Audit/AI/Report에 사용한 Context만 Snapshot으로 보존한다 | Snapshot Service | `POST /context-snapshots` | `ui_context_snapshots` | ui-context | 6 | 보존/만료 Test |
| CTX-004 | 기존 분석 결과를 재분석 없이 Bundle로 조회한다 | Analysis Context Builder | `GET /analysis-bundle` | `analysis_context_snapshots` | analysis-context | 6 | Analyzer 미호출 E2E |
| CTX-005 | Snapshot의 모든 ID는 같은 Case여야 한다 | Analysis Context Builder | Snapshot API | Snapshot FK/검증 | analysis-context, citation | 6 | Cross-case 거부 Test |
| CTX-006 | GUI Update 충돌을 Revision으로 감지한다 | Session Context Port | `If-Match` UI PUT | - | ui-context | 6 | Concurrent Update Test |

## 3. Localization

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| LOC-001 | 기본 Locale은 `ko-KR`이다 | Localization | Case API | `cases.locale` | common, case | 1 | Default/Override Test |
| LOC-002 | 기본 Timezone은 `Asia/Seoul`이다 | Localization | Case API | `cases.timezone` | common, case | 1 | UTC/Display Test |
| LOC-003 | UI 문자열은 Resource 파일로 분리한다 | Frontend/Localization 경계 | Resource Key 반환 | `*_name_key` | common resourceKey | 1-3 | Missing Key 검사 |
| LOC-004 | 한글 파일명/경로를 손실 없이 처리한다 | FS/Localization | File API | `name_raw`, `full_path_raw` | file | 2 | 한글/자모 Round-trip |
| LOC-005 | 한국어 Keyword Search를 지원한다 | Search Adapter | Search API | `normalization_profile` | search | 4 | 한국어 Corpus Test |
| LOC-006 | 한국어 Report Template을 제공한다 | Template Manager | Report API | `template_id`, `locale` | report | 8 | PDF/HTML Golden Test |
| LOC-007 | AI 출력 언어를 Case Locale에 맞춘다 | AI Layer | Enrichment API | `ai_enrichments.locale` | ai-enrichment | 7 | Fake Adapter Contract |
| LOC-008 | UTC/원본 시간과 표시 Timezone을 구분한다 | Timeline/Localization | Timeline/Report API | `timestamp_utc`, Raw/Offset | timeline, report | 4/8 | DST/Timezone Fixture |
| LOC-009 | 오류는 언어 중립 Code/Key로 반환한다 | API/Localization | 모든 오류 응답 | - | common, api-response | 1 | 한국어 Resource Mapping |

## 4. Report

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| RPT-001 | AI Draft는 승인 전 Export할 수 없다 | Approval Manager | approve/export | `reports`, `report_exports` | report | 8 | 상태 전이 거부 Test |
| RPT-002 | AI Draft 뒤 Human Review가 필수다 | Review Manager | request-review | `reports`, `report_sections` | report | 8 | AI 자동 승인 차단 |
| RPT-003 | Evidence/Artifact/Timeline/Search/Tag를 선택한다 | Selectors | Report CRUD | `report_*_links` | report | 8 | Cross-case Link 거부 |
| RPT-004 | 17개 표준 Section을 지원한다 | Template Manager | Report GET/PATCH | `report_sections` | report | 8 | Section Completeness |
| RPT-005 | 승인 Version과 Content Hash를 고정한다 | Approval Manager | approve | `approved_content_sha256` | report | 8 | Optimistic Lock/Hash |
| RPT-006 | 승인 후 수정은 재검토가 필요하다 | Report Domain | PATCH | `version`, `status` | report | 8 | Version Transition |
| RPT-007 | PDF/HTML Export를 지원한다 | Exporter | export/exports | `report_exports` | report `$defs/reportExport` | 8 | Format/Hash Test |
| RPT-008 | AI Draft 호출은 Port로 격리한다 | ReportDraftPort | generate-draft | `analysis_context_snapshot_id` | analysis-context, report | 8 | Fake Port Contract |

## 5. MCP Integration Boundary

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MCP-001 | Forensic Engine은 MCP SDK에 의존하지 않는다 | 배포/Port 경계 | 공개 API만 제공 | - | 모든 공개 Schema | 0/9 | Dependency Scan |
| MCP-002 | Built-in MCP는 제품에 포함하되 별도 Component다 | Desktop Distribution | Engine API Consumer | - | Context/Result Schema | 별도/9 | Packaging Boundary |
| MCP-003 | MCP는 GUI 결과와 Context를 조회한다 | Context Service | Context/Analysis API | Snapshot/Search Result | ui/analysis-context | 6 | Fake MCP Consumer |
| MCP-004 | MCP가 Analyzer/DB를 직접 호출하지 않는다 | Application Interface | `/api/v1` | - | API Schema | 6/9 | Architecture Rule |
| MCP-005 | Engine에는 Prompt/Credential/Provider가 없다 | AI Port 경계 | Provider-neutral DTO | `adapter_ref`만 허용 | ai-enrichment | 7/9 | 금지 의존성/Secret Scan |

## 6. Performance

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| PERF-001 | Lazy Loading | FS Analyzer | children + cursor | Parent Index | file | 2 | 100만 File RSS |
| PERF-002 | Cursor Pagination | Query Plane | 목록 API | 정렬 복합 Index | common pageInfo | 2 | Page 안정성 Test |
| PERF-003 | Process Pool | Job Orchestrator | Job API | Task 상태 | job | 4 | CPU 처리량/Crash |
| PERF-004 | Async I/O와 Streaming | Reader/API | Content Range | - | job progress | 2/4 | Backpressure Test |
| PERF-005 | Artifact 병렬 분석 | Analyzer/Job | Ingest Job | `ingest_tasks` | job | 4 | 결정성/격리 Test |
| PERF-006 | 단일 DB Writer | Result Writer | - | WAL/Batch | - | 1/4 | Lock Contention |
| PERF-007 | Full Text Index | Search | Search API | FTS5/동등 Index | search | 4 | Query P95/정확도 |
| PERF-008 | Cache Layer | Cache Port | - | `cache_entries` | - | 4 | Hit/손상/LRU |
| PERF-009 | Checkpoint/Resume | Job Orchestrator | retry | `checkpoint_json` | job | 4 | Process Kill Test |
| PERF-010 | 중복 분석 방지 | Analyzer Run | Ingest Job | Fingerprint/Config Hash | job | 4 | Idempotency Test |
| PERF-011 | 취소와 Progress | Job Orchestrator | cancel/events | Job Progress | job | 1/4 | Cooperative Cancel |
| PERF-012 | 검증 전 성능 우위를 주장하지 않는다 | Benchmark 정책 | - | - | - | 9 | 문서 표현/Benchmark |

## 7. Communications와 Media

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| COMM-001 | Browser 방문/검색/다운로드 History를 분석한다 | Browser Communications | Artifact/Search | `artifacts` | artifact | 5 | Browser DB Fixture |
| COMM-002 | URL/File/Profile과 시간을 제공한다 | Browser Analyzer | Artifact/Timeline | Artifact/Timeline | artifact, timeline | 5 | Provenance Fixture |
| COMM-003 | Email/Messenger는 후순위 Plugin이다 | Analyzer Plugin 경계 | Capability | Artifact Type 등록 | artifact | 후순위 | Plugin Contract |
| MEDIA-001 | Image/Video를 분류한다 | Media Analyzer | File/Artifact | File/Artifact | file, artifact | 5 | MIME/Magic Fixture |
| MEDIA-002 | EXIF/GPS/Codec/Duration/시간을 제공한다 | Media Analyzer | Artifact/Timeline | Artifact/Timeline | artifact, timeline | 5 | Media Metadata Fixture |
| MEDIA-003 | Thumbnail은 Cache 파생물이다 | Media/Cache | Content API | `cache_entries` | artifact Citation | 5 | 원본 불변/Cache Test |
| MEDIA-004 | 삭제 Media를 표시한다 | FS/Media | File API | `files.deleted` | file | 5 | Deleted Media Fixture |
| MEDIA-005 | AI는 저장 Metadata만 요약하고 원본을 수정하지 않는다 | AI/Media 경계 | Enrichment | `ai_enrichments` | ai-enrichment | 7 | Read-only/Fake Adapter |

## 8. AI, Audit와 Citation

| ID | 요구사항 | Architecture | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AI-001 | 기존 결과를 요약/설명/상관 분석한다 | AIEnrichmentPort | Enrichment | `ai_enrichments` | ai-enrichment | 7 | Fake Adapter Contract |
| AI-002 | 추가 Artifact/대응을 Recommendation으로 제안한다 | AI Layer | Enrichment | `ai_enrichments` | ai-enrichment | 7 | Category Validation |
| AI-003 | Observed/Annotation/Inference/Recommendation을 구분한다 | AI Layer | Enrichment GET | 별도 Result JSON | ai-enrichment | 7 | Schema/혼합 거부 |
| AI-004 | 특정 Provider에 종속되지 않는다 | Port 경계 | Provider 필드 없음 | Provider 컬럼 없음 | ai-enrichment | 7 | Schema/Dependency Scan |
| AI-005 | Token 과금은 Backend/Billing 책임이다 | Billing 경계 | Core API 범위 밖 | Core Table 없음 | Core Schema 없음 | 별도 | Boundary Review |
| AUD-001 | AI 결과는 실제 Source Citation을 포함한다 | Citation Service | Context/AI/Report | `report_citations` | citation | 6-8 | Source Resolve Test |
| AUD-002 | Citation은 경로와 Offset/Reference를 보존한다 | Provenance | Result GET | Citation Snapshot | citation | 6 | Byte/Record 역추적 |
| AUD-003 | 상태 변경은 Append-only Audit에 기록한다 | Audit Service | Command 전체 | `audit_events` | common Error/IDs | 1-8 | Hash Chain Test |
| AUD-004 | AI/Report 입력 Context를 Hash로 고정한다 | Snapshot Service | Snapshot/approve | Context/Report Hash | analysis-context, report | 6/8 | Canonical Hash Test |

## 9. 소유권 중복 검사

| 데이터/행위 | 단일 소유 모듈 | 다른 모듈의 허용 동작 |
| --- | --- | --- |
| Evidence/Artifact Fact | Evidence/Artifact Analyzer | Context/AI/Report는 ID로 읽기만 함 |
| Live UI Context | Backend Session Store | Engine은 DTO/Port와 Snapshot 생성만 제공 |
| Context Snapshot | Context Service | AI/Report/MCP는 불변 조회만 함 |
| Analyst Annotation/Tag | Annotation/Tag Service | Context/Report는 선택/인용 |
| AI Enrichment | AI Layer Repository | Artifact/Timeline을 수정하지 않음 |
| Report 상태/Version | Report Module | AI Draft Adapter는 Draft만 반환 |
| Export 파일 | Report Exporter | GUI/MCP는 다운로드/조회 |
| Token 사용량/과금 | Backend/Billing | Core는 상관관계 ID만 제공 |

## 10. 설계 완료 판정

- [x] Architecture, Directory, Module, Database, API 통합
- [x] UI/Analysis Context, Citation, AI Enrichment Schema
- [x] Report/Human Review/Export Schema와 상태 규칙
- [x] Localization, Communications, Media, Performance 요구사항 추적
- [x] MCP/LLM/Billing 분리 경계
- [ ] 실제 Core/Backend/Frontend/MCP/AI 구현
- [ ] Library Spike, Forensic Fixture와 성능 Baseline
