# 요구사항 추적표

각 요구사항은 Architecture Component, Module Owner, API, Database, JSON Schema, 구현 Phase와
검증 근거에 연결한다. `-`는 해당 Layer에 영속 상태나 공개 계약이 필요하지 않다는 뜻이다.

## 1. Core

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CORE-001 | Case/Evidence와 Hash를 관리한다 | Evidence Manager | Evidence Manager | Case/Evidence API | `cases`, `evidence_*` | case, evidence | 1 | Known Hash/Reader Contract |
| CORE-002 | Evidence는 읽기 전용이다 | Evidence Reader | Evidence Reader | Content Range | `read_only` | evidence | 1 | Write Attempt Test |
| CORE-003 | File Tree/Metadata/삭제 항목을 조회한다 | FS Analyzer | FS Analyzer | File API | `objects`, `files`, `extents` | file | 2 | FS Fixture/Capability |
| CORE-004 | Registry/Event Log/Prefetch를 독립 분석한다 | Artifact Analyzers | Artifact Analyzers | Artifact API | `artifacts`, `analyzer_runs` | artifact | 3 | 손상/정상 Fixture |
| CORE-005 | Timeline과 Search를 제공한다 | Timeline/Search | Timeline/Search | Timeline/Search API | `timeline_events`, `search_*` | timeline, search | 4 | Projection/Query Test |
| CORE-006 | 장시간 작업을 취소/재개한다 | Job Orchestrator | Job Orchestrator | Job API | `ingest_jobs`, `ingest_tasks` | job | 1-4 | Kill/Resume/Cancel |

## 2. GUI 및 Analysis Context

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| CTX-001 | 선택 Artifact와 현재 Filter를 Context로 전달한다 | Context Service | Context Service | `PUT/GET /sessions/.../ui-context` | Live 상태는 저장 안 함 | ui-context | 6 | Session Contract |
| CTX-002 | File/Timeline/Search/Tag와 시간 범위를 전달한다 | Context Service | Context Service | UI Context API | Live 상태는 저장 안 함 | ui-context | 6 | DTO Fixture |
| CTX-003 | Audit/AI/Report에 사용한 Context만 Snapshot으로 보존한다 | Snapshot Service | Snapshot Service | `POST /context-snapshots` | `ui_context_snapshots` | ui-context | 6 | 보존/만료 Test |
| CTX-004 | 기존 분석 결과를 재분석 없이 Bundle로 조회한다 | Analysis Context Builder | Analysis Context Builder | `GET /analysis-bundle` | `analysis_context_snapshots` | analysis-context | 6 | Analyzer 미호출 E2E |
| CTX-005 | Snapshot의 모든 ID는 같은 Case여야 한다 | Analysis Context Builder | Analysis Context Builder | Snapshot API | Snapshot FK/검증 | analysis-context, citation | 6 | Cross-case 거부 Test |
| CTX-006 | GUI Update 충돌을 Revision으로 감지한다 | Session Context Port | Session Context Port | `If-Match` UI PUT | - | ui-context | 6 | Concurrent Update Test |

## 3. Localization

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| LOC-001 | 기본 Locale은 `ko-KR`이다 | Localization | Localization | Case API | `cases.locale` | common, case | 1 | Default/Override Test |
| LOC-002 | 기본 Timezone은 `Asia/Seoul`이다 | Localization | Localization | Case API | `cases.timezone` | common, case | 1 | UTC/Display Test |
| LOC-003 | UI 문자열은 Resource 파일로 분리한다 | Frontend/Localization 경계 | Frontend/Localization 경계 | Resource Key 반환 | `*_name_key` | common resourceKey | 1-3 | Missing Key 검사 |
| LOC-004 | 한글 파일명/경로를 손실 없이 처리한다 | FS/Localization | FS/Localization | File API | `name_raw`, `full_path_raw` | file | 2 | 한글/자모 Round-trip |
| LOC-005 | 한국어 Keyword Search를 지원한다 | Search Adapter | Search Adapter | Search API | `normalization_profile` | search | 4 | 한국어 Corpus Test |
| LOC-006 | 한국어 Report Template을 제공한다 | Template Manager | Template Manager | Report API | `template_id`, `locale` | report | 8 | PDF/HTML Golden Test |
| LOC-007 | AI 출력 언어를 Case Locale에 맞춘다 | AI Layer | AI Layer | Enrichment API | `ai_enrichments.locale` | ai-enrichment | 7 | Fake Adapter Contract |
| LOC-008 | UTC/원본 시간과 표시 Timezone을 구분한다 | Timeline/Localization | Timeline/Localization | Timeline/Report API | `timestamp_utc`, Raw/Offset | timeline, report | 4/8 | DST/Timezone Fixture |
| LOC-009 | 오류는 언어 중립 Code/Key로 반환한다 | API/Localization | API/Localization | 모든 오류 응답 | - | common, api-response | 1 | 한국어 Resource Mapping |

## 4. Report

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RPT-001 | AI Draft는 승인 전 Export할 수 없다 | Approval Manager | Approval Manager | approve/export | `reports`, `report_exports` | report | 8 | 상태 전이 거부 Test |
| RPT-002 | AI Draft 뒤 Human Review가 필수다 | Review Manager | Review Manager | request-review | `reports`, `report_sections` | report | 8 | AI 자동 승인 차단 |
| RPT-003 | Evidence/Artifact/Timeline/Search/Tag를 선택한다 | Selectors | Selectors | Report CRUD | `report_*_links` | report | 8 | Cross-case Link 거부 |
| RPT-004 | 17개 표준 Section을 지원한다 | Template Manager | Template Manager | Report GET/PATCH | `report_sections` | report | 8 | Section Completeness |
| RPT-005 | 승인 Version과 Content Hash를 고정한다 | Approval Manager | Approval Manager | approve | `approved_content_sha256` | report | 8 | Optimistic Lock/Hash |
| RPT-006 | 승인 후 수정은 재검토가 필요하다 | Report Domain | Report Domain | PATCH | `version`, `status` | report | 8 | Version Transition |
| RPT-007 | PDF/HTML Export를 지원한다 | Exporter | Exporter | export/exports | `report_exports` | report `$defs/reportExport` | 8 | Format/Hash Test |
| RPT-008 | AI Draft 호출은 Port로 격리한다 | ReportDraftPort | ReportDraftPort | generate-draft | `analysis_context_snapshot_id` | analysis-context, report | 8 | Fake Port Contract |

## 5. MCP Integration Boundary

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| MCP-001 | Forensic Engine은 MCP SDK에 의존하지 않는다 | 배포/Port 경계 | 배포/Port 경계 | 공개 API만 제공 | - | 모든 공개 Schema | 0/9 | Dependency Scan |
| MCP-002 | Built-in MCP는 제품에 포함하되 별도 Component다 | Desktop Distribution | Desktop Distribution | Engine API Consumer | - | Context/Result Schema | 별도/9 | Packaging Boundary |
| MCP-003 | MCP는 GUI 결과와 Context를 조회한다 | Context Service | Context Service | Context/Analysis API | Snapshot/Search Result | ui/analysis-context | 6 | Fake MCP Consumer |
| MCP-004 | MCP가 Analyzer/DB를 직접 호출하지 않는다 | Application Interface | Application Interface | `/api/v1` | - | API Schema | 6/9 | Architecture Rule |
| MCP-005 | Engine에는 Prompt/Credential/Provider가 없다 | AI Port 경계 | AI Port 경계 | Provider-neutral DTO | `adapter_ref`만 허용 | ai-enrichment | 7/9 | 금지 의존성/Secret Scan |

## 6. Performance

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PERF-001 | Lazy Loading | FS Analyzer | FS Analyzer | children + cursor | Parent Index | file | 2 | 100만 File RSS |
| PERF-002 | Cursor Pagination | Query Plane | Query Plane | 목록 API | 정렬 복합 Index | common pageInfo | 2 | Page 안정성 Test |
| PERF-003 | Process Pool | Job Orchestrator | Job Orchestrator | Job API | Task 상태 | job | 4 | CPU 처리량/Crash |
| PERF-004 | Async I/O와 Streaming | Reader/API | Reader/API | Content Range | - | job progress | 2/4 | Backpressure Test |
| PERF-005 | Artifact 병렬 분석 | Analyzer/Job | Analyzer/Job | Ingest Job | `ingest_tasks` | job | 4 | 결정성/격리 Test |
| PERF-006 | 단일 DB Writer | Result Writer | Result Writer | - | WAL/Batch | - | 1/4 | Lock Contention |
| PERF-007 | Full Text Index | Search | Search | Search API | FTS5/동등 Index | search | 4 | Query P95/정확도 |
| PERF-008 | Cache Layer | Cache Port | Cache Port | - | `cache_entries` | - | 4 | Hit/손상/LRU |
| PERF-009 | Checkpoint/Resume | Job Orchestrator | Job Orchestrator | retry | `checkpoint_json` | job | 4 | Process Kill Test |
| PERF-010 | 중복 분석 방지 | Analyzer Run | Analyzer Run | Ingest Job | Fingerprint/Config Hash | job | 4 | Idempotency Test |
| PERF-011 | 취소와 Progress | Job Orchestrator | Job Orchestrator | cancel/events | Job Progress | job | 1/4 | Cooperative Cancel |
| PERF-012 | 검증 전 성능 우위를 주장하지 않는다 | Benchmark 정책 | Benchmark 정책 | - | - | - | 9 | 문서 표현/Benchmark |

## 7. Communications와 Media

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| COMM-001 | Browser 방문/검색/다운로드 History를 분석한다 | Browser Communications | Browser Communications | Artifact/Search | `artifacts` | artifact | 5 | Browser DB Fixture |
| COMM-002 | URL/File/Profile과 시간을 제공한다 | Browser Analyzer | Browser Analyzer | Artifact/Timeline | Artifact/Timeline | artifact, timeline | 5 | Provenance Fixture |
| COMM-003 | Email/Messenger는 후순위 Plugin이다 | Analyzer Plugin 경계 | Analyzer Plugin 경계 | Capability | Artifact Type 등록 | artifact | 후순위 | Plugin Contract |
| MEDIA-001 | Image/Video를 분류한다 | Media Analyzer | Media Analyzer | File/Artifact | File/Artifact | file, artifact | 5 | MIME/Magic Fixture |
| MEDIA-002 | EXIF/GPS/Codec/Duration/시간을 제공한다 | Media Analyzer | Media Analyzer | Artifact/Timeline | Artifact/Timeline | artifact, timeline | 5 | Media Metadata Fixture |
| MEDIA-003 | Thumbnail은 Cache 파생물이다 | Media/Cache | Media/Cache | Content API | `cache_entries` | artifact Citation | 5 | 원본 불변/Cache Test |
| MEDIA-004 | 삭제 Media를 표시한다 | FS/Media | FS/Media | File API | `files.deleted` | file | 5 | Deleted Media Fixture |
| MEDIA-005 | AI는 저장 Metadata만 요약하고 원본을 수정하지 않는다 | AI/Media 경계 | AI/Media 경계 | Enrichment | `ai_enrichments` | ai-enrichment | 7 | Read-only/Fake Adapter |

## 8. AI, Audit와 Citation

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| AI-001 | 기존 결과를 요약/설명/상관 분석한다 | AIEnrichmentPort | AIEnrichmentPort | Enrichment | `ai_enrichments` | ai-enrichment | 7 | Fake Adapter Contract |
| AI-002 | 추가 Artifact/대응을 Recommendation으로 제안한다 | AI Layer | AI Layer | Enrichment | `ai_enrichments` | ai-enrichment | 7 | Category Validation |
| AI-003 | Observed/Annotation/Inference/Recommendation을 구분한다 | AI Layer | AI Layer | Enrichment GET | 별도 Result JSON | ai-enrichment | 7 | Schema/혼합 거부 |
| AI-004 | 특정 Provider에 종속되지 않는다 | Port 경계 | Port 경계 | Provider 필드 없음 | Provider 컬럼 없음 | ai-enrichment | 7 | Schema/Dependency Scan |
| AI-005 | Token 과금은 Backend/Billing 책임이다 | Billing 경계 | Billing 경계 | Core API 범위 밖 | Core Table 없음 | Core Schema 없음 | 별도 | Boundary Review |
| AUD-001 | AI 결과는 실제 Source Citation을 포함한다 | Citation Service | Citation Service | Context/AI/Report | `report_citations` | citation | 6-8 | Source Resolve Test |
| AUD-002 | Citation은 경로와 Offset/Reference를 보존한다 | Provenance | Provenance | Result GET | Citation Snapshot | citation | 6 | Byte/Record 역추적 |
| AUD-003 | 상태 변경은 Append-only Audit에 기록한다 | Audit Service | Audit Service | Command 전체 | `audit_events` | common Error/IDs | 1-8 | Hash Chain Test |
| AUD-004 | AI/Report 입력 Context를 Hash로 고정한다 | Snapshot Service | Snapshot Service | Snapshot/approve | Context/Report Hash | analysis-context, report | 6/8 | Canonical Hash Test |

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

## Python-Native 하이브리드 요구사항

| ID | 요구사항 | 담당 구조 | 검증 방법 |
|---|---|---|---|
| PERF-HYB-001 | Python은 Application 및 Orchestration Layer를 담당하고 성능 핵심 경로는 Native Adapter를 통해 실행해야 한다. | Architecture / Native Adapter | Architecture Review |
| PERF-HYB-002 | Domain 및 Application Layer는 특정 Native Library API에 직접 의존하지 않아야 한다. | Ports / Adapters | Dependency Test |
| PERF-HYB-003 | CPU 집약적 Analyzer는 Process 기반 병렬 처리를 지원해야 한다. | Process Pool | Multi-core Benchmark |
| PERF-HYB-004 | Evidence 전체를 메모리에 적재하지 않고 Streaming 또는 Offset 기반 접근을 사용해야 한다. | Evidence Reader | Large Evidence Memory Test |
| PERF-HYB-005 | Analyzer 결과는 Bounded Queue를 통해 Single DB Writer에 전달해야 한다. | Result Queue / DB Writer | SQLite Concurrency Test |
| PERF-HYB-006 | Native Provider는 Windows 지원, License, 유지보수 상태, Packaging 및 Benchmark 결과를 기준으로 선정해야 한다. | Provider Selection | Technology Spike |
| PERF-HYB-007 | 실제 병목이 확인되기 전에는 Native Extension을 도입하지 않아야 한다. | Performance Strategy | Profiling Report |

## 11. 외부 요구사항 인터뷰 보강 Traceability

대학원 연구자 및 디지털 포렌식·사이버 작전 경험자를 대상으로 한 요구사항 인터뷰를 통해
기능 범위를 보완하였다. 다음 요구사항은 특정 기관의 공식 입장, 협력 또는 인증을 의미하지
않는다.

### Progressive Indexing

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| IDX-001 | 전체 Index 완료 전 File Tree와 Partial Result를 조회할 수 있어야 한다 | Progressive Indexing Coordinator | Progressive Indexing Coordinator | Partial Result/File API | `indexing_jobs`, `indexing_job_scopes` | job, common | 2 | Partial Batch/미완료 표시 Contract |
| IDX-002 | Quick Triage, Selected Scope, Full Analysis, Custom Profile을 지원해야 한다 | Analysis Profile Manager | Analysis Profile Manager | Analysis Profile API | `analysis_profiles` | analysis-profile | 0/2 | 4 Profile Fixture/Schema |
| IDX-003 | Index Job은 Pause, Resume, Cancel을 지원해야 한다 | Job State Machine | Job Orchestrator | Index Job Command | `indexing_jobs`, `indexing_checkpoints` | job | 2 | Pause/Resume/Cancel Recovery |
| IDX-004 | 사용자 선택 Scope를 Background보다 우선 처리해야 한다 | Priority Job Scheduler | Job Orchestrator | priority PATCH | `indexing_job_scopes` | analysis-profile, job | 2 | Priority/Fairness Test |
| IDX-005 | 처리량, ETA, 신뢰도, Analyzer, Worker, Cache 지표를 제공해야 한다 | Progress Estimator | Job Orchestrator | progress GET | `analyzer_progress` | job | 2/9 | ETA Unknown/Confidence Fixture |

### Timezone

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| TZ-001 | 원본 Timestamp를 보존하고 정규화 Timestamp는 UTC로 저장해야 한다 | Timestamp Normalizer | Localization/Timeline | Timestamp Interpretation API | `timestamp_interpretations` | common, file, timeline | 1/4 | Raw 불변/UTC Fixture |
| TZ-002 | Case Timezone 후보를 자동 탐지할 수 있어야 한다 | Timezone Resolver | Localization | timezone detect/candidates | `timezone_candidates` | case | 0/1 | Registry/Linux/Browser Fixture |
| TZ-003 | 후보는 출처와 Confidence를 제공하고 분석자가 결정해야 한다 | Timezone Decision Service | Localization/Backend | timezone PUT/GET | `timezone_decisions` | case, common | 1 | Human Decision/Low 자동확정 거부 |
| TZ-004 | Report에 Timezone과 변환 정책을 기록해야 한다 | Report Provenance | Report Module | Report API | `report_timezone_decision_links` | report | 8 | Report Version/Timezone Contract |
| TZ-005 | DST 중복·불가능 Local Time과 해석 변경을 경고·감사해야 한다 | Timezone Audit | Localization/Audit | interpretations GET | `timestamp_interpretations`, `audit_events` | common | 4 | DST Boundary Fixture |

### AI Keyword Recommendation

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| KW-001 | AI Keyword Candidate는 Reason, Scope, Confidence와 Citation을 포함해야 한다 | Keyword Recommendation Port | AI Layer/Keyword Set Manager | recommendation POST/GET | `keyword_recommendations` | keyword-recommendation, citation | 7 | Missing Citation/Reason 거부 |
| KW-002 | Candidate는 분석자 승인 전 검색에 사용해서는 안 된다 | Human Review Gate | Keyword Set Manager | approve/reject/execute | `keyword_approvals`, `keyword_set_items` | keyword-recommendation | 7 | 승인 전 Execute 409 |
| KW-003 | Keyword Set, Search Scope와 Options를 저장해 동일 검색을 재현해야 한다 | Search Reproduction Manager | Search Engine | keyword-set execute/rerun | `search_executions`, `search_execution_options` | search, keyword-recommendation | 4/7 | 0건/Options/Index Version 재현 |

### Chain of Custody

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| COC-001 | Custody Event는 Append-only로 관리해야 한다 | Chain of Custody Ledger | Chain of Custody Ledger | Event POST/GET | `custody_events` | chain-of-custody | 1/8 | DB Update/Delete 거부 |
| COC-002 | 기존 Event 수정 대신 Correction Event를 추가해야 한다 | Custody Correction Rule | Chain of Custody Ledger | Event POST | `custody_events.correction_of_event_id` | chain-of-custody | 1/8 | Correction 대상/Revision Test |
| COC-003 | Evidence Hash 검증 이력을 저장하고 불일치를 경고해야 한다 | Custody Verification Service | Custody Verification Service | hash-verifications | `custody_hash_verifications` | chain-of-custody | 1/8 | Match/Mismatch Known Hash |
| COC-004 | Custody Snapshot을 Report Version과 연결해야 한다 | Custody Snapshot Service | Custody Verification/Report | custody-snapshots/report | `custody_snapshots`, `report_custody_snapshot_links` | chain-of-custody, report | 8 | Snapshot/Report Hash Test |
| COC-005 | Ledger 순서와 Hash Chain 무결성을 검증해야 한다 | Custody Verification Service | Custody Verification Service | custody export | `custody_events` | chain-of-custody | 8 | Broken Previous Hash Test |

### View와 Machine Extraction

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| VIEW-001 | 동일 Finding에 Simple, Detailed, Raw View를 제공해야 한다 | View Contract | Frontend/API Interface | Existing Result + Raw API | Live UI Context | ui-context | 6 | 동일 Source/View 전환 Contract |
| VIEW-002 | Raw View는 Source Offset, Length와 Citation을 제공해야 한다 | Raw Evidence Locator | Raw Evidence Locator | raw endpoints | Artifact/File Provenance | citation, artifact | 3/6 | Locator Bounds/Resolve Test |
| VIEW-003 | Raw View는 원본을 수정하거나 전체 파일을 적재해서는 안 된다 | Read-only Range Reader | Evidence Manager | raw-ranges | `audit_events` | citation | 6 | Write Attempt/1 MiB Limit/RSS |
| MEDIA-006 | OCR/STT 결과는 Machine-extracted Candidate로 분류해야 한다 | Machine Extraction Port | Media Extraction Candidate Store | candidate list/show | `machine_extracted_candidates` | machine-extracted-candidate | 5 | Fact 혼합 거부 |
| MEDIA-007 | Candidate는 Confidence, Provider Version, Source Locator와 Citation을 포함해야 한다 | Candidate Contract | Media Extraction Candidate Store | candidate show | `machine_extracted_candidates` | machine-extracted-candidate, citation | 5 | Required Field Contract |
| MEDIA-008 | 분석자는 Candidate를 Accept, Reject, Correct할 수 있어야 한다 | Candidate Review | Media Extraction Candidate Store | candidate review/correct | `candidate_review_events` | machine-extracted-candidate | 5 | 원 Candidate 불변/Review Test |

### AI Scope와 Human Verification

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| AI-006 | AI Context는 Scope별 독립 Revision으로 분리해야 한다 | Scope Context Service | Context Service | Context Snapshot API | `analysis_context_snapshots` | analysis-context | 6/7 | Scope Revision/Hash Test |
| AI-007 | Partial Result 기반 AI 답변은 미완료임을 표시해야 한다 | AI Partial Gate | Context/AI Layer | Analysis Bundle/Enrichment | `analysis_context_snapshots`, `ai_enrichments` | common, analysis-context, ai-enrichment | 7 | Partial 경고 누락 거부 |
| AI-008 | AI는 Citation 없이 새 Observed Fact를 생성해서는 안 된다 | Citation Gate | AI Layer/Citation Service | Enrichment | `ai_enrichments` | ai-enrichment, citation | 7 | Engine Quoted Fact/Citation Test |
| AI-009 | AI 추천 Keyword를 자동 실행하거나 Scope 외 데이터를 포함하면 안 된다 | Human/Scope Gate | AI Layer/Keyword Set Manager | Recommendation/Execute | `keyword_approvals` | analysis-context, keyword-recommendation | 7 | 미승인/Scope 외 거부 |

### External Validation과 Report

| ID | 요구사항 | Architecture | Module Owner | API | Database | Schema | Phase | 검증 |
|---|---|---|---|---|---|---|---|---|
| VAL-001 | 성능 비교는 동일 Hardware/Evidence/Scope/Option/Cache/Worker/Storage에서만 수행해야 한다 | Benchmark Plan | External Validation Plan | 내부 Tool/Port | `benchmark_runs`, `benchmark_measurements` | - | 9 | Benchmark Metadata Completeness |
| VAL-002 | 외부 평가는 공개/Synthetic/법적 Test Dataset만 사용해야 한다 | Validation Data Policy | External Validation Plan | 내부 Tool/Port | `external_validation_reviews` | - | 9 | Dataset/PII Policy Review |
| VAL-003 | 승인 없는 기관명을 인증·협력 기관으로 표시하면 안 된다 | Publication Policy | External Validation Plan/Backend | 공개 API 미정 | `external_validation_reviews` | - | 9 | 금지 표현/동의 검사 |
| RPT-009 | Report는 Index/Timezone/Keyword/Custody/Raw/Machine Candidate Provenance를 고정해야 한다 | Report Provenance | Report Module | Report API | `report_*_links` | report | 8 | 승인 Version Provenance |
| RPT-010 | Report 문장은 Fact/Annotation/Candidate/Inference/Recommendation을 구분해야 한다 | Report Statement Classification | Report Module | Report GET/PATCH | `report_sections` | report | 8 | Category 혼합 거부 |

## 12. 보강 소유권 중복 검사

| 데이터/행위 | 단일 소유 모듈 | 다른 모듈의 허용 동작 |
|---|---|---|
| Analysis Profile | Analysis Profile Manager | Job은 ID/Revision 참조 |
| Index 실행/Progress | Job Orchestrator | GUI/AI는 Partial 상태 조회 |
| Timezone Candidate/Decision | Timezone Resolver/Decision Service | Timeline/Report는 불변 Decision 참조 |
| Keyword Candidate/Set | Keyword Set Manager | AI는 Candidate 생성, Search는 승인 Set만 실행 |
| Search Execution Snapshot | Search Reproduction Manager | Context/Report는 불변 조회 |
| Custody Event | Chain of Custody Ledger | Report는 Snapshot만 연결 |
| Machine Candidate/Review | Media Extraction Candidate Store | Search/AI/Report는 상태 포함 조회 |
| Raw Byte Range | Evidence Manager/Raw Locator | Frontend는 제한된 Chunk 표시 |
| Benchmark/External Review | External Validation Plan | Backend는 공개·동의 정책 협의 |

## Phase 2 Traceability Update

Phase 2 implementation now maps the progressive indexing requirements to concrete artifacts:

- Domain contract: `FileSystemNode`, `IndexCoverage`, provider capability DTOs, index/pause/resume/cancel job states.
- Provider: Logical directory/file metadata provider with Unicode path preservation and no default symlink/reparse traversal.
- Persistence: `fs_nodes`, provider metadata, index job metadata, queue/checkpoint, coverage, and scan event tables.
- Interface: CLI commands for indexing, status, resume, cancel, root/list/show, and prioritization.
- Schema: `file.schema.json`, `job.schema.json`, `evidence.schema.json`, and `analysis-profile.schema.json` extensions.
- Verification: unit and integration coverage for partial/resume, selected scope priority, stable cursor pagination, unsupported disk images, schema validation, and Phase 1 regressions.

Unsupported Phase 2 boundaries remain explicit and are not traced as completed: disk image internal parsing, native filesystem parsers, deleted file recovery, full text search, artifact/timeline integrations, GUI, MCP, LLM, OCR/STT, and report rendering.

## Phase 3 Traceability Update

- Requirement scope: CORE-004 and VIEW-002 now have runtime coverage for Windows Registry, Event Log,
  Prefetch, raw locators, citations, artifact persistence, and cursor queries.
- Implementation: `ArtifactAnalysisService`, `ArtifactAnalyzer`/`ArtifactRepository` ports,
  `WindowsRegistryAnalyzer`, `WindowsEventLogAnalyzer`, `WindowsPrefetchAnalyzer`, and
  `SQLiteRepository` Phase 3 tables.
- Interface: CLI commands for artifact discover/analyze/status/resume/cancel/list/show/warnings and
  registry/eventlog/prefetch helper queries.
- Schema: `artifact.schema.json` and `citation.schema.json` now validate Phase 3 artifact facts and
  logical/byte raw locators.
- Verification: unit and integration coverage for `.reg` encoding, autorun, USB, timezone,
  UserAssist ROT13/safe counters, Event XML namespace fields, event subtype mapping, corrupt XML,
  Prefetch bounds/unsupported/MAM handling, discovery from `fs_nodes`, SQLite reopen/resume, stable
  cursor mismatch rejection, duplicate prevention, CLI E2E, and schema validation.

Unsupported Phase 3 boundaries remain explicit and are not traced as completed: live Windows
acquisition, remote Registry, credential/secret extraction, Registry transaction log recovery,
deleted key recovery, Event Message DLL rendering, full EVTX fixture coverage when `python-evtx` is
absent, full binary hive fixture coverage when `python-registry` is absent, Prefetch MAM
decompression, timeline integration, FTS/search engine, GUI, MCP, LLM, OCR/STT, browser/media
analyzers, and report rendering.

### Phase 4 Search, Keyword Set, Timeline Trace

- Implementation: `SearchService`, `TimelineService`, `SearchIndexProvider`, `SearchRepository`,
  `TimelineRepository`, and SQLite Phase 4 tables implement metadata/artifact search, keyword set
  versioning, reproduction, cache, timestamp normalization, and timeline query.
- Verification: `tests/unit/test_phase4_search_timeline.py` covers FTS5 capability, term/phrase/prefix/
  exact/metadata-regex search, SQL-injection-like query safety, cache hit, 0-result reproduction,
  keyword duplicate/version/regex validation, explicit offset normalization, naive timestamp unknown
  handling, timeline build, stable cursor pagination, Asia/Seoul display, and schema validation.
- Integration: CLI smoke was exercised for search index/query, keyword set activate, and timeline
  build/list. Existing Phase 1-3 tests remain passing.
- Persistence: new tables include `search_documents`, `search_index_metadata`, `search_jobs`,
  `search_checkpoints`, `search_queries`, `search_executions`, `search_results`, `search_cache`,
  `keyword_sets`, `keyword_set_versions`, `keywords`, `timeline_events`, `timeline_jobs`,
  `timeline_checkpoints`, `timeline_revisions`, `timeline_coverage`, and `timezone_mappings`.
- Unsupported boundaries: file body FTS, Office/PDF extraction, OCR/STT, YARA, AI keyword
  recommendation, LLM/agent loops, GUI/web/MCP, report rendering, disk image internals,
  deleted/slack/unallocated search, live acquisition, credential/secret extraction, full Windows
  timezone auto-confirmation, compromise assertions, and benchmark superiority remain unimplemented.

### Phase 5 Browser and Media Trace

- Implementation: `MediaMetadataAnalyzer`, `BrowserHistoryAnalyzer`, and `MachineExtractionService`
  are registered in `build_services()` and reuse existing artifact/job/search/timeline persistence.
- Media coverage: image/video/audio source detection, JPEG EXIF/GPS raw and normalized values,
  filesystem created/modified/deleted metadata, MP4 codec/duration, optional `ffprobe` video/audio
  metadata, corrupt media warnings, `cache_entries`, and `thumbnail_records` derivative metadata.
- Browser coverage: browser profile/database artifacts plus Chromium visit/search/download rows,
  Firefox visit/download candidate rows, native timestamp normalization, SQLite Snapshot/WAL/SHM
  fingerprints, and profile/database/table/row provenance.
- Candidate coverage: immutable machine-extracted candidates, unavailable OCR/STT provider
  capabilities, stable candidate cursor pagination, append-only review events, and required
  correction text for `CORRECTED` decisions.
- Interface: existing `artifact discover/analyze/list/show/warnings` JSON commands, legacy
  `artifact media` / `artifact browser` helpers, and top-level `browser`, `media`, and `candidate`
  command groups.
- Verification: `tests/unit/test_phase5_media_browser.py` covers synthetic media metadata, audio
  capability/corrupt handling, GPS/time raw+normalized preservation, thumbnail cache rows, browser
  visit/search/download provenance queries, corrupt media/browser resilience, candidate review
  immutability, and top-level CLI smoke coverage.
- Unsupported boundaries: raster thumbnail pixel rendering, actual OCR/STT execution, Email,
  Discord, Telegram, KakaoTalk, other messenger parsers, deleted/slack/unallocated recovery, live
  browser acquisition, GUI/web/MCP, AI/LLM flows, and report rendering remain outside Phase 5.
