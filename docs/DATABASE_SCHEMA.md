# APEX SQLite Database Schema

## 1. 권위 원본과 범위

**CURRENT IMPLEMENTED SQLITE SCHEMA**의 권위 원본은 `src/apex_forensic/adapters/persistence/sqlite/repository.py::SQLiteRepository.initialize()`이다. 이 문서는 그 DDL을 요약한다. 아래 “Legacy/Conceptual” 이름은 실제 table로 오해하면 안 된다.

현재 database는 case별 SQLite adapter이며 foreign key, 단일 application writer, structured error translation과 optional FTS5를 사용한다. Runtime doctor/benchmark/release 결과를 자동 보존하는 별도 table은 없다.

## 2. 실제 Migration Marker

`schema_migrations`에 다음 marker를 idempotently 기록한다.

- `phase1-core-foundation`
- `phase2-progressive-filesystem-indexing`
- `phase3-windows-artifact-analysis`
- `phase4-search-keyword-timeline`
- `phase5-browser-media-metadata`
- `phase6-gui-context-view-interface`
- `phase7-ai-assistance-engine-contract`
- `phase8-report-review-export-contract`
- `apex-engine-work-package-a-evidence-readers`
- `apex-engine-advanced-runtime-audit`

별도 migration directory는 없다. Initialize DDL과 `_ensure_column`이 current migration mechanism이며, `jobs.job_revision`, `jobs.index_revision`, `artifact_sources.source_fingerprint`, `source_checkpoint_json`, `inspected_count`을 보강한다.

## 3. Current Implemented Tables

### 3.1 Case, Evidence, Hash, Custody

| 실제 table | 역할 |
|---|---|
| `schema_migrations` | 적용 marker |
| `cases` | case name/locale/IANA timezone/status/metadata |
| `evidence` | DIRECTORY/RAW/DD/IMG/E01/VHD/VHDX, source path, read-only flag, fingerprint |
| `evidence_volumes` | reader/version, MBR/GPT/extended/protective/superfloppy/unallocated range |
| `evidence_hashes` | MD5/SHA1/SHA256 streaming hash record |
| `hash_verifications` | expected/observed digest와 MATCH/MISMATCH/ERROR |
| `jobs` | 공통 HASH/VERIFY/INDEX/ARTIFACT/SEARCH_INDEX/TIMELINE job |
| `custody_events` | evidence별 append-only canonical hash chain |

`JobStatus`는 `QUEUED`, `RUNNING`, `PAUSING`, `PAUSED`, `RESUMING`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED`이다. Evidence 상태는 `REGISTERED`, `HASHING`, `READY`, `FAILED`이다.

Directory evidence는 등록되지만 directory manifest hash policy가 없으므로 file hash job 대상이 아니다. Unknown ordinary file은 현재 `RAW` byte-stream으로 등록된다.

### 3.2 Progressive Filesystem

| 실제 table | 역할 |
|---|---|
| `fs_providers` | provider/version/capability registry |
| `fs_nodes` | stable node, original/display/comparison path, timestamp, deleted/extents locator metadata |
| `fs_index_jobs` | profile/options/index revision/status |
| `fs_index_queue` | priority/depth/cursor/reason queue |
| `fs_index_checkpoints` | current node/path와 processed/discovered count |
| `fs_index_coverage` | COMPLETE/PARTIAL/FAILED/CANCELLED coverage와 ETA |
| `fs_scan_events` | bounded warning/error event |

`analysis_profiles`, `indexing_jobs` 같은 초기 설계 이름은 실제 table이 아니다. Profile은 current enum/options JSON으로 `fs_index_jobs`, artifact/search/timeline job table에 기록된다.

### 3.3 Artifact Runtime

| 실제 table | 역할 |
|---|---|
| `artifact_analyzers` | analyzer/backend version과 capability |
| `analyzer_option_fingerprints` | deterministic option identity |
| `artifact_analysis_jobs` | artifact job/profile/options/revision |
| `artifact_sources` | fs-node 기반 source queue/checkpoint/fingerprint |
| `artifacts` | Windows/browser/media/communication fact 또는 candidate |
| `artifact_warnings` | job/artifact warning |
| `artifact_checkpoints` | source-level resume checkpoint |
| `artifact_coverage` | analyzer/evidence coverage |

Registry deleted-cell candidate는 `artifacts`에 explicit candidate metadata와 provenance로 저장된다. 별도 current fact table로 승격되지 않는다. Event Message runtime output도 provider/analyzer artifact contract 안에서 다룬다.

### 3.4 Browser, Media, Machine Extraction와 Secret Recovery

| 실제 table | 역할 |
|---|---|
| `browser_profiles` | profile identity/platform/fingerprint |
| `browser_analysis_jobs`, `browser_checkpoints` | browser-specific job resume |
| `browser_source_revisions`, `browser_snapshot_records` | SQLite/WAL/SHM source snapshot provenance |
| `browser_artifacts` | projected browser DTO |
| `media_analysis_jobs`, `media_checkpoints` | media-specific job resume |
| `media_source_revisions` | source revision |
| `media_artifacts` | image/video/audio DTO |
| `thumbnail_records` | source-linked derived thumbnail |
| `machine_extracted_candidates` | OCR/STT candidate; observed fact 아님 |
| `candidate_review_events` | append-only review/correction |
| `provider_capabilities` | OCR/STT 등 generic provider snapshot |
| `secret_provider_capabilities` | DPAPI/NSS/Kakao capability snapshot |
| `decryption_attempts`, `decryption_results` | redacted immutable decryption provenance/result |
| `cache_entries` | derived cache metadata |

Email/Discord/Telegram은 common `artifacts` pipeline을 사용하며 별도 messenger table이 없다. KakaoTalk decrypted messages도 provider result/citation contract이며 current DDL에 독립 Kakao message table은 없다.

### 3.5 Search, Keyword와 Timeline

| 실제 table | 역할 |
|---|---|
| `search_index_metadata` | case index revision/backend |
| `search_documents` | allowlisted normalized search projection |
| `search_documents_fts` | FTS5가 있을 때 생성되는 virtual table |
| `search_jobs`, `search_checkpoints` | search index job/resume |
| `search_queries` | immutable query/filter/options identity |
| `search_executions` | backend/revision/cache/partial reproduction |
| `search_results` | ranked fixed result records |
| `search_cache` | revision-bound result cache |
| `keyword_sets`, `keyword_set_versions`, `keywords` | versioned human-controlled keyword sets |
| `timeline_revisions` | current timeline revision |
| `timeline_jobs`, `timeline_checkpoints` | build job/resume |
| `timeline_events` | raw/timezone/UTC/case-time separated events |
| `timeline_coverage` | source coverage/partial |
| `timezone_mappings` | Windows-to-IANA candidate mapping |

FTS5가 없으면 `search_documents_fts`를 만들거나 query success를 가장하지 않고 capability error를 반환한다. 한국어 검색은 NFC 사본과 `unicode61`을 사용하며 형태소 table/analyzer는 없다.

### 3.6 Context, View와 Public Interface

| 실제 table | 역할 |
|---|---|
| `gui_session_contexts` | mutable TTL live context/current revision |
| `gui_session_context_revisions` | revision history |
| `analysis_context_snapshots` | immutable context snapshot |
| `analysis_scope_contexts` | snapshot별 scope summary/page state |
| `context_snapshot_resources` | included/excluded membership |
| `context_revision_states` | expected/current revision과 stale reason |
| `view_projections`, `view_projection_cache` | Simple/Detailed/Raw projection |
| `raw_read_audit_records` | bounded raw read append-only audit |
| `engine_interface_versions` | public interface snapshot |
| `engine_tool_descriptors` | operation descriptor snapshot |

초기 `ui_context_snapshots`는 conceptual name이며 current table이 아니다. Canonical live/snapshot 분리는 `gui_session_contexts`와 `analysis_context_snapshots`다.

### 3.7 AI Assistance

| 실제 table | 역할 |
|---|---|
| `ai_assistance_requests` | snapshot-bound TTL request |
| `ai_keyword_recommendation_batches` | provider batch/result hash |
| `ai_keyword_recommendations` | immutable NOT_OBSERVED_FACT candidate |
| `ai_scope_summaries` | immutable scope summary |
| `ai_verification_events` | append-only review hash chain |
| `ai_keyword_promotions` | reviewed candidate → draft keyword-set provenance |
| `ai_provider_capabilities` | configured provider capability snapshot |

Prompt, API key, credential, chain-of-thought와 raw provider body column은 없다. 선택적 OpenAI-compatible adapter도 동일 ingest validator를 통과한다.

### 3.8 Report Runtime

| 실제 table | 역할 |
|---|---|
| `reports` | mutable aggregate header/status/active version |
| `report_versions` | immutable content fingerprint/version |
| `report_version_sections` | immutable ordered sections |
| `report_version_references` | version resource references |
| `report_review_events` | append-only review hash chain |
| `report_approval_records` | approval/rejection/revocation hash chain |
| `custody_snapshots`, `custody_snapshot_events` | version/export에 고정된 custody view |
| `report_render_packages` | approved deterministic renderer input |
| `report_export_manifests` | format/filename/status/output policy |
| `rendered_report_artifacts` | renderer/hash/size/reference metadata |
| `report_export_audit_events` | append-only export audit |
| `report_renderer_capabilities` | HTML/PDF provider snapshot |

HTML runtime은 built-in이며 PDF는 ReportLab optional dependency다. Renderer capability는 table에 snapshot될 수 있지만 dependency가 모든 host에서 available하다는 뜻은 아니다.

## 4. Immutability와 Append-only Enforcement

SQLite trigger가 UPDATE/DELETE를 차단하는 current tables:

- `analysis_context_snapshots`, `raw_read_audit_records`, `custody_events`
- `candidate_review_events`, `decryption_attempts`, `decryption_results`
- `ai_keyword_recommendations`, `ai_scope_summaries`, `ai_verification_events`, `ai_keyword_promotions`
- `report_versions`, `report_review_events`, `report_approval_records`
- `custody_snapshots`, `rendered_report_artifacts`, `report_export_audit_events`

Mutable header/status tables와 immutable content/event tables를 혼동하지 않는다. Correction/revocation은 기존 row overwrite가 아니라 새 event다.

## 5. 실제로 Persistence하지 않는 상태

다음은 runtime/tool output이지만 current SQLite DDL의 별도 table이 아니다.

- doctor host capability report
- benchmark run/measurement report와 Peak RSS
- release gate/check result
- Bandit finding disposition 결과(권위 원본은 `tools/security_findings.json`)
- Windows host semantic verification output
- external expert validation 결과

필요하면 외부 CI artifact 또는 향후 migration으로 보존해야 한다. 현재 실행 결과가 repository에 남아 있다고 가정하지 않는다.

## 6. Legacy / Conceptual Original Design

다음 이름은 초기 제품 설계와 validator compatibility를 위해 기록하지만 **CURRENT IMPLEMENTED TABLE이 아니다**.

- Case/Evidence: `evidence_sources`, `evidence_fingerprints`
- Object model: `objects`, `file_systems`, `files`, `file_extents`
- Ingest/analyzer: `ingest_jobs`, `ingest_tasks`, `analyzer_runs`, `artifact_types`, `artifact_attributes`
- Search/cache: conceptual `cache_entries`는 이름이 current와 같지만 초기 column model은 권위가 아님
- Context/annotation: `ui_context_snapshots`, `analyst_annotations`, `tags`, `tagged_items`
- Report links: `report_sections`, `report_evidence_links`, `report_artifact_links`, `report_timeline_links`, `report_search_result_links`, `report_tag_links`, `report_citations`, `report_exports`
- Index/profile: `analysis_profiles`, `indexing_jobs`, `indexing_job_scopes`, `indexing_checkpoints`, `analyzer_progress`
- Timezone/search design: `timezone_candidates`, `timezone_decisions`, `timestamp_interpretations`, `keyword_recommendations`, `keyword_set_items`, `keyword_approvals`, `search_execution_options`
- Custody design: `custody_hash_verifications`, `custody_approvals`
- Validation/product: `benchmark_runs`, `benchmark_measurements`, `external_validation_reviews`
- Historical generic AI/audit: `audit_events`, `ai_enrichments`, `schema_versions`

`search_queries`, `search_results`, `search_executions`, `keyword_sets`, `custody_events`, `custody_snapshots`, browser/media tables는 실제로도 존재하지만 current DDL/columns가 권위다. 같은 이름의 초기 conceptual layout은 superseded다.

## 7. Schema 변경 원칙

- DDL 변경은 `initialize()` 또는 명시적 migration mechanism에 추가하고 `schema_migrations` marker를 기록한다.
- 문서만으로 table/column을 발명하지 않는다.
- forensic immutable row를 update하는 migration을 만들지 않는다.
- optional runtime/release result persistence가 필요하면 별도 migration과 retention/privacy policy를 먼저 정의한다.
