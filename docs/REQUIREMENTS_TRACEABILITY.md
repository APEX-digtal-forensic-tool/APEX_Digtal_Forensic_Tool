# APEX Requirements Traceability

## 1. Reading This Matrix

This matrix maps current requirements to Architecture, Module Owner, API, Database, Schema, Phase, and concrete 검증 evidence. Status terms are deliberately narrow:

- **IMPLEMENTED / TESTED**: code and repository tests cover the stated contract.
- **IMPLEMENTED / CAPABILITY-GATED**: the code path exists but the current host/dependency/configuration decides availability.
- **CONTRACT ONLY**: schema/service contract exists; an external product transport is not implemented here.
- **EXTERNAL VERIFICATION REMAINING**: synthetic or unit evidence exists, but representative licensed fixtures, target hosts, expert review, or retained benchmark results are still required.
- **UNSUPPORTED**: explicitly outside the current implementation.

A passing unit test does not establish legal admissibility, universal file-format support, a clean security report, or superiority over another forensic product.

## 2. Core, Evidence, and Indexing

| ID | Requirement | Architecture | Module Owner | API | Database | Schema | Phase | Status / 검증 |
|---|---|---|---|---|---|---|---|---|
| CORE-001 | Create/list/get a case with locale and IANA timezone | Core/application | Case Service | CLI `case create`, `case list` | `cases` | `case.schema.json` | 1 | IMPLEMENTED / TESTED — `test_case_manager.py`, `test_sqlite_workflow.py` |
| CORE-002 | Register evidence read-only and stream SHA-256 for supported file inputs | Evidence plane | Evidence Service | CLI evidence add/hash/verify | `evidence`, `evidence_hashes`, `hash_verifications` | `evidence.schema.json` | 1 | IMPLEMENTED / TESTED — `test_evidence_manager.py`, `test_hashing.py` |
| CORE-003 | Preserve append-only custody events and verify their hash chain | Audit plane | Chain of Custody Ledger | Engine/CLI custody operations; planned `/cases/{case_id}/evidence/{evidence_id}/custody-events` | `custody_events` | `chain-of-custody.schema.json` | 1/8 | IMPLEMENTED / TESTED — `test_custody_and_schema.py`, `test_phase8_report_contract.py` |
| CORE-004 | Read RAW/DD/IMG and probe partitions without writing evidence | Evidence plane | Evidence Image Service | CLI `evidence volumes`, `evidence read-range`, `evidence unallocated-ranges`, `evidence export-range` | `evidence_volumes` | `evidence.schema.json`, `provider-capability.schema.json` | 9 | IMPLEMENTED / TESTED — `test_evidence_readers.py` |
| CORE-005 | Support E01, VHD, and VHDX only when their providers are available | Capability plane | Evidence reader adapters | Engine capability descriptor; doctor | capability snapshot, no dedicated reader table | `provider-capability.schema.json` | 9 | IMPLEMENTED / CAPABILITY-GATED — `test_evidence_readers.py`, `test_doctor_capabilities.py` |
| CORE-006 | Treat directory evidence as bounded metadata-only input and unknown ordinary files as RAW | Evidence plane | Evidence Service | CLI evidence add | `evidence` | `evidence.schema.json` | 1/9 | IMPLEMENTED / TESTED — `test_evidence_manager.py` |
| IDX-001 | Index NTFS/FAT/exFAT/ext2/3/4 through pytsk when available | Progressive analysis plane | Progressive Indexing Coordinator | CLI `evidence index` and `fs roots/list/show`; planned `/cases/{case_id}/index-jobs` | `fs_nodes`, `fs_providers`, `fs_index_jobs` | `analysis-profile.schema.json`, `file.schema.json` | 2/9 | IMPLEMENTED / CAPABILITY-GATED — `test_image_filesystem_provider.py` |
| IDX-002 | Provide QUICK_TRIAGE, SELECTED_SCOPE, FULL_ANALYSIS, CUSTOM profiles | Progressive analysis plane | Analysis Profile Manager | planned `/cases/{case_id}/analysis-profiles` | profile/options in `fs_index_jobs` and job tables | `analysis-profile.schema.json` | 2 | IMPLEMENTED / TESTED — `test_file_system_indexing.py` |
| IDX-003 | Queue, prioritize, checkpoint, pause, resume, cancel, and expose partial coverage | Progressive analysis plane | Priority Job Scheduler; Progress Estimator | CLI `evidence index-status/index-resume/index-cancel` and `fs prioritize`; planned pause/resume/cancel/priority/progress/partial-results routes | `fs_index_queue`, `fs_index_checkpoints`, `fs_index_coverage` | `job.schema.json` | 2 | IMPLEMENTED / TESTED — `test_filesystem_indexing_workflow.py` |
| IDX-004 | Export bounded raw/unallocated/slack ranges and recover a stored run | Recovery plane | Raw Evidence Locator; indexing service | CLI raw/slack/export/recover | job/checkpoint/source records and `raw_read_audit_records` | `raw-read-request.schema.json`, `raw-read-response.schema.json` | 9 | IMPLEMENTED / TESTED — `test_release_hardening_recovery.py`; complete file recovery is not claimed |

## 3. Windows, Browser, Communications, and Media

| ID | Requirement | Architecture | Module Owner | API | Database | Schema | Phase | Status / 검증 |
|---|---|---|---|---|---|---|---|---|
| CORE-007 | Parse Registry text fixtures and optional binary hives/transaction replay | Artifact plane | Windows Registry Analyzer | CLI artifacts analyze | `artifacts`, artifact job/coverage tables | `artifact.schema.json` | 3 | IMPLEMENTED / CAPABILITY-GATED — `test_windows_artifacts.py`; representative host/fixture verification remains |
| CORE-008 | Carve bounded free/slack NK/VK Registry candidates | Artifact plane | Registry Deleted Cell Carver | analyzer operation | candidates in `artifacts` | `registry-deleted-candidate.schema.json` | 9 | IMPLEMENTED / TESTED — `test_registry_deleted_cell_carving.py`; candidate, not recovered fact |
| CORE-009 | Parse bounded XML and optional binary EVTX; render messages only with host resources | Artifact plane | Windows Event Log Analyzer/Renderer | analyzer operation; doctor capability | `artifacts` | `artifact.schema.json`, `provider-capability.schema.json` | 3/9 | IMPLEMENTED / CAPABILITY-GATED — `test_windows_artifacts.py`; Windows host semantic verification remains |
| CORE-010 | Parse Prefetch 17/23/26/30 with optional MAM decompression | Artifact plane | Windows Prefetch Analyzer | analyzer operation | `artifacts` | `artifact.schema.json` | 3 | IMPLEMENTED / CAPABILITY-GATED — `test_windows_artifacts.py` |
| CORE-011 | Extract Chromium/Firefox history/search/download/cookie/credential metadata from safe snapshots | Artifact plane | Browser Analyzer | CLI browser analysis | `browser_profiles`, `browser_snapshot_records`, `browser_artifacts` | `browser-profile.schema.json`, `browser-artifact.schema.json` | 5 | IMPLEMENTED / TESTED — `test_phase5_media_browser.py` |
| CORE-012 | Report browser freelist/WAL/cache/private candidates without claiming recovered deleted rows | Artifact plane | Browser Analyzer | browser result contract | `browser_artifacts` | `browser-artifact.schema.json` | 5/9 | IMPLEMENTED WITH LIMITATIONS — `test_phase5_media_browser.py` |
| COMM-001 | Parse MBOX plus the defined Discord/Telegram SQLite fixture contract | Artifact plane | Communication Core Plugin | CLI artifact analysis | common `artifacts` pipeline | `artifact.schema.json` | 5/9 | IMPLEMENTED WITH LIMITATIONS — `test_communication_artifacts.py`; PST/OST, LevelDB, tdesktop unsupported |
| COMM-002 | Discover and optionally decrypt bounded Windows KakaoTalk 2.0.8.990 stores using external key/IV | Secret/artifact plane | KakaoTalk Provider | CLI artifact/decryption operations | `artifacts`, `decryption_attempts`, `decryption_results` | `kakaotalk-artifact.schema.json`, `decryption-request.schema.json` | 9 | IMPLEMENTED / EXTERNAL VERIFICATION REMAINING — `test_kakaotalk_runtime.py`; automatic key acquisition false, real fixture not verified |
| MEDIA-001 | Extract EXIF/GPS, image dimensions, MP4 metadata and create derived thumbnails/frames | Artifact plane | Media Analyzer | CLI `media analyze` and `media thumbnail` | `media_artifacts`, `thumbnail_records` | `media-artifact.schema.json`, `thumbnail.schema.json` | 5/9 | IMPLEMENTED / CAPABILITY-GATED — `test_phase5_media_browser.py` |
| MEDIA-002 | Run OCR/STT through optional local providers and retain reviewable candidates | Machine extraction plane | Machine Extraction Port; Media Extraction Candidate Store | CLI OCR/STT; planned media/machine extraction jobs | `machine_extracted_candidates`, `candidate_review_events`, provider capability tables | `machine-extraction-request.schema.json`, `machine-extraction-result.schema.json`, `machine-extracted-candidate.schema.json` | 9 | IMPLEMENTED / CAPABILITY-GATED — `test_advanced_runtime_machine_extraction.py` |
| CORE-013 | Attempt DPAPI, Firefox NSS, and external-key Chromium decryption without persisting secrets | Secret plane | Secret Provider adapters | CLI secret/decrypt operations | `secret_provider_capabilities`, immutable decryption attempt/result rows | `dpapi-key-source.schema.json`, `nss-profile.schema.json`, secret/decryption schemas | 9 | IMPLEMENTED / CAPABILITY-GATED — `test_advanced_runtime_decryption.py` |

## 4. Search, Time, Context, and Views

| ID | Requirement | Architecture | Module Owner | API | Database | Schema | Phase | Status / 검증 |
|---|---|---|---|---|---|---|---|---|
| KW-001 | Support TERM, PHRASE, PREFIX, EXACT, REGEX_METADATA with reproducible options | Search plane | Search Service; Search Reproduction Manager | CLI search; planned `/cases/{case_id}/search-executions/{execution_id}/rerun` | `search_queries`, `search_executions`, `search_results`, `search_cache` | `search.schema.json` | 4 | IMPLEMENTED / TESTED — `test_phase4_search_timeline.py` |
| KW-002 | Manage versioned keyword sets and reviewed AI promotion | Search/AI boundary | Keyword Set Manager; Keyword Recommendation Port | CLI keyword operations; planned keyword recommendation/set routes | `keyword_sets`, `keyword_set_versions`, `keywords`, `ai_keyword_promotions` | keyword and AI recommendation schemas | 4/7 | IMPLEMENTED / TESTED — phase 4/7 unit and CLI workflows |
| LOC-001 | Normalize Unicode with NFC/casefold/slash rules and canonical Hangul composition | Canonical domain boundary | Localization | search/index operations | normalized fields in search/filesystem tables | `search.schema.json` | 4 | IMPLEMENTED / TESTED — `test_phase4_search_timeline.py` and release Unicode gate; morphology not implemented |
| TZ-001 | Preserve raw time while adding UTC, IANA timezone, confidence, precision, and partial state | Timeline plane | Timezone Resolver; Timestamp Normalizer | timeline CLI; planned timezone detect/candidates and timestamp-interpretations routes | `timeline_events`, `timezone_mappings` | `timeline-event.schema.json` | 4 | IMPLEMENTED / TESTED — `test_phase4_search_timeline.py` |
| CTX-001 | Maintain TTL session context with optimistic `expected_revision` | Context plane | Context Service | Engine/CLI context operations; planned `/sessions/{session_id}/ui-context` | `gui_session_contexts`, revisions/states | `gui-session-context.schema.json`, `context-revision-state.schema.json` | 6 | IMPLEMENTED / TESTED — `test_phase6_context_views.py`, `test_phase6_cli_workflow.py` |
| CTX-002 | Create immutable analysis snapshots and bounded resource scopes | Context plane | Context Service | planned context-snapshots and analysis-bundle routes | `analysis_context_snapshots`, `analysis_scope_contexts`, `context_snapshot_resources` | `analysis-context-snapshot.schema.json`, `analysis-scope-context.schema.json` | 6 | IMPLEMENTED / TESTED — `test_phase6_context_views.py` |
| VIEW-001 | Project Simple/Detailed/Raw views without changing forensic facts | View plane | View Projection Service | Engine/CLI view operations | `view_projections`, `view_projection_cache` | `view-projection.schema.json`, `raw-view.schema.json` | 6 | IMPLEMENTED / TESTED — `test_phase6_context_views.py` |
| VIEW-002 | Bound raw reads to default 4 KiB/max 1 MiB and audit them immutably | View/audit plane | Raw Evidence Locator | planned file/artifact/raw-range routes | `raw_read_audit_records` | `raw-read-request.schema.json`, `raw-read-response.schema.json` | 6 | IMPLEMENTED / TESTED — `test_phase6_context_views.py` |
| AUD-001 | Keep analyst annotations/tags distinct from extracted facts | Product/context boundary | Annotation/Tag | planned product mutation API | no current table; `analyst_annotations`, `tags`, `tagged_items` are legacy conceptual names | legacy analysis-context/AI compatibility schemas | Product | CONTRACT ONLY — current context can carry references, but no dedicated annotation/tag service exists |

## 5. AI, Reports, and Public Interface

| ID | Requirement | Architecture | Module Owner | API | Database | Schema | Phase | Status / 검증 |
|---|---|---|---|---|---|---|---|---|
| AI-001 | Keep AI provider-neutral, unavailable by default, and bind output to immutable context | AI assistance plane | AI Assistance Service | CLI AI operations | AI request/recommendation/summary/verification/promotion tables | granular `ai-*.schema.json` | 7 | IMPLEMENTED / TESTED — `test_phase7_ai_assistance.py`, `test_phase7_cli_workflow.py` |
| AI-002 | Optionally call an OpenAI-compatible endpoint without storing prompts/API keys/raw bodies/CoT | Optional provider boundary | AI Provider Port | provider config/capability operation | redacted capability/execution metadata only | provider config/capability/execution schemas | 9 | IMPLEMENTED / CAPABILITY-GATED — `test_advanced_runtime_ai_provider.py` |
| AI-003 | Prevent AI, OCR, or STT candidates from becoming Observed Facts without review | Review boundary | AI Assistance Service; Machine Extraction Service | verification/review operations | immutable candidate and review/promotion events | AI verification/promotion and machine candidate schemas | 7/9 | IMPLEMENTED / TESTED — AI and machine-extraction unit tests |
| RPT-001 | Version reports immutably with sections/references and hash-chained review decisions | Report plane | Report Module | CLI report operations; planned report/generate-draft/request-review/approve/reject routes | `reports` plus version/section/reference/review/approval tables | granular report record/version/section/review/approval schemas | 8 | IMPLEMENTED / TESTED — `test_phase8_report_contract.py`, `test_phase8_cli_workflow.py` |
| RPT-002 | Require approval and a custody snapshot before final export | Report/audit plane | Report Module; Chain of Custody Ledger | planned report export route | custody snapshot, render package, export manifest/audit tables | custody snapshot, render package, export manifest schemas | 8 | IMPLEMENTED / TESTED — `test_phase8_report_contract.py` |
| RPT-003 | Render built-in HTML and optional PDF with collision/permission/hash/magic checks | Renderer boundary | Report Renderer | CLI render/export | `rendered_report_artifacts`, `report_renderer_capabilities` | report renderer/request/result/artifact schemas | 8/9 | IMPLEMENTED / CAPABILITY-GATED — `test_advanced_runtime_report_secret.py`; PDF requires ReportLab |
| MCP-001 | Expose one stable Engine Interface for product transports | Public interface plane | Engine Interface plus external `apex_mcp` adapter | in-process/CLI version `1.0.0`, MCP stdio and authenticated Streamable HTTP | `engine_interface_versions`, `engine_tool_descriptors` | `engine-interface.schema.json`, `engine-tool-descriptor.schema.json` plus MCP invocation schemas | 6/9/M8 | IMPLEMENTED / TESTED — 52 Tool allowlist, clean wheel console, stdio/HTTP, Inspector strict and Windows CI matrix; hosted Windows run evidence remains external |
| CORE-014 | Keep planned REST endpoints transport-only over the Engine Interface | Product integration boundary | Future backend adapter | paths documented in `API_INTERFACE.md` | no HTTP persistence layer | `api-response.schema.json` and operation schemas | Product | CONTRACT ONLY — no FastAPI/Flask/server runtime in repository |

## 6. Runtime, Performance, Security, and External Validation

| ID | Requirement | Architecture | Module Owner | API | Database | Schema | Phase | Status / 검증 |
|---|---|---|---|---|---|---|---|---|
| PERF-001 | Run deterministic Quick/Full cold/warm benchmarks with throughput and Peak RSS | Runtime hardening | Benchmark Runner | CLI `benchmark` | not persisted by current DDL | tool JSON output, not a `schemas/v1` contract | 9 | IMPLEMENTED / TESTED — `test_benchmark_harness.py`; no comparative superiority claim |
| AUD-002 | Probe exact host capabilities and distinguish unavailable/configuration/unsupported/blocked/host-verification states | Runtime hardening | Capability Registry | CLI `doctor`, Engine descriptor | optional capability snapshots only | provider capability schemas | 9 | IMPLEMENTED / TESTED — `test_doctor_capabilities.py` |
| COC-001 | Freeze custody snapshots for approved report versions and exports | Audit/report boundary | Custody Verification Service | custody/report operations | `custody_snapshots`, `custody_snapshot_events` | `custody-snapshot.schema.json` | 8 | IMPLEMENTED / TESTED — phase 8 report tests |
| VAL-001 | Run design, runtime, recovery, pytest, Ruff, mypy, Bandit, benchmark, CLI, Unicode, and portable MCP gates | Release hardening | Release Gate | developer tool, not product API | not persisted by current DDL | schemas are inputs, no release-result schema | 9/M8 | IMPLEMENTED — full Engine gate plus `--mcp-only` CI scope; actual release and hosted Windows run artifacts must be retained externally |
| VAL-002 | Classify known security findings without claiming a clean scan | Release hardening | Security Gate | developer tool | not persisted | `tools/security_findings.json` | 9/M8 | IMPLEMENTED — current manifest classifies 44 medium findings, including the explicit authenticated MCP non-loopback bind mode; disposition must be reviewed per release |
| VAL-003 | Validate representative licensed evidence on target hosts with expected results and false-positive/negative analysis | External validation | External Validation Plan | external process | no current `external_validation_reviews` table | future validation artifact | External | EXTERNAL VERIFICATION REMAINING |
| VAL-004 | Verify Windows message resources, DPAPI/NSS providers, and optional native dependencies on supported hosts | External validation | External Validation Plan plus provider owners | doctor/provider tests | capability snapshots when invoked | provider/secret capability schemas | External | EXTERNAL VERIFICATION REMAINING |
| VAL-005 | Verify genuine supported KakaoTalk store semantics and version assumptions | External validation | External Validation Plan plus KakaoTalk Provider | provider fixture run | decryption attempt/result records when invoked | `kakaotalk-artifact.schema.json` | External | BLOCKED_EXTERNAL_FIXTURE / `real_kakaotalk_fixture_verified=false` |
| VAL-006 | Retain representative benchmark and release-gate artifacts for a release decision | Release process | Release owner | external CI/artifact store | no current benchmark/release result tables | tool outputs | External | PRODUCT/RELEASE INTEGRATION REMAINING |

## 7. Explicitly Unsupported or Deferred Scope

| ID | Requirement disposition | Architecture | Module Owner | API | Database | Schema | Phase | Status / 검증 |
|---|---|---|---|---|---|---|---|---|
| COMM-003 | PST/OST, Discord LevelDB, Telegram tdesktop are not current parsers | Artifact plane | Communication analyzers | none | none | none | Future | UNSUPPORTED |
| MEDIA-003 | OCR/STT model download is not automatic | Machine extraction plane | Provider adapters | local configured provider only | provider capability snapshot | provider schemas | 9 | BY DESIGN |
| KW-003 | Korean morphological analysis is not implemented | Search plane | Localization/Search | no morphology option | no morphology table | none | Future | UNSUPPORTED |
| CORE-015 | Complete deleted/unallocated file recovery is not claimed | Recovery plane | Evidence/indexing owners | bounded export/stored-run recovery only | current index/audit state | raw-read schemas | Future | UNSUPPORTED BEYOND CURRENT BOUNDED CONTRACT |
| COMM-004 | KakaoTalk Android/iOS and automatic key acquisition are not supported | Secret/artifact plane | KakaoTalk Provider | none | none | none | Future | UNSUPPORTED |
| RPT-004 | Legal admissibility and product-comparison conclusions are not automated outputs | Governance boundary | External expert/product owner | none | none | none | External | OUTSIDE AUTOMATED VERIFICATION |

## 8. 소유권 중복 검사

The ownership matrix and this traceability table enforce the following checks:

1. CLI, a future REST adapter, GUI, or MCP adapter calls the Engine Interface instead of SQLite/analyzers directly.
2. SQLite persists records but does not decide artifact meaning, AI truth, report approval, or host capability.
3. An analyzer emits facts or explicitly labeled candidates; candidate review/promotion belongs to application services.
4. Report rendering does not grant approval, and approval does not fabricate renderer availability.
5. Capability probes describe the current host; schemas describe valid shapes; tests describe only covered scenarios.
6. Product identity/RBAC/billing remains separate from forensic evidence, provenance, custody, and report semantics.

No duplicate requirement ID is intentional. A future requirement must add a unique prefix/number and update its implementation, schema/database implications, tests, and status together.
