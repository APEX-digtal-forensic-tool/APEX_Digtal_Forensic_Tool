# Phase 1 Implementation Decisions

## Scope

This document records design and implementation conflicts found while implementing Phase 1 Core
Foundation. The implementation keeps Phase 2+ behavior out of runtime code.

## Decisions

| Topic | Conflict | Phase 1 decision | Follow-up |
|---|---|---|---|
| Python package name | `DIRECTORY_STRUCTURE.md` shows `src/apex`, while the Phase 1 goal and CLI entry point require `apex_forensic`. | Use `src/apex_forensic` and `apex-forensic = apex_forensic.cli:main`. | Align directory documentation in a later documentation pass. |
| Design validator and `src` | Phase 0 validators rejected any `src` directory, but Phase 1 requires executable Python code. | Validators now reject `mcp` and `prompts`, but allow `src`. | Keep MCP/LLM/prompt scans in future packaging checks. |
| SHA-1 support | Phase 1 requires MD5, SHA-1, and SHA-256, while the original hash schema omitted SHA-1. | Add `SHA1` as an additive schema enum value in evidence and custody hash contracts. | Confirm whether SHA-512 remains needed before API v1 stabilization. |
| SQLite table names | `DATABASE_SCHEMA.md` uses names such as `evidence_sources` and `ingest_jobs`; the Phase 1 goal names minimum implementation tables such as `evidence`, `jobs`, and `hash_verifications`. | Implement the Phase 1 minimum table names and keep repository boundaries so later migrations can map to the full design. | Reconcile table naming before Phase 2 migrations. |
| Logical file evidence | The schema has `DIRECTORY`, `RAW`, `E01`, `VHD`, and `VHDX`, but Phase 1 must register ordinary files. | Register ordinary logical files as byte-stream `RAW` evidence with metadata noting no filesystem parsing. | Add a dedicated logical-file format if API clients need the distinction. |
| Directory hashing | Directory evidence registration is required, but no canonical directory hash policy is designed. | Register directory metadata only. Hash requests return `CAPABILITY_UNAVAILABLE`. | Define a manifest hash policy in a later phase. |
| Custody legal effect | Chain hash fields are implemented, but legal evidence status is policy-dependent. | Implement append-only events, correction events, and hash-chain verification without claiming legal evidentiary effect. | Add signature/approval policy only after backend/legal requirements are finalized. |
| Shell validator line endings | `validate_design.sh` had CRLF line endings, causing Bash to fail on `pipefail`. | Normalize the script to LF without changing validator logic. | Keep shell scripts LF-normalized. |

## Phase 2 Implementation Decisions

- Reused the existing `Job` model and `jobs` table for INDEX jobs, adding job/index revision fields instead of creating a parallel job model.
- Kept SQLite as the single writer. Providers return domain nodes/issues; they do not write directly to SQLite.
- Used deterministic provider node IDs derived from case/evidence/provider/version/relative path so resume and repeated indexing avoid duplicate nodes.
- Extended `file.schema.json` with filesystem node/page definitions rather than adding a new schema file, because the existing file contract is the closest public data contract for file tree entries.
- Used separate `comparison_path` and cursor fingerprints for search/pagination while preserving original names and relative paths unchanged.
- Returned `CAPABILITY_UNAVAILABLE` for disk image internal traversal until native providers are implemented.
- ETA remains `null` with `UNKNOWN` confidence when there is insufficient total-work evidence.

## Phase 3 Implementation Decisions

| Decision | Rationale | Result |
|---|---|---|
| Artifact model uses explicit Phase 3 fields plus compatibility aliases | The goal requires `artifact_id`, `source_file_node_id`, parser backend/version, parse status, raw locator, citations, and partial state, while earlier docs referenced `id`/`payload`/`provenance`. | `ArtifactRecord.to_schema_dict()` emits required Phase 3 fields and compatibility aliases without weakening validation. |
| `.reg`, Event XML, and minimal Prefetch parsers are local adapters | These formats can be handled safely with bounded standard-library parsing and synthetic fixtures. | Core tests do not require optional binary parser packages or external fixtures. |
| Binary Registry/EVTX support is capability-first | Full binary parsers should use maintained libraries and stay isolated in adapters. | `python-registry` and `python-evtx` are optional dependencies; absence returns `CAPABILITY_UNAVAILABLE`/`UNSUPPORTED`. |
| Artifact discovery reuses `fs_nodes` only | Phase 3 must not rescan directories or access paths not represented by the Phase 2 index. | `ArtifactAnalysisService` discovers candidates from stored nodes and validates local paths under the evidence root before parsing. |
| Item budget is applied at source boundaries | The MVP does not implement source-internal parser cursors for `.reg` sections or EVTX record offsets. | Resume remains deterministic; a single source may emit more artifacts than the requested budget, then the job pauses before the next source. |
| Logical raw locators may have null byte offsets | Registry keys/values and XML records often have logical provenance without parser-exposed byte offsets. | `citation.schema.json` allows `offset`/`length` to be null and records `locator_type`, `limitations`, and details. |
| New Windows artifact schema stays in `artifact.schema.json` | The common artifact contract is shared by Registry, Event Log, and Prefetch records. | No additional Windows-only schema file was needed for Phase 3. |

## Phase 4 Implementation Decisions

| Decision | Rationale | Result |
|---|---|---|
| Search uses SQLite FTS5 only when capability is present | Returning fake search success without FTS5 would make forensic reproduction misleading. | `search_capability()` probes FTS5 and SearchService raises `CAPABILITY_UNAVAILABLE` when unavailable. |
| File body full text indexing is excluded | Phase 4 scope is stored metadata and artifact fields only. | Search documents are built from `fs_nodes`, `artifacts`, and optional `timeline_events`; no original evidence body reads are performed. |
| Search field input is allowlisted | Large JSON blobs and unbounded arbitrary metadata are unsafe and noisy. | Filesystem provider metadata and artifact fields are projected through explicit allowlists with bounded string/list sizes. |
| Application service depends on SearchIndexProvider | The application layer must not depend on SQLite FTS SQL. | FTS query construction and virtual table operations live in `SQLiteRepository`; SearchService uses provider methods. |
| Regex metadata search uses bounded candidates | Unlimited regex over all DB rows can be unsafe. | Regex mode applies case/evidence/type/path/time filters first and scans at most a bounded candidate page. |
| Keyword set edits create versions | Reproduction needs the exact keyword set used by a search. | Active and draft edits produce a new version row; older versions remain queryable. |
| Cache does not replace reproduction | Cache hits still need auditable search execution records. | Every query creates a new Search Query/Execution row; cached hits are copied into the new result record set. |
| Raw/UTC/case timeline times are separate fields | Original timestamps must not be overwritten or silently reinterpreted. | Timeline events persist raw timestamp/timezone, normalized UTC when justified, case display time, source/confidence, semantics, and precision. |
| Windows timezone mapping is candidate-only | TimeZoneKeyName is not enough to confirm every IANA zone automatically. | Phase 4 stores candidate mapping support but does not auto-confirm broad Windows timezone decisions. |
| Search and Timeline schemas were expanded in existing files | They are core Phase 4 DTOs, not separate product-specific schemas. | `search.schema.json` and `timeline-event.schema.json` were replaced with Phase 4 DTO definitions. |

## Phase 5 Implementation Decisions

| Decision | Rationale | Result |
|---|---|---|
| Media parsing stays metadata-only and bounded | Phase 5 needs image/video/audio classification, EXIF/GPS, codec, duration, and time preservation without full decode risk. | `MediaMetadataAnalyzer` parses safe image headers and MP4 boxes, streams hashes, limits reads, uses optional `ffprobe` for video/audio, and reports unavailable/corrupt states instead of faking success. |
| Thumbnail support is derivative metadata first | The design requires source-linked thumbnails, but raster rendering backends are optional and should not run automatically. | `cache_entries` and `thumbnail_records` store deterministic `THUMBNAIL` derivative metadata keyed by source SHA-256; original media is not modified. |
| Browser MVP uses snapshot SQLite readers | Browser history/search/download evidence is commonly SQLite and may require WAL/SHM state for a consistent read. | `BrowserHistoryAnalyzer` creates safe `/tmp` snapshots, preserves WAL/SHM hashes, uses read-only SELECTs with table introspection, and records profile/database/table/row provenance. |
| Candidate review is implemented without OCR/STT execution | OCR/STT output must stay provider-neutral and cannot become observed fact automatically. | `MachineExtractionService` persists unavailable OCR/STT capabilities, immutable candidates, append-only review events, and requires correction text for `CORRECTED`. |
| Corrupt media/browser sources produce partial facts | One damaged file or SQLite database must not stop the whole artifact job. | Damaged media and browser DBs return `CORRUPT`/`UNSUPPORTED` artifacts with warnings; the coordinator continues remaining sources and marks coverage partial. |
| Email and messengers remain plugin scope | The Phase 5 roadmap explicitly excludes Email, Discord, Telegram, KakaoTalk, and other messengers from completion criteria. | No messenger parser is registered in core; browser cache bodies, passwords, deleted records, and cloud sync stay unsupported. |

## Phase 6 Implementation Decisions

| Decision | Rationale | Result |
|---|---|---|
| Live context and immutable snapshots use separate tables | GUI state changes frequently, while AI/report context needs reproducible evidence bundles. | `gui_session_contexts` remains mutable until TTL expiry; `analysis_context_snapshots` is append-only and content-fingerprinted. |
| Context fingerprints exclude transient provenance | Snapshot IDs, creation timestamps, actor IDs, and previous links should not change the hash of equivalent selected evidence. | Equivalent resolved context produces stable SHA-256 fingerprints while previous-snapshot lineage is stored separately. |
| Raw reads are service-level bounded operations | Raw View must not load full evidence files or bypass case/evidence validation. | `SafeRawRangeReader` enforces root containment, offset/length limits, logical locator rules, EOF behavior, and audit records. |
| MCP is represented as an adapter boundary only | Core Phase 6 must expose contracts without coupling to a transport, prompts, or provider credentials. | `EngineInterfaceService` publishes version/capability/tool descriptors and structured responses; no MCP server or LLM code is imported. |
| Scope paging uses persisted resource membership | Large analysis contexts should not require reserializing a full snapshot for every page. | Snapshot and scope resource tables preserve included/excluded resource IDs for bounded pagination and stale-source refresh. |

## Phase 7 Implementation Decisions

| Decision | Rationale | Result |
|---|---|---|
| AI Assistance is snapshot-first | AI output must be reproducible against the exact context the external adapter saw. | `AiAssistanceRequest` stores snapshot ID, source revision fingerprint, coverage, citations, TTL, and a deterministic request fingerprint. |
| Provider output is never trusted directly | A future adapter may have different models or providers, but the engine must enforce one forensic contract. | Provider results and CLI JSON ingestion both pass through the same keyword/summary validators before persistence. |
| AI results are not observed facts | AI text can assist analysis but must not modify artifacts, timeline events, filesystem nodes, or evidence. | Keyword recommendations and summaries store `NOT_OBSERVED_FACT` and remain in AI tables with citations and provenance warnings. |
| Review is append-only | Analyst acceptance, rejection, and correction need an auditable history. | `ai_verification_events` records revision, actor, reason, previous hash, and event hash; original AI result rows are not overwritten. |
| Keyword promotion reuses existing set versioning | Search reproduction already depends on keyword-set versions. | Accepted/corrected recommendations create draft keyword-set versions with AI provenance and do not execute search or activate the set. |
| Runtime AI execution remains outside core | Phase 7 is an engine contract, not an LLM integration phase. | The default provider returns `CAPABILITY_UNAVAILABLE`; no MCP SDK, LLM SDK, prompt, API-key, chain-of-thought, or network provider code is added. |

## Phase 8 Implementation Decisions

| Decision | Rationale | Result |
|---|---|---|
| Reports use a mutable aggregate header plus immutable versions | Workflow state and active-version pointers change, but report content must remain reviewable and reproducible. | `reports` stores the header; `report_versions` and section/reference tables are append-only and content-fingerprinted. |
| Content fingerprints exclude sequence metadata | Idempotent draft replay should not create a new version solely because the current active pointer changed. | Fingerprints cover content, source kind, citations, references, limitations, coverage, and source revisions while version number and previous-version link are stored separately. |
| AI draft ingest is validation-only | Phase 8 must not generate report text or persist prompts/raw provider bodies. | `ingest_ai_draft()` requires an existing assistance request, stores provider metadata/response hash only, and marks source kind `AI_DRAFT`. |
| Review and approval are append-only hash chains | Report decisions need audit history and optimistic-lock conflict detection. | `report_review_events` and `report_approval_records` store sequential revisions, previous hashes, and event hashes with update/delete triggers. |
| Approval requires custody verification | Exporting an approved report should not hide broken custody metadata. | Approval creates or checks a custody snapshot and blocks when verification is not `VERIFIED`. |
| Export is a contract, not rendering | PDF/HTML rendering dependencies and command execution are outside the engine boundary. | `ReportRendererPort` exists, default capability is `CAPABILITY_UNAVAILABLE`, and only metadata returned through service validation is persisted. |
