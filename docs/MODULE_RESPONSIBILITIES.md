# APEX Module Responsibilities

## 1. Ownership Rule

This document assigns one primary owner to each forensic behavior. A module may call another through a port or service, but it must not duplicate that module's validation, persistence, capability, or audit policy.

The implemented package root is `src/apex_forensic`. Product-shell concerns such as HTTP routing, GUI widgets, identity, RBAC, tenancy, billing, and an MCP server are outside this repository unless a future adapter is added explicitly.

## 2. Layer Boundaries

| Layer | Owns | Must not own |
|---|---|---|
| `domain/models` | immutable/value-oriented domain records and enums | SQLite, subprocess, filesystem, HTTP |
| `ports` | provider/repository protocols and capability/result boundaries | concrete dependencies or host probing |
| `application/services` | use-case orchestration, invariants, review/audit decisions | third-party API mechanics or UI state |
| `adapters` | SQLite, evidence readers, analyzers, renderers, optional providers | product policy or cross-use-case orchestration |
| `runtime` | host capability probes and deterministic benchmark runner | feature availability promises independent of probes |
| `config` | explicit service composition | hidden global service location |
| `cli` | argument parsing and command dispatch | direct database/analyzer shortcuts around services |
| `schemas/v1` | exchange-contract shapes | business execution or persistence behavior |
| `tools` | repository validation and release-gate orchestration | runtime product behavior |

## 3. Core Application Owners

| Responsibility name | Implemented owner | Inputs/outputs and constraints |
|---|---|---|
| Case Service | `CaseManager` | create/list/get cases and enforce case existence |
| Evidence Service | `EvidenceManager` | register evidence, stream SHA-256, record verification and custody effects |
| Evidence Image Service | `EvidenceImageService` | select reader, probe partitions, enumerate supported filesystem content |
| Progressive Indexing Coordinator | `FileSystemIndexService` | QUICK_TRIAGE/SELECTED_SCOPE/FULL_ANALYSIS/CUSTOM scans, cursor/checkpoint, pause/resume/cancel, partial status |
| Analysis Profile Manager | `FileSystemIndexService` plus profile models/repository methods | validates profile and bounded scope; profile persistence belongs to SQLite |
| Priority Job Scheduler | service/repository queue fields and CLI operations | priority/order state; no separate distributed scheduler exists |
| Progress Estimator | file/artifact/search run state and `jobs/progress.py` | estimated versus exact progress must be labeled |
| Artifact Analysis Service | `ArtifactAnalysisService` | analyzer selection, bounded runs, issues, candidate persistence |
| Search Service | `SearchService` | FTS5 indexing, five query modes, keyword sets, reproduction, cache |
| Timeline Service | `TimelineService` | source event collection and raw/UTC/timezone/confidence/precision normalization |
| Context Service | `ContextService` | GUI/session context, eight-hour TTL, optimistic revision, immutable snapshots |
| View Projection Service | `ViewProjectionService` | Simple/Detailed/Raw projections without changing underlying facts |
| Raw Evidence Locator | `SafeRawRangeReader` | bounded reads with provenance and immutable audit records |
| Chain of Custody Ledger; Custody Verification Service | `CustodyLedger` | append-only custody events, hash-chain verification, snapshots |
| Machine Extraction Service | `MachineExtractionService` | OCR/STT candidate workflow and review state |
| AI Assistance Service | `AiAssistanceService` | provider-neutral recommendation/summary/draft operations, human verification |
| Report Module | `ReportService` | mutable report identity, immutable versions, sections, references, review, approval, revoke, export audit |
| Engine Interface | `EngineInterfaceService` | stable in-process/CLI facade, version `1.0.0`, tool descriptor, operation dispatch |
| Annotation/Tag | product/context integration boundary; no dedicated current service/table | legacy contracts can reference annotation IDs; mutation/persistence remains product work |
| Localization | canonical Unicode/time helpers and presentation consumers | NFC/casefold/Hangul composition and locale-safe display; no Korean morphology |

Some responsibility names above are architectural labels required for ownership review, not claims that a same-named Python class exists.

## 4. Evidence and Filesystem Adapters

| Module | Owns | Capability boundary |
|---|---|---|
| `adapters/evidence/raw.py` | RAW/DD/IMG random-access reader and probe | built in for ordinary raw images |
| `adapters/evidence/ewf.py` | E01 segmented-image reader | optional `pyewf/libewf` |
| `adapters/evidence/virtual_disk.py` | VHD and VHDX reader paths | VHD optional `pyvhdilib/libvhdi`; VHDX external `qemu-img` |
| `adapters/evidence/partitions.py` | MBR/GPT/extended/protective/superfloppy/unallocated regions | parsing only; does not identify arbitrary proprietary containers |
| `adapters/filesystem/pytsk.py` | NTFS, FAT12/16/32, exFAT, ext2/3/4 enumeration for RAW/DD/IMG | optional `pytsk3` |
| `adapters/filesystem/logical.py` | bounded logical directory metadata enumeration | directory evidence is metadata-only and not content-hashed |
| `adapters/hashing/hashlib_provider.py` | streaming SHA-256 and progress/cancellation | cannot prove source-device immutability by itself |

Unknown ordinary files are registered as `RAW`; this is a type fallback, not proof that their internal layout is supported. Symlink/reparse containment and original-evidence no-write rules are enforced by the responsible reader/service boundary.

## 5. Artifact Analyzer Owners

| Analyzer | Owns | Explicit limitation |
|---|---|---|
| `WindowsRegistryAnalyzer` | text fixture and optional binary hive key/value extraction | binary parsing depends on `python-registry`; optional transaction replay depends on `regipy` |
| `RegistryDeletedCellCarver` | conservative free/slack NK/VK candidate carving | candidate only, not complete deleted-key recovery |
| `WindowsEventLogAnalyzer` | bounded XML and optional binary EVTX records | 64 MiB total/2 MiB record XML limits; binary depends on `python-evtx` |
| `WindowsEventMessageRenderer` | host message expansion | actual Windows message resources/`pywin32` required |
| `WindowsPrefetchAnalyzer` | Prefetch 17/23/26/30 metadata | MAM decompression is optional via `dissect.util` |
| `BrowserHistoryAnalyzer` | Chromium/Firefox history/search/download/cookie/credential metadata, safe SQLite snapshot | cache is opaque candidate data; freelist/WAL paths report deleted presence, not recovered row contents |
| `MediaMetadataAnalyzer` | EXIF/GPS, image dimensions, MP4 metadata, optional ffprobe, thumbnail/frame derivation | ffmpeg/ffprobe/Pillow paths are capability-driven |
| `CommunicationCorePluginAnalyzer` | MBOX, limited Discord/Telegram SQLite fixture adapters, Kakao encrypted-store discovery | no PST/OST, Discord LevelDB, or Telegram tdesktop parser |
| `KakaoTalkEncryptedStoreProvider` | bounded Windows Desktop 2.0.8.990 AES-128-CBC/PKCS7 decryption and SQLite validation | external key/IV required; no automatic key acquisition; max 5,000 rows |
| `RapidOcrProvider` / `TesseractCliOcrProvider` | OCR provider execution | optional binaries/libraries; output is a candidate |
| `WhisperCppCliSttProvider` / `FasterWhisperSttProvider` | STT provider execution | optional local model; no automatic model download |

### Browser Secret Owners

| Port/adapter | Responsibility |
|---|---|
| `DpapiProviderPort` / `DpapiOfflineProvider` / `DpapiExternalKeyProvider` | bounded Windows DPAPI material processing with explicit key source |
| `NssProviderPort` / `NssLibProvider` | Firefox NSS profile decryption through a locally available NSS library |
| `SecretProviderPort` and capability schemas | redaction, status, provenance, and separation of provider availability from success |

Chromium AES-GCM requires external key material. A credential/cookie candidate is never an Observed Fact solely because decryption returned bytes.

## 6. Persistence Owner

`SQLiteRepository` is the only production persistence adapter. It owns:

- schema creation and the migration markers recorded in `schema_migrations`;
- foreign keys and relevant uniqueness/index constraints;
- FTS5 capability probing and search index storage;
- job/profile/scope/checkpoint/analyzer progress/cache state;
- cases, evidence, hashes, filesystem rows, artifacts, browser/media/communication records;
- context, raw-read audit, AI, report, custody, and render/export records;
- immutable-table update/delete rejection triggers.

The repository does not own evidence parsing, renderer output correctness, optional-provider availability, or product authorization. Services decide invariants; the repository enforces persistent integrity.

## 7. Search and Time Ownership

| Responsibility name | Owner | Rule |
|---|---|---|
| Search Index Provider | SQLite FTS5 implementation behind `SearchIndexProvider` | actual FTS5 probe required |
| Keyword Recommendation Port | `AiAssistanceProviderPort` and AI service review workflow | recommendations are candidates |
| Keyword Set Manager | `SearchService` plus repository | explicit keyword items/approval/promotion |
| Search Reproduction Manager | `SearchService` | save normalized options and rerun by execution ID |
| Timezone Resolver | timeline/context time policy | use explicit IANA timezone or record ambiguity |
| Timestamp Normalizer | `TimelineService` and canonical time helpers | preserve source value; add UTC, confidence, precision, and partial flags |

NFC, case folding, slash normalization, `unicode61`, and canonical Hangul composition are implemented. Tokenization must not be documented as Korean morphological analysis.

## 8. Context, Annotation, and View Ownership

The Context Service is the only owner of session context mutation and optimistic revision checks. Immutable snapshots belong to the context service and SQLite immutable tables.

Annotation/Tag is a retained product ownership boundary, not a dedicated current runtime service or SQLite table. Legacy schemas may reference analyst annotation IDs; a future implementation must retain actor/time/provenance and must not rewrite source artifacts.

`ViewProjectionService` owns Simple/Detailed/Raw presentation projections. `SafeRawRangeReader` owns raw bounds, provenance, and audit. A GUI, HTTP endpoint, or MCP tool should call the Engine Interface; it must not assemble these views by querying SQLite directly.

## 9. AI and Machine Extraction Ports

| Responsibility name | Port | Runtime adapter/status |
|---|---|---|
| Machine Extraction Port | `OcrProviderPort`, `SttProviderPort`, `MachineExtractionRepository` | Tesseract/RapidOCR/whisper.cpp/faster-whisper optional |
| Media Extraction Candidate Store | `MachineExtractionRepository` implemented by SQLite | candidate, review, promotion/audit state |
| AI Provider Port | `AiAssistanceProviderPort` | unavailable by default; optional OpenAI-compatible HTTP adapter |
| AI Verification | `AiAssistanceService` | append-only human verification events and promotion |

Core blocks persistence of prompts, API keys, raw provider bodies, and chain-of-thought. Provider output cannot independently change custody, approve a report, or become a confirmed finding.

### AI Data Governance Owners

`CaseAiPolicyService` owns immutable policy revisions. `AiProjectionService` resolves existing
source DTOs; the domain projection function selects validated structural fields and reuses
`redact_secret_fields`. The pure egress evaluator owns deterministic decisions; `AiEgressService`
owns source verification and audit-before-return. SQLite owns policy/audit persistence and integrity.
These owners have no provider, prompt or transmission responsibility. Existing AI Assistance and
Context owners remain unchanged. See [AI Data Governance](AI_DATA_GOVERNANCE.md).

## 10. Report and Renderer Ownership

| Owner | Responsibility |
|---|---|
| `ReportService` | draft creation, immutable versioning, section/reference validation, review request, approve/reject/revoke, custody snapshot linkage |
| `ReportRendererPort` | renderer capability and deterministic render request/result |
| `RuntimeReportRenderer` | built-in HTML and optional ReportLab PDF, path/collision/permission checks, output hash and magic verification |
| SQLite report repositories | immutable events/versions/artifacts/export audits and hash-chain persistence |

Approval is required before final export. Rendering success and report approval are independent states. Korean synthetic HTML coverage verifies an encoding path, not every font/platform.

## 11. Public Interface and Composition

`config/services.py` builds the explicit `ServiceBundle`. `EngineInterfaceService` exposes supported operations and a descriptor whose schema identifiers come from `schemas/v1`. `cli/parser.py` and `cli/commands.py` provide the current user-facing transport.

Product ownership remains separate: Frontend owns Desktop UX, screen rendering, and localized resource bundles; Backend owns authenticated product sessions, identity, RBAC, tenancy, billing, and approval-identity policy; the MCP/AI product layer owns MCP transport/tool registration, provider selection, prompts, and agent loops. Core owns forensic facts/candidates, provenance, bounded operations, and report-file rendering contracts.

There is no implemented REST server and no MCP SDK/server. REST paths in `API_INTERFACE.md` are planned product integration contracts. A future MCP adapter would be a thin transport over the Engine Interface and would not own forensic logic.

## 12. Runtime Capability Ownership

`runtime/capabilities.py` owns probes and normalized statuses:

- `AVAILABLE`
- `AVAILABLE_WITH_LIMITATIONS`
- `CAPABILITY_UNAVAILABLE`
- `EXTERNAL_CONFIGURATION_REQUIRED`
- `UNSUPPORTED_PLATFORM`
- `BLOCKED_EXTERNAL_FIXTURE`
- `HOST_VERIFICATION_REQUIRED`

Adapters report what they can do; the runtime probe aggregates host evidence; documentation reports limitations. None may convert “module importable” into “real fixture verified.”

`runtime/benchmark.py` owns deterministic Quick/Full benchmark execution, cold/warm measurement, throughput, Peak RSS, and read-only before/after evidence snapshots. It does not own comparative performance claims.

## 13. Validation and Release Ownership

| Responsibility name | Owner | Deliverable |
|---|---|---|
| Design Contract Validator | `tools/validate_design.mjs` and `tools/validate_design_basic.py` | schema/doc/DDL/traceability cross-check |
| Runtime Contract Validator | `tools/verify_windows_host_runtime.py` | Windows host semantic/capability classification |
| Evidence Recovery Validator | `tests/unit/test_release_hardening_recovery.py` | stored-run recovery contract |
| Security Gate | `tools/verify_engine_release.py` plus Bandit/report interpretation | classified findings; current test manifest includes 44 medium findings, not a clean claim |
| Release Gate | `tools/verify_engine_release.py` | full pytest/runtime gate and portable `--mcp-only` pytest/stdio/design/security CI scope |
| External Validation Plan | release/validation owner outside automated unit tests | licensed real fixtures, expected outputs, host/dependency matrix, false-positive/negative assessment |

A validator pass proves only its stated gate. Persistent Windows host results, real KakaoTalk fixture verification, and representative external benchmark results are not currently committed evidence.

## 14. Prohibited Ownership Duplication

- CLI, future REST, GUI, and MCP adapters do not query SQLite or invoke analyzers directly.
- An analyzer does not create a confirmed finding, approve a report, or alter custody.
- Optional providers do not decide feature availability without a capability record.
- SQLite does not reinterpret artifact payloads.
- AI and OCR/STT do not write Observed Facts without review/promotion.
- Report rendering does not grant approval.
- Product identity/RBAC/billing does not redefine forensic evidence or provenance semantics.
