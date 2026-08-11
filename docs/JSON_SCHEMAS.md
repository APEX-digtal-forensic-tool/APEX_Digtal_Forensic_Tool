# APEX JSON Schema Catalog

## 1. Authority and Scope

`schemas/v1/*.schema.json` is the versioned exchange-contract source of truth. This document describes the 66 schemas that are present in that directory; Python models, SQLite DDL, and planned transport examples do not override them.

- Dialect: JSON Schema Draft 2020-12
- Namespace: `https://schemas.apex-forensics.dev/v1/`
- Versioning: the `v1` directory is the compatibility boundary
- References: local `$ref` targets must resolve inside `schemas/v1`
- Objects: schemas normally close known records with `additionalProperties: false`
- Time: timestamps are RFC 3339 strings; source/raw time, normalized UTC time, IANA timezone, confidence, and precision remain distinct when the contract provides them
- Validation: `tools/validate_design.mjs` checks the catalog and cross-document references; runtime validation is provided by `JsonSchemaValidator`

A schema's existence proves a contract shape, not that every optional dependency, host capability, data source, or product transport is available.

## 2. Canonical Core and Interface Schemas

| Schema | Canonical purpose |
|---|---|
| `common.schema.json` | shared identifiers, timestamps, hashes, status/error fragments |
| `api-response.schema.json` | transport-neutral success/error response envelope |
| `case.schema.json` | case identity and metadata |
| `evidence.schema.json` | evidence registration, source, size, type, and hash state |
| `file.schema.json` | indexed filesystem record |
| `artifact.schema.json` | normalized artifact record |
| `citation.schema.json` | provenance locator used by findings and reports |
| `job.schema.json` | background/index job state |
| `engine-interface.schema.json` | public Engine Interface request/response operation envelope |
| `engine-tool-descriptor.schema.json` | tool identity, operations, schemas, and capability disclosure |
| `provider-capability.schema.json` | generic provider capability/status record |
| `derived-output.schema.json` | derived-file provenance and hash contract |

The implemented Engine Interface version is `1.0.0`. It is callable in process and through the CLI. These schemas do not imply an HTTP or MCP server.

## 3. Context and View Schemas

| Schema | Current role |
|---|---|
| `gui-session-context.schema.json` | current Phase 6 GUI/session context contract |
| `context-revision-state.schema.json` | optimistic revision state |
| `analysis-scope-context.schema.json` | selected evidence, files, artifacts, and search scope |
| `analysis-context-snapshot.schema.json` | immutable analysis context snapshot |
| `analysis-context.schema.json` | aggregate/compatibility analysis-context contract |
| `view-projection.schema.json` | Simple/Detailed/Raw projection request/result |
| `raw-read-request.schema.json` | bounded raw-read request |
| `raw-read-response.schema.json` | bounded bytes plus provenance/audit result |
| `raw-view.schema.json` | compatibility raw-view projection |
| `ui-context.schema.json` | legacy Phase 6 compatibility schema |

Runtime context uses an eight-hour default TTL, `expected_revision` optimistic concurrency, and immutable snapshots. Raw reads default to 4 KiB and are capped at 1 MiB by the public service. The schemas do not authorize unrestricted disk reads.

## 4. Evidence, Custody, and Secret Schemas

| Schema | Current role |
|---|---|
| `chain-of-custody.schema.json` | custody event contract |
| `custody-snapshot.schema.json` | immutable custody-chain snapshot |
| `decryption-request.schema.json` | bounded secret-provider request |
| `decryption-result.schema.json` | redacted result/provenance contract |
| `dpapi-key-source.schema.json` | externally supplied DPAPI key-source description |
| `nss-profile.schema.json` | Firefox/NSS profile input |
| `secret-provider-capability.schema.json` | provider support and limitation disclosure |
| `kakaotalk-artifact.schema.json` | Windows KakaoTalk artifact discovery/decryption output |

The custody event vocabulary maintained by the design is:

`ACQUISITION`, `RECEIVED`, `TRANSFERRED`, `STORED`, `OPENED`, `MOUNTED`, `ANALYZED`, `HASH_VERIFIED`, `COPIED`, `EXPORTED`, `RETURNED`, `RELEASED`, `ARCHIVED`, `DISPOSED`, `CORRECTION`.

Secrets are external inputs or host-provider results. API keys, raw provider bodies, decrypted secret material, and chain-of-thought are not normal persisted forensic records.

## 5. Search, Timeline, and Analysis Schemas

| Schema | Current role |
|---|---|
| `analysis-profile.schema.json` | QUICK_TRIAGE, SELECTED_SCOPE, FULL_ANALYSIS, or CUSTOM profile |
| `search.schema.json` | query, match, reproduction, and result structures |
| `timeline-event.schema.json` | normalized event with raw/UTC/timezone/confidence/precision separation |
| `keyword-recommendation.schema.json` | compatibility keyword recommendation |
| `registry-deleted-candidate.schema.json` | conservative Registry deleted-cell candidate |

Search supports `TERM`, `PHRASE`, `PREFIX`, `EXACT`, and `REGEX_METADATA`. Normalization is Unicode NFC, case folding, slash normalization, SQLite FTS5 `unicode61` behavior, and canonical Hangul composition. Korean morphological analysis is not implemented.

Candidate contracts must not be interpreted as confirmed facts. Deleted Registry cells, browser deleted-presence indicators, private-mode indicators, OCR/STT outputs, and AI suggestions require provenance and review.

## 6. Browser and Media Schemas

| Schema | Current role |
|---|---|
| `browser-profile.schema.json` | discovered Chromium/Firefox profile |
| `browser-artifact.schema.json` | normalized browser record |
| `media-artifact.schema.json` | media metadata/EXIF/GPS/probe output |
| `thumbnail.schema.json` | derived thumbnail/frame output |
| `machine-extraction-request.schema.json` | OCR/STT request |
| `machine-extraction-result.schema.json` | OCR/STT result and execution metadata |
| `machine-extracted-candidate.schema.json` | reviewable extracted candidate |
| `machine-extraction.schema.json` | legacy aggregate machine-extraction contract |

Pillow/EXIF and MP4 parsing have built-in paths. ffmpeg/ffprobe, Tesseract, RapidOCR/ONNX Runtime, whisper.cpp, and faster-whisper are capability-gated. Models are not downloaded automatically.

## 7. AI Assistance Schemas

| Schema | Current role |
|---|---|
| `ai-assistance-request.schema.json` | provider-neutral operation request |
| `ai-provider-capability.schema.json` | provider availability and limits |
| `ai-provider-config.schema.json` | redacted provider configuration |
| `ai-provider-execution.schema.json` | execution status/provenance without secret/raw-body storage |
| `ai-keyword-recommendation.schema.json` | one reviewable recommendation |
| `ai-keyword-recommendation-batch.schema.json` | batch recommendation result |
| `ai-keyword-promotion.schema.json` | reviewed promotion to a keyword set |
| `ai-scope-summary.schema.json` | reviewable scope summary |
| `ai-report-draft-input.schema.json` | constrained report-draft input |
| `ai-verification-event.schema.json` | human verification/audit event |
| `ai-enrichment.schema.json` | legacy compatibility enrichment contract |

The default AI provider is unavailable. An optional OpenAI-compatible HTTP adapter can be configured with endpoint, model, API-key environment reference, and network access. AI output remains a candidate; it cannot create an Observed Fact by itself.

## 8. Report Schemas

| Schema | Current role |
|---|---|
| `report-record.schema.json` | mutable report identity/current state |
| `report-version.schema.json` | immutable version snapshot |
| `report-section.schema.json` | versioned section |
| `report-review-event.schema.json` | review request/decision hash-chain event |
| `report-approval-record.schema.json` | approval/revocation record |
| `report-render-request.schema.json` | renderer request |
| `report-render-package.schema.json` | deterministic renderer package |
| `report-render-result.schema.json` | renderer result |
| `report-renderer-capability.schema.json` | HTML/PDF capability disclosure |
| `rendered-report-artifact.schema.json` | rendered output path/hash/magic/provenance |
| `report-export-manifest.schema.json` | export contents and verification metadata |
| `report.schema.json` | legacy aggregate report compatibility contract |

The historical report section vocabulary retained for compatibility is `INDEXING_SCOPE`, `TIMEZONE_POLICY`, `KEYWORD_SEARCH`, `CHAIN_OF_CUSTODY`, `HASH_VERIFICATION`, `MACHINE_EXTRACTION`, and `EXTERNAL_VALIDATION`. Current Phase 8 runtime uses the granular record/version/section/review/approval/render schemas above.

HTML rendering is built in. PDF rendering is optional through ReportLab. A schema-valid render result is not proof that a renderer exists on the current host.

## 9. Complete 66-Schema Inventory

This inventory is exhaustive for `schemas/v1` at the audited revision.

| # | File |
|---:|---|
| 1 | `ai-assistance-request.schema.json` |
| 2 | `ai-enrichment.schema.json` |
| 3 | `ai-keyword-promotion.schema.json` |
| 4 | `ai-keyword-recommendation-batch.schema.json` |
| 5 | `ai-keyword-recommendation.schema.json` |
| 6 | `ai-provider-capability.schema.json` |
| 7 | `ai-provider-config.schema.json` |
| 8 | `ai-provider-execution.schema.json` |
| 9 | `ai-report-draft-input.schema.json` |
| 10 | `ai-scope-summary.schema.json` |
| 11 | `ai-verification-event.schema.json` |
| 12 | `analysis-context-snapshot.schema.json` |
| 13 | `analysis-context.schema.json` |
| 14 | `analysis-profile.schema.json` |
| 15 | `analysis-scope-context.schema.json` |
| 16 | `api-response.schema.json` |
| 17 | `artifact.schema.json` |
| 18 | `browser-artifact.schema.json` |
| 19 | `browser-profile.schema.json` |
| 20 | `case.schema.json` |
| 21 | `chain-of-custody.schema.json` |
| 22 | `citation.schema.json` |
| 23 | `common.schema.json` |
| 24 | `context-revision-state.schema.json` |
| 25 | `custody-snapshot.schema.json` |
| 26 | `decryption-request.schema.json` |
| 27 | `decryption-result.schema.json` |
| 28 | `derived-output.schema.json` |
| 29 | `dpapi-key-source.schema.json` |
| 30 | `engine-interface.schema.json` |
| 31 | `engine-tool-descriptor.schema.json` |
| 32 | `evidence.schema.json` |
| 33 | `file.schema.json` |
| 34 | `gui-session-context.schema.json` |
| 35 | `job.schema.json` |
| 36 | `kakaotalk-artifact.schema.json` |
| 37 | `keyword-recommendation.schema.json` |
| 38 | `machine-extracted-candidate.schema.json` |
| 39 | `machine-extraction-request.schema.json` |
| 40 | `machine-extraction-result.schema.json` |
| 41 | `machine-extraction.schema.json` |
| 42 | `media-artifact.schema.json` |
| 43 | `nss-profile.schema.json` |
| 44 | `provider-capability.schema.json` |
| 45 | `raw-read-request.schema.json` |
| 46 | `raw-read-response.schema.json` |
| 47 | `raw-view.schema.json` |
| 48 | `registry-deleted-candidate.schema.json` |
| 49 | `rendered-report-artifact.schema.json` |
| 50 | `report-approval-record.schema.json` |
| 51 | `report-export-manifest.schema.json` |
| 52 | `report-record.schema.json` |
| 53 | `report-render-package.schema.json` |
| 54 | `report-render-request.schema.json` |
| 55 | `report-render-result.schema.json` |
| 56 | `report-renderer-capability.schema.json` |
| 57 | `report-review-event.schema.json` |
| 58 | `report-section.schema.json` |
| 59 | `report-version.schema.json` |
| 60 | `report.schema.json` |
| 61 | `search.schema.json` |
| 62 | `secret-provider-capability.schema.json` |
| 63 | `thumbnail.schema.json` |
| 64 | `timeline-event.schema.json` |
| 65 | `ui-context.schema.json` |
| 66 | `view-projection.schema.json` |

## 10. Contract-to-Runtime Rules

1. Validate inbound/outbound documents at the boundary, not after persistence.
2. Persist the schema/version identifier with material derived records when the table supports it.
3. Preserve raw/source values; normalized values are additive.
4. Reject unknown enum values at a closed contract boundary.
5. Treat capability status separately from schema validity. Valid input can still yield `CAPABILITY_UNAVAILABLE`, `AVAILABLE_WITH_LIMITATIONS`, `EXTERNAL_CONFIGURATION_REQUIRED`, `UNSUPPORTED_PLATFORM`, `BLOCKED_EXTERNAL_FIXTURE`, or `HOST_VERIFICATION_REQUIRED`.
6. Never infer a successful optional provider run from the existence of its request/result schema.
7. Keep legacy schemas for compatibility until an explicit migration removes their consumers; do not describe them as the current aggregate runtime when granular contracts are canonical.

## 11. Change Discipline

A schema change requires:

- the schema file and all local references to remain valid;
- Python model/adapter changes where applicable;
- SQLite migration changes where persistence changes;
- positive and negative contract tests;
- catalog, API, database, module, roadmap, and traceability review;
- explicit compatibility handling for renamed or retired fields.

The design validators and schema tests are release gates, but passing them does not replace fixture, host, security, or forensic-method validation.
