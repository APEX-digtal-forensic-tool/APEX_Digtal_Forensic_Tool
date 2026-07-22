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
