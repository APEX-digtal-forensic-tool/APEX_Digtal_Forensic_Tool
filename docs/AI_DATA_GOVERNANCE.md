# Engine AI Data Governance

## Scope and ownership

Governance is an engine contract for policy evaluation, minimal data projection and assessment
history. It has no provider, HTTP, prompt, model, agent-loop or MCP dependency. It does not send
requests, store provider responses or change forensic facts.

The existing layered architecture is retained:

| Owner | Responsibility |
|---|---|
| `domain/enums` | Classification, destination, representation, secret-handling and decision enums |
| `domain/models/ai_governance.py` | Immutable policy revisions, source references, input metadata, decisions, projections and audits |
| `domain/services/ai_egress.py` | Pure deterministic policy evaluation |
| `domain/services/ai_projection.py` | Allowlisted structural projection over existing source DTOs |
| `domain/models/secret.py` | Existing recursive secret-field redaction rules, exposed through `redact_secret_fields` |
| `CaseAiPolicyService` | Case existence, policy configuration and expected-revision workflow |
| `AiProjectionService` | Read existing case-scoped artifacts, snapshots and AI assistance requests |
| `AiEgressService` | Source fingerprint checks, current policy assessment and audit-before-return |
| `AiGovernanceRepository` / `AiProjectionSourceRepository` | Persistence and source-reader protocols |
| `SQLiteRepository` | Policy revision and append-only audit persistence |

`build_services()` exposes `ai_policies`, `ai_projections` and `ai_egress`. The existing AI
Assistance request, context snapshot, evidence and artifact contracts remain unchanged. The
projection consumes these records through their existing repository readers; it does not
replace them or introduce a second context store.

## Policy semantics

Policies have a UUID `policy_id`, case UUID, positive `revision`, UTC `created_at`, and schema
version `1.0.0`. Updating a policy appends a new immutable row with a new ID. The caller must
supply `expected_revision` (zero for the first policy). Concurrent stale writes are rejected.
Audit records retain the exact policy revision and canonical policy fingerprint.

Defaults are deliberately restrictive:

| Field | Default | Meaning |
|---|---|---|
| `ai_enabled` | `false` | AI data use must be explicitly enabled |
| `external_allowed` | `false` | External destinations require explicit permission |
| `local_only` | `true` | Overrides external permission when both flags are set |
| `allowed_classifications` | `PUBLIC`, `INTERNAL` | Explicit allowlist; an empty list denies every classification |
| `secret_handling` | `DENY` | `DENY`, `REDACT` or explicit `ALLOW` for material still present |
| `raw_allowed` | `false` | Raw representations cannot receive an unconditional allow |
| `redaction_required` | `true` | Requires a redacted representation or safe projection |
| `projection_required` | `true` | Only the safe projection representation can receive an allow |

A missing policy produces `DENY / POLICY_MISSING`; it does not create a permissive row.
`PUBLIC`, `INTERNAL`, `SENSITIVE` and `SECRET` describe sensitivity, independently of the
presence of literal secret strings. Known or conservatively assumed secret presence raises
classification to `SECRET`. Redaction/projection never lowers classification. Therefore
using a secret-free projection of secret evidence still requires `SECRET` in the policy's
classification allowlist. `secret_handling=DENY` rejects remaining secret material, while the
classification allowlist separately controls secret-classified data after removal.

The engine does not infer arbitrary-text sensitivity or trust a destination URL as proof of
local execution. The trusted caller supplies classification, secret presence and destination
category. Omitted classification is `SENSITIVE`; omitted secret presence conservatively means
`true`. Known secret-field markers and credential/cookie artifact types cannot be downgraded
by the service caller. These checks reuse the existing redactor, not a second secret detector.

## Decision semantics

Only `ALLOW` applies to the exact assessed representation. Every result includes its source
reference/fingerprint, representation fingerprint (required for derived forms), classification,
secret presence, destination, reason codes, fixed reason text, required transformations and
policy reference. Evaluation contains no clock access or random identifiers.

| Decision | Meaning |
|---|---|
| `DENY` | Policy prohibits the submitted data; no transmission permission |
| `ALLOW_WITH_REDACTION` | Redaction is required; assess the transformed representation again |
| `ALLOW_PROJECTION_ONLY` | Build a safe projection and assess it again |
| `ALLOW` | This representation satisfies the evaluated policy |

Hard denials (case mismatch, disabled AI, forbidden destination/classification, denied secrets,
or incomplete redaction) take precedence over transformation requirements. Raw denial returns
a hard denial unless the policy requires projection, in which case only the projection path
can satisfy it. A record marked redacted/projection that still contains secrets is denied.

`AiEgressService.evaluate()` accepts trusted metadata for raw, structured and redacted data.
A redaction flag and digest are an integration attestation, not a scan of an unseen payload.
A `SAFE_PROJECTION` label alone is rejected by this service: use `evaluate_projection()`, which
reconstructs the exact selected fields from the stored source and checks equality before
assessment. Stale or tampered source/projection fingerprints are rejected. The pure evaluator
can assess all representation labels for callers implementing their own trusted boundary.

## Safe projection

The v1 projection is a deliberately small structural contract. It is not a prompt builder or
an arbitrary-text sanitizer. It accepts only these fields, and callers may choose a subset:

| Source | Allowed fields |
|---|---|
| `ARTIFACT` | `artifact_type`, `parse_status`, `confidence`, `is_partial` |
| `CONTEXT_SNAPSHOT` | `search_index_revision`, `timeline_revision`, `is_partial`, `is_stale`, `resource_count` |
| `AI_ASSISTANCE_REQUEST` | `purpose`, `is_partial`, `is_stale`, `resource_count`, `max_keyword_candidates`, `max_summary_length` |

All values are validated enums, finite bounded numbers, booleans or nullable revision numbers.
Titles, summaries, paths, raw locators, payloads, free text, warning messages and citation
excerpts are excluded. Field-name redaction alone cannot safely release those strings.
Unknown fields, duplicate selections, empty selections and invalid structural values fail.

Each projection retains its case/source UUIDs, source type and canonical source fingerprint,
classification, projection version and content fingerprint. Source references remain resolvable
inside the engine without embedding potentially sensitive citation text. Field pairs are
immutable and sorted; serialization returns a fresh mapping. Identical sources, classification,
secret metadata and field selections produce identical projections independent of selection
order. No original DTO, database artifact or evidence bytes are mutated.

## Example: projection, assessment, audit

```python
from apex_forensic.domain.enums import (
    AiDataSourceType, AiDestinationCategory, AiSecretHandling, DataClassification,
)

# `services` comes from the existing build_services(db_path) factory.
services.ai_policies.configure(
    case_id=case_id,
    expected_revision=0,
    ai_enabled=True,
    external_allowed=True,
    local_only=False,
    allowed_classifications=(DataClassification.SENSITIVE, DataClassification.SECRET),
    secret_handling=AiSecretHandling.REDACT,
)
projection = services.ai_projections.create(
    case_id=case_id,
    source_id=artifact_id,
    source_type=AiDataSourceType.ARTIFACT,
    classification=DataClassification.SENSITIVE,
    selected_fields=("artifact_type", "is_partial"),
)
audit = services.ai_egress.evaluate_projection(
    projection, destination=AiDestinationCategory.EXTERNAL,
)
# The caller inspects audit.result.decision. Nothing is transmitted here.
```

## SQLite and audit

`initialize()` adds the idempotent `apex-engine-ai-data-governance` migration marker and two
tables. Existing databases require no forensic-row rewrite or new mandatory case policy.

- `case_ai_policies`: explicit policy columns, one small classification enum-array column,
  unique `(case_id, revision)` and immutable update/delete triggers.
- `ai_egress_audit_records`: explicit case/source, classification, representation, decision,
  reason, transformation flags, destination, policy reference and UTC timestamp columns.
  Only the bounded reason-code and transformation arrays use JSON. No payload is stored.

Case and composite policy foreign keys prevent mismatched policy references. Polymorphic source
ownership is checked by an insertion trigger against the existing artifact/snapshot/request
tables. Audit insertion compares the latest policy ID atomically; if policy changes between
assessment and persistence, the operation fails and must be retried. Storage errors propagate;
an allow result is not returned without its audit record. Both policy and audit tables reject
updates and deletes. Audits record assessment, including denial and transformation requirements;
they do not assert that any bytes were actually transmitted. Projection application and redaction
application flags describe the assessed representation, not a future required transformation.

## Schemas and validation

All new contracts use Draft 2020-12, the existing `/v1/` ID namespace, local `$ref`, existing
common UUID/timestamp/SHA-256 types, explicit required fields and closed object shapes. The
classification enum is shared from `common.schema.json#/$defs/dataClassification`.

New schemas: `case-ai-policy`, `data-classification`, `ai-egress-data`, `ai-egress-decision`,
`safe-ai-projection`, `ai-egress-audit` (all `.schema.json`). Type-specific projection fields
are closed through conditional schemas. Application validation additionally verifies fingerprints,
source ownership, policy concurrency and reason consistency, which JSON Schema cannot prove.

`rfc3339-validator` is a required validation dependency: without it, the existing jsonschema
format checker silently omitted `date-time` checks. `tools/validate_design.sh` now registers all
schemas before strict Ajv compilation; its previous CLI probe/reference handling could skip
strict validation or fail to resolve local references. Ajv remains optional tooling and is not
an engine runtime dependency. The Bandit disposition manifest retains the original 43 findings
and justifications, with corrected locations (including pre-existing line-number drift).

Behavioral tests are in `tests/unit/test_ai_data_governance.py` and
`tests/integration/test_ai_governance_workflow.py`. They cover default denial, policy combinations,
secret handling, serialization/schema validation, projection minimization and immutability,
source/case checks, tampering, redaction/projection reassessment, concurrent policy revisions,
audit integrity, persistence round trips and idempotent database upgrades.

## Integration boundary and remaining limitations

Existing optional provider execution code is unchanged. Governance is not automatically wired
into that legacy runtime path, and is not a network firewall. The runtime/product owner must
consume the assessment and transmit only its approved representation, re-evaluating after any
payload, source, destination or policy change. A persisted allow is historical evidence, not a
permanent authorization token. This change does not claim engine-wide enforcement of an external
runtime's behavior.

Existing AI Assistance, review/promotion and Context APIs retain their behavior; adding governance
does not approve AI results or turn them into observed facts. Provider runtime, API call sites,
Frontend, MCP transport, prompt construction and LLM response persistence are outside this change.
Windows-only verifiers and optional OCR/STT/image/secret providers still require their existing
host, dependency, model and fixture setup. No real external AI request is needed for governance
validation.
