# APEX 인터페이스 계약

## 1. 현재 구현 경계

- **Application/Public Engine Interface — IMPLEMENTED**: `EngineInterfaceService`가 version, tool descriptor, read/mutation 호출과 구조화된 응답을 제공한다.
- **CLI — IMPLEMENTED**: `apex-forensic`가 application service와 public interface를 호출하는 현재 adapter다.
- **HTTP `/api/v1` — PLANNED**: 아래 HTTP 표는 transport 계약 목표다. 현재 저장소에는 HTTP API server, router 또는 daemon이 없다.
- **Desktop GUI와 MCP — PLANNED CONSUMERS**: 같은 versioned contract를 소비해야 한다. 현재 MCP server/SDK와 Desktop GUI는 없다.
- **OpenAI-compatible AI adapter — EXTERNAL_CONFIGURATION_REQUIRED**: 선택적 provider adapter이며 Core 또는 MCP의 필수 runtime이 아니다.

계약은 JSON Schema Draft 2020-12, UTF-8, partial/stale/capability 상태, citation과 source revision을 사용한다. 시간 계약은 raw/UTC를 분리하고 Case의 IANA timezone, confidence, precision을 보존한다. HTTP 상태 코드나 REST route가 존재한다는 전제 없이 application service와 CLI가 같은 DTO를 사용한다.

## 2. 현재 Public Engine Interface

| CLI | 현재 동작 | 대표 계약 |
|---|---|---|
| `interface version` | interface/engine/schema version과 capability 조회 | `engine-interface.schema.json` |
| `interface tools` | versioned tool descriptor 조회 | `engine-tool-descriptor.schema.json` |
| `interface capability` | 전체 또는 특정 capability 조회 | structured response |
| `interface invoke-read` | 등록된 read-only operation 호출 | operation별 schema |
| `interface invoke-mutation` | 상태 변경 operation 호출 | operation별 schema |

Descriptor는 `mutates_state`, `requires_confirmation`, pagination, partial, citation과 최대 결과 수를 공개한다. 알려지지 않은 operation이나 read/mutation 경계 위반은 구조화된 오류다. 이는 HTTP/MCP transport가 아닌 transport-neutral application interface다.

현재 operation은 GUI context/snapshot/scope, Simple/Detailed/Raw view와 최대 1 MiB raw read, AI request/ingest/review/promotion, report/version/review/approval/custody/export를 포함한다.

## 3. 현재 CLI Surface

`src/apex_forensic/cli/parser.py`와 `commands.py`가 권위 원본이다.

| 영역 | 구현된 명령 범위 |
|---|---|
| Case/Evidence | `init`, case create/list/show/status, evidence register/hash/verify/volumes/range/unallocated/export |
| Filesystem/Recovery | progressive index/status/resume/cancel, roots/list/show/prioritize, deleted recovery, slack export |
| Artifacts | Registry/Event XML/EVTX/Prefetch, deleted-cell carve, browser/media/communication query |
| Browser/Media | history/search/download/cookie/credential/cache/deleted/private-mode, thumbnail |
| Machine extraction | optional Tesseract/RapidOCR, whisper.cpp/faster-whisper, candidate review/correction |
| Secret recovery | DPAPI, Chromium external-key AES-GCM, Firefox NSS, KakaoTalk inspect/decrypt |
| Search/Timeline | FTS index/query/rerun/cache/rebuild, keyword sets, timeline build/query |
| Context/View | TTL/revision context, immutable snapshots/scopes, Simple/Detailed/Raw/raw-read |
| AI | provider capability, configured generation, ingest, review, correction, promotion |
| Report/Custody | aggregate/version/review/approval/revocation/custody/package/export/render, custody chain |
| Runtime | `doctor [--json]`, deterministic `benchmark`, `tools/verify_engine_release.py` |

Optional dependency가 없으면 빈 성공이 아니라 `CAPABILITY_UNAVAILABLE`, `HOST_VERIFICATION_REQUIRED` 또는 `EXTERNAL_CONFIGURATION_REQUIRED`를 보존한다.

## 4. 응답과 오류

응답은 status, data, warnings/errors, correlation, partial/stale reason과 revision을 보존한다. 주요 오류 경계는 다음과 같다.

- `VALIDATION_ERROR`, `NOT_FOUND`, `STATE_CONFLICT`
- `CAPABILITY_UNAVAILABLE`, `HOST_VERIFICATION_REQUIRED`, `EXTERNAL_CONFIGURATION_REQUIRED`
- `UNSUPPORTED_PLATFORM`, `UNSUPPORTED_VERSION`, `UNSUPPORTED_SCHEMA`
- `SOURCE_UNAVAILABLE`, `CORRUPT_DB`, `AUTHENTICATION_FAILED`
- `RAW_RANGE_INVALID`, `RAW_READ_LIMIT_EXCEEDED`, root-containment 위반
- `REPORT_APPROVAL_REQUIRED`, renderer/output/collision/path 오류

## 5. 현재 계약과 Schema 대응

| 영역 | Canonical schema |
|---|---|
| Case/Evidence/Job | `case.schema.json`, `evidence.schema.json`, `job.schema.json`, `chain-of-custody.schema.json` |
| Filesystem/Artifact/Search/Timeline | `file.schema.json`, `artifact.schema.json`, `registry-deleted-candidate.schema.json`, `search.schema.json`, `timeline-event.schema.json` |
| Browser/Media/Machine | `browser-profile.schema.json`, `browser-artifact.schema.json`, `media-artifact.schema.json`, `thumbnail.schema.json`, `machine-extracted-candidate.schema.json`, `machine-extraction-request.schema.json`, `machine-extraction-result.schema.json` |
| Secret recovery | `secret-provider-capability.schema.json`, `decryption-request.schema.json`, `decryption-result.schema.json`, `dpapi-key-source.schema.json`, `nss-profile.schema.json`, `kakaotalk-artifact.schema.json` |
| Phase 6 context/view | `gui-session-context.schema.json`, `analysis-context-snapshot.schema.json`, `analysis-scope-context.schema.json`, `context-revision-state.schema.json`, `view-projection.schema.json`, `raw-view.schema.json`, `raw-read-request.schema.json`, `raw-read-response.schema.json` |
| Public interface | `engine-interface.schema.json`, `engine-tool-descriptor.schema.json`, `api-response.schema.json` |
| AI | `ai-assistance-request.schema.json`, `ai-keyword-recommendation-batch.schema.json`, `ai-keyword-recommendation.schema.json`, `ai-scope-summary.schema.json`, `ai-verification-event.schema.json`, `ai-keyword-promotion.schema.json`, `ai-provider-capability.schema.json`, `ai-provider-config.schema.json`, `ai-provider-execution.schema.json`, `ai-report-draft-input.schema.json` |
| Phase 8 report | `report-record.schema.json`, `report-version.schema.json`, `report-section.schema.json`, `report-review-event.schema.json`, `report-approval-record.schema.json`, `custody-snapshot.schema.json`, `report-render-package.schema.json`, `report-export-manifest.schema.json`, `rendered-report-artifact.schema.json`, `report-renderer-capability.schema.json`, `report-render-request.schema.json`, `report-render-result.schema.json` |

**SHARED / BASE**:

- `common.schema.json`, `citation.schema.json`, `analysis-profile.schema.json`, `derived-output.schema.json`은 current shared/base contracts다.

**LEGACY / COMPATIBILITY**:

- `ui-context.schema.json`은 초기 live UI context 설계다. `analysis-context.schema.json`의 참조 호환성 때문에 유지되지만 Phase 6 canonical GUI DTO는 `gui-session-context.schema.json`이다.
- `report.schema.json`은 초기 aggregate/statement 설계와 validator 호환성이다. 현재 report runtime은 granular Phase 8 schemas를 사용한다.
- `analysis-context.schema.json`, `ai-enrichment.schema.json`, `keyword-recommendation.schema.json`, `machine-extraction.schema.json`은 초기 aggregate/consumer compatibility contracts다.

## 6. KakaoTalk Interface Boundary

현재 `secret kakaotalk inspect`와 `secret kakaotalk decrypt-store` 범위:

- Windows Desktop `2.0.8.990`, `chatLogs*.edb`, `chatLogs` schema
- 명시적 offline root의 bounded discovery, symlink/reparse 차단, PE fixed file version 검증
- 외부 KPRAGMA+nonce 또는 외부 16-byte AES key+IV
- AES-128-CBC/PKCS#7, SQLite header, read-only `quick_check(1)`, column-aware extraction
- 자동 key acquisition과 실제 encrypted fixture 검증은 `BLOCKED_EXTERNAL_FIXTURE`
- 합성 AES/SQLite 계약은 real fixture 검증이 아님
- Android/iOS는 `UNSUPPORTED_PLATFORM`

Artifact analyzer의 Kakao discovery candidate는 외부-key provider 성공을 자동으로 의미하지 않는다.

## 7. HTTP Adapter Contract — PLANNED

아래 endpoint는 향후 `/api/v1` adapter 설계 목표다. **현재 실행 중인 REST/HTTP server가 아니다.**

| Method | Planned endpoint | Mapping |
|---|---|---|
| `PUT` | `/sessions/{session_id}/ui-context` | live GUI context |
| `POST` | `/cases/{case_id}/context-snapshots` | immutable snapshot |
| `GET` | `/cases/{case_id}/analysis-bundle` | scopes bundle |
| `GET` | `/cases/{case_id}/search-results` | search page |
| `POST` | `/cases/{case_id}/reports` | report workflow |
| `POST` | `/generate-draft` | optional AI draft |
| `POST` | `/request-review` | review submit |
| `POST` | `/approve` | approval |
| `POST` | `/reject` | rejection |
| `POST` | `/export` | approved export |
| `GET` | `/cases/{case_id}/analysis-profiles` | profiles |
| `POST` | `/cases/{case_id}/index-jobs` | index start |
| `POST` | `/cases/{case_id}/index-jobs/{job_id}/pause` | pause |
| `POST` | `/cases/{case_id}/index-jobs/{job_id}/resume` | resume |
| `POST` | `/cases/{case_id}/index-jobs/{job_id}/cancel` | cancel |
| `PATCH` | `/cases/{case_id}/index-jobs/{job_id}/priority` | priority |
| `GET` | `/cases/{case_id}/index-jobs/{job_id}/progress` | progress |
| `GET` | `/cases/{case_id}/partial-results` | partial coverage |
| `POST` | `/cases/{case_id}/timezone/detect` | timezone candidates |
| `GET` | `/cases/{case_id}/timezone/candidates` | candidates |
| `GET` | `/cases/{case_id}/timestamp-interpretations` | raw/UTC/case time |
| `POST` | `/cases/{case_id}/keyword-recommendations` | recommendations |
| `POST` | `/cases/{case_id}/keyword-sets` | keyword sets |
| `POST` | `/cases/{case_id}/search-executions/{execution_id}/rerun` | reproduction |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/custody-events` | ledger |
| `GET` | `/cases/{case_id}/evidence/{evidence_id}/hash-verifications` | hashes |
| `POST` | `/cases/{case_id}/evidence/{evidence_id}/custody-snapshots` | snapshot |
| `GET` | `/cases/{case_id}/files/{file_id}/raw` | bounded raw |
| `GET` | `/cases/{case_id}/artifacts/{artifact_id}/raw` | bounded raw |
| `POST` | `/cases/{case_id}/raw-ranges` | audited raw range |
| `POST` | `/cases/{case_id}/media-extraction-jobs` | optional OCR/STT |
| `GET` | `/cases/{case_id}/machine-extractions` | candidates |

향후 HTTP adapter의 identity/session/RBAC/rate limit/billing/approval identity policy는 Backend 책임이다. Core는 forensic operation, provenance와 capability를 소유한다.

## 8. 보안과 호환성

- 원본 evidence는 read-only, output은 configured derived root에만 생성한다.
- raw secret/API key/prompt/chain-of-thought/provider raw body를 Core record에 저장하지 않는다.
- OCR/STT/AI 결과는 Observed Fact가 아니며 human review/citation 상태를 보존한다.
- GUI/HTTP/MCP는 public engine interface를 우회해 SQLite나 analyzer를 직접 호출하지 않는다.
