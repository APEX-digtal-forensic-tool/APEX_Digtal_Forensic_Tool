# APEX Implementation Roadmap

## 1. Current Milestone

APEX Forensic Core는 **Feature Complete Candidate**다. Phase 1~8의 Core contracts/runtime과 Phase 9 release-hardening tooling이 구현되어 있다. 다음을 서로 구분한다.

- **COMPLETED CORE FEATURE IMPLEMENTATION**
- **COMPLETED RELEASE HARDENING IMPLEMENTATION**
- **OPTIONAL / DEPENDENCY-GATED**
- **EXTERNAL VERIFICATION REMAINING**
- **PRODUCT INTEGRATION REMAINING**

이는 전체 APEX 제품, 모든 host capability, real forensic fixture 검증 또는 packaging 완료를 뜻하지 않는다.

## 2. Phase Status

| Phase | 범위 | 현재 상태 |
|---|---|---|
| 0 | architecture/schema/validator baseline | COMPLETED |
| 1 | package, case/evidence/hash/custody/SQLite/CLI | COMPLETED |
| 2 | progressive filesystem/index/cursor/checkpoint | COMPLETED; image provider는 capability-driven |
| 3 | Registry/Event Log/Prefetch | COMPLETED CORE; 일부 optional/host |
| 4 | FTS5/search/keyword/timeline/timezone/cache | COMPLETED |
| 5 | browser/media/communications/candidates | COMPLETED WITH LIMITATIONS |
| 6 | GUI context/snapshot/view/public interface | COMPLETED CONTRACT; GUI/MCP transport 별도 |
| 7 | AI assistance/review/provider contract | COMPLETED CONTRACT; provider optional config |
| 8 | report/review/approval/custody/render/export | COMPLETED; PDF optional |
| 9 | doctor/benchmark/recovery/security/release gate | IMPLEMENTED; external/host verification 지속 |

## 3. Completed Core Feature Implementation

### Phase 1 — Foundation

- `src/apex_forensic` package와 `apex-forensic` CLI
- Case/Evidence/Job/Hash/Custody services와 SQLite
- Directory와 ordinary file registration
- MD5/SHA1/SHA256 streaming hash/verification
- read-only evidence policy, structured error와 Unicode round-trip

Directory manifest hash는 설계되지 않았으며 미완료 Core defect가 아니라 explicit capability boundary다.

### Phase 2 — Evidence, Filesystem와 Recovery

- RAW/DD/IMG reader
- optional E01/EWF, VHD와 VHDX adapters
- MBR/GPT/extended/protective/superfloppy/unallocated parsing
- logical + optional pytsk3 filesystem
- Quick Triage/Selected Scope/Full Analysis/Custom
- lazy tree/cursor/checkpoint/resume/prioritize/coverage
- deleted entry/extent/slack metadata
- bounded raw/unallocated/slack export와 deleted-file data-run recovery

Generic unallocated carving과 complete recovery는 제외한다.

### Phase 3 — Windows Artifacts

- Registry export/binary adapter
- optional transaction-log replay
- built-in deleted-cell candidate carving
- Event XML/optional EVTX
- Windows Event Message renderer boundary
- Prefetch 17/23/26/30과 optional MAM
- corrupt/oversized input isolation과 raw locator/citation

### Phase 4 — Search와 Timeline

- SQLite FTS5 probe/index
- `TERM`, `PHRASE`, `PREFIX`, `EXACT`, bounded `REGEX_METADATA`
- NFC/casefold/path normalization, canonical Hangul composition
- versioned keyword sets
- search query/execution/result reproduction와 cache
- filesystem/Registry/Event/Prefetch/media/browser/communication timeline
- raw/UTC/IANA case timezone/source/confidence/partial 분리

한국어 형태소 분석은 현재 범위가 아니다.

### Phase 5 — Browser, Media와 Communications

- Chromium/Firefox history/search/download/cookie/credential/cache metadata
- WAL/SHM snapshot provenance, freelist/deleted-presence candidate, private-mode candidate
- external-key Chromium AES-GCM
- image/EXIF/GPS, video/audio metadata
- optional Pillow thumbnail와 ffmpeg/ffprobe
- limited MBOX Email, simple Discord/Telegram SQLite analyzers
- machine candidate persistence/review

Production-native PST/OST, Discord LevelDB, Telegram tdesktop와 browser live acquisition은 제외한다.

### Phase 6 — Context/View/Public Interface

- live GUI session context, 8-hour default TTL, optimistic revision
- immutable content-fingerprinted snapshots와 scope pages
- partial/stale/source revision
- Simple/Detailed/Raw와 1 MiB bounded audited read
- public engine version/tool descriptor/read-mutation invocation

Desktop GUI, HTTP server와 MCP server는 이 contract를 소비할 future product work다.

### Phase 7 — AI Assistance

- snapshot-bound request/TTL/fingerprint
- keyword and scope-summary ingest
- citation/scope/partial/stale validation
- append-only human review와 draft keyword promotion
- optional OpenAI-compatible HTTP provider adapter
- provider capability persistence와 secret/prompt/raw-body rejection

Default Core는 LLM 없이 실행된다. MCP, prompt strategy, agent loop는 별도 product layer다.

### Phase 8 — Report Runtime

- mutable report aggregate + immutable versions/sections/references
- deterministic fingerprint/idempotent replay
- section review와 append-only review hash chain
- approval/rejection/revocation hash chain
- custody snapshots와 approval/export gate
- render packages/export manifests/rendered artifact/audit
- built-in HTML runtime
- optional ReportLab PDF
- Unicode/Korean synthetic verification와 output path security

Backend identity/RBAC, electronic signature와 legal effect는 별도다.

## 4. Completed Release Hardening Implementation

- dependency-light runtime `doctor`와 exact capability IDs/status
- deterministic synthetic/user-evidence benchmark
- cold/warm search, throughput와 Peak RSS
- before/after read-only invariant
- SQLite corruption/lock/contention recovery tests
- filesystem/artifact resume/cancel/temp cleanup tests
- bounded regex와 oversized Event XML protection
- Bandit Medium/High disposition manifest drift audit
- Windows semantic verifier와 fixture generator
- DPAPI/NSS/OCR/STT/AI/report/Kakao individual verifiers
- single release gate for pytest/Ruff/mypy/diff/design/runtime/recovery/security/benchmark/CLI/Unicode

Release hardening tooling 구현 완료는 현재 host의 모든 probe가 PASS임을 뜻하지 않는다.

## 5. Optional / Dependency-Gated

| Capability | 필요 조건 | 없는 경우 |
|---|---|---|
| E01/EWF | `pyewf` | `CAPABILITY_UNAVAILABLE` |
| VHD | `pyvhdilib` | `CAPABILITY_UNAVAILABLE` |
| VHDX | `qemu-img` | `CAPABILITY_UNAVAILABLE` |
| Image filesystem | `pytsk3` | `CAPABILITY_UNAVAILABLE` |
| Binary Registry/EVTX | python-registry/python-evtx | partial/unavailable |
| Registry replay/MAM | regipy/dissect.util | optional feature unavailable |
| Event Message | Windows + pywin32 | `HOST_VERIFICATION_REQUIRED` 또는 unavailable |
| Thumbnail/media | Pillow/ffmpeg/ffprobe | capability-specific fallback/unavailable |
| OCR | Tesseract 또는 RapidOCR+onnxruntime | `CAPABILITY_UNAVAILABLE`/config required |
| STT | whisper.cpp 또는 faster-whisper+local model | unavailable/config required |
| DPAPI | impacket + offline material | unavailable/key/config boundary |
| NSS | libnss3 + profile/password | unavailable/profile/config boundary |
| PDF | ReportLab | HTML만 available |
| AI provider | endpoint/model/API-key environment/network | `EXTERNAL_CONFIGURATION_REQUIRED` |
| Kakao external-key path | cryptography + exact version + external key/nonce | blocked/unavailable |

Optional capability는 Core feature 목록에 존재하지만 모든 설치에서 always available로 표시하지 않는다.

## 6. External Verification Remaining

- Windows registered Event Message resource의 actual host verification
- configured DPAPI/NSS profiles의 synthetic/legal fixture verification and host matrix
- OCR Korean/mixed-language model/font fixture
- STT Korean/English local model/audio fixture
- E01/VHD/VHDX/pytsk의 broader public/legally redistributable image matrix
- real evidence accuracy/coverage evaluation
- large-scale memory/performance baselines와 regression thresholds
- external forensic expert review
- platform packaging/signing/install/upgrade test
- supported Python/Windows/Linux dependency CI matrix

Repository에 persistent successful Windows-host result artifact가 없으므로 과거 외부 실행을 PASS로 문서화하지 않는다.

## 7. KakaoTalk External Blockers

Implemented:

- Windows Desktop `2.0.8.990` exact target
- bounded explicit offline-root discovery
- `chatLogs*.edb`와 PE fixed file version
- external KPRAGMA+nonce 또는 raw key+IV
- AES-128-CBC/PKCS#7
- SQLite header/read-only `quick_check(1)`
- `chatLogs` column-aware extraction와 citation/redaction
- synthetic algorithm/SQLite contract tests

Remaining/blocking:

- authoritative automatic KPRAGMA/device/disk/nonce acquisition
- redistributable real encrypted KakaoTalk fixture
- actual message/attachment accuracy across real database
- any newer Windows version
- Android/iOS

따라서 automatic acquisition과 real fixture는 `BLOCKED_EXTERNAL_FIXTURE`이고 `real_kakaotalk_fixture_verified=false`다.

## 8. Product Integration Remaining

Core completion gate와 별도인 product work:

- Desktop GUI/UX/resource bundle
- HTTP `/api/v1` server adapter
- MCP server와 tool registration
- LLM provider selection/product prompt/agent loop
- backend identity/session/RBAC/organization/approval policy
- billing/subscription
- distribution packaging, auto-update와 operational telemetry policy

이 작업들이 남았다는 사실을 “Core forensic features incomplete”로 계산하지 않는다. 반대로 Core feature candidate를 “whole product complete”로 표현하지 않는다.

## 9. Acceptance Gates Going Forward

### External validation gate

- fixture provenance/license와 expected result
- host/dependency/version 기록
- synthetic vs real 분리
- false positive/negative와 partial coverage
- original evidence no-write proof
- no legal/performance superiority overclaim

### Packaging gate

- clean install and CLI smoke
- optional extra matrix
- schema migration/reopen
- platform output permission/path behavior
- release gate artifact retention

### Product gate

- public engine contract를 통한 호출
- backend/GUI/MCP가 SQLite/analyzer를 직접 우회하지 않음
- identity/RBAC/billing과 forensic fact ownership 분리
- secret/prompt/provider data retention review

## 10. Excluded/Future Consideration

- Korean morphological analyzer
- live acquisition
- complete deleted/unallocated recovery
- all messenger/browser/Windows versions
- automatic KakaoTalk key extraction
- legal admissibility guarantee
- X-Ways/Autopsy 대비 우월성 claim

요구와 evidence가 생기면 별도 design/fixture/gate를 통해 추가한다.
