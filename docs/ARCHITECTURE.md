# APEX Core Architecture

## 1. 현재 상태와 경계

APEX Core는 hexagonal/layered 구조의 **Feature Complete Candidate**다. 이는 Core forensic 기능 구현 상태를 뜻하며 전체 제품 완성이나 real-evidence 정확도, packaging, 모든 optional dependency/host의 가용성을 뜻하지 않는다.

현재 구현 계층:

1. `domain`: forensic enum과 immutable/mutable DTO, canonical hash 규칙
2. `application`: case/evidence/index/artifact/search/timeline/context/AI/report orchestration
3. `ports`: evidence, filesystem, analyzer, decryption, OCR/STT, renderer 등 provider-neutral 경계
4. `adapters`: SQLite, evidence reader, pytsk3, Windows/browser/media/communications, decryption, renderer, optional AI provider
5. `cli`: 현재 실행 가능한 transport adapter
6. `runtime`와 `tools`: doctor, benchmark, semantic verification, release gate

현재 저장소에는 Desktop GUI, backend web server, identity/RBAC/billing, MCP server/SDK가 없다. 이들은 Core 분석 구현을 복제하지 않고 public engine contract를 소비해야 한다.

## 2. 현재 처리 Plane

| Plane | 현재 책임 | 대표 구현 |
|---|---|---|
| Evidence | read-only registration, fingerprint, hash, image range/volume | `EvidenceManager`, evidence adapters |
| Index | profile-driven progressive tree, queue/checkpoint/coverage | `FileSystemIndexService` |
| Artifact | source discovery, bounded independent analyzers, partial isolation | `ArtifactAnalysisService` |
| Recovery | unallocated/range/slack/deleted-file derived output | `EvidenceImageService` |
| Search/Timeline | FTS5, reproduction/cache, raw/UTC/case-time projection | `SearchService`, `TimelineService` |
| Context/View | live TTL context, immutable snapshot, scope page, bounded raw | context/view/interface services |
| AI assistance | provider-neutral request/result/review contracts | `AiAssistanceService` |
| Report | mutable aggregate, immutable versions, review/approval/render/export | `ReportService` |
| Diagnostics | capability probe, benchmark, semantic verifier, release gate | `runtime/*`, `tools/*` |

SQLite는 current case database의 단일 writer다. Adapter는 직접 business state를 결정하지 않고 domain 결과와 warning을 application service로 반환한다.

## 3. Evidence와 Filesystem Architecture

Evidence registration은 directory와 ordinary file을 받는다. Directory는 metadata-only 등록이며 canonical directory manifest hash는 없다. 확장자가 알려지지 않은 ordinary file은 현재 byte-stream `RAW`로 등록된다.

Reader boundary:

- RAW/DD/IMG: built-in random access와 partition enumeration
- E01/EWF: optional `pyewf`, segmented chain와 embedded-hash metadata
- VHD: optional `pyvhdilib`
- VHDX: optional `qemu-img` read-only raw cache conversion; differencing parent resolution은 지원하지 않음
- partition parser: MBR, extended partition chain, GPT/CRC warnings, protective MBR, superfloppy, unallocated gaps

Filesystem provider:

- logical directory/file provider는 OS metadata를 읽되 symlink/reparse point를 따라가지 않는다.
- `PyTskFileSystemProvider`는 RAW/DD/IMG의 NTFS/FAT12/16/32/exFAT/ext2/3/4 범위, deleted entry, extent와 slack metadata를 제공한다.
- E01/VHD/VHDX reader가 있어도 pytsk provider에 자동 연결되는 것으로 문서화하지 않는다.
- Quick Triage, Selected Scope, Full Analysis, Custom profile, lazy/cursor tree, prioritize, pause/cancel/resume, coverage가 구현되어 있다.

Recovery output은 원본과 분리된 derived root에만 생성된다. deleted recovery는 저장된 data run 범위만, slack/raw/unallocated는 bounded range만 처리하므로 complete carving이나 perfect recovery를 주장하지 않는다.

## 4. Artifact Architecture

모든 analyzer는 capability, version/backend, source kind, raw locator, citation, parse status와 partial/warning을 반환한다. 한 source의 corruption 또는 optional dependency 부재가 다른 analyzer 결과를 rollback하지 않는다.

### Windows

- Registry export text와 optional binary hive parsing
- optional `regipy` transaction-log replay
- built-in conservative free-cell/slack deleted-cell candidate carving
- Event XML bounded streaming과 optional binary EVTX
- Windows Event Message rendering adapter: pywin32 + Windows host가 필요
- Prefetch versions 17/23/26/30과 optional `dissect.util` MAM decompression

Deleted Registry cell은 current observed key/value가 아니라 carved candidate다. Event Message adapter 구현은 synthetic call-contract tests가 있지만 실제 registered provider rendering은 Windows host verification 대상으로 남는다.

### Browser, Communications, Media

Browser analyzer는 safe SQLite snapshot과 WAL/SHM provenance를 사용한다. Chromium/Firefox history, search/download 후보, cookie/credential metadata, Chromium opaque cache candidates, freelist/WAL deleted-presence candidates와 private-mode candidates를 다룬다. Deleted row content와 private browsing 사용을 확정하지 않는다.

Communications는 Core plugin으로 구현되었지만 범위가 좁다.

- Email: RFC5322 MBOX fixture schema, text/plain과 attachment reference
- Discord/Telegram: simple verified SQLite `messages` schema
- KakaoTalk artifact analyzer: encrypted store discovery/unsupported candidate
- KakaoTalk decryption provider: 별도 version-limited external-key path

Media는 image dimensions/EXIF/GPS, MP4 또는 optional ffprobe metadata, optional Pillow raster thumbnail과 ffmpeg one-frame sampling을 사용한다. OCR/STT는 별도 optional machine-extraction ports이며 결과는 review 전 Observed Fact가 아니다.

## 5. Decryption/Secret Recovery Plane

- Chromium AES-GCM: explicit external key path
- Offline DPAPI: optional `impacket`, external masterkey/password/NT-hash material과 bounded blob handling
- Firefox NSS: local `libnss3` profile path, supported `logins.json` version과 optional primary password
- KakaoTalk: Windows Desktop 2.0.8.990, external KPRAGMA+nonce 또는 raw key/IV, AES-128-CBC

Plaintext/keys는 persistent contract에 그대로 저장하지 않는다. 결과는 hash, length, redacted metadata와 citation 중심이다. Live-user secret extraction, app-bound Chromium key, automatic KakaoTalk key acquisition은 구현 완료로 취급하지 않는다.

## 6. Search와 Timeline

Search는 SQLite FTS5 capability를 실제 probe한다. 모드는 `TERM`, `PHRASE`, `PREFIX`, `EXACT`, `REGEX_METADATA`다. Query/options, keyword-set version, index/source revision, cache key와 결과가 reproduction을 위해 저장된다. Regex는 길이/구문/후보 범위를 제한한다.

한국어 정책은 Unicode NFC/casefold/path normalization과 FTS5 `unicode61`이다. 완성형과 canonical decomposed Hangul을 NFC 사본에서 맞추지만 형태소 분석은 하지 않는다.

Timeline source는 filesystem, Registry, Event Log, Prefetch, media, browser, communications, annotation이다. 원본 timestamp/timezone, 정당화된 UTC, IANA case timezone 표시, source/confidence/precision을 분리한다. timestamp를 해석할 수 없거나 upstream coverage가 partial이면 partial 상태를 보존한다.

## 7. Context와 Public Interface

Live `GuiSessionContext`는 기본 8시간 TTL과 optimistic `expected_revision`을 사용한다. `AnalysisContextSnapshot`은 immutable/content-fingerprinted이며 scope별 membership/revision/partial/stale/cursor를 보존한다. Refresh는 원본을 변경하지 않고 previous link를 가진 새 snapshot을 만든다.

Simple, Detailed, Raw view는 같은 resource revision의 projection이다. Raw read는 기본 4 KiB, 최대 1 MiB, evidence-root containment, locator 검증, EOF와 audit record를 적용한다.

`EngineInterfaceService`는 version 1.0.0, tool descriptors와 structured invocation을 제공한다. CLI/미래 GUI/HTTP/MCP가 공유할 interface이며 MCP transport 구현 자체는 아니다.

## 8. AI Architecture

Core의 AI 계약은 snapshot-first, provider-neutral, citation/review 기반이다. 기본 service는 unavailable provider를 사용하므로 LLM이 없어도 Core가 동작한다. 선택적 OpenAI-compatible HTTP adapter는 keyword, scope summary, report draft operation을 제공하지만 endpoint/model/API-key environment 설정이 필요하다.

금지 경계:

- MCP SDK 또는 agent loop를 Core에 결합하지 않음
- prompt, API key, raw provider response, chain-of-thought 저장 금지
- AI result를 filesystem/artifact/timeline Observed Fact로 승격하지 않음
- 승인 keyword를 자동 활성화하거나 search를 자동 실행하지 않음

### AI Data Governance

Case AI policy, data classification, deterministic egress evaluation, safe structural projection과
append-only assessment audit가 Engine contract로 추가되었다. `CaseAiPolicyService`,
`AiProjectionService`, `AiEgressService`는 기존 repository/DTO와 Secret Redaction 규칙을 재사용하며
provider 실행이나 전송을 수행하지 않는다. 누락된 정책은 deny이고 변환 후에는 재평가가 필요하다.
기존 optional provider 호출 경로에 대한 자동 강제 적용은 이번 Engine contract 범위에 포함되지 않는다.
상세 의미와 통합 책임은 [AI Data Governance](AI_DATA_GOVERNANCE.md)를 따른다.

## 9. Report Architecture

`reports`는 mutable workflow header이고 `report_versions`/sections/references는 immutable content다. Review와 approval/revocation은 optimistic revision과 hash-chain append-only event로 저장된다. Approval/export는 content fingerprint와 verified custody snapshot을 확인한다.

Runtime renderer boundary:

- HTML: built-in, UTF-8/HTML escaping, synthetic Korean/Unicode test
- PDF: optional ReportLab, Unicode CID font registration을 시도하며 dependency가 없으면 `CAPABILITY_UNAVAILABLE`
- approved render package만 허용
- portable filename, traversal/root escape, symlink/collision/overwrite 방지
- temporary output과 hash/magic verification

이는 legal evidentiary effect, electronic signature 또는 backend identity approval policy를 보장하지 않는다.

## 10. Runtime Diagnostics와 Release Hardening

`doctor`는 정확한 current-host capability ID와 status를 출력하며 secret/environment value/name을 출력하지 않는다. 주요 ID는 `raw-dd-img`, `pytsk3`, `e01-libewf`, `vhd-libvhdi`, `vhdx-qemu-img`, Windows parser/renderer, `pillow`, `ffmpeg`, `rapidocr`, `onnx-runtime`, `faster-whisper`, `firefox-nss`, `dpapi-impacket`, `html-renderer`, `pdf-renderer`, `ai-provider-openai-compatible`, `kakaotalk-existing`이다.

Benchmark는 deterministic synthetic fixture 또는 user-provided read-only evidence로 Quick/Full pipeline, cold/warm search, throughput와 Peak RSS를 기록하고 before/after metadata snapshot으로 read-only invariant를 확인한다. 다른 제품보다 빠르다는 비교 주장을 생성하지 않는다.

Release gate는 pytest, Ruff, mypy, diff check, design/schema validation, runtime semantic probe, recovery/fault tests, Bandit disposition audit, benchmark, CLI/Unicode/read-only checks를 모은다. Optional/host/external limitation이 있으면 pass와 구분한 limitation status를 유지한다.

## 11. Verification State

| Area | Repo-local evidence | 상태 |
|---|---|---|
| Core services/contracts | unit/integration tests와 schemas | IMPLEMENTED_SYNTHETICALLY_VERIFIED |
| E01/VHD/VHDX, optional binaries | dependency-conditional tests | IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY |
| Registry transaction replay | bundled compressed Registry fixtures + optional regipy | IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY |
| Event Message rendering | mocked contract + verifier | HOST_VERIFICATION_REQUIRED |
| DPAPI/NSS/OCR/STT | adapters/verifiers, 일부 synthetic/config-driven tests | dependency/config/host별 상태 필요 |
| HTML/PDF | HTML synthetic verified; PDF dependency-gated tests/verifier | HTML IMPLEMENTED, PDF OPTIONAL |
| KakaoTalk | synthetic AES/SQLite contract only | BLOCKED_EXTERNAL_FIXTURE |
| Real evidence accuracy/performance | persistent result artifact 없음 | external validation required |

## 12. Product Deployment Boundary

Frontend는 Desktop UX, screen rendering/resource bundle과 사용자 상호작용을 소유한다. Backend는 authenticated product session, identity, RBAC, billing과 organization approval policy를 소유한다. Core의 `GuiSessionContext`는 인증 session이 아니라 forensic selection/view state다. MCP/AI product layer는 MCP transport, tool registration, provider selection, prompt와 agent loop를 소유한다. Core는 forensic facts, immutable/reproducible contracts, capability와 provenance를 소유한다.

## 13. Historical Phase Boundaries

초기 Phase 1~8 문서에서 disk image traversal, communications, OCR/STT, Registry carving, Event Message adapter, DPAPI/NSS, runtime renderer를 “없음”으로 적은 내용은 당시 구현 경계였다. 현재 상태 설명으로 사용하지 않는다. 초기 `src/apex` 제안도 historical design이며 실제 package는 `src/apex_forensic`이다.
