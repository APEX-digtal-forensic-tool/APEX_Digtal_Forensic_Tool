# APEX Forensic Core Engine

## 1. 목적과 제품 경계

APEX Forensic Core Engine은 read-only evidence 처리, forensic fact/candidate 생성, provenance, search/timeline/context/report 계약을 제공하는 Python runtime이다. 현재 Core는 **Feature Complete Candidate**이며 다음 조건을 별도로 남긴다.

- real external evidence의 정확도/coverage 검증
- optional dependency와 host별 capability
- packaging/CI matrix/external expert review
- KakaoTalk real encrypted fixture와 automatic key acquisition blocker
- Desktop GUI, backend identity/RBAC/billing, HTTP/MCP product integration

Core 기능 완성 후보를 전체 APEX 제품 완성과 동일시하지 않는다. 법적 증거 효력, 전자서명, 모든 forensic format 지원 또는 타 제품 대비 성능 우위를 보장하지 않는다.

## 2. 상태 용어

| 상태 | 의미 |
|---|---|
| `IMPLEMENTED` | current source와 service/CLI path 존재 |
| `IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY` | adapter는 있으나 dependency/host에 따라 unavailable |
| `IMPLEMENTED_SYNTHETICALLY_VERIFIED` | repository test/fixture로 contract와 behavior 검증 |
| `AVAILABLE_WITH_LIMITATIONS` | runtime probe 성공 또는 adapter 가용하지만 알려진 제한 존재 |
| `CAPABILITY_UNAVAILABLE` | current host dependency/API가 없음 |
| `HOST_VERIFICATION_REQUIRED` | Windows 등 필요한 host에서 semantic 실행 필요 |
| `EXTERNAL_CONFIGURATION_REQUIRED` | executable/model/profile/key/provider 설정 필요 |
| `BLOCKED_EXTERNAL_FIXTURE` | real fixture/evidence가 없어 실제 호환성 주장을 차단 |
| `UNSUPPORTED_PLATFORM` | 명시적으로 지원하지 않는 platform |
| `PLANNED` | product/transport/external validation 후속 작업 |

“implemented”는 real-world fixture 검증을 자동으로 의미하지 않는다.

## 3. Current Overall Status

현재 application service bundle은 Case, Evidence/Image, Custody, Filesystem, Artifact, Search, Timeline, Machine Candidate, AI Assistance, Report, Context/View, Public Engine Interface를 연결한다. CLI가 이를 실행한다. SQLite와 schemas/tests가 runtime contract를 고정한다.

Core runtime에는 다음이 구현되어 있다.

- evidence registration/hash/volume/range와 progressive filesystem
- recovery output
- Windows/browser/media/communication artifact
- search/timeline
- GUI/session context와 public interface
- provider-neutral AI assistance와 optional configured provider
- report review/approval/render/export
- capability doctor, deterministic benchmark와 release gate

현재 HTTP server, Desktop GUI, MCP server/SDK는 없다.

## 4. Evidence와 Reader

### 4.1 Directory와 Ordinary File

- Directory evidence: metadata registration과 logical tree indexing이 가능하다. canonical directory manifest hash는 없으므로 directory hash 요청은 capability error다.
- Ordinary file: 알려진 image suffix가 아니면 현재 `RAW` byte-stream으로 등록한다. logical provider는 그 파일을 one-file evidence root로 표현할 수 있다.
- 모든 evidence는 read-only flag와 source fingerprint/provenance를 보존하고 symlink/reparse traversal을 기본 거부한다.

### 4.2 Image Formats

| Format | 상태 | 경계 |
|---|---|---|
| RAW/DD/IMG | IMPLEMENTED | built-in read/random access/partition enumeration |
| E01/EWF | IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY | `pyewf`, first segment/chain/signature, embedded hash metadata |
| VHD | IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY | `pyvhdilib` |
| VHDX | IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY | `qemu-img` conversion to temporary read-only raw cache |
| VHDX differencing parent | CAPABILITY_UNAVAILABLE | parent resolution disabled |

Partition parser는 MBR, extended/EBR chain, GPT와 CRC warning, protective MBR, superfloppy, unallocated gap을 생성한다. Corrupt/out-of-bounds 상태는 warning/unsupported로 분리한다.

## 5. Filesystem, Progressive Index와 Recovery

Analysis profiles:

- `QUICK_TRIAGE`
- `SELECTED_SCOPE`
- `FULL_ANALYSIS`
- `CUSTOM`

Queue/checkpoint/coverage, selected-scope priority, pause/cancel/resume, lazy root/child traversal와 stable cursor pagination이 구현되어 있다. Original path와 search comparison path를 분리한다.

`PyTskFileSystemProvider`의 current scope:

- RAW/DD/IMG
- NTFS, FAT12/16/32, exFAT, ext2/3/4 family
- allocated/deleted entry, extents, slack metadata
- stable raw locator

E01/VHD/VHDX reader availability이 pytsk filesystem 연결을 자동 보장하지 않는다.

Recovery operations:

- partition-level unallocated range list/read/export
- bounded raw range read/export
- deleted file data-run recovery
- file slack export

출력은 configured derived root 안에 생성되고 custody audit가 추가된다. Stored run/extent로 읽을 수 있는 범위만 처리하므로 complete deleted-file carving이나 perfect recovery가 아니다. Generic unallocated file carving은 planned boundary다.

## 6. Windows Artifacts

### 6.1 Registry

- Registry export text: IMPLEMENTED
- Binary hive: optional `python-registry`
- Adjacent transaction logs: optional `regipy` replay, original hive를 변경하지 않고 temp restored hive 사용
- Deleted-cell carving: built-in conservative NK/VK free-cell/slack candidate
- Autorun, USB, timezone, UserAssist candidate projections

Carved record는 current observed value가 아니라 `deleted_candidate=true`인 candidate다. Parentage와 completeness가 partial일 수 있으며 transaction replay fact와 별도 provenance를 유지한다.

### 6.2 Event Log

- Exported Event XML: bounded streaming; total 64 MiB, record 2 MiB safety limit
- Binary EVTX: optional `python-evtx`
- Event Message: Windows Eventing/pywin32 adapter 구현

Message DLL rendering은 구현되었지만 non-Windows에서는 `HOST_VERIFICATION_REQUIRED`다. Mocked API contract test는 실제 Windows registered publisher resource 검증과 동일하지 않다.

### 6.3 Prefetch

Versions 17, 23, 26, 30의 safe header/run count/time을 처리한다. MAM wrapper를 탐지하고 optional `dissect.util` LZXPRESS-Huffman으로 bounded decompress한다. Unsupported version, corrupt/signature/size mismatch는 success fact로 만들지 않는다. Prefetch 단독으로 user execution을 확정하지 않는다.

## 7. Browser

Chromium과 Firefox profile/store를 safe SQLite snapshot으로 읽으며 WAL/SHM component hash와 source revision을 보존한다.

구현 범위:

- Chromium/Firefox visit history
- Chromium search terms
- Firefox `moz_inputhistory`는 confirmed search가 아닌 URL-bar input candidate
- Chromium downloads와 Firefox annotation-based partial download candidate
- Chromium/Firefox cookie metadata
- Chromium credential metadata
- Chromium opaque cache file candidate
- SQLite freelist/WAL presence 기반 deleted-row candidate
- path indicator 기반 private-mode candidate
- cursor/resume, search/timeline projection

제한:

- cookie/credential secret는 기본 redacted
- deleted record content recovery는 하지 않고 presence candidate만 생성
- private use 또는 private use 부재를 확정하지 않음
- Chromium cache HTTP header/URL key 전체 decode 없음
- live browser acquisition/cloud sync 없음

Chromium v10+ AES-GCM은 explicit external key로 복호화할 수 있다. OS-protected key recovery는 아래 DPAPI adapter availability/configuration에 의존한다.

## 8. Communications

Current communications analyzer는 **fixture-schema-limited core plugin**이다.

| Application | 구현 범위 | 명시적 미지원 |
|---|---|---|
| Email | RFC5322 MBOX, text/plain, message/conversation/attachment reference | PST/OST |
| Discord | verified simple SQLite `messages(id, conversation_id, sender, recipients, timestamp, body)` | native LevelDB/cache |
| Telegram | 같은 limited SQLite fixture schema | tdesktop native binary |
| KakaoTalk artifact analyzer | encrypted store discovery/structured unsupported candidate | automatic decrypt in artifact pipeline |

Secret/token-like content를 redaction하고 Korean/Unicode와 stable checkpoint/provenance를 보존한다. “all versions supported” 또는 production-native Discord/Telegram database support로 넓혀 표현하지 않는다.

## 9. KakaoTalk Boundary

`KakaoTalkEncryptedStoreProvider`의 정확한 current contract:

- platform: Windows Desktop only
- application version: `2.0.8.990` only
- source: 명시적 offline root
- discovery: `chatLogs.edb` 또는 `chatLogs_*.edb`, 최대 depth/entry/candidate/size/hash budget
- path safety: symlink/reparse point와 root escape 차단
- version evidence: `KakaoTalk.exe` PE `VS_FIXEDFILEINFO`
- key input: 외부 KPRAGMA + user/server nonce 또는 외부 raw DB key + IV
- cipher: AES-128-CBC + PKCS#7
- validation: SQLite header, read-only/query-only, `PRAGMA quick_check(1)`
- schema: `chatLogs` table, required `logId`와 message/attachment 중 하나, supported columns에 한정
- output: 최대 5,000 row, hashed/redacted message metadata와 row citation

현재 automatic key acquisition은 구현되지 않았다. 필요한 built-in KPRAGMA/device/disk/nonce mapping과 redistributable encrypted database 근거가 없어 `BLOCKED_EXTERNAL_FIXTURE`다. Repository test는 synthetic AES-CBC SQLite contract이며 실제 KakaoTalk DB 검증이 아니다. `real_kakaotalk_fixture_verified=false`를 유지한다. Android/iOS는 `UNSUPPORTED_PLATFORM`이다.

## 10. Media, OCR와 STT

Media metadata:

- image classification/dimensions
- JPEG EXIF와 raw/normalized GPS
- PNG/GIF/TIFF dimensions
- MP4 duration/codec
- optional `ffprobe` video/audio metadata
- optional Pillow raster PNG thumbnail
- optional `ffmpeg` bounded one-frame sampling

OCR providers:

- Tesseract CLI: executable/language/tessdata configuration
- RapidOCR + onnxruntime: optional Python packages; model inference 상태를 capability가 구분

STT providers:

- whisper.cpp CLI: executable/model path
- faster-whisper: optional package와 explicit local model; auto-download하지 않음

OCR/STT output은 immutable machine-extracted candidate와 append-only analyst review/correction으로 저장된다. Candidate는 Observed Fact가 아니다. 실제 Korean model/font/audio fixture가 없는 실행은 검증 완료로 주장하지 않는다.

## 11. Search

Backend는 SQLite FTS5 availability를 in-memory probe한다. 지원 모드:

- `TERM`
- `PHRASE`
- `PREFIX`
- `EXACT`
- `REGEX_METADATA`

Index source는 filesystem metadata, allowlisted artifact fields와 optional timeline projection이다. Full file-body/Office/PDF text extraction은 포함하지 않는다.

Normalization:

- NFC
- casefold
- backslash → slash
- whitespace/path separator normalization
- FTS5 `unicode61`

Canonical decomposed Hangul과 composed Hangul을 NFC copy에서 일치시키지만 한국어 형태소 분석을 하지 않는다. Query/options fingerprint, keyword set version, index/source revision, cache hit와 result를 보존해 rerun한다. Regex는 pattern length, bounded repeat와 candidate 범위를 제한한다.

## 12. Timeline

Source types:

- filesystem node
- Registry artifact
- Event Log artifact
- Prefetch artifact
- media
- browser
- communication
- analyst annotation

Timestamp fields는 raw value/timezone, normalized UTC, displayed case time, IANA case timezone, source, confidence, semantics와 precision을 분리한다. Naive/ambiguous timestamp를 임의로 UTC fact로 만들지 않는다. Upstream partial/corrupt/unknown 상태와 build coverage를 timeline event/page에 보존한다.

## 13. Context와 Simple/Detailed/Raw

- live GUI session context: mutable, 기본 TTL 8시간
- optimistic revision: update마다 `expected_revision` 확인
- immutable analysis snapshot: content fingerprint와 previous-snapshot lineage
- scope contexts: case/evidence/filesystem/registry/eventlog/prefetch/browser/media/timeline/keyword/machine/custody/report/selection
- independent scope fingerprint/revision/partial/stale/cursor
- Simple/Detailed/Raw: 같은 source revision의 projection
- raw read: 기본 4 KiB, 최대 1 MiB, case/evidence/root/locator 검증과 append-only audit

Public Engine Interface 1.0.0은 descriptor와 read/mutation invocation을 구현한다. GUI/MCP consumer가 사용할 계약이지만 현재 GUI나 MCP transport를 의미하지 않는다.

## 14. DPAPI, NSS와 Decryption

### Chromium/DPAPI

- external-key AES-GCM provider: optional `cryptography`
- offline DPAPI provider: optional `impacket`
- bounded DPAPI blob/masterkey parsing
- external masterkey, password/NT hash 등의 offline material
- Local State DPAPI-wrapped key inspection/decrypt path
- app-bound encrypted key는 unsupported version

### Firefox NSS

- local `libnss3` symbols
- offline profile discovery
- `key4.db`와 `logins.json` version 3 probe
- optional primary password
- PK11SDR decrypt
- decrypted username/password를 persistent output에서 redaction

Adapter 구현은 모든 user profile/credential recovery를 보장하지 않는다. Host/profile/key/password와 dependency가 필요하며 verifier result에 따라 `CAPABILITY_UNAVAILABLE`, `EXTERNAL_CONFIGURATION_REQUIRED` 또는 host/fixture limitation을 유지한다.

## 15. Chain of Custody

Evidence registration/hash verification/recovery/export action은 append-only custody event와 canonical previous/event hash chain으로 연결된다. Correction은 기존 event 수정이 아니라 `CORRECTION` event다. Report approval/export는 custody snapshot verification을 확인한다.

이 구조는 integrity/audit mechanism이다. 조직 policy, 서명, 인증, 법원 admissibility를 자동 보장하지 않는다.

## 16. Report Runtime

- mutable `ReportRecord` aggregate
- immutable/fingerprinted versions와 sections/references
- section accept/reject/comment/change request/reopen
- review revision/hash chain
- approval/rejection/revocation revision/hash chain
- custody snapshots
- deterministic render packages
- export manifests와 rendered artifact/audit
- built-in HTML renderer
- optional ReportLab PDF renderer

승인된 version만 runtime render한다. HTML은 escaped UTF-8이며 synthetic Korean text test가 있다. PDF는 ReportLab와 font registration에 의존하며 capability-gated다. Output filename/root containment, traversal, Windows reserved name, collision/overwrite, temp cleanup, permission와 output hash/magic을 검증한다.

## 17. Runtime Doctor, Benchmark와 Release Gate

`doctor` exact capability IDs:

`python`, `sqlite`, `sqlite-fts5`, `raw-dd-img`, `pytsk3`, `e01-libewf`, `vhd-libvhdi`, `vhdx-qemu-img`, `filesystem-provider`, `registry-parser`, `registry-binary-parser`, `registry-deleted-cell-carving`, `event-log-parser`, `event-log-binary-parser`, `prefetch-parser`, `prefetch-mam`, `windows-event-message-renderer`, `pillow`, `browser-cryptography`, `ffmpeg`, `ffprobe`, `rapidocr`, `onnx-runtime`, `faster-whisper`, `firefox-nss`, `dpapi-impacket`, `html-renderer`, `pdf-renderer`, `ai-provider-openai-compatible`, `kakaotalk-existing`.

`benchmark`는 deterministic synthetic fixture 또는 user-provided read-only evidence로 Quick/Full indexing/artifact/search/timeline, cold/warm latency, throughput와 Peak RSS를 측정한다. Evidence before/after snapshot으로 no-write invariant를 확인한다. Comparative superiority flag는 false다.

`verify_engine_release.py`는 full/focused pytest, Ruff, mypy, diff check, design/schema validators, Windows semantic verifier, doctor, recovery/fault tests, Bandit disposition, benchmark/read-only, CLI/Unicode를 묶는다. Optional/host/config limitation이 있으면 release-ready-on-this-host와 분리한다.

## 18. Capability-driven Limitations

- E01, VHD, VHDX, binary Registry/EVTX, MAM, Pillow, ffmpeg/ffprobe, OCR/STT, DPAPI, NSS, PDF는 host dependency에 따라 달라진다.
- Windows Event Message는 Windows host + pywin32가 필요하다.
- OpenAI-compatible adapter는 URL/model/API-key environment 설정과 network가 필요하다.
- KakaoTalk provider는 cryptography와 external key/nonce가 필요하며 automatic acquisition은 blocked다.
- Internal module import 성공은 real forensic fixture 정확도 검증이 아니다.

## 19. Explicit Unsupported Boundaries

- live acquisition 또는 원본 쓰기
- all-format/all-version forensic support
- Korean morphological search
- YARA나 arbitrary body full-text
- complete unallocated carving/perfect deleted recovery
- production-native PST/OST, Discord LevelDB, Telegram tdesktop
- automatic KakaoTalk key extraction, Android/iOS KakaoTalk
- live-user credential extraction과 unsupported Chromium app-bound key
- Desktop GUI, running HTTP server, MCP server/tool registration
- Core-required LLM, prompt/agent loop
- backend identity/session/RBAC/billing
- electronic signature/legal evidentiary guarantee
- X-Ways/Autopsy 등과의 성능 우위 주장

## 20. Verification와 Development Status

| 범위 | 현재 증거 | 판정 |
|---|---|---|
| Core contracts/services | schemas + unit/integration tests | IMPLEMENTED_SYNTHETICALLY_VERIFIED |
| E01/VHD/VHDX/pytsk | dependency-aware tests | optional/dependency-gated |
| Windows parsing/carving | synthetic + bundled Registry replay fixtures | implemented; per-backend capability |
| Event Message | mocked contract + Windows verifier | HOST_VERIFICATION_REQUIRED |
| Browser/media/comms | synthetic/limited fixture tests | implemented with documented limitations |
| OCR/STT/DPAPI/NSS | adapter/verifier/config-driven tests | optional; environment-specific |
| HTML | synthetic UTF-8/Korean runtime test | IMPLEMENTED |
| PDF | ReportLab-gated test/verifier | IMPLEMENTED_WITH_OPTIONAL_DEPENDENCY |
| KakaoTalk | synthetic algorithm/SQLite contract | BLOCKED_EXTERNAL_FIXTURE |
| Real evidence benchmark/accuracy | no persistent repository result | external validation remaining |

Development status는 Core feature-complete candidate와 release hardening implementation 완료다. 남은 것은 real evidence/host validation, optional runtime provisioning, packaging/CI, external expert review와 product integration이다.
