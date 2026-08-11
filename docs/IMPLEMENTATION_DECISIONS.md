# APEX Implementation Decision Log

이 문서는 설계/구현 의사결정의 이력을 보존한다. 과거 decision을 현재 상태로 읽지 않도록 각 항목에 `CURRENT`, `HISTORICAL` 또는 `SUPERSEDED`를 표시한다.

## 1. Foundation Decisions

| Decision | 당시 이유 | 현재 상태 |
|---|---|---|
| Python package는 `src/apex_forensic` | CLI entry point와 package identity 일치 | **CURRENT**. 초기 `src/apex` proposal은 historical |
| SQLite table은 먼저 minimum runtime name 사용 | 초기 conceptual schema와 executable Phase 1 요구가 달랐음 | **CURRENT/SUPERSEDED IN PART**. Current DDL이 권위이며 conceptual names는 docs appendix |
| Ordinary logical file은 `RAW` byte stream 등록 | 별도 logical-file EvidenceFormat 부재 | **CURRENT** |
| Directory evidence는 metadata-only, manifest hash 없음 | canonical directory hash policy 미정 | **CURRENT** |
| MD5/SHA1/SHA256 streaming hash | 기존 schema의 SHA1 누락 보강 | **CURRENT** |
| Custody hash chain은 legal effect를 주장하지 않음 | 법적 효력은 조직/관할 정책 문제 | **CURRENT** |
| MCP/prompt directory를 Core validator가 거부 | provider/transport coupling 방지 | **CURRENT** |

## 2. Historical Phase 2 Decisions

- **Historical decision**: logical provider만 구현하고 disk image internal traversal은 `CAPABILITY_UNAVAILABLE`로 반환한다.
  - **Superseded by**: RAW/DD/IMG reader, partition parser와 optional pytsk3 image filesystem provider.
  - E01/VHD/VHDX reader availability이 pytsk traversal을 자동 제공하지 않는 제한은 current다.
- **Current decision**: deterministic provider node ID, original/comparison path 분리, SQLite single writer, queue/checkpoint/coverage와 cursor fingerprint.
- **Current decision**: symlink/reparse point는 기록하되 기본 traversal하지 않는다.
- **Current decision**: ETA 근거가 부족하면 null/UNKNOWN을 유지한다.

## 3. Historical Phase 3 Decisions

- **Historical decision**: Registry transaction replay, deleted key recovery, Event Message DLL rendering, MAM decompression은 미구현 경계다.
  - **Superseded by**:
    - optional regipy transaction-log replay
    - built-in Registry free-cell/slack candidate carving
    - Windows/pywin32 Event Message renderer
    - optional dissect.util MAM decompression
- **Current decision**: text Registry/Event XML/minimal Prefetch는 bounded local parser로 유지한다.
- **Current decision**: binary Registry/EVTX/MAM은 optional dependency absence를 success로 바꾸지 않는다.
- **Current decision**: Registry carved cell은 Observed Fact가 아닌 candidate이며 transaction replay provenance와 분리한다.
- **Current decision**: Event XML은 total/record byte limit을 적용하고 oversized input을 structured failure로 격리한다.
- **Current decision**: Prefetch만으로 user execution을 단정하지 않는다.

## 4. Phase 4 Search/Timeline Decisions

| Decision | 현재 결과 |
|---|---|
| FTS5 실제 runtime probe | 없으면 `CAPABILITY_UNAVAILABLE` |
| metadata/artifact 중심 index | arbitrary file-body extraction 없음 |
| allowlisted search projection | secret/large JSON을 index에서 제한 |
| bounded `REGEX_METADATA` | pattern/repeat/candidate 제한 |
| keyword set versioning | search reproduction이 정확한 version 참조 |
| cache와 reproduction 분리 | cache hit도 새 execution/result audit 생성 |
| raw/UTC/case time 분리 | IANA case timezone과 source/confidence 보존 |
| Korean NFC + unicode61 | canonical jamo composition; 형태소 분석 없음 |

## 5. Historical Phase 5 Decisions

- **Historical decision**: Email/messenger는 plugin scope이며 Core parser는 등록하지 않는다.
  - **Superseded by**: limited Core communications plugin의 MBOX Email, simple Discord/Telegram SQLite fixture analyzers.
  - PST/OST, Discord LevelDB, Telegram native tdesktop와 broad version support는 여전히 unavailable이다.
- **Historical decision**: thumbnail은 derivative metadata만 생성하고 raster rendering은 실행하지 않는다.
  - **Superseded by**: optional Pillow raster PNG thumbnail.
- **Historical decision**: OCR/STT execution 없이 provider-neutral candidate store만 둔다.
  - **Superseded by**: optional Tesseract/RapidOCR 및 whisper.cpp/faster-whisper runtime adapters.
  - Candidate가 Observed Fact가 아니고 human review가 필요하다는 원칙은 current다.
- **Current decision**: Browser는 source SQLite를 직접 변경하지 않고 WAL/SHM을 포함한 temporary snapshot을 사용한다.
- **Current decision**: browser secret는 redacted metadata가 기본이며 external-key/DPAPI/NSS adapter로 분리한다.
- **Current decision**: freelist/WAL와 private-mode는 candidate semantics만 제공한다.

## 6. Phase 6 Context/Public Interface Decisions

- Live context와 immutable snapshot은 별도 table/model로 분리한다.
- Live context는 TTL과 optimistic `expected_revision`을 사용한다.
- Equivalent content fingerprint에서 transient ID/time/lineage를 제외하고 previous link는 별도 저장한다.
- Scope membership은 persist해 bounded pagination과 stale refresh를 재현한다.
- Simple/Detailed/Raw는 같은 source revision의 projection이다.
- Raw read는 최대 1 MiB, evidence root/locator/case를 검증하고 append-only audit를 남긴다.
- Public Engine Interface는 CLI/미래 GUI/HTTP/MCP가 공유하는 contract다.
- **Historical decision**: interface descriptor만 있고 operations가 제한적이다.
  - **Superseded by**: current context/view/AI/report read/mutation operation registry.
- MCP server/SDK 자체는 여전히 product-layer planned boundary다.

## 7. Phase 7 AI Decisions

- Snapshot-first request, source revision, TTL, coverage와 citation을 고정한다.
- Provider output과 CLI ingest는 같은 validation path를 통과한다.
- AI recommendation/summary/draft는 `NOT_OBSERVED_FACT`이고 artifact/timeline을 수정하지 않는다.
- Human verification/promotion은 append-only/hash-linked이며 keyword promotion은 draft set만 만들고 search/activation을 자동 수행하지 않는다.
- Prompt, API key, raw provider body, credential, chain-of-thought 저장을 거부한다.
- **Historical decision**: runtime AI provider execution은 Core에 구현하지 않는다.
  - **Superseded by**: optional `OpenAICompatibleProvider` HTTP adapter.
  - Default service는 unavailable provider이고 LLM은 Core 필수 dependency가 아니며 external configuration/network가 필요하다.
- MCP, tool registration, agent loop와 product prompt strategy는 여전히 Core 밖이다.

## 8. Phase 8 Report Decisions

- `reports` mutable header와 immutable/fingerprinted `report_versions`을 분리한다.
- Content fingerprint는 transient sequence metadata를 제외해 idempotent replay를 지원한다.
- AI draft는 기존 assistance request/citation을 검증하고 raw provider body를 저장하지 않는다.
- Review와 approval/revocation은 optimistic revision + append-only hash chain이다.
- Approval/export는 exact content fingerprint와 custody verification을 요구한다.
- Export filename과 `derived://` reference는 root containment/portable policy를 적용한다.
- **Historical decision**: export는 contract만 있고 실제 PDF/HTML rendering은 없다.
  - **Superseded by**: `RuntimeReportRenderer`.
  - HTML은 built-in; PDF는 optional ReportLab; approved package만 render.
- Renderer output은 collision overwrite를 거부하고 temp cleanup, hash와 magic을 검증한다.
- Electronic signature, backend approver identity/RBAC와 legal effect는 Core가 소유하지 않는다.

## 9. Advanced Evidence Reader Decisions

- RAW/DD/IMG built-in reader는 bounded random access와 partition enumeration을 제공한다.
- E01은 optional pyewf이며 segment chain/signature/dependency를 capability-honest하게 처리한다.
- VHD는 optional pyvhdilib, VHDX는 qemu-img conversion을 사용한다.
- VHDX differencing parent resolution은 enabled하지 않는다.
- MBR extended chain/GPT CRC/protective MBR/superfloppy/unallocated range는 malformed input에 bounds를 적용한다.
- Recovery output은 new derived file이며 evidence 원본에 쓰지 않는다.
- Deleted file recovery는 recorded run을 사용하므로 complete recovery claim을 금지한다.

## 10. Registry Carving와 Event Rendering Decisions

- Registry free-cell/slack carving은 bounded, conservative candidate producer다.
- False positive를 줄이기 위해 NK/VK structure/name/size bounds를 검증한다.
- Carved parentage가 완전하지 않을 수 있으므로 confidence/partial/provenance를 표기한다.
- Transaction replay는 adjacent logs와 temp restored hive를 사용하고 source hashes를 기록한다.
- Event Message renderer는 Windows registered provider trust boundary에 있으며 non-Windows result를 PASS로 만들지 않는다.
- Mocked pywin32 contract와 actual host semantic verification을 구분한다.

## 11. Browser Secret Recovery Decisions

- Chromium AES-GCM은 explicit external key가 있어야 decrypt한다.
- Offline DPAPI는 optional impacket adapter로 격리하고 blob/masterkey size와 offline credential를 검증한다.
- Firefox NSS는 local libnss3/profile schema/version/password 경계로 격리한다.
- Decrypted plaintext는 persistent result에 raw로 노출하지 않고 hash/length/redacted metadata를 사용한다.
- App-bound Chromium keys, live-user unprotect와 “all credentials recovered” 표현을 지원하지 않는다.

## 12. OCR/STT Decisions

- OCR/STT는 ports + optional runtime adapters다.
- Executable/package/model/language/profile configuration을 capability로 표면화한다.
- faster-whisper model을 자동 download하지 않는다.
- Korean fixture/model/font/audio validation이 실제로 실행되지 않으면 verified로 기록하지 않는다.
- Machine candidate 원문은 immutable하고 analyst correction은 append-only event다.

## 13. Runtime Doctor Decisions

- Doctor는 import/API/executable/platform/in-memory semantic probe를 수행한다.
- Secret value, environment value와 environment variable name을 출력하지 않는다.
- Internal module import, optional dependency, Windows host, external config를 다른 status/reason으로 구분한다.
- Kakao capability는 external-key-only와 automatic acquisition blocker를 명시한다.

## 14. Benchmark Decisions

- default fixture는 deterministic synthetic이며 user evidence는 explicit read-only input이다.
- profile/run마다 fresh database를 사용한다.
- cold/warm search를 분리하고 elapsed/throughput/Peak RSS를 기록한다.
- before/after evidence metadata snapshot으로 read-only invariant를 확인한다.
- benchmark 결과로 다른 forensic tool 대비 superiority를 주장하지 않는다.
- Benchmark result table을 current case DB에 발명하지 않고 JSON output으로 유지한다.

## 15. Recovery/Fault-injection Decisions

- SQLite busy/locked는 retryable structured error, corrupt/not-a-db는 non-retryable error로 변환한다.
- Failed write는 rollback하고 이후 writer recovery를 test한다.
- Filesystem/artifact resume/cancel과 temporary derived output cleanup을 regression test한다.
- Retry를 위한 arbitrary sleep보다 deterministic contention/failure injection을 사용한다.

## 16. Bandit Disposition Decisions

- Medium/High finding은 `tools/security_findings.json`의 exact test/location/disposition/justification과 현재 scan을 대조한다.
- `FALSE_POSITIVE_WITH_JUSTIFICATION` 등 허용 disposition은 “Bandit clean”과 다르다.
- New unclassified 또는 stale classification은 release gate failure다.
- Dynamic SQL은 hardcoded allowlist/placeholder 경계를 근거로 개별 disposition한다.

## 17. Release Gate Decisions

- `tools/verify_engine_release.py`가 pytest, Ruff, mypy, diff/design/schema, runtime semantic verifier, doctor, recovery, Bandit, benchmark/read-only, CLI/Unicode를 결합한다.
- Optional dependency/host/config 부재는 allowed limitation status일 수 있지만 `release_ready_on_this_host`와 구분한다.
- Semantic JSON 내용이 맞아야 PASS이며 process exit code만으로 판정하지 않는다.
- KakaoTalk는 automatic/real-fixture blocker 때문에 default release semantic probe에서 별도 경계로 유지한다.

## 18. KakaoTalk Runtime Decisions

- Windows Desktop `2.0.8.990`과 `chatLogs`만 지원 matrix에 둔다.
- Offline root traversal은 bounded하고 symlink/reparse/root escape를 거부한다.
- `KakaoTalk.exe` PE fixed version resource가 정확히 일치해야 한다.
- 외부 KPRAGMA+nonce 또는 raw key+IV만 받는다.
- AES-128-CBC/PKCS#7 후 SQLite header, `quick_check(1)`, table/column을 검증한다.
- Automatic key acquisition을 구현 또는 검증했다고 표시하지 않는다.
- Synthetic AES/SQLite fixture를 actual KakaoTalk fixture로 명명하지 않는다.
- Android/iOS를 지원 범위로 확장하지 않는다.
- 실제 encrypted fixture가 없으므로 `BLOCKED_EXTERNAL_FIXTURE`를 유지한다.

## 19. Product Boundary Decisions

- Frontend: Desktop UX/rendering/resource bundle
- Backend: identity/session/RBAC/billing/approval identity policy
- MCP/AI product layer: MCP transport/tool registration, provider selection, prompts, agent loop
- Core: forensic facts/candidates, provenance, immutable contracts, capability와 bounded operations

Core의 optional OpenAI-compatible adapter와 future MCP boundary가 존재해도 product ownership 구분은 유지한다.
