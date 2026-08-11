# Current Repository Structure

이 문서는 현재 `/workspace/APEX` tree를 설명한다. 초기 제안인 `src/apex` layout은 사용하지 않으며 실제 Python package는 `src/apex_forensic`이다.

## 1. High-level Tree

~~~text
APEX/
├── pyproject.toml
├── README.md
├── docs/
│   ├── API_INTERFACE.md
│   ├── ARCHITECTURE.md
│   ├── DATABASE_SCHEMA.md
│   ├── DIRECTORY_STRUCTURE.md
│   ├── FORENSIC_ENGINE.md
│   ├── IMPLEMENTATION_DECISIONS.md
│   ├── IMPLEMENTATION_ROADMAP.md
│   ├── JSON_SCHEMAS.md
│   ├── MODULE_RESPONSIBILITIES.md
│   └── REQUIREMENTS_TRACEABILITY.md
├── schemas/
│   └── v1/                         # 66 Draft 2020-12 contracts
├── src/
│   └── apex_forensic/
├── tests/
│   ├── fixtures/registry/
│   ├── integration/
│   └── unit/
└── tools/
~~~

Cache directories such as `__pycache__`, `.pytest_cache`, `.mypy_cache`와 `.ruff_cache`는 architecture 구성 요소가 아니다.

## 2. Current Python Package

~~~text
src/apex_forensic/
├── __init__.py
├── __main__.py
├── _time.py
├── constants.py
├── domain/
│   ├── enums/__init__.py
│   ├── errors/__init__.py
│   ├── models/
│   │   ├── ai.py
│   │   ├── artifact.py
│   │   ├── browser_media.py
│   │   ├── case.py
│   │   ├── context.py
│   │   ├── custody.py
│   │   ├── evidence.py
│   │   ├── filesystem.py
│   │   ├── job.py
│   │   ├── registry_carving.py
│   │   ├── report.py
│   │   ├── search.py
│   │   ├── secret.py
│   │   └── timeline.py
│   └── services/canonical.py
├── application/
│   ├── dto/responses.py
│   └── services/
│       ├── ai_assistance.py
│       ├── artifact_analysis.py
│       ├── case_manager.py
│       ├── context.py
│       ├── custody_ledger.py
│       ├── evidence_image.py
│       ├── evidence_manager.py
│       ├── file_system_index.py
│       ├── machine_extraction.py
│       ├── report.py
│       ├── search.py
│       └── timeline.py
├── ports/
├── adapters/
├── cli/
├── config/
├── jobs/
└── runtime/
~~~

`application/services/context.py`에는 Context Service, ViewProjectionService, SafeRawRangeReader와 EngineInterfaceService가 함께 있다. 이것은 현재 layout이며 향후 file split이 필요하다는 뜻은 아니다.

## 3. Adapter Tree

~~~text
src/apex_forensic/adapters/
├── ai/
│   └── openai_compatible.py
├── artifacts/
│   ├── browser.py
│   ├── media.py
│   ├── communication/
│   │   └── core.py
│   └── windows/
│       ├── common.py
│       ├── eventlog.py
│       ├── prefetch.py
│       ├── registry.py
│       └── registry_carving.py
├── decryption/
│   ├── dpapi.py
│   ├── kakaotalk.py
│   └── nss.py
├── evidence/
│   ├── ewf.py
│   ├── partitions.py
│   ├── raw.py
│   └── virtual_disk.py
├── filesystem/
│   ├── logical.py
│   └── pytsk.py
├── hashing/
│   └── hashlib_provider.py
├── machine_extraction/
│   ├── ocr.py
│   └── stt.py
├── persistence/
│   └── sqlite/
│       └── repository.py
├── report/
│   └── runtime.py
├── schema/
│   └── json_schema.py
└── system.py
~~~

중요한 현재 경계:

- `adapters/evidence`: RAW/DD/IMG, optional E01/VHD/VHDX와 partitions
- `adapters/filesystem/pytsk.py`: image filesystem provider
- `adapters/artifacts/windows`: Registry replay/carving, Event XML/EVTX/message rendering, Prefetch/MAM
- `adapters/artifacts/communication`: limited Email/Discord/Telegram/Kakao discovery
- `adapters/decryption`: DPAPI/NSS/KakaoTalk secret recovery
- `adapters/machine_extraction`: optional OCR/STT runtime
- `adapters/report/runtime.py`: built-in HTML와 optional ReportLab PDF
- `adapters/ai/openai_compatible.py`: external-config optional AI provider; MCP server가 아님

## 4. Ports

`src/apex_forensic/ports`에는 다음 실제 provider-neutral 경계가 있다.

~~~text
ai_assistance.py
artifact_analyzer.py
artifact_repository.py
browser_analyzer.py
case_repository.py
clock.py
custody_repository.py
dpapi_provider.py
evidence_reader.py
evidence_repository.py
filesystem_provider.py
file_system_repository.py
hash_provider.py
id_generator.py
kakaotalk_provider.py
machine_extraction.py
media_analyzer.py
nss_provider.py
ocr_provider.py
raw_reader.py
registry_carver.py
report_renderer.py
search_index.py
secret_provider.py
stt_provider.py
timeline_repository.py
~~~

Ports는 optional dependency나 transport SDK를 domain/application에 직접 유입하지 않는 역할을 한다.

## 5. CLI, Runtime와 Configuration

~~~text
src/apex_forensic/
├── cli/
│   ├── __init__.py                # doctor/benchmark dependency-light dispatch
│   ├── parser.py                  # current CLI surface
│   └── commands.py                # application/public-interface adapter
├── config/
│   └── services.py                # concrete ServiceBundle wiring
├── jobs/
│   ├── cancellation.py
│   └── progress.py
└── runtime/
    ├── benchmark.py
    └── capabilities.py
~~~

`config/services.py`가 logical/pytsk providers와 Windows, media, browser, communications analyzers를 등록한다. Optional OCR/STT/decryption/AI/report renderer는 operation/CLI에서 명시적으로 선택되는 경계도 있으므로 `ServiceBundle` 생성만으로 모든 optional capability가 available하다고 판단하지 않는다.

## 6. Schema Tree

`schemas/v1`에는 66개의 `*.schema.json` 파일이 있다. 주요 current cluster:

- Core: common/api/case/evidence/file/job/artifact/search/timeline/custody
- Browser/media/machine extraction
- Context/view/raw/public interface
- Secret/decryption/DPAPI/NSS/KakaoTalk
- AI assistance/provider
- Granular report/review/approval/render/export

`ui-context.schema.json`, `analysis-context.schema.json`, `ai-enrichment.schema.json`, `keyword-recommendation.schema.json`, `machine-extraction.schema.json`, `report.schema.json`은 초기 aggregate/consumer compatibility contracts다. Current Phase 6/8 runtime은 각각 `gui-session-context.schema.json`과 granular report schemas를 사용한다. 전체 inventory는 `docs/JSON_SCHEMAS.md`가 관리한다.

## 7. Tests

~~~text
tests/
├── conftest.py
├── fixtures/
│   └── registry/
│       ├── REGIPY_FIXTURES.md
│       └── transactions_*.xz
├── integration/
│   ├── test_cli_smoke.py
│   ├── test_filesystem_indexing_workflow.py
│   ├── test_phase6_cli_workflow.py
│   ├── test_phase7_cli_workflow.py
│   ├── test_phase8_cli_workflow.py
│   ├── test_sqlite_workflow.py
│   └── test_windows_artifact_workflow.py
└── unit/
    ├── test_evidence_readers.py
    ├── test_image_filesystem_provider.py
    ├── test_windows_artifacts.py
    ├── test_registry_deleted_cell_carving.py
    ├── test_phase4_search_timeline.py
    ├── test_phase5_media_browser.py
    ├── test_communication_artifacts.py
    ├── test_phase6_context_views.py
    ├── test_phase7_ai_assistance.py
    ├── test_phase8_report_contract.py
    ├── test_advanced_runtime_*.py
    ├── test_kakaotalk_runtime.py
    ├── test_doctor_capabilities.py
    ├── test_benchmark_harness.py
    ├── test_release_hardening_recovery.py
    └── test_engine_release_gate.py
~~~

Glob 표기는 여러 실제 `test_advanced_runtime_*` files의 요약이며 새 file 이름을 주장하는 것이 아니다.

## 8. Verification Tools

~~~text
tools/
├── validate_design_basic.py
├── validate_design.mjs
├── validate_design.sh
├── verify_engine_release.py
├── verify_windows_host_runtime.py
├── verify_windows_event_message_renderer.py
├── generate_windows_runtime_fixtures.py
├── run_windows_runtime_verification.ps1
├── verify_report_renderers.py
├── verify_dpapi_runtime.py
├── verify_nss_runtime.py
├── verify_ocr_runtime.py
├── verify_stt_runtime.py
├── verify_ai_provider.py
├── verify_kakaotalk_runtime.py
├── verification_common.py
└── security_findings.json
~~~

`verify_windows_host_runtime.py`는 semantic orchestrator이고 성공 output이 repository에 자동 저장되지는 않는다. `security_findings.json`은 current Medium/High Bandit disposition manifest다.

## 9. 의존성 방향

허용 방향은 CLI/adapter → application → domain/ports다. Domain은 SQLite, pytsk3, pyewf, pywin32, OCR/STT, ReportLab, network provider 또는 transport에 의존하지 않는다.

별도 product components가 추가될 때:

- Frontend/GUI: public engine interface consumer
- Backend: identity/session/RBAC/billing
- MCP: engine descriptor를 transport tool로 등록
- LLM/Prompt/Agent: AI product layer

현재 tree에 `mcp/` 또는 `prompts/` directory가 없는 것은 의도된 Core boundary다.

## 10. Historical Note

초기 설계 문서의 `src/apex/core`, `src/apex/adapters`, 별도 frontend/backend/mcp monorepo tree는 historical proposal이다. 현재 repository structure로 제시하지 않는다. 향후 실제 component가 생성되기 전에는 tree에 선반영하지 않는다.
