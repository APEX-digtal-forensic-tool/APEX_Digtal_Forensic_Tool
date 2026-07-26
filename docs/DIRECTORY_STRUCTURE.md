# 제안 디렉터리 구조

이 문서는 설계 구조와 현재 구현 구조를 함께 기록한다. Phase 1~5 실행 코드는
`src/apex_forensic` 패키지 아래에 있으며, 초기 `src/apex` 다이어그램은 책임 분리를 설명하는
참고 구조다.

```text
APEX/
├── README.md
├── pyproject.toml
├── src/
│   └── apex/
│       ├── domain/
│       │   ├── cases/
│       │   ├── evidence/
│       │   ├── filesystem/
│       │   ├── artifacts/
│       │   ├── timeline/
│       │   ├── search/
│       │   ├── contexts/
│       │   ├── annotations/
│       │   ├── reports/
│       │   └── jobs/
│       ├── application/
│       │   ├── commands/
│       │   ├── queries/
│       │   └── services/
│       ├── ports/
│       │   ├── evidence_reader.py
│       │   ├── repositories.py
│       │   ├── index.py
│       │   ├── cache.py
│       │   ├── clock.py
│       │   └── event_sink.py
│       ├── adapters/
│       │   ├── evidence/
│       │   │   ├── directory/
│       │   │   ├── raw/
│       │   │   ├── e01/
│       │   │   └── vhd/
│       │   ├── persistence/
│       │   │   └── sqlite/
│       │   ├── index/
│       │   │   └── sqlite_fts/
│       │   └── cache/
│       │       └── filesystem/
│       ├── analyzers/
│       │   ├── base/
│       │   ├── filesystem/
│       │   └── artifacts/
│       │       ├── registry/
│       │       ├── eventlog/
│       │       ├── prefetch/
│       │       ├── communications/
│       │       │   └── browser/
│       │       └── media/
│       ├── timeline/
│       ├── search/
│       ├── jobs/
│       ├── contexts/
│       │   ├── ui_context_service.py
│       │   ├── analysis_context_builder.py
│       │   └── snapshot_service.py
│       ├── reports/
│       │   ├── template_manager.py
│       │   ├── evidence_selector.py
│       │   ├── finding_selector.py
│       │   ├── timeline_selector.py
│       │   ├── ai_draft_port.py
│       │   ├── review_manager.py
│       │   ├── approval_manager.py
│       │   └── exporter.py
│       ├── localization/
│       │   ├── resource_keys.py
│       │   └── normalization.py
│       ├── api/
│       │   ├── http/
│       │   ├── dto/
│       │   └── serialization/
│       ├── ai_layer/
│       │   ├── ports/
│       │   ├── dto/
│       │   └── README.md
│       ├── observability/
│       └── bootstrap/
├── schemas/
│   └── v1/
│       ├── common.schema.json
│       ├── api-response.schema.json
│       ├── case.schema.json
│       ├── ui-context.schema.json
│       ├── analysis-context.schema.json
│       ├── citation.schema.json
│       ├── report.schema.json
│       ├── evidence.schema.json
│       ├── file.schema.json
│       ├── artifact.schema.json
│       ├── timeline-event.schema.json
│       ├── search.schema.json
│       ├── job.schema.json
│       └── ai-enrichment.schema.json
├── migrations/
│   └── sqlite/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── fixtures/
│   └── performance/
├── docs/
└── tools/
    ├── validate_design.mjs
    └── validate_design.sh
```

## 구조 원칙

| 원칙 | 적용 방식 |
| --- | --- |
| Domain 독립성 | `domain`은 DB, HTTP, 파일 형식 Library를 Import하지 않음 |
| Use Case 분리 | 상태 변경은 `commands`, 조회는 `queries`에 배치 |
| Port 우선 | Evidence/DB/Index/Cache 연동은 `ports`의 계약을 먼저 정의 |
| Adapter 격리 | E01, VHD, SQLite 등 외부 기술을 `adapters`에 제한 |
| Analyzer 독립성 | Artifact 종류별 패키지와 Manifest, Fixture, Test 보유 |
| DTO 경계 | API DTO는 Domain Entity를 그대로 노출하지 않음 |
| AI 격리 | Provider-neutral 계약만 `ai_layer`에 두고 구현체는 Core 외부에 둠 |
| Context 분리 | Live UI 상태는 Session Store, 재현용 Snapshot만 Case DB에 저장 |
| Report Gate | Draft/Review/Approval/Export를 별도 Domain 상태로 강제 |
| Localization | 오류/표시명은 Resource Key, 원본 문자열과 검색 정규화 사본 분리 |
| Schema 동기화 | DTO Contract Test로 `schemas/v1`과 실제 직렬화 결과를 검증 |

## 금지되는 의존성

```text
domain       -> api/adapters/analyzers/ai_layer
analyzers    -> api/http
application  -> concrete sqlite/e01/vhd adapter
core modules -> MCP SDK / LLM provider SDK / prompt package
ai_layer     -> artifact 원본 행 수정
reports      -> concrete LLM/MCP provider adapter
contexts     -> GUI framework state object
```

MCP Adapter는 이 Core 트리 안에 만들지 않는다. APEX Desktop Distribution에는 별도 Component로
기본 포함할 수 있으며 `api`의 공개 계약만 소비한다. Frontend의 한국어 Resource 파일도 GUI
저장소가 소유하고 Core에는 안정적인 Resource Key와 기본 Locale/Timezone 정책만 둔다.

## Python-Native Adapter 제안 구조

~~~text
src/
|-- domain/
|-- application/
|-- ports/
|   |-- evidence_reader.py
|   |-- filesystem_provider.py
|   |-- hash_provider.py
|   |-- search_index.py
|   |-- binary_scanner.py
|   `-- multimedia_processor.py
|
|-- adapters/
|   |-- native/
|   |   |-- tsk/
|   |   |-- ewf/
|   |   |-- vhdi/
|   |   |-- yara/
|   |   `-- ffmpeg/
|   `-- database/
|
|-- workers/
|   |-- process_pool.py
|   |-- result_queue.py
|   `-- db_writer.py
|
`-- api/
~~~

Native Adapter는 선택한 Library에 종속될 수 있지만 Domain과 Application Layer는 Native 구현 세부사항을 알지 못한다.

## Progressive 분석 확장 제안 구조

아래 경로는 구현 단계의 책임 배치를 위한 설계이며 현재 생성된 실행 코드를 뜻하지 않는다.

```text
src/apex/
├── domain/
│   ├── analysis_profiles/
│   ├── custody/
│   ├── keywords/
│   ├── machine_extraction/
│   └── timezones/
├── application/services/
│   ├── progressive_indexing_coordinator.py
│   ├── analysis_profile_manager.py
│   ├── progress_estimator.py
│   ├── timezone_resolver.py
│   ├── timestamp_normalizer.py
│   ├── keyword_set_manager.py
│   ├── search_reproduction_manager.py
│   ├── custody_verification_service.py
│   └── raw_evidence_locator.py
├── ports/
│   ├── keyword_recommendation.py
│   ├── machine_extraction.py
│   └── benchmark_measurement.py
├── jobs/
│   ├── priority_scheduler.py
│   └── progressive_indexing.py
└── adapters/
    └── persistence/sqlite/
        ├── custody_repository.py
        ├── keyword_repository.py
        └── machine_extraction_repository.py

schemas/v1/
├── analysis-profile.schema.json
├── keyword-recommendation.schema.json
├── chain-of-custody.schema.json
└── machine-extraction.schema.json

tools/
├── validate_design.mjs
├── validate_design_basic.py
└── validate_design.sh
```

`keyword_recommendation.py`와 `machine_extraction.py`는 Provider-neutral Port만 정의한다.
MCP Server, LLM API, Prompt, Agent Loop, OCR/STT Provider 실행 코드는 Core 트리에 만들지
않는다. Live Progress와 Live UI Context는 Session Store 우선이며 재현·Audit·Report에 필요한
Checkpoint와 Snapshot만 Case DB에 저장한다.

## Phase 2 Source Layout

Phase 2 adds these implementation areas under the existing package layout:

```text
src/apex_forensic/adapters/filesystem/
  logical.py                    # Logical directory/file provider
src/apex_forensic/application/services/file_system_index.py
  # Progressive index coordinator and file tree query facade
src/apex_forensic/domain/models/filesystem.py
  # FileSystemNode, IndexCoverage, cursor page DTOs
src/apex_forensic/ports/filesystem_provider.py
src/apex_forensic/ports/file_system_repository.py
  # Provider and persistence ports
```

The existing CLI, service factory, schema validator, SQLite repository, domain enums, and job/cancellation helpers are extended rather than duplicated.

## Phase 3 Source Layout

Phase 3 keeps the `src/apex_forensic` package shape and adds artifact-specific code without adding
GUI, MCP, OCR/STT, or LLM execution directories.

```text
src/apex_forensic/domain/models/artifact.py
src/apex_forensic/ports/artifact_analyzer.py
src/apex_forensic/ports/artifact_repository.py
src/apex_forensic/application/services/artifact_analysis.py
src/apex_forensic/adapters/artifacts/windows/registry.py
src/apex_forensic/adapters/artifacts/windows/eventlog.py
src/apex_forensic/adapters/artifacts/windows/prefetch.py
```

The existing `SQLiteRepository`, CLI parser/commands, service factory, JSON Schema validator, and
domain enum module are extended in place. Tests use synthetic Registry export, Event XML, and Prefetch
fixtures; optional binary hive/EVTX dependency tests may be skipped when the parser dependency is not
installed.

## Phase 4 Added Files

```text
src/apex_forensic/domain/models/search.py
src/apex_forensic/domain/models/timeline.py
src/apex_forensic/ports/search_index.py
src/apex_forensic/ports/timeline_repository.py
src/apex_forensic/application/services/search.py
src/apex_forensic/application/services/timeline.py
tests/unit/test_phase4_search_timeline.py
```

Existing files extended in place include the SQLite repository, service factory, CLI parser/commands,
domain enum exports, model exports, `search.schema.json`, `timeline-event.schema.json`,
`keyword-recommendation.schema.json`, and `job.schema.json`.

## Phase 5 Added Files

```text
src/apex_forensic/domain/models/browser_media.py
src/apex_forensic/ports/browser_analyzer.py
src/apex_forensic/ports/media_analyzer.py
src/apex_forensic/ports/machine_extraction.py
src/apex_forensic/application/services/machine_extraction.py
src/apex_forensic/adapters/artifacts/browser.py
src/apex_forensic/adapters/artifacts/media.py
schemas/v1/browser-profile.schema.json
schemas/v1/browser-artifact.schema.json
schemas/v1/media-artifact.schema.json
schemas/v1/machine-extracted-candidate.schema.json
schemas/v1/provider-capability.schema.json
schemas/v1/thumbnail.schema.json
tests/unit/test_phase5_media_browser.py
```

Phase 5 keeps Browser and Media analyzers under the existing artifact adapter boundary and adds only
provider-neutral ports for Browser, Media, and Machine Extraction. It does not add GUI, MCP, LLM,
OCR/STT engine, browser credential, or report-renderer execution directories.

## Phase 6 구현 구조

Phase 6 runtime code lives in `src/apex_forensic/application/services/context.py`, with DTOs in `src/apex_forensic/domain/models/context.py` and the raw reader boundary in `src/apex_forensic/ports/raw_reader.py`. SQLite persistence is implemented in `src/apex_forensic/adapters/persistence/sqlite/repository.py`, and CLI wiring is in `src/apex_forensic/cli/parser.py` and `src/apex_forensic/cli/commands.py`.

Phase 6 schemas are added under `schemas/v1` for GUI session context, analysis snapshots, scope context, revision state, view projection, raw view, raw read request/response, engine interface, and engine tool descriptors. Focused tests live in `tests/unit/test_phase6_context_views.py` and `tests/integration/test_phase6_cli_workflow.py`.

## Phase 7 구현 구조

Phase 7 keeps the same package boundaries and adds only engine-side AI assistance contracts:

```text
src/apex_forensic/domain/models/ai.py
src/apex_forensic/ports/ai_assistance.py
src/apex_forensic/application/services/ai_assistance.py
tests/unit/test_phase7_ai_assistance.py
tests/integration/test_phase7_cli_workflow.py
```

Existing files extended in place include the SQLite repository, service factory, domain enum/model/error exports, public engine interface, CLI parser/commands, and JSON schemas. No `mcp`, `prompt`, LLM provider, API-key, chain-of-thought, or runtime network adapter directory is added.

Phase 7 schemas are added under `schemas/v1` for assistance requests, keyword recommendation batches and items, scope summaries, verification events, keyword promotions, and provider capability snapshots.
