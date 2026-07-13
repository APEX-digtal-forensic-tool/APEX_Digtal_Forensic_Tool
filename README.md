# APEX Forensic Core Engine

APEX는 한국어 디지털 포렌식 환경을 우선 지원하고, 대용량 Evidence를 읽기 전용으로 분석해
버전이 지정된 JSON 결과를 제공하는 Python 기반 Forensic Core Engine이다. X-Ways의 빠른
분석 철학을 참고하여 대용량 Evidence 처리 최적화를 목표로 하며, 검증되지 않은 제품 간 성능
우위를 주장하지 않는다.

현재 저장소는 **설계 기준선(Design Baseline)** 단계다. 아래 문서와 JSON Schema는 설계가
완료된 항목이며 실제 Engine, MCP, AI 및 Report 실행 코드는 아직 구현되지 않았다.

| 산출물 | 문서 |
| --- | --- |
| 전체 아키텍처와 품질 속성 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| 제안 디렉터리 구조 | [docs/DIRECTORY_STRUCTURE.md](docs/DIRECTORY_STRUCTURE.md) |
| 모듈 역할과 의존성 | [docs/MODULE_RESPONSIBILITIES.md](docs/MODULE_RESPONSIBILITIES.md) |
| 데이터베이스 스키마 | [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) |
| API 인터페이스 | [docs/API_INTERFACE.md](docs/API_INTERFACE.md) |
| JSON Schema 규칙 | [docs/JSON_SCHEMAS.md](docs/JSON_SCHEMAS.md) |
| 단계별 구현 순서 | [docs/IMPLEMENTATION_ROADMAP.md](docs/IMPLEMENTATION_ROADMAP.md) |
| 요구사항 추적표 | [docs/REQUIREMENTS_TRACEABILITY.md](docs/REQUIREMENTS_TRACEABILITY.md) |

기계 판독 계약은 [`schemas/v1`](schemas/v1), 설계 검증 도구는 [`tools`](tools)에 둔다.

## 제품과 Engine 경계

사용자에게 배포되는 APEX Desktop Distribution에는 GUI, Backend, Forensic Engine과 Built-in
MCP Adapter가 함께 포함될 수 있다. 그러나 개발 구조와 Runtime 의존성은 분리한다.

```text
APEX Desktop Distribution
├── Frontend GUI
├── Backend / Session Context
├── Forensic Core Engine
└── Built-in MCP Adapter -> AI/LLM Provider
```

Forensic Core Engine이 담당하는 범위:

- Case/Evidence, File System, Artifact, Timeline, Search/Index/Cache
- Analysis Result Database, Job, 무결성, Audit와 Citation
- GUI와 MCP Adapter가 공통으로 사용하는 Application Interface와 JSON Schema
- GUI/Analysis Context Snapshot, Annotation/Tag, Report 상태와 승인 규칙
- Provider-neutral `AIEnrichmentPort`와 `ReportDraftPort`

Engine이 담당하지 않는 범위:

- MCP Server/Tool, MCP SDK와 AI Workflow
- LLM Provider SDK/API, Prompt, Agent Loop, API Key/Credential
- AI Token 과금과 Provider별 사용량 집계
- Evidence 원본 수정 또는 AI 결과를 Observed Fact로 확정하는 동작

Built-in MCP Adapter는 Engine의 공개 Port/API만 사용한다. 배포판에 기본 포함된다는 제품
요건이 Engine 내부에 MCP 또는 LLM 의존성을 넣는 근거가 되지 않는다.

## 결과 재사용 Workflow

AI는 Evidence를 무조건 처음부터 다시 분석하지 않는다.

```text
GUI 분석 -> Engine Job -> Analysis Result DB
         -> GUI Context -> Analysis Context Snapshot
         -> Built-in MCP Adapter -> AI 해석/제안/보고서 초안
```

`UI Context`는 현재 화면, 선택 파일/Artifact/Timeline/Search Result, 필터, 시간 범위와 Tag를
담는 세션 단위 임시 상태다. Audit, AI 요청 또는 보고서 재현이 필요할 때만 불변 Snapshot을
저장한다. `Analysis Context`는 기존 Fact와 선택 결과를 Citation과 함께 고정한 전달 Bundle다.

AI 결과는 `Observed Fact`, `Analyst Annotation`, `AI Inference`, `AI Recommendation`으로
구분한다. AI Inference와 Recommendation은 원본 Artifact를 수정하지 않으며 가능한 모든
문장에 Evidence/File/Artifact/Timeline/Search Result Citation을 포함한다.

## 보고서 Workflow

```text
AI Draft -> Human Review -> Approval -> PDF/HTML Export
```

AI가 만든 한국어 초안은 `REVIEW_REQUIRED` 상태를 거쳐야 한다. 분석자가 승인한 특정 Report
Version만 Export할 수 있고, 승인 뒤 내용이 변경되면 다시 검토해야 한다. 보고서는 Evidence
Hash, 주요 발견, File System, Artifact, Media, Browser Communications, Timeline, AI 분석,
Citation과 한계를 포함할 수 있다.

## 한국어와 분석 범위

- 기본 Locale은 `ko-KR`, 기본 Timezone은 `Asia/Seoul`이다.
- UI/Artifact/오류 표시는 Resource Key로 관리하고 Engine 오류 코드는 언어 중립적이다.
- 원본 Unicode 파일명과 경로를 보존하고, 검색용 사본에 정규화/Case Folding을 적용한다.
- 한국어 Keyword Search와 한국어 Report Template을 별도 Fixture로 검증한다.
- Browser Communications MVP는 방문·검색·다운로드 History, URL/File, Profile, 시간 조회다.
- Email, Discord, Telegram, KakaoTalk 등은 후순위 Plugin 범위다.
- Media MVP는 Image/Video 분류, EXIF/GPS, Thumbnail, Codec/Duration, 시간, 삭제 표시다.

## 성능 방향

Lazy Loading, Cursor Pagination, Evidence Streaming, Process Pool, Async I/O, 병렬 Artifact
분석, Case별 단일 DB Writer, FTS5 또는 동등 Index, Content Cache, Checkpoint/Resume, 입력
Fingerprint 기반 중복 분석 방지, 취소와 Progress Reporting을 설계 기준으로 사용한다. 성능
수치는 동일 Hardware/Evidence/분석 범위의 Benchmark 이후에만 문서화한다.

## 완료 상태

- [x] Core Architecture, Database, API 및 JSON Schema 설계
- [x] GUI/Analysis Context와 Citation 설계
- [x] Provider-neutral AI 경계 설계
- [x] Report Module과 Human Review/Approval 설계
- [x] 한국어, Browser Communications, Media 범위 설계
- [ ] Project Skeleton과 Case/Evidence Manager 구현
- [ ] File System 및 Artifact Analyzer 구현
- [ ] GUI/Context/Report Application 구현
- [ ] Built-in MCP Adapter 구현(별도 담당)
- [ ] LLM Provider/Prompt/AI Workflow 구현(별도 담당)
- [ ] 성능 Benchmark와 Desktop Packaging

문서/Schema 검증은 `bash tools/validate_design.sh`로 실행한다. Git commit과 push는 이 설계
작업 범위에 포함하지 않는다.
