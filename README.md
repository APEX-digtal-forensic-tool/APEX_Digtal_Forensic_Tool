# APEX Forensic Core Engine

APEX는 한국어 디지털 포렌식 환경을 우선 지원하고, 대용량 Evidence를 읽기 전용으로 분석하여 버전이 지정된 JSON 결과를 제공하는 Python 기반 Forensic Core Engine입니다.

X-Ways Forensics의 빠른 분석 철학과 Autopsy의 Case·Artifact 중심 분석 Workflow를 참고하여, 사용자 친화성과 대용량 Evidence 처리 효율성을 함께 확보하는 것을 목표로 합니다.

현재 저장소는 **설계 기준선(Design Baseline)** 단계입니다. 문서와 JSON Schema 설계는 완료되었지만 실제 Forensic Engine, GUI, MCP, AI 및 Report 실행 코드는 아직 구현되지 않았습니다.

---

## 핵심 목표

APEX는 다음 세 가지를 핵심 차별점으로 합니다.

1. **한국어 기반 디지털 포렌식 환경**
2. **제품에 기본 포함되는 MCP 기반 AI 분석 기능**
3. **대용량 Evidence 처리를 위한 분석 엔진 최적화**

단, 검증되지 않은 제품 간 성능 우위는 주장하지 않습니다. 성능 수치는 동일한 Hardware, Evidence 및 분석 범위를 사용한 Benchmark 이후에만 문서화합니다.

---

## 설계 산출물

| 산출물 | 문서 |
|---|---|
| 전체 아키텍처 및 품질 속성 | [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) |
| 제안 디렉터리 구조 | [`docs/DIRECTORY_STRUCTURE.md`](./docs/DIRECTORY_STRUCTURE.md) |
| 모듈 역할 및 의존성 | [`docs/MODULE_RESPONSIBILITIES.md`](./docs/MODULE_RESPONSIBILITIES.md) |
| 데이터베이스 스키마 | [`docs/DATABASE_SCHEMA.md`](./docs/DATABASE_SCHEMA.md) |
| API 인터페이스 | [`docs/API_INTERFACE.md`](./docs/API_INTERFACE.md) |
| JSON Schema 규칙 | [`docs/JSON_SCHEMAS.md`](./docs/JSON_SCHEMAS.md) |
| 단계별 구현 로드맵 | [`docs/IMPLEMENTATION_ROADMAP.md`](./docs/IMPLEMENTATION_ROADMAP.md) |
| 요구사항 추적표 | [`docs/REQUIREMENTS_TRACEABILITY.md`](./docs/REQUIREMENTS_TRACEABILITY.md) |

기계 판독용 데이터 계약은 [`schemas/v1/`](./schemas/v1)에 있으며, 설계 검증 도구는 [`tools/`](./tools)에 있습니다.

---

## 제품과 Engine 경계

사용자에게 배포되는 APEX Desktop Distribution에는 GUI, Backend, Forensic Engine 및 Built-in MCP Adapter가 함께 포함될 수 있습니다.

그러나 개발 구조와 Runtime 의존성은 명확히 분리합니다.

```text
APEX Desktop Distribution
├── Frontend GUI
├── Backend / Session Context
├── Forensic Core Engine
└── Built-in MCP Adapter
    └── AI / LLM Provider
```

사용자 관점에서는 MCP 기능이 APEX에 기본 포함되지만, Forensic Engine 내부에는 MCP SDK나 특정 AI Provider 의존성을 포함하지 않습니다.

---

## Forensic Core Engine 담당 범위

Forensic Core Engine은 다음 기능을 담당합니다.

- Case 및 Evidence 관리
- File System 분석
- Artifact 분석
- Timeline 생성
- Search, Index 및 Cache
- Analysis Result Database
- 분석 Job 및 Progress 관리
- Evidence 무결성 검증
- Audit 및 Citation 데이터 관리
- GUI와 MCP Adapter가 공통으로 사용하는 Application Interface 제공
- 버전이 지정된 JSON Schema 기반 결과 제공
- GUI 및 Analysis Context Snapshot 관리
- Analyst Annotation 및 Tag 관리
- Report 상태와 승인 규칙 관리
- Provider-neutral `AIEnrichmentPort` 제공
- Provider-neutral `ReportDraftPort` 제공

---

## Forensic Core Engine 비담당 범위

다음 기능은 Engine 외부 계층에서 담당합니다.

- MCP Server 구현
- MCP Tool 정의
- MCP SDK 의존성
- LLM Provider SDK 및 API 연동
- Prompt Engineering
- Agent Loop 및 AI Workflow
- API Key 및 Credential 관리
- AI Token 과금
- Provider별 사용량 집계
- AI 분석 결과를 Observed Fact로 확정하는 동작
- Evidence 원본 수정

Built-in MCP Adapter는 Engine의 공개 Port 또는 API만 사용합니다.

제품에 MCP가 기본 포함된다는 요구사항은 Engine 내부에 MCP 또는 LLM 의존성을 추가하는 근거가 되지 않습니다.

---

## 전체 분석 구조

```text
사용자
  │
  ▼
Frontend GUI
  │
  │ 분석 실행 및 현재 선택 상태 전달
  ▼
Application Interface
  │
  ▼
Forensic Core Engine
  │
  ├── Analysis Result Database
  ├── Timeline / Search / Artifact Result
  ├── Session Context
  └── Context Snapshot
          │
          ▼
    Built-in MCP Adapter
          │
          ▼
       AI Agent
```

GUI와 MCP Adapter는 서로 다른 분석 로직을 구현하지 않고, 동일한 Engine Interface와 JSON Schema를 사용합니다.

---

## 기존 분석 결과 재사용 Workflow

APEX의 AI는 Evidence를 무조건 처음부터 다시 분석하지 않습니다.

사용자가 GUI에서 이미 수행한 분석 결과를 저장하고, MCP Adapter가 해당 결과와 Context를 조회하여 AI Agent에 전달합니다.

```text
GUI 분석 실행
    ↓
Forensic Engine Job
    ↓
Analysis Result Database 저장
    ↓
GUI Context 구성
    ↓
Analysis Context Snapshot 생성
    ↓
Built-in MCP Adapter 조회
    ↓
AI 해석 / 추가 분석 제안 / 보고서 초안
```

이를 통해 다음 효과를 기대할 수 있습니다.

- 동일 Evidence 중복 분석 방지
- GUI 분석 결과와 AI 답변의 일관성 유지
- AI 입력 근거 추적
- 보고서 생성 과정 재현
- 분석자의 선택 및 판단 보존
- AI 추론과 실제 Evidence의 명확한 구분

---

## GUI Context

GUI Context는 현재 사용자의 분석 상태를 표현하는 Session 단위 임시 데이터입니다.

포함 가능한 정보:

- 현재 Case
- 현재 Evidence
- 현재 화면
- 선택된 파일
- 선택된 Artifact
- 선택된 Timeline Event
- 선택된 Search Result
- 활성화된 Filter
- Timeline 시간 범위
- Tag 및 주요 증거
- 현재 Locale
- 현재 Timezone

예시:

```json
{
  "case_id": "case-001",
  "evidence_id": "evidence-001",
  "current_view": "registry",
  "selected_file_ids": [],
  "selected_artifact_ids": [
    "artifact-001"
  ],
  "selected_timeline_event_ids": [],
  "active_filters": {
    "risk_level": [
      "high"
    ]
  },
  "timeline_range": {
    "from": "2026-07-01T00:00:00Z",
    "to": "2026-07-13T23:59:59Z"
  },
  "locale": "ko-KR",
  "timezone": "Asia/Seoul"
}
```

Live GUI Context는 기본적으로 Session Store에서 관리합니다.

Audit, AI 요청 또는 보고서 재현이 필요한 경우에만 불변 Context Snapshot으로 저장합니다.

---

## Analysis Context

Analysis Context는 MCP, AI 및 Report 계층에 전달하기 위해 기존 분석 결과를 고정한 구조화된 Bundle입니다.

포함 가능한 정보:

- Case Metadata
- Evidence Metadata 및 Hash
- 선택된 File
- 선택된 Artifact
- Timeline Event
- Search Result
- Analyst Annotation
- Tag
- 기존 AI Enrichment
- Citation
- Context 생성 시점
- Context Revision

Analysis Context는 원본 Evidence를 포함하지 않고, Engine이 검증한 구조화된 결과와 실제 결과를 조회할 수 있는 식별자를 제공합니다.

---

## AI 결과 분류

APEX는 AI가 생성한 내용을 포렌식 엔진의 실제 분석 결과와 분리합니다.

### Observed Fact

Forensic Engine이 Evidence에서 직접 추출한 사실입니다.

예:

- 파일 경로
- Hash
- Timestamp
- Registry Value
- Event ID
- Browser URL

### Analyst Annotation

분석자가 작성하거나 지정한 설명, 태그 및 판단입니다.

### AI Inference

AI가 Observed Fact와 Context를 기반으로 생성한 추론입니다.

### AI Recommendation

AI가 제안하는 추가 분석 절차 또는 대응 권고입니다.

AI Inference와 AI Recommendation은 원본 Artifact를 변경하지 않으며, 가능한 모든 문장에 근거가 되는 Citation을 포함해야 합니다.

Citation은 다음 식별자를 참조할 수 있습니다.

- `evidence_id`
- `file_id`
- `artifact_id`
- `timeline_event_id`
- `search_result_id`
- `source_path`
- `source_offset`
- `source_reference`

---

## AI 보고서 Workflow

AI가 생성한 보고서는 즉시 최종 결과로 확정하지 않습니다.

```text
AI Draft
    ↓
Human Review
    ↓
Approval
    ↓
PDF / HTML Export
```

보고서 상태는 다음과 같이 관리합니다.

- `draft`
- `generating`
- `review_required`
- `approved`
- `rejected`
- `exporting`
- `exported`
- `failed`

분석자가 승인한 특정 Report Version만 Export할 수 있습니다.

승인 후 보고서 내용이 변경되면 기존 승인은 무효화되고 다시 검토해야 합니다.

---

## 보고서 구성

보고서는 다음 Section을 포함할 수 있습니다.

1. 사건 개요
2. 분석 목적
3. 분석 대상
4. Evidence 정보
5. Hash 및 무결성 정보
6. 분석 환경
7. 주요 발견 사항
8. File System 분석 결과
9. Artifact 분석 결과
10. Images / Videos 분석 결과
11. Browser Communications 분석 결과
12. Timeline
13. AI 분석 요약
14. 결론
15. 대응 권고
16. 증거 출처 및 Citation
17. 분석 한계

지원 예정 Export 형식:

- PDF
- HTML

---

## 한국어 및 Localization

APEX는 한국어 환경을 기본값으로 사용합니다.

- 기본 Locale: `ko-KR`
- 기본 Timezone: `Asia/Seoul`
- 기본 Encoding: UTF-8

Localization 설계 원칙:

- UI 문자열은 Resource Key로 관리
- Engine 오류 코드는 언어 중립적으로 반환
- GUI가 오류 코드에 대응하는 한국어 메시지 표시
- Artifact 표시명과 설명의 다국어 지원
- 한글 파일명과 경로를 손실 없이 보존
- 원본 Unicode 문자열과 검색용 정규화 문자열 분리
- 검색용 문자열에 Unicode Normalization 및 Case Folding 적용
- 한국어 Keyword Search 지원
- 한국어 Report Template 제공
- AI 출력 언어를 Case Locale에 맞춤
- 원본 Timestamp와 표시용 Timezone 변환 결과 분리

---

## Evidence 분석 원칙

원본 Evidence는 항상 읽기 전용으로 처리합니다.

- Evidence 원본 수정 금지
- Evidence 등록 시 Hash 계산
- 분석 전후 무결성 검증
- 원본 경로와 분석 결과 분리
- 파생 데이터와 원본 데이터 구분
- 분석 작업 Audit 기록
- 동일 Evidence 입력 Fingerprint 기반 중복 분석 방지

---

## 주요 Engine 모듈

### Case Manager

- Case 생성 및 조회
- Locale 및 Timezone 관리
- Case 상태 관리
- Case별 Evidence 및 분석 결과 연결

### Evidence Manager

- Disk Image 및 Logical Evidence 등록
- Metadata 추출
- Hash 계산
- 무결성 검증
- Evidence 분석 상태 관리

지원 예정 형식:

- E01
- RAW
- DD
- IMG
- VHD
- VHDX
- Directory Evidence

### File System Analyzer

- Directory Tree 조회
- 파일 및 폴더 목록 조회
- File Metadata 추출
- 삭제 파일 탐색
- 파일 유형 분류
- Cursor Pagination
- Lazy Loading

### Artifact Analyzer

초기 지원 대상:

- Windows Registry
- Windows Event Log
- Windows Prefetch
- Browser History
- Download History
- Recent Activity
- Image Metadata
- Video Metadata

### Timeline Engine

- File MAC Time 통합
- Registry Timestamp 통합
- Event Log Timestamp 통합
- Browser Activity 통합
- Program Execution Time 통합
- 시간 범위 및 Event Type Filter
- Citation 가능한 Timeline Event 생성

### Search Engine

- 파일명 검색
- Keyword Search
- Regex Search
- Metadata Search
- Artifact Search
- FTS5 또는 동등한 Full Text Index
- Cursor 기반 결과 조회
- 검색 결과 Cache

### Context Module

- Live GUI Context 관리
- Context Revision 관리
- Analysis Context Bundle 생성
- 재현용 Context Snapshot 저장

### Report Module

- Report Template 관리
- Evidence 선택
- Finding 선택
- Timeline 선택
- Citation 관리
- AI Draft 요청 Port
- Human Review
- Approval
- Export 상태 관리

---

## Browser Communications MVP

초기 Communications 범위는 Browser Artifact 중심으로 제한합니다.

MVP 범위:

- 방문 History
- 검색 History
- 다운로드 History
- URL
- 다운로드 File
- Browser Profile
- 시간 범위 조회
- 사용자 Profile별 Filter

후순위 Plugin 범위:

- Email
- Discord
- Telegram
- KakaoTalk
- 기타 Messenger

README와 설계에서는 후순위 기능을 초기 구현 완료 항목으로 표시하지 않습니다.

---

## Images / Videos MVP

초기 Media 분석 범위:

- Image File 분류
- Video File 분류
- Image Metadata
- Video Metadata
- EXIF
- GPS
- Thumbnail
- Codec
- Duration
- 생성 및 수정 시간
- 삭제된 Media File 표시

AI는 기존 Metadata와 분석 결과를 요약하거나 사건 관련성을 설명할 수 있지만, 원본 Media를 변경하지 않습니다.

---

## 성능 최적화 방향

APEX는 X-Ways의 빠른 분석 철학을 참고하여 대용량 Evidence 처리 최적화를 목표로 합니다.

설계에 포함된 최적화 항목:

- Lazy Loading
- Cursor Pagination
- Evidence Streaming
- Process Pool
- Async I/O
- Artifact 병렬 분석
- Case별 단일 DB Writer
- FTS5 또는 동등한 Full Text Index
- Content Cache
- Checkpoint 및 Resume
- 입력 Fingerprint 기반 중복 분석 방지
- 취소 가능한 Long-running Job
- Progress Reporting
- 분석 결과 재사용
- 변경되지 않은 Evidence의 재분석 방지

성능 비교는 동일한 조건의 Benchmark 이후에만 수행합니다.

---

## 데이터 계약

APEX는 JSON Schema Draft 2020-12 기반 데이터 계약을 사용합니다.

현재 주요 Schema:

- Case
- Evidence
- File
- Artifact
- Timeline Event
- Search Result
- Job
- API Response
- AI Enrichment
- UI Context
- Analysis Context
- Citation
- Report

모든 Schema는 다음 원칙을 따릅니다.

- 명시적인 `required`
- 명시적인 `additionalProperties`
- 일관된 ID 형식
- ISO 8601 Timestamp
- 로컬 `$ref`
- Schema Version 명시
- Observed Fact와 AI 결과 분리
- 순환 참조 방지

---

## 현재 저장소 구조

```text
APEX/
├── README.md
│
├── docs/
│   ├── API_INTERFACE.md
│   ├── ARCHITECTURE.md
│   ├── DATABASE_SCHEMA.md
│   ├── DIRECTORY_STRUCTURE.md
│   ├── IMPLEMENTATION_ROADMAP.md
│   ├── JSON_SCHEMAS.md
│   ├── MODULE_RESPONSIBILITIES.md
│   └── REQUIREMENTS_TRACEABILITY.md
│
├── schemas/
│   └── v1/
│       ├── ai-enrichment.schema.json
│       ├── analysis-context.schema.json
│       ├── api-response.schema.json
│       ├── artifact.schema.json
│       ├── case.schema.json
│       ├── citation.schema.json
│       ├── common.schema.json
│       ├── evidence.schema.json
│       ├── file.schema.json
│       ├── job.schema.json
│       ├── report.schema.json
│       ├── search.schema.json
│       ├── timeline-event.schema.json
│       └── ui-context.schema.json
│
└── tools/
    ├── validate_design.mjs
    └── validate_design.sh
```

---

## 개발 진행 상태

### 설계 완료

- [x] Core Architecture 설계
- [x] Database Schema 설계
- [x] API Interface 설계
- [x] JSON Schema v1 설계 및 검증
- [x] Module Responsibility 정의
- [x] Requirements Traceability 작성
- [x] Implementation Roadmap 작성
- [x] GUI Context 설계
- [x] Analysis Context 설계
- [x] Citation 설계
- [x] Provider-neutral AI 경계 설계
- [x] Report Module 설계
- [x] Human Review 및 Approval 설계
- [x] 한국어 및 Localization 설계
- [x] Browser Communications MVP 범위 설계
- [x] Images / Videos MVP 범위 설계
- [x] MCP 및 Billing 경계 설계
- [x] 설계 검증 도구 작성

### 구현 예정

- [ ] Project Skeleton 구현
- [ ] Case Manager 구현
- [ ] Evidence Manager 구현
- [ ] Hash 계산 및 무결성 검증 구현
- [ ] File System Analyzer 구현
- [ ] Registry Analyzer 구현
- [ ] Event Log Analyzer 구현
- [ ] Prefetch Analyzer 구현
- [ ] Browser Communications Analyzer 구현
- [ ] Images / Videos Analyzer 구현
- [ ] Timeline Engine 구현
- [ ] Search 및 Index Engine 구현
- [ ] Cache 및 병렬 Job 구조 구현
- [ ] GUI Context 구현
- [ ] Analysis Context Snapshot 구현
- [ ] Report Application 구현
- [ ] PDF 및 HTML Export 구현
- [ ] 한국어 Keyword Search 구현
- [ ] Built-in MCP Adapter 구현 — 별도 담당
- [ ] LLM Provider 및 Prompt Workflow 구현 — 별도 담당
- [ ] Token Billing 구현 — Backend 담당
- [ ] 성능 Benchmark
- [ ] Desktop Packaging

---

## 구현 Roadmap

### Phase 0 — 설계 정합성 검증

- Schema 검증
- 문서 링크 검증
- Requirements Traceability 검증
- 테스트 기반 준비

### Phase 1 — Core Foundation

- Project Skeleton
- Case Manager
- Evidence Manager
- Hash 및 무결성 검증

### Phase 2 — File System

- File System Analyzer
- Lazy Loading
- Cursor Pagination
- 기본 Index

### Phase 3 — Windows Artifact

- Registry
- Event Log
- Prefetch

### Phase 4 — Timeline 및 Search

- Timeline
- Search
- Cache
- Parallel Job

### Phase 5 — Media 및 Browser Communications

- Images / Videos
- Browser Communications MVP

### Phase 6 — Context 및 MCP Interface

- GUI Context
- Analysis Context
- MCP Adapter용 공개 Interface

### Phase 7 — AI Enrichment

- Citation
- Fact / Inference 분리
- 한국어 분석 결과

### Phase 8 — Report

- AI Draft
- Human Review
- Approval
- PDF 및 HTML Export

### Phase 9 — 검증 및 배포

- 성능 Benchmark
- 안정성 테스트
- Desktop Packaging

MCP Server와 LLM Provider 구현은 별도 담당자의 Roadmap에서 관리합니다.

---

## 설계 검증

문서와 JSON Schema의 정합성은 다음 명령으로 검증합니다.

```bash
bash tools/validate_design.sh
```

검증 범위:

- JSON Syntax
- JSON Schema Draft 2020-12
- Ajv Strict Mode
- 로컬 `$ref`
- 순환 참조
- Markdown Link
- API와 Schema 대응 관계
- Requirements Traceability
- Database와 Module 소유권
- MCP 및 LLM 실행 코드 미포함 여부

---

## 참고 프로젝트

- [X-Ways 스타일 포렌식 엔진](https://github.com/tagalston101/x-way-forensics-tool)
- [Autopsy](https://github.com/sleuthkit/autopsy)
- [X-Ways Forensics MCP](https://github.com/joyooosama/x-ways-forensics-mcp)

| 참고 프로젝트 | 참고 영역 |
|---|---|
| X-Ways 스타일 포렌식 엔진 | 빠른 Evidence 탐색 및 대용량 분석 구조 |
| Autopsy | Case 기반 Workflow, Artifact 분석 구조 및 사용자 경험 |
| X-Ways Forensics MCP | GUI 결과와 포렌식 기능을 MCP Context로 연결하는 방식 |

APEX는 위 프로젝트의 구조와 Workflow를 참고하지만, 특정 제품을 그대로 복제하는 것을 목표로 하지 않습니다.

외부 소스 코드를 직접 사용하는 경우 각 프로젝트의 License와 저작권 조건을 확인해야 합니다.

---

## 개발 목적

APEX는 합법적인 디지털 포렌식 조사, 보안 연구 및 교육을 목적으로 개발합니다.

AI가 생성한 분석 결과와 보고서는 분석 보조 자료이며, 최종 판단은 분석자가 원본 Evidence와 근거를 검토한 후 내려야 합니다.

모든 분석 과정은 Evidence 무결성 유지와 분석 과정 재현 가능성을 기본 원칙으로 합니다.
