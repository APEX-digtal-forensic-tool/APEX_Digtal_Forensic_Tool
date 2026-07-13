# APEX Digital Forensic Tool

APEX는 디지털 증거 분석의 접근성과 자동화를 목표로 개발하는 **AI 기반 디지털 포렌식 분석 플랫폼**입니다.

기존 디지털 포렌식 도구는 강력한 분석 기능을 제공하지만, 높은 비용과 복잡한 사용 환경, 영어 중심의 인터페이스, 전문 지식 요구 등의 한계가 있습니다.

APEX는 다음 프로젝트의 장점을 참고하여 누구나 접근할 수 있는 차세대 DFIR 환경을 제공하는 것을 목표로 합니다.

- X-Ways Forensics의 빠른 분석 철학
- Autopsy의 Case 및 Artifact 중심 분석 Workflow
- MCP 기반 AI Agent 연동 구조

> 현재 프로젝트는 **설계 기준선(Design Baseline)** 단계입니다.  
> Architecture, Database, API 및 JSON Schema 설계는 완료되었지만 실제 Engine, GUI, MCP, AI 및 Report 실행 기능은 아직 구현 중입니다.

---

## 핵심 차별점

### 1. 한국어 기반 디지털 포렌식 환경

APEX는 한국어 사용자를 우선 고려한 디지털 포렌식 환경을 제공합니다.

지원 목표:

- 한국어 사용자 인터페이스
- Artifact 이름 및 분석 결과의 한국어 설명
- 한국어 자연어 기반 AI 질의
- 한국어 디지털 포렌식 보고서 생성
- 분석 결과와 위험도에 대한 한국어 해설
- 한글 파일명과 경로의 손실 없는 처리
- 한국어 Keyword Search
- Case별 Locale 및 Timezone 관리

기본 설정:

- Locale: `ko-KR`
- Timezone: `Asia/Seoul`
- Encoding: UTF-8

UI 문자열은 Resource Key 기반으로 관리하며, Forensic Engine은 언어에 종속되지 않는 오류 코드와 구조화된 결과를 반환합니다.

---

### 2. 기본 내장 MCP 기반 AI Forensic Assistant

APEX Desktop Distribution에는 MCP 기반 AI 연동 기능이 기본 포함될 수 있습니다.

다만 Forensic Engine 내부에 MCP SDK, LLM SDK, Prompt 또는 특정 AI Provider 의존성을 포함하지 않습니다.

```text
APEX Desktop Distribution
├── Frontend GUI
├── Backend / Session Context
├── Forensic Core Engine
└── Built-in MCP Adapter
    └── AI / LLM Provider
```

사용자 관점에서는 AI 기능이 프로그램에 기본 포함되지만, 개발 구조에서는 각 계층을 분리하여 독립적으로 개발하고 교체할 수 있도록 설계합니다.

---

### 3. 대용량 Evidence 분석 최적화

APEX는 X-Ways Forensics의 빠른 분석 철학을 참고하여 대용량 디지털 증거 처리 최적화를 목표로 합니다.

주요 최적화 방향:

- Lazy Loading
- Cursor 기반 Pagination
- Evidence Streaming
- Process Pool
- Async I/O
- Artifact 병렬 분석
- Case별 단일 Database Writer
- FTS5 또는 동등한 Full Text Index
- 분석 결과 Cache
- Checkpoint 및 Resume
- 입력 Fingerprint 기반 중복 분석 방지
- 취소 가능한 Long-running Job
- Progress Reporting
- 기존 분석 결과 재사용

성능 비교는 동일한 Hardware, Evidence 및 분석 범위를 사용한 Benchmark 이후에만 문서화합니다.

---

## 전체 시스템 구조

```text
                           사용자
                              │
                              ▼
                    한국어 기반 Forensic GUI
                              │
                              ▼
                   Backend / Application Layer
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
      Forensic Core Engine             Session Context
              │                               │
              ▼                               ▼
      Analysis Result Database         Built-in MCP Adapter
              │                               │
              └───────────────┬───────────────┘
                              ▼
                         AI / LLM Provider
```

GUI와 MCP Adapter는 서로 다른 분석 로직을 구현하지 않습니다.

두 계층 모두 Forensic Engine이 제공하는 동일한 Application Interface와 버전이 지정된 JSON Schema를 사용합니다.

---

## 기존 GUI 분석 결과 재사용

APEX의 AI는 Evidence를 무조건 처음부터 다시 분석하지 않습니다.

사용자가 GUI에서 이미 수행한 분석 결과를 저장하고, MCP Adapter가 현재 GUI Context와 기존 결과를 조회하여 AI Agent에 전달합니다.

```text
GUI에서 분석 실행
        ↓
Forensic Engine Job 실행
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

AI가 활용할 수 있는 정보:

- 현재 Case
- 현재 Evidence
- 현재 GUI 화면
- 선택된 파일
- 선택된 Artifact
- 선택된 Timeline Event
- 선택된 Search Result
- 활성화된 Filter
- Timeline 시간 범위
- Analyst Annotation
- Tag 및 주요 증거
- 기존 분석 결과
- 기존 AI 분석 결과

이를 통해 중복 분석을 방지하고, GUI 분석 결과와 AI 답변의 일관성을 유지하며, AI 답변과 보고서의 근거를 추적할 수 있습니다.

---

## GUI Context

GUI Context는 현재 사용자의 분석 상태를 나타내는 Session 단위 임시 데이터입니다.

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

## AI 분석 결과 구분

APEX는 AI가 생성한 내용을 Forensic Engine이 추출한 실제 분석 결과와 명확하게 분리합니다.

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

분석자가 작성한 설명, 판단 또는 Tag입니다.

### AI Inference

AI가 Observed Fact와 Analysis Context를 기반으로 생성한 추론입니다.

### AI Recommendation

AI가 제안하는 추가 분석 절차 또는 대응 방안입니다.

AI Inference와 Recommendation은 원본 Artifact를 변경하지 않으며, 가능한 모든 문장에 실제 Evidence 또는 분석 결과를 가리키는 Citation을 포함해야 합니다.

Citation은 다음 항목을 참조할 수 있습니다.

- `evidence_id`
- `file_id`
- `artifact_id`
- `timeline_event_id`
- `search_result_id`
- `source_path`
- `source_offset`
- `source_reference`

---

## 주요 기능

### Case Management

사건 단위의 분석 환경을 생성하고 관리합니다.

기능:

- 신규 Case 생성
- 기존 Case 불러오기
- 사건명, 분석자 및 사건 설명 관리
- Case Locale 및 Timezone 관리
- Evidence 관리
- 분석 결과 저장
- Timeline 및 Report 관리
- 분석 작업 상태 저장 및 복원

---

### Evidence Management

분석할 디지털 증거를 등록하고 무결성을 검증합니다.

지원 예정 형식:

- E01
- RAW
- DD
- IMG
- VHD
- VHDX
- Logical File
- Directory Evidence

기능:

- Evidence 등록
- Evidence Metadata 확인
- MD5, SHA-1, SHA-256 Hash 계산
- Evidence 무결성 검증
- 분석 상태 관리
- 입력 Fingerprint 기반 중복 분석 방지
- 원본 Evidence 읽기 전용 처리

---

### File System Analysis

Evidence 내부의 파일 시스템을 탐색하고 분석합니다.

기능:

- Directory Tree 탐색
- 파일 및 폴더 목록 조회
- File Metadata 분석
- 생성·수정·접근 시간 확인
- 삭제 파일 탐색
- 파일 유형별 분류
- 파일 상세 정보 조회
- Lazy Loading
- Cursor Pagination

---

### Windows Artifact Analysis

운영체제와 사용자 활동 흔적을 분석합니다.

#### Registry

지원 예정:

- Run Key
- UserAssist
- Recent Files
- USB History

#### Event Log

지원 예정:

- Security Event
- System Event
- Application Event
- Sysmon Event

#### Prefetch

지원 예정:

- 실행 프로그램 확인
- 실행 횟수 분석
- 마지막 실행 시간 확인

---

### User Activity Analysis

사용자의 최근 활동과 Browser Artifact를 분석합니다.

지원 예정:

- Browser History
- Search History
- Download History
- Recent Activity
- Browser Profile
- 방문 URL
- 다운로드 파일

---

### Timeline Analysis

여러 Artifact의 시간 정보를 통합하여 사건 흐름을 제공합니다.

분석 대상:

- 파일 생성·수정·접근 시간
- Registry 변경 시간
- 프로그램 실행 기록
- Browser 활동
- Event Log
- 다운로드 기록

기능:

- 시간순 Event 표시
- Event Type별 Filter
- 데이터 출처별 Filter
- 시간 범위 Filter
- 주요 증거 지정
- Citation 가능한 Timeline Event 생성
- AI 기반 사건 흐름 요약

---

### Search & Discovery

Evidence와 분석 결과를 빠르게 탐색합니다.

기능:

- File Name Search
- Keyword Search
- Regex Search
- Metadata Search
- Artifact Search
- 한국어 Keyword Search
- Index 기반 검색
- Cursor 기반 결과 조회
- 검색 결과 Filter
- 검색 결과 Cache

---

### Images / Videos Analysis

이미지와 영상 Artifact를 분석합니다.

MVP 범위:

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

AI는 기존 Metadata와 분석 결과를 요약하거나 사건 관련성을 설명할 수 있지만 원본 Media를 변경하지 않습니다.

---

### Communications Analysis

초기 Communications 기능은 Browser Artifact 중심으로 구현합니다.

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

후순위 기능은 초기 구현 완료 항목으로 표시하지 않습니다.

---

### Tag 및 Analyst Annotation

분석자가 중요한 증거와 판단을 기록할 수 있도록 지원합니다.

기능:

- 파일, Artifact 및 Timeline Event에 Tag 지정
- 주요 증거 표시
- 분석자 Annotation 작성
- 보고서 포함 항목 선택
- Annotation 작성자와 수정 시간 기록
- AI 결과와 Analyst 판단 분리

---

## AI Forensic Assistant

AI Assistant는 자연어 기반으로 현재 분석 결과를 설명하고 추가 분석을 보조합니다.

지원 목표:

- 한국어 자연어 질의
- 현재 GUI 화면과 선택 항목 이해
- 기존 분석 결과 요약
- 선택된 Artifact 설명
- 의심 행위 분석
- Artifact 간 관계 분석
- Timeline 흐름 요약
- 추가 분석 항목 추천
- 위험도 판단 보조
- Citation 기반 답변
- 보고서 초안 작성

AI는 Forensic Engine을 대체하지 않으며, Engine이 반환한 구조화된 분석 결과를 기반으로 보조 역할을 수행합니다.

특정 AI Provider에 종속되지 않도록 설계하며 향후 다양한 API 또는 Local LLM과 연결할 수 있도록 구성합니다.

---

## AI 보고서 생성

AI가 생성한 보고서는 즉시 최종 결과로 확정되지 않습니다.

```text
AI Draft
    ↓
Human Review
    ↓
Approval
    ↓
PDF / HTML Export
```

보고서 상태:

- `draft`
- `generating`
- `review_required`
- `approved`
- `rejected`
- `exporting`
- `exported`
- `failed`

분석자가 승인한 특정 Report Version만 Export할 수 있습니다.

승인 후 내용이 변경되면 기존 승인은 무효화되고 다시 검토해야 합니다.

---

## 보고서 구성

생성 가능한 Section:

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

## Evidence 분석 원칙

APEX는 다음 원칙에 따라 디지털 증거를 처리합니다.

- 원본 Evidence 읽기 전용 처리
- Evidence 원본 수정 금지
- 등록 시 Hash 계산
- 분석 전후 무결성 검증
- 원본 데이터와 파생 데이터 분리
- 분석 작업 Audit 기록
- AI 결과와 Observed Fact 분리
- Citation을 통한 분석 근거 추적
- 분석 과정 재현 가능성 확보

---

## 역할 및 책임

### Forensic Engine

담당:

- Case 및 Evidence 관리
- File System 분석
- Artifact 분석
- Timeline 생성
- Search, Index 및 Cache
- Analysis Result Database
- Job 및 Progress 관리
- Audit 및 Citation
- GUI와 MCP Adapter용 Application Interface
- 버전이 지정된 JSON Schema 결과 제공

비담당:

- MCP SDK
- LLM SDK
- Prompt
- Agent Loop
- API Key
- AI Token 과금

---

### MCP / AI Layer

담당:

- Built-in MCP Adapter
- MCP Server
- MCP Tool 정의
- Engine API Wrapping
- GUI Context 전달
- LLM Provider 연결
- Prompt Engineering
- AI 분석 Workflow
- 보고서 초안 작성 요청

---

### Frontend

담당:

- 한국어 GUI
- Case Explorer
- Evidence View
- File System View
- Artifact View
- Timeline UI
- Images / Videos UI
- Communications UI
- AI Assistant UI
- Report Preview
- GUI Context 생성

---

### Backend

담당:

- Case 및 사용자 데이터 관리
- Session Context Store
- 분석 작업 상태 관리
- API 및 Service Layer
- 분석 결과 저장 및 조회
- Report File 관리
- 사용자 승인 Identity 관리
- AI Token 사용량 및 Billing 경계

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

## 설계 문서

| 산출물 | 문서 |
|---|---|
| 전체 Architecture 및 품질 속성 | [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) |
| 제안 Directory Structure | [`docs/DIRECTORY_STRUCTURE.md`](./docs/DIRECTORY_STRUCTURE.md) |
| Module 역할과 의존성 | [`docs/MODULE_RESPONSIBILITIES.md`](./docs/MODULE_RESPONSIBILITIES.md) |
| Database Schema | [`docs/DATABASE_SCHEMA.md`](./docs/DATABASE_SCHEMA.md) |
| API Interface | [`docs/API_INTERFACE.md`](./docs/API_INTERFACE.md) |
| JSON Schema 규칙 | [`docs/JSON_SCHEMAS.md`](./docs/JSON_SCHEMAS.md) |
| 구현 Roadmap | [`docs/IMPLEMENTATION_ROADMAP.md`](./docs/IMPLEMENTATION_ROADMAP.md) |
| 요구사항 Traceability | [`docs/REQUIREMENTS_TRACEABILITY.md`](./docs/REQUIREMENTS_TRACEABILITY.md) |

기계 판독용 데이터 계약은 [`schemas/v1/`](./schemas/v1)에 있으며 설계 검증 도구는 [`tools/`](./tools)에 있습니다.

---

## 개발 진행 상태

### 설계 완료

- [x] 전체 System Architecture 설계
- [x] Forensic Core Engine Architecture 설계
- [x] Module Responsibility 정의
- [x] Database Schema 설계
- [x] API Interface 설계
- [x] JSON Schema v1 설계 및 검증
- [x] GUI Context 설계
- [x] Analysis Context 설계
- [x] Citation 설계
- [x] Provider-neutral AI 경계 설계
- [x] MCP Integration Boundary 설계
- [x] Report Module 설계
- [x] Human Review 및 Approval Workflow 설계
- [x] 한국어 및 Localization 설계
- [x] Browser Communications MVP 범위 설계
- [x] Images / Videos MVP 범위 설계
- [x] Requirements Traceability 작성
- [x] Implementation Roadmap 작성
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
- [ ] 한국어 GUI 구현
- [ ] GUI Context 구현
- [ ] Analysis Context Snapshot 구현
- [ ] Built-in MCP Adapter 구현
- [ ] LLM Provider 및 Prompt Workflow 구현
- [ ] AI 분석 기능 구현
- [ ] Report Application 구현
- [ ] PDF 및 HTML Export 구현
- [ ] 한국어 Keyword Search 구현
- [ ] AI Token Billing 구현
- [ ] 성능 Benchmark
- [ ] Desktop Packaging

---

## 구현 Roadmap

### Phase 0 — 설계 정합성 검증

- JSON Schema 검증
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

### Phase 6 — GUI Context 및 MCP Interface

- GUI Context
- Analysis Context
- MCP Adapter용 공개 Interface

### Phase 7 — AI Enrichment

- Citation
- Observed Fact와 AI Inference 분리
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

MCP Server와 LLM Provider 구현은 MCP 및 AI 담당자의 별도 Roadmap에서 관리합니다.

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
| X-Ways Forensics MCP | GUI 분석 결과와 포렌식 기능을 MCP Context로 연결하는 방식 |

APEX는 위 프로젝트의 구조와 Workflow를 참고하지만, 특정 제품을 그대로 복제하는 것을 목표로 하지 않습니다.

외부 소스 코드를 직접 사용하는 경우 각 프로젝트의 License와 저작권 조건을 확인합니다.

---

## 개발 목적 및 주의 사항

APEX는 합법적인 디지털 포렌식 조사, 보안 연구 및 교육을 목적으로 개발합니다.

AI가 생성한 분석 결과와 보고서는 분석 보조 자료이며, 최종 판단은 분석자가 원본 Evidence와 분석 근거를 검토한 후 내려야 합니다.

모든 분석 과정은 다음 원칙을 따릅니다.

- Evidence 무결성 유지
- 원본 Evidence 읽기 전용 처리
- 분석 과정 Audit
- Citation 기반 근거 추적
- AI 결과와 Observed Fact 분리
- 분석 결과 재현 가능성 확보
