# APEX Frontend 구현 인수인계서 v2

> 기준 저장소: `APEX-digtal-forensic-tool/APEX_Digtal_Forensic_Tool`
>
> 기준 브랜치/커밋: `main == feat/forensic-engine @ dbee798f12031d5f654430fe44ecfd1f8fa2211f`
>
> 문서 목적: Frontend 담당자가 **현재 실제 Forensic Core Engine이 제공하는 계약과 상태를 기준으로** APEX Desktop UI를 구현할 수 있도록, 해야 할 작업·화면·상태·데이터 계약·예외 처리·검증 기준을 구체적으로 전달한다.
>
> 중요: 이 문서는 “원하는 제품 아이디어”와 “현재 실제 구현된 Engine 계약”을 구분한다. Frontend는 없는 기능을 있는 것처럼 표시하면 안 된다.

>
> **v2 반영 범위**
>
> - `docs/` 10개 문서를 현재 Runtime/Schema/Test 기준으로 동기화한 상태를 반영
> - `schemas/v1` 전체 67개 계약 감사 및 Runtime Contract Drift 수정 결과 반영
> - Source-side Contract mismatch(Secret redaction, Hash verification case scope, Search bounds, AI/Report bounds, Case validation) 수정 결과 반영
> - Windows에서 전체 `pytest` PASS(실패 0, 일부 optional test skip), Ruff PASS, mypy 115 source files PASS 결과 반영
> - `validate_design_basic.py` 1,813 checks PASS, `validate_design.mjs` 4,124 checks PASS 결과 반영
> - Frontend가 현재 Runtime에서 기대하면 안 되는 Annotation/Tag persistence와 plaintext secret 표시를 명확히 분리

---

# 0. 먼저 읽어야 하는 결론

Frontend가 지금부터 해야 할 핵심은 아래 5개다.

1. **Engine 결과를 직접 해석하거나 재구현하지 않고 표시하는 UI**를 만든다.
2. **Case → Evidence → File System → Artifact → Search/Timeline → Report** 분석 흐름을 Desktop GUI로 연결한다.
3. 모든 조회 결과에서 `Partial`, `Stale`, `Warning`, `Capability unavailable`, `Citation`, `Raw Locator`를 숨기지 않는다.
4. GUI 선택 상태를 `GUI Session Context`로 관리하여 Backend/MCP/Report가 같은 선택 상태를 재사용할 수 있게 한다.
5. Engine에 없는 HTTP Server, MCP, LLM, Credential 추출, 분석 로직을 Frontend가 임의로 만들지 않는다.

현재 Frontend가 구현해야 하는 화면 레벨 기능은 다음이다.

- Case Explorer
- Evidence Manager
- Analysis Job / Progress
- File System Explorer
- Artifact Explorer
  - Registry
  - Event Log
  - Prefetch
  - Browser
  - Communications
  - Media
- Search
- Timeline
- Machine-extracted Candidate Review
- Simple / Detailed / Raw Inspector
- Timezone 확인
- Annotation / Tag **제품 Placeholder** — 현재 Core에 전용 persistence/service/API 없음
- Chain of Custody
- Report Review / Approval / Export UI
- Runtime Capability / Settings
- AI Assistant 연동용 UI Shell

단, **AI Assistant의 실제 AI 실행, MCP Server, Prompt, Model 연결은 Frontend 담당이 아니다.**

---

# 1. 검증 방법

이 문서는 한 번만 README를 읽고 작성하지 않았다.

## 1차 검증 — 요구사항/문서/Schema 교차 확인

다음을 서로 대조했다.

- `README.md`
- `docs/API_INTERFACE.md`
- `docs/DIRECTORY_STRUCTURE.md`
- `docs/FORENSIC_ENGINE.md`
- `docs/REQUIREMENTS_TRACEABILITY.md`
- `schemas/v1/*.schema.json`

확인 목적:

- Frontend 담당 범위가 무엇인지
- 어떤 화면이 필요한지
- 각 화면에 어떤 상태와 필드가 존재하는지
- 어떤 기능이 설계만 있고 실제 Runtime은 없는지
- Legacy 문서와 현재 구현이 충돌하는 부분이 있는지

## 2차 검증 — 실제 Runtime/CLI/Test와 다시 대조

문서 표현만 믿지 않고 다음 구현을 다시 확인했다.

- `src/apex_forensic/cli/parser.py`
- `src/apex_forensic/runtime/capabilities.py`
- `tests/unit/test_phase6_context_views.py`
- `tests/unit/test_phase8_report_contract.py`
- 현재 `main`의 Phase 6/8 Schema
- 현재 Job / File / Artifact / Timeline / Search Schema

확인 목적:

- 실제 CLI에 존재하는 기능인지
- 실제 Schema 검증 Test가 있는지
- 현재 GUI Context Enum이 무엇인지
- Raw View 제한이 실제 Test와 일치하는지
- Report Review/Approval 규칙이 실제 Runtime에서 강제되는지
- Capability 상태가 실제 Runtime에서 어떤 값으로 나오는지

## 3차 검증 — 67개 JSON Schema 전수 감사

현재 `schemas/v1`은 67개 Schema로 정리되어 있다.

이 단계에서 다음을 전수 비교했다.

- Runtime Enum ↔ Schema Enum
- `to_schema_dict()` ↔ `required` / nullability / bounds
- `$ref` graph
- Legacy compatibility Schema ↔ Current canonical Schema
- Secret/Prompt/Raw provider body 제한
- Runtime Capability 상태
- Report/Context granular Schema
- Search query bounds
- Evidence/Hash contract

대표적으로 `SHA512`는 Evidence Streaming Hash Contract에서 제거되었고, 현재 Evidence Hash 알고리즘은 `SHA256`, `SHA1`, `MD5` 세 가지다.

## 4차 검증 — Source-side mismatch 수정 및 Windows Regression

Schema 감사에서 발견한 Source mismatch를 실제 Runtime에 반영했다.

- Secret DTO recursive redaction
- Hash verification `case_id` persistence/reload 보존
- Search 일반 Query 4,096자 / Regex 512자 제한
- AI Assistance bounded validation
- Report bounded validation
- Case Name 255자 / Locale 검증

Windows 검증 결과:

```text
pytest: PASS (failure 0, optional dependency test 일부 skip)
ruff: PASS
mypy: PASS (115 source files)
validate_design_basic.py: PASS (1813 checks)
validate_design.mjs: PASS (4124 checks)
```

---

# 2. 두 번 검증하면서 발견한 주의사항

이 부분은 Frontend 담당자가 특히 중요하게 봐야 한다.

## 2.1 `/api/v1` REST Endpoint를 지금 바로 존재하는 서버라고 가정하면 안 됨

`docs/API_INTERFACE.md`에는 `/api/v1` HTTP 계약이 설계되어 있다.

하지만 현재 Core Runtime은 주로:

- Application Service
- Public Engine Interface
- CLI
- JSON Schema

형태로 구현되어 있고, **현재 저장소에 완성된 Backend Web Server가 포함되어 있다고 보면 안 된다.**

따라서 Frontend는 처음부터 아래처럼 작성해야 한다.

```text
UI Component
    ↓
Frontend Service / Gateway Interface
    ↓
Backend / Desktop Bridge / IPC / HTTP Adapter
    ↓
Forensic Core Engine
```

금지:

```text
UI Component
    ↓
fetch("/api/v1/...")를 화면마다 직접 하드코딩
```

Frontend는 Transport를 추상화해야 한다.

Backend가 최종적으로 HTTP를 쓰든 IPC를 쓰든 Desktop Bridge를 쓰든 UI를 갈아엎지 않도록 한다.

---

## 2.2 Legacy `ui-context.schema.json`을 최신 GUI Contract로 사용하지 말 것

저장소에는 오래된 `ui-context.schema.json`이 남아 있다.

현재 Phase 6 Runtime Test가 직접 검증하는 최신 GUI Session Contract는:

```text
schemas/v1/gui-session-context.schema.json
```

이다.

Frontend에서 사용할 현재 Route Enum도 이 Schema/실제 CLI와 맞춰야 한다.

현재 Route:

```text
CASE_OVERVIEW
EVIDENCE
FILE_SYSTEM
ARTIFACTS
REGISTRY
EVENT_LOG
PREFETCH
BROWSER
MEDIA
SEARCH
TIMELINE
CANDIDATES
CHAIN_OF_CUSTODY
REPORT
SETTINGS
UNKNOWN
```

Legacy Schema에 있는:

```text
FILES
BROWSER_COMMUNICATIONS
INDEXING
KEYWORD_RECOMMENDATIONS
MACHINE_EXTRACTIONS
RAW
```

등을 현재 메인 Route 이름으로 그대로 사용하지 말 것.

---

## 2.3 Communications는 실제 기능이 있지만 현재 독립 `current_route`는 없음

Engine은 현재 Communication Artifact를 지원한다.

지원 Artifact 종류에는 다음이 존재한다.

```text
COMMUNICATION_PROFILE
COMMUNICATION_ACCOUNT
COMMUNICATION_CONVERSATION
COMMUNICATION_MESSAGE
COMMUNICATION_ATTACHMENT
COMMUNICATION_UNSUPPORTED_STORE
```

CLI에도 Communication 조회가 존재한다.

그러나 현재 GUI Route Enum에는:

```text
COMMUNICATIONS
```

라는 별도 Route가 없다.

따라서 Frontend 초기 구현에서는 다음 중 하나를 사용한다.

**권장:**

```text
ARTIFACTS
└── Communications 탭
```

또는 제품 디자인에 따라 별도 Route를 추가하려면 먼저 Backend/Engine Context Enum과 합의하고 Schema를 같이 변경해야 한다.

Frontend 혼자 Route 문자열을 추가하면 안 된다.

---

## 2.4 Raw View는 메인 Route가 아니라 선택 Resource의 View Mode로 구현하는 것이 현재 계약에 맞음

현재 Runtime은:

```text
SIMPLE
DETAILED
RAW
```

View Projection을 제공한다.

따라서 Raw는 좌측 메인 메뉴보다는:

```text
선택된 File / Artifact / Timeline / Search Result
    ↓
Inspector
    ├── Simple
    ├── Detailed
    └── Raw
```

구조가 현재 Runtime과 가장 잘 맞는다.

---

## 2.5 Report는 Legacy `report.schema.json` 하나만 보고 구현하지 말 것

Phase 8 이후 Runtime에서는 다음 분리 Schema가 실제 Test에 사용된다.

```text
report-record.schema.json
report-version.schema.json
report-section.schema.json
report-review-event.schema.json
report-approval-record.schema.json
custody-snapshot.schema.json
report-render-package.schema.json
report-export-manifest.schema.json
rendered-report-artifact.schema.json
report-renderer-capability.schema.json
```

Frontend Report 화면은 위 최신 분리 Contract 기준으로 작성한다.

---

## 2.6 Report Renderer를 Frontend가 구현할 필요 없음

일부 오래된 문서에는 PDF/HTML Renderer가 미구현처럼 남아 있는 설명이 있다.

그러나 현재 Runtime에는:

```text
report render-html
report render-pdf
```

CLI 경로와 Runtime Renderer Capability가 존재한다.

현재 Runtime Doctor에도:

```text
html-renderer
pdf-renderer
```

Capability가 존재한다.

따라서 Frontend의 역할은:

- Export 옵션 표시
- Renderer Capability 표시
- Export 요청
- Export 상태 표시
- 완성된 결과 다운로드/열기

이다.

Frontend가 PDF Renderer 자체를 구현하는 것이 아니다.

PDF는 `reportlab` Optional Dependency 상태에 따라 unavailable일 수 있다.

---

## 2.7 Registry Deleted-cell Carving은 현재 구현되어 있음

오래된 README 일부에는 Binary Deleted-cell Carving 미지원 설명이 남아 있을 수 있다.

현재 Runtime/CLI에는:

```text
artifact registry carve-deleted
```

가 존재하고 Core Runtime 완료 항목에 포함된다.

따라서 Frontend Registry 화면에 삭제 Candidate UI를 만들 수 있다.

단, Carving 결과는 원본 Registry의 정상 Live Key와 동일한 확정 Fact처럼 표시하면 안 된다.

반드시:

```text
Deleted Candidate
Recovered Candidate
Partial / Confidence / Warning
```

성격을 UI에서 구분한다.

---

## 2.8 “Logical File Evidence” 표기는 Backend와 한번 더 맞춰야 함

README에는 Logical File Evidence 지원 표현이 존재하지만 현재 `evidence.schema.json`의 안정적 `format` Enum은:

```text
DIRECTORY
RAW
DD
IMG
E01
VHD
VHDX
```

이다.

Frontend가 Evidence 등록 Dropdown에 임의로 `LOGICAL_FILE` Enum을 추가하면 Schema와 충돌할 수 있다.

초기 구현에서는:

- 사용자가 파일/디렉터리를 선택
- 실제 Format은 Backend/Engine Probe 결과를 표시

방식으로 만든다.

`LOGICAL_FILE`을 정식 Format Enum으로 노출하려면 Backend/Engine Schema 확정 후 진행한다.

---

## 2.9 Generic Job에 Pause 버튼을 무조건 만들면 안 됨

Job Schema에는:

```text
QUEUED
RUNNING
PAUSING
PAUSED
RESUMING
SUCCEEDED
PARTIAL
FAILED
CANCELLED
```

상태가 존재한다.

하지만 모든 Job 종류에 동일한 Generic Pause Endpoint가 현재 확정된 것은 아니다.

Index/Artifact/Search/Timeline 등은 Resume/Cancel 계약이 실제 CLI에 존재한다.

따라서 버튼은 Capability/Operation Descriptor 기준으로 노출한다.

잘못된 구현:

```text
모든 RUNNING Job → 무조건 Pause 버튼 표시
```

권장:

```text
backend 제공 action 목록에 PAUSE/RESUME이 있을 때만 표시
```

---

## 2.10 Evidence Hash에 `SHA512`를 표시하지 말 것

현재 Evidence Streaming Hash Contract는 다음 세 가지다.

```text
SHA256
SHA1
MD5
```

`SHA512`는 DPAPI/KakaoTalk 등 내부 cryptographic scope에서 사용될 수 있지만, **Evidence Hash 선택지**가 아니다.

Frontend Hash Algorithm dropdown에 `SHA512`를 추가하지 말 것.

---

## 2.11 Search Query 길이 제한을 Frontend에서도 동일하게 적용

현재 Runtime이 실제로 강제하는 최대 길이:

```text
TERM / PHRASE / PREFIX / EXACT : 4096 characters
REGEX_METADATA                 : 512 characters
```

Frontend는 입력 단계에서 동일한 제한을 적용하되 Backend Validation을 대체한다고 생각하면 안 된다.

---

## 2.12 Runtime Capability Report는 전용 Schema가 있음

현재 Runtime Doctor/Capability Matrix의 canonical contract:

```text
schemas/v1/runtime-capability-report.schema.json
```

Status:

```text
AVAILABLE
AVAILABLE_WITH_LIMITATIONS
CAPABILITY_UNAVAILABLE
EXTERNAL_CONFIGURATION_REQUIRED
UNSUPPORTED_PLATFORM
BLOCKED_EXTERNAL_FIXTURE
HOST_VERIFICATION_REQUIRED
```

Frontend Settings/Capability 화면은 boolean `available=true/false`로 축약하지 않는다.

---

## 2.13 Annotation / Tag persistence를 현재 구현 기능으로 가정하지 말 것

현재 Core에는 전용:

```text
AnnotationService
TagService
annotations table
tag_items table
current Annotation/Tag transport API
```

가 확정 구현되어 있지 않다.

따라서 Frontend에서 Annotation/Tag UI를 디자인할 수는 있지만, **현재 동작하는 저장 기능처럼 연결하면 안 된다.**

초기 제품에서는:

```text
Disabled / Coming later / Backend contract required
```

상태로 두거나, Backend가 실제 persistence contract를 제공한 뒤 활성화한다.

`ANALYST_ANNOTATION`이라는 semantic category가 존재하는 것과 현재 Annotation CRUD가 구현되어 있다는 것은 다른 문제다.

---

## 2.14 Secret plaintext를 Frontend가 받을 것이라고 가정하지 말 것

현재 Secret/Decryption DTO public serialization은 recursive redaction을 적용한다.

다음과 같은 값은 public DTO에서 원문으로 노출되지 않는다.

```text
db_key_hex
db_iv_hex
pragma_key
user_nonce
nt_hash_hex
masterkey_hex
password
API key
plaintext
```

`include_secret=True`, `include_plaintext=True` 같은 과거 escape-style serializer 호출도 현재 public output에서 raw secret을 내보내지 않는다.

안전한 fingerprint/provenance:

```text
sha256
pragma_key_hash
user_nonce_hash
content_sha256
```

는 원본 비밀값과 구분하여 표시할 수 있다.

Frontend에 “비밀번호 보기”, “키 보기” 같은 UI가 필요하다면 **현재 Core Contract와 별도의 privileged Backend contract**가 새로 필요하다.

---

## 2.15 Hash verification의 `case_id`는 Current Runtime에서 보존됨

현재 Runtime은 Hash Verification을:

```text
create
→ persist
→ reload
```

한 뒤에도 `case_id`를 보존한다.

다만 `chain-of-custody.schema.json`의 `runtimeHashVerification`은 이전 DB/compatibility를 위해 `case_id` 누락 형태도 아직 허용할 수 있다.

Frontend 규칙:

- Current Runtime 응답에서는 `case_id`를 사용한다.
- Legacy record에서 `case_id`가 없다고 다른 Case로 추측하지 않는다.
- Backend가 Evidence/Case scope를 resolve해야 한다.
- Frontend가 임의로 `case_id`를 생성하거나 보정하지 않는다.

---

# 3. Frontend의 책임과 비책임

## Frontend 담당

Frontend가 책임져야 하는 것:

- 한국어 GUI
- Case Explorer
- Evidence 선택/표시
- File System Tree/Table
- Artifact 화면
- Registry 화면
- Event Log 화면
- Prefetch 화면
- Browser 화면
- Communication 화면
- Media 화면
- Search 화면
- Timeline 화면
- Machine Candidate 검토 화면
- Simple / Detailed / Raw Inspector
- Analysis Progress 표시
- Partial/Stale/Warning 표시
- Timezone 확인 UI
- Keyword 승인/검색 UI
- Annotation / Tag UI **Placeholder** — Backend persistence contract가 생길 때만 활성화
- Chain of Custody 입력/조회 UI
- Report 편집/검토/승인/Export UI
- AI Assistant 결과를 보여줄 UI Shell
- GUI Session Context 상태 관리
- 한국어 Resource Bundle
- Capability 상태에 따른 기능 활성/비활성
- 오류 Code → 사용자 메시지 Resource Key 매핑
- Loading / Empty / Partial / Error / Unavailable 상태 구분

## Frontend 비담당

Frontend가 하면 안 되는 것:

- E01 파싱
- VHD/VHDX 파싱
- File System 파싱
- Registry 파싱
- Event Log 파싱
- Prefetch 파싱
- Browser DB 직접 분석
- SQLite Case DB 직접 열기
- Evidence Hash 직접 계산
- Evidence 원본 직접 수정
- 삭제 File 복구 알고리즘 구현
- DPAPI/NSS 복호화 알고리즘 구현
- KakaoTalk Key 획득 로직 구현
- MCP Server 구현
- LLM Provider 연결
- Prompt Engineering
- Agent Loop
- API Key 저장
- AI 결과를 Observed Fact로 변환
- PDF/HTML Renderer 자체 구현
- Engine의 `developer_message`를 사용자용 한국어 메시지로 그대로 표시
- 임의 Absolute Evidence Path로 File을 직접 읽기

---

# 4. Frontend 구현의 Source of Truth 우선순위

문서가 충돌할 때 다음 순서로 판단한다.

## 1순위 — 현재 Runtime 코드와 Test

```text
src/apex_forensic/
tests/
```

## 2순위 — 현재 Canonical Schema

현재 `schemas/v1`은 67개이며, 특히 Frontend는 legacy aggregate보다 granular/current contract를 우선한다.


특히:

```text
schemas/v1/gui-session-context.schema.json
schemas/v1/analysis-context-snapshot.schema.json
schemas/v1/analysis-scope-context.schema.json
schemas/v1/view-projection.schema.json
schemas/v1/raw-view.schema.json
schemas/v1/raw-read-response.schema.json
schemas/v1/engine-interface.schema.json
schemas/v1/engine-tool-descriptor.schema.json
schemas/v1/runtime-capability-report.schema.json
schemas/v1/report-record.schema.json
schemas/v1/report-version.schema.json
schemas/v1/report-section.schema.json
schemas/v1/report-review-event.schema.json
schemas/v1/report-approval-record.schema.json
schemas/v1/report-export-manifest.schema.json
```

## 3순위 — Core Entity Schema

```text
case.schema.json
evidence.schema.json
file.schema.json
artifact.schema.json
search.schema.json
timeline-event.schema.json
job.schema.json
machine-extracted-candidate.schema.json
citation.schema.json
common.schema.json
```

## 4순위 — API 설계 문서

```text
docs/API_INTERFACE.md
```

주의:

이 문서의 HTTP Endpoint는 Backend Adapter 설계 계약이며 현재 Frontend가 직접 호출할 실제 서버가 존재한다고 단정하면 안 된다.

## 5순위 — README / Roadmap 설명

README는 제품 설명 용도다.

Runtime/Test/Schema와 충돌하면 최신 Runtime/Test/Schema를 우선한다.

---

# 5. Frontend 전체 화면 구조

현재 Engine GUI Route와 제품 요구사항을 합치면 다음 구조를 권장한다.

```text
APEX Desktop
├── Case Overview
├── Evidence
├── File System
├── Artifacts
│   ├── All Artifacts
│   ├── Registry
│   ├── Event Log
│   ├── Prefetch
│   └── Communications
├── Browser
├── Media
├── Search
├── Timeline
├── Candidates
├── Chain of Custody
├── Report
└── Settings
```

AI Assistant는 별도 메인 Route로 강제하지 않고:

```text
우측 Assistant Drawer
또는
하단 Assistant Panel
```

형태로 두는 것을 권장한다.

이유:

- 현재 `current_route` Enum에 AI Route가 없음
- AI Runtime은 별도 Layer
- 현재 GUI Context와 선택 Resource를 Assistant가 재사용하는 구조가 제품 설계에 맞음

---

# 6. 권장 Desktop Layout

아래는 계약이 아니라 현재 APEX Workflow에 맞는 **Frontend 구현 권장안**이다.

```text
┌─────────────────────────────────────────────────────────────────────┐
│ Top Bar                                                             │
│ APEX | Case | Active Evidence | Timezone | Jobs | Capabilities      │
├──────────────┬───────────────────────────────────┬──────────────────┤
│ Left Nav     │ Main Workspace                    │ Inspector        │
│              │                                   │                  │
│ Case         │ Table / Tree / Timeline           │ Simple           │
│ Evidence     │ Search Results                    │ Detailed         │
│ Files        │ Artifact View                     │ Raw              │
│ Artifacts    │                                   │ Citation         │
│ Browser      │                                   │ Warnings         │
│ Media        │                                   │ Actions          │
│ Search       │                                   │                  │
│ Timeline     │                                   │                  │
│ ...          │                                   │                  │
├──────────────┴───────────────────────────────────┴──────────────────┤
│ Job / Partial / Warning / Background Status                         │
└─────────────────────────────────────────────────────────────────────┘
```

핵심:

- 좌측: 탐색
- 중앙: 대량 결과
- 우측: 현재 선택 Resource 상세
- 상단/하단: 작업 상태와 Capability
- 선택 Resource를 바꿔도 같은 `resource_id` 기반으로 Simple/Detailed/Raw를 전환

---

# 7. Frontend 공통 Client Layer

화면 Component가 Engine Transport를 직접 호출하지 않도록 한다.

## 반드시 하나의 Gateway를 둔다

예시 이름:

```text
ApexFrontendClient
ApexGateway
ForensicBackendClient
```

프레임워크가 무엇이든 아래 책임을 한 곳에 모은다.

```text
- Case 조회/변경
- Evidence 등록/조회
- Job 조회/취소/재개
- File Tree 조회
- Artifact 조회
- Search
- Timeline
- Context
- View Projection
- Raw Read
- Candidate Review
- Custody
- Report
- Capability
```

### 금지

```ts
// 각 Component마다 fetch 직접 호출
fetch("/api/v1/cases/...")
```

### 권장 개념

```ts
interface ApexGateway {
  listCases(...)
  getCase(...)
  createCase(...)

  listEvidence(...)
  getEvidence(...)
  registerEvidence(...)

  getJob(...)
  cancelJob(...)

  listFileNodes(...)
  getFileNode(...)

  listArtifacts(...)
  getArtifact(...)

  search(...)
  listTimeline(...)

  getSessionContext(...)
  updateSessionContext(...)

  getSimpleView(...)
  getDetailedView(...)
  getRawView(...)

  listCapabilities(...)

  listReports(...)
  getReport(...)
}
```

이 TypeScript 예시는 **권장 Frontend 구조**이며 Engine에 동일 이름의 TypeScript Interface가 있다는 뜻은 아니다.

---

# 8. Type 생성 전략

Frontend가 TypeScript를 사용한다면 JSON Schema에서 Type을 생성하는 것을 권장한다.

직접 수기로 아래 Enum을 여러 곳에 복사하지 말 것.

예:

```text
JobStatus
ArtifactType
ReportStatus
ViewMode
GuiRoute
MachineCandidateStatus
CapabilityStatus
```

가능하면:

```text
schemas/v1/*.schema.json
        ↓
generated types
        ↓
UI
```

방식으로 관리한다.

Schema Version 변경 시 Compile/Test 단계에서 깨지도록 하는 것이 좋다.

---

# 9. GUI Session Context — 반드시 구현

Frontend가 단순히 화면만 그리면 안 되는 가장 중요한 이유다.

현재 GUI Session Context가 저장해야 하는 핵심 상태:

```text
session_context_id
session_id
case_id
actor_id
locale
timezone
current_route
current_panel
active_evidence_id

selected_file_node_ids
selected_artifact_ids
selected_timeline_event_ids
selected_search_result_ids
selected_media_artifact_ids
selected_browser_artifact_ids
selected_candidate_ids

active_filters
active_sort
active_time_range

active_keyword_set_id
active_keyword_set_version
active_search_execution_id
active_timeline_revision
active_context_scope

ui_preferences

context_revision
source_revision_fingerprint
is_partial
stale_reasons

created_at
updated_at
expires_at
```

## Context Update 규칙

사용자가 다음을 변경하면 GUI Context도 갱신한다.

- Route 변경
- 현재 Evidence 변경
- File 선택
- Artifact 선택
- Timeline Event 선택
- Search Result 선택
- Media 선택
- Browser Artifact 선택
- Candidate 선택
- Filter 변경
- Sort 변경
- Timeline Range 변경
- 활성 Keyword Set 변경

## Revision을 무시하면 안 됨

현재 Context Runtime은 Optimistic Lock을 사용한다.

예:

```text
현재 context_revision = 7

Frontend Update:
expected_revision = 7
```

다른 창/동작이 먼저 갱신해 Revision이 8이 되었으면:

```text
CONTEXT_REVISION_CONFLICT
```

가 발생할 수 있다.

Frontend 처리:

```text
1. 사용자 변경값을 임시 보존
2. 최신 Context 다시 조회
3. 충돌 UI 표시
4. 최신 상태에 사용자 Intent를 재적용할지 결정
5. 절대 조용히 덮어쓰지 않음
```

## Context 만료

`CONTEXT_EXPIRED`가 오면:

```text
오류 Toast만 띄우고 끝
```

이 아니라:

```text
새 Session Context 생성
→ 현재 Case/Route/Selection을 가능한 범위에서 복원
→ 사용자에게 Session 갱신 안내
```

하도록 한다.

---

# 10. 공통 View Projection Component

Frontend는 File/Artifact/Timeline 등마다 상세 UI를 전부 별개로 다시 설계하기보다 공통 Inspector를 만들 수 있다.

현재 `view-projection.schema.json`이 제공하는 필드:

```text
projection_id
case_id
resource_type
resource_id
view_mode
title
subtitle
summary
severity
badges
primary_fields
secondary_fields
technical_fields
raw_fields
timestamps
timezone
confidence
partial_state
stale_state
warnings
citations
raw_locator
available_actions
source_revision
analyzer_id
analyzer_version
projection_version
created_at
```

## Inspector UI

```text
[ Simple ] [ Detailed ] [ Raw ]
```

### Simple

표시:

- title
- subtitle
- summary
- severity
- badges
- primary_fields
- 핵심 timestamp
- Partial/Stale
- Citation

### Detailed

표시:

- primary_fields
- secondary_fields
- technical_fields
- analyzer
- analyzer version
- source revision
- timezone
- confidence
- warnings
- citations

### Raw

표시:

- locator type
- source path
- requested/returned offset
- requested/returned length
- total length
- encoding
- hex preview
- text preview
- structured raw fields
- SHA-256 정보
- truncated 여부
- citation

---

# 11. Raw View 제한

현재 Raw Read의 최대 `requested_length`는:

```text
1,048,576 bytes
```

즉 1 MiB다.

Frontend는 1 MiB를 넘는 Range를 한 번에 요청하지 않는다.

## Raw UI 행동

- 기본은 작은 Chunk
- 다음 Chunk 버튼 또는 Cursor/Offset 방식
- `truncated=true`이면 “원본이 더 있음” 표시
- Hex와 Text Preview 전환
- Offset 입력 검증
- Negative Offset 금지
- 1 MiB 초과 Length 입력 차단
- Raw Read는 Audit이 남는 동작이라는 점 표시 가능

## 보안

Frontend는 `raw_locator`에 들어 있는 값만으로 로컬 파일을 직접 열면 안 된다.

Raw Byte는 반드시 Backend/Engine 검증 경로를 통해 요청한다.

---

# 12. Case 화면

Route:

```text
CASE_OVERVIEW
```

## Case List

표시 권장 필드:

```text
name
status
locale
timezone
created_at
created_by
engine_version
```

Status:

```text
OPEN
CLOSED
ARCHIVED
```

## Case 생성

입력:

```text
Name                 필수
Description          선택
Locale               기본 ko-KR
Timezone             기본 Asia/Seoul
```

Frontend Validation:

- Name 빈 문자열 금지
- Name 최대 255자
- Locale은 현재 Schema가 허용하는 Locale pattern을 사용
- Timezone은 IANA ID
- 사용자에게 Local UTC Offset 문자열만 저장시키지 말 것

Runtime도 Name 255자와 caller-provided Locale validation을 강제한다.
Frontend는 동일 제약을 UX 단계에서 먼저 보여주되 Backend Validation을 신뢰 경계로 유지한다.

## Case 삭제

현재 기본 Core 계약은 Case 삭제를 제품 일반 기능으로 보장하지 않는다.

따라서:

```text
Delete Case
```

버튼을 임의로 만들지 말 것.

필요하다면 Backend/Admin 정책이 확정된 뒤 추가한다.

---

# 13. Evidence 화면

Route:

```text
EVIDENCE
```

## 지원되는 안정적 Evidence Format

현재 `evidence.schema.json` 기준:

```text
DIRECTORY
RAW
DD
IMG
E01
VHD
VHDX
```

## Evidence List 표시

필수/권장:

```text
display_name
format
status
size_bytes
read_only
reader.id
reader.version
capabilities
hashes
registered_at
acquired_at
```

Status:

```text
REGISTERED
HASHING
READY
FAILED
```

`read_only`는 현재 Schema에서 `true`가 강제된다.

UI에 Evidence를 수정하는 기능을 만들지 않는다.

## Evidence 등록 Workflow

```text
[Evidence 추가]
      ↓
Desktop File/Folder Picker
      ↓
Backend에 Source Reference 전달
      ↓
Format Probe
      ↓
Capability 확인
      ↓
Evidence 등록
      ↓
Hash / Quick Triage 선택
```

Frontend가 자체적으로 확장자만 보고 Format을 최종 확정하면 안 된다.

## Capability에 따른 표시

예:

```text
E01
e01-libewf = CAPABILITY_UNAVAILABLE
```

이면:

- “E01 지원 안 됨”을 성공적인 빈 Evidence처럼 보여주지 않는다.
- 기능을 Disabled 처리
- Capability 이유 표시
- 필요한 Dependency가 Backend/Packaging 영역이라는 점 표시

---

# 14. Hash / Integrity UI

Evidence Streaming Hash의 현재 알고리즘 Contract:

```text
SHA256
SHA1
MD5
```

**`SHA512`는 Evidence Hash 선택지가 아니다.**

Evidence Hash record의 Verification:

```text
NOT_CHECKED
MATCH
MISMATCH
```

Chain of Custody의 Runtime Hash Verification은 별도 Contract이며:

```text
MATCH
MISMATCH
ERROR
```

를 표현할 수 있다.

Current Runtime에서는 Hash Verification `case_id`가 persistence/reload 이후에도 보존된다.
Legacy compatibility record에서 `case_id`가 없을 수 있는 경우 Frontend가 추측하지 말고 Backend scope resolution을 사용한다.

Frontend 표시 예:

```text
SHA-256
[ digest ]
Status: MATCH
Bytes Hashed: ...
Completed: ...
```

`MISMATCH`는 일반 Warning보다 강한 무결성 경고로 보여야 한다.

하지만 Frontend가 “증거 조작 확정” 같은 문장을 자동 생성하면 안 된다.

표현 예:

```text
무결성 검증 결과가 이전 기준 Hash와 일치하지 않습니다.
원인 확인이 필요합니다.
```

---

# 15. Analysis Profile 화면

현재 File System Index Profile:

```text
QUICK_TRIAGE
SELECTED_SCOPE
FULL_ANALYSIS
CUSTOM
```

## QUICK_TRIAGE

사용자에게:

- 빠른 초기 File Tree
- Partial Result 가능
- 전체 분석 완료를 의미하지 않음

## SELECTED_SCOPE

- 사용자가 선택한 Node/Path 우선
- Background 분석보다 높은 우선 처리 가능

## FULL_ANALYSIS

- 전체 Metadata Index
- 완료 시 Coverage COMPLETE 기대

## CUSTOM

Backend가 허용하는 옵션만 UI로 제공:

```text
max_depth
item_budget
batch_size
selected_path
selected_node_id
include
exclude
```

Frontend가 Engine에 없는 분석 Option을 임의로 추가하지 않는다.

---

# 16. Job / Progress UI

모든 장시간 작업은 Job 개념으로 표시한다.

현재 상태:

```text
QUEUED
RUNNING
PAUSING
PAUSED
RESUMING
SUCCEEDED
PARTIAL
FAILED
CANCELLED
```

## Progress에서 표시 가능한 값

```text
processed_items
estimated_total_items
progress_percent
throughput_items_per_second
elapsed_seconds
estimated_remaining_seconds
estimate_confidence
current_analyzer
worker_count
cache_hits
cache_misses
partial_results_available
discovered_items
skipped_items
warning_count
error_count
current_path
```

## 중요한 UX 규칙

### `progress_percent = null`

0%로 표시하지 않는다.

다음처럼 표시:

```text
진행 중
총량 계산 중
```

Indeterminate Progress 사용.

### ETA

`estimated_remaining_seconds`가 없거나:

```text
estimate_confidence = UNKNOWN
```

이면 정확한 남은 시간을 만들어내지 않는다.

### PARTIAL

`PARTIAL`은 실패와 동일하지 않다.

표시:

```text
일부 결과 사용 가능
Warning 3
Failed Task 1
```

결과 화면은 열 수 있어야 한다.

---

# 17. File System Explorer

Route:

```text
FILE_SYSTEM
```

## Tree는 Lazy Loading

전체 Tree를 한 번에 받아 그리면 안 된다.

동작:

```text
Root 조회
→ Node Expand
→ 직접 Children 조회
→ Cursor 있으면 추가 페이지 조회
```

## File/Node에서 표시할 데이터

현재 Schema에서 사용 가능한 주요 필드:

```text
original_name
original_relative_path
display_path
node_type
file_size
extension
mime_candidate
mime_confidence
platform
raw_timestamps
utc_timestamps
timestamp_sources
is_deleted
is_readable
is_link
is_traversed
is_partial
index_revision
```

Node Type:

```text
ROOT
DIRECTORY
FILE
SYMLINK
REPARSE_POINT
OTHER
```

## 추천 File Table Column

```text
Name
Type
Size
Extension
MIME
Modified
Created
Deleted
Readable
Partial
```

## 삭제 File

`is_deleted=true`이면 일반 File과 시각적으로 구분한다.

단:

```text
Deleted = 완전 복구 가능
```

으로 표시하면 안 된다.

## Recovery 버튼

현재 Engine에는 삭제 File Recovery, Unallocated Range, Slack Export 기능이 존재한다.

Frontend 버튼은 Backend Adapter가 해당 Operation을 노출한 경우에만 활성화한다.

예:

```text
Recover Deleted File
Export Slack
Read Unallocated Range
Export Raw Range
```

실행 전:

- Output 위치
- 예상 크기
- Overwrite 여부
- 원본 Evidence는 변경되지 않는다는 점

확인 UI가 필요하다.

---

# 18. Artifact Explorer

Route:

```text
ARTIFACTS
```

Artifact 공통 목록은 모든 Artifact를 한 화면에서 볼 수 있게 한다.

## 공통 Artifact Type

현재 주요 Enum:

```text
REGISTRY_KEY
REGISTRY_VALUE
REGISTRY_AUTORUN
REGISTRY_USB_DEVICE
REGISTRY_TIMEZONE
REGISTRY_USERASSIST

EVENT_LOG_RECORD
PREFETCH_EXECUTION

MEDIA_IMAGE
MEDIA_VIDEO
MEDIA_AUDIO

BROWSER_PROFILE
BROWSER_VISIT
BROWSER_SEARCH
BROWSER_DOWNLOAD
BROWSER_COOKIE
BROWSER_CREDENTIAL
BROWSER_CACHE_ENTRY
BROWSER_DELETED_SQLITE_ROW
BROWSER_PRIVATE_MODE_CANDIDATE

COMMUNICATION_PROFILE
COMMUNICATION_ACCOUNT
COMMUNICATION_CONVERSATION
COMMUNICATION_MESSAGE
COMMUNICATION_ATTACHMENT
COMMUNICATION_UNSUPPORTED_STORE

UNKNOWN_WINDOWS_ARTIFACT
```

## Artifact List 공통 Column

```text
Title
Type
Subtype
Observed Time
Source
Parse Status
Confidence
Partial
Warning Count
```

Parse Status:

```text
SUCCESS
PARTIAL
UNSUPPORTED
CORRUPT
FAILED
```

`UNSUPPORTED`, `CORRUPT`, `FAILED`를 빈 결과로 숨기지 않는다.

## Artifact Detail

표시:

```text
title
summary
fields
payload
parse_status
confidence
warnings
analyzer_id
analyzer_version
parser_backend
parser_backend_version
source_path
source_kind
observed_at_raw
observed_at_utc
timezone_source
timezone_confidence
citations
provenance
raw_locator
```

Artifact별 `payload`/`fields`는 자유 구조일 수 있다.

따라서 Frontend는:

- Common Field Renderer
- Generic Key/Value Fallback

둘 다 준비한다.

---

# 19. Registry 화면

Route:

```text
REGISTRY
```

## Sub View

```text
All
Keys
Values
Autoruns
USB
Timezone
UserAssist
Deleted Candidates
Warnings
```

## Autorun

가능하면 표시:

```text
Registry Path
Value Name
Value Data
Source
Observed Time
```

## USB

가능하면 표시:

```text
Device Identifier
Registry Path
Observed / Last Write
Source Hive
```

## Timezone

Case Timezone 자동 확정에 사용하지 말고 Candidate 성격을 보여준다.

## UserAssist

ROT13 등 Parser 처리는 Engine 책임이다.

Frontend는 이미 구조화된 결과를 표시한다.

## Deleted Candidate

반드시 뱃지:

```text
RECOVERED CANDIDATE
PARTIAL
CONFIDENCE
```

사용.

확정 Live Registry Key와 동일 스타일 금지.

---

# 20. Event Log 화면

Route:

```text
EVENT_LOG
```

## 권장 Column

```text
Timestamp
Channel
Provider
Event ID
Title
Computer
User SID
Record ID
Parse Status
```

## Detail

표시 가능한 정보:

```text
Provider
Channel
Event ID
Record ID
Computer
User SID
Process ID
Thread ID
EventData
UserData
Raw XML / Raw View
Rendered Message
```

## Windows Event Message Rendering

Capability:

```text
windows-event-message-renderer
```

가 unavailable이면:

```text
Message unavailable
```

을 “Event가 없음”으로 표현하지 않는다.

Event ID만으로:

```text
악성
침해 확정
```

같은 Label을 자동으로 붙이지 않는다.

---

# 21. Prefetch 화면

Route:

```text
PREFETCH
```

현재 표시 가능한 주요 내용:

```text
Executable Name
Prefetch Hash
Format Version
File Size
Run Count
Last Run Time
Referenced Path Candidate
Parse Status
Warnings
```

지원 Version 범위 밖이면:

```text
UNSUPPORTED
```

표시.

MAM Dependency 문제도 Capability/Warning으로 보여준다.

Prefetch 결과만으로 “사용자가 직접 실행했다”라고 표현하지 않는다.

---

# 22. Browser 화면

Route:

```text
BROWSER
```

## Sub Tab

```text
Profiles
History / Visits
Searches
Downloads
Cookies
Credentials
Cache
Deleted Candidates
Private-mode Candidates
Warnings
```

현재 Runtime/CLI에서 대응되는 조회가 존재한다.

## Browser Profile

표시:

```text
Browser Type
Profile
Source
Revision
Warnings
```

## History

표시:

```text
Time
URL
Title
Profile
Source DB
```

## Search

표시:

```text
Time
Search Term
URL / Source
Profile
```

## Downloads

표시:

```text
Start / Observed Time
URL
Target Path Candidate
Profile
Status
```

## Deleted SQLite Candidate

확정 History와 분리해서:

```text
Deleted Candidate
```

Badge 필수.

## Private-mode Candidate

반드시:

```text
Candidate
```

로 표시.

“Private Browsing 사용 확정” 표현 금지.

## Credential / Cookie

Engine이 복호화 결과/Redaction 경계를 관리한다.

Frontend 규칙:

- 일반 Console Log 금지
- Error Report에 Secret 값 금지
- Analytics/Event Telemetry에 Value 금지
- 기본적으로 민감값을 평문 UI에 강제로 노출하지 않음
- 표시 정책은 Backend/제품 보안 정책과 별도 합의

---

# 23. Communications 화면

현재 별도 Route가 없으므로:

```text
ARTIFACTS > Communications
```

를 권장한다.

## Sub Tab

```text
Profiles
Accounts
Conversations
Messages
Attachments
Unsupported Stores
KakaoTalk
```

지원 Adapter 범위에는 현재:

- Email
- Discord
- Telegram
- KakaoTalk 제한 경로

가 존재한다.

## 메시지 UI

Artifact Payload가 서비스별로 달라질 수 있으므로 특정 앱 전용 Field만 가정하지 않는다.

공통:

```text
Source
Account
Conversation
Timestamp
Sender/Participant Candidate
Message Summary/Field
Attachment
Parse Status
Provenance
Citation
```

서비스별 추가 Field는 Generic Detailed View에서 보여줄 수 있게 한다.

---

# 24. KakaoTalk UI — 절대로 과장하지 말 것

현재 KakaoTalk 상태:

```text
Platform:
Windows Desktop

Verified target version:
2.0.8.990

Store:
chatLogs*.edb

Current capability:
external-key based

Automatic key acquisition:
BLOCKED_EXTERNAL_FIXTURE

Android:
unsupported

iOS:
unsupported
```

Frontend 표시 문구 예:

```text
KakaoTalk Windows Desktop 2.0.8.990
외부 Key 기반 분석 지원

자동 Key 획득은 현재 지원되지 않습니다.
실제 KakaoTalk 암호화 DB Fixture 검증은 외부 근거 확보 전까지 제한됩니다.
```

금지 문구:

```text
카카오톡 자동 복호화 지원
모든 카카오톡 버전 지원
Android KakaoTalk 지원
iOS KakaoTalk 지원
계정 비밀번호 자동 추출
```

외부 Key가 없으면 사용자에게 명확히:

```text
External key required
```

상태를 보여준다.

---

# 25. Media 화면

Route:

```text
MEDIA
```

## Sub Tab

```text
Images
Videos
Audio
Thumbnails
Frame Samples
Warnings
```

## Image

표시 가능한 항목:

```text
Type
Dimensions / Metadata
EXIF
GPS Candidate
Orientation
Camera Make
Camera Model
Timestamp
Deleted
```

## Video

```text
Container
Codec
Duration
Timestamp
Frame Sample availability
```

## Audio

```text
Codec
Duration
Timestamp
STT Capability
```

## Capability 연결

```text
pillow
ffmpeg
ffprobe
rapidocr
onnx-runtime
faster-whisper
```

각 Capability 상태에 따라 버튼을 활성/비활성한다.

예:

```text
ffmpeg = CAPABILITY_UNAVAILABLE

[Sample Frames] Disabled
Tooltip: FFmpeg runtime unavailable
```

## Reverse Geocoding

현재 Core Feature로 확정하지 않는다.

GPS는 좌표를 표시할 수 있지만 Frontend가 임의로 외부 Geocoding API를 붙이지 않는다.

---

# 26. Machine-extracted Candidate 화면

Route:

```text
CANDIDATES
```

OCR/STT 결과는 Observed Fact가 아니다.

현재 Candidate Semantic은 명시적으로:

```text
MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT
```

이다.

## Candidate Type

```text
OCR
STT
SUBTITLE
SCREEN_TEXT
OTHER
```

## Source Type

```text
IMAGE
VIDEO_FRAME
AUDIO
DOCUMENT
OTHER
```

## Review Status

```text
UNREVIEWED
ACCEPTED
REJECTED
CORRECTED
```

## 화면 표시

```text
Text
Language
Confidence
Provider
Provider Version
Model
Source
Frame Number
Media Timestamp
Audio Start/End
Region
Review Status
Citation
Raw Locator
```

## Review 동작

```text
Accept
Reject
Correct
```

`Correct`는 원 Candidate를 덮어쓰는 방식으로 UI 상태를 만들면 안 된다.

원본 Candidate + Correction Review가 같이 보이도록 한다.

---

# 27. Search 화면

Route:

```text
SEARCH
```

현재 Query Mode:

```text
TERM
PHRASE
PREFIX
EXACT
REGEX_METADATA
```

현재 Search Document Type:

```text
FILE
DIRECTORY
REGISTRY
EVENT_LOG
PREFETCH
MEDIA
BROWSER
COMMUNICATION
TIMELINE
OTHER
```

Source Type:

```text
FILE_SYSTEM_NODE
WINDOWS_ARTIFACT
TIMELINE_EVENT
```

## Search Form

입력:

```text
Query
Mode
Evidence Scope
Source Type
Document Type
Time From
Time To
Path Scope
Case Sensitive
Sort
Limit
```

현재 일반 Query Text 최대:

```text
4096 characters
```

`REGEX_METADATA`는 별도 stricter limit:

```text
512 characters
```

Frontend는 Regex 입력에서 4,096자를 허용하면 안 된다.

현재 Limit 최대:

```text
1000
```

Frontend Validation에 반영한다.

## Search Result

표시:

```text
Rank
Source Type
Matched Fields
Matched Terms
Snippet
Partial
Index Revision
Citation
```

## Search History

다음 기능 UI:

```text
History
Show Execution
Rerun
Cache Status
```

## 형태소 검색

현재 지원한다고 표시하지 않는다.

지원:

- NFC
- Casefold
- Path normalization
- 한글 완성형/자모 혼합 처리

하지만:

```text
한국어 형태소 분석 검색
```

을 지원한다고 적으면 안 된다.

---

# 28. Keyword Set UI

Search 화면 안의 Sub Panel 권장:

```text
Keyword Sets
```

상태:

```text
DRAFT
ACTIVE
ARCHIVED
```

기능:

```text
Create
List
Show
Add
Remove
Activate
Archive
Version
```

AI Keyword Candidate가 있는 경우:

```text
추천 직후 자동 Search 실행 금지
분석자 승인
→ Keyword Set 반영
→ 사용자가 Search 실행
```

순서를 유지한다.

---

# 29. Timeline 화면

Route:

```text
TIMELINE
```

## 주요 Source

```text
FILE_SYSTEM_NODE
REGISTRY_ARTIFACT
EVENT_LOG_ARTIFACT
PREFETCH_ARTIFACT
MEDIA_ARTIFACT
BROWSER_ARTIFACT
COMMUNICATION_ARTIFACT
ANALYST_ANNOTATION
```

## 주요 Event Type

예:

```text
FILE_CREATED
FILE_MODIFIED
FILE_ACCESSED
FILE_METADATA_CHANGED

REGISTRY_KEY_LAST_WRITE
REGISTRY_VALUE_OBSERVED
REGISTRY_MODIFIED

PROCESS_EXECUTION
PROCESS_CREATED
LOGON
LOGOFF
NETWORK_CONNECTION
DNS_QUERY
SERVICE_INSTALLED
EVENT_LOG_CLEARED
PREFETCH_LAST_RUN

MEDIA_CREATED
MEDIA_MODIFIED
MEDIA_CAPTURED
MEDIA_METADATA_TIMESTAMP
MEDIA_CAPTURED_CANDIDATE

BROWSER_VISIT
BROWSER_SEARCH
BROWSER_DOWNLOAD
BROWSER_COOKIE_OBSERVED
BROWSER_CREDENTIAL_OBSERVED
BROWSER_CACHE_ENTRY_OBSERVED
BROWSER_DELETED_SQLITE_ROW_CANDIDATE
BROWSER_PRIVATE_MODE_CANDIDATE

COMMUNICATION_MESSAGE
COMMUNICATION_ATTACHMENT
```

## Timeline Table

권장 Column:

```text
Displayed Time
Event Type
Title
Source
Evidence
Confidence
Partial
```

## Detail

반드시 원본 시간과 표시 시간을 구분할 수 있어야 한다.

```text
raw_timestamp
raw_timezone
timestamp_semantics
normalized_utc
case_timezone
displayed_case_time
timezone_source
timezone_confidence
precision
```

Naive Timestamp의 `normalized_utc`가 `null`일 수 있다.

Frontend가 임의로 UTC 변환해서 값을 만들어내면 안 된다.

---

# 30. Timezone 확인 UI

Case 상단 또는 Timeline Settings에 제공.

기본:

```text
Asia/Seoul
```

## Candidate

표시:

```text
Timezone
Source
Confidence
Citation
```

Confidence:

```text
CONFIRMED
HIGH
MEDIUM
LOW
UNKNOWN
```

`LOW`, `UNKNOWN` Candidate는 자동 선택하지 않는다.

사용자가 직접 확인하게 한다.

DST Ambiguous / Nonexistent 상태도 Warning으로 표시한다.

---

# 31. Partial / Stale UI는 반드시 공통 Component로 만들 것

모든 결과에서 다음을 구분한다.

## COMPLETE

```text
현재 Scope 결과 완료
```

## PARTIAL

```text
현재 확인된 일부 결과입니다.
분석이 계속 진행 중이거나 일부 Task가 실패했습니다.
```

## STALE

```text
이 결과 생성 후 Source Revision이 변경되었습니다.
재분석 또는 Refresh가 필요할 수 있습니다.
```

## UNAVAILABLE

```text
현재 Runtime에 필요한 Capability가 없습니다.
```

## UNSUPPORTED

```text
형식/버전은 판별했지만 지원하지 않습니다.
```

## FAILED

```text
분석 실패
```

## EMPTY

```text
정상적으로 조회했지만 결과 0건
```

이 6~7가지를 하나로 합치면 안 된다.

특히:

```text
CAPABILITY_UNAVAILABLE
```

을:

```text
0 results
```

로 보여주면 안 된다.

---

# 32. Annotation / Tag UI — 현재는 Product Placeholder

`ANALYST_ANNOTATION`은 Fact/Inference와 구분되는 semantic category로 사용할 수 있다.

하지만 현재 Core에는 전용 Annotation/Tag CRUD persistence가 확정 구현되어 있지 않다.

현재 Frontend에서 하면 안 되는 것:

```text
POST /annotations가 존재한다고 가정
Tag 저장 Table이 존재한다고 가정
Report/Context가 저장된 Tag를 현재 바로 Resolve한다고 가정
```

초기 UI 권장:

```text
Annotation / Tag
[ Backend contract required ]
```

또는 해당 기능을 숨긴다.

Backend가 추후 실제 contract를 제공하면 다음 UX를 추가할 수 있다.

- File/Artifact/Timeline/Search Result에 Analyst memo
- Tag name/color/description
- Report selection과 연결
- Context snapshot에 analyst-authored metadata 포함

그때도 Annotation은 Engine Observed Fact가 아니다.

---

# 33. Chain of Custody 화면

Route:

```text
CHAIN_OF_CUSTODY
```

Event Type:

```text
ACQUISITION
RECEIVED
TRANSFERRED
STORED
OPENED
MOUNTED
ANALYZED
HASH_VERIFIED
COPIED
EXPORTED
RETURNED
RELEASED
ARCHIVED
DISPOSED
CORRECTION
```

## 중요한 규칙

기존 Event 수정/삭제 UI를 만들지 않는다.

잘못 입력된 Event는:

```text
CORRECTION
```

Event를 새로 추가한다.

## 화면

```text
Sequence
Event Type
Timestamp
Actor
Action
Reason
Previous Hash
Event Hash
Correction Target
Verification
```

Hash Chain 불일치가 있으면 숨기지 않는다.

`MISMATCH`가 있다고 법적 결론을 자동 생성하지 않는다.

---

# 34. Report 화면

Route:

```text
REPORT
```

## Report Record Status

현재 최신 분리 Schema 기준:

```text
DRAFT
REVIEW_REQUIRED
APPROVED
REJECTED
EXPORT_PREPARING
EXPORT_READY
EXPORTED
EXPORT_FAILED
ARCHIVED
```

## Report Type

```text
INVESTIGATION
TRIAGE
INCIDENT_RESPONSE
EVIDENCE_SUMMARY
CHAIN_OF_CUSTODY
TECHNICAL_APPENDIX
OTHER
```

## Version

각 Report는 Immutable Version을 가진다.

표시:

```text
Version Number
Source Kind
Created By
Created At
Content Fingerprint
Previous Version
Review State
Approval State
Partial State
Stale State
Limitations
```

Source Kind:

```text
ANALYST_DRAFT
AI_DRAFT
IMPORTED_DRAFT
SYSTEM_ASSEMBLED_DATA
OTHER
```

## Report Screen 구조 권장

```text
Report List
    ↓
Report Detail
├── Versions
├── Sections
├── Citations
├── Review
├── Approval
├── Custody Snapshot
└── Export
```

---

# 35. Report Review Workflow

Frontend는 아래 Workflow를 강제해야 한다.

```text
Draft Version
    ↓
Submit Review
    ↓
Section Review
    ├── Accept
    └── Request Changes
    ↓
Complete Review
    ↓
Approve / Reject
    ↓
Export
```

## 승인 전 Export

버튼 Disabled.

Runtime에서도 차단되지만 UI에서도 미리 막는다.

## 새 Version 생성

기존 승인 상태를 그대로 복사해서:

```text
Approved
```

로 표시하면 안 된다.

새 Version은 다시 Review/Approval 필요.

## Revision Conflict

Report Review에도 Optimistic Revision 충돌이 존재한다.

예:

```text
REPORT_REVIEW_REVISION_CONFLICT
```

발생 시:

- 현재 Version 상태 Reload
- 사용자가 작성 중이던 Comment 보존
- 최신 Review 상태 표시
- 재적용 여부 선택

---

# 36. Report Section Editor

각 Section에는:

```text
section_type
title
content
source kind
review status
citations
```

을 보여준다.

## AI Draft Section

다른 스타일로 표시:

```text
AI DRAFT
Human review required
```

## Analyst Section

```text
ANALYST
```

## Observed Fact / AI 구분

Report 내 문장 분류를 지원하는 경우:

```text
OBSERVED_FACT
ANALYST_ANNOTATION
MACHINE_EXTRACTED_CANDIDATE
AI_INFERENCE
AI_RECOMMENDATION
```

을 스타일로 구분한다.

AI Inference를 Fact처럼 같은 색/Badge로 표시하지 않는다.

---

# 37. Report Export UI

Format:

```text
PDF
HTML
```

## Export 전 확인

- Report Version
- Approval 상태
- Filename
- Format
- Citation 포함 여부
- Custody 포함 여부
- Technical Appendix 포함 여부
- Stale 결과 확인 여부

## Renderer Capability

Runtime Capability:

```text
html-renderer
pdf-renderer
```

예:

```text
HTML: AVAILABLE
PDF: CAPABILITY_UNAVAILABLE
```

이면 PDF 버튼 Disabled.

## Export 결과

표시:

```text
Status
Filename
MIME
Size
SHA-256
Renderer
Renderer Version
Warnings
```

---

# 38. AI Assistant UI

Frontend가 구현해야 할 것은 **AI UI와 Context 연결부**다.

Frontend가 구현하지 않는 것:

```text
LLM 연결
Prompt
Agent
MCP Server
API Key
Model 선택 로직
```

## 권장 UI

```text
Assistant Drawer
```

Assistant에 전달할 수 있는 현재 Context:

- Current Case
- Current Evidence
- Selected File
- Selected Artifact
- Selected Timeline Event
- Selected Search Result
- Filter
- Time Range
- Current Scope

현재 Core에 전용 Annotation/Tag persistence contract가 없으므로, 저장된 Tag/Annotation을 AI Context의 필수 입력으로 가정하지 않는다.

AI 결과에는 반드시:

```text
Observed Facts
Inference
Recommendation
Citation
Confidence
Limitations
```

구분이 가능해야 한다.

## Adapter 미연결

`ai-provider-openai-compatible`이:

```text
EXTERNAL_CONFIGURATION_REQUIRED
```

이면:

```text
AI 연결 필요
```

상태로 표시한다.

빈 답변/무응답처럼 보이면 안 된다.

---

# 39. Settings / Capability 화면

Route:

```text
SETTINGS
```

Runtime Doctor의 Capability 상태를 그대로 사용자에게 표시할 수 있는 화면이 필요하다.

현재 상태 종류:

```text
AVAILABLE
AVAILABLE_WITH_LIMITATIONS
CAPABILITY_UNAVAILABLE
EXTERNAL_CONFIGURATION_REQUIRED
UNSUPPORTED_PLATFORM
BLOCKED_EXTERNAL_FIXTURE
HOST_VERIFICATION_REQUIRED
```

## 현재 주요 Capability ID

```text
python
sqlite
sqlite-fts5

raw-dd-img
pytsk3
e01-libewf
vhd-libvhdi
vhdx-qemu-img
filesystem-provider

registry-parser
registry-binary-parser
registry-deleted-cell-carving

event-log-parser
event-log-binary-parser
windows-event-message-renderer

prefetch-parser
prefetch-mam

pillow
browser-cryptography
ffmpeg
ffprobe

rapidocr
onnx-runtime
faster-whisper

firefox-nss
dpapi-impacket

html-renderer
pdf-renderer

ai-provider-openai-compatible

kakaotalk-existing
```

## Capability UI

표시:

```text
Capability Name
Status
Version
Reason
Probe
Details
```

주의:

Runtime Doctor는 Secret/Environment Value를 노출하지 않도록 설계되어 있다.

Frontend도 Environment Value를 추가로 수집해서 표시하지 않는다.

---

# 40. KakaoTalk Capability 표시

`kakaotalk-existing`의 의미:

```text
AVAILABLE_WITH_LIMITATIONS
```

이어도 자동 Key 획득까지 된다는 뜻이 아니다.

세부 상태:

```text
external_key_only = true
automatic_key_acquisition_status = BLOCKED_EXTERNAL_FIXTURE
android_supported = false
ios_supported = false
```

Frontend는 Details까지 읽어야 한다.

Status Badge 하나만 보고 “사용 가능”으로 단순 표시하면 안 된다.

---

# 41. 오류 처리 규칙

Frontend는 HTTP 숫자보다 Engine `code`를 우선 처리해야 한다.

## 사용자 메시지

Engine:

```json
{
  "code": "CAPABILITY_UNAVAILABLE",
  "message_key": "error.evidence.capability_unavailable",
  "developer_message": "...",
  "retryable": false
}
```

Frontend:

```text
message_key → 한국어 Resource
```

사용.

`developer_message`는 개발/진단용이다.

사용자에게 그대로 출력하는 것을 기본으로 하지 않는다.

---

# 42. 반드시 별도 처리할 오류

## CAPABILITY_UNAVAILABLE

```text
필요 기능이 현재 Runtime에서 사용할 수 없음
```

버튼 Disabled / 설치·설정 상태 안내.

## CONTEXT_REVISION_CONFLICT

Context Reload 후 재시도.

## CONTEXT_EXPIRED

새 Session Context 생성.

## STATE_CONFLICT

현재 Resource/Job 상태 Reload.

## PROFILE_REVISION_CONFLICT

Resume 불가 안내 + 새 분석 선택.

## REPORT_NOT_APPROVED

Export 차단.

## KEYWORD_NOT_APPROVED

Keyword 실행 차단.

## CUSTODY_CHAIN_CONFLICT

Ledger 변경 중단 + Reload.

## RESOURCE_LIMIT_EXCEEDED

사용자 입력 범위 축소.

## RAW_RANGE_NOT_SATISFIABLE / RAW_READ_LIMIT_EXCEEDED

Raw Offset/Length 수정.

## TIMEZONE_AMBIGUOUS

분석자 확인 요구.

## WORK_QUEUE_FULL

재시도 가능 상태로 안내.

## SERVICE_NOT_READY

Backend/Engine Ready 상태 재확인.

---

# 43. 한국어 Localization

Frontend가 한국어 Resource 파일을 소유한다.

기본:

```text
Locale: ko-KR
Timezone: Asia/Seoul
Encoding: UTF-8
```

## 금지

Engine `message_key`를 화면에 그대로:

```text
error.evidence.capability_unavailable
```

표시.

## 권장

```text
error.evidence.capability_unavailable
→ 현재 환경에서 이 증거 형식 분석 기능을 사용할 수 없습니다.
```

Fallback:

```text
정의되지 않은 Resource Key
→ "처리 중 오류가 발생했습니다. 오류 코드: {code}"
```

개발자 메시지는 상세 로그 패널에서 권한 있는 개발 모드에만 제한적으로 보여주는 것을 권장한다.

---

# 44. 한글/Unicode 검증

Frontend는 반드시 다음 Test Fixture를 준비한다.

```text
한글.txt
ㅎㅏㄴㄱㅡㄹ.txt
한글-english-123.txt
공백 포함 경로
긴 경로
Emoji 포함 표시명
```

중요:

- 원본 Path를 임의 NFKC 변환해 저장하지 않음
- Engine이 제공한 `display_path`와 원본 경로 Field를 구분
- Search용 정규화 문자열을 원본 File Name처럼 표시하지 않음

---

# 45. Cursor Pagination

APEX는 목록을 Page Number 방식으로 고정하지 않는다.

현재 공통 Page:

```text
next_cursor
has_more
returned
```

Frontend는:

```text
?page=2
```

를 자체 계산해서 Engine 상태와 분리하지 않는다.

## Table 구현

```text
initial query
→ items
→ page.next_cursor
→ Load more / Virtualized next fetch
```

Filter/Sort가 바뀌면 기존 Cursor 폐기.

---

# 46. Empty / Error / Unavailable UI State 표준화

공통 Component를 만들 것을 강력 권장한다.

예:

```text
<ResultState>
```

State:

```text
LOADING
READY
EMPTY
PARTIAL
STALE
UNAVAILABLE
UNSUPPORTED
FAILED
CANCELLED
```

각 화면이 제각각 오류 UI를 만들지 않는다.

---

# 47. Loading Skeleton과 Progressive Result

APEX는 Progressive Indexing이 핵심이므로:

```text
분석 완료 전까지 화면 전체 잠금
```

방식은 제품 철학과 맞지 않는다.

예:

```text
Quick Triage 진행 중 37%
File 12,340개 확인됨
현재 결과는 Partial
```

상태에서 File Tree를 이미 보여줄 수 있어야 한다.

Partial Badge를 유지한다.

---

# 48. Citation UI

다음 화면 모두 Citation을 표시할 수 있어야 한다.

- Artifact
- Timeline
- Search Result
- Candidate
- AI Result
- Report

권장 Interaction:

```text
Citation 클릭
→ Source Resource Highlight
→ Detailed/Raw Inspector 이동
```

Citation이 없는데 AI가 Fact를 주장하는 경우 UI가 이를 정상 Fact로 보이면 안 된다.

---

# 49. Provenance UI

Artifact Detail의 고급 탭에서:

```text
Evidence
Source Object
Source Path
Source Offset
Source Length
Analyzer Run
Analyzer ID
Analyzer Version
Raw Locator
```

를 볼 수 있게 한다.

“왜 이 결과가 나왔는지” 추적 가능해야 한다.

---

# 50. Confidence 표시

Confidence가 숫자 또는 Enum으로 존재할 수 있다.

권장:

```text
0.00 ~ 1.00
```

숫자 그대로도 상세에서 보여주고, Simple View에서는:

```text
High / Medium / Low
```

등의 UX로 표시 가능.

단, Frontend가 임의 Threshold를 정한다면 그 기준을 제품 정책으로 명시해야 한다.

Engine 값 자체를 변경하지 않는다.

---

# 51. Secrets / 민감정보 UI 정책

현재 Core의 public Secret/Decryption serialization은 **plaintext secret을 반환하지 않는 방향으로 고정**되어 있다.

Frontend는 다음 값을 Console/Telemetry/State persistence에 기록하지 않는다.

- Password
- Cookie Secret
- AES/DB Key
- IV
- DPAPI Derived Secret
- NSS Decrypted Secret
- KakaoTalk Key
- KPRAGMA
- User/Server Nonce
- NT Hash
- Master Key
- API Key
- Plaintext payload

현재 DTO에서 sensitive field는 `<redacted>`로 내려올 수 있다.

Frontend는 `<redacted>`를:

```text
실제 값
```

처럼 취급하거나 복원하려고 하면 안 된다.

반대로 다음과 같은 **비밀 원문이 아닌 fingerprint/provenance hash**는 표시 가능하다.

```text
content_sha256
pragma_key_hash
user_nonce_hash
fingerprint
```

이 값은 “Key” 자체가 아니라 Hash/Fingerprint라는 라벨을 반드시 붙인다.

특히:

```js
console.log(response)
```

로 전체 Backend Response를 Production console/telemetry에 남기지 않는다.

현재 Core public contract에는 일반적인 “Show password”, “Show DB key” 기능이 없다.
해당 제품 기능이 필요하면 별도 privileged Backend/authorization contract가 필요하다.

---

# 52. Frontend가 직접 Evidence Path를 다루지 않는 원칙

API 설계상 Host Absolute Path는 권한 없는 Client에 그대로 노출하지 않는 것이 원칙이다.

Desktop App이라 하더라도:

```text
사용자가 선택한 Evidence 경로
```

와:

```text
Engine 내부 Source Reference
```

를 분리할 수 있도록 설계한다.

Frontend가 Raw `C:\...` Path를 전역 상태/로그에 무조건 저장하지 않는다.

---

# 53. Backend와 먼저 합의해야 할 Transport

Frontend 개발 시작 전에 Backend 담당과 다음 한 가지는 확정해야 한다.

```text
Frontend ↔ Backend Transport
```

후보:

- HTTP localhost
- IPC
- Desktop native bridge
- 기타 내부 transport

이 문서에서는 특정 Transport를 확정하지 않는다.

이유:

현재 Core Repository의 `/api/v1`은 설계 계약이며 완성된 Web Server가 있다는 근거로 사용하면 안 된다.

---

# 54. Backend와 합의해야 하는 최소 DTO

Frontend가 먼저 요구해야 할 Backend DTO/Operation:

```text
Case
Evidence
Job
FileTreePage
FileNode
Artifact
TimelinePage
SearchExecution
SearchResultPage

GuiSessionContext
ViewProjection
RawView

RuntimeCapabilityReport

MachineCandidate
CandidateReview

CustodyEvent
HashVerification
CustodyVerification

ReportRecord
ReportVersion
ReportReview
ReportApproval
ReportExport
```

Backend가 아직 Transport 구현 전이라면 Mock Adapter로 화면을 먼저 작성한다.

---

# 55. Mock Data 규칙

Mock JSON을 임의로 만들지 않는다.

반드시 `schemas/v1`을 통과하는 Fixture를 사용한다.

Mock에서도 아래 상태를 전부 만든다.

```text
Success
Empty
Partial
Stale
Capability Unavailable
Unsupported
Corrupt
Failed
Cancelled
Revision Conflict
```

Happy Path만 Mock하면 실제 통합 시 화면을 다시 만들어야 한다.

---

# 56. Frontend 테스트 시나리오 — 필수

## FT-001 Case 생성

```text
ko-KR
Asia/Seoul
OPEN
```

정상 표시.

## FT-002 한글 Evidence

```text
C:\증거\사용자 PC\한글 파일...
```

표시 손실 없음.

## FT-003 E01 Capability 없음

`e01-libewf = CAPABILITY_UNAVAILABLE`

결과:

- Import 실패를 Empty Evidence로 보이지 않음
- Capability 안내 표시

## FT-004 Quick Triage Partial

Job 실행 중 File Tree 결과 도착.

결과:

- File Tree 사용 가능
- Partial Badge
- Progress 계속 표시

## FT-005 Progress Percent Unknown

`progress_percent = null`

결과:

- 0% 표시 금지
- Indeterminate Progress

## FT-006 Context Revision Conflict

오래된 Revision으로 Selection Update.

결과:

- 최신 Context Reload
- 사용자 선택값 유실 방지
- Silent overwrite 금지

## FT-007 Raw View

1 MiB 초과 요청.

결과:

- Frontend Validation으로 차단
- 또는 Backend Error를 명확히 표시

## FT-008 Deleted File

`is_deleted=true`

결과:

- 삭제 항목 스타일
- “완전 복구됨” 표현 금지

## FT-009 Corrupt Artifact

`parse_status=CORRUPT`

결과:

- Artifact 행 유지
- Warning/Corrupt 표시
- 결과를 삭제하지 않음

## FT-010 Event Message Unavailable

`windows-event-message-renderer=CAPABILITY_UNAVAILABLE`

결과:

- Event는 표시
- Rendered Message만 unavailable

## FT-011 Browser Deleted Candidate

결과:

- 정상 History와 구분
- Candidate Badge

## FT-012 KakaoTalk

`kakaotalk-existing=AVAILABLE_WITH_LIMITATIONS`

Details:

```text
external_key_only=true
automatic_key_acquisition_status=BLOCKED_EXTERNAL_FIXTURE
```

결과:

- 자동 복호화 지원 문구 없음
- External Key Required 표시

## FT-013 Search Zero Result

정상 Query 결과 0건.

결과:

```text
검색 결과 없음
```

`CAPABILITY_UNAVAILABLE`과 다르게 표시.

## FT-014 Search Regex

긴/제한 위반 Regex.

결과:

- Validation/Resource Error
- 앱 Crash 없음

## FT-015 Timeline Timezone Unknown

`normalized_utc=null`

결과:

- UTC 값을 Frontend가 임의 생성하지 않음

## FT-016 Machine Candidate

`review_status=UNREVIEWED`

결과:

- Observed Fact 스타일 사용 금지

## FT-017 Candidate Correct

결과:

- 원문 유지
- Correction 별도 표시

## FT-018 Custody Correction

기존 Event 오류.

결과:

- Edit/Delete 버튼 없음
- CORRECTION Event 작성

## FT-019 Report 승인 전 Export

결과:

- Export Disabled

## FT-020 Report 새 Version

승인된 v1 이후 v2 생성.

결과:

- v2는 다시 Review Required
- 승인 자동 승계 금지

## FT-021 PDF Renderer 없음

`pdf-renderer=CAPABILITY_UNAVAILABLE`

결과:

- PDF Export Disabled
- HTML Capability가 있으면 HTML은 독립적으로 사용 가능

## FT-022 AI Adapter 없음

결과:

- AI Assistant “연결 필요”
- 일반 Engine 기능 정상 사용

## FT-023 PARTIAL Job 종료

결과:

- 결과 조회 가능
- Failed로만 표시하지 않음
- Warning 노출

## FT-024 Service Not Ready

결과:

- Retry UI
- Case 데이터가 삭제된 것처럼 보이지 않음

## FT-025 Case Name / Locale Boundary

입력:

```text
Name 255자 → 허용
Name 256자 → 차단
Valid Locale → 허용
Malformed Locale → 차단
```

결과:

- Frontend Validation과 Backend Validation 의미가 일치
- 한글 Case Name 손실 없음

## FT-026 Search Query Boundary

```text
TERM 4096자 → 허용
TERM 4097자 → 차단
REGEX_METADATA 512자 → 허용
REGEX_METADATA 513자 → 차단
```

결과:

- Regex에 generic 4096 limit을 잘못 적용하지 않음

## FT-027 Secret Redaction

Backend Mock/실제 DTO:

```text
pragma_key="<redacted>"
user_nonce="<redacted>"
pragma_key_hash=<64 hex>
user_nonce_hash=<64 hex>
```

결과:

- raw secret 표시/로그 없음
- Hash는 `Fingerprint`로만 표시
- `<redacted>`를 reveal 가능한 값으로 취급하지 않음

## FT-028 Runtime Capability Report

`runtime-capability-report.schema.json` fixture 사용.

결과:

- 7개 capability status를 모두 구분
- `CAPABILITY_UNAVAILABLE`을 false/0 results로 축약하지 않음
- `HOST_VERIFICATION_REQUIRED`와 `BLOCKED_EXTERNAL_FIXTURE` 구분

## FT-029 Hash Verification Case Scope

Current Runtime record:

```text
case_id
evidence_id
status
```

결과:

- Current `case_id`를 표시/사용
- Legacy `case_id` 누락 record는 Backend resolve 없이 추측하지 않음

## FT-030 Annotation / Tag Placeholder

Backend가 Annotation/Tag contract를 제공하지 않는 상태.

결과:

- 저장 성공 UI를 보여주지 않음
- Disabled/Hidden/Backend contract required 처리

---

# 57. Frontend 구현 순서

## Frontend Phase F0 — Contract Foundation

먼저 해야 한다.

- [ ] Frontend 프로젝트 기본 구조
- [ ] `schemas/v1` 기반 Type 생성/동기화 방법 결정
- [ ] `ApexGateway` 추상화
- [ ] Mock Gateway
- [ ] Error Code Mapper
- [ ] Korean Resource Bundle
- [ ] Cursor Pagination 공통 Utility
- [ ] Capability Gate Component
- [ ] Partial/Stale/Warning Component
- [ ] Loading/Empty/Error State Component

F0가 끝나기 전에 각 화면에서 직접 API 호출부터 작성하지 말 것.

---

## Frontend Phase F1 — Case / Evidence / Job

- [ ] Case List
- [ ] Case Create
- [ ] Case Detail/Overview
- [ ] Case Status 표시
- [ ] Evidence Add
- [ ] Evidence List
- [ ] Evidence Detail
- [ ] Reader/Capability 표시
- [ ] Hash 표시
- [ ] Integrity Verification
- [ ] Analysis Profile 선택
- [ ] Job Progress
- [ ] Cancel
- [ ] Resume가 지원되는 Operation에서 Resume
- [ ] Partial Result 배너
- [ ] Warning/Error Drill-down

이 단계 완료 후 사용자는:

```text
Case 생성
→ Evidence 등록
→ 분석 시작
→ 진행률 확인
```

까지 가능해야 한다.

---

## Frontend Phase F2 — File System / Raw Inspector

- [ ] Lazy File Tree
- [ ] Cursor Pagination
- [ ] File Table
- [ ] Deleted 표시
- [ ] MIME/Extension Filter
- [ ] Selected Scope 우선 요청 UI
- [ ] Simple View
- [ ] Detailed View
- [ ] Raw View
- [ ] Hex/Text Viewer
- [ ] Citation
- [ ] Raw Locator
- [ ] Recovery Action UI
- [ ] Slack/Unallocated Export UI는 Backend Operation 노출 후 활성화

---

## Frontend Phase F3 — Artifact / Browser / Media / Communications

- [ ] Artifact All View
- [ ] Registry
- [ ] Event Log
- [ ] Prefetch
- [ ] Browser
- [ ] Media
- [ ] Communications
- [ ] KakaoTalk 제한 상태 UI
- [ ] Warning/Parse Status
- [ ] Provenance
- [ ] Artifact Simple/Detailed/Raw 연결

---

## Frontend Phase F4 — Search / Timeline / Candidates

- [ ] Search Form
- [ ] Search Modes
- [ ] Search Filters
- [ ] Search Result
- [ ] Search History/Rerun
- [ ] Keyword Set
- [ ] Timeline
- [ ] Timezone 표시
- [ ] Candidate Review
- [ ] Candidate Correct
- [ ] Partial/Stale 통합
- [ ] Context Selection 동기화

---

## Frontend Phase F5 — Custody / Report

- [ ] Custody Ledger
- [ ] Custody Add Event
- [ ] Correction Event
- [ ] Chain Verify UI
- [ ] Report List
- [ ] Report Create
- [ ] Report Version List
- [ ] Version Compare
- [ ] Section Editor
- [ ] Review
- [ ] Request Changes
- [ ] Section Accept/Reject
- [ ] Approval
- [ ] Revoke Approval
- [ ] Custody Snapshot
- [ ] Export
- [ ] Renderer Capability
- [ ] Export Status/Hash

---

## Frontend Phase F6 — Settings / AI Shell / Integration Polish

- [ ] Capability Matrix
- [ ] Engine Version
- [ ] Optional Dependency 상태
- [ ] AI Assistant Drawer
- [ ] AI Unavailable 상태
- [ ] GUI Context Snapshot 연결
- [ ] Keyboard/Selection UX
- [ ] 대용량 Table Virtualization
- [ ] Frontend Contract Test
- [ ] 통합 E2E

---

# 58. 우선순위

## P0 — 반드시 먼저

```text
Gateway / Contract
Case
Evidence
Jobs
File System
Artifact
Search
Timeline
Context
Inspector
Error/Capability
```

## P1 — 제품 분석 Workflow 완성

```text
Browser
Media
Communications
Candidates
Timezone
Custody
Report
```

## P2 — 통합/고급 UX

```text
AI Assistant UI
Advanced Settings
Performance UX
Virtualization
Polish
```

---

# 59. Frontend Definition of Done

한 화면이 “완료”됐다고 하려면 다음을 모두 만족해야 한다.

- [ ] Loading 상태 있음
- [ ] Empty 상태 있음
- [ ] Error 상태 있음
- [ ] Capability Unavailable 상태 있음
- [ ] Partial 상태 있음
- [ ] Stale 상태 처리 가능
- [ ] Warning 표시 가능
- [ ] Cursor Pagination 적용
- [ ] 한글/Unicode 정상
- [ ] Resource Key 기반 오류 표시
- [ ] `developer_message`를 사용자 문구로 직접 사용하지 않음
- [ ] 선택 Resource가 GUI Session Context와 동기화됨
- [ ] Citation 표시 가능
- [ ] Detailed View 이동 가능
- [ ] Raw 지원 Resource는 Raw View 이동 가능
- [ ] Cross-case Resource를 Frontend가 임의 합성하지 않음
- [ ] Secret 값 Console Logging 없음
- [ ] Mock과 실제 Contract가 같은 Schema 사용
- [ ] 실패를 0건 결과처럼 표시하지 않음

---

# 60. Frontend에서 절대 하드코딩하지 말아야 할 것

```text
"이 기능은 무조건 설치되어 있다"
"PDF는 항상 된다"
"E01은 항상 된다"
"VHDX는 항상 된다"
"OCR은 항상 된다"
"STT는 항상 된다"
"Windows Event Message는 항상 렌더링된다"
"KakaoTalk은 자동 복호화된다"
"AI는 항상 연결되어 있다"
```

전부 Runtime Capability 기반으로 판단한다.

---

# 61. Frontend에서 사용자에게 절대 과장하면 안 되는 문구

금지 예:

```text
APEX가 X-Ways보다 빠릅니다.
APEX가 Autopsy보다 빠릅니다.
삭제 파일을 완벽 복구했습니다.
Private Mode 사용이 확정되었습니다.
Prefetch가 있으므로 사용자가 직접 실행했습니다.
Event ID만으로 공격이 확정되었습니다.
OCR 결과가 증거 사실입니다.
AI 분석 결과가 침해 사실입니다.
카카오톡 자동 복호화를 지원합니다.
Chain of Custody 기능이 법적 증거능력을 보장합니다.
```

Frontend는 Engine이 제공하는 Fact/Status/Confidence/Warning을 있는 그대로 표시한다.

---

# 62. Backend 담당에게 Frontend가 요청해야 할 목록

Frontend 담당자는 Backend 담당에게 아래를 요구하면 된다.

## Transport

- [ ] 실제 Desktop Transport 확정
- [ ] Gateway 연결 방식
- [ ] Session 생성 방식
- [ ] Actor Identity 전달 방식

## Operations

- [ ] Case operations
- [ ] Evidence operations
- [ ] Analysis Job operations
- [ ] File Tree query
- [ ] Artifact query
- [ ] Browser/Media/Communication query
- [ ] Search/Timeline
- [ ] Context create/get/update/select
- [ ] View simple/detailed/raw
- [ ] Raw read
- [ ] Candidate review
- [ ] Custody operations
- [ ] Report operations
- [ ] Capability report

## File Picker

- [ ] Desktop File/Folder Picker 결과를 Backend가 어떤 Token/Path Reference로 받는지

## Output

- [ ] Recovery/Export Output Directory를 어떤 방식으로 선택할지
- [ ] Download/derived output reference를 Frontend가 어떻게 열지

---

# 63. 현재 Backend/Engine과 반드시 합의해야 할 미결정점

이 부분은 Frontend가 임의 결정하면 안 된다.

## 63.1 Transport

```text
HTTP / IPC / Desktop Bridge
```

## 63.2 Actor Identity

Context/Report/Custody에서 필요한 실제 사용자 Identity를 Frontend가 임의 문자열로 만들지 않는다.

## 63.3 Communications Route

현재 Engine Route Enum에 별도 `COMMUNICATIONS`가 없음.

초기에는 ARTIFACTS Sub Tab 권장.

## 63.4 Logical File Evidence

README 표현과 안정적 Evidence Format Enum 사이 차이가 있음.

## 63.5 Generic Pause

모든 Job에 Pause를 제공할지 Operation별로 제공할지 Backend와 확정.

## 63.6 Raw View 권한

Role/RBAC는 Backend 통합 책임.

Frontend는 Backend가 허용한 경우에만 Raw Action을 노출.

## 63.7 Secret Plaintext Reveal

현재 Core public serialization은 plaintext Password/Key/Nonce를 내보내지 않는다.

따라서 Frontend가 plaintext reveal 기능을 임의 구현하지 않는다.

제품에서 반드시 필요하면:

```text
Privileged Backend Operation
+ RBAC
+ Audit
+ explicit reveal lifecycle
```

를 별도 계약으로 설계해야 한다.

## 63.8 AI Assistant Transport

Frontend는 MCP/AI 직접 구현하지 않고 Backend/MCP Adapter가 제공하는 인터페이스를 기다린다.

## 63.9 Annotation / Tag Persistence

현재 Core에 전용 Annotation/Tag 저장 Service/Table/API가 없다.

Frontend가 이 기능을 활성화하기 전에 Backend와 CRUD/Persistence/Report linkage contract를 확정한다.

## 63.10 Hash Verification Legacy Compatibility

Current Runtime은 `case_id`를 보존하지만 `runtimeHashVerification` Schema는 legacy case-less record를 아직 허용할 수 있다.

Frontend는 legacy missing `case_id`를 직접 추론하지 않고 Backend resolve 결과를 사용한다.

---

# 64. 추천 Frontend 디렉터리 구조

현재 Frontend 기술 Stack이 저장소 Contract에서 강제되어 있지 않으므로 아래는 예시다.

```text
frontend/
├── src/
│   ├── app/
│   ├── routes/
│   ├── features/
│   │   ├── cases/
│   │   ├── evidence/
│   │   ├── jobs/
│   │   ├── filesystem/
│   │   ├── artifacts/
│   │   ├── registry/
│   │   ├── eventlog/
│   │   ├── prefetch/
│   │   ├── browser/
│   │   ├── communications/
│   │   ├── media/
│   │   ├── search/
│   │   ├── timeline/
│   │   ├── candidates/
│   │   ├── custody/
│   │   ├── reports/
│   │   └── settings/
│   ├── components/
│   │   ├── inspector/
│   │   ├── result-state/
│   │   ├── capability/
│   │   ├── citation/
│   │   ├── progress/
│   │   └── tables/
│   ├── contracts/
│   │   ├── generated/
│   │   └── adapters/
│   ├── gateway/
│   │   ├── ApexGateway
│   │   ├── MockGateway
│   │   └── BackendGateway
│   ├── context/
│   ├── localization/
│   │   └── ko-KR/
│   └── utils/
└── tests/
```

이 구조는 권장안이며 현재 Core Repository가 특정 Frontend Framework를 강제한다는 의미는 아니다.

---

# 65. Frontend 담당자에게 바로 전달할 작업 지시 요약

아래를 그대로 전달해도 된다.

## 1단계

먼저 UI부터 마구 만들지 말고:

```text
schemas/v1
→ Frontend Type
→ Gateway
→ Mock
→ 공통 Error/Capability/Partial UI
```

부터 만든다.

## 2단계

```text
Case
Evidence
Job
File System
```

을 연결한다.

## 3단계

```text
Artifact
Registry
Event Log
Prefetch
Browser
Media
Communications
```

을 연결한다.

## 4단계

```text
Search
Timeline
Candidates
Simple/Detailed/Raw
GUI Session Context
```

을 연결한다.

## 5단계

```text
Chain of Custody
Report Review/Approval/Export
```

을 연결한다.

## 6단계

```text
Settings/Capabilities
AI Assistant UI Shell
통합 테스트
```

을 진행한다.

---

# 66. 완료 기준

Frontend가 최종적으로 보여줘야 하는 사용자 Workflow:

```text
APEX 실행
    ↓
Case 생성/선택
    ↓
Evidence 등록
    ↓
Capability 확인
    ↓
Quick Triage / Full Analysis 실행
    ↓
Partial File Tree 확인
    ↓
File / Artifact 분석
    ↓
Registry / Event Log / Prefetch / Browser / Media / Communication 조회
    ↓
Search
    ↓
Timeline
    ↓
Simple / Detailed / Raw 검증
    ↓
Candidate Review
    ↓
Chain of Custody 확인
    ↓
Report 작성
    ↓
Human Review
    ↓
Approval
    ↓
PDF / HTML Export
```

AI가 연결된 환경이면 같은 GUI Context를 이용해:

```text
현재 선택 Resource
    ↓
Context Snapshot
    ↓
MCP / AI Layer
    ↓
Citation 포함 결과
    ↓
Frontend Assistant 표시
```

흐름을 추가한다.

AI가 없어도 위 Forensic Workflow는 정상 동작해야 한다.

---

# 67. 최종 검증 결과 — v2

현재 기준:

```text
main == feat/forensic-engine
commit: dbee798f12031d5f654430fe44ecfd1f8fa2211f
schemas/v1: 67 schemas
```

Windows Runtime 검증:

```text
전체 pytest: PASS (failure 0, optional dependency 관련 일부 skip)
Ruff: PASS
mypy: PASS (115 source files)
validate_design_basic.py: PASS (1813 checks)
validate_design.mjs: PASS (4124 checks)
git diff --check: PASS
```

이번 v2에서는 다음 Contract drift까지 반영했다.

- Evidence Hash에서 stale `SHA512` 제거
- Evidence Hash 알고리즘을 `SHA256/SHA1/MD5`로 확정
- Hash Verification `case_id` persistence/reload 보존
- Search generic 4096 / Regex 512 bound source enforcement
- Case Name 255 / Locale source enforcement
- AI Assistance bounds source enforcement
- Report bounds source enforcement
- Secret/Decryption recursive redaction
- `runtime-capability-report.schema.json` 추가
- Kakao `pragma_key_hash`/`user_nonce_hash`와 raw secret redaction 구분
- Annotation/Tag persistence가 현재 Core 구현이 아님을 명시

이 문서에서는 다음을 의도적으로 **구현 완료라고 적지 않는다.**

- 완성된 HTTP Backend Server
- MCP Server
- LLM Provider Runtime
- Prompt/Agent
- AI 자동 판단
- KakaoTalk 자동 Key 획득
- Android/iOS KakaoTalk
- 형태소 기반 한국어 검색
- 모든 Host에서 OCR/STT 사용 가능
- 모든 Host에서 E01/VHD/VHDX 사용 가능
- 모든 Host에서 PDF Export 사용 가능
- Live Windows Artifact Acquisition
- Annotation/Tag CRUD persistence
- plaintext Password/Key Reveal API
- 법적 증거능력 보장
- X-Ways/Autopsy 대비 성능 우위

반대로 현재 구현 근거가 확인된 기능은 Frontend 범위에 반영한다.

- Case/Evidence
- Progressive File System
- RAW/DD/IMG 및 Optional E01/VHD/VHDX 경로
- Deleted/Unallocated/Slack 관련 Engine 경로
- Registry/Event Log/Prefetch
- Registry Deleted-cell Carving
- Browser
- Media
- Communications
- KakaoTalk Windows 2.0.8.990 외부 Key 제한 경로
- Search
- Timeline
- Machine Candidate Contract/Review
- Context Snapshot
- Simple/Detailed/Raw View
- Chain of Custody
- Runtime Hash Verification
- Report Version/Review/Approval/Export
- HTML Renderer / Optional PDF Renderer
- Runtime Doctor/Capability Report
- Partial/Stale/Warning/Citation/Provenance 계약
- Secret public-output redaction

---

# 68. Frontend 담당자가 가장 먼저 해야 할 실제 TODO

```text
[ ] 1. schemas/v1 기반 Frontend Contract 정리
[ ] 2. Legacy ui-context.schema.json 대신 gui-session-context.schema.json 사용
[ ] 3. Gateway Interface 작성
[ ] 4. Schema-valid Mock Fixture 작성
[ ] 5. 공통 ResultState Component 작성
[ ] 6. CapabilityGate 작성
[ ] 7. JobProgress 작성
[ ] 8. CursorTable / LazyTree 작성
[ ] 9. Simple/Detailed/Raw Inspector 작성
[ ] 10. GUI Session Context Store 작성
[ ] 11. Case 화면
[ ] 12. Evidence 화면
[ ] 13. File System 화면
[ ] 14. Artifact 화면
[ ] 15. Registry/EventLog/Prefetch
[ ] 16. Browser
[ ] 17. Media
[ ] 18. Communications
[ ] 19. Search
[ ] 20. Timeline
[ ] 21. Candidates
[ ] 22. Chain of Custody
[ ] 23. Report
[ ] 24. Settings/Capabilities
[ ] 25. AI Assistant Shell
[ ] 26. ko-KR Resource 완성
[ ] Annotation/Tag는 Backend contract가 생길 때까지 Disabled/Hidden 상태 유지
[ ] 27. 30개 필수 Frontend Test Scenario 통과
[ ] 28. Backend Transport 연결
[ ] 29. 실제 Engine 결과와 Contract Test
[ ] 30. 대용량 Evidence UI 성능 검증
```

---

# 69. Frontend 인수인계 시 같이 전달할 Repository 파일

Frontend 담당자에게 최소 다음 파일을 함께 보라고 할 것.

```text
docs/API_INTERFACE.md

schemas/v1/common.schema.json
schemas/v1/case.schema.json
schemas/v1/evidence.schema.json
schemas/v1/file.schema.json
schemas/v1/artifact.schema.json
schemas/v1/search.schema.json
schemas/v1/timeline-event.schema.json
schemas/v1/job.schema.json
schemas/v1/runtime-capability-report.schema.json

schemas/v1/gui-session-context.schema.json
schemas/v1/analysis-context-snapshot.schema.json
schemas/v1/analysis-scope-context.schema.json
schemas/v1/view-projection.schema.json
schemas/v1/raw-view.schema.json
schemas/v1/raw-read-response.schema.json

schemas/v1/machine-extracted-candidate.schema.json

schemas/v1/decryption-request.schema.json
schemas/v1/decryption-result.schema.json
schemas/v1/dpapi-key-source.schema.json
schemas/v1/nss-profile.schema.json
schemas/v1/kakaotalk-artifact.schema.json
schemas/v1/secret-provider-capability.schema.json

schemas/v1/report-record.schema.json
schemas/v1/report-version.schema.json
schemas/v1/report-section.schema.json
schemas/v1/report-review-event.schema.json
schemas/v1/report-approval-record.schema.json
schemas/v1/report-export-manifest.schema.json
schemas/v1/rendered-report-artifact.schema.json
schemas/v1/report-renderer-capability.schema.json

src/apex_forensic/cli/parser.py
src/apex_forensic/runtime/capabilities.py
src/apex_forensic/domain/models/secret.py

tests/unit/test_phase6_context_views.py
tests/unit/test_phase8_report_contract.py
```

---

# 70. 마지막 한 줄

Frontend는 **포렌식 분석을 새로 구현하는 팀이 아니라, Engine이 반환하는 검증 가능한 Fact·Candidate·Warning·Citation·State를 손실 없이 사용자 Workflow로 연결하는 팀**으로 구현하면 된다.

특히 APEX에서는:

```text
빠르게 보여주는 것
+
Partial임을 숨기지 않는 것
+
원본 근거로 돌아갈 수 있는 것
+
AI/추론과 Evidence Fact를 섞지 않는 것
```

이 네 가지를 Frontend UX의 핵심 원칙으로 잡는다.


---

# 71. v2 인수인계 결론

Frontend 구현은 이제 `dbee798` 기준 Runtime/Schema/Docs가 서로 맞춰진 상태를 기준으로 시작한다.

가장 중요한 추가 원칙은 다음이다.

```text
Evidence Hash = SHA256 / SHA1 / MD5
Search = generic 4096 / regex 512
Case Name = max 255
Runtime Capability = 7-state report
Secret plaintext = public DTO에서 기대하지 않음
Annotation/Tag persistence = 아직 Backend contract 필요
Current Hash Verification = case_id 보존
```

Frontend는 Schema를 단순 TypeScript type source로만 사용하지 말고, `maxLength`, `maxItems`, `enum`, `null`, `partial`, `stale`, `capability status`, `redaction` semantics까지 UX에 반영한다.
