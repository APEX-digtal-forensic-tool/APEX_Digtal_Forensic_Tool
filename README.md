# APEX Forensic Core Engine

APEX 플랫폼의 **Forensic Core Engine**입니다.

이 브랜치는 디지털 증거의 등록·무결성 검증·인덱싱·Artifact 추출·검색·Timeline·Context·검토 Workflow를 담당합니다.

Frontend GUI, Backend Identity·Billing, MCP Server, LLM Provider, Prompt 및 Agent Loop는 별도 모듈의 책임입니다.

> **현재 상태**
>
> Phase 1~8에서 정의한 **엔진 기반 기능과 외부 연동 계약 범위**를 구현했습니다.
> 이는 전체 디지털 포렌식 제품의 모든 기능이 완성됐다는 의미가 아닙니다.
>
> 현재 실제 분석 대상은 Directory·일반 파일과 지원되는 Registry·Event Log·Prefetch·Browser·Media Artifact입니다.
> E01·RAW·DD·IMG·VHD·VHDX 내부 File System 탐색, 삭제 파일 복구, 실제 OCR·STT, 실제 AI 실행 및 PDF·HTML 렌더링은 아직 지원하지 않습니다.

---

## 현재 지원 범위

상태는 `IMPLEMENTED`(실제 Runtime), `OPTIONAL`(선택 Dependency), `CONTRACT_ONLY`(계약만 구현), `UNSUPPORTED`(현재 미지원)로 구분합니다.


| 영역 | 상태 | 현재 범위 |
|---|---|---|
| Case·Evidence 관리 | `IMPLEMENTED` | Case, Evidence 등록, 상태, Locale, Timezone |
| 파일 Hash·무결성 | `IMPLEMENTED` | 일반 파일 MD5·SHA-1·SHA-256 Streaming Hash와 재검증 |
| Directory Hash | `UNSUPPORTED` | Directory Manifest Hash 정책 미구현 |
| Chain of Custody | `IMPLEMENTED` | Append-only Event, Hash Chain, Correction Event |
| Progressive Indexing | `IMPLEMENTED` | Directory 및 단일 일반 파일 Metadata Index |
| Windows Registry | `IMPLEMENTED` | `.reg`, Autorun, USBSTOR, TimeZoneInformation, UserAssist |
| Binary Registry Hive | `OPTIONAL` | `python-registry` 설치 시 Offline Hive Capability |
| Event Log | `IMPLEMENTED` | Exported Windows Event XML |
| Binary EVTX | `OPTIONAL` | `python-evtx` 설치 시 Binary EVTX Capability |
| Prefetch | `IMPLEMENTED` | Version 17·23·26·30 최소 Metadata, MAM 감지 |
| Browser | `IMPLEMENTED` | Chromium Visit·Search·Download, Firefox Visit·Download Candidate |
| Media | `IMPLEMENTED` | Image Header, JPEG EXIF·GPS, MP4 기본 Metadata |
| Pillow Image Parsing | `OPTIONAL` | `browser-media` Extra 설치 시 |
| ffprobe Metadata | `OPTIONAL` | 시스템에 `ffprobe`가 있을 때 Video·Audio Metadata 확장 |
| Search | `IMPLEMENTED` | Metadata·Artifact 기반 SQLite FTS5 Search |
| Timeline | `IMPLEMENTED` | File System·Artifact·Browser·Media Timestamp Projection |
| GUI Context | `IMPLEMENTED` | Session Context, Revision, TTL, Immutable Snapshot |
| Simple·Detailed·Raw View | `IMPLEMENTED` | 동일 Resource 기반 Projection과 제한된 Raw Read |
| Public Engine Interface | `IMPLEMENTED` | JSON-friendly Envelope, Capability, Tool Descriptor |
| AI Assistance | `CONTRACT_ONLY` | 외부 Recommendation·Summary 검증, 저장, Human Review |
| OCR·STT | `CONTRACT_ONLY` | Provider Port와 Candidate Review Workflow |
| Report Workflow | `IMPLEMENTED` | Immutable Version, Review, Approval, Custody Snapshot |
| PDF·HTML Renderer | `CONTRACT_ONLY` | Render Package·Manifest·Renderer Port, 실제 렌더링 없음 |
| Disk Image 내부 탐색 | `UNSUPPORTED` | E01·RAW·DD·IMG·VHD·VHDX 내부 Parser 없음 |
| 삭제·Unallocated·Slack | `UNSUPPORTED` | 탐색·검색·복구 미구현 |

Search는 SQLite FTS5가 필요합니다.

FTS5를 사용할 수 없는 환경에서는 다른 검색 방식으로 성공을 가장하지 않고 `CAPABILITY_UNAVAILABLE`을 반환합니다.

---

## Evidence 지원 수준

등록 가능 여부와 내부 분석 가능 여부는 다릅니다.

| Evidence 유형 | 등록 | 파일 Hash | 내부 Tree 탐색 | 지원 Artifact 분석 | 삭제 복구 |
|---|---:|---:|---:|---:|---:|
| Directory | 지원 | 미지원 | 지원 | 지원되는 파일 대상 | 해당 없음 |
| 일반 파일 | 지원 | 지원 | 단일 File Node | 파일 형식이 지원될 때 | 미지원 |
| E01 | 지원 | 지원 | 미지원 | Image 내부는 미지원 | 미지원 |
| RAW·DD·IMG | 지원 | 지원 | 미지원 | Image 내부는 미지원 | 미지원 |
| VHD·VHDX | 지원 | 지원 | 미지원 | Image 내부는 미지원 | 미지원 |

일반 파일은 Logical File Reader로 단일 Node를 구성합니다.

`.e01`, `.dd`, `.img`, `.vhd`, `.vhdx` 파일은 형식을 식별해 등록하고 Hash를 계산할 수 있지만, 현재 해당 Container 내부를 Mount하거나 File System으로 Parsing하지 않습니다.

---

## Architecture

```text
CLI / Frontend / Backend / MCP Adapter
                  │
                  ▼
       Public Application Interface
                  │
                  ▼
          Application Services
  Case · Evidence · Artifact · Search
  Timeline · Context · AI Contract · Report
                  │
                  ▼
       Domain Models and Ports
                  │
          ┌───────┴────────┐
          ▼                ▼
   Analysis Adapters   SQLite Repository
```

### 책임 경계

| Engine 담당 | 별도 모듈 담당 |
|---|---|
| Case·Evidence·Hash·Integrity | Desktop GUI |
| File System·Artifact·Search·Timeline | Identity·RBAC·Billing |
| Context Snapshot·View·Raw Locator | MCP Server·Tool Registration |
| Citation·Custody·Audit | LLM·Prompt·Agent Loop |
| 외부 AI Result 검증·저장·검토 | 실제 AI 생성 |
| Report Version·Review·Approval 계약 | 실제 OCR·STT와 PDF·HTML Renderer |
| CLI·SQLite·JSON Schema | 악성 여부 최종 판단 |

Engine은 Evidence 내부 실행 파일을 실행하거나 AI 결과를 Observed Fact로 승격하지 않습니다.

---

## Quick Start

### 설치

요구 버전은 Python `3.11+`입니다.

```powershell
git clone https://github.com/APEX-digtal-forensic-tool/APEX_Digtal_Forensic_Tool.git
cd APEX_Digtal_Forensic_Tool

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,windows-artifacts,browser-media]"
```

Linux/macOS Shell에서는 `source .venv/bin/activate`로 활성화합니다.

최소 Runtime은 `python -m pip install -e .`, 개발 도구만 포함하려면 `python -m pip install -e ".[dev]"`를 사용합니다.

`ffprobe`는 Python Package가 아니라 별도 시스템 실행 파일입니다.

### 기본 Workflow

```powershell
apex-forensic --db .\apex.db init --json

apex-forensic --db .\apex.db case create `
  --name "Sample Case" --investigator "Analyst" --json

apex-forensic --db .\apex.db evidence add `
  --case-id <CASE_ID> --path "C:\evidence\sample" --json

apex-forensic --db .\apex.db evidence index `
  --case-id <CASE_ID> --evidence-id <EVIDENCE_ID> `
  --profile QUICK_TRIAGE --json

apex-forensic --db .\apex.db artifact analyze `
  --case-id <CASE_ID> --evidence-id <EVIDENCE_ID> --json
```

Timeline과 Search:

```powershell
apex-forensic --db .\apex.db timeline build `
  --case-id <CASE_ID> --evidence-id <EVIDENCE_ID> --json

apex-forensic --db .\apex.db search index `
  --case-id <CASE_ID> --evidence-id <EVIDENCE_ID> --json

apex-forensic --db .\apex.db search query `
  --case-id <CASE_ID> --query "powershell" --json
```

일반 파일 Hash:

```powershell
apex-forensic --db .\apex.db evidence hash `
  --evidence-id <EVIDENCE_ID> --algorithm sha256 --json
```

Directory Evidence는 Manifest Hash를 지원하지 않습니다.

```powershell
apex-forensic --help
apex-forensic artifact --help
apex-forensic context --help
apex-forensic ai --help
apex-forensic report --help
```

상세 사용법은 [`docs/FORENSIC_ENGINE.md`](./docs/FORENSIC_ENGINE.md)를 참고합니다.

---

## 주요 CLI Group

| Group | 역할 |
|---|---|
| `init` | SQLite DB 초기화 |
| `case` | Case 생성·조회·상태 변경 |
| `evidence` | Evidence 등록·Hash·Index |
| `fs` | Indexed File Tree 조회·우선순위 |
| `artifact` | Artifact Discovery·Analysis·Query |
| `browser` | Browser 전용 분석·조회 |
| `media` | Media 전용 분석·조회 |
| `candidate` | Machine Candidate 조회·검토·수정 |
| `search` | Search Index·Query·History·Cache |
| `keyword-set` | Keyword Set와 Immutable Version |
| `timeline` | Timeline Build·Query |
| `context` | GUI Session과 Immutable Snapshot |
| `view` | Simple·Detailed·Raw View와 Raw Read |
| `ai` | 외부 AI Result Ingest·Review·Promotion 계약 |
| `report` | Report Version·Review·Approval·Export 계약 |

---

## Engine과 AI의 데이터 경계

```text
Engine Observed Fact·Revision·Citation
                ↓
        External MCP / AI
Keyword Candidate·Summary·Draft 생성
                ↓
          Engine Validation
Case·Evidence·Citation·Stale 상태 검증
                ↓
            Human Review
```

Engine은 Resource ID, Observed Field, Analyzer 정보, Source Revision, Citation, Raw Locator, Partial·Stale·Coverage 및 Immutable Context Snapshot을 제공합니다.

외부 AI는 자연어 설명, Keyword Recommendation, Scope Summary, 추론 후보와 Report Draft를 생성합니다.

Engine은 외부 결과를 다시 검증하며 Prompt·API Key·Chain-of-thought·Raw Provider Body 저장을 거부하고 AI Result를 Observed Fact와 분리합니다.

아래는 개념을 설명하는 축약 예시이며 실제 전체 필드는 `schemas/v1/`을 따릅니다.

```json
{
  "artifact_id": "artifact-00184",
  "evidence_id": "evidence-001",
  "artifact_type": "PREFETCH_EXECUTION",
  "observed": {
    "executable_name": "POWERSHELL.EXE",
    "run_count": 4
  },
  "source_revision": "rev-12",
  "citation_id": "citation-001",
  "raw_locator": {
    "locator_type": "PREFETCH_FIELD",
    "offset": 144,
    "length": 32
  },
  "partial": false,
  "stale": false
}
```

---

## Citation과 Raw Locator

Citation은 결과와 원본 Source를 연결합니다.

현재 계약은 `id`, `label`, `case_id`, 선택적 `evidence_id`, `source_kind`, `source_id`, 선택적 전문 Resource ID, Source Path·Reference·Offset·Length·Encoding, Excerpt·Hash·생성 시각 및 `raw_locator`를 포함합니다.

Raw Locator는 Evidence·Source ID, Locator Type, Byte Range 또는 Logical Reference, `HEX`·`TEXT` View, Hash와 제한사항을 기록합니다.

핵심 원칙:

- 존재하지 않거나 다른 Case·Evidence의 Resource 거부
- Caller가 전달한 임의 Path만으로 Raw Read 금지
- Indexed Source Node와 Evidence Root 검증
- Revision 변경 시 Partial·Stale 상태 보존
- AI 설명과 원본 Fact 분리
- Report 문장을 Observed Fact로 승격하지 않음

전체 형식은 [`schemas/v1/citation.schema.json`](./schemas/v1/citation.schema.json)을 참고합니다.

---

## Security and Forensic Safety

- 원본 Evidence 읽기 전용, Derived Data 분리
- Symlink·Junction·Reparse Point 기본 미추적 및 사후 교체 방어
- Evidence Root 밖 Path Traversal 차단
- Cross-case·Cross-evidence 연결 차단
- Raw Read Offset·Length·EOF·최대 크기 검증
- Export Absolute Path·Drive Prefix·UNC·Reserved Name 차단
- 외부 Process argv 실행, `shell=True` 금지, Timeout·출력 제한
- Image Decompression Bomb·손상 입력 보호
- Append-only Custody·Review·Approval와 Hash Chain
- Read Interface에서 Mutation 실행 차단
- AI Result와 Observed Fact 분리

통합 감사에서 발견된 2 High, 2 Medium, 2 Low Finding은 Regression Test와 함께 수정됐으며 현재 미해결 Finding은 Critical·High·Medium·Low 모두 `0`입니다.

---

## 지원 환경과 Dependency

| 구분 | 현재 기준 |
|---|---|
| Python | `3.11+` |
| OS | Windows·Linux 회귀 Test 수행 |
| Database | SQLite |
| Search | SQLite FTS5 필요 |
| JSON Schema | Draft 2020-12 |
| Base Dependency | `jsonschema`, Windows의 `tzdata` |
| Dev Dependency | `pytest`, `ruff`, `mypy` |
| Binary Registry | `python-registry` 선택 |
| Binary EVTX | `python-evtx` 선택 |
| Image Parsing | `Pillow` 선택 |
| Video·Audio 확장 | 외부 `ffprobe` 선택 |

특정 Windows 또는 Linux 배포판 버전을 공식 지원 범위로 선언하지 않았습니다.

---

## 검증

현재 기준:

- Windows·Linux `pytest`: **94 passed**
- Ruff: **All checks passed**
- mypy: **81 source files, no issues**
- Python Validator: **1607 checks, 52 schemas**
- Node Validator: **3586 checks, 52 schemas**

```powershell
python -m pytest
python -m ruff check .
python -m mypy src
python -X utf8 .\tools\validate_design_basic.py
node .\tools\validate_design.mjs
```

Linux·WSL·CI에서는 `bash ./tools/validate_design.sh`를 사용합니다.

---

## 주요 제한 사항

- Directory Evidence Manifest Hash 미지원
- E01·RAW·DD·IMG·VHD·VHDX 내부 File System Parsing 미지원
- NTFS·FAT·exFAT·ext 직접 Parser 미지원
- 삭제 File·Unallocated·Slack 분석 미지원
- Registry Transaction Log·삭제 Key 복구 미지원
- Prefetch MAM 압축 해제 미지원
- Event Message DLL Rendering 미지원
- Browser Credential·Cookie 복호화 미지원
- Browser Cache·Incognito·삭제 Record 복구 미지원
- 실제 OCR·STT 실행 미지원
- 실제 MCP Server·LLM·Prompt·Agent 미지원
- 실제 AI Keyword·Summary·Report 생성 미지원
- 실제 PDF·HTML Rendering 미지원
- 실제 GUI·Report Preview 미지원
- 전자서명·Identity·RBAC·Billing 미지원
- 공식 성능 우위 Benchmark 없음
- 법적 증거능력을 자동 보장하지 않음

---

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/FORENSIC_ENGINE.md`](./docs/FORENSIC_ENGINE.md) | Engine 상세 구현과 사용 |
| [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) | 전체 Architecture |
| [`docs/API_INTERFACE.md`](./docs/API_INTERFACE.md) | Public Interface와 Endpoint |
| [`docs/DATABASE_SCHEMA.md`](./docs/DATABASE_SCHEMA.md) | SQLite Table·Trigger·Index |
| [`docs/JSON_SCHEMAS.md`](./docs/JSON_SCHEMAS.md) | JSON Schema 규칙 |
| [`docs/MODULE_RESPONSIBILITIES.md`](./docs/MODULE_RESPONSIBILITIES.md) | Module 책임 |
| [`docs/DIRECTORY_STRUCTURE.md`](./docs/DIRECTORY_STRUCTURE.md) | Directory 구조 |
| [`docs/IMPLEMENTATION_DECISIONS.md`](./docs/IMPLEMENTATION_DECISIONS.md) | 구현 결정 |
| [`docs/IMPLEMENTATION_ROADMAP.md`](./docs/IMPLEMENTATION_ROADMAP.md) | 상세 Roadmap |
| [`docs/REQUIREMENTS_TRACEABILITY.md`](./docs/REQUIREMENTS_TRACEABILITY.md) | 요구사항 추적 |

---

## 다음 우선순위

1. E01·RAW·DD·IMG·VHD·VHDX 내부 File System Provider
2. 삭제 File·Unallocated·Slack 분석
3. Registry Transaction Log, Prefetch MAM, Event Message 확장
4. Browser Credential·Cache·삭제 Record 분석
5. 실제 OCR·STT·AI·Renderer Adapter 통합
6. 동일 조건 Benchmark와 Windows Packaging

Disk Image 내부 탐색과 복구 기능이 구현되기 전까지 현재 Engine 범위는 **Directory·일반 파일 기반 MVP**로 명확히 제한합니다.

---

## 용어

| 용어 | 의미 |
|---|---|
| Evidence | 분석 대상으로 등록된 원본 Source |
| Artifact | Engine이 Source에서 추출한 구조화된 결과 |
| Observed Fact | Evidence에서 직접 추출한 값 |
| Candidate | 자동 추출됐지만 Analyst 검토 전인 값 |
| Citation | 결과와 원본 Source를 연결하는 근거 |
| Raw Locator | 원본의 Byte Range 또는 Logical Record 위치 |
| Context Snapshot | 분석 시점의 Resource·Revision·Filter를 고정한 불변 기록 |
| Derived Data | Thumbnail·Report Output 등 원본에서 파생된 데이터 |
| Contract-only | 외부 Provider를 위한 계약은 있지만 실제 Provider 실행은 없는 상태 |

---

## 프로젝트 경계

전체 APEX 제품은 Engine 외에 Frontend, Backend, MCP·AI Adapter로 구성됩니다.

이 README는 **Forensic Core Engine의 실제 Runtime 기능과 계약**만 설명합니다.

한국어 UI, AI 자연어 품질, 사용자 인증, Billing 및 실제 Report Rendering은 각 담당 Module에서 구현합니다.

---

## 라이선스

현재 저장소에는 `LICENSE` 파일이 포함되어 있지 않습니다.

외부 공개·배포 전에 프로젝트 License와 Third-party Dependency License 정책을 확정해야 합니다.
