# APEX Forensic Engine

APEX Forensic Engine은 X-Ways Forensics의 빠른 분석 구조와 Autopsy의 Artifact 기반 분석 Workflow를 참고하여 개발하는 디지털 포렌식 핵심 분석 엔진입니다.

본 엔진은 APEX Digital Forensic Tool의 Core Layer로서 Evidence 관리, File System 분석, Artifact 분석, Timeline 생성, Search 및 결과 관리 기능을 담당합니다.

초기 구조는 **Port/Adapter 기반 모듈형 모놀리스(Modular Monolith)** 형태로 설계하며, 분석 모듈의 독립성과 확장성을 유지하면서 GUI, CLI, MCP Adapter 등 다양한 Client가 동일한 분석 기능을 사용할 수 있도록 구성합니다.

---

# Engine 역할

Forensic Engine은 다음 기능을 담당합니다.

- Evidence 등록 및 관리
- 증거 무결성 검증
- File System 분석
- Artifact 분석
- Timeline 생성
- Search 및 Index 관리
- Analysis Result 저장
- GUI 및 MCP Adapter를 위한 Interface 제공


중요:

Forensic Engine은 특정 AI 모델이나 MCP Server에 직접 의존하지 않습니다.

AI Layer와 분석 Layer를 분리하여, 향후 GPT, Claude, Gemini, Local LLM 등 다양한 Provider와 연결할 수 있도록 설계합니다.

---

# Architecture

전체 구조:

```text
                         사용자

                           |
                           v

                    Forensic GUI

                           |
                           v

                 Application Interface

                           |
                           v

                 Forensic Core Engine

        +------------------+------------------+
        |                                     |
        v                                     v

 Analysis Result Database              Context Manager

                                              |
                                              v

                                        MCP Adapter

                                              |
                                              v

                                           AI Agent
```


---

# GUI Context 기반 AI 연동 구조

APEX는 AI가 Evidence를 직접 분석하는 방식이 아닌, 사용자가 GUI에서 수행한 분석 과정과 결과를 기반으로 AI가 보조하는 구조를 목표로 합니다.


분석 흐름:

```text
사용자 GUI 분석

        ↓

Forensic Engine 실행

        ↓

Analysis Result 저장

        ↓

Context Manager 관리

        ↓

MCP Adapter 전달

        ↓

AI Agent 분석 및 설명
```


AI는 다음 정보를 활용합니다.

- 현재 Case 정보
- 등록된 Evidence 정보
- 사용자가 선택한 Artifact
- 기존 분석 결과
- Timeline 정보
- 검색 결과


예:

사용자가 GUI에서:

```text
Data Artifact
 └ Registry
      └ Run Key 분석
```


실행 후:

```json
{
  "artifact_type": "registry",
  "finding": {
    "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "value": "update.exe",
    "risk_level": "high"
  }
}
```


저장.


이후 AI 요청:

> "현재 결과가 위험한 이유를 설명해줘"


AI는 기존 분석 Context를 기반으로:

- 관련 증거 설명
- 위험도 판단
- 추가 분석 추천
- 보고서 작성

을 수행합니다.

---

# Core Modules

## Evidence Manager

Evidence Manager는 분석 대상 증거 데이터를 관리합니다.

주요 기능:

- Case 단위 Evidence 관리
- Disk Image 등록
- Logical File 등록
- Metadata 관리
- Hash 계산
- 무결성 검증
- 분석 Job 관리


지원 예정:

- E01
- RAW/DD
- IMG
- VHD/VHDX
- Directory Evidence


원칙:

- 원본 Evidence Read Only 처리
- 분석 과정에서 원본 데이터 변경 금지

---

# File System Analyzer

Evidence 내부 파일 시스템을 분석합니다.

주요 기능:

- Directory Tree 조회
- File Metadata 추출
- 파일 목록 조회
- 삭제 파일 탐색
- 파일 유형 분류
- Lazy Loading 기반 탐색


목표:

대용량 Evidence에서도 필요한 데이터만 효율적으로 조회할 수 있는 구조 제공.

---

# Artifact Analyzer

운영체제 및 사용자 활동 흔적을 분석합니다.


초기 지원 대상:

## Windows Artifact

### Registry

- Run Key
- UserAssist
- Recent Files
- USB History


### Event Log

- Security Event
- System Event
- Application Event
- Sysmon Event


### Prefetch

- 실행 프로그램
- 실행 횟수
- 마지막 실행 시간


---

## User Activity

예정:

- Browser History
- Download History
- Recent Activity


---

## Multimedia

예정:

- Image Metadata
- Video Metadata
- EXIF 분석


각 Artifact Analyzer는 독립 모듈 구조로 설계하여 확장 가능합니다.

---

# Timeline Engine

Timeline Engine은 여러 Artifact에서 추출된 시간 정보를 통합합니다.


지원:

- File MAC Time
- Registry Time
- Event Log Time
- Browser Activity
- Program Execution Time


기능:

- 시간순 사건 흐름 생성
- 이벤트 필터링
- 데이터 출처 표시
- AI 분석용 Timeline 제공

---

# Search Engine

Search Engine은 Evidence와 분석 결과를 빠르게 검색하기 위한 모듈입니다.


기능:

- File Name Search
- Keyword Search
- Regex Search
- Metadata Search
- Artifact Search
- Index 기반 검색


최적화:

- Full Text Index
- Cache Layer
- Cursor 기반 조회

---

# Interface Layer

Engine은 GUI와 MCP Adapter가 사용할 수 있는 공통 Interface를 제공합니다.


구조:

```text
GUI

 |

API Interface

 |

Forensic Engine

 |

Structured JSON Result

 |

MCP Adapter
```


분석 결과는 JSON Schema 기반으로 관리합니다.


예:

```json
{
  "case_id": "case-001",
  "artifact_type": "windows_registry",
  "status": "completed",
  "findings": []
}
```


---

# Data Contract

APEX는 JSON Schema Draft 2020-12 기반의 데이터 계약을 사용합니다.


Schema 목적:

- GUI 결과 표시
- API 응답 검증
- MCP Adapter 연동
- AI Layer 입력 데이터 표준화


주요 Schema:

- Case
- Evidence
- File
- Artifact
- Timeline Event
- Search Result
- Job Status
- AI Enrichment Result

---

# Performance Optimization

APEX는 X-Ways의 빠른 분석 철학을 참고하여 다음 최적화를 목표로 합니다.


## Lazy Loading

필요한 데이터만 로딩하여 초기 분석 비용 감소


## Index System

검색 및 결과 조회 성능 개선


## Cache Layer

반복 분석 방지 및 결과 재사용


## Parallel Processing

독립적인 Artifact 분석 병렬 처리


---

# Project Structure

```text
engine/

├── domain/
│   ├── cases
│   ├── evidence
│   ├── filesystem
│   ├── artifacts
│   ├── timeline
│   └── search
│
├── application/
│
├── adapters/
│
├── analyzers/
│
├── api/
│
├── context/
│
└── jobs/
```

---

# Reference Projects

## X-Ways Style Forensic Engine

참고:

- 빠른 Evidence 탐색
- 분석 Workflow
- 성능 최적화 구조


## Autopsy

참고:

- Case Workflow
- Artifact 분석 구조
- 사용자 친화적 분석 환경


## X-Ways Forensics MCP

참고:

- 포렌식 기능과 AI Agent 연결 방식
- MCP Adapter 구조
- 분석 Context 활용 방식


---

# Development Status

## Completed

- [x] 전체 Architecture 설계
- [x] Module Responsibility 정의
- [x] Database Schema 설계
- [x] API Interface 설계
- [x] JSON Schema v1 작성 및 검증
- [x] Implementation Roadmap 작성


## Planned

- [ ] Case Manager 구현
- [ ] Evidence Manager 구현
- [ ] Hash 및 무결성 검증 구현
- [ ] File System Analyzer 구현
- [ ] Registry Analyzer 구현
- [ ] Event Log Analyzer 구현
- [ ] Prefetch Analyzer 구현
- [ ] Timeline Engine 구현
- [ ] Search Engine 구현
- [ ] Index / Cache 구현
- [ ] GUI Interface 연동
- [ ] MCP Adapter 연동
- [ ] 성능 Benchmark 및 최적화


---

# Documents

상세 설계 문서:

- Architecture
- Database Schema
- API Interface
- Module Responsibilities
- JSON Schema


위 문서는 `docs/` 디렉터리에서 확인할 수 있습니다.
