# APEX Forensic Engine

APEX Forensic Engine은 X-Ways Forensics의 빠른 분석 구조와 Autopsy의 Artifact 기반 분석 Workflow를 참고하여 개발하는 디지털 포렌식 핵심 분석 엔진입니다.

본 엔진은 APEX Digital Forensic Tool의 핵심 계층으로, Evidence 처리부터 Artifact 분석, Timeline 생성, 검색 및 분석 결과 관리까지 담당합니다.

MCP Server 및 LLM Layer와 독립적으로 설계하여 GUI, MCP, AI Agent 등 다양한 환경에서 동일한 분석 기능을 사용할 수 있도록 구성합니다.

---

# Forensic Engine 역할

Forensic Engine은 다음 기능을 담당합니다.

- Evidence 관리
- File System 분석
- Artifact 분석
- Timeline 생성
- 검색 및 Index 관리
- 분석 결과 구조화
- GUI 및 MCP 연동 Interface 제공

본 엔진은 AI 모델이나 MCP 구현에 직접 의존하지 않으며, 구조화된 분석 결과를 제공하는 것을 목표로 합니다.

---

# Architecture

APEX의 전체 분석 구조는 다음과 같습니다.

```text
                         사용자

                           |
                           v

                  Korean Forensic GUI

                           |
                           v

                  Forensic Core Engine

             +-------------+-------------+
             |                           |
             v                           v

      Analysis Result DB          Context Manager

                                         |
                                         v

                                   MCP Server

                                         |
                                         v

                                    AI Agent
```

---

# GUI Context 기반 분석 구조

APEX는 단순히 AI가 Evidence를 직접 분석하는 구조가 아닙니다.

사용자가 GUI에서 수행한 분석 작업과 결과를 저장하고, MCP Layer가 해당 Context를 기반으로 AI Agent에게 제공합니다.

분석 흐름:

```text
사용자가 GUI에서 분석 수행

        ↓

Forensic Engine 분석

        ↓

Analysis Result 저장

        ↓

Context Manager 관리

        ↓

MCP Server 전달

        ↓

AI Agent 분석 및 설명
```

이를 통해 AI는:

- 현재 Case 정보
- 등록된 Evidence 정보
- 사용자가 선택한 Artifact
- 기존 분석 결과
- Timeline 정보

를 기반으로 분석을 수행합니다.

---

# 담당 모듈

## Evidence Manager

Evidence Manager는 디지털 증거 데이터를 관리하는 핵심 모듈입니다.

### 주요 기능

- Case 단위 Evidence 관리
- 디스크 이미지 등록
- Logical File 등록
- Evidence Metadata 관리
- Hash 계산
- 무결성 검증
- 분석 작업 상태 관리


지원 예정 형식:

- E01
- RAW/DD
- IMG
- VHD/VHDX
- Logical File


예시 결과:

```json
{
  "case_id": "case-001",
  "evidence": "disk.E01",
  "hash": {
    "md5": "xxxx",
    "sha256": "xxxx"
  },
  "status": "loaded"
}
```

---

# File System Analyzer

File System Analyzer는 Evidence 내부의 파일 시스템을 분석합니다.

### 주요 기능

- Directory Tree 탐색
- 파일 및 폴더 목록 조회
- 파일 Metadata 추출
- 삭제 파일 탐색
- 파일 유형 분류
- 파일 검색
- Lazy Loading 기반 대용량 데이터 처리


목표:

대용량 Evidence 환경에서도 필요한 데이터만 효율적으로 조회할 수 있도록 설계합니다.

---

# Artifact Analyzer

Artifact Analyzer는 운영체제 및 사용자 활동 흔적을 분석합니다.

초기 구현 대상:

## Windows Artifact

### Registry

분석:

- Run Key
- UserAssist
- Recent Files
- USB History


### Event Log

분석:

- Security Event
- System Event
- Application Event
- Sysmon Event


### Prefetch

분석:

- 실행 프로그램
- 실행 횟수
- 마지막 실행 시간


---

## User Activity Artifact

분석 예정:

- Browser History
- Download History
- Recent Activity


---

## Multimedia Artifact

분석 예정:

- Image Metadata
- Video Metadata
- EXIF 정보


---

각 Artifact Analyzer는 독립적인 Module 구조로 구성하여 향후 확장 가능하도록 설계합니다.

---

# Timeline Engine

Timeline Engine은 여러 Artifact에서 추출된 시간 정보를 통합하여 사건 흐름을 생성합니다.

### 주요 기능

- 파일 생성 시간 분석
- 파일 수정 시간 분석
- 파일 접근 시간 분석
- Registry 변경 시간 분석
- 프로그램 실행 시간 분석
- Browser 활동 시간 분석
- Event Log 시간 분석


결과 예시:

```json
[
  {
    "timestamp": "2026-07-13 12:30",
    "type": "process",
    "source": "prefetch",
    "description": "powershell.exe executed"
  }
]
```

---

# Search Engine

Search Engine은 Evidence 내부 데이터를 빠르게 탐색하기 위한 모듈입니다.

### 주요 기능

- 파일명 검색
- Keyword Search
- Regex Search
- Metadata Search
- Artifact Search
- Index 기반 검색
- 검색 결과 Cache


최적화 방향:

- Index Database
- Cache Layer
- 병렬 검색 처리

---

# Interface Layer

Forensic Engine은 GUI와 MCP가 동일한 분석 기능을 사용할 수 있도록 Interface Layer를 제공합니다.

MCP Server 및 LLM Provider는 Engine 내부에 포함하지 않습니다.

분석 결과는 JSON Schema 기반 구조화 데이터로 반환합니다.

예시:

```json
{
  "case_id": "case-001",
  "artifact_type": "windows_registry",
  "status": "completed",
  "findings": [
    {
      "path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "value": "update.exe",
      "risk_level": "high"
    }
  ]
}
```

---

# 설계 원칙

- Forensic Engine과 AI Layer 분리
- MCP Server와 LLM Provider 독립성 유지
- Artifact Analyzer 모듈화
- 원본 Evidence 읽기 전용 분석
- 분석 결과 구조화 및 검증 가능 데이터 제공
- GUI와 MCP가 동일한 Engine Interface 사용
- Lazy Loading 기반 대용량 데이터 처리
- 병렬 처리 및 Cache 구조 적용
- 사실 정보와 AI 추론 결과 분리

---

# Performance Optimization

APEX Forensic Engine은 X-Ways의 빠른 분석 철학을 참고하여 다음 최적화를 목표로 합니다.

## Lazy Loading

필요한 데이터만 로딩하여 초기 분석 시간을 단축합니다.

## Index System

분석 결과 및 검색 데이터를 Index화하여 빠른 탐색을 제공합니다.

## Cache Layer

반복 분석 시 기존 결과를 재사용하여 불필요한 분석을 방지합니다.

## Parallel Processing

독립적인 Artifact 분석 작업을 병렬 처리하여 전체 분석 시간을 단축합니다.

---

# Project Structure

```text
engine/

├── evidence/
│   ├── loader
│   ├── hash
│   └── metadata
│
├── filesystem/
│
├── artifact/
│   ├── registry
│   ├── eventlog
│   ├── prefetch
│   ├── browser
│   └── multimedia
│
├── timeline/
│
├── search/
│
├── index/
│
├── context/
│
└── api/
```

---

# Reference Projects

## X-Ways Style Forensic Engine

참고 영역:

- 빠른 Evidence 탐색 구조
- 대용량 데이터 처리 방식
- 분석 Workflow


## Autopsy

참고 영역:

- Case 기반 분석 구조
- Artifact Workflow
- 사용자 친화적인 분석 방식


## X-Ways Forensics MCP

참고 영역:

- 포렌식 기능과 MCP 연결 방식
- 분석 Context 활용 구조


참고 프로젝트:

- https://github.com/tagalston101/x-way-forensics-tool
- https://github.com/sleuthkit/autopsy
- https://github.com/joyooosama/x-ways-forensics-mcp

---

# Development Status

## Completed

- [x] Forensic Engine Architecture 설계
- [x] Module Responsibility 정의
- [x] Database Schema 설계
- [x] API Interface 설계
- [x] JSON Schema v1 작성 및 검증
- [x] Implementation Roadmap 작성


## Planned

- [ ] Evidence Manager 구현
- [ ] Hash 및 무결성 검증 구현
- [ ] File System Analyzer 구현
- [ ] Registry Analyzer 구현
- [ ] Event Log Analyzer 구현
- [ ] Prefetch Analyzer 구현
- [ ] Timeline Engine 구현
- [ ] Search Engine 구현
- [ ] Index 및 Cache 구현
- [ ] GUI Interface 연동
- [ ] MCP Interface 연동
- [ ] 성능 테스트 및 최적화


---

# Documents

상세 설계 문서:

- [Architecture](../docs/ARCHITECTURE.md)
- [Database Schema](../docs/DATABASE_SCHEMA.md)
- [API Interface](../docs/API_INTERFACE.md)
- [Module Responsibilities](../docs/MODULE_RESPONSIBILITIES.md)


JSON Schema:

- `../schemas/v1/`
