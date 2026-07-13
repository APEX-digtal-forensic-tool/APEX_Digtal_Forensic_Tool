# APEX Digital Forensic Tool

APEX는 디지털 증거 분석의 접근성과 자동화를 목표로 개발하는 **AI 기반 디지털 포렌식 분석 플랫폼**입니다.

기존 디지털 포렌식 도구는 강력한 분석 기능을 제공하지만 높은 비용, 복잡한 사용 환경, 전문 지식 요구 등의 한계가 존재합니다.

APEX는 이러한 문제를 해결하기 위해:

- **X-Ways Forensics의 빠른 분석 구조**
- **Autopsy의 사용자 친화적인 분석 Workflow**
- **MCP 기반 AI Agent 연동 구조**

를 참고하여 누구나 접근 가능한 차세대 DFIR(Digital Forensics & Incident Response) 환경을 제공하는 것을 목표로 합니다.

---

# 핵심 차별점

## 1. 한국어 기반 디지털 포렌식 환경

기존 포렌식 도구는 대부분 영어 UI와 전문 용어 중심으로 구성되어 있어 입문자와 비전공자가 접근하기 어렵습니다.

APEX는 한국어 기반 분석 환경을 제공합니다.

지원 목표:

- 한국어 사용자 인터페이스
- Artifact 분석 결과 한국어 설명
- 한국어 자연어 기반 AI 질의
- 한국어 포렌식 보고서 생성
- 분석 결과 및 위험도 설명

이를 통해 디지털 포렌식 분석 과정의 진입 장벽을 낮추는 것을 목표로 합니다.

---

# 2. MCP 기반 AI Forensic Assistant

APEX는 단순히 외부 AI 서비스를 연결하는 방식이 아닌, 포렌식 분석 환경 내부에 MCP 기반 AI 연동 구조를 포함합니다.

AI는 포렌식 엔진을 직접 대체하지 않습니다.

사용자가 GUI에서 수행한 분석 과정과 구조화된 분석 결과를 기반으로 AI가 분석을 보조하는 형태로 설계됩니다.

---

## AI 분석 Workflow

```text
사용자

  |
  v

Forensic GUI
(Autopsy Style Interface)

  |
  | 분석 작업 수행
  v

Forensic Core Engine

  |
  | 분석 결과 저장
  v

Analysis Result Database

  |
  | Context 관리
  v

MCP Adapter

  |
  v

AI Agent
```

---

## Context 기반 AI 분석

AI는 다음 정보를 기반으로 분석을 수행합니다.

- 현재 Case 정보
- 등록된 Evidence 정보
- 사용자가 선택한 Artifact
- 기존 분석 결과
- Timeline 정보
- 검색 결과


예시:

사용자가 GUI에서:

```text
Data Artifact

 └ Registry

      └ Run Key Analysis
```

를 수행합니다.


Forensic Engine 결과:

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


사용자가 AI에게:

> "이 결과가 위험한 이유를 설명해줘"

라고 요청하면 AI는 기존 분석 Context를 기반으로:

- 관련 증거 설명
- 위험도 판단
- 추가 분석 제안
- 보고서 작성

을 수행합니다.

---

# 3. 빠른 분석 엔진 최적화

APEX는 대용량 디지털 증거 처리를 고려한 효율적인 포렌식 엔진 개발을 목표로 합니다.

주요 최적화 방향:

- Lazy Loading 기반 파일 탐색
- Artifact 병렬 분석
- Index 기반 검색
- 분석 결과 Cache
- 중복 분석 방지
- 대용량 Evidence 처리 최적화
- GUI와 분석 엔진 분리


목표:

> X-Ways의 빠른 분석 성능과 Autopsy의 쉬운 사용성을 결합한 DFIR 플랫폼

---

# 주요 기능

## Case Management

사건 단위 분석 환경 관리

기능:

- 신규 Case 생성
- 기존 Case 불러오기
- 사건 정보 관리
- Evidence 관리
- 분석 결과 저장
- Timeline 및 Report 관리


---

# Evidence Management

디지털 증거 데이터를 등록하고 관리합니다.

지원 예정:

- Disk Image
- Logical File
- Memory Dump


지원 형식:

- E01
- RAW/DD
- IMG
- VHD
- VHDX


기능:

- Evidence 등록
- Metadata 확인
- Hash 계산
- 무결성 검증
- 분석 상태 관리


---

# File System Analysis

Evidence 내부 파일 시스템을 분석합니다.

기능:

- Directory Tree 탐색
- 파일 목록 조회
- 파일 Metadata 분석
- 삭제 파일 탐색
- 파일 유형 분류
- 파일 검색
- 상세 정보 확인


---

# Artifact Analysis

운영체제 및 사용자 활동 흔적을 분석합니다.


## Windows Artifact

지원 예정:

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

- 실행 프로그램 확인
- 실행 횟수 분석
- 마지막 실행 시간 확인


---

## User Activity Artifact

지원 예정:

- Browser History
- Download History
- Recent Activity


---

## Multimedia Artifact

지원 예정:

- Image Metadata
- Video Metadata
- EXIF 분석


---

# Timeline Analysis

여러 Artifact의 시간 정보를 통합하여 사건 흐름을 제공합니다.

분석 대상:

- 파일 생성/수정/접근 시간
- Registry 변경 시간
- 프로그램 실행 기록
- Browser 활동
- Event Log


기능:

- 시간순 이벤트 표시
- 이벤트 필터링
- 주요 증거 지정
- AI 기반 사건 흐름 요약


---

# Search & Discovery

Evidence와 분석 결과를 빠르게 탐색합니다.

기능:

- Keyword Search
- Regex Search
- File Search
- Metadata Search
- Artifact Search
- Index 기반 검색
- 검색 결과 필터링


---

# Images / Videos Analysis

이미지 및 영상 Artifact 분석 기능입니다.

기능:

- 이미지 Metadata 분석
- EXIF 정보 확인
- GPS 정보 확인
- 영상 Metadata 분석
- Thumbnail 추출
- AI 기반 정보 분석


---

# Communications Analysis

사용자 통신 흔적 분석 기능입니다.

지원 예정:

- Browser Activity
- Email Artifact
- Messenger Artifact


분석:

- 방문 기록
- 검색 기록
- 다운로드 기록
- 파일 전송 기록
- 통신 관계 분석


---

# AI Report Generation

AI 기반 자동 포렌식 보고서 생성 기능입니다.

생성 내용:

- 사건 개요
- 분석 대상 정보
- Evidence 정보
- Artifact 분석 결과
- Timeline
- 주요 발견 사항
- 위험도 분석
- 결론 및 대응 방안


지원 예정:

- PDF Report
- HTML Report


---

# System Architecture

```text
                         User

                          |
                          v

                 Korean Forensic GUI

                          |
                          v

              Forensic Core Engine

        +-----------------+----------------+
        |                                  |
        v                                  v

 Analysis Result DB                 Context Manager

                                             |
                                             v

                                       MCP Adapter

                                             |
                                             v

                                          AI Agent
```


---

# Technology Structure

## Forensic Engine

담당:

- Evidence 처리
- File System 분석
- Artifact 분석
- Timeline 생성
- Search Engine
- Index / Cache
- 분석 Interface 제공


---

## MCP / AI Layer

담당:

- MCP Server
- Tool 정의
- LLM API 연동
- Prompt Engineering
- AI 분석 Workflow


---

## Frontend

담당:

- 한국어 GUI
- Case Explorer
- Evidence View
- Artifact View
- Timeline UI
- AI Assistant UI
- Report Preview


---

## Backend

담당:

- 데이터 관리
- Case 저장
- API 관리
- 분석 결과 저장
- Report 관리


---

# Reference Projects

## X-Ways Style Forensic Engine

참고 영역:

- 빠른 Evidence 탐색
- 분석 Workflow
- 성능 최적화 구조


## Autopsy

참고 영역:

- Case 기반 Workflow
- Artifact 분석 구조
- 사용자 친화적인 UI


## X-Ways Forensics MCP

참고 영역:

- MCP 기반 포렌식 기능 연결 방식
- 분석 Context 활용 구조


참고:

- https://github.com/tagalston101/x-way-forensics-tool
- https://github.com/sleuthkit/autopsy
- https://github.com/joyooosama/x-ways-forensics-mcp


---

# Development Status

## Completed

- [x] 전체 시스템 Architecture 설계
- [x] Forensic Engine 구조 설계
- [x] Database Schema 설계
- [x] API Interface 설계
- [x] JSON Schema v1 설계 및 검증
- [x] MCP 연동 구조 설계


## Planned

- [ ] Forensic Core Engine 구현
- [ ] Evidence Manager 구현
- [ ] File System Analyzer 구현
- [ ] Artifact Analyzer 구현
- [ ] Timeline Engine 구현
- [ ] Search Engine 구현
- [ ] Index / Cache 구현
- [ ] 한국어 GUI 구현
- [ ] MCP Adapter 구현
- [ ] LLM API 연동
- [ ] AI 분석 기능 구현
- [ ] AI Report 생성 기능 구현
- [ ] 성능 테스트 및 최적화


---

# License & Purpose

APEX는 합법적인 디지털 포렌식 조사, 보안 연구 및 교육 목적을 위해 개발됩니다.

AI가 생성한 분석 결과는 보조 자료이며, 최종 판단은 분석자가 원본 증거와 분석 근거를 검토한 후 수행해야 합니다.

모든 분석 과정은 원본 Evidence의 무결성을 유지하는 것을 원칙으로 합니다.
