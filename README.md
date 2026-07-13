# APEX Digital Forensic Tool

APEX는 디지털 증거 분석의 접근성과 자동화를 목표로 개발하는 **AI 기반 디지털 포렌식 분석 플랫폼**입니다.

기존 디지털 포렌식 도구는 높은 전문 지식과 복잡한 분석 과정을 요구하며, 분석 결과를 정리하고 보고서를 작성하는 과정에도 많은 시간이 필요합니다.

APEX는 이러한 문제를 해결하기 위해:

- X-Ways Forensics의 빠른 분석 구조
- Autopsy의 사용자 친화적인 분석 Workflow
- MCP 기반 AI Agent 연동 구조

를 참고하여 누구나 접근 가능한 차세대 DFIR 분석 환경을 제공하는 것을 목표로 합니다.

---

# 핵심 차별점

## 1. 한국어 기반 디지털 포렌식 환경

기존 포렌식 도구는 대부분 영문 UI와 전문 용어 중심으로 구성되어 있어 입문자와 비전공자가 사용하기 어렵습니다.

APEX는 다음 영역에서 한국어 기반 환경을 제공합니다.

- 한국어 UI
- Artifact 분석 결과 한국어 설명
- 한국어 자연어 기반 AI 질의
- 한국어 포렌식 보고서 생성
- 분석 결과 및 위험도 설명

이를 통해 디지털 포렌식 분석 과정의 진입 장벽을 낮추는 것을 목표로 합니다.

---

# 2. 기본 내장 MCP 기반 AI Forensic Assistant

APEX는 단순히 외부 AI 서비스를 연결하는 방식이 아닌, 포렌식 분석 환경 내부에 MCP 기반 AI 연동 구조를 포함합니다.

AI는 포렌식 엔진을 직접 대체하지 않고, 분석자가 수행한 작업과 구조화된 분석 결과를 기반으로 보조 역할을 수행합니다.

## 분석 Context 기반 AI 구조

```text
사용자
 |
 v
Autopsy Style GUI
 |
 |  분석 작업 수행
 |
 v
Forensic Core Engine
 |
 +----------------------+
 |                      |
 v                      v
Analysis Result     Context Manager
Database                  |
                          v
                    MCP Server
                          |
                          v
                       AI Agent
```

---

## 동작 방식

1. 사용자가 GUI에서 Evidence 추가 및 Artifact 분석 수행

2. Forensic Engine이 분석 결과 저장

3. 분석 Case, 선택 Artifact, Timeline, 결과 정보를 Context로 관리

4. MCP가 해당 Context를 AI Agent에게 제공

5. AI는 기존 분석 결과를 기반으로 설명 및 추가 분석 수행


예:

사용자가 GUI에서:

```
Registry
 └ Run Key 분석
```

을 수행하면,


분석 결과:

```json
{
  "artifact": "registry",
  "type": "run_key",
  "finding": {
    "value": "update.exe",
    "risk": "high"
  }
}
```

저장.


사용자가 AI에게:

> "이 결과가 위험한 이유를 설명해줘"


라고 요청하면 AI는 현재 분석 Context를 기반으로:

```
Registry Run Key에서 자동 실행 등록 흔적이 확인되었습니다.

해당 항목은 Persistence 기법으로 악용될 가능성이 있습니다.

관련 증거:
- Registry Path
- 실행 파일 정보
- 생성 시간
```

형태로 설명합니다.

---

# 3. 빠른 분석 엔진 최적화

APEX는 대용량 디지털 증거 분석 환경을 고려하여 빠르고 효율적인 분석 엔진 개발을 목표로 합니다.

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

- 사건 생성
- 기존 사건 불러오기
- 사건 정보 관리
- Evidence 및 분석 결과 관리
- Timeline 및 Report 관리


---

## Data Source Management

지원 예정:

- E01
- RAW/DD
- IMG
- VHD/VHDX
- Logical File


기능:

- Evidence 등록
- Metadata 확인
- Hash 계산
- 무결성 검증


---

## File System Analysis

기능:

- 파일 탐색
- Directory Tree 표시
- 파일 Metadata 분석
- 삭제 파일 탐색
- 파일 검색
- 파일 유형 분류


---

## Artifact Analysis

지원 예정 Artifact:

### Windows

- Registry
- Event Log
- Prefetch


### User Activity

- Browser History
- Download History
- Recent Activity


### Multimedia

- Image Metadata
- Video Metadata
- EXIF 분석


### Communication

- Email
- Messenger Artifact
- 통신 흔적 분석


---

## Timeline Analysis

여러 Artifact의 시간 정보를 통합하여 사건 흐름을 분석합니다.

지원:

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

## Search & Discovery

기능:

- Keyword Search
- Regex Search
- Metadata Search
- Artifact Search
- Index 기반 검색
- 검색 결과 필터링


---

## AI Analysis

AI Assistant 기능:

- 자연어 기반 분석 요청
- 현재 Case Context 이해
- Artifact 결과 설명
- 의심 행위 분석
- 증거 간 연관 분석
- Timeline 요약
- 추가 분석 제안


---

## Generate Report

AI 기반 자동 보고서 생성 기능.

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

# 시스템 구조

```text
                         사용자

                           |
                           v

                  Korean Forensic GUI

                           |
             +-------------+-------------+
             |                           |
             v                           v

      Forensic Core Engine          AI Assistant

             |                           |
             |                           v

             |                    MCP Server
             |
     ---------------------
     |          |        |
     v          v        v

 Evidence   Artifact  Timeline
 Manager    Analyzer   Engine


             |
             v

      Analysis Database
      Index / Cache
```

---

# 프로젝트 참고

## X-Ways 스타일 포렌식 엔진

참고 영역:

- 빠른 Evidence 탐색
- 분석 Workflow
- 대용량 데이터 처리 구조


## Autopsy

참고 영역:

- Case 기반 Workflow
- Artifact 구조
- 사용자 친화적인 분석 화면


## X-Ways Forensics MCP

참고 영역:

- 포렌식 기능과 AI Agent 연결 구조
- MCP 기반 Tool 호출 방식
- 분석 Context 활용 방식


---

# 개발 진행 상태

## 완료

- [x] 전체 시스템 구조 설계
- [x] 포렌식 엔진 아키텍처 설계
- [x] Database Schema 설계
- [x] API Interface 설계
- [x] JSON Schema v1 설계
- [x] MCP 연동 구조 설계


## 개발 예정

- [ ] 포렌식 Core Engine 구현
- [ ] Evidence Manager 구현
- [ ] File System Analyzer 구현
- [ ] Artifact Analyzer 구현
- [ ] Timeline Engine 구현
- [ ] Search Engine 구현
- [ ] 한국어 GUI 구현
- [ ] MCP Server 연동
- [ ] AI 분석 기능 구현
- [ ] AI Report 생성 기능 구현
- [ ] 성능 최적화 및 테스트


---

# License & Purpose

APEX는 합법적인 디지털 포렌식 조사, 보안 연구 및 교육 목적을 위해 개발됩니다.

AI가 생성한 분석 결과는 보조 자료이며, 최종 판단은 분석자가 원본 증거와 분석 근거를 검토한 후 수행해야 합니다.

모든 분석 과정은 원본 Evidence의 무결성을 유지하는 것을 원칙으로 합니다.
