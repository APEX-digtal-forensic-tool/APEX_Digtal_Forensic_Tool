# APEX Digital Forensic Tool

APEX는 디지털 증거 분석의 접근성과 자동화를 목표로 개발 중인 **AI 기반 디지털 포렌식 분석 플랫폼**입니다.

X-Ways Forensics의 빠른 분석 방식, Autopsy의 사용자 친화적인 분석 Workflow, MCP 기반 AI 연동 구조를 참고하여 다음과 같은 환경을 제공하는 것을 목표로 합니다.

- 한국어 중심의 포렌식 분석 환경
- MCP가 기본 내장된 AI 분석 기능
- 대용량 디지털 증거 처리를 위한 분석 엔진 최적화
- 분석 결과를 기반으로 한 AI 포렌식 보고서 자동 작성

> 현재 프로젝트는 설계 및 초기 개발 단계이며, 기능은 개발 진행 상황에 따라 변경될 수 있습니다.

---

## 핵심 차별점

### 1. 한국어 기반 사용자 환경

기존 디지털 포렌식 도구는 영문 UI와 전문 용어 중심으로 구성되어 있어 입문자와 비전공자가 사용하기 어렵다는 문제가 있습니다.

APEX는 다음 영역에서 한국어 지원을 제공합니다.

- 한국어 사용자 인터페이스
- Artifact 및 분석 항목의 한국어 설명
- 분석 결과의 한국어 요약
- 한국어 자연어 기반 AI 질의
- 한국어 디지털 포렌식 보고서 생성

---

### 2. 기본 내장 MCP

APEX는 AI 기능을 별도의 외부 프로그램으로 제공하는 것이 아니라, 포렌식 도구 내부에 MCP 연동 구조를 포함하는 것을 목표로 합니다.

MCP를 통해 AI는 다음 정보를 활용할 수 있습니다.

- 현재 열려 있는 Case 정보
- 등록된 Evidence 정보
- GUI에서 사용자가 선택한 파일 및 Artifact
- 포렌식 엔진의 분석 결과
- Timeline과 검색 결과
- 분석자가 지정한 태그 및 주요 증거

AI는 MCP를 통해 포렌식 엔진의 기능을 호출하고, 반환된 분석 결과를 바탕으로 사용자에게 설명을 제공합니다.

특정 AI 모델에 종속되지 않도록 설계하며, 향후 GPT, Claude, Gemini 및 Local LLM 등 다양한 Provider와 연결할 수 있는 구조를 목표로 합니다.

---

### 3. 빠른 분석 엔진

APEX는 대용량 디스크 이미지와 다수의 Artifact를 효율적으로 분석할 수 있도록 포렌식 엔진을 최적화하는 것을 목표로 합니다.

주요 최적화 방향은 다음과 같습니다.

- Lazy Loading 기반 파일 탐색
- Artifact 분석 작업 병렬 처리
- 인덱스 기반 검색
- 분석 결과 캐싱
- 변경되지 않은 데이터의 중복 분석 방지
- 대용량 Evidence 스트리밍 처리
- GUI와 분석 엔진의 비동기 작업 분리

---

## 주요 기능

### Case 관리

- 새로운 Case 생성
- 기존 Case 불러오기
- 사건명, 분석자, 사건 설명 관리
- Case별 Evidence 및 분석 결과 관리
- Case별 Timeline 및 보고서 관리
- 분석 진행 상태 저장 및 복원

### Data Source 추가

- 디스크 이미지 등록
- 논리 파일 및 폴더 등록
- Evidence 기본 정보 확인
- 파일 크기 및 형식 확인
- MD5, SHA-1, SHA-256 해시 계산
- Evidence 무결성 검증
- 등록된 Data Source 관리

지원 예정 형식:

- E01
- RAW
- DD
- IMG
- VHD
- VHDX
- 논리 파일 및 폴더

### File System 분석

- 디렉터리 트리 탐색
- 파일 및 폴더 목록 조회
- 파일 생성·수정·접근 시간 확인
- 파일 크기 및 형식 확인
- 파일 해시 확인
- 삭제 파일 탐색
- 파일 유형별 분류
- 파일 상세 정보 조회
- 대용량 디렉터리 Lazy Loading

### Images / Videos 분석

- 이미지 및 영상 파일 자동 분류
- 이미지 미리보기
- 영상 Thumbnail 생성
- EXIF Metadata 분석
- 촬영 시간 확인
- 카메라 및 기기 정보 확인
- GPS 정보 확인
- 영상 Codec 및 재생 시간 확인
- 삭제된 이미지 및 영상 탐색
- 분석 대상 파일 태그 지정

### Communications 분석

- Browser History 분석
- 방문 URL 확인
- 검색 기록 확인
- 다운로드 기록 확인
- 송신자 및 수신자 정보 확인
- 이메일 및 메시지 Artifact 분석
- 첨부파일 및 파일 전송 기록 확인
- 사용자와 대상 간 통신 관계 시각화
- 시간 및 사용자 기준 필터링

지원 범위는 확보 가능한 Artifact와 개발 우선순위에 따라 단계적으로 확장합니다.

### Timeline 분석

- 파일 생성·수정·접근 시간 통합
- Browser, Registry, Event Log 등 Artifact 시간 정보 통합
- 시간순 사건 흐름 표시
- 기간별 Timeline 필터링
- 이벤트 유형별 필터링
- 데이터 출처별 필터링
- 주요 이벤트 태그 지정
- AI 기반 사건 흐름 요약
- 보고서용 Timeline 선택

### Search 및 Discovery

- 파일명 검색
- 키워드 검색
- 정규식 검색
- Metadata 검색
- Artifact 유형별 검색
- 날짜 및 시간 범위 검색
- 인덱스 기반 빠른 검색
- 검색 결과 정렬 및 필터링
- 검색 결과에서 원본 파일 위치로 이동

### AI Forensic Assistant

- 한국어 자연어 질의
- 현재 GUI 화면과 선택 항목 인식
- Case 및 Evidence Context 활용
- 분석 결과 요약
- 의심 항목 설명
- 추가 분석 항목 추천
- MCP Tool을 이용한 포렌식 기능 호출
- Artifact 간 연관 관계 분석
- 시간순 사건 흐름 정리
- 분석 결과의 위험도 분류
- 증거와 추론의 구분 표시

AI는 포렌식 엔진을 대체하지 않으며, 엔진이 반환한 구조화된 분석 결과를 해석하고 정리하는 보조 기능으로 사용합니다.

### Generate Report

- Case 정보 자동 반영
- Evidence 정보 및 해시 반영
- 선택한 증거 항목 반영
- Images / Videos 분석 결과 반영
- Communications 분석 결과 반영
- Timeline 반영
- AI 분석 요약 반영
- 주요 발견 사항 자동 정리
- 결론 및 대응 권고 작성
- 한국어 보고서 생성
- PDF 및 HTML 형식 출력

보고서 생성 시 분석자는 포함할 증거와 내용을 직접 선택하고, AI가 작성한 문장을 검토한 후 최종 보고서를 생성할 수 있습니다.

---

## 사용자 이용 흐름

```text
프로그램 실행
    ↓
새 Case 생성 또는 기존 Case 열기
    ↓
Data Source 추가
    ↓
Evidence 해시 계산 및 무결성 확인
    ↓
파일 시스템 및 Artifact 분석
    ↓
Images / Videos, Communications 결과 확인
    ↓
Timeline 생성 및 주요 증거 태그 지정
    ↓
AI Forensic Assistant에 분석 요청
    ↓
AI가 MCP를 통해 추가 분석 기능 호출
    ↓
분석 결과와 근거 확인
    ↓
Generate Report 실행
    ↓
한국어 포렌식 보고서 생성
```

---

## 시스템 구조

```text
                         사용자
                            │
                            ▼
                  한국어 기반 포렌식 GUI
                     Autopsy Style UI
                            │
              ┌─────────────┴─────────────┐
              │                           │
              ▼                           ▼
       Application Backend         AI Assistant UI
              │                           │
              ▼                           ▼
       Forensic Core Engine          MCP Server
              │                           │
     ┌────────┼────────┐                  ▼
     │        │        │               LLM API
     ▼        ▼        ▼
 Evidence  Artifact  Timeline
 Manager   Analyzer   Engine
     │        │        │
     └────────┼────────┘
              ▼
       Index / Cache / Database
```

포렌식 엔진은 MCP 및 특정 AI 모델에 직접 의존하지 않습니다.

엔진은 분석 결과를 구조화된 JSON 형식으로 반환하고, MCP 담당 모듈이 해당 기능을 AI Tool로 연결합니다.

---

## 팀 역할

### Forensic Engine

- Evidence Manager
- File System Analyzer
- Artifact Analyzer
- Timeline Engine
- Search 및 Index Engine
- Cache 및 성능 최적화
- GUI와 MCP에서 사용할 엔진 인터페이스 제공

### MCP 및 AI

- MCP Server
- MCP Tool 정의
- LLM API 연동
- Prompt Engineering
- GUI Context 전달
- AI 분석 및 보고서 생성 Workflow

### Frontend

- 한국어 GUI
- Case Explorer
- Evidence 및 Artifact 결과 화면
- Images / Videos 화면
- Communications 화면
- Timeline 화면
- AI Assistant 화면
- 보고서 미리보기

### Backend

- Case 및 사용자 데이터 관리
- 분석 작업 상태 관리
- 데이터베이스 연동
- API 및 서비스 계층
- 결과 저장 및 조회
- 보고서 파일 관리

---

## 저장소 구조

```text
APEX_Digtal_Forensic_Tool/
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
│       ├── api-response.schema.json
│       ├── artifact.schema.json
│       ├── case.schema.json
│       ├── common.schema.json
│       ├── evidence.schema.json
│       ├── file.schema.json
│       ├── job.schema.json
│       ├── search.schema.json
│       └── timeline-event.schema.json
│
└── README.md
```

---

## 개발 진행 상태

### 완료

- [x] 전체 시스템 아키텍처 설계
- [x] 포렌식 엔진 모듈 책임 정의
- [x] 데이터베이스 스키마 설계
- [x] API 인터페이스 설계
- [x] JSON Schema v1 설계 및 검증
- [x] 초기 구현 로드맵 작성

### 개발 예정

- [ ] 프로젝트 기본 패키지 구조 생성
- [ ] Case 및 Evidence Manager 구현
- [ ] 해시 계산 및 무결성 검증 구현
- [ ] File System Analyzer 구현
- [ ] Images / Videos 분석 기능 구현
- [ ] Communications 분석 기능 구현
- [ ] Timeline Engine 구현
- [ ] Search 및 Index Engine 구현
- [ ] 한국어 GUI 구현
- [ ] MCP Server 및 Tool 연동
- [ ] LLM API 및 Prompt Engineering 적용
- [ ] AI 분석 기능 구현
- [ ] AI 보고서 생성 기능 구현
- [ ] 성능 측정 및 최적화

---

## 참고 프로젝트

- [X-Ways 스타일 포렌식 엔진](https://github.com/tagalston101/x-way-forensics-tool)
- [Autopsy](https://github.com/sleuthkit/autopsy)
- [X-Ways Forensics MCP](https://github.com/joyooosama/x-ways-forensics-mcp)

| 참고 프로젝트 | 참고 영역 |
|---|---|
| X-Ways 스타일 포렌식 엔진 | 빠른 증거 탐색 및 분석 엔진 구조 |
| Autopsy | Case 기반 Workflow, Artifact 구조 및 사용자 인터페이스 |
| X-Ways Forensics MCP | GUI와 포렌식 기능을 MCP로 연결하는 방식 |

APEX는 위 프로젝트들의 구조와 Workflow를 참고하지만, 특정 제품을 그대로 복제하는 것을 목표로 하지 않습니다. 외부 소스 코드를 직접 사용할 경우 해당 프로젝트의 라이선스와 저작권 조건을 확인합니다.

---

## 주의 사항

APEX는 합법적인 디지털 포렌식 조사, 보안 연구 및 교육을 목적으로 개발됩니다.

AI가 생성한 분석 결과와 보고서는 보조 자료이며, 최종 판단은 분석자가 원본 증거와 분석 근거를 직접 검증한 후 내려야 합니다. 원본 Evidence는 읽기 전용으로 처리하고, 모든 분석 과정에서 증거 무결성을 유지하는 것을 원칙으로 합니다.
