# APEX Digital Forensic Tool

APEX는 X-Ways Forensics의 빠른 분석 구조와 Autopsy의 사용자 친화적인 분석 흐름을 참고하여 개발하는 디지털 포렌식 분석 도구입니다.

본 프로젝트는 다음 세 가지를 핵심 차별점으로 합니다.

- 한국어 기반 사용자 인터페이스 및 분석 결과 제공
- MCP가 기본 내장된 AI 포렌식 분석 환경
- 대용량 디지털 증거 처리를 위한 분석 엔진 최적화

## `feat/forensic-engine` 브랜치

이 브랜치는 APEX의 포렌식 핵심 엔진과 관련된 기능을 개발하는 브랜치입니다.

MCP 서버, LLM API 연동 및 프롬프트 엔지니어링은 별도 담당자가 개발합니다. 본 브랜치에서는 GUI와 MCP에서 호출할 수 있는 포렌식 분석 기능과 구조화된 결과 인터페이스를 제공합니다.

## 담당 범위

### Evidence Manager

- Case 단위 증거 관리
- 디스크 이미지 및 논리 파일 등록
- 증거 데이터 메타데이터 관리
- MD5, SHA-1, SHA-256 해시 계산
- 증거 데이터 무결성 검증
- 분석 상태 및 처리 작업 관리

### File System Analyzer

- 디렉터리 트리 조회
- 파일 및 폴더 목록 조회
- 파일 메타데이터 추출
- 삭제 파일 탐색
- 파일 유형별 분류
- Lazy Loading 기반 대용량 데이터 조회

### Artifact Analyzer

초기 구현 대상은 다음과 같습니다.

- Windows Registry
- Windows Event Log
- Windows Prefetch
- Browser History
- Image 및 Video Metadata
- Communication Artifact

각 분석기는 독립적인 모듈로 구성하여 새로운 Artifact 분석 기능을 확장할 수 있도록 설계합니다.

### Timeline Engine

- 파일 생성·수정·접근 시간 통합
- Artifact 분석 결과의 시간 정보 통합
- 시간순 사건 흐름 생성
- 이벤트 유형 및 출처별 필터링
- GUI와 MCP에서 사용할 수 있는 구조화된 Timeline 결과 제공

### Search Engine

- 파일명 검색
- 키워드 검색
- 정규식 검색
- 메타데이터 검색
- 인덱스 기반 검색
- 검색 결과 캐싱

### Interface Layer

포렌식 엔진은 특정 AI 모델이나 MCP 구현에 직접 의존하지 않습니다.

분석 결과는 JSON 형태로 반환하며, MCP 담당자가 해당 인터페이스를 MCP Tool로 감싸서 사용할 수 있도록 설계합니다.

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

## 프로젝트 구조

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

## 설계 원칙

- 포렌식 엔진과 AI 계층 분리
- MCP 서버 및 LLM Provider 코드 미포함
- 분석 모듈 간 독립성 유지
- 대용량 Evidence를 고려한 Lazy Loading 적용
- 병렬 처리, 인덱스 및 캐시 구조 적용
- 모든 분석 결과를 검증 가능한 JSON Schema로 제공
- 사실, 분석 결과, 추론 및 AI 보강 결과를 명확하게 분리
- GUI와 MCP가 동일한 엔진 인터페이스를 사용하도록 설계
- 원본 증거를 변경하지 않는 읽기 전용 분석 원칙 적용

## 참고 프로젝트

- [X-Ways 스타일 포렌식 엔진](https://github.com/tagalston101/x-way-forensics-tool)
- [Autopsy](https://github.com/sleuthkit/autopsy)
- [X-Ways Forensics MCP](https://github.com/joyooosama/x-ways-forensics-mcp)

각 프로젝트는 다음 영역을 참고합니다.

| 참고 프로젝트 | 참고 영역 |
|---|---|
| X-Ways 스타일 포렌식 엔진 | 빠른 증거 탐색 및 분석 엔진 구조 |
| Autopsy | Case 기반 분석 Workflow, Artifact 구조 및 UI 구성 |
| X-Ways Forensics MCP | 포렌식 기능과 MCP 간 연동 방식 |

## 개발 상태

### 완료된 항목

- [x] 전체 포렌식 엔진 아키텍처 설계
- [x] 모듈별 책임 분리
- [x] 데이터베이스 스키마 설계
- [x] API 인터페이스 설계
- [x] 구현 로드맵 작성
- [x] JSON Schema v1 작성 및 검증

### 개발 예정 항목

- [ ] 프로젝트 기본 패키지 구조 생성
- [ ] Case 및 Evidence Manager 구현
- [ ] 해시 계산 및 무결성 검증 구현
- [ ] File System Analyzer 구현
- [ ] Artifact Analyzer 구현
- [ ] Timeline Engine 구현
- [ ] Search 및 Index Engine 구현
- [ ] Cache 및 병렬 처리 구조 구현
- [ ] GUI 연동용 인터페이스 구현
- [ ] MCP 연동용 엔진 인터페이스 제공
- [ ] 성능 측정 및 최적화

## 문서

상세 설계 문서는 [`docs/`](./docs) 디렉터리에서 확인할 수 있습니다.

JSON Schema는 [`schemas/v1/`](./schemas/v1) 디렉터리에서 확인할 수 있습니다.
