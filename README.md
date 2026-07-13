# APEX Digital Forensic Tool

APEX는 X-Ways Forensics의 빠른 분석 구조와 Autopsy의 사용자 친화적인 분석 흐름을 참고하여 개발하는 디지털 포렌식 분석 도구입니다.

본 프로젝트는 다음 세 가지를 핵심 차별점으로 합니다.

- 한국어 기반 사용자 인터페이스 및 분석 결과 제공
- MCP가 기본 내장된 AI 포렌식 분석 환경
- 대용량 증거 데이터 처리를 위한 분석 엔진 최적화

## feat/forensic-engine 브랜치

이 브랜치는 APEX의 포렌식 핵심 엔진과 관련된 기능을 개발하는 브랜치입니다.

MCP 서버, LLM API, 프롬프트 엔지니어링 기능은 별도 담당자가 개발하며, 본 브랜치에서는 MCP가 호출할 수 있는 포렌식 분석 기능과 구조화된 결과 인터페이스를 제공합니다.

## 담당 범위

### Evidence Manager

- Case 단위 증거 관리
- 디스크 이미지 및 논리 파일 등록
- 증거 데이터 메타데이터 관리
- MD5, SHA-1, SHA-256 해시 계산
- 증거 데이터 무결성 검증

### File System Analyzer

- 디렉터리 트리 조회
- 파일 및 폴더 목록 조회
- 파일 메타데이터 추출
- 삭제 파일 탐색
- Lazy Loading 기반 대용량 데이터 조회

### Artifact Analyzer

초기 구현 대상은 다음과 같습니다.

- Windows Registry
- Windows Event Log
- Windows Prefetch
- Browser History
- Image 및 Video Metadata

각 분석기는 독립적인 모듈로 구성하여 확장할 수 있도록 설계합니다.

### Timeline Engine

- 파일 생성·수정·접근 시간 통합
- Artifact 분석 결과의 시간 정보 통합
- 시간순 사건 흐름 생성
- GUI 및 MCP에서 사용할 수 있는 구조화된 Timeline 결과 제공

### Search Engine

- 파일명 검색
- 키워드 검색
- 정규식 검색
- 인덱스 기반 검색
- 검색 결과 캐싱

### Interface Layer

포렌식 엔진은 특정 AI 모델이나 MCP 구현에 의존하지 않습니다.

분석 결과는 JSON 형태로 반환하며, MCP 담당자가 이를 Tool로 감쌀 수 있도록 인터페이스를 제공합니다.

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
프로젝트 구조
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
설계 원칙
포렌식 엔진과 AI 계층 분리
MCP 코드 및 LLM Provider 코드 미포함
분석 모듈의 독립성 유지
대용량 Evidence를 고려한 Lazy Loading 적용
병렬 처리, 인덱스 및 캐시 구조 적용
모든 분석 결과를 검증 가능한 JSON Schema로 제공
사실, 추론 및 AI 보강 결과를 명확하게 분리
참고 프로젝트
X-Ways 스타일 포렌식 엔진 구조
Autopsy 분석 Workflow 및 Artifact 구조
X-Ways Forensics MCP의 포렌식 기능 연동 방식
개발 상태

현재 완료된 항목:

전체 포렌식 엔진 아키텍처 설계
모듈 책임 분리
데이터베이스 스키마 설계
API 인터페이스 설계
구현 로드맵 작성
JSON Schema v1 작성 및 검증

다음 개발 예정 항목:

프로젝트 기본 패키지 구조 생성
Case 및 Evidence Manager 구현
Hash 계산 및 무결성 검증 구현
File System Analyzer 구현
Artifact Analyzer 구현
Timeline 및 Search Engine 구현
성능 측정 및 최적화

README 전체를 이 내용으로 교체해도 되고, 기존 README가 팀 공통 소개를 담고 있다면 아래 부분만 추가해도 됨.

```markdown
## Forensic Engine

`feat/forensic-engine` 브랜치는 Evidence 관리, 파일 시스템 분석, Artifact 분석, Timeline 생성, 검색 및 캐시 최적화를 담당합니다.

MCP 및 LLM 구현과 분리된 Provider-neutral 구조를 사용하며, 분석 결과는 MCP와 GUI에서 사용할 수 있도록 JSON 형태로 제공합니다.

자세한 설계 문서는 [`docs/`](./docs)에서 확인할 수 있습니다.