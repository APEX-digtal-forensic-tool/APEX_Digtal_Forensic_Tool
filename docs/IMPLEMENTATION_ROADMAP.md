# 단계별 구현 Roadmap

현재 단계는 **Phase 0: 설계 기준선**이다. 각 Phase는 앞 단계의 Acceptance Gate가 통과된
뒤 시작한다. 기능 수보다 증거 무결성과 재현 가능한 결과를 우선한다.

## Phase 0. 설계 기준선

범위:

- Architecture, Directory, Module, Database, API 설계
- 공통 JSON Schema v1
- 요구사항 추적표와 비기능 요구사항
- 기술 Spike 대상과 의사결정 항목 식별

완료 Gate:

- 모든 요구사항이 문서/Phase에 매핑됨
- JSON Schema가 Draft 2020-12 Validator에서 로드됨
- Core, AI Layer, 향후 MCP Adapter의 소유 경계가 명확함
- DB 키/관계와 API Resource ID가 일치함

## Phase 1. Case, Directory Evidence, Job 기반

구현:

- Python Package, Dependency/Quality Tooling
- Case 생성/조회와 Case별 SQLite Migration
- Directory Evidence Reader와 형식 Probe
- SHA-256/MD5 Streaming Hash
- Job State Machine, 단일 Writer, Audit Event
- Case/Evidence/Job HTTP API와 Schema Contract Test

Acceptance Gate:

- Evidence를 쓰기 모드로 열지 않음을 Test로 검증
- 동일 Fixture의 Hash가 기준값과 일치
- 중단/재개 시 중복 Fact 없이 종료
- 10만 파일 Directory 등록 중 Memory가 파일 수에 비례해 무한 증가하지 않음
- API Fixture가 `schemas/v1`을 통과

## Phase 2. RAW/E01과 File System Ingest

구현:

- RAW/DD Random Access와 Partition/Volume 열거
- E01 Adapter와 Segment/Embedded Hash 검증
- 우선 File System(NTFS 우선) 열거
- Object/File/Extent Batch 저장
- 삭제 파일 Capability와 Lazy Directory API
- VHD/VHDX 기술 Spike 및 Adapter 범위 확정

Acceptance Gate:

- 공인 또는 재현 가능한 소형 Fixture로 File Count/Path/Offset 비교
- 손상/누락 E01 Segment가 명시적 오류를 반환
- 삭제 항목 미지원 Reader가 빈 성공을 반환하지 않음
- 100만 File Metadata 조회에서 Cursor Page 응답 시간 목표 충족

초기 성능 목표는 Benchmark 환경을 문서화한 뒤 확정한다. 근거 없이 “Autopsy보다 빠름”을
선언하지 않고 동일 Hardware, Evidence, Analyzer Scope로 비교한다.

## Phase 3. 1순위 Artifact Analyzer

구현 순서:

1. Windows Registry
2. Windows Event Log
3. Windows Prefetch

각 Analyzer마다 Manifest, 후보 탐색, 독립 Parser, Artifact Payload Schema, 손상 Fixture,
Contract Test를 함께 제공한다.

Acceptance Gate:

- 정상/손상/부분 파일을 대상으로 Process Crash 없음
- 모든 Artifact가 Evidence/Object/Offset/Run으로 역추적됨
- Parser 버전 변경 시 이전 Run 결과를 덮어쓰지 않음
- Analyzer 하나의 실패가 다른 Analyzer 결과를 Rollback하지 않음

## Phase 4. Timeline, Search, Index, Cache

구현:

- File/Artifact Timeline Projector
- UTC/원본 시간/Timezone 보존
- SQLite FTS5 Index와 증분 재색인
- Keyword/Exact/제한된 Regex Search
- Content-addressed Cache, Quota, LRU, Hash 검증

Acceptance Gate:

- 같은 입력과 버전으로 결정적인 Timeline/Dedup Key 생성
- Index 재구축 전후 Query 의미가 동일
- Regex Timeout/후보/Pattern Limit이 실제로 작동
- Cache 전체 삭제 후 Fact 손실 없이 재생성

## Phase 5. 2순위 Artifact Analyzer

구현:

- Chromium/Firefox 계열 Browser History 최소 공통 모델
- EXIF/GPS, 기본 영상/음성 Container Metadata
- 개인정보 및 민감 Data 표시/로그 정책

Acceptance Gate:

- Browser Profile/DB/Table/Row Provenance 제공
- GPS/시간의 원본 값과 정규화 값 동시 보존
- 미지원 Codec/손상 Media가 전체 Job을 중단하지 않음

## Phase 6. Provider-neutral AI Layer 연결점

구현 범위는 Provider-neutral Port와 DTO, Null Adapter, 저장 격리까지만 포함한다.

- `AnalysisBundle` Builder
- `AIEnrichmentPort` Protocol
- `EnrichmentResult` Validator와 별도 저장소
- Citation 누락 거부, Feature Flag, 권한과 감사

금지 범위:

- LLM Provider SDK/API
- 모델 선택/설정
- Prompt Template/Agent Loop
- AI 결과로 Core Artifact Update

Acceptance Gate:

- AI Adapter 없이 Core Test와 모든 핵심 기능 통과
- Fake Adapter Contract Test 통과
- 모든 Finding에 유효한 Citation 존재
- Adapter 실패가 Ingest/Timeline/Search 상태를 변경하지 않음

## Phase 7. 외부 통합 준비

Core는 안정화된 API, Capability, Schema, Idempotency 및 Job Polling 계약을 제공한다. MCP
Server는 다른 담당자가 별도 Component로 구현하며 이 저장소에는 MCP SDK나 Tool 코드를
추가하지 않는다.

Acceptance Gate:

- 공개 API만 사용한 Reference Client End-to-End Test
- Schema/Capability Discovery로 Client가 기능 지원 여부 판별
- 장시간 작업의 생성, Polling/Event, 취소 흐름 검증
- API v1 호환성 검사 통과

## 공통 검증 Matrix

| 종류 | 최소 검증 |
| --- | --- |
| Unit | Domain 상태 규칙, Projector, Query Parser, Canonical Hash |
| Contract | Reader/Analyzer/Repository/AI Port, JSON Schema |
| Integration | Case DB, Migration, Worker/Writer, HTTP API |
| Forensic Fixture | 정상·삭제·손상·부분 이미지와 기대 Artifact |
| Property | Bounds, Path, Offset, Timestamp, Parser 비정상 입력 |
| Performance | 처리량, P95 Query, Peak RSS, Cache Hit, DB Batch |
| Security | Path Traversal, Regex DoS, Zip/Decompression Bomb, 권한 |
| Recovery | Process Kill, Disk Full, DB Lock, Cache 손상, 재개 |

## 구현 전 남은 기술 Spike

| 주제 | 확인할 결정 |
| --- | --- |
| File System Library | pytsk3/직접 Binding/대안의 Python 및 Windows 지원성 |
| E01 | libewf Binding의 Random Read, Thread/Process 안전성 |
| VHD/VHDX | libvhdi 또는 OS API의 읽기 전용·배포 가능성 |
| SQLite FTS5 | Tokenizer, 한글/Unicode, External Content 동기화 |
| Regex Engine | Timeout과 Linear-time 보장 가능한 Engine 선택 |
| Canonical JSON | RFC 8785 구현과 숫자/Unicode 처리 |
| HTTP Adapter | ASGI Framework 선택과 Binary Range Streaming |

