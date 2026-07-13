# 요구사항 추적표

## 1. 기능 요구사항

| ID | 요구사항 | 설계 위치 | 구현 Phase | 검증 |
| --- | --- | --- | --- | --- |
| FR-001 | Case 생성/관리 | Architecture §4, DB `cases`, API §3 | 1 | Case API/DB Integration |
| FR-002 | Evidence 등록/Metadata | Architecture §5, DB `evidence_sources`, API §4 | 1 | Reader Contract/Schema |
| FR-003 | MD5/SHA-256 Hash | Architecture §10, DB `evidence_hashes` | 1 | Known Digest Fixture |
| FR-004 | Directory 지원 | Evidence Adapter 표 | 1 | Directory Fixture |
| FR-005 | RAW/DD 지원 | Evidence Adapter 표 | 2 | Partition/Bounds Fixture |
| FR-006 | E01 지원 | Evidence Adapter 표 | 2 | Segment/Hash Fixture |
| FR-007 | VHD/VHDX 지원 예정 | Roadmap 기술 Spike | 2 이후 | Capability/Format Fixture |
| FR-008 | 파일 목록/Tree | File Analyzer, API §6 | 2 | Cursor/Lazy Tree Test |
| FR-009 | File Metadata | DB `files`, File Schema | 2 | FS Fixture Comparison |
| FR-010 | 삭제 파일 탐색 | Reader Capability, API §4/6 | 2 | Deleted File Fixture |
| FR-011 | 파일 검색 | Search Module/API §9 | 4 | Exact/Path Query Test |
| FR-012 | Registry 분석 | Analyzer 표 | 3 | Hive Fixture/Provenance |
| FR-013 | Event Log 분석 | Analyzer 표 | 3 | EVTX Fixture/Provenance |
| FR-014 | Prefetch 분석 | Analyzer 표 | 3 | PF Fixture/Provenance |
| FR-015 | Browser History | Analyzer 표 | 5 | Profile DB Fixture |
| FR-016 | Multimedia Metadata | Analyzer 표 | 5 | EXIF/Media Fixture |
| FR-017 | 통합 Timeline | Timeline Module/API §8 | 4 | Projection/Dedup Test |
| FR-018 | Keyword Search | Search Module/API §9 | 4 | FTS Relevance/Filter Test |
| FR-019 | Regex Search | Search Module/API §9 | 4 | Timeout/Limit/Test Corpus |
| FR-020 | Index 기반 검색 | Storage/Search 설계 | 4 | Index Rebuild/Benchmark |
| FR-021 | Cache | Storage/DB `cache_entries` | 4 | Hash/LRU/Rebuild Test |
| FR-022 | JSON 결과 | API/Schema 문서 | 1부터 | JSON Schema Contract |
| FR-023 | MCP Wrapping 가능한 Interface | API §1, §13 | 7 | Public API Reference Client |

## 2. 최적화 및 품질 요구사항

| ID | 요구사항 | 설계 결정 | 검증 |
| --- | --- | --- | --- |
| NFR-001 | Multi Processing | CPU 작업 Process Pool | 처리량과 Worker Crash Recovery |
| NFR-002 | Async Processing | Job + I/O Async/Thread Pool | 상태 전이, 취소, 재개 |
| NFR-003 | Index Database | SQLite FTS5 Port | 대규모 Fixture Query P95 |
| NFR-004 | Cache Layer | SHA-256 Content Cache | Hit/Miss/손상/Quota |
| NFR-005 | Lazy Loading | Parent/Cursor File API | 100만 행 Memory/Page Test |
| NFR-006 | 증거 무결성 | Read-only Reader, Hash, Audit | Write Attempt/Hash Fixture |
| NFR-007 | 분석 추적성 | Provenance와 Analyzer Run | Artifact-to-byte 역추적 |
| NFR-008 | 장애 격리 | Batch, `PARTIAL`, 구조화 오류 | 손상 파일 Mixed Fixture |
| NFR-009 | 결정성 | Canonical JSON, Version, Fingerprint | 동일 입력 반복 결과 비교 |
| NFR-010 | 확장성 | Port/Adapter, Analyzer Manifest | Fake Adapter Contract Test |
| NFR-011 | API 호환성 | `/api/v1`, Schema Version | Breaking Change 검사 |
| NFR-012 | Resource 보호 | Bounded Queue, Range/Regex Limit | 부하/DoS Test |

## 3. 개발 규칙

| ID | 규칙 | 준수 방식 |
| --- | --- | --- |
| DR-001 | Python 기반 | `src/apex` Python Package 제안 |
| DR-002 | 명확한 모듈 분리 | Domain/Application/Port/Adapter/Analyzer 경계 |
| DR-003 | MCP 코드 금지 | MCP Adapter를 별도 Component로 명시 |
| DR-004 | LLM API 코드 금지 | AI Layer에는 Port/DTO만 허용 |
| DR-005 | Prompt Engineering 금지 | Prompt/Agent를 금지 범위로 명시 |
| DR-006 | JSON 반환 | `/api/v1`과 `schemas/v1` 계약 |
| DR-007 | 추후 Tool Wrapping | Capability, Async Job, Stable IDs, JSON Schema |

## 4. AI Layer 추가 조건

| ID | 조건 | 반영 위치 | 검증 |
| --- | --- | --- | --- |
| AI-001 | 특정 Provider 미지정 | Architecture §9, AI Schema | Provider 필드 부재 검사 |
| AI-002 | 별도 모듈 | Directory `ai_layer`, Module §10 | Dependency Rule Test |
| AI-003 | 선택 기능 | 기본 비활성/Null Adapter | Adapter 없는 E2E Test |
| AI-004 | Fact 비변조 | 별도 `ai_enrichments` | Artifact Row 불변성 Test |
| AI-005 | 근거 추적 | Citation 필수 Schema | Citation Validation |

## 5. 설계 완료 판정

- [x] 전체 Architecture
- [x] Directory Structure
- [x] Module 역할
- [x] Database Schema
- [x] API Interface
- [x] JSON Schema 초안
- [x] 단계별 구현 Roadmap
- [x] 요구사항 추적표
- [ ] 구현 기술 Spike 결과
- [ ] 성능 Baseline과 수치 목표

마지막 두 항목은 코드 구현 전/초기 Phase에 실제 Library와 Fixture를 사용해 측정해야 하며,
설계 문서만으로 임의 수치를 확정하지 않는다.
