# Database Schema 설계

## 1. 저장 전략

MVP는 **Case별 SQLite 데이터베이스**를 사용한다. 각 Case가 이동 가능한 하나의 분석 단위가
되고, Case별 단일 Writer와 WAL Mode로 쓰기 경합을 제한한다. 각 `case.sqlite`의 `cases`
테이블은 정확히 한 행을 가지며 같은 DB의 모든 FK 기준이 된다. Workspace의 `catalog.sqlite`는
Case ID, 이름, 상태와 DB 위치만 가진 재구성 가능한 목록이다. Repository Port를 유지해 향후
다중 사용자 환경에서 PostgreSQL으로 교체할 수 있다.

기본 설정:

```sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 5000;
```

모든 ID는 API에서 UUID 문자열로 표현하고 SQLite에는 36자 `TEXT`로 저장한다. Timestamp는
UTC ISO 8601 문자열(`TEXT`)을 사용한다. JSON 컬럼은 Canonical JSON `TEXT`이며 저장 전
Schema 검증을 수행한다.

## 2. Case와 Evidence

### `cases`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Case UUID |
| `name` | TEXT | NOT NULL | Case 이름 |
| `description` | TEXT | NULL | 설명 |
| `status` | TEXT | NOT NULL, CHECK | `OPEN`, `CLOSED`, `ARCHIVED` |
| `locale` | TEXT | NOT NULL DEFAULT `ko-KR` | BCP 47 Locale |
| `timezone` | TEXT | NOT NULL DEFAULT `Asia/Seoul` | IANA Timezone |
| `created_at` | TEXT | NOT NULL | 생성 UTC |
| `created_by` | TEXT | NULL | 사용자/시스템 식별자 |
| `closed_at` | TEXT | NULL | 종료 UTC |
| `engine_version` | TEXT | NOT NULL | 생성 Engine 버전 |
| `metadata_json` | TEXT | NOT NULL DEFAULT `{}` | 확장 Metadata |

### `evidence_sources`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Evidence UUID |
| `case_id` | TEXT | FK `cases(id)`, NOT NULL | 소속 Case |
| `display_name` | TEXT | NOT NULL | 표시 이름 |
| `source_uri` | TEXT | NOT NULL | 원본 경로/URI, API에서 권한 통제 |
| `format` | TEXT | NOT NULL | `DIRECTORY`, `RAW`, `E01`, `VHD`, `VHDX` |
| `status` | TEXT | NOT NULL | `REGISTERED`, `HASHING`, `READY`, `FAILED` |
| `size_bytes` | INTEGER | NOT NULL, CHECK >= 0 | 논리 크기 |
| `sector_size` | INTEGER | NULL, CHECK > 0 | Sector 크기 |
| `read_only` | INTEGER | NOT NULL CHECK = 1 | 항상 1 |
| `acquired_at` | TEXT | NULL | 취득 시각 |
| `registered_at` | TEXT | NOT NULL | 등록 시각 |
| `registered_by` | TEXT | NULL | 등록 주체 |
| `reader_id` | TEXT | NOT NULL | Adapter 식별자 |
| `reader_version` | TEXT | NOT NULL | Adapter 버전 |
| `capabilities_json` | TEXT | NOT NULL | 지원 Capability 목록 |
| `metadata_json` | TEXT | NOT NULL DEFAULT `{}` | 형식별 Metadata |
| `error_json` | TEXT | NULL | 등록/Reader 오류 |

Index: `(case_id, status)`, `(case_id, format)`. 같은 실제 파일을 중복 등록할 수 있으므로
`source_uri`에 Unique를 강제하지 않고 중복 여부를 경고한다.

### `evidence_hashes`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Hash 실행 결과 UUID |
| `evidence_id` | TEXT | FK, NOT NULL | 대상 Evidence |
| `algorithm` | TEXT | NOT NULL | `SHA256`, `MD5`, 선택적 `SHA512` |
| `digest_hex` | TEXT | NOT NULL | 소문자 Hex Digest |
| `scope` | TEXT | NOT NULL | `FULL_SOURCE`, `LOGICAL_STREAM` |
| `bytes_hashed` | INTEGER | NOT NULL | 실제 처리 Byte |
| `started_at` | TEXT | NOT NULL | 시작 UTC |
| `completed_at` | TEXT | NOT NULL | 완료 UTC |
| `job_id` | TEXT | FK `ingest_jobs(id)` | 계산 Job |
| `verified_against` | TEXT | NULL | Embedded/제공 Hash |
| `verification_status` | TEXT | NOT NULL | `NOT_CHECKED`, `MATCH`, `MISMATCH` |

Unique: `(evidence_id, algorithm, scope, digest_hex)`.

## 3. Object와 파일 시스템

### `objects`

Evidence 내부 계층을 공통 Object ID로 표현한다.

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Object UUID |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `parent_id` | TEXT | FK `objects(id)`, NULL | 상위 Object |
| `object_type` | TEXT | NOT NULL | `EVIDENCE`, `VOLUME`, `FILESYSTEM`, `DIRECTORY`, `FILE` |
| `sequence_no` | INTEGER | NULL | 원본 FS Sequence/Inode 보조값 |
| `created_at` | TEXT | NOT NULL | DB 등록 시각 |

Index: `(evidence_id, parent_id, object_type)`, `(parent_id, sequence_no)`.

### `file_systems`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | File System UUID |
| `object_id` | TEXT | FK `objects(id)`, UNIQUE | 대응 Object |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `fs_type` | TEXT | NOT NULL | NTFS, FAT, EXFAT 등 |
| `offset_bytes` | INTEGER | NOT NULL | Evidence 내 시작 Offset |
| `size_bytes` | INTEGER | NOT NULL | 논리 크기 |
| `block_size` | INTEGER | NULL | Block/Cluster 크기 |
| `label` | TEXT | NULL | Volume Label |
| `serial_number` | TEXT | NULL | File System 식별자 |
| `metadata_json` | TEXT | NOT NULL DEFAULT `{}` | 형식별 Metadata |

### `files`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | File UUID |
| `object_id` | TEXT | FK `objects(id)`, UNIQUE | 대응 Object |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `file_system_id` | TEXT | FK `file_systems(id)`, NULL | 소속 FS |
| `parent_file_id` | TEXT | FK `files(id)`, NULL | 상위 Directory |
| `name` | TEXT | NOT NULL | 원본 이름 |
| `name_raw` | BLOB | NULL | Decoder가 손실 없이 보존할 원본 이름 Byte |
| `name_encoding` | TEXT | NULL | Raw 이름의 원본 Encoding/FS 규칙 |
| `name_normalized` | TEXT | NOT NULL | 검색용 정규화 이름 |
| `full_path` | TEXT | NOT NULL | Evidence 내부 경로 |
| `full_path_raw` | BLOB | NULL | 필요 시 원본 경로 Byte |
| `file_type` | TEXT | NOT NULL | `REGULAR`, `DIRECTORY`, `SYMLINK`, `STREAM`, `SPECIAL` |
| `mime_type` | TEXT | NULL | 판별된 MIME |
| `size_bytes` | INTEGER | NOT NULL CHECK >= 0 | 논리 크기 |
| `allocated` | INTEGER | NOT NULL | Allocation 여부 |
| `deleted` | INTEGER | NOT NULL | 삭제 추정 여부 |
| `hidden` | INTEGER | NOT NULL | Hidden 여부 |
| `metadata_address` | INTEGER | NULL | Inode/MFT Entry 등 |
| `data_source_ref` | TEXT | NULL | 형식별 Stream 참조 |
| `created_time_utc` | TEXT | NULL | 생성 시각 |
| `modified_time_utc` | TEXT | NULL | 수정 시각 |
| `accessed_time_utc` | TEXT | NULL | 접근 시각 |
| `changed_time_utc` | TEXT | NULL | Metadata 변경 시각 |
| `time_raw_json` | TEXT | NOT NULL DEFAULT `{}` | 원본 시간/Offset |
| `hash_sha256` | TEXT | NULL | 선택적 파일 Hash |
| `metadata_json` | TEXT | NOT NULL DEFAULT `{}` | 추가 Metadata |

Index: `(parent_file_id, name_normalized)`, `(evidence_id, full_path)`,
`(evidence_id, deleted)`, `(mime_type)`, 각 UTC 시간 컬럼. `full_path`는 표시/검색용이며 실제
읽기는 `object_id`와 Reader 참조를 사용한다.

### `file_extents`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | INTEGER | PK AUTOINCREMENT | Extent 순번 |
| `file_id` | TEXT | FK, NOT NULL | 대상 파일 |
| `sequence_no` | INTEGER | NOT NULL | 파일 내 순서 |
| `logical_offset` | INTEGER | NOT NULL | 파일 내 Offset |
| `source_offset` | INTEGER | NULL | Evidence 내 Offset |
| `length_bytes` | INTEGER | NOT NULL | 길이 |
| `is_sparse` | INTEGER | NOT NULL | Sparse 여부 |

Unique: `(file_id, sequence_no)`.

## 4. Job과 Analyzer 실행

### `ingest_jobs`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Job UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NULL | 대상 Evidence |
| `job_type` | TEXT | NOT NULL | `HASH`, `FS_INGEST`, `ARTIFACT`, `TIMELINE`, `INDEX`, `SEARCH`, `AI_ENRICHMENT`, `REPORT_DRAFT`, `REPORT_EXPORT` |
| `status` | TEXT | NOT NULL | `QUEUED`, `RUNNING`, `SUCCEEDED`, `PARTIAL`, `FAILED`, `CANCELLED` |
| `priority` | INTEGER | NOT NULL DEFAULT 100 | 낮을수록 우선 |
| `idempotency_key` | TEXT | NULL | 중복 Command 방지 |
| `config_json` | TEXT | NOT NULL | 검증된 실행 설정 |
| `progress_current` | INTEGER | NOT NULL DEFAULT 0 | 현재 단위 |
| `progress_total` | INTEGER | NULL | 전체 단위 |
| `progress_unit` | TEXT | NOT NULL | `BYTES`, `FILES`, `TASKS`, `UNKNOWN` |
| `queued_at` | TEXT | NOT NULL | 등록 UTC |
| `started_at` | TEXT | NULL | 시작 UTC |
| `finished_at` | TEXT | NULL | 종료 UTC |
| `cancel_requested_at` | TEXT | NULL | 취소 요청 UTC |
| `error_json` | TEXT | NULL | Job 오류 |

Unique partial index: `(case_id, idempotency_key)` where key is not null. Index:
`(case_id, status, priority, queued_at)`.

### `ingest_tasks`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Task UUID |
| `job_id` | TEXT | FK, NOT NULL | 상위 Job |
| `task_type` | TEXT | NOT NULL | Task 종류 |
| `status` | TEXT | NOT NULL | Job과 같은 상태 집합 |
| `attempt` | INTEGER | NOT NULL DEFAULT 0 | 시도 횟수 |
| `max_attempts` | INTEGER | NOT NULL DEFAULT 1 | 최대 시도 |
| `input_json` | TEXT | NOT NULL | Task 입력 참조 |
| `checkpoint_json` | TEXT | NULL | 재개 Cursor |
| `worker_id` | TEXT | NULL | 실행 Worker |
| `started_at` | TEXT | NULL | 시작 UTC |
| `finished_at` | TEXT | NULL | 종료 UTC |
| `error_json` | TEXT | NULL | 오류 |

Index: `(job_id, status)`, `(status, task_type)`.

### `analyzer_runs`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Run UUID |
| `job_id` | TEXT | FK, NOT NULL | Job |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `analyzer_id` | TEXT | NOT NULL | 안정적 Analyzer ID |
| `analyzer_version` | TEXT | NOT NULL | 구현 버전 |
| `config_hash` | TEXT | NOT NULL | Canonical 설정 SHA-256 |
| `input_fingerprint` | TEXT | NOT NULL | 입력 집합 Fingerprint |
| `status` | TEXT | NOT NULL | 실행 상태 |
| `processed_count` | INTEGER | NOT NULL DEFAULT 0 | 처리 대상 수 |
| `artifact_count` | INTEGER | NOT NULL DEFAULT 0 | 생성 Fact 수 |
| `warning_count` | INTEGER | NOT NULL DEFAULT 0 | 경고 수 |
| `started_at` | TEXT | NULL | 시작 UTC |
| `finished_at` | TEXT | NULL | 종료 UTC |
| `statistics_json` | TEXT | NOT NULL DEFAULT `{}` | 성능/결과 통계 |

Index: `(evidence_id, analyzer_id, status)`. 재사용 후보 Index:
`(input_fingerprint, analyzer_id, analyzer_version, config_hash)`.

## 5. Artifact와 Timeline

### `artifact_types`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK 복합 `(id, schema_version)` | 예: `windows.eventlog.record` |
| `schema_version` | TEXT | PK 복합 `(id, schema_version)` | Payload Schema 버전 |
| `display_name_key` | TEXT | NOT NULL | 다국어 표시명 Resource Key |
| `description_key` | TEXT | NOT NULL | 다국어 설명 Resource Key |
| `schema_uri` | TEXT | NOT NULL | JSON Schema URI |
| `analyzer_id` | TEXT | NOT NULL | 소유 Analyzer |
| `created_at` | TEXT | NOT NULL | 등록 UTC |

Primary Key는 `(id, schema_version)` 복합키다.

### `artifacts`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Artifact UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `source_object_id` | TEXT | FK `objects(id)`, NULL | 원본 Object |
| `analyzer_run_id` | TEXT | FK, NOT NULL | 생성 Run |
| `artifact_type` | TEXT | NOT NULL | Type ID |
| `schema_version` | TEXT | NOT NULL | Payload Schema 버전 |
| `source_path` | TEXT | NULL | 사람이 확인할 원본 경로 |
| `source_offset` | INTEGER | NULL | 원본 Byte/Record Offset |
| `source_length` | INTEGER | NULL | 원본 범위 길이 |
| `title` | TEXT | NOT NULL | 표시용 요약 |
| `payload_json` | TEXT | NOT NULL | Schema 검증된 불변 Fact |
| `search_text` | TEXT | NOT NULL DEFAULT `''` | Index용 정규화 Text |
| `confidence` | REAL | NOT NULL CHECK 0..1 | Parser 신뢰도 |
| `created_at` | TEXT | NOT NULL | Fact 저장 UTC |

FK: `(artifact_type, schema_version)` -> `artifact_types`. Index:
`(evidence_id, artifact_type)`, `(source_object_id)`, `(analyzer_run_id)`, `(created_at)`.

### `artifact_attributes`

빈번한 Filter용 Typed Attribute만 선택적으로 투영한다. 진실의 원본은 `payload_json`이다.

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | INTEGER | PK AUTOINCREMENT | 행 ID |
| `artifact_id` | TEXT | FK, NOT NULL | Artifact |
| `name` | TEXT | NOT NULL | Attribute 이름 |
| `value_type` | TEXT | NOT NULL | `TEXT`, `INTEGER`, `REAL`, `BOOLEAN`, `DATETIME`, `BYTES_REF` |
| `value_text` | TEXT | NULL | 문자열/시간 값 |
| `value_integer` | INTEGER | NULL | 정수/Boolean 값 |
| `value_real` | REAL | NULL | 실수 값 |
| `ordinal` | INTEGER | NOT NULL DEFAULT 0 | 다중 값 순서 |

Check: Typed Value 컬럼 중 정확히 하나만 값이 있어야 한다. Index:
`(name, value_text)`, `(name, value_integer)`, `(artifact_id, name)`.

### `timeline_events`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Event UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `source_kind` | TEXT | NOT NULL | `FILE`, `ARTIFACT` |
| `source_id` | TEXT | NOT NULL | File/Artifact ID |
| `timestamp_utc` | TEXT | NOT NULL | 정규화 UTC |
| `timestamp_raw` | TEXT | NULL | 원본 표현 |
| `timezone_offset_minutes` | INTEGER | NULL | 원본 Offset |
| `event_type` | TEXT | NOT NULL | 생성/실행/접속 등 |
| `title` | TEXT | NOT NULL | 짧은 설명 |
| `description` | TEXT | NULL | 상세 설명 |
| `actor` | TEXT | NULL | User/Process 등 |
| `path` | TEXT | NULL | 관련 경로 |
| `confidence` | REAL | NOT NULL CHECK 0..1 | 시간/Projection 신뢰도 |
| `dedup_key` | TEXT | NOT NULL | Source 내 결정적 중복키 |
| `metadata_json` | TEXT | NOT NULL DEFAULT `{}` | 추가 정보 |

Unique: `(source_kind, source_id, dedup_key)`. Index:
`(case_id, timestamp_utc, id)`, `(evidence_id, event_type, timestamp_utc)`.

## 6. Search와 Cache

### `search_documents`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | 문서 UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `source_kind` | TEXT | NOT NULL | `FILE`, `ARTIFACT`, `TIMELINE` |
| `source_id` | TEXT | NOT NULL | 원본 ID |
| `title` | TEXT | NOT NULL | 검색 제목 |
| `body` | TEXT | NOT NULL | 검색 본문 |
| `path` | TEXT | NULL | 관련 경로 |
| `content_hash` | TEXT | NOT NULL | 재색인 판정용 Hash |
| `normalization_profile` | TEXT | NOT NULL | 예: `NFKC_CASEFOLD_V1` |
| `indexed_at` | TEXT | NOT NULL | Index 시각 |

Unique: `(source_kind, source_id)`. FTS5 Virtual Table `search_documents_fts`는 `title`, `body`,
`path`를 External Content 방식으로 색인한다. Trigger 또는 명시적 Index Service로 동기화한다.
원본 `title/body/path`는 보존하고 FTS 입력용 사본만 정규화한다. 한국어 Tokenizer는 교체 가능한
Index Adapter 설정이며 Profile/Version을 기록한다.

### `search_queries`

AI Context 또는 Report에 사용한 검색 조건을 재현하기 위한 불변 Query Snapshot이다.

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Query UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `mode` | TEXT | NOT NULL | `KEYWORD`, `EXACT`, `REGEX` |
| `query_text` | TEXT | NOT NULL | 원본 Query |
| `query_normalized` | TEXT | NOT NULL | 검색용 정규화 Query |
| `scope_json` | TEXT | NOT NULL | File/Artifact/Timeline Scope |
| `filters_json` | TEXT | NOT NULL | Evidence/Type/시간 Filter |
| `index_version` | TEXT | NOT NULL | 실행 Index Version |
| `created_by` | TEXT | NOT NULL | 실행 사용자 |
| `created_at` | TEXT | NOT NULL | 실행 UTC |

### `search_results`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | 안정적인 Search Result UUID |
| `query_id` | TEXT | FK `search_queries(id)`, NOT NULL | Query Snapshot |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `source_kind` | TEXT | NOT NULL | `FILE`, `ARTIFACT`, `TIMELINE` |
| `source_id` | TEXT | NOT NULL | 원본 결과 ID |
| `rank` | INTEGER | NOT NULL | 결과 순서 |
| `score` | REAL | NOT NULL | Index 점수 |
| `snippet` | TEXT | NULL | 당시 표시 Snippet |
| `matched_fields_json` | TEXT | NOT NULL | 일치 필드 |
| `created_at` | TEXT | NOT NULL | 결과 고정 UTC |

Unique: `(query_id, source_kind, source_id)`. 일반 대화형 검색은 모든 Hit를 저장하지 않아도
되지만 Context/Report에 선택된 Hit는 반드시 `search_queries`와 `search_results`로 고정한다.

### `cache_entries`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `key_sha256` | TEXT | PK | Cache Key/내용 주소 |
| `case_id` | TEXT | FK, NOT NULL | Namespace |
| `kind` | TEXT | NOT NULL | `EXTRACTED`, `THUMBNAIL`, `PARSER`, `INDEX` |
| `relative_path` | TEXT | NOT NULL | Cache Root 기준 경로 |
| `size_bytes` | INTEGER | NOT NULL | 크기 |
| `content_sha256` | TEXT | NOT NULL | 파일 검증 Hash |
| `created_at` | TEXT | NOT NULL | 생성 UTC |
| `last_accessed_at` | TEXT | NOT NULL | LRU 시각 |
| `expires_at` | TEXT | NULL | 만료 시각 |
| `producer_json` | TEXT | NOT NULL | Analyzer/Version/Input Fingerprint |

Index: `(case_id, kind, last_accessed_at)`, `(expires_at)`.

## 7. Context, Annotation과 Tag

Live UI Context는 Backend Session Store가 소유하며 Case DB에 매번 기록하지 않는다. 아래
Snapshot은 사용자가 명시적으로 저장하거나 AI/Report/Audit 요청이 참조할 때만 생성한다.

### `ui_context_snapshots`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Snapshot UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `session_id` | TEXT | NOT NULL | 원 Session 상관관계 ID |
| `reason` | TEXT | NOT NULL | `AUDIT`, `AI_REQUEST`, `REPORT`, `USER_SAVED` |
| `schema_version` | TEXT | NOT NULL | UI Context Schema Version |
| `context_json` | TEXT | NOT NULL | 검증된 불변 UI Context |
| `content_sha256` | TEXT | NOT NULL | Canonical JSON Hash |
| `created_by` | TEXT | NOT NULL | 생성 사용자 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Index: `(case_id, created_at)`, `(session_id, created_at)`. Snapshot은 Update하지 않는다.

### `analysis_context_snapshots`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Analysis Context UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `ui_context_snapshot_id` | TEXT | FK, NULL | 근거 UI Snapshot |
| `purpose` | TEXT | NOT NULL | `AI_ENRICHMENT`, `REPORT_DRAFT` 등 |
| `schema_version` | TEXT | NOT NULL | Analysis Context Schema Version |
| `context_json` | TEXT | NOT NULL | Resolve된 Result/Citation Bundle |
| `content_sha256` | TEXT | NOT NULL | Canonical JSON Hash |
| `created_by` | TEXT | NOT NULL | 생성 사용자/시스템 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Analysis Context는 다른 Case ID를 포함할 수 없으며 생성 시 모든 Source ID와 Citation을
검증한다. AI나 Report가 참조한 Snapshot은 보존 정책 기간 동안 삭제하지 않는다.

### `analyst_annotations`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Annotation UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `target_type` | TEXT | NOT NULL | `EVIDENCE`, `FILE`, `ARTIFACT`, `TIMELINE`, `SEARCH_RESULT` |
| `target_id` | TEXT | NOT NULL | 대상 ID |
| `body` | TEXT | NOT NULL | 분석자 작성 내용 |
| `locale` | TEXT | NOT NULL DEFAULT `ko-KR` | 작성 언어 |
| `created_by` | TEXT | NOT NULL | 분석자 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |
| `updated_at` | TEXT | NOT NULL | 수정 UTC |

### `tags`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Tag UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `name` | TEXT | NOT NULL | Tag 표시명 |
| `color` | TEXT | NULL | UI 색상 Token |
| `description` | TEXT | NULL | 설명 |
| `created_by` | TEXT | NOT NULL | 생성자 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(case_id, name)`.

### `tagged_items`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `tag_id` | TEXT | FK `tags(id)`, PK 복합 | Tag |
| `target_type` | TEXT | PK 복합 | `EVIDENCE`, `FILE`, `ARTIFACT`, `TIMELINE`, `SEARCH_RESULT` |
| `target_id` | TEXT | PK 복합 | 대상 ID |
| `tagged_by` | TEXT | NOT NULL | 사용자 |
| `tagged_at` | TEXT | NOT NULL | 지정 UTC |

Application Service가 `target_type + target_id`의 Case 소속과 존재 여부를 검증한다.

## 8. Report

### `reports`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Report UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `analysis_context_snapshot_id` | TEXT | FK, NULL | AI Draft 입력 Snapshot |
| `title` | TEXT | NOT NULL | 제목 |
| `locale` | TEXT | NOT NULL DEFAULT `ko-KR` | 보고서 언어 |
| `timezone` | TEXT | NOT NULL DEFAULT `Asia/Seoul` | 표시 Timezone |
| `status` | TEXT | NOT NULL | `DRAFT`, `GENERATING`, `REVIEW_REQUIRED`, `APPROVED`, `REJECTED`, `EXPORTING`, `EXPORTED`, `FAILED` |
| `template_id` | TEXT | NOT NULL | 한국어 등 Template ID |
| `version` | INTEGER | NOT NULL DEFAULT 1 | 내용 Revision |
| `created_by` | TEXT | NOT NULL | 생성 분석자 |
| `generated_by` | TEXT | NULL | AI Adapter/시스템 식별자, Provider 비종속 |
| `reviewed_by` | TEXT | NULL | 검토 분석자 |
| `approved_by` | TEXT | NULL | 승인 분석자 |
| `review_comment` | TEXT | NULL | 검토 의견 |
| `rejection_reason` | TEXT | NULL | 반려 사유 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |
| `updated_at` | TEXT | NOT NULL | 갱신 UTC |
| `approved_at` | TEXT | NULL | 승인 UTC |
| `approved_content_sha256` | TEXT | NULL | 승인 Version Canonical Hash |
| `failure_json` | TEXT | NULL | 생성/Export 오류 |

`approved_by`와 `approved_at`은 `APPROVED` 이후에만 존재한다. 승인된 내용을 수정하면 Version을
증가시키고 승인 필드를 비운 뒤 Review 상태로 되돌린다.

### `report_sections`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Section UUID |
| `report_id` | TEXT | FK, NOT NULL | Report |
| `report_version` | INTEGER | NOT NULL | 소속 Version |
| `section_type` | TEXT | NOT NULL | 개요, Evidence, Artifact, Timeline 등 고정 Type |
| `sort_order` | INTEGER | NOT NULL | 출력 순서 |
| `title_key` | TEXT | NOT NULL | 다국어 제목 Resource Key |
| `content` | TEXT | NOT NULL | 검토 가능한 중립 Markup |
| `author_kind` | TEXT | NOT NULL | `ANALYST`, `AI_DRAFT`, `SYSTEM` |
| `review_status` | TEXT | NOT NULL | `NOT_REVIEWED`, `REVIEWED`, `CHANGES_REQUESTED` |
| `updated_by` | TEXT | NOT NULL | 최종 수정자 |
| `updated_at` | TEXT | NOT NULL | 최종 수정 UTC |

Unique: `(report_id, report_version, section_type)`.

### Report 선택 Link

| Table | 복합 PK/FK | 역할 |
| --- | --- | --- |
| `report_evidence_links` | `(report_id, report_version, evidence_id)` | Evidence와 Hash 포함 |
| `report_artifact_links` | `(report_id, report_version, artifact_id)` | 주요 Artifact 포함 |
| `report_timeline_links` | `(report_id, report_version, timeline_event_id)` | Timeline Event 포함 |
| `report_search_result_links` | `(report_id, report_version, search_result_id)` | 고정 Search Result 포함 |
| `report_tag_links` | `(report_id, report_version, tag_id)` | 선택 Tag 기준 포함 |

각 Link에는 `selected_by`, `selected_at`을 기록한다. 승인 Version의 Link는 수정하지 않는다.

### `report_citations`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Citation UUID |
| `report_id` | TEXT | FK, NOT NULL | Report |
| `report_version` | INTEGER | NOT NULL | Report Version |
| `section_id` | TEXT | FK, NULL | 사용 Section |
| `label` | TEXT | NOT NULL | `CIT-001` 형식 |
| `source_kind` | TEXT | NOT NULL | Evidence/File/Artifact/Timeline/Search 등 |
| `source_id` | TEXT | NOT NULL | 실제 Source ID |
| `evidence_id` | TEXT | FK, NULL | Evidence |
| `source_path` | TEXT | NULL | 원본 경로 |
| `source_offset` | INTEGER | NULL | 원본 Offset |
| `source_reference` | TEXT | NULL | Record/Row 등 Locator |
| `citation_json` | TEXT | NOT NULL | Citation Schema Snapshot |
| `content_sha256` | TEXT | NULL | 인용 내용 Hash |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(report_id, report_version, label)`.

### `report_exports`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Export UUID |
| `report_id` | TEXT | FK, NOT NULL | Report |
| `report_version` | INTEGER | NOT NULL | 승인된 Version |
| `format` | TEXT | NOT NULL | `PDF`, `HTML` |
| `status` | TEXT | NOT NULL | `QUEUED`, `EXPORTING`, `EXPORTED`, `FAILED` |
| `relative_path` | TEXT | NULL | Export Root 기준 경로 |
| `content_sha256` | TEXT | NULL | 생성 파일 Hash |
| `template_version` | TEXT | NOT NULL | Renderer/Template Version |
| `created_by` | TEXT | NOT NULL | 요청 사용자 |
| `created_at` | TEXT | NOT NULL | 요청 UTC |
| `completed_at` | TEXT | NULL | 완료 UTC |
| `error_json` | TEXT | NULL | 실패 상세 |

Export Service는 Report의 현재 상태가 `APPROVED`이고 `report_version` 및
`approved_content_sha256`이 일치할 때만 Job을 생성한다.

## 9. 감사와 선택적 AI 보강

### `audit_events`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | INTEGER | PK AUTOINCREMENT | 단조 증가 순번 |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `occurred_at` | TEXT | NOT NULL | UTC |
| `actor_type` | TEXT | NOT NULL | `USER`, `SYSTEM`, `WORKER`, `EXTERNAL` |
| `actor_id` | TEXT | NULL | 주체 식별자 |
| `action` | TEXT | NOT NULL | 수행 동작 |
| `target_type` | TEXT | NOT NULL | 대상 종류 |
| `target_id` | TEXT | NULL | 대상 ID |
| `request_id` | TEXT | NULL | API 상관관계 ID |
| `details_json` | TEXT | NOT NULL DEFAULT `{}` | 민감정보 제외 세부사항 |
| `previous_event_hash` | TEXT | NULL | 이전 Audit Chain Hash |
| `event_hash` | TEXT | NOT NULL | 현재 Event Canonical Hash |

`audit_events`는 Application 권한으로 Update/Delete하지 않는다. `event_hash`는 변조 방지를
보조하지만 외부 서명이나 WORM 저장소를 대체하지 않는다.

### `ai_enrichments`

Core 분석과 물리적으로/논리적으로 분리된 선택 테이블이다.

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `id` | TEXT | PK | Enrichment UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `request_id` | TEXT | NOT NULL | 보강 요청 ID |
| `analysis_context_snapshot_id` | TEXT | FK, NOT NULL | 입력 Context Snapshot |
| `status` | TEXT | NOT NULL | `PENDING`, `SUCCEEDED`, `FAILED` |
| `locale` | TEXT | NOT NULL DEFAULT `ko-KR` | 출력 언어 |
| `input_fingerprint` | TEXT | NOT NULL | 입력 Bundle Hash |
| `adapter_ref` | TEXT | NULL | Provider 비종속 구현 식별자 |
| `result_json` | TEXT | NULL | `ai-enrichment` Schema 결과 |
| `error_json` | TEXT | NULL | 구조화 오류 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |
| `finished_at` | TEXT | NULL | 종료 UTC |

Core의 `artifacts`와 FK로 강결합하지 않고 Citation 배열로 Source ID를 참조한다. AI 결과를
삭제해도 Core Fact와 Timeline/Search 결과는 유지된다.

### `schema_versions`

| 컬럼 | 타입 | 제약 | 설명 |
| --- | --- | --- | --- |
| `component` | TEXT | PK 복합 | `database`, `api`, `artifact:*` |
| `version` | TEXT | PK 복합 | 적용 버전 |
| `applied_at` | TEXT | NOT NULL | 적용 UTC |
| `checksum` | TEXT | NOT NULL | Migration/Schema SHA-256 |

## 10. 데이터 보존 규칙

1. Evidence 원본은 DB에 복사하지 않고 읽기 전용 참조와 Hash를 보존한다.
2. Artifact Payload는 생성 후 수정하지 않는다. Parser 변경은 새 Analyzer Run과 새 Artifact를
   만든다.
3. Timeline, Search Document와 Cache는 재생성 가능하다. Report/AI/Audit가 참조한 Search
   Result, Context Snapshot, Citation과 AI Enrichment는 재현성 보존 대상이다.
4. Case 삭제 기능은 기본 API에서 제공하지 않는다. 별도 관리 절차와 감사 기록이 필요하다.
5. DB Migration은 전·후 Integrity Check, Backup, Checksum 검증을 수행한다.
6. Live UI Context는 Session 만료 시 폐기하며 명시적 Snapshot만 Case 보존 정책을 따른다.
7. 승인된 Report Version과 Export는 Append-only로 취급하고 수정 시 새 Version을 생성한다.
