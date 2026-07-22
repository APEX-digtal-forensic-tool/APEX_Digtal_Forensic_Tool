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

## 11. Progressive Indexing

기존 `ingest_jobs`와 `ingest_tasks`는 범용 실행 상태를 유지한다. Progressive Index 전용
Profile, Scope, Checkpoint와 추세 데이터는 다음 Table로 분리한다. Live Progress Event는
Backend Session Store/Stream이 우선이며 재현과 장애 복구에 필요한 표본만 Case DB에 저장한다.

### `analysis_profiles`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Profile UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `name` | TEXT | NOT NULL | Profile 이름 |
| `profile_type` | TEXT | CHECK | `QUICK_TRIAGE`, `SELECTED_SCOPE`, `FULL_ANALYSIS`, `CUSTOM_PROFILE` |
| `revision` | INTEGER | NOT NULL, CHECK >= 1 | 불변 설정 Revision |
| `stages_json` | TEXT | NOT NULL | Stage 목록 |
| `hashing_mode` | TEXT | NOT NULL | `NONE`, `ON_DEMAND`, `FULL` |
| `analyzers_json` | TEXT | NOT NULL | Enable/Disable, Version 조건, Options |
| `scope_json` | TEXT | NOT NULL | Evidence/File/Path/Artifact/시간 범위 |
| `priority_policy` | TEXT | NOT NULL | 사용자 Scope 우선 정책 |
| `background_indexing` | INTEGER | NOT NULL | Background 실행 여부 |
| `content_sha256` | TEXT | NOT NULL | Canonical Profile Hash |
| `created_by` | TEXT | NOT NULL | 생성 분석자 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(case_id, name, revision)`. 실행된 Profile Revision은 Update하지 않고 새 Revision을 만든다.

### `indexing_jobs`

`ingest_jobs`의 `job_type=INDEX` 행과 1:1로 연결하는 Progressive Index 특화 Projection이다.

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `job_id` | TEXT | PK/FK `ingest_jobs(id)` | 범용 Job |
| `profile_id` | TEXT | FK, NOT NULL | 실행 Profile |
| `profile_revision` | INTEGER | NOT NULL | 실행 설정 Revision |
| `evidence_fingerprint_id` | TEXT | FK, NOT NULL | 입력 Fingerprint |
| `queue_class` | TEXT | NOT NULL | `USER_SELECTED`, `FOREGROUND`, `BACKGROUND` |
| `priority` | INTEGER | NOT NULL | 낮을수록 우선 |
| `pause_requested_at` | TEXT | NULL | Pause 요청 UTC |
| `paused_at` | TEXT | NULL | Checkpoint 완료 UTC |
| `resumed_at` | TEXT | NULL | 마지막 Resume UTC |
| `partial_results_available` | INTEGER | NOT NULL | 완료 Batch 조회 가능 여부 |
| `completed_scope_json` | TEXT | NOT NULL | 완료 Scope |
| `pending_scope_json` | TEXT | NOT NULL | 대기 Scope |

Index: `(queue_class, priority, job_id)`, `(profile_id, profile_revision)`.

### `indexing_job_scopes`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Scope UUID |
| `job_id` | TEXT | FK, NOT NULL | Index Job |
| `scope_type` | TEXT | NOT NULL | Case/Evidence/File/Artifact 범위 |
| `scope_json` | TEXT | NOT NULL | 검증된 Scope |
| `priority` | INTEGER | NOT NULL | 사용자 선택 우선순위 |
| `status` | TEXT | NOT NULL | `QUEUED`, `RUNNING`, `PAUSED`, 종료 상태 |
| `processed_items` | INTEGER | NOT NULL DEFAULT 0 | 처리 수 |
| `estimated_total_items` | INTEGER | NULL | 추정 전체 수 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |
| `finished_at` | TEXT | NULL | 종료 UTC |

### `indexing_checkpoints`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Checkpoint UUID |
| `job_id` | TEXT | FK, NOT NULL | Job |
| `scope_id` | TEXT | FK, NOT NULL | Scope |
| `analyzer_id` | TEXT | NOT NULL | Analyzer |
| `analyzer_version` | TEXT | NOT NULL | Cache/Resume 검증 Version |
| `options_hash` | TEXT | NOT NULL | Canonical Options SHA-256 |
| `cursor_json` | TEXT | NOT NULL | 재개 Cursor |
| `processed_items` | INTEGER | NOT NULL | Checkpoint 처리 수 |
| `checkpoint_hash` | TEXT | NOT NULL | 내용 무결성 Hash |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(job_id, scope_id, analyzer_id, processed_items)`.

### `analyzer_progress`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | INTEGER | PK AUTOINCREMENT | 표본 순서 |
| `job_id` | TEXT | FK, NOT NULL | Job |
| `analyzer_id` | TEXT | NOT NULL | 현재 Analyzer |
| `processed_items` | INTEGER | NOT NULL | 처리 수 |
| `estimated_total_items` | INTEGER | NULL | 추정 전체 |
| `throughput_items_per_second` | REAL | NULL | 관측 처리량 |
| `elapsed_seconds` | REAL | NOT NULL | 경과 시간 |
| `estimated_remaining_seconds` | REAL | NULL | ETA |
| `estimate_confidence` | TEXT | NOT NULL | `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` |
| `worker_count` | INTEGER | NOT NULL | Worker 수 |
| `cache_hits` | INTEGER | NOT NULL | 누적 Hit |
| `cache_misses` | INTEGER | NOT NULL | 누적 Miss |
| `sampled_at` | TEXT | NOT NULL | 표본 UTC |

고빈도 Event 전체를 저장하지 않고 상태 전환, Checkpoint와 주기적 표본만 보존한다.

### `evidence_fingerprints`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Fingerprint UUID |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `algorithm` | TEXT | NOT NULL | 초기 `SHA256` |
| `fingerprint_hex` | TEXT | NOT NULL | 입력 식별 Hash |
| `size_bytes` | INTEGER | NOT NULL | 계산 당시 크기 |
| `reader_id` | TEXT | NOT NULL | Reader |
| `reader_version` | TEXT | NOT NULL | Reader Version |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(evidence_id, algorithm, fingerprint_hex, reader_version)`.

기존 `cache_entries`를 재사용한다. `producer_json`의 Cache Key 계약은 Evidence Fingerprint,
Analyzer ID/Version, Canonical Options Hash와 Scope Fingerprint를 포함한다.

## 12. Timezone

### `timezone_candidates`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | 후보 UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `timezone` | TEXT | NOT NULL | IANA Timezone ID |
| `source` | TEXT | NOT NULL | Case/OS/Registry/Linux/Browser/Application/Offset/Analyst |
| `confidence` | TEXT | NOT NULL | `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN` |
| `citation_json` | TEXT | NOT NULL | 후보 근거 |
| `status` | TEXT | NOT NULL | `CANDIDATE`, `CONFIRMED`, `REJECTED` |
| `detected_at` | TEXT | NOT NULL | 탐지 UTC |

Index: `(case_id, status, confidence)`.

### `timezone_decisions`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Decision UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `timezone` | TEXT | NOT NULL | 선택 IANA ID |
| `candidate_id` | TEXT | FK, NULL | 근거 후보 |
| `confidence` | TEXT | NOT NULL | 확인 신뢰도 |
| `reason` | TEXT | NULL | 수동 변경 사유 |
| `decided_by` | TEXT | NOT NULL | 분석자 Identity |
| `decided_at` | TEXT | NOT NULL | Decision UTC |
| `supersedes_decision_id` | TEXT | FK, NULL | 이전 Decision |

Decision은 Update하지 않고 새 행으로 이전 Decision을 대체한다.

### `timestamp_interpretations`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Interpretation UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `source_kind` | TEXT | NOT NULL | File/Artifact/Timeline Source |
| `source_id` | TEXT | NOT NULL | Source UUID |
| `field_name` | TEXT | NOT NULL | Timestamp Field |
| `raw_timestamp` | TEXT | NOT NULL | 원본 값 |
| `raw_timezone` | TEXT | NULL | 원본 Timezone/Offset |
| `normalized_utc` | TEXT | NULL | UTC 해석 |
| `display_timestamp` | TEXT | NULL | 당시 Case Timezone 표시값 |
| `display_timezone` | TEXT | NOT NULL | IANA ID |
| `timezone_source` | TEXT | NOT NULL | 해석 출처 |
| `timezone_confidence` | TEXT | NOT NULL | 신뢰도 |
| `dst_status` | TEXT | NOT NULL | Standard/Daylight/Transition |
| `ambiguity` | TEXT | NOT NULL | 중복/불가능/오류 Local Time |
| `decision_id` | TEXT | FK, NOT NULL | 사용 Decision |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(source_kind, source_id, field_name, decision_id)`. 새 Decision은 새 Interpretation
Projection을 만들며 원본 행을 수정하지 않는다.

## 13. Keyword와 Search Reproduction

### `keyword_recommendations`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Candidate UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `analysis_context_snapshot_id` | TEXT | FK, NOT NULL | Scope Context |
| `context_scope` | TEXT | NOT NULL | 전달 Scope |
| `context_revision` | INTEGER | NOT NULL | Context Revision |
| `keyword` | TEXT | NOT NULL | 원본 Keyword |
| `keyword_type` | TEXT | NOT NULL | File/Process/Account/URL 등 Enum |
| `reason` | TEXT | NOT NULL | 추천 이유 |
| `scope` | TEXT | NOT NULL | 검색 Scope |
| `citations_json` | TEXT | NOT NULL | AI 추천은 최소 1개 |
| `confidence` | REAL | NULL | AI 추천 신뢰도 |
| `source_kind` | TEXT | NOT NULL | `AI_RECOMMENDATION`, `ANALYST` |
| `status` | TEXT | NOT NULL | `PENDING_REVIEW`, `APPROVED`, `REJECTED` |
| `partial_result` | INTEGER | NOT NULL | Partial Context 여부 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

중복 후보는 Case/Scope/정규화 Keyword/Type 기준으로 표시하되 원본 제안 이력은 보존한다.

### `keyword_sets`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Set UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `name` | TEXT | NOT NULL | 이름 |
| `version` | INTEGER | NOT NULL | 불변 Version |
| `status` | TEXT | NOT NULL | `DRAFT`, `APPROVED`, `EXECUTED`, `SUPERSEDED` |
| `content_sha256` | TEXT | NOT NULL | Set Hash |
| `created_by` | TEXT | NOT NULL | 생성자 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Unique: `(case_id, name, version)`.

### `keyword_set_items`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Item UUID |
| `keyword_set_id` | TEXT | FK, NOT NULL | Set |
| `recommendation_id` | TEXT | FK, NULL | AI Candidate 또는 null |
| `keyword` | TEXT | NOT NULL | 실행 문자열 |
| `keyword_type` | TEXT | NOT NULL | Keyword Type |
| `source_kind` | TEXT | NOT NULL | AI/Analyst |
| `approved` | INTEGER | NOT NULL | 승인 여부 |
| `ordinal` | INTEGER | NOT NULL | 결정적 순서 |

Unique: `(keyword_set_id, ordinal)`.

### `keyword_approvals`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Approval UUID |
| `recommendation_id` | TEXT | FK, NOT NULL | Candidate |
| `decision` | TEXT | NOT NULL | `APPROVED`, `REJECTED` |
| `reason` | TEXT | NULL | 검토 사유 |
| `decided_by` | TEXT | NOT NULL | 분석자 |
| `decided_at` | TEXT | NOT NULL | 결정 UTC |

Approval은 Append-only이며 최신 Decision을 Application에서 Projection한다.

### `search_executions`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Execution UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `keyword_set_id` | TEXT | FK, NOT NULL | 승인 Set |
| `keyword_set_version` | INTEGER | NOT NULL | 실행 Version |
| `status` | TEXT | NOT NULL | Job 상태 |
| `index_version` | TEXT | NOT NULL | 사용 Index |
| `executed_by` | TEXT | NOT NULL | 실행 분석자 |
| `started_at` | TEXT | NOT NULL | 시작 UTC |
| `completed_at` | TEXT | NULL | 완료 UTC |
| `result_count` | INTEGER | NOT NULL DEFAULT 0 | 전체 결과 수 |
| `zero_result_keyword_ids_json` | TEXT | NOT NULL | 0건 Keyword |
| `rerun_of_execution_id` | TEXT | FK, NULL | 원 실행 |
| `content_sha256` | TEXT | NOT NULL | 재현 Snapshot Hash |

### `search_execution_options`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `execution_id` | TEXT | PK/FK | Search Execution |
| `case_sensitive` | INTEGER | NOT NULL | 대소문자 |
| `regex_enabled` | INTEGER | NOT NULL | Regex |
| `encodings_json` | TEXT | NOT NULL | Encoding 목록 |
| `time_from` | TEXT | NULL | 시작 UTC |
| `time_to` | TEXT | NULL | 종료 UTC |
| `evidence_scope_json` | TEXT | NOT NULL | Evidence Scope |
| `source_scope_json` | TEXT | NOT NULL | File/Artifact/Timeline/Candidate |
| `normalization_profile` | TEXT | NOT NULL | 검색 정규화 Version |

기존 `search_queries`와 `search_results`는 각 실행의 Query/Hit Snapshot으로 연결한다.

## 14. Chain of Custody

### `custody_events`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `event_id` | TEXT | PK | Event UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `event_type` | TEXT | NOT NULL, CHECK | 15개 Custody Event Enum |
| `actor_id` | TEXT | NULL | Backend Identity |
| `actor_name` | TEXT | NOT NULL | 당시 표시 이름 |
| `actor_role` | TEXT | NULL | 당시 Role |
| `organization` | TEXT | NULL | 당시 Organization |
| `source_location` | TEXT | NULL | 이동 전 위치 |
| `destination_location` | TEXT | NULL | 이동 후 위치 |
| `action` | TEXT | NOT NULL | 수행 행위 |
| `reason` | TEXT | NULL | 사유 |
| `occurred_at_utc` | TEXT | NOT NULL | 실제 발생 UTC |
| `displayed_at` | TEXT | NOT NULL | Snapshot 표시 시간 |
| `timezone` | TEXT | NOT NULL | IANA ID |
| `tool_name` | TEXT | NULL | Tool |
| `tool_version` | TEXT | NULL | Tool Version |
| `previous_hash_json` | TEXT | NULL | 이전 Evidence Hash |
| `current_hash_json` | TEXT | NULL | 현재 Evidence Hash |
| `notes` | TEXT | NULL | 메모 |
| `created_at` | TEXT | NOT NULL | 기록 UTC |
| `immutable_revision` | INTEGER | NOT NULL | Evidence별 단조 Revision |
| `previous_event_hash` | TEXT | NULL | 이전 Ledger Event Hash |
| `event_hash` | TEXT | NOT NULL | 현재 Canonical Event Hash |
| `ledger_algorithm` | TEXT | NOT NULL | 초기 `SHA256` |
| `ledger_version` | TEXT | NOT NULL | Canonicalization Version |
| `approval_json` | TEXT | NULL | 승인/서명 Reference |
| `correction_of_event_id` | TEXT | FK, NULL | Correction 대상 |

Unique: `(evidence_id, immutable_revision)`. Application 권한과 SQLite Trigger 정책으로
`UPDATE`와 `DELETE`를 거부한다. `CORRECTION`만 원 Event를 참조할 수 있다.

### `custody_hash_verifications`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Verification UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `expected_hash_json` | TEXT | NOT NULL | 기대 Hash |
| `observed_hash_json` | TEXT | NOT NULL | 관측 Hash |
| `status` | TEXT | NOT NULL | `MATCH`, `MISMATCH` |
| `verified_by` | TEXT | NOT NULL | 실행 Actor |
| `verified_at` | TEXT | NOT NULL | 실행 UTC |
| `tool_name` | TEXT | NOT NULL | Tool |
| `tool_version` | TEXT | NOT NULL | Tool Version |
| `custody_event_id` | TEXT | FK, NOT NULL | `HASH_VERIFIED` Event |

### `custody_snapshots`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Snapshot UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `from_event_id` | TEXT | FK, NOT NULL | 시작 Event |
| `through_event_id` | TEXT | FK, NOT NULL | 끝 Event |
| `event_count` | INTEGER | NOT NULL | Event 수 |
| `head_event_hash` | TEXT | NOT NULL | Ledger Head |
| `snapshot_hash` | TEXT | NOT NULL | Snapshot Hash |
| `verification_status` | TEXT | NOT NULL | `VALID`, `INVALID`, `INCOMPLETE` |
| `report_id` | TEXT | FK, NULL | 연결 Report |
| `report_version` | INTEGER | NULL | 연결 Version |
| `created_by` | TEXT | NOT NULL | 생성자 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

### `custody_approvals`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Approval UUID |
| `snapshot_id` | TEXT | FK, NOT NULL | Snapshot |
| `status` | TEXT | NOT NULL | `PENDING`, `APPROVED`, `REJECTED` |
| `approved_by` | TEXT | NULL | 사람 Identity |
| `approved_at` | TEXT | NULL | 승인 UTC |
| `signature_reference` | TEXT | NULL | 외부 서명 Reference |
| `notes` | TEXT | NULL | 검토 메모 |

전자서명 방식과 법적 효력은 관할 정책 검토 대상이며 DB 설계가 이를 보장하지 않는다.

## 15. Machine Extraction

### `machine_extractions`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Extraction UUID |
| `case_id` | TEXT | FK, NOT NULL | Case |
| `evidence_id` | TEXT | FK, NOT NULL | Evidence |
| `file_id` | TEXT | FK, NOT NULL | Media/File |
| `media_type` | TEXT | NOT NULL | Image/Video/Audio/Document |
| `extraction_type` | TEXT | NOT NULL | OCR/Frame OCR/Subtitle/STT 등 |
| `extracted_text` | TEXT | NOT NULL | 원 Candidate Text |
| `confidence` | REAL | NOT NULL CHECK 0..1 | Machine Confidence |
| `language` | TEXT | NULL | 탐지 언어 |
| `engine_id` | TEXT | NOT NULL | Provider-neutral Engine ID |
| `engine_version` | TEXT | NOT NULL | Engine Version |
| `frame_number` | INTEGER | NULL | Video Frame |
| `timestamp_offset_ms` | INTEGER | NULL | Video/Audio Offset |
| `source_region_json` | TEXT | NULL | 이미지 영역 |
| `source_locator_json` | TEXT | NOT NULL | Raw Locator |
| `citations_json` | TEXT | NOT NULL | Source Citation |
| `analyst_status` | TEXT | NOT NULL | `UNREVIEWED`, `ACCEPTED`, `REJECTED`, `CORRECTED` |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

Candidate 원문은 Update하지 않는다.

### `machine_extraction_reviews`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Review UUID |
| `extraction_id` | TEXT | FK, NOT NULL | Candidate |
| `decision` | TEXT | NOT NULL | Accept/Reject/Correct |
| `corrected_text` | TEXT | NULL | Correction Text |
| `reason` | TEXT | NULL | 사유 |
| `reviewed_by` | TEXT | NOT NULL | 분석자 |
| `reviewed_at` | TEXT | NOT NULL | 검토 UTC |

Review는 Append-only이며 현재 상태는 최신 Review Projection이다. OCR/STT 결과는 승인 전에도
Observed Fact가 아니며 Review 상태를 항상 함께 조회한다.

## 16. Benchmark와 External Validation

### `benchmark_runs`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Run UUID |
| `case_id` | TEXT | FK, NULL | Synthetic/Test Case |
| `dataset_name` | TEXT | NOT NULL | 공개 가능한 Dataset |
| `dataset_kind` | TEXT | NOT NULL | `PUBLIC_DFIR`, `SYNTHETIC`, `LEGAL_TEST_IMAGE` |
| `dataset_reference` | TEXT | NOT NULL | Version/URI/Hash |
| `hardware_json` | TEXT | NOT NULL | CPU/Memory/Storage |
| `scope_json` | TEXT | NOT NULL | Analyzer/Hash/Index 범위 |
| `cache_state` | TEXT | NOT NULL | `COLD`, `WARM`, `MIXED` |
| `worker_count` | INTEGER | NOT NULL | Worker |
| `tool_version` | TEXT | NOT NULL | APEX Version |
| `status` | TEXT | NOT NULL | `PLANNED`, `RUNNING`, `COMPLETED`, `FAILED` |
| `started_at` | TEXT | NULL | 시작 UTC |
| `completed_at` | TEXT | NULL | 완료 UTC |

### `benchmark_measurements`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Measurement UUID |
| `benchmark_run_id` | TEXT | FK, NOT NULL | Run |
| `metric_name` | TEXT | NOT NULL | 첫 Tree/Index/P95/RSS/I/O 등 |
| `value` | REAL | NOT NULL | 측정값 |
| `unit` | TEXT | NOT NULL | 단위 |
| `sample_count` | INTEGER | NOT NULL | 표본 수 |
| `conditions_json` | TEXT | NOT NULL | 측정 조건 |
| `recorded_at` | TEXT | NOT NULL | 기록 UTC |

### `external_validation_reviews`

| 컬럼 | 타입 | 제약 | 설명 |
|---|---|---|---|
| `id` | TEXT | PK | Review UUID |
| `benchmark_run_id` | TEXT | FK, NULL | 관련 Benchmark |
| `status` | TEXT | NOT NULL | 초기 `PLANNED` |
| `review_scope_json` | TEXT | NOT NULL | 성능/사용성/Workflow 범위 |
| `reviewer_reference` | TEXT | NULL | 동의된 경우에만 공개 가능한 식별자 |
| `identity_disclosure_consent` | INTEGER | NOT NULL | 공개 동의 |
| `findings_json` | TEXT | NULL | 자문 결과 |
| `limitations_json` | TEXT | NOT NULL | 검증 한계 |
| `created_at` | TEXT | NOT NULL | 생성 UTC |

비공개 작전 자료, 개인정보와 기밀정보를 Dataset으로 사용할 수 없다. 기관명이나 인증 상태를
이 Table에서 추론하거나 자동 표시하지 않는다.

## 17. Report Link와 보존 확장

| Table | 복합 PK/FK | 역할 |
|---|---|---|
| `report_keyword_set_links` | `(report_id, report_version, keyword_set_id, keyword_set_version)` | Keyword Set 고정 |
| `report_search_execution_links` | `(report_id, report_version, search_execution_id)` | Search Options/Result 고정 |
| `report_custody_snapshot_links` | `(report_id, report_version, custody_snapshot_id)` | Custody 부록 연결 |
| `report_machine_extraction_links` | `(report_id, report_version, extraction_id)` | Candidate와 Review 상태 고정 |
| `report_index_job_links` | `(report_id, report_version, index_job_id)` | Profile/완료 범위 고정 |
| `report_timezone_decision_links` | `(report_id, report_version, timezone_decision_id)` | 표시 정책 고정 |

승인 Version의 Link와 Provenance는 Update하지 않는다. Report Section Type에는
`INDEXING_SCOPE`, `TIMEZONE_POLICY`, `KEYWORD_SEARCH`, `CHAIN_OF_CUSTODY`,
`HASH_VERIFICATION`, `MACHINE_EXTRACTION`, `EXTERNAL_VALIDATION`을 추가한다.

## 18. 신규 Table과 Module Owner

| Table 그룹 | Module Owner |
|---|---|
| `analysis_profiles` | Analysis Profile Manager |
| `indexing_jobs`, `indexing_job_scopes`, `indexing_checkpoints`, `analyzer_progress` | Progressive Indexing Coordinator / Job Orchestrator |
| `evidence_fingerprints`, `cache_entries` | Evidence Manager / Cache Port |
| `timezone_candidates`, `timezone_decisions`, `timestamp_interpretations` | Timezone Resolver / Timestamp Normalizer |
| `keyword_recommendations`, `keyword_sets`, `keyword_set_items`, `keyword_approvals` | Keyword Set Manager |
| `search_executions`, `search_execution_options` | Search Reproduction Manager |
| `custody_events` | Chain of Custody Ledger |
| `custody_hash_verifications`, `custody_snapshots`, `custody_approvals` | Custody Verification Service |
| `machine_extractions`, `machine_extraction_reviews` | Media Extraction Candidate Store |
| `benchmark_runs`, `benchmark_measurements`, `external_validation_reviews` | External Validation Plan |

Live Progress와 Live GUI Context는 Session Store를 우선한다. 재현, Audit, Recovery와 Report에
필요한 Snapshot만 DB에 저장한다.

## Phase 2 SQLite Tables

The SQLite repository now applies an idempotent `phase2-progressive-filesystem-indexing` migration while preserving Phase 1 tables, WAL, foreign keys, and append-only custody triggers.

Implemented tables:

- `fs_providers`: provider id/version, capabilities, and metadata.
- `fs_nodes`: provider-neutral filesystem nodes with original path strings, comparison path, metadata, raw/UTC timestamps, raw locator, partial flag, and index revision.
- `fs_index_jobs`: filesystem-specific job metadata linked to the existing `jobs` table.
- `fs_index_queue`: bounded priority queue/checkpoint state for resumable traversal.
- `fs_index_checkpoints`: resumable progress snapshot for current path, pending count, processed count, and discovered count.
- `fs_index_coverage`: NOT_STARTED/PARTIAL/COMPLETE/FAILED/CANCELLED coverage counters and ETA fields.
- `fs_scan_events`: warnings/errors such as permission denied, file changed during scan, and callback errors.

`fs_nodes` enforces uniqueness by case, evidence, provider, provider version, and original relative path to prevent duplicate node creation across resume or repeated indexing. The custody ledger remains append-only and evidence deletion/original modification is not added.
