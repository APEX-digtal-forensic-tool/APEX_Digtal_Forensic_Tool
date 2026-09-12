# Phase 1 완료 — 데이터 모델 + 저장소

상태: 완료
완료일: 2026-09-11

## 구현 요약

PostgreSQL (async) 기반의 4개 ORM 모델과 Alembic 초기 마이그레이션을 구현했다.

## 만든/수정한 파일

| 파일 | 설명 |
|---|---|
| `src/apex_backend/__init__.py` | 패키지 진입점 |
| `src/apex_backend/py.typed` | mypy py.typed 마커 |
| `src/apex_backend/database.py` | 비동기 엔진/세션 팩토리 (`build_engine`, `build_session_factory`) |
| `src/apex_backend/models.py` | ORM 모델 4개 |
| `src/apex_backend/alembic/env.py` | Alembic async 환경 설정 |
| `src/apex_backend/alembic/versions/0001_initial_schema.py` | 초기 마이그레이션 |
| `tests/backend/conftest.py` | SQLite in-memory 테스트 픽스처 |
| `tests/backend/test_models.py` | CRUD 테스트 9개 |
| `pyproject.toml` | `[backend]` 옵셔널 의존성 그룹 추가, mypy files에 `src/apex_backend` 추가 |
| `alembic.ini` | 루트에 생성, `prepend_sys_path = src` |

## 테이블 설계

```
users
  id            STRING(36) PK  (UUID)
  username      STRING(255)
  email         STRING(255)
  hashed_password STRING(255)
  tenant_id     STRING(255)
  created_at    DATETIME(tz)
  is_active     BOOLEAN
  UNIQUE(email, tenant_id)

case_tenancy
  id            STRING(36) PK
  actor_id      STRING(36) FK→users.id CASCADE
  case_id       STRING(255)
  role          STRING(50)  — VIEWER/ANALYST/APPROVER/EXPORTER/ADMIN
  granted_at    DATETIME(tz)
  UNIQUE(actor_id, case_id)

user_sessions
  session_id    STRING(36) PK
  actor_id      STRING(36) FK→users.id CASCADE
  tenant_id     STRING(255)
  created_at    DATETIME(tz)
  expires_at    DATETIME(tz)
  revoked_at    DATETIME(tz) NULLABLE  — NULL이면 활성 세션

confirmation_grants
  grant_id           STRING(36) PK
  actor_id           STRING(36)
  session_id         STRING(36)
  case_id            STRING(255)
  tool_name          STRING(255)
  request_fingerprint STRING(255)
  target_ids         JSON        — LIST[str], ConfirmationGrant.target_ids 대응
  expires_at         DATETIME(tz)
  max_uses           INTEGER     default 1
  uses_count         INTEGER     default 0
```

## 설계 결정

- **String(36) for UUID**: UUID 타입 대신 String(36) 사용 — SQLite/PostgreSQL 양쪽 호환. 값은 항상 `str(uuid.uuid4())` 형태.
- **UserSession 명칭**: `Session`은 `sqlalchemy.orm.Session`과 충돌하므로 `UserSession`으로 명명.
- **target_ids = JSON**: `ConfirmationGrant.target_ids: tuple[str, ...]`를 JSON 컬럼으로 저장. SQLite는 TEXT로, PostgreSQL은 JSON으로 처리. ORM 레이어에서 list로 읽어 tuple 변환은 Phase 5에서 처리.
- **uses_count 컬럼**: 인메모리 구현의 `_uses` dict를 DB 컬럼으로 대응. 소비 시 `UPDATE SET uses_count = uses_count + 1` 원자적 실행 가능.
- **email unique per tenant**: `UNIQUE(email, tenant_id)` — 멀티테넌트에서 이메일 중복 허용.

## 테스트 현황

- 추가: 9개 (test_models.py)
- 결과: 9/9 통과
- 사용 DB: SQLite in-memory (aiosqlite)
- 기존 MCP 49개 테스트: `mcp` 패키지 미설치로 수집 불가 (Phase 1 이전부터 동일한 환경 문제, 내 변경과 무관)

## 알려진 제약

- `uses_count` 동시 업데이트 안전성 — Phase 5에서 `SELECT FOR UPDATE` 또는 낙관적 락으로 처리 예정.
- 실제 PostgreSQL 대상 통합 테스트는 Phase 6에서 다룸.
- `hashed_password` 해싱 알고리즘은 Phase 2(인증 API)에서 확정.
