# 백엔드 개발 진행 로그

새 세션은 이 파일의 "현재 상태" / "마지막 진행 상황" / "다음 작업" 세
섹션만 읽으면 어디까지 됐고 뭘 해야 하는지 바로 알 수 있어야 한다.
작업을 끝내기 전에 반드시 이 파일을 갱신한다 (`01_DEVELOPMENT_RULES.md` 3절).

---

## 현재 상태

Phase: 2 대기 중 (인증/토큰 발급 API)
마지막 업데이트: 2026-09-11

## 마지막 진행 상황

Phase 1 완료.
- `src/apex_backend/` 패키지 생성 (`__init__.py`, `py.typed`, `database.py`, `models.py`)
- ORM 모델 4개: `User`, `CaseTenancy`, `UserSession`, `ConfirmationGrantRow`
- Alembic 설정: `alembic.ini` (루트), `src/apex_backend/alembic/env.py` (async), `versions/0001_initial_schema.py`
- `pyproject.toml`: `[backend]` 옵셔널 그룹 추가, mypy files에 `src/apex_backend` 추가
- pytest 9개 추가 (`tests/backend/test_models.py`), 9/9 통과
- ruff clean, mypy clean (5 source files)
- `docs/backend/data-model/README.md` 작성, `specs/01_data_model_and_storage.md` 완료로 표시

## 다음 작업

Phase 2: `specs/02_auth_token_issuance_api.md` 읽고 착수.
- FastAPI 앱 (`src/apex_backend/app.py`)
- 로그인 엔드포인트 (`POST /auth/login`) — 패스워드 검증 + JWT 발급
- 리프레시 엔드포인트 (`POST /auth/refresh`)
- JWT 서명: RS256 or ES256 (스펙에 결정 위임, 없으면 HS256 + SECRET_KEY 환경변수로 시작)

## 결정 대기

(없음 — 모든 결정 확정됨, `specs/00_DECISIONS.md` 참고)

## 확정된 결정 사항

- 인증: Option A (JWT 로컬 검증 + 공유 PostgreSQL for confirmation_grant)
- DB: PostgreSQL + asyncpg
- SQLAlchemy: async 모드
- 테스트 DB: 단위=SQLite/aiosqlite in-memory, 통합=실제 PostgreSQL

## 히스토리 (오래된 순으로 append, 삭제 금지)

### 2026-09-11
- `docs/backend/` 폴더 생성. 마스터 플랜/규칙/진행로그/Phase 1~6 스펙 작성.
  배경: MCP는 M8까지 완성돼 merge된 상태 확인됨(`6e55f12`), 남은 건
  `FrontendSecurityProvider`/`TokenVerifier`를 인메모리 스텁에서 실제 백엔드
  구현으로 교체하는 것뿐이라 이걸 마스터 플랜으로 정리함.
- 아키텍처 결정 확정 (사람): Option A (JWT 로컬 검증), PostgreSQL, async SQLAlchemy.
  `specs/00_DECISIONS.md`에 기록.
- Phase 1 완료: `src/apex_backend/` 패키지, ORM 모델 4개, Alembic 마이그레이션,
  pytest 9개 신규 (9/9 통과), ruff/mypy 클린.
  as-built: `docs/backend/data-model/README.md`.
