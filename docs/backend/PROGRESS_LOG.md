# 백엔드 개발 진행 로그

새 세션은 이 파일의 "현재 상태" / "마지막 진행 상황" / "다음 작업" 세
섹션만 읽으면 어디까지 됐고 뭘 해야 하는지 바로 알 수 있어야 한다.
작업을 끝내기 전에 반드시 이 파일을 갱신한다 (`01_DEVELOPMENT_RULES.md` 3절).

---

## 현재 상태

Phase: 3 대기 중 (MCP TokenVerifier)
마지막 업데이트: 2026-09-12

## 마지막 진행 상황

Phase 2 완료.
- `src/apex_backend/app.py` — FastAPI 앱 팩토리 (`create_app`)
- `src/apex_backend/auth/` — keys.py, jwt_utils.py, scopes.py, schemas.py, service.py, router.py
- 엔드포인트: `POST /auth/login`, `POST /auth/refresh`, `GET /.well-known/jwks.json`
- JWT 서명: RS256 + kid. 클레임: sub/session_id/tenant_id/allowed_case_ids/roles/scopes/iss/aud/jti
- 비밀번호: bcrypt (passlib)
- pytest 11개 추가 (`tests/backend/test_auth_api.py`), 11/11 통과 (누적 20/20)
- ruff clean, mypy clean (13 source files)
- `docs/backend/auth-api/README.md` 작성, `specs/02_auth_token_issuance_api.md` 완료로 표시

## 다음 작업

Phase 3: `specs/03_mcp_token_verifier.md` 읽고 착수.
- `JwtTokenVerifier` 구현 (`src/apex_backend/` 또는 `src/apex_mcp/`)
- Phase 2 JWKS 엔드포인트로 공개키 가져와 서명 검증
- exp/iss/aud 검증, 실패 시 None 반환 (예외 금지)
- 공개키 캐싱 + 주기적 갱신

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
- PR 규칙 추가 (`01_DEVELOPMENT_RULES.md` 6절): Phase 완료 후 PR 생성, 머지는 사람이 함.

### 2026-09-12
- Phase 2 완료: FastAPI 앱 + RS256 JWT 발급 API + JWKS 엔드포인트.
  pytest 11개 신규 (누적 20/20 통과), ruff/mypy 클린.
  as-built: `docs/backend/auth-api/README.md`.
  브랜치: `feat/backend-phase-2-auth-api` → PR 생성 예정.
