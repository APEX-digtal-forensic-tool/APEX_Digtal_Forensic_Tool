# 백엔드 개발 진행 로그

새 세션은 이 파일의 "현재 상태" / "마지막 진행 상황" / "다음 작업" 세
섹션만 읽으면 어디까지 됐고 뭘 해야 하는지 바로 알 수 있어야 한다.
작업을 끝내기 전에 반드시 이 파일을 갱신한다 (`01_DEVELOPMENT_RULES.md` 3절).

---

## 현재 상태

Phase: 1~9 전부 완료. 백엔드 마스터플랜 전체 완료.
마지막 업데이트: 2026-09-15

## 마지막 진행 상황

Phase 9 완료 (레거시 mcp_server 정리):
- `mcp_server/` 디렉터리 삭제 (git untracked 상태였음, `git rm` 불필요)
- `.gitignore`에 `mcp_server/` 추가 (재발 방지)
- `ruff check .` 레포 전체 기준 클린 확인
- docs/ 안 `mcp_server/` 참조 검색: specs/09 파일만 해당, 별도 정리 불필요

## 다음 작업

없음. Phase 1~9 전부 완료. 새 작업은 사람이 별도 기획서를 주면 시작.

보류 중인 항목(착수 금지):
- Windows Desktop bundle 제품 통합 검증 — 프론트/패키징 담당과 협의 필요
- Case/Evidence/Search 신규 Domain Tool — Core Descriptor 열릴 때까지 대기

## 결정 대기

(없음 — 모든 결정 확정됨, `specs/00_DECISIONS.md` 참고)

## 확정된 결정 사항

- 인증: Option A (JWT 로컬 검증 + 공유 PostgreSQL for confirmation_grant)
- DB: PostgreSQL + asyncpg
- SQLAlchemy: async 모드
- 테스트 DB: 단위=SQLite/aiosqlite in-memory, 통합=실제 PostgreSQL
- bcrypt: `>=4.0,<4.1` 고정 (passlib 비호환 버그, Phase 7)

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
  as-built: `docs/backend/auth-api/README.md`. 커밋 `e66d80c`/`2d88282`.
- Phase 3 완료: `JwtTokenVerifier` 구현 (`src/apex_backend/auth/jwt_verifier.py`).
  JWKS fetch + TTL 캐시(300초) + RS256 서명 검증 + 실패 시 None 반환.
  pytest 11개 신규 (`tests/backend/test_jwt_verifier.py`, 누적 31/31 통과).
  as-built: `docs/backend/mcp-token-verifier/README.md` (Phase 8에서 백필).
  커밋 `c6d7051`/`28e9ab3`.
- Phase 4 완료: `PersistentFrontendSecurityProvider` 구현
  (`src/apex_mcp/frontend_security.py`). JWT 클레임 → FrontendSession 직접 재구성
  (DB 조회 없음, Option A 핵심). pytest 12개 신규
  (`tests/mcp/test_persistent_security_provider.py`, 누적 43/43 통과).
  as-built: `docs/backend/mcp-frontend-security-provider/README.md` (Phase 8에서 백필).
  커밋 `a62dca6`/`555c0f2`.
- Phase 5 완료: confirmation grant 발급/소비 플로우.
  `POST /confirmations` (FastAPI, JWT 검증, 1회용 5분 grant 발급),
  `DbFrontendSecurityProvider` (sync SQLAlchemy, grant 조회/소비).
  pytest 13개 신규 (`tests/backend/test_confirmation_grant.py`, 누적 65/65 통과).
  as-built: `docs/backend/confirmation-grant-flow/README.md` (Phase 8에서 백필).
  커밋 `23a2762`/`31d0c6d`.
- 커밋 author/uv.lock 규칙 추가 (`01_DEVELOPMENT_RULES.md` 7절).

### 2026-09-14
- Phase 6 완료: E2E 테스트 4건 (`tests/mcp/test_e2e_backend_integration.py`),
  `docs/backend/deployment/README.md`, `docs/MCP_SERVER.md` 6절 갱신.
  pytest 4개 신규 (누적 109/109 통과). 백엔드 마스터플랜 코드 부분 전체 완료.
  커밋 `f023c94`/`8edb18b`.

### 2026-09-15
- 사람이 클린 venv로 Phase 1~6 전체 재검증 (109개 테스트, ruff/mypy 클린 확인).
  재검증 중 `bcrypt==5.0.0` + `passlib` 비호환으로 로그인/비번해시 테스트 2개
  깨지는 실제 버그 발견. Phase 3~5 문서 백필 규칙 미준수 확인.
  Phase 7/8/9 스펙 신규 작성. `00_MASTER_PLAN.md` 6-1/6-2 섹션 추가.
- Phase 7 완료: `pyproject.toml`에 `bcrypt>=4.0,<4.1` 추가, `uv.lock` 갱신
  (bcrypt 5.0.0 → 4.0.1), 109개 테스트 통과, ruff/mypy 클린.
  `specs/00_DECISIONS.md` bcrypt 결정 기록 추가. PR #10 생성 (머지 완료).
- Phase 8 완료: specs/03~06 상태 완료로 정정, 도메인 폴더 3개 신규 생성
  (mcp-token-verifier/, mcp-frontend-security-provider/, confirmation-grant-flow/),
  PROGRESS_LOG.md 전체 동기화. PR #11 생성 (머지 완료).
- Phase 9 완료: `mcp_server/` 디렉터리 삭제, `.gitignore`에 `mcp_server/` 추가,
  `ruff check .` 클린 확인. PR #12 생성. 백엔드 마스터플랜 Phase 1~9 전부 완료.
