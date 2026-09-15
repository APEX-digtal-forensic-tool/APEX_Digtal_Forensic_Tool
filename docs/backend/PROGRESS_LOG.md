# 백엔드 개발 진행 로그

새 세션은 이 파일의 "현재 상태" / "마지막 진행 상황" / "다음 작업" 세
섹션만 읽으면 어디까지 됐고 뭘 해야 하는지 바로 알 수 있어야 한다.
작업을 끝내기 전에 반드시 이 파일을 갱신한다 (`01_DEVELOPMENT_RULES.md` 3절).

---

## 현재 상태

Phase: 1~7 완료. Phase 8(문서 백필), Phase 9(레거시 정리) 진행 중.
마지막 업데이트: 2026-09-15

## 마지막 진행 상황

Phase 7 완료: `pyproject.toml` backend extra에 `bcrypt>=4.0,<4.1` 추가,
`uv lock`으로 `uv.lock` 갱신 (bcrypt 5.0.0 → 4.0.1). 109개 테스트 통과,
ruff/mypy 클린 확인. `specs/00_DECISIONS.md`에 bcrypt 버전 고정 결정 기록 추가.
PR 생성 완료 (fix/backend-phase-7-bcrypt-pin). 머지 대기 중.

## 다음 작업

1. Phase 8 (`specs/08_docs_sync_backfill.md`) — specs/03~06 상태 완료로 정정,
   도메인 폴더 3개 생성(mcp-token-verifier/, mcp-frontend-security-provider/,
   confirmation-grant-flow/), PROGRESS_LOG/MASTER_PLAN 갱신. 브랜치:
   `docs/backend-phase-8-docs-sync`.
2. Phase 9 (`specs/09_remove_legacy_mcp_server_scaffold.md`) — 레거시
   `mcp_server/` 삭제, ruff check . 클린 확인. 브랜치:
   `chore/backend-phase-9-remove-legacy-mcp-server`.

세 개 다 서로 독립적, 순서 상관없음. Phase 1~6과 달리 이 셋은 새 기능이
아니라 수습/정리 작업.

**하지 말 것**: Windows Desktop bundle 통합 검증, Case/Evidence/Search 신규
Domain Tool — `00_MASTER_PLAN.md` 6-2절 "보류 항목" 참고. 사람이 별도로
새 기획서를 줄 때까지 스스로 시작하지 않는다.

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
- Phase 3 완료: `JwtTokenVerifier` (JWKS fetch + TTL 캐시 + RS256 검증).
  (커밋 `c6d7051`/`28e9ab3` — as-built 문서화는 Phase 8에서 백필 예정.)
- Phase 4 완료: `PersistentFrontendSecurityProvider` (JWT 클레임 → FrontendSession).
  (커밋 `a62dca6`/`555c0f2` — as-built 문서화는 Phase 8에서 백필 예정.)
- Phase 5 완료: confirmation grant 발급/DB 소비 (`DbFrontendSecurityProvider`,
  `POST /confirmations`, 5분 1회용).
  (커밋 `23a2762`/`31d0c6d` — as-built 문서화는 Phase 8에서 백필 예정.)
- 커밋 author/uv.lock 규칙 추가 (`01_DEVELOPMENT_RULES.md` 7절).

### 2026-09-14
- Phase 6 완료: E2E 테스트 4건 (`tests/mcp/test_e2e_backend_integration.py`),
  `docs/backend/deployment/README.md`, `docs/MCP_SERVER.md` 6절 갱신.
  (커밋 `f023c94`/`8edb18b`.) 백엔드 마스터플랜 코드 부분 전체 완료.

### 2026-09-15
- 사람이 클린 venv로 Phase 1~6 전체 재검증 (109개 테스트, ruff/mypy 클린
  확인). 재검증 중 `bcrypt==5.0.0` + `passlib` 비호환으로 로그인/비번해시
  테스트 2개가 깨지는 실제 버그 발견 (재현 확인, `bcrypt<4.1` 핀으로 해결
  확인). 동시에 Phase 3~5의 문서 백필 규칙 미준수(스펙 상태/도메인 폴더)와
  이 로그 자체가 Phase 2에서 멈춰있던 것 확인.
- Phase 7(bcrypt 버전 고정), Phase 8(문서 백필), Phase 9(레거시 mcp_server
  제거) 스펙 신규 작성. `00_MASTER_PLAN.md`에 6-1(진행 현황), 6-2(보류 항목:
  Windows Desktop bundle 통합, Case/Evidence/Search Domain Tool — 둘 다
  지금 착수 안 함) 섹션 추가.
- Phase 7 완료: `pyproject.toml`에 `bcrypt>=4.0,<4.1` 추가, `uv.lock` 갱신
  (bcrypt 5.0.0 → 4.0.1), 109개 테스트 통과, ruff/mypy 클린,
  `specs/00_DECISIONS.md`에 bcrypt 결정 기록, spec 07 상태 완료로 갱신.
  PR #10(fix/backend-phase-7-bcrypt-pin) 생성.
