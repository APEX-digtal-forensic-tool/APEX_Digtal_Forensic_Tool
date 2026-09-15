# 백엔드 개발 진행 로그

새 세션은 이 파일의 "현재 상태" / "마지막 진행 상황" / "다음 작업" 세
섹션만 읽으면 어디까지 됐고 뭘 해야 하는지 바로 알 수 있어야 한다.
작업을 끝내기 전에 반드시 이 파일을 갱신한다 (`01_DEVELOPMENT_RULES.md` 3절).

---

## 현재 상태

Phase: 1~11, 13 완료 (PR #14, #15, #16 머지 완료). Phase 14, 15 대기 (바로
착수 가능). Phase 12는 대기하되 착수 전 사람 확인 필요 (범위 미확정, 스펙
아님).
마지막 업데이트: 2026-09-15

## 마지막 진행 상황

Phase 10 완료 (apex-mcp CLI JWT 인증 체인 배선, PR #14 머지됨):
- `src/apex_mcp/__main__.py`: `--http-jwks-uri`/`APEX_JWKS_URI`,
  `--http-db-url`/`APEX_CONFIRMATION_DB_URL`, `--http-jwks-cache-ttl`
  인자 추가. JWKS URI 지정 시 `JwtTokenVerifier` + `DbFrontendSecurityProvider`
  프로덕션 모드, 미지정 시 기존 `StaticBearerTokenVerifier` +
  `InMemoryFrontendSecurityProvider` 개발용 모드 유지.
- `docs/backend/deployment/README.md` 4단계 명령어 수정.
- `tests/mcp/test_cli_jwt_subprocess.py` 신규: subprocess JWT 인증 검증.

Phase 11 완료 (confirmation grant 소비 경쟁 조건 수정, PR #15 머지 대기):
- `src/apex_backend/auth/db_confirmation.py` `authorize()`: 읽기-검사-쓰기를
  원자적 `UPDATE ... WHERE uses_count < max_uses`로 교체. 두 요청이 동시에
  같은 grant를 소비하려 해도 정확히 하나만 True를 반환한다.
- `tests/backend/test_confirmation_grant.py`: `sync_db_threadsafe` 픽스처(파일
  기반 SQLite, `check_same_thread=False`) 추가, `threading.Barrier`로 동시
  호출 재현 테스트 추가. 통과 확인.
- 전체 테스트 564 통과, ruff/mypy 클린.

2026-09-15 2차 재검토: Phase 10/11 및 Core NSS 스키마 픽스(PR #13, 권태욱)를
전부 직접 재현해서 재검증함(정상 동작 확인). 이어서 "설정값이 실제로
쓰이는지", "예외 처리가 흔적을 남기는지", "CI가 실제로 뭘 검증하는지"까지
점검해서 새 문제 3건 확인:
- CI(`mcp-ci.yml`)가 `tests/mcp`(66개)만 돌리고 `tests/backend`(45개)는
  전혀 실행한 적 없음 (`tools/verify_engine_release.py --mcp-only`도
  전체 pytest 블록을 스킵하는 것 소스로 확인). Phase 7 bcrypt 버그가
  지금까지 CI에서 안 걸린 이유가 이거였음.
- `--log-level`/`APEX_MCP_LOG_LEVEL`이 검증만 되고 실제 로깅에 미적용
  (애초에 `apex_backend`/`apex_mcp`에 `logging` 모듈 자체가 없음).
- `JwtTokenVerifier._fetch_jwks()`가 JWKS 조회 실패를 로그 없이 완전
  무음으로 삼킴 (fail-open/fail-closed 동작 자체는 안전, 관측성만 0).
확인했으나 문제 아닌 것: DPAPI/AI/리포트 렌더러 unavailable 클래스들
(의도된 null-object 폴백), `overwrite_policy` 제한(의도된 증거 무결성
보호), 라우터 `NotImplementedError` 스텁(`app.py`가 실제로 연결함).
`specs/13_ci_backend_tests.md`, `14_log_level_wiring.md`,
`15_jwks_failure_logging.md` 신규 작성. `00_MASTER_PLAN.md` 5절/6-4절
갱신. 전체 근거는 `docs/backend/AUDIT_2026-09-15_part2_full_recheck.md`
참고.

Phase 13 완료 (CI tests/backend 검증 공백 수정, PR #16 머지 대기):
- `.github/workflows/mcp-ci.yml` `contract-and-security` job: `MCP contract tests`
  스텝 바로 뒤에 `Backend tests` 스텝(`uv run --locked pytest -q tests/backend`)
  추가. `tests/unit`(Core)·`tests/integration`은 이번 범위 제외.
- 로컬 `tests/backend` 45/45 통과 재확인.
- `tests/unit`(Core, 438개)·`tests/integration`(29개) CI 추가는 Core 담당과
  별도 상의 필요 — PR 설명에 제외 사유 명시.
- `docs/backend/ci-backend-tests/README.md` as-built 신규 작성.

## 다음 작업

1. Phase 14 착수: `specs/14_log_level_wiring.md` — `--log-level` 죽은
   설정값 실제로 적용. 바로 시작 가능.
2. Phase 15 착수: `specs/15_jwks_failure_logging.md` — JWKS 조회 실패
   로깅 추가. Phase 14와 로깅 체계를 공유하는 게 이상적이라, 가능하면
   Phase 14 이후에 진행 (필수는 아님, 완전 독립 진행도 가능).

Phase 14/15 둘 다 끝나면 이 섹션을 "없음. Phase 12는 대기 (사람 확인 필요)"로
갱신할 것.

Phase 12는 대기만 시켜두고 스스로 시작하지 말 것 —
`specs/12_refresh_token_rotation_logout.md` "주의" 절 참고, 범위를
사람과 먼저 확정해야 함.

보류 중인 항목(착수 금지):
- Windows Desktop bundle 제품 통합 검증 — 프론트/패키징 담당과 협의 필요
- Case/Evidence/Search 신규 Domain Tool — Core Descriptor 열릴 때까지 대기
- Phase 12 (refresh token rotation/로그아웃) — 범위 확정 전까지 대기
- `tests/unit`(Core)/`tests/integration`을 CI에 추가하는 것 — Core 담당과
  별도 상의 필요, 백엔드가 일방적으로 진행하지 말 것
- Phase 12 (refresh token rotation/로그아웃) — 범위 확정 전까지 대기

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
  `ruff check .` 클린 확인. PR #12 생성 (머지 완료).

### 2026-09-15 (재검토)
- Phase 1~9 완료 후 "테스트 green = 문제 없음" 결론에 대한 재검증 요청 받음.
  실행 경로를 직접 추적해서 재조사, 추측 없이 코드/재현으로만 판단.
- 확인된 실제 문제 2건: (1) `apex-mcp` CLI가 `JwtTokenVerifier`/
  `DbFrontendSecurityProvider`를 안 쓰고 여전히 개발용 스텁으로만 동작
  (배포 가이드 명령어도 이것 때문에 실행 불가, 재현함). (2)
  `DbFrontendSecurityProvider.authorize()`의 1회 소비 로직에 경쟁 조건
  있음 (원자적 UPDATE/행 잠금 없음).
- 확인했으나 문제 아님으로 판정한 것 2건: `PersistentFrontendSecurityProvider
  .confirmation_for`가 항상 `None`인 건 의도된 추상 기반 설계 (서브클래스
  `DbFrontendSecurityProvider`가 실제 로직 담당, docstring으로 확인).
  `JwtTokenVerifier`의 `client_id`에 issuer를 넣는 것도 실제로 읽는 곳이
  없어서 영향 없음.
- 참고 사항 1건 (버그 아님): refresh token rotation/로그아웃 엔드포인트
  없음. 어떤 스펙에도 요구사항 명시된 적 없음.
- Core 쪽 문제 1건 별도 확인 (Firefox NSS redaction 스키마 vs
  `_SAFE_INDICATOR_FIELD_NAMES` 화이트리스트 불일치) — 백엔드/MCP 범위
  밖이라 이 마스터플랜에는 안 넣고 Core 담당에게 별도 전달.
- `specs/10_cli_jwt_wiring_fix.md`, `specs/11_confirmation_grant_race_fix.md`,
  `specs/12_refresh_token_rotation_logout.md` 신규 작성.
  `00_MASTER_PLAN.md` 5절/6-1절 Phase 9 상태 정정(완료), 6-3절에 이번
  재검토 요약 추가. 전체 근거는
  `docs/backend/AUDIT_2026-09-15_production_wiring.md` 참고.
- Phase 10 완료: apex-mcp CLI JWT 인증 체인 배선. PR #14 생성 (머지 완료).
- Phase 11 완료: confirmation grant 소비 경쟁 조건 수정 (원자적 UPDATE).
  PR #15 생성 (머지 완료).
- Phase 13 완료: CI `tests/backend` 검증 공백 수정. `mcp-ci.yml`에 `Backend tests`
  스텝 추가. 로컬 45/45 통과 확인. PR #16 생성 (머지 대기).
