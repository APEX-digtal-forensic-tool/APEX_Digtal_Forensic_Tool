# Phase 10 — apex-mcp CLI를 새 JWT 인증 체인에 실제로 배선

상태: 대기
선행조건: 없음 (Phase 1~9 완료된 코드 기반 위에서 바로 착수 가능)
분류: fix

## 배경 (재현 확인함, 추측 아님)

Phase 3~5에서 만든 `JwtTokenVerifier`(`src/apex_backend/auth/jwt_verifier.py`),
`DbFrontendSecurityProvider`(`src/apex_backend/auth/db_confirmation.py`)는
전부 구현되고 테스트도 통과하는데, 실제로 배포해서 띄우는 `apex-mcp`
CLI(`src/apex_mcp/__main__.py`, `pyproject.toml`의
`apex-mcp = "apex_mcp.__main__:main"`)는 이 둘을 단 한 줄도 쓰지 않는다.

`--transport http` 분기는 지금도 `InMemoryFrontendSecurityProvider()`를
새로 만들어서 `--http-actor-id`/`--http-session-id`/`--http-tenant-id`/
`--http-case-id`/`--http-role` 같은 CLI 인자로 받은 액터 하나를 고정
등록하고, `StaticBearerTokenVerifier(secret, access_token)`(비교 대상
토큰도 CLI/`APEX_MCP_HTTP_TOKEN` 환경변수로 고정된 문자열 하나)를
`token_verifier`로 넘긴다. 요청마다 실제 JWT를 검증해서 사용자를 가려내는
경로가 없다.

증거 (직접 실행/grep해서 확인):

- `grep -rln "DbFrontendSecurityProvider\|JwtTokenVerifier(" --include="*.py" . | grep -v /tests/`
  → `apex_backend` 쪽 파일만 나오고 `apex_mcp` 패키지는 안 나옴.
- `grep -rn "APEX_JWKS_URI\|APEX_JWKS_CACHE_TTL" --include="*.py" .` → 결과 없음.
  `docs/backend/deployment/README.md`가 "apex-mcp 실행 시 필요"라고 적어놓은
  환경변수를 실제로 읽는 코드가 리포 전체에 없다.
- `docs/backend/deployment/README.md` 4단계 명령어를 그대로 실행하면
  `--http`라는 플래그가 없어서 (`--transport http`가 맞음) 바로 실패하고,
  고쳐서 실행해도 `--http-actor-id` 등 필수 인자가 없으면 또 막힌다. 즉
  가이드에 적힌 방식(`APEX_JWKS_URI` 환경변수만으로 띄우기)으로는 절대 못
  띄운다.
- `tests/mcp/test_e2e_backend_integration.py`("Phase 6 E2E")는 `apex-mcp`
  CLI를 실행하지 않고 `create_http_app()`을 테스트 코드 안에서 직접
  파이썬으로 호출해서 `JwtTokenVerifier`를 수동 조립한다. CLI 배선 자체는
  한 번도 검증된 적이 없다.
- `.github/workflows/mcp-ci.yml`에도 `apex-mcp` CLI를 실제로 띄워보는
  스텝이 없다 (`grep -n "apex-mcp\|--http\|--transport"` → 결과 없음).

`00_MASTER_PLAN.md` 6절 완료 기준 중 "`src/apex_mcp`가 더 이상
`InMemoryFrontendSecurityProvider`/`StaticBearerTokenVerifier`를 프로덕션
경로에서 쓰지 않음"이 실제로는 충족되지 않은 상태다.

## 할 일

1. `src/apex_mcp/__main__.py`의 `--transport http` 분기에 새 인자를
   추가해서, JWKS 기반 검증 모드를 선택할 수 있게 한다. 제안 예시
   (정확한 이름/조합은 구현하면서 기존 인자 스타일에 맞춰 판단):
   - `--http-jwks-uri` (또는 `APEX_JWKS_URI` 환경변수) — 지정되면
     `JwtTokenVerifier`를 구성해서 `token_verifier`로 사용.
   - `--http-issuer`, `--http-audience` — JWT 발급 시 쓰인 issuer/audience와
     맞춰서 `JwtTokenVerifier`에 전달 (이미 `--http-issuer-url`,
     `--http-resource-url` 인자가 있으니 재사용 가능한지 먼저 확인할 것).
   - `--http-confirmation-db-url` (또는 기존 `--database` 인자 재사용
     가능한지 확인) — 지정되면 `DbFrontendSecurityProvider`를 구성해서
     `frontend_security`로 사용.
2. 기존 `StaticBearerTokenVerifier` + `InMemoryFrontendSecurityProvider`
   경로는 삭제하지 말고 **로컬 개발/테스트 전용**으로 명확히 분리해서
   남긴다 (예: 위 새 인자들이 하나도 안 주어졌을 때만 폴백으로 쓰거나,
   `--http-dev-mode` 같은 명시적 플래그 뒤로 옮기기). 실수로 프로덕션에서
   개발용 스텁이 기본값이 되는 상황은 피할 것 — 다만 이 판단(폴백 vs 필수
   플래그)은 구현하면서 기존 CLI 인자 설계와 제일 자연스럽게 맞는 쪽으로
   결정해도 된다.
3. `docs/backend/deployment/README.md` 4단계 명령어를 실제 새 인터페이스에
   맞게 다시 쓰고, **직접 실행해서 재현 확인** (에러 없이 뜨는지, 헬스체크나
   간단한 tool 호출까지 성공하는지).
4. `tests/mcp/test_e2e_backend_integration.py` 또는 새 테스트 파일에
   `apex-mcp` CLI를 서브프로세스로 실제로 띄워서 (`subprocess.Popen` 등)
   JWT 토큰으로 인증되는 요청과, 잘못된/만료된 토큰으로 거부되는 요청을
   최소 1개씩 검증하는 테스트를 추가한다. 이게 이번 Phase의 핵심 완료
   기준이다 — CLI 배선 자체를 테스트가 커버해야 다음에 또 이 gap이
   생기는 걸 막을 수 있다.
5. `.github/workflows/mcp-ci.yml`에 위 4번 테스트가 CI에서 실행되는지
   확인 (이미 `pytest tests/mcp`를 도는 스텝이 있다면 새 테스트 파일도
   자동으로 포함될 것 — 별도 스텝 추가가 필요한지만 확인).

## 완료 조건

- [ ] `apex-mcp --transport http`가 JWKS URI/issuer/audience/confirmation DB를
      인자로 받아 `JwtTokenVerifier` + `DbFrontendSecurityProvider`를
      실제로 구성해서 쓸 수 있음
- [ ] 개발용 스텁 경로(`StaticBearerTokenVerifier`/`InMemoryFrontendSecurityProvider`)는
      남아있되 프로덕션 기본 경로와 명확히 분리됨
- [ ] `docs/backend/deployment/README.md` 4단계 명령어를 그대로 실행해서
      실제로 뜨는 것까지 확인 (재현 로그를 PR 설명에 포함)
- [ ] CLI를 실제 서브프로세스로 띄워서 JWT 인증 성공/실패를 검증하는 테스트
      신규 작성, 통과
- [ ] 기존 `tests/mcp`, `tests/backend` 전부 계속 통과 (회귀 없음)
- [ ] ruff/mypy 클린
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `fix/backend-phase-10-cli-jwt-wiring`
- PR 제목: `fix(backend): Phase 10 — apex-mcp CLI JWT 인증 체인 배선`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- PR 설명에 완료 조건 체크리스트, 배포 가이드 명령어 재현 결과(전/후) 포함
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
