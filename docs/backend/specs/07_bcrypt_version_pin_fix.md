# Phase 7 — bcrypt 버전 고정 (실제 버그 수정)

상태: 완료 (2026-09-15)
선행조건: 없음 (바로 착수 가능)
분류: fix

## 배경 (사람이 직접 재현 확인함, 추측 아님)

`pyproject.toml`의 backend extra가 `passlib[bcrypt]>=1.7`만 지정하고
`bcrypt` 자체 버전은 안 박아뒀다. 그 결과 `uv.lock`이 최신 `bcrypt==5.0.0`으로
잠겨있는데, `passlib==1.7.4`가 `bcrypt>=4.1`의 변경된 동작(72바이트 넘는
입력을 조용히 자르지 않고 `ValueError`를 던짐, `_bcrypt.__about__` 속성 제거)과
호환이 안 된다.

재현 확인: 지금 lock 상태 그대로 `uv sync`해서 `tests/backend/test_auth_api.py`를
돌리면 `test_password_hash_and_verify`, `test_login_success` 두 개가
`ValueError: password cannot be longer than 72 bytes` 로 죽는다.
`bcrypt`를 `4.0.1`로 내리면 즉시 통과하는 것까지 확인함 — 진짜 이 조합
문제가 맞고, 코드 로직 버그가 아니라 순수 버전 고정 누락이다.

**이 상태는 지금 당장 신규로 `uv sync`하는 누구에게나 재현된다** (CI 포함
가능성 높음 — CI가 매번 새로 resolve하는 게 아니라 lock 그대로 설치한다면
지금 lock이 이미 깨진 버전으로 고정돼 있어서 CI도 언젠가 이걸로 갈아탈 때
같이 깨짐). 그러니 최우선으로 고친다.

## 할 일

1. `pyproject.toml`의 `backend` extra에서 `passlib[bcrypt]>=1.7` 옆에
   `bcrypt>=4.0,<4.1`를 명시적으로 추가한다.
2. `uv lock`을 다시 돌려서 `uv.lock`에 `bcrypt==4.0.1`(또는 4.0.x 최신)이
   잠기도록 갱신한다.
3. `uv sync --locked --extra dev --extra mcp-server --extra backend`로 클린
   설치 재현 → `tests/backend`, `tests/mcp` 전부 통과 확인 (기준: 109개 전부
   통과, 새로 깨지는 테스트 없어야 함).
4. `ruff check src/apex_backend tests/backend`, `mypy src/apex_backend` 클린 확인.
5. 장기적으로 passlib 자체가 유지보수가 뜸해서 같은 문제가 또 생길 수 있음 —
   당장 고칠 필요는 없지만, `specs/00_DECISIONS.md`에 "언젠가 passlib을
   직접 `bcrypt` 호출로 교체하는 것도 고려" 정도로 남겨서 다음에 누가 또
   이 문제를 겪으면 왜 이렇게 박아뒀는지 알 수 있게 한다.

## 완료 조건

- [ ] `pyproject.toml`에 `bcrypt` 버전 상한 명시
- [ ] `uv.lock` 갱신, 같은 커밋에 포함 (`01_DEVELOPMENT_RULES.md` 7절 규칙)
- [ ] `tests/backend`, `tests/mcp` 클린 설치 기준으로 전부 통과 (109개 기준)
- [ ] ruff/mypy 클린
- [ ] `specs/00_DECISIONS.md`에 이 결정 기록 추가
- [ ] PR 생성 (`01_DEVELOPMENT_RULES.md` 6절 규칙 그대로 적용, 아래 참고)

## PR 규칙 (기존 6절과 동일하게 적용)

- 브랜치: `fix/backend-phase-7-bcrypt-pin`
- PR 제목: `fix(backend): Phase 7 — bcrypt 버전 고정`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- PR 설명에 완료 조건 체크리스트, 재현 방법과 수정 전/후 테스트 결과 포함
- 커밋 author는 `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
