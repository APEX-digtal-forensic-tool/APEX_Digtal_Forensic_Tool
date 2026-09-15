# Phase 13 — CI에 `tests/backend` 실행 추가 (실제 버그: 검증 공백)

상태: 완료
선행조건: 없음 (Phase 10~12와 무관, 바로 착수 가능)
분류: fix

## 배경 (코드/워크플로 직접 읽고 확인함, 추측 아님)

리포에 있는 유일한 CI 워크플로 `.github/workflows/mcp-ci.yml`의
`contract-and-security` job은 pytest를 딱 한 줄만 돈다:

```yaml
- name: MCP contract tests
  run: uv run --locked pytest -q tests/mcp
```

같은 job 마지막에 "Security and release gate"라는 스텝이 있어서
`tools/verify_engine_release.py --mcp-only --json`을 실행하는데, 뭔가
더 검증해줄 것처럼 보이지만 실제로는 아니다. `tools/verify_engine_release.py`의
`run_release_gate()`를 직접 읽어보면:

```python
if not mcp_only:
    ...
    checks.append(_run_command("pytest", [python_executable, "-m", "pytest", "-q"], ...))
checks.append(
    _run_command("mcp-contract", [python_executable, "-m", "pytest", "-q", "tests/mcp"], ...)
)
```

전체 스위트를 도는 `pytest -q`(경로 제한 없음) 블록이 `if not mcp_only:`
안에 있는데, CI는 `--mcp-only`로 호출하기 때문에 이 블록이 통째로
스킵된다. 결과적으로 CI가 실제로 실행하는 pytest는 `tests/mcp` 하나뿐이다.

`pytest --collect-only`로 직접 세어봄:

| 디렉터리 | 테스트 수 | CI 실행 여부 |
|---|---|---|
| `tests/mcp` | 66 | O |
| `tests/backend` | 45 | **X** |
| `tests/unit` (Core) | 438 | X (이번 Phase 범위 아님, 아래 참고) |
| `tests/integration` | 29 | X (이번 Phase 범위 아님, 아래 참고) |

**이게 왜 실제 버그인가**: Phase 7에서 발견했던 bcrypt/passlib 비호환
버그(`tests/backend/test_auth_api.py` 2개 실패)가 지금까지 CI에서 한
번도 안 걸린 이유가 정확히 이거다 — CI가 애초에 `tests/backend`를 돈
적이 없어서, 그 버그가 있는 상태로 여러 번 merge돼도 CI는 계속
green이었다. `00_MASTER_PLAN.md` 6절의 완료 기준도 "tests/mcp ... 통과"만
명시하고 있어서 이 gap을 마스터플랜 작성 시점부터 아무도 못 잡았다.
지금 이 순간에도 `tests/backend`를 깨뜨리는 PR이 올라오면 CI는 계속
green을 찍는다.

`mypy --strict src`, `ruff check src ...`는 `src/` 전체를 대상으로 하니
타입/린트 문제는 잡히지만, **실제 동작 검증(pytest)에서 `apex_backend`가
완전히 빠져있다**는 게 핵심 문제다.

## 할 일

1. `.github/workflows/mcp-ci.yml`의 `contract-and-security` job에
   `tests/backend`를 도는 스텝을 추가한다. 기존 "MCP contract tests"
   스텝 이름/구조를 참고해서 자연스럽게 추가 (별도 스텝으로 분리하거나,
   같은 스텝에서 `pytest -q tests/mcp tests/backend`로 합쳐도 됨 — 실패
   시 어느 쪽이 깨졌는지 구분하기 쉬운 쪽으로 판단해서 결정).
2. `tests/backend`가 요구하는 extra(`backend`)가 이미
   `uv sync --locked --extra dev --extra mcp-server --extra backend`에
   포함돼있는지 확인 (이미 포함돼있을 가능성 높음 — Phase 7에서 이
   extra를 CI가 이미 설치하고 있었기 때문. 확인만 하고 빠져있으면 추가).
3. 로컬에서 클린 환경 기준으로 `tests/backend` 전체가 실제로 통과하는지
   먼저 재확인 (지금 시점 기준으로는 통과할 것으로 보이나, CI에 추가하기
   전에 반드시 재확인 — 여기서 실패가 나오면 그것도 이 Phase의 완료
   조건에 포함해서 같이 고칠 것).
4. **`tests/unit`(Core, 438개)과 `tests/integration`(29개)은 이번 Phase
   범위에 넣지 말 것.** 이유: (a) Core 담당(권태욱) 소관 테스트라 백엔드/
   MCP 담당이 일방적으로 CI 정책을 바꾸는 건 부적절하고, (b) 438개
   테스트를 추가하면 CI 실행 시간(현재 job timeout 30분)에 영향을 줄 수
   있어서 별도 검토가 필요함. 대신 PR 설명에 "Core 테스트는 이번 범위에서
   제외했고, CI에 포함시킬지는 Core 담당과 별도로 상의 필요"라고 명시할 것.

## 완료 조건

- [ ] `mcp-ci.yml`에 `tests/backend`를 실행하는 스텝 추가
- [ ] 로컬 클린 설치 기준으로 `tests/backend` 전체 통과 확인 (실패
      있었다면 같이 수정)
- [ ] 위 변경을 담은 PR 자체의 CI가 실제로 `tests/backend` 스텝을 실행하고
      통과하는 것까지 확인 (PR 링크/실행 로그를 PR 설명에 포함)
- [ ] `tests/unit`, `tests/integration`은 건드리지 않음, PR 설명에 제외
      사유 명시
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `fix/backend-phase-13-ci-backend-tests`
- PR 제목: `fix(backend): Phase 13 — CI에 tests/backend 실행 추가`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
