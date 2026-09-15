# CI Backend Tests — as-built (Phase 13)

상태: 완료 (PR #16)

## 문제

`.github/workflows/mcp-ci.yml`의 `contract-and-security` job이
`tests/mcp`(66개)만 실행하고 `tests/backend`(45개)는 전혀 실행하지 않았다.
`tests/unit`(Core, 438개)·`tests/integration`(29개)도 CI에서 실행 안 됐으나
이번 범위 제외.

## 변경 내용

`.github/workflows/mcp-ci.yml` — `contract-and-security` job에 스텝 추가:

```yaml
- name: Backend tests
  run: uv run --locked pytest -q tests/backend
```

`MCP contract tests` 스텝 바로 뒤, `Lint and type check` 스텝 앞에 삽입.
`extra backend`는 기존 `uv sync --locked --extra dev --extra mcp-server --extra backend`에
이미 포함돼있어서 별도 설치 불필요.

## 테스트

로컬 `tests/backend` 45/45 통과 확인:

| 파일 | 통과 |
|---|---|
| `test_auth_api.py` | 11 |
| `test_confirmation_grant.py` | 14 |
| `test_jwt_verifier.py` | 11 |
| `test_models.py` | 9 |
| **합계** | **45** |

## 제외 항목

`tests/unit`(Core, 438개)·`tests/integration`(29개)은 Core 담당(권태욱) 소관이라
백엔드가 일방적으로 CI 정책 변경 부적절. CI 실행 시간 검토도 필요. Core 담당과
별도 상의 후 결정.
