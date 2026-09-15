# Phase 14 — `--log-level` 죽은 설정값 실제로 적용

상태: 완료
선행조건: 없음
분류: fix (낮은 우선순위)

## 배경 (코드 확인함, 추측 아님)

`src/apex_mcp/config.py`의 `McpConfig.log_level`은 값 검증(`DEBUG/INFO/
WARNING/ERROR/CRITICAL` 중 하나인지)만 하고, `--log-level` CLI 인자와
`APEX_MCP_LOG_LEVEL` 환경변수로 설정할 수 있게 돼있다. 근데 이 값을
실제로 Python `logging` 모듈에 적용하는 코드가 리포 전체에 없다:

```
$ grep -rln "^import logging\|logging.getLogger" src/apex_backend src/apex_mcp --include="*.py"
(결과 없음)
```

같은 `McpConfig`의 다른 필드들은 실제로 쓰인다 (`server.py`의
`allowed_tools=validated.allowed_tools`, `engine_adapter.py`의
`initialize=validated.initialize_database`, `ai_provider` 조건부 사용).
`log_level`만 검증되고 버려진다. `--log-level DEBUG`를 줘도 실제로는
아무 로그 레벨도 안 바뀐다 (애초에 이 계층에 로거 자체가 없음).

기능이 깨지는 건 아니고, 운영자가 설정이 실제로 동작한다고 착각하게
만드는 misleading config다.

## 할 일

1. `apex_mcp`/`apex_backend`에 표준 `logging` 모듈 기반 로거를 도입한다
   (예: 모듈별 `logging.getLogger(__name__)`). 처음부터 전면적인 로깅
   체계를 새로 설계하지 말고, 최소한 다음 두 곳부터 시작:
   - `src/apex_mcp/__main__.py`의 `main()` 시작 부분에서
     `logging.basicConfig(level=config.log_level, ...)`(또는 동등한
     설정)를 호출해서 `--log-level`이 실제로 루트 로거 레벨을 바꾸게 함.
   - Phase 15(스펙 15 참고)의 JWKS 조회 실패 로깅이 이 로거를 쓸 수
     있게, 이 Phase를 먼저 하거나 Phase 15와 순서 조율할 것 (둘 다
     독립적으로 진행 가능하지만 최종적으로는 같은 로깅 체계를 써야 함).
2. `--log-level`이 실제로 적용되는지 검증하는 테스트 추가 (예:
   `caplog` 픽스처로 특정 레벨 이하 로그가 안 찍히는지 확인).
3. 이 Phase에서 apex_forensic(Core) 쪽 로깅 체계까지 건드리지 말 것 —
   범위는 `apex_mcp`/`apex_backend`로 한정.

## 완료 조건

- [ ] `--log-level`/`APEX_MCP_LOG_LEVEL`이 실제로 로그 출력 레벨에 영향을 줌
- [ ] 검증 테스트 신규 작성, 통과
- [ ] 기존 `tests/mcp`, `tests/backend` 회귀 없음
- [ ] ruff/mypy 클린
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `fix/backend-phase-14-log-level-wiring`
- PR 제목: `fix(backend): Phase 14 — apex-mcp log-level 설정 실제 적용`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
