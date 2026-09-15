# Log-Level Wiring — as-built (Phase 14)

상태: 완료 (PR #17)

## 문제

`McpConfig.log_level`이 `DEBUG/INFO/WARNING/ERROR/CRITICAL` 검증만 하고
Python `logging` 모듈에 실제로 적용하는 코드가 없었다. `--log-level DEBUG`를
줘도 루트 로거 레벨이 바뀌지 않아 모든 모듈의 로그 출력 레벨에 영향 없음.

## 변경 내용

`src/apex_mcp/__main__.py`:

```python
import logging

_logger = logging.getLogger(__name__)

def main(...):
    ...
    config = McpConfig(...).validate()
    logging.basicConfig(level=config.log_level, format="%(levelname)s %(name)s %(message)s")
    logging.root.setLevel(config.log_level)  # basicConfig가 no-op일 때도 항상 적용
    _logger.debug(
        "apex-mcp starting (transport=%s, log_level=%s)", args.transport, config.log_level
    )
```

- `logging.basicConfig()`: 핸들러 미존재 시 루트 로거에 핸들러 추가 + 레벨 설정
- `logging.root.setLevel()`: 이미 핸들러가 있어 `basicConfig`가 no-op인 경우에도 레벨 보장
- `_logger.debug()`: 기동 메시지. 로깅 체계가 실제 동작하는지 운영 중 확인 가능

## 테스트

`tests/mcp/test_log_level.py` (4개 신규):

| 테스트 | 검증 내용 |
|---|---|
| `test_log_level_debug_sets_root_logger` | `--log-level DEBUG` → `logging.root.level == logging.DEBUG` |
| `test_log_level_warning_sets_root_logger` | `--log-level WARNING` → `logging.root.level == logging.WARNING` |
| `test_log_level_debug_startup_log_captured` | DEBUG 레벨에서 "apex-mcp starting" 로그 포착 |
| `test_log_level_warning_startup_log_hidden` | WARNING 레벨에서 DEBUG 로그 미포착 |

`_restore_root_log_level` fixture(autouse)로 각 테스트 후 루트 로거 레벨 복원.

## 범위 제한

`apex_forensic`(Core) 쪽 로깅 체계는 건드리지 않음. `apex_mcp`/`apex_backend`로 한정.
