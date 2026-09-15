# JWKS Failure Logging — as-built (Phase 15)

상태: 완료 (PR #18)

## 문제

`JwtTokenVerifier._fetch_jwks()`의 두 `except` 블록이 로그 없이 조용히 실패했다:
- 전체 JWKS fetch 실패 시: `except Exception: return` — 로그 없음
- 개별 JWK 파싱 실패 시: `except Exception: continue` — 로그 없음

JWKS 엔드포인트가 다운돼 MCP 서버가 모든 토큰을 거부해도 서버 쪽에 아무 흔적이
남지 않아 운영자가 원인을 추적할 수 없었다.

## 변경 내용

`src/apex_backend/auth/jwt_verifier.py`:

```python
import logging
_logger = logging.getLogger(__name__)
```

`_fetch_jwks()` fetch 실패 시:
- 빈 캐시: `"JWKS fetch failed for {uri}; no cached keys — all tokens will be rejected"` (WARNING + exc_info)
- 캐시 있음: `"JWKS fetch failed for {uri}; continuing with N cached key(s)"` (WARNING + exc_info)

개별 JWK 파싱 실패 시:
- `"Failed to parse JWK kid={kid!r} from {uri}; skipping"` (WARNING + exc_info)

**fail-open/fail-closed 동작 변경 없음**:
- 빈 캐시에서 fetch 실패 → `_keys == {}` 유지 → 모든 토큰 거부 (fail-closed)
- 캐시 있는 상태에서 fetch 실패 → 기존 캐시 유지 (fail-open to stale cache)
- 개별 JWK 파싱 실패 → 해당 키 건너뜀, 나머지 키는 정상 캐시

## 테스트

`tests/backend/test_jwks_failure_logging.py` (7개 신규):

| 테스트 | 검증 내용 |
|---|---|
| `test_fetch_failure_empty_cache_logs_warning` | 빈 캐시 fetch 실패 → WARNING + "no cached keys" |
| `test_fetch_failure_stale_cache_logs_warning` | 캐시 있는 상태 fetch 실패 → WARNING + "cached key" |
| `test_fetch_failure_includes_exc_info` | exc_info 첨부 확인 |
| `test_bad_jwk_logs_warning` | 파싱 실패 JWK → WARNING + kid |
| `test_bad_jwk_does_not_affect_valid_keys` | 파싱 실패 무시, 유효 키 생존 |
| `test_fetch_failure_empty_cache_fail_closed` | fail-closed 동작 유지 |
| `test_fetch_failure_stale_cache_fail_open` | fail-open(stale cache) 동작 유지 |
