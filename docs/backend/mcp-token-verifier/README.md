# Phase 3 완료 — MCP용 JwtTokenVerifier 구현

상태: 완료
완료일: 2026-09-12

## 구현 요약

JWKS 엔드포인트에서 RS256 공개키를 가져와 JWT를 검증하는 `JwtTokenVerifier`를
구현했다. MCP SDK의 `TokenVerifier` Protocol(`async verify_token(token) ->
AccessToken | None`)을 만족한다.

## 만든/수정한 파일

| 파일 | 설명 |
|---|---|
| `src/apex_backend/auth/jwt_verifier.py` | `JwtTokenVerifier`, `_jwk_to_pem`, `_b64url_to_int` |
| `tests/backend/test_jwt_verifier.py` | 테스트 11개 |

## 주요 동작

### verify_token 흐름

1. `jose_jwt.get_unverified_header(token)` → `kid` 추출
2. `_resolve_key(kid)` → PEM 공개키 반환 (캐시 hit/miss)
3. `jose_jwt.decode(token, pem, algorithms=["RS256"], audience=..., issuer=...)` → claims 딕셔너리
4. `claims["token_type"] == "access"` 확인
5. `AccessToken` 생성 후 반환. 단계 어디서든 실패하면 `None` 반환 (예외 절대 propagate 안 함)

### 키 캐싱

- `_keys: dict[str, str]` — `{kid: PEM}` 인메모리 캐시
- `_fetched_at: float` — `time.monotonic()` 기준 마지막 JWKS fetch 시각
- `_lock: asyncio.Lock()` — concurrent 요청 시 중복 fetch 방지
- 캐시 만료 조건: `(now - _fetched_at) > cache_ttl_seconds` (기본값 300초)
- unknown kid 또는 만료 시 `_fetch_jwks()` 호출 후 재조회
- JWKS fetch 실패(네트워크 오류, HTTP 오류) 시 조용히 no-op (기존 캐시 유지)

### JWKS → PEM 변환 (`_jwk_to_pem`)

- JWK의 `n`, `e` (base64url) → `int` 변환
- `cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers(e, n).public_key()` → PEM

## 설계 결정과 이유

| 결정 | 이유 |
|---|---|
| 공개키만 사용, 개인키 없음 | 검증만 하면 됨 — 개인키는 apex_backend에만 있음. Option A 아키텍처 직접 구현. |
| `jose`(python-jose) 사용 | 기존 Phase 2 의존성(`python-jose[cryptography]`)과 통일 |
| 검증 실패 시 예외 대신 `None` | MCP SDK `TokenVerifier` Protocol이 `AccessToken | None` 반환을 요구 |
| asyncio.Lock으로 fetch 직렬화 | 같은 kid 미스가 동시에 여러 번 발생해도 JWKS를 한 번만 fetch |
| kid 없는 토큰도 허용 (첫 번째 키 사용) | 단일 키 환경에서 kid 생략 허용 — 실제로는 kid 포함 필수 권장 |

## 테스트 현황

- 추가: 11개 (`tests/backend/test_jwt_verifier.py`)
- 누적 (Phase 3 완료 시점): 31개 통과
- 다루는 케이스:
  - 유효 토큰 → `AccessToken` 반환, claims 확인
  - 위조 서명 → `None`
  - 만료 토큰 → `None`
  - 잘못된 issuer / audience → `None`
  - token_type이 "refresh"인 access token → `None`
  - kid 불일치 → `None`
  - JWKS fetch 실패 시 graceful no-op
  - 캐시 TTL 내 재사용 (fetch 횟수 확인)
  - kid 없는 토큰 처리

## 알려진 제약

- 키 로테이션 중 구 kid와 신 kid 혼용 처리: 신 JWKS에 구 kid가 없으면 구 토큰 검증 실패. 현재 단일 kid 운용만 검증됨.
- JWKS fetch는 동기 SQLAlchemy 경로(`call_tool`)가 아닌 async 경로에서만 동작. `call_tool`은 `verify_token`을 직접 호출하지 않으므로 실제 문제 없음.
