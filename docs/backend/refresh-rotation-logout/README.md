# Phase 12 — refresh token rotation & logout (as-built)

## 구현 내역

### DB 스키마 변경

- `user_sessions.current_refresh_jti VARCHAR(36) NULL` 추가 (migration 0002)
- 기존 세션은 NULL로 유지됨 (레거시 경로 참고)

### 토큰 rotation 흐름

```
login  → UserSession.current_refresh_jti = <jti-A>
         refresh token JWT claim jti = <jti-A>

refresh → UPDATE user_sessions
            SET current_refresh_jti = <jti-B>
            WHERE session_id = ? AND current_refresh_jti = <jti-A> AND revoked_at IS NULL
         rowcount == 1 → 성공, 새 토큰 발급 (jti-B)
         rowcount == 0 → 아래 세 가지 경우로 분기
```

### rowcount == 0 분기 처리

| 경우 | 조건 | 처리 |
|---|---|---|
| 세션 없음/이미 말소 | `session IS NULL or revoked_at IS NOT NULL` | 401 반환, 세션 말소 없음 |
| 레거시 세션 | `current_refresh_jti IS NULL` | 401 반환, 재로그인 안내, 세션 말소 없음 |
| 재사용 탐지 | `current_refresh_jti != incoming_jti` (이미 rotation됨) | `revoked_at = now` 설정 후 401 반환 |

### 동시성

Phase 11과 동일한 atomic UPDATE 패턴 사용. SQLAlchemy `update(...).where(...)` 단일 쿼리.
SQLite WAL + asyncio 단일 스레드 환경에서 두 코루틴이 같은 refresh token을 동시에 제출하면
하나만 UPDATE 성공 (rowcount==1), 나머지는 rowcount==0 → 재사용으로 간주, 세션 전체 말소.

### POST /auth/logout

- Bearer access token 필요 (`JwtTokenVerifier` 검증)
- claims의 `session_id`로 `UserSession.revoked_at = datetime.now(UTC)` 설정
- 멱등: 이미 말소된 세션은 조용히 무시

### POST /confirmations 세션 검증

- JWT 검증 후 DB에서 `UserSession` 조회
- 세션이 존재하고 `is_active == False`이면 401 반환
- 세션이 DB에 없으면 통과 (JWT 서명 검증만으로 충분, 레거시/테스트 호환)

### MCP 경로 제한

`apex_mcp`는 JWT 서명만 검증한다. 로그아웃 후에도 access token의 `exp` 전까지
MCP 도구 호출이 기술적으로 가능하다. 즉각 차단이 필요하면 `APEX_ACCESS_TOKEN_TTL`을
짧게 설정할 것 (예: 300초).

## 파일 목록

| 파일 | 변경 내역 |
|---|---|
| `src/apex_backend/models.py` | `UserSession.current_refresh_jti` 컬럼 추가 |
| `src/apex_backend/alembic/versions/0002_refresh_jti.py` | DB 마이그레이션 신규 |
| `src/apex_backend/auth/jwt_utils.py` | `issue_refresh_token(jti=)` 파라미터 추가 |
| `src/apex_backend/auth/service.py` | `login()` jti 저장, `refresh()` atomic rotation, `logout()` 신규 |
| `src/apex_backend/auth/router.py` | `POST /auth/logout` 엔드포인트 신규, `_get_jwt_verifier` 의존성 추가 |
| `src/apex_backend/auth/schemas.py` | `LogoutResponse` 추가 |
| `src/apex_backend/auth/confirmation_router.py` | DB 세션 말소 체크 추가 |
| `src/apex_backend/app.py` | `_get_jwt_verifier` → auth_router dependency 배선 |
| `tests/backend/test_refresh_rotation.py` | 9개 신규 테스트 |
| `docs/backend/deployment/README.md` | 운영 참고 섹션 추가 |
