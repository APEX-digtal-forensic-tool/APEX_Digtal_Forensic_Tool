# Phase 2 완료 — 인증/토큰 발급 API

상태: 완료
완료일: 2026-09-12

## 구현 요약

FastAPI 앱 팩토리 + RS256 JWT 발급 API + JWKS 엔드포인트 구현.
MCP `TokenVerifier` (Phase 3)가 이 JWT를 로컬 서명 검증으로 처리한다.

## 만든/수정한 파일

| 파일 | 설명 |
|---|---|
| `src/apex_backend/app.py` | FastAPI 앱 팩토리 (`create_app(database_url)`) |
| `src/apex_backend/auth/__init__.py` | 서브패키지 진입점 |
| `src/apex_backend/auth/keys.py` | RSA 키 로드/생성, JWK 직렬화 |
| `src/apex_backend/auth/jwt_utils.py` | access/refresh 토큰 발급, refresh 디코딩 |
| `src/apex_backend/auth/scopes.py` | role → scope 매핑 |
| `src/apex_backend/auth/schemas.py` | Pydantic 요청/응답 스키마 |
| `src/apex_backend/auth/service.py` | AuthService: 로그인/리프레시, 비밀번호 해싱 |
| `src/apex_backend/auth/router.py` | FastAPI 라우터 |
| `tests/backend/test_auth_api.py` | 테스트 11개 |

## API 스펙

### POST /auth/login

요청:
```json
{ "email": "user@example.com", "password": "...", "tenant_id": "tenant-1" }
```

응답 (`TokenResponse`):
```json
{
  "access_token": "<JWT>",
  "refresh_token": "<JWT>",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### POST /auth/refresh

요청:
```json
{ "refresh_token": "<JWT>" }
```

응답: 위와 동일.

### GET /.well-known/jwks.json

응답:
```json
{
  "keys": [{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "...", "n": "...", "e": "..." }]
}
```

## JWT 클레임 구조 (access token)

| 클레임 | 값 |
|---|---|
| `iss` | `APEX_ISSUER` env (default: `https://apex.local`) |
| `aud` | `APEX_MCP_RESOURCE` env (default: `https://apex.local/mcp`) |
| `sub` | `actor_id` (users.id) |
| `jti` | random UUID (replay 추적용) |
| `iat` / `exp` | 발급/만료 시각 |
| `session_id` | `UserSession.session_id` |
| `tenant_id` | 테넌트 ID |
| `allowed_case_ids` | 접근 가능한 case_id 목록 |
| `roles` | 사용자 역할 목록 |
| `scopes` | OAuth scope 목록 (아래 매핑 기준) |
| `token_type` | `"access"` |

refresh token은 `sub`, `session_id`, `token_type="refresh"`, `iss`, `aud`, `jti`, `iat`, `exp`만 포함.

## Role → Scope 매핑

| Role | Scopes |
|---|---|
| VIEWER | `apex:mcp`, `apex:read` |
| ANALYST | + `apex:write`, `apex:confirm` |
| EXPORTER | + `apex:export` |
| APPROVER | + `apex:write`, `apex:confirm`, `apex:approve`, `apex:export` |
| ADMIN | 위 전부 + `apex:raw` |

여러 role을 가진 유저는 scope를 union. 근거: `FrontendAuthorizationGate.require` 로직에서 역추적.

## 설계 결정

- **RS256**: MCP 쪽에서 공개키만으로 서명 검증 가능 (대칭키는 공유 필요라 탈락).
- **`kid` 필수**: 키 로테이션 시 구 토큰과 신 토큰 구분 가능.
- **refresh token은 `UserSession`에 바인딩**: session revoke → refresh도 무효화. `refresh` 엔드포인트에서 `UserSession.revoked_at IS NULL` 체크.
- **key 관리**: env `APEX_RS256_PRIVATE_KEY_PEM` 없으면 in-memory 자동 생성 (개발용). 프로덕션은 반드시 env 설정.
- **비밀번호**: bcrypt (passlib). `hash_password`/`verify_password`는 `apex_backend.auth.service`에서 export.
- **환경변수**:
  - `APEX_ISSUER` (default `https://apex.local`)
  - `APEX_MCP_RESOURCE` (default `https://apex.local/mcp`)
  - `APEX_RS256_PRIVATE_KEY_PEM`
  - `APEX_RS256_KID`
  - `APEX_ACCESS_TOKEN_TTL` (seconds, default 3600)
  - `APEX_REFRESH_TOKEN_TTL` (seconds, default 86400)

## 테스트 현황

- 추가: 11개 (test_auth_api.py)
- 누적: 20개 (Phase 1: 9 + Phase 2: 11)
- 결과: 20/20 통과
- ruff clean, mypy clean (13 source files)

## 알려진 제약

- `POST /auth/login`의 end-to-end HTTP 테스트는 앱 내부 SQLite 인스턴스 공유 문제로 unit 수준에서 bad-creds (401) 케이스만 검증. 성공 케이스 통합 테스트는 Phase 6에서 실제 PostgreSQL으로 처리 예정.
- 키 로테이션 (JWKS에 복수 키 게시) 미구현 — Phase 6 범위.
