# APEX Backend — 배포 가이드

상태: Phase 12 완료 (2026-09-16)

## 구성 요소

| 컴포넌트 | 역할 |
|---|---|
| `apex_backend` | FastAPI 앱 — 인증 API + confirmation grant 발급 |
| `apex_mcp` (HTTP 모드) | MCP Streamable HTTP 서버 — `JwtTokenVerifier` 사용 |
| PostgreSQL | 사용자/세션 + confirmation grant 영속 저장소 |

## 환경 변수

### apex_backend

| 변수 | 기본값 | 설명 |
|---|---|---|
| `APEX_DATABASE_URL` | (필수) | `postgresql+asyncpg://user:pass@host:5432/db` |
| `APEX_RS256_PRIVATE_KEY_PEM` | 자동 생성 | RS256 개인키 PEM (프로덕션 필수) |
| `APEX_RS256_KID` | `"default"` | 키 ID (JWKS `kid` 필드 값) |
| `APEX_ISSUER` | `https://apex.local` | JWT `iss` 클레임 |
| `APEX_MCP_RESOURCE` | `https://apex.local/mcp` | JWT `aud` 클레임 |
| `APEX_ACCESS_TOKEN_TTL` | `3600` (**프로덕션 권장: `300`**) | access token 유효기간 (초). MCP 경로는 세션 revoked 여부를 DB로 확인하지 않으므로, 로그아웃/재사용 탐지 후에도 이 TTL이 지날 때까지는 MCP 도구 호출이 통과될 수 있다 — 상세는 "세션 관리 운영 참고" 참고 |
| `APEX_REFRESH_TOKEN_TTL` | `86400` | refresh token 유효기간 (초) |

### apex_mcp (HTTP 모드)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `APEX_JWKS_URI` | (필수) | `https://<backend-host>/.well-known/jwks.json` (`--http-jwks-uri`로도 설정 가능) |
| `APEX_CONFIRMATION_DB_URL` | (필수) | `postgresql+psycopg2://user:pass@host:5432/db` — confirmation grant 조회용 sync 커넥션 (`--http-db-url`로도 설정 가능) |
| `APEX_JWKS_CACHE_TTL` | `300` | JWKS 캐시 TTL (초) (`--http-jwks-cache-ttl`로도 설정 가능) |

## 실행 방법

### 1. 의존성 설치

```bash
uv sync --extra backend --extra mcp-server
```

### 2. DB 마이그레이션

```bash
uv run alembic upgrade head
```

> `APEX_DATABASE_URL`이 설정돼 있어야 한다.

### 3. apex_backend 실행

```bash
APEX_DATABASE_URL="postgresql+asyncpg://apex:secret@localhost:5432/apex" \
APEX_RS256_PRIVATE_KEY_PEM="$(cat private.pem)" \
APEX_ISSUER="https://apex.example.com" \
APEX_MCP_RESOURCE="https://apex.example.com/mcp" \
APEX_ACCESS_TOKEN_TTL="300" \
uv run uvicorn apex_backend.app:create_app --factory --host 0.0.0.0 --port 8000
```

### 4. apex_mcp (HTTP 모드) 실행

```bash
APEX_JWKS_URI="https://apex.example.com/.well-known/jwks.json" \
APEX_CONFIRMATION_DB_URL="postgresql+psycopg2://apex:secret@localhost:5432/apex" \
uv run apex-mcp \
  --database /path/to/forensics.db \
  --schema-dir /path/to/schemas/v1 \
  --transport http \
  --http-port 8765 \
  --http-issuer-url "https://apex.example.com" \
  --http-resource-url "https://apex.example.com/mcp"
```

> `APEX_JWKS_URI`가 설정되면 JWT 프로덕션 모드로 동작한다
> (`JwtTokenVerifier` + `DbFrontendSecurityProvider`). 설정하지 않으면
> `--http-actor-id`/`--http-session-id`/`--http-tenant-id`/`--http-case-id` +
> `APEX_MCP_HTTP_TOKEN`을 요구하는 개발용 스텁 모드로 동작한다.

## 인증 흐름

```
Frontend                apex_backend              apex_mcp
   |                        |                         |
   |── POST /auth/login ───>|                         |
   |<── access_token ───────|                         |
   |                        |                         |
   |── MCP request (Bearer <token>) ─────────────────>|
   |                        |  GET /.well-known/jwks  |
   |                        |<───────────────────────>|
   |                        |  (캐시 TTL 내 재사용)   |
   |<── MCP response ────────────────────────────────|
   |                        |                         |
   |── POST /confirmations (Bearer <token>) ─────────>|  (apex_backend)
   |<── grant_id ───────────|                         |
   |                        |                         |
   |── MCP confirm tool (grant_id) ──────────────────>|
   |<── confirmed result ───────────────────────────|
```

## Confirmation Grant 흐름

1. Frontend가 `POST /confirmations`를 호출 (Bearer access token 필요)
2. apex_backend가 JWT 검증 후 `ConfirmationGrantRow` 생성 (5분 유효, 1회 사용)
3. MCP 서버가 confirmation 필요 Tool 실행 시 `DbFrontendSecurityProvider.confirmation_for`로 DB 조회
4. `authorize(request)` 호출 시 `uses_count` 증가 → 재사용 차단

## 로컬 개발 (in-memory)

JWT 없이 빠르게 테스트하려면 `InMemoryFrontendSecurityProvider` + `StaticBearerTokenVerifier` 사용:

```python
from apex_mcp.frontend_security import (
    InMemoryFrontendSecurityProvider,
    StaticBearerTokenVerifier,
    FrontendSession,
)
from mcp.server.auth.provider import AccessToken

secret = "dev-secret"
token = AccessToken(token=secret, client_id="dev", subject="dev-user",
                    scopes=["apex:mcp", "apex:read", "apex:write", "apex:confirm"],
                    resource="http://localhost:8765/mcp", claims={"iss": "http://localhost:8765"})
security = InMemoryFrontendSecurityProvider()
security.register(token, FrontendSession(
    actor_id="dev-user", session_id="dev-session", tenant_id="dev-tenant",
    allowed_case_ids=frozenset({"case-001"}), roles=frozenset({"ANALYST"}),
))
```

## psycopg2 요구사항

`DbFrontendSecurityProvider`는 동기 SQLAlchemy를 사용한다 (`call_tool`이 sync이므로).
PostgreSQL 연결 시 `psycopg2` 드라이버가 필요하다:

```bash
uv add psycopg2-binary --extra backend
```

SQLite(테스트용)는 추가 드라이버 불필요.

## 세션 관리 운영 참고

### 로그아웃 / MCP 경로 즉각 차단 범위 (중요)

`POST /auth/logout`에 Bearer access token을 보내면 해당 세션이 즉시 무효화된다.
이후 동일 세션의 refresh token은 `401 Session revoked or not found`로 거부되고,
`POST /confirmations`도 DB 세션 상태를 확인하므로 즉시 401로 막힌다.

**MCP 경로(`apex_mcp`, Case/Evidence/Search/Report/AI 등 실제 도구 호출)는 JWT
서명만 검증하고 DB에 세션 revoked 여부를 확인하지 않는다** (Option A 설계 —
매 도구 호출마다 DB 왕복을 만들지 않기 위한 의도적 트레이드오프). 따라서
로그아웃하거나 refresh token 재사용이 탐지돼도, 이미 발급된 access token은
`exp`(만료 시각)까지는 MCP 도구 호출에 계속 사용될 수 있다.

**결정 (2026-09-16, 사람 확정)**: `resolve_session`/`verify_token`에 DB 체크를
추가하는 근본 수정 대신, `APEX_ACCESS_TOKEN_TTL`을 짧게(**300초 권장**) 설정해서
노출 구간을 최소화하는 쪽으로 완화하기로 함. Option A의 "매 도구 호출마다 DB
안 탄다"는 성능·내결함성 이점을 유지하는 게 더 중요하다고 판단. 즉각(0초) 차단이
필요해지면 별도 스펙으로 revoked-session 캐시(하이브리드: MCP 프로세스가 주기적으로
말소 목록을 폴링해 메모리에 캐시) 도입을 검토할 것 — 매 호출 DB 왕복 없이도
차단 지연을 초 단위로 줄일 수 있다.

### refresh token 재사용 탐지

세션이 갑자기 강제 로그아웃되고 이유를 모르겠다면 **refresh token 재사용 탐지가
발동한 것**이다. 클라이언트 측에서 같은 refresh token을 중복 사용하는 버그를 먼저
의심할 것. 탐지 시 `revoked_at`이 설정되며 해당 세션의 모든 토큰이 이후 거부된다.

로그에서 `AuthError: Refresh token reuse detected. Session revoked.` 를 검색하면
어느 세션이 탐지를 발동시켰는지 확인할 수 있다.

### DB 마이그레이션 (Phase 12 이전 세션)

Phase 12 배포 후 기존 세션(`current_refresh_jti IS NULL`)은 다음 refresh 시도에서
`401 Session requires re-login after server upgrade.`를 받는다. 세션은 자동 말소되지
않으며 사용자는 재로그인해야 한다.

## 프로덕션 체크리스트

- [ ] `APEX_RS256_PRIVATE_KEY_PEM` 환경변수로 키 주입 (in-memory 자동생성 금지)
- [ ] `APEX_DATABASE_URL`에 PostgreSQL URL 설정
- [ ] `APEX_ISSUER`, `APEX_MCP_RESOURCE`를 실제 도메인으로 변경
- [ ] `APEX_ACCESS_TOKEN_TTL=300` 설정 확인 (기본값 3600을 그대로 두면 로그아웃/
      재사용탐지 후에도 최대 1시간까지 MCP 도구 호출이 통과될 수 있음 — "세션 관리
      운영 참고" 참고)
- [ ] TLS 종단 (reverse proxy 또는 `--ssl-keyfile/--ssl-certfile`)
- [ ] `psycopg2-binary` (또는 `psycopg2`) 설치 확인
- [ ] DB 마이그레이션 (`alembic upgrade head`) CI/CD에 포함
- [ ] `ConfirmationGrantRow` 만료 레코드 정기 삭제 배치 설정 (선택)
