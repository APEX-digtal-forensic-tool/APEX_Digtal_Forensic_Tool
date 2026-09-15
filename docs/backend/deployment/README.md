# APEX Backend — 배포 가이드

상태: Phase 6 완료 (2026-09-12)

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
| `APEX_ACCESS_TOKEN_TTL` | `3600` | access token 유효기간 (초) |
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

## 프로덕션 체크리스트

- [ ] `APEX_RS256_PRIVATE_KEY_PEM` 환경변수로 키 주입 (in-memory 자동생성 금지)
- [ ] `APEX_DATABASE_URL`에 PostgreSQL URL 설정
- [ ] `APEX_ISSUER`, `APEX_MCP_RESOURCE`를 실제 도메인으로 변경
- [ ] TLS 종단 (reverse proxy 또는 `--ssl-keyfile/--ssl-certfile`)
- [ ] `psycopg2-binary` (또는 `psycopg2`) 설치 확인
- [ ] DB 마이그레이션 (`alembic upgrade head`) CI/CD에 포함
- [ ] `ConfirmationGrantRow` 만료 레코드 정기 삭제 배치 설정 (선택)
