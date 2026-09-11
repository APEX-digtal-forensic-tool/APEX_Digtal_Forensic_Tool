# Phase 2 — 인증/토큰 발급 API

상태: 대기
선행조건: Phase 1 완료

## 목적

FastAPI로 로그인 → 토큰 발급 API를 만든다. 이 토큰이 나중에 MCP HTTP
transport(`src/apex_mcp/http_transport.py`)의 `Authorization: Bearer` 헤더로
들어가서 Phase 3의 `TokenVerifier`가 검증하게 된다.

## 범위 (옵션 A 기준, 확정된 아키텍처에 맞춰 조정)

- `POST /auth/login` — 자격증명 확인 → JWT 발급.
  클레임에 최소한 `sub`(actor_id), `session_id`, `tenant_id`,
  `allowed_case_ids`(array), `roles`(array), `scopes`(array) 포함.
  `scopes`는 `src/apex_mcp/frontend_security.py`의
  `FrontendAuthorizationGate.require`가 검사하는 값들과 맞춰야 함:
  `apex:mcp`, `apex:read`, `apex:write`, `apex:confirm`, `apex:raw`,
  `apex:approve`, `apex:export`. 역할(role)에 따라 어떤 scope를 자동으로
  붙일지는 이 스펙 안에서 정의하고 문서화할 것.
- `POST /auth/refresh` — 토큰 재발급.
- JWT 서명은 RS256/ES256 (대칭키 금지 — MCP 쪽에서 공개키만으로 검증 가능해야
  로컬 검증 이점이 산다).
- JWKS 엔드포인트(`/.well-known/jwks.json`) 노출 — MCP가 공개키를 가져가는 용도.

## 완료 조건

- [ ] 로그인 → JWT 발급 API 동작
- [ ] JWKS 엔드포인트 동작
- [ ] 토큰 클레임에 필요한 필드 전부 포함 확인하는 테스트
- [ ] `docs/backend/auth-api/README.md`에 API 스펙(엔드포인트, 요청/응답, 클레임 구조) 기록
