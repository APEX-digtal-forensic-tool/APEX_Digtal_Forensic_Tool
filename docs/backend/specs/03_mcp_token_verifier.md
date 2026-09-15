# Phase 3 — MCP용 TokenVerifier 실제 구현

상태: 완료 (2026-09-12)
선행조건: Phase 2 완료 (JWKS 엔드포인트 필요)

## 목적

`src/apex_mcp/frontend_security.py`의 `StaticBearerTokenVerifier`를 대체할
`TokenVerifier` 구현체를 만든다. 이 구현체가 Phase 2에서 발급한 JWT를
검증한다.

## 정확한 계약 (수정 금지, 그대로 구현만)

```python
# mcp.server.auth.provider.TokenVerifier
class TokenVerifier(Protocol):
    async def verify_token(self, token: str) -> AccessToken | None: ...
```

`AccessToken`은 최소한 `client_id`, `subject`, `resource`, `scopes`,
`claims`(dict)를 채워야 한다 — `StaticBearerTokenVerifier.__init__`에서
이미 이 필드들에 대한 검증 예시를 볼 수 있음 (`client_id`, `subject`,
`issuer`(`claims["iss"]`), `resource`, `"apex:mcp" in scopes` 전부 필수).

## 구현 방향

- 새 클래스 이름 제안: `JwtTokenVerifier` (`src/apex_backend/` 또는
  `src/apex_mcp/` 중 어디에 둘지는 구현 시점에 정하되, `apex_mcp`가
  `apex_backend`를 import하는 방향으로 — 반대 방향 금지, MCP는 backend에
  의존해도 되지만 backend가 MCP 내부를 알 필요는 없음).
- Phase 2의 JWKS 엔드포인트에서 공개키를 가져와 서명 검증 (라이브러리:
  `PyJWT` 또는 `python-jose` — 둘 중 하나, pyproject.toml에 새로 추가 필요).
- 토큰 만료(`exp`), 발급자(`iss`), audience(`aud`, MCP 리소스 URL과 일치)
  검증 포함.
- 서명 검증 실패, 만료, 클레임 누락 시 `None` 반환 (예외 던지지 않음 —
  `TokenVerifier` 계약상 `None`이 "인증 실패"를 의미).
- 공개키(JWKS)는 캐싱하되 주기적으로 갱신 (키 로테이션 대비).

## 완료 조건

- [ ] `JwtTokenVerifier` 구현, 기존 `StaticBearerTokenVerifier`는 그대로 유지
- [ ] 정상 토큰 검증 성공, 위조/만료/스코프 누락 토큰 검증 실패 테스트
- [ ] `tests/mcp` 기존 49개 계속 통과
- [ ] `docs/backend/mcp-token-verifier/README.md` 작성
