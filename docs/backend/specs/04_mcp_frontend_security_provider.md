# Phase 4 — MCP용 FrontendSecurityProvider 실제 구현

상태: 대기
선행조건: Phase 3 완료

## 목적

`InMemoryFrontendSecurityProvider`를 대체할, 실제 세션/RBAC/테넌시를
반영하는 구현체를 만든다.

## 정확한 계약 (수정 금지)

```python
class FrontendSecurityProvider(ConfirmationProvider, Protocol):
    def resolve_session(self, access_token: AccessToken) -> FrontendSession: ...
    def confirmation_for(
        self, session: FrontendSession, *,
        case_id: str, tool_name: str,
        request_fingerprint: str, target_ids: tuple[str, ...],
    ) -> ConfirmationRequest | None: ...

class ConfirmationProvider(Protocol):
    def authorize(self, request: ConfirmationRequest) -> bool: ...
```

`FrontendSession`은 `actor_id, session_id, tenant_id, allowed_case_ids
(frozenset[str], 최소 1개), roles(frozenset[str], VIEWER/ANALYST/APPROVER/
EXPORTER/ADMIN 중 최소 1개)`. `__post_init__`이 이미 검증하므로, 구현체는
이 값들을 올바르게 채우기만 하면 된다.

## 구현 방향

- `resolve_session`: Phase 3에서 검증된 `AccessToken.claims`에서 바로
  `FrontendSession`을 구성 (JWT에 이미 다 들어있으므로 DB 조회 불필요 —
  옵션 A 아키텍처의 이점).
- `confirmation_for` / `authorize`: 옵션 A대로면 이 두 개만 Phase 1의
  `confirmation_grant` 테이블을 직접 조회 (실시간성이 중요한 부분이므로
  토큰에 실어두지 않음). Phase 5에서 grant 발급 API를 만들고, 여기서는
  조회/소비만 담당.
- 새 클래스 이름 제안: `PersistentFrontendSecurityProvider`.
- 기존 `InMemoryFrontendSecurityProvider`, `InMemoryConfirmationProvider`는
  로컬 개발/pytest fixture용으로 유지.

## 완료 조건

- [ ] `PersistentFrontendSecurityProvider` 구현
- [ ] 세션 해석, 테넌시 검증(`allowed_case_ids` 밖 case 접근 시
      `McpTenantScopeViolationError`), 역할 부족 시 거부 흐름 테스트
- [ ] `tests/mcp` 기존 49개 계속 통과
- [ ] `docs/backend/mcp-frontend-security-provider/README.md` 작성
