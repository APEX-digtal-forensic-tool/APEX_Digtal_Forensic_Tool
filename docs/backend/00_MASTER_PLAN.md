# APEX 백엔드 마스터 기획서

상태: 착수 전 (Phase 0)
작성일: 2026-09-11
담당: 한예준 (Backend + MCP)
실행: Claude Code (이 문서와 하위 스펙을 읽고 구현)

---

## 1. 배경

MCP 서버(`src/apex_mcp`)는 M8까지 이미 다른 팀원이 구현해서 main에 merge된 상태다.
49개 테스트 통과, ruff/구조 검증 통과까지 확인됨. 다만 `docs/MCP_SERVER.md` 6절과
실제 코드(`src/apex_mcp/frontend_security.py`)를 보면, 인증/세션/승인 계층이
아직 진짜 백엔드가 아니라 **인메모리 스텁**으로 되어 있다:

- `InMemoryFrontendSecurityProvider` — 세션을 프로세스 메모리 dict에만 저장. 재시작하면 날아감.
- `StaticBearerTokenVerifier` — 토큰 하나를 고정 secret과 비교하는 개발용 검증기.
- `InMemoryConfirmationProvider` — 승인(confirmation) grant도 메모리 dict.

이 세 개를 실제 영속 저장소 기반의 백엔드 구현으로 교체하는 것이 이번 마스터
플랜의 목표다. 이게 정확히 "백엔드"와 "MCP"라는 내 두 역할이 실제로 맞물리는
지점이고, 이거 하나만 끝내면 MCP 쪽에서 내가 더 할 일은 없다 (Case/Evidence/
Search 확장은 코어가 Descriptor를 열어줘야 가능한 부분이라 내 소관 밖).

## 2. 목표

FastAPI 기반 백엔드가 다음의 authoritative source가 되도록 만든다:

1. 사용자 인증 및 세션 발급 (로그인 → 세션/토큰 발급)
2. 케이스 테넌시 매핑 (어떤 사용자가 어떤 case_id에 접근 가능한지)
3. 역할(RBAC) — VIEWER / ANALYST / APPROVER / EXPORTER / ADMIN
4. 승인(confirmation) grant 발급 및 1회성 소비 관리 (report 승인/반려, 민감 작업 확인)
5. 위 4가지를 MCP 프로세스가 검증할 수 있는 방법 제공

이 다섯 가지는 전부 이미 `src/apex_mcp/frontend_security.py`와
`src/apex_mcp/confirmation.py`에 정의된 Protocol 계약으로 못 박혀 있다.
**새로 설계하는 게 아니라, 이미 있는 계약을 실제로 구현하는 작업이다.**
Claude Code는 이 Protocol의 메서드 시그니처를 절대 바꾸면 안 된다 (아래
`01_DEVELOPMENT_RULES.md` 참고).

## 3. 지금 구현해야 하는 정확한 계약 (코드 기준, 추측 아님)

`src/apex_mcp/frontend_security.py`:

```python
class FrontendSecurityProvider(ConfirmationProvider, Protocol):
    def resolve_session(self, access_token: AccessToken) -> FrontendSession: ...
    def confirmation_for(
        self, session: FrontendSession, *,
        case_id: str, tool_name: str,
        request_fingerprint: str, target_ids: tuple[str, ...],
    ) -> ConfirmationRequest | None: ...
```

`src/apex_mcp/confirmation.py`:

```python
class ConfirmationProvider(Protocol):
    def authorize(self, request: ConfirmationRequest) -> bool: ...
```

그리고 MCP SDK가 요구하는 `mcp.server.auth.provider.TokenVerifier`:

```python
class TokenVerifier(Protocol):
    async def verify_token(self, token: str) -> AccessToken | None: ...
```

`FrontendSession`은 `actor_id`, `session_id`, `tenant_id`, `allowed_case_ids`,
`roles` 다섯 개 필드를 요구하고, `roles`는 `VIEWER/ANALYST/APPROVER/EXPORTER/
ADMIN` 중 하나 이상이어야 한다 (frozen dataclass, `__post_init__`에서 검증함 —
검증 로직 자체는 건드릴 필요 없음, 이 값들을 실제로 채워서 넘겨주기만 하면 됨).

## 4. 아키텍처 결정 — 이거 하나는 실제로 확정하고 시작해야 함

MCP 프로세스와 FastAPI 백엔드가 "인증 진실"을 어떻게 공유할지 두 가지 방식이
있고, 둘 다 말이 된다. Claude Code가 임의로 고르게 두지 말고, 아래 중 하나를
**Phase 1 시작 전에 사람이 확정**해야 한다.

**옵션 A (추천): JWT 로컬 검증 + 승인 grant는 공유 DB**
- 백엔드가 로그인 시 서명된 JWT(RS256/ES256)를 발급. 클레임에 actor_id,
  session_id, tenant_id, allowed_case_ids, roles, scopes 전부 포함.
- MCP의 `TokenVerifier.verify_token`은 백엔드에 매 요청마다 물어볼 필요 없이
  JWKS로 서명만 로컬 검증 → 빠르고 백엔드 장애에도 MCP 자체 인증은 안 죽음.
- `resolve_session`도 JWT 클레임을 그대로 `FrontendSession`으로 매핑 — DB
  안 타도 됨.
- 승인(confirmation) grant는 세션과 달리 "1회용, 실시간 취소 가능"해야 하므로
  이것만 백엔드와 같은 DB 테이블을 공유하거나, 백엔드가 노출하는 내부 API를
  MCP가 호출하는 방식으로 확인.

**옵션 B: 백엔드 API를 매번 호출**
- `verify_token`/`resolve_session`/`confirmation_for` 전부 백엔드 HTTP API를
  호출해서 확인. 구현은 단순하지만 MCP 요청마다 백엔드 왕복이 생기고, 백엔드가
  죽으면 MCP도 같이 막힘.

추천은 A. 근거: 세션/역할처럼 자주 조회하지만 자주 안 바뀌는 건 토큰에 실어서
로컬 검증(빠름), 승인 grant처럼 "방금 취소됐을 수도 있는" 상태만 공유 저장소로
확인(정확함). 이 결정은 `specs/00_DECISIONS.md`에 확정해서 적어두고 시작한다.

## 5. 로드맵 (Phase)

각 Phase는 `specs/` 밑에 하위 구현 기획서가 하나씩 있다. 순서대로 진행하고,
Phase 하나 끝날 때마다 `PROGRESS_LOG.md`를 갱신한다 (필수, 생략 금지).

| Phase | 내용 | 스펙 파일 |
|---|---|---|
| 1 | 데이터 모델 + DB 스키마 (user, session, case_tenancy, role, confirmation_grant) | `specs/01_data_model_and_storage.md` |
| 2 | 인증/토큰 발급 API (로그인, JWT 발급, 리프레시) | `specs/02_auth_token_issuance_api.md` |
| 3 | MCP용 `TokenVerifier` 실제 구현체 | `specs/03_mcp_token_verifier.md` |
| 4 | MCP용 `FrontendSecurityProvider` 실제 구현체 (세션/RBAC/테넌시) | `specs/04_mcp_frontend_security_provider.md` |
| 5 | 승인(confirmation) grant 발급/조회 플로우 | `specs/05_confirmation_grant_flow.md` |
| 6 | 통합 테스트 + 배포 설정 문서화 | `specs/06_integration_and_docs.md` |

## 6. 완료 기준 (전체)

- `src/apex_mcp`가 더 이상 `InMemoryFrontendSecurityProvider`/
  `StaticBearerTokenVerifier`를 프로덕션 경로에서 쓰지 않음 (테스트/로컬 개발용으로만 남김)
- 새 구현체들이 각 Protocol 계약을 100% 만족 (mypy로 구조적 타입 체크 통과)
- `tests/mcp` 기존 49개 테스트 전부 계속 통과
- 새 구현체마다 대응하는 pytest 존재하고 통과
- ruff/mypy 클린
- `docs/backend/<도메인명>/` 밑에 완료된 각 Phase의 as-built 문서 존재

## 7. 이 폴더 안내

- `00_MASTER_PLAN.md` — 이 문서. 전체 그림.
- `01_DEVELOPMENT_RULES.md` — Claude Code가 지켜야 할 규칙. 작업 시작 전 필독.
- `PROGRESS_LOG.md` — 진행상황. 세션 시작 시 여기부터 읽고, 세션 끝나기 전 여기부터 갱신.
- `specs/` — Phase별 하위 구현 기획서. 구현 전에 해당 스펙 파일부터 읽을 것.
- Phase가 완료되면 `docs/backend/<도메인명>/`에 완료 기록을 남긴다 (규칙은
  `01_DEVELOPMENT_RULES.md` 5절 참고).
