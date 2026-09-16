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

| Phase | 내용 | 스펙 파일 | 상태 |
|---|---|---|---|
| 1 | 데이터 모델 + DB 스키마 (user, session, case_tenancy, role, confirmation_grant) | `specs/01_data_model_and_storage.md` | 완료 (2026-09-11) |
| 2 | 인증/토큰 발급 API (로그인, JWT 발급, 리프레시) | `specs/02_auth_token_issuance_api.md` | 완료 (2026-09-12) |
| 3 | MCP용 `TokenVerifier` 실제 구현체 | `specs/03_mcp_token_verifier.md` | 완료 (2026-09-12) |
| 4 | MCP용 `FrontendSecurityProvider` 실제 구현체 (세션/RBAC/테넌시) | `specs/04_mcp_frontend_security_provider.md` | 완료 (2026-09-12) |
| 5 | 승인(confirmation) grant 발급/조회 플로우 | `specs/05_confirmation_grant_flow.md` | 완료 (2026-09-12) |
| 6 | 통합 테스트 + 배포 설정 문서화 | `specs/06_integration_and_docs.md` | 완료 (2026-09-14) |
| 7 | bcrypt 버전 고정 (실제 버그: bcrypt 5.0.0 + passlib 비호환) | `specs/07_bcrypt_version_pin_fix.md` | 완료 (2026-09-15) |
| 8 | 진행 문서 백필 (Phase 3~6 spec 상태/도메인 폴더/PROGRESS_LOG 동기화) | `specs/08_docs_sync_backfill.md` | 완료 (2026-09-15) |
| 9 | 레거시 `mcp_server/` 스캐폴드 제거 | `specs/09_remove_legacy_mcp_server_scaffold.md` | 완료 (2026-09-15) |
| 10 | apex-mcp CLI를 새 JWT 인증 체인에 실제로 배선 (실제 버그) | `specs/10_cli_jwt_wiring_fix.md` | 완료 (2026-09-15) |
| 11 | confirmation grant 1회 소비 경쟁 조건 수정 (실제 버그) | `specs/11_confirmation_grant_race_fix.md` | 대기 |
| 12 | refresh token rotation(재사용 시 세션 전체 로그아웃) + 로그아웃 엔드포인트 | `specs/12_refresh_token_rotation_logout.md` | 대기 (범위 확정됨, 바로 착수 가능) |

## 6. 완료 기준 (전체)

- `src/apex_mcp`가 더 이상 `InMemoryFrontendSecurityProvider`/
  `StaticBearerTokenVerifier`를 프로덕션 경로에서 쓰지 않음 (테스트/로컬 개발용으로만 남김)
- 새 구현체들이 각 Protocol 계약을 100% 만족 (mypy로 구조적 타입 체크 통과)
- `tests/mcp` 기존 49개 테스트 전부 계속 통과
- 새 구현체마다 대응하는 pytest 존재하고 통과
- ruff/mypy 클린
- `docs/backend/<도메인명>/` 밑에 완료된 각 Phase의 as-built 문서 존재

## 6-1. 진행 현황 갱신 (2026-09-14)

Phase 1~6은 실제로 전부 구현되어 main에 merge 완료됨 (git log 확인:
Phase1 `1777d31`, Phase2 `e66d80c`/`2d88282`, Phase3 `c6d7051`/`28e9ab3`,
Phase4 `a62dca6`/`555c0f2`, Phase5 `23a2762`/`31d0c6d`, Phase6
`f023c94`/`8edb18b`). Backend+MCP 인증 체인(JWT 발급 → JwtTokenVerifier →
PersistentFrontendSecurityProvider → confirmation grant)이 실제로 동작하고
109개 테스트로 검증됨. 다만 배포 환경에서 재현되는 실제 버그 하나(Phase 7)와
문서 백필(Phase 8), 레거시 정리(Phase 9)가 후속 작업으로 남아 확인됨.

| Phase | 내용 | 스펙 파일 | 상태 |
|---|---|---|---|
| 7 | bcrypt 버전 고정 (실제 버그: bcrypt 5.0.0 + passlib 비호환) | `specs/07_bcrypt_version_pin_fix.md` | 대기 |
| 8 | 진행 문서 백필 (Phase 3~6 spec 상태/도메인 폴더/PROGRESS_LOG 동기화) | `specs/08_docs_sync_backfill.md` | 대기 |
| 9 | 레거시 `mcp_server/` 스캐폴드 제거 | `specs/09_remove_legacy_mcp_server_scaffold.md` | 대기 |

Phase 7, 8, 9는 서로 독립적이라 순서 상관없이, 또는 동시에 진행해도 된다.

## 6-3. 2026-09-15 재검토 발견 사항 및 후속 Phase 10~12

Phase 1~9 전부 완료 후, 코드를 다시 처음부터 끝까지 실행 경로 기준으로
재검토했다 (테스트/ruff/mypy/CI green이라는 사실만으로 "문제 없음"이라고
결론 내리지 말라는 지적에 따른 재조사). 테스트가 실제로 검증하지 않는
경로에서 실제 문제 2건, 참고 사항 1건을 확인함. 전체 재검토 근거는
`AUDIT_2026-09-15_production_wiring.md` 참고.

- **Phase 10 (높음, 실제 버그)**: `apex-mcp` CLI가 `JwtTokenVerifier`/
  `DbFrontendSecurityProvider`를 전혀 안 쓰고 여전히 개발용 스텁
  (`StaticBearerTokenVerifier`/`InMemoryFrontendSecurityProvider`)으로만
  동작함. 배포 가이드 명령어도 이것 때문에 실제로 실행 불가 (재현 확인함).
  6절 완료 기준 중 "프로덕션 경로에서 인메모리 스텁을 안 씀"이 실제로는
  충족되지 않은 상태였음.
- **Phase 11 (중간, 실제 버그)**: `DbFrontendSecurityProvider.authorize()`의
  1회 소비 로직에 읽기-검사-쓰기 원자성이 없어서 동시 요청 시 `max_uses=1`
  grant가 두 번 소비될 수 있는 경쟁 조건 있음.
- **Phase 12 (선택, 낮음, 버그 아님)**: refresh token 재사용 탐지/rotation,
  로그아웃 엔드포인트 없음. 어떤 스펙에도 요구사항으로 명시된 적 없어서
  참고 사항으로만 남김 — 착수 전 사람 확인 필요.

Phase 10/11은 바로 착수 가능한 실제 버그 수정이고, Phase 12는 범위 확정을
사람과 먼저 해야 한다 (해당 스펙 파일 "주의" 절 참고).

## 6-2. 보류 항목 (지금 시작하지 않음)

아래 두 개는 남은 작업으로 확인은 됐지만, 지금 이 마스터 플랜(Backend)
범위에서 착수하지 않는다. 이유를 명시해두는 건 나중에 "왜 안 했지"를
다시 따지지 않기 위함이다. Claude Code는 이 두 항목에 대해 스스로 작업을
시작하지 말 것 — 사람이 별도로 새 기획서를 만들어서 지시할 때까지 대기.

- **Windows Desktop bundle 제품 통합 검증**: `docs/MCP_SERVER.md` 6-2절에
  남은 작업으로 명시돼있음. Desktop 프론트엔드 번들링, 콘솔 lifecycle,
  경로/권한, 한국어 환경 검증까지 얽혀있어서 프론트/패키징 담당과 같이
  진행해야 하는 범위. 백엔드 단독으로 끝낼 수 있는 일이 아님.
- **Case/Evidence/Search 신규 Domain Tool**: Core Forensic Engine이
  `EngineInterfaceService`에 해당 Descriptor를 아직 공개하지 않음. Core
  담당이 그걸 열어주기 전까지는 MCP/백엔드 쪽에서 손댈 수 있는 게 없음
  (재구현 금지 원칙 위반이 됨). Core 쪽 진행 상황을 기다린다.

## 7. 이 폴더 안내

- `00_MASTER_PLAN.md` — 이 문서. 전체 그림.
- `01_DEVELOPMENT_RULES.md` — Claude Code가 지켜야 할 규칙. 작업 시작 전 필독.
- `PROGRESS_LOG.md` — 진행상황. 세션 시작 시 여기부터 읽고, 세션 끝나기 전 여기부터 갱신.
- `specs/` — Phase별 하위 구현 기획서. 구현 전에 해당 스펙 파일부터 읽을 것.
- Phase가 완료되면 `docs/backend/<도메인명>/`에 완료 기록을 남긴다 (규칙은
  `01_DEVELOPMENT_RULES.md` 5절 참고).
