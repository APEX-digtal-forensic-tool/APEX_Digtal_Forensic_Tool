# Phase 4 완료 — PersistentFrontendSecurityProvider 구현

상태: 완료
완료일: 2026-09-12

## 구현 요약

JWT 클레임으로부터 `FrontendSession`을 직접 재구성하는
`PersistentFrontendSecurityProvider`를 구현했다. `FrontendSecurityProvider` Protocol
(`resolve_session`, `confirmation_for`, `authorize`)을 만족한다.

DB 조회 없이 JWT 클레임만으로 세션을 복원한다 — 이것이 Option A 아키텍처의 핵심 이점이다.

## 만든/수정한 파일

| 파일 | 설명 |
|---|---|
| `src/apex_mcp/frontend_security.py` | `PersistentFrontendSecurityProvider` 클래스 추가 |
| `tests/mcp/test_persistent_security_provider.py` | 테스트 12개 |

## 주요 동작

### resolve_session

JWT `AccessToken.claims`에서 다음 클레임을 추출해 `FrontendSession`을 생성:

| 클레임 | FrontendSession 필드 | 비고 |
|---|---|---|
| `sub` (fallback: `access_token.subject`) | `actor_id` | 비어있으면 `McpAuthorizationDeniedError` |
| `session_id` | `session_id` | 비어있으면 `McpAuthorizationDeniedError` |
| `tenant_id` | `tenant_id` | 비어있으면 `McpAuthorizationDeniedError` |
| `allowed_case_ids` (list) | `allowed_case_ids` (frozenset) | 빈 문자열 필터링 |
| `roles` (list) | `roles` (frozenset, upper) | 빈 문자열 필터링 |

### confirmation_for / authorize

- `confirmation_for`: Phase 4 기준으로는 항상 `None` 반환 (Phase 5의 `DbFrontendSecurityProvider`에서 오버라이드)
- `authorize`: 생성자로 주입된 `ConfirmationProvider.authorize` 위임 (기본값: `DenyAllConfirmationProvider`)

## 설계 결정과 이유

| 결정 | 이유 |
|---|---|
| DB 조회 없이 JWT 클레임만 사용 | Option A 핵심: MCP 프로세스가 DB 없이도 세션 복원 가능. 백엔드 장애 시에도 읽기 전용 작업은 정상 동작. |
| `FrontendSession.__post_init__`이 이미 역할/테넌시 검증함 | `resolve_session`에서 중복 검증하지 않음. FrontendSession 생성 시 자동 검증됨. |
| `ConfirmationProvider` 주입으로 확장성 확보 | Phase 5에서 `DbFrontendSecurityProvider`가 `PersistentFrontendSecurityProvider`를 상속하고 `confirmation_for`/`authorize`만 오버라이드. 인터페이스 변경 없음. |
| 기존 `InMemoryFrontendSecurityProvider` 유지 | 로컬 개발/테스트 fixture로 계속 사용. 삭제 금지 (`01_DEVELOPMENT_RULES.md` 규칙). |

## 테스트 현황

- 추가: 12개 (`tests/mcp/test_persistent_security_provider.py`)
- 누적 (Phase 4 완료 시점): 43개 통과
- 다루는 케이스:
  - 유효 JWT 클레임 → `FrontendSession` 정상 생성, 각 필드 확인
  - `sub` 클레임 없을 때 `access_token.subject` fallback
  - `session_id`/`tenant_id` 비어있으면 `McpAuthorizationDeniedError`
  - `allowed_case_ids`/`roles` 빈 문자열 필터링
  - `confirmation_for`는 항상 `None` (Phase 4 기준)
  - `authorize`는 주입된 provider에 위임

## 알려진 제약

- 이 클래스의 `confirmation_for`는 항상 `None` 반환 — 실제 DB 조회는 Phase 5의
  `DbFrontendSecurityProvider`에서 오버라이드.
- 역할(`roles`)이 `allowed_case_ids`를 포함하는지 여부는 `FrontendSession` 생성
  시 검증하지 않음 — 각 Tool에서 case tenancy 체크는 `FrontendAuthorizationGate`가 담당.
