# Phase 5 완료 — confirmation grant 발급 플로우

상태: 완료
완료일: 2026-09-12

## 구현 요약

사람이 직접 승인(confirm) 버튼을 누른 뒤 MCP 서버가 해당 작업을 실제로 실행할
수 있도록, 일회용 5분 grant를 발급하고 DB에서 소비하는 전체 흐름을 구현했다.

- `POST /confirmations` — JWT 검증 후 `ConfirmationGrantRow` 생성 (5분, 1회)
- `DbFrontendSecurityProvider` — sync SQLAlchemy로 grant 조회/소비

## 만든/수정한 파일

| 파일 | 설명 |
|---|---|
| `src/apex_backend/auth/confirmation_router.py` | `POST /confirmations` FastAPI 라우터 |
| `src/apex_backend/auth/db_confirmation.py` | `DbFrontendSecurityProvider` |
| `src/apex_backend/auth/schemas.py` | `ConfirmationRequest`, `ConfirmationResponse` Pydantic 스키마 추가 |
| `src/apex_backend/app.py` | confirmation 라우터 등록, `_get_db` 의존성 오버라이드 |
| `tests/backend/test_confirmation_grant.py` | 테스트 13개 |

## grant 발급 플로우 (POST /confirmations)

```
Frontend (사람이 승인 클릭)
    ↓
POST /confirmations
    Authorization: Bearer <access_token>
    {
      "case_id": "case-001",
      "tool_name": "report.approve",
      "request_fingerprint": "fp-abc",
      "target_ids": ["report-1"]
    }
    ↓
JwtTokenVerifier.verify_token → AccessToken
    ↓
actor_id = claims["sub"]
session_id = claims["session_id"]
case_id가 allowed_case_ids에 포함인지 확인 (아니면 403)
    ↓
ConfirmationGrantRow 생성 (DB INSERT):
    grant_id = uuid4()
    expires_at = now + 5분
    max_uses = 1
    uses_count = 0
    ↓
응답 201: { "grant_id": "..." }
```

## grant 소비 플로우 (MCP call_tool)

```
MCP call_tool(tool_name, args={..., "grant_id": "..."})
    ↓
DbFrontendSecurityProvider.confirmation_for(session, case_id, tool_name, fingerprint, target_ids)
    → DB SELECT WHERE actor_id/session_id/case_id/tool_name/fingerprint/expires_at > now
    → uses_count < max_uses AND target_ids 일치
    → ConfirmationRequest 반환 (없으면 None)
    ↓
DbFrontendSecurityProvider.authorize(request)
    → DB GET grant by grant_id
    → 만료/소비횟수 초과/필드 불일치 → False
    → row.uses_count += 1 → DB commit → True
```

## DB 스키마 (ConfirmationGrantRow)

| 컬럼 | 타입 | 설명 |
|---|---|---|
| `grant_id` | VARCHAR(36), PK | UUID v4 |
| `actor_id` | VARCHAR(36) | `claims["sub"]` |
| `session_id` | VARCHAR(36) | `claims["session_id"]` |
| `case_id` | VARCHAR(36) | 요청 body의 case_id |
| `tool_name` | VARCHAR(128) | 승인 대상 Tool 이름 |
| `request_fingerprint` | VARCHAR(256) | 요청 고유 식별자 |
| `target_ids` | JSON | 승인 대상 리소스 ID 목록 |
| `expires_at` | TIMESTAMP WITH TZ | 발급 시각 + 5분 |
| `max_uses` | INTEGER | 최대 소비 횟수 (기본 1) |
| `uses_count` | INTEGER | 현재 소비 횟수 (기본 0) |

## 설계 결정과 이유

| 결정 | 이유 |
|---|---|
| sync SQLAlchemy (`sessionmaker[Session]`) 사용 | `call_tool`이 sync 함수. async session_factory는 event loop 없이 호출 불가. |
| actor_id/session_id는 JWT 클레임에서 추출, 클라이언트 제공 불가 | 클라이언트가 임의 actor_id를 주입하는 것 방지. |
| `request_fingerprint` 포함 | 같은 tool_name이라도 다른 요청(다른 파라미터 세트)과 구분. |
| `target_ids` JSON 저장 | PostgreSQL/SQLite 모두 지원 (SQLAlchemy JSON 타입). |
| `max_uses=1` 고정 (현재) | 1회용이 기본 요구사항. 향후 multi-use가 필요하면 endpoint body에 `max_uses` 추가 가능. |
| grant 만료/소비 시 삭제 안 하고 `uses_count` 증가 | 감사 추적 보존. 주기적 배치로 만료 레코드 정리 권장 (배포 가이드 참조). |

## 테스트 현황

- 추가: 13개 (`tests/backend/test_confirmation_grant.py`)
- 누적 (Phase 5 완료 시점): 65개 통과
- 다루는 케이스:
  - `POST /confirmations` 성공 → 201 + grant_id
  - 토큰 없음 → 401
  - 허용되지 않은 case_id → 403
  - `confirmation_for`: 유효 grant 조회 성공
  - `confirmation_for`: grant 없음, 만료, 소비 완료 → None
  - `authorize`: 정상 소비 → True
  - `authorize`: 2회 소비 시도 → 2번째 False
  - `authorize`: 만료된 grant → False
  - `authorize`: actor_id 불일치 → False
  - `authorize`: 존재하지 않는 grant_id → False
  - `authorize`: max_uses=3인 grant 3번 소비 후 4번째 False

## 알려진 제약

- 프로덕션 PostgreSQL에는 `psycopg2` (또는 `psycopg2-binary`) 드라이버 필요.
  `call_tool`이 sync이므로 async 드라이버(`asyncpg`) 사용 불가.
- 만료된 `ConfirmationGrantRow`는 자동 삭제되지 않음. 배포 환경에서 주기적 배치
  삭제 설정 권장 (`docs/backend/deployment/README.md` 참조).
- `max_uses` > 1 다중 소비 grant는 현재 API로 발급 불가 (endpoint 확장 필요).
