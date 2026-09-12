# Phase 1 — 데이터 모델 + 저장소

상태: 완료 (2026-09-11)
선행조건: 충족됨

## 목적

인증/세션/RBAC/승인 grant를 영속적으로 저장할 데이터 모델과 DB 스키마를
만든다. 이 위에 Phase 2~5가 올라간다.

## 범위

최소한 아래 개념을 표현하는 테이블/모델이 필요하다 (정확한 컬럼 설계는
구현하면서 확정):

- **user**: 로그인 계정. actor_id에 대응.
- **case_tenancy**: user ↔ case_id ↔ role 매핑. 한 유저가 여러 케이스에
  다른 역할로 접근할 수 있음을 감안 (`FrontendSession.allowed_case_ids`,
  `roles`가 세션 단위지 case 단위 role까지는 현재 코드에 없음 — 세션 발급
  시점에 여러 case_tenancy row를 모아서 하나의 FrontendSession으로
  합치는 방식으로 구현).
- **session**: 로그인 세션. `session_id`, `tenant_id`, 발급 시각, 만료 시각.
- **confirmation_grant**: `report.approve`/`report.reject`/민감 작업 승인
  1회용 토큰. `src/apex_mcp/confirmation.py`의 `ConfirmationGrant` 필드
  (`grant_id, actor_id, session_id, case_id, tool_name, request_fingerprint,
  target_ids, expires_at, max_uses`)를 그대로 컬럼으로 옮기면 됨. 이미
  domain 모델이 정의돼 있으니 이거 그대로 재사용.

## 완료 조건

- [ ] DB 마이그레이션 스크립트 존재 (Alembic 등)
- [ ] 위 4개 개념에 대응하는 ORM 모델 또는 명시적 SQL 스키마 존재
- [ ] 로컬에서 마이그레이션 적용 → 최소 CRUD 테스트 통과
- [ ] `docs/backend/data-model/README.md`에 ERD 또는 테이블 설명 기록
