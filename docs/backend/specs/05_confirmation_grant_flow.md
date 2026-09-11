# Phase 5 — 승인(confirmation) grant 발급 플로우

상태: 대기
선행조건: Phase 4 완료

## 목적

`report.approve` / `report.reject` / 기타 `requires_confirmation` 도구를
실행하기 전에 필요한 1회용 승인 grant를 실제로 발급하는 백엔드 API를
만든다. 지금까지는 Phase 1~4가 "검증"만 다뤘고, 이 Phase가 "발급" 쪽이다.

## 배경

`src/apex_mcp/confirmation.py`의 `ConfirmationGrant`가 이미 필요한 필드를
전부 정의해둠: `grant_id, actor_id, session_id, case_id, tool_name,
request_fingerprint, target_ids, expires_at, max_uses`. 이건 "사람이 프론트
엔드 화면에서 버튼을 눌러 승인했다"는 사실을 서버가 대신 증명하는 토큰이다.
MCP 쪽 모델이 요청하는 게 아니라 **백엔드(사람이 실제로 조작하는 화면)가
발급해야 한다** (`ConfirmationGrant`의 docstring: "never accepted as MCP
arguments").

## 범위

- `POST /confirmations` — 프론트엔드가 사람의 승인 액션을 받으면 호출.
  요청 바디: `case_id, tool_name, request_fingerprint, target_ids`.
  서버가 `actor_id`, `session_id`는 인증된 세션에서 채움 (클라이언트가
  임의로 못 넣게).
  응답: `grant_id`.
- 발급 시 `max_uses=1`, `expires_at`은 짧게(예: 5분) — 정확한 값은 구현
  시점에 팀 컨벤션 확인.
- Phase 1의 `confirmation_grant` 테이블에 저장.
- Phase 4의 `PersistentFrontendSecurityProvider.confirmation_for`/
  `authorize`가 이 테이블을 조회.

## 완료 조건

- [ ] grant 발급 API 동작
- [ ] 발급된 grant가 MCP 쪽 `authorize`에서 1회만 소비되고 이후 재사용
      거부되는지 통합 테스트
- [ ] 만료된 grant 거부 테스트
- [ ] `docs/backend/confirmation-grant-flow/README.md` 작성
