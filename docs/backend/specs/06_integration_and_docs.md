# Phase 6 — 통합 테스트 + 배포 설정 문서화

상태: 완료 (2026-09-14)
선행조건: Phase 5 완료

## 목적

Backend + MCP를 실제로 같이 띄워서 끝까지 동작하는지 확인하고, 배포/실행
방법을 문서화한다. 여기서 끝나면 마스터 플랜 전체가 완료 상태가 된다.

## 범위

- MCP HTTP transport(`src/apex_mcp/http_transport.py`)의
  `create_http_app(..., token_verifier=...)`에 Phase 3에서 만든
  `JwtTokenVerifier`를 실제로 주입하는 실행 스크립트/설정 작성.
- 로그인 → 토큰 발급 → MCP 툴 호출 → (필요시) 승인 grant 발급 → 승인 필요한
  툴 호출까지 end-to-end 시나리오 테스트 최소 1개.
- 환경변수/설정 정리: 어떤 값을 Backend가, 어떤 값을 MCP가 필요로 하는지
  표로 정리 (`src/apex_mcp/config.py`의 `APEX_MCP_*` 값들과 겹치지 않게
  네이밍 정리할 것).
- 기존 `InMemoryFrontendSecurityProvider`/`StaticBearerTokenVerifier` 경로는
  로컬 개발용으로 계속 동작하는지 확인 (실수로 깨뜨리지 않았는지).

## 완료 조건

- [ ] end-to-end 시나리오 테스트 통과
- [ ] 전체 `pytest` 통과 (Phase 진행 중 새로 깨진 테스트 없음)
- [ ] ruff/mypy 클린
- [ ] `docs/backend/deployment/README.md`에 실행 방법, 환경변수 표 작성
- [ ] `docs/MCP_SERVER.md` 6절의 "남은 작업" 항목 중 이번 플랜으로 끝난
      부분을 갱신 (실제 백엔드 연동 완료로 표시)
