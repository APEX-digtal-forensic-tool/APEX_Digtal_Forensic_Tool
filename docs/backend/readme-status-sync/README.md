# Phase 16 — README.md 상태표·체크리스트 동기화 (as-built)

## 변경 내역

Backend Phase 1~11·13~15 (PR #14~#18) 머지 완료 후 README.md 상태표와 체크리스트를 실제 구현 상태와 동기화.

### README.md 변경 위치

| 위치 | 변경 전 | 변경 후 |
|---|---|---|
| Line 30 (MCP/LLM Runtime 행 끝) | 제품용 영속 identity/approval/billing backend는 별도 통합 대상 | 영속 Identity/Approval backend 구현 완료 (JWT RS256·JWKS·RBAC·DB confirmation grant, Phase 1~11·13~15). Billing backend는 별도 통합 대상 |
| Line 31 (Frontend/Backend 행) | **별도 담당 및 통합 대상** / GUI, Session/Identity, Approval, Billing, Desktop 통합은 Core Engine과 분리 | **Identity/Approval 완료 · GUI·Billing 별도 담당** / Session/Identity·Approval Backend 구현 완료. GUI, Billing, Desktop 통합은 별도 담당 |
| Line 34 (마무리 요약) | 별도 AI·Frontend·Backend 통합 | 별도 AI·Frontend·Billing 통합 |
| Line 1736 (체크리스트) | `[ ] 영속 Identity / Approval policy / Billing backend — Backend 담당` (한 줄) | `[x] 영속 Identity / Approval policy` 완료 + `[ ] Billing backend` 별도 (두 줄) |

## 구현된 Backend 내역 (Phase 1~11·13~15)

- Phase 1~6: ORM 모델, RS256 JWT 발급/JWKS, `JwtTokenVerifier`, `PersistentFrontendSecurityProvider`, confirmation grant 발급/소비, E2E 테스트
- Phase 7: bcrypt 버전 고정
- Phase 8: 문서 백필
- Phase 9: 레거시 mcp_server 제거
- Phase 10: apex-mcp CLI JWT 인증 체인 배선
- Phase 11: confirmation grant 경쟁 조건 수정 (원자적 UPDATE)
- Phase 13: CI tests/backend 검증 공백 수정
- Phase 14: --log-level 죽은 설정값 실제 로깅 적용
- Phase 15: JwtTokenVerifier JWKS 조회 실패 경고 로깅
