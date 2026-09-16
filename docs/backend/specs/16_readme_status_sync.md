# Phase 16 — README.md 상태표·체크리스트 동기화

## 상태: 완료

## 배경

Backend Phase 1~11·13~15 (PR #14~#18) 머지 완료. JWT RS256 검증(JWKS TTL 캐시), RBAC, DB confirmation grant, MCP 연동, JWKS 실패 로깅이 모두 구현되어 main에 반영됨.

`README.md` 상태표(lines 24–31)와 "별도 담당" 체크리스트(lines 1726–1737)는 여전히 identity/approval을 미구현 상태로 표시하고 있음. 이를 실제 상태와 동기화.

## 할 일

1. `README.md` line 30 (MCP/LLM Runtime 행): "제품용 영속 identity/approval/billing backend는 별도 통합 대상" → identity/approval 구현 완료, billing만 미완료로 수정
2. `README.md` line 31 (Frontend/Backend 행): 상태 및 설명에서 Identity/Approval 제거, Billing·GUI·Desktop만 잔여로 수정
3. `README.md` line 34 (마무리 요약 문장): "AI·Frontend·Backend 통합" → "AI·Frontend·Billing 통합"
4. `README.md` line 1736 (체크리스트): `[ ] 영속 Identity / Approval policy / Billing backend` 한 줄 → `[x]` Identity/Approval 완료 + `[ ]` Billing 별도 두 줄로 분리

## 절대 하지 말 것

- Feature Complete Candidate·PASSED_WITH_LIMITATIONS 등 Core 행 수정 금지
- "자율 Agent Workflow" 항목 변경 금지
- "한국어 GUI 및 View" 항목 변경 금지
- 코드 변경 금지 (순수 문서 작업)

## PR 규칙

- Branch: `feat/backend-phase-16-readme-status-sync`
- Title: `feat(backend): Phase 16 — README.md 상태표·체크리스트 동기화`
- Base: `main`
