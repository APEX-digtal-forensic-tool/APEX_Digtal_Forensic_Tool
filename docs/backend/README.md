# docs/backend — 백엔드 개발 기획 및 진행 기록

이 폴더는 APEX 백엔드(FastAPI) 개발을 Claude Code가 세션을 넘나들며 진행할 수
있게 만든 기획 + 진행상황 기록 공간이다.

## 읽는 순서

1. `00_MASTER_PLAN.md` — 왜, 무엇을, 어떤 순서로 만드는지 전체 그림.
2. `01_DEVELOPMENT_RULES.md` — 코드 규칙 + 세션 핸드오프 규칙. 작업 시작 전 필독.
3. `PROGRESS_LOG.md` — 지금 어디까지 됐고 다음에 뭘 해야 하는지. 세션마다
   여기부터 읽고, 여기부터 갱신한다.
4. `specs/` — Phase별 하위 구현 기획서. 구현 직전에 해당 Phase 스펙을 읽는다.

## 완료된 구현은 어디로 가는가

Phase(스펙 파일)가 하나 끝나면, 그 결과물은 `specs/`에 남기지 않고
`docs/backend/<도메인명>/README.md`로 옮겨 기록한다. 즉 이 폴더는 시간이
지나면 아래처럼 자라난다:

```
docs/backend/
  00_MASTER_PLAN.md
  01_DEVELOPMENT_RULES.md
  PROGRESS_LOG.md
  specs/
    00_DECISIONS.md
    01_data_model_and_storage.md      (진행 중엔 여기, 완료 후 상태만 "완료"로 표시)
    02_auth_token_issuance_api.md
    03_mcp_token_verifier.md
    04_mcp_frontend_security_provider.md
    05_confirmation_grant_flow.md
    06_integration_and_docs.md
  data-model/README.md                (Phase 1 완료 후 생성)
  auth-api/README.md                  (Phase 2 완료 후 생성)
  mcp-token-verifier/README.md        (Phase 3 완료 후 생성)
  mcp-frontend-security-provider/README.md  (Phase 4 완료 후 생성)
  confirmation-grant-flow/README.md   (Phase 5 완료 후 생성)
  deployment/README.md                (Phase 6 완료 후 생성)
```

`specs/`는 "계획", 도메인별 폴더는 "완료 기록(as-built)"이라는 구분이다.
스펙은 구현 전에 쓴 예상이라 실제로 구현하면서 달라질 수 있는데, 그 최종
결과는 도메인 폴더 쪽에 정확하게 남긴다.
