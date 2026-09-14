# APEX MCP Server

## 1. 현재 범위

`src/apex_mcp`는 APEX public Engine Interface를 MCP 2.x에 연결하는 제품 외부 계층이다. 현재 M8 구현은 stdio와 authenticated Streamable HTTP, 시작 시 interface/descriptor 검증, 명시적 Tool allowlist, capability/TTL gate, frontend session/RBAC/case tenancy, server-side one-time confirmation, snapshot-first AI provider 실행, human verification/promotion, report draft/review/approval/export, invocation 전용 JSON Schema, 결과 budget, 중앙 redaction, 구조화 오류, payload-free telemetry 경계를 제공한다. M8은 M7의 52개 Tool surface를 변경하지 않고 재현 가능한 lock, wheel/sdist, clean-install verifier, Inspector strict smoke와 Windows CI를 추가한다.

M7 서버는 다음 52개 Tool만 등록한다.

- `apex.context.get`
- `apex.context.snapshot`
- `apex.context.snapshot_show`
- `apex.context.scope_page`
- `apex.view.simple`
- `apex.view.detailed`
- `apex.view.raw`
- `apex.view.raw_read`
- `ai.capabilities`
- `ai.request.create`
- `ai.request.get`
- `ai.request.list`
- `ai.request.execute`
- `ai.keyword-batch.get`
- `ai.keyword-recommendation.get`
- `ai.keyword-recommendation.list`
- `ai.scope-summary.get`
- `ai.scope-summary.list`
- `ai.keyword-recommendation.review`
- `ai.scope-summary.review`
- `ai.verification.history`
- `ai.promotion.preview`
- `ai.keyword-recommendation.promote`
- `report.get`
- `report.list`
- `report.version.get`
- `report.version.list`
- `report.version.compare`
- `report.review.history`
- `report.approval.get`
- `report.custody-snapshot.get`
- `report.render-package.get`
- `report.export-manifest.get`
- `report.export-status`
- `report.capabilities`
- `report.create`
- `report.version.create`
- `report.ai-draft.ingest`
- `report.review.submit`
- `report.review.comment`
- `report.review.request-changes`
- `report.review.accept-section`
- `report.review.reject-section`
- `report.review.complete`
- `report.review.reopen`
- `report.approve`
- `report.reject`
- `report.approval.revoke`
- `report.custody-snapshot.create`
- `report.render-package.create`
- `report.export.prepare`
- `report.archive`

M7 검토 시점의 public Engine Interface에는 Case/Evidence/Search/Timeline/Annotation/Tag/KakaoTalk용 Tool Descriptor와 대응 transport operation이 없다. 따라서 M7의 신규 Domain Tool 수는 0개다. Core service method나 legacy aggregate schema만으로 Tool을 만들지 않으며, 추후 Descriptor·operation·bounded pagination·capability·partial·citation 정책이 함께 제공될 때 별도 allowlist/binding 검토를 거친다.

`apex.view.raw_read`, AI review/preview/promotion과 report review/approval/custody/export/archive Tool은 discovery에 존재하지만 기본 stdio CLI에는 신뢰 가능한 identity/approval source가 없으므로 `HUMAN_CONFIRMATION_REQUIRED`로 거부된다. actor만 필요한 `report.create`, `report.version.create`, `report.render-package.create`도 기본 stdio에서는 `MCP_AUTHENTICATED_ACTOR_REQUIRED`로 거부된다. HTTP에서는 검증된 bearer principal에 등록된 frontend actor/session, OAuth scope, role, case allowlist와 server-side approval grant를 사용한다. `report.ai-draft.ingest`는 AI actor를 `mcp-ai-layer`로 고정하고 review나 approval을 만들지 않는다.

Core의 Descriptor가 가리키는 persisted object schema를 MCP 호출 인자 스키마로 자동 재사용하지 않는다. `apex.context.snapshot`의 purpose는 client가 선택하지 못하며 MCP layer가 `MCP_REQUEST`로 고정한다. Renderer가 검증 완료 후 호출하는 `report.export.record-result`는 MCP Tool로 등록하지 않고 host-only callback으로 유지한다.

## 2. 의존성 및 실행

MCP 의존성은 Core 기본 설치와 분리된 optional extra다.

```bash
uv sync --locked --extra mcp-server
apex-mcp \
  --database /absolute/path/to/existing-case.db \
  --schema-dir /absolute/path/to/APEX_Digtal_Forensic_Tool/schemas/v1
```

배포물 검증은 저장소 root에서 다음 순서로 수행한다. `verify_mcp_package.py`는 lock에서 hash가 포함된 requirements를 내보내 새 임시 virtual environment에 설치하고, wheel은 `--no-deps`로 설치한 뒤 `uv pip check`, 실제 console stdio와 선택적 Inspector 검증을 수행한다.

```bash
uv lock --check
uv build --out-dir dist
python tools/verify_mcp_package.py --wheel-dir dist --inspector --json
```

일반 `pip` 설치를 제공할 때도 먼저 검증된 wheel을 만들고 해당 artifact를 설치한다. 저장소 개발 설치는 위의 locked `uv sync`를 기준으로 한다.

기본 transport는 newline-delimited JSON-RPC stdio다. 두 파일 경로는 모두 명시해야 하며, 기본값으로 evidence나 임의 데이터베이스를 탐색하지 않는다. 존재하지 않는 database는 `initialize_database=False` 정책 때문에 시작 전에 거부한다.

로컬 HTTP smoke 구성은 다음과 같다. token 값은 CLI 인자가 아니라 지정한 환경 변수에서만 읽는다.

```bash
export APEX_MCP_HTTP_TOKEN='replace-with-a-random-secret'
apex-mcp \
  --transport http \
  --database /absolute/path/to/existing-case.db \
  --schema-dir /absolute/path/to/APEX_Digtal_Forensic_Tool/schemas/v1 \
  --http-actor-id analyst-123 \
  --http-session-id frontend-session-123 \
  --http-tenant-id tenant-123 \
  --http-case-id case-allowed-by-backend \
  --http-allowed-host 127.0.0.1:8765 \
  --http-allowed-origin http://127.0.0.1:8765
```

기본 HTTP endpoint는 `http://127.0.0.1:8765/mcp`다. HTTP 모드는 bearer auth가 없으면 Tool discovery와 call을 401로 거부한다. Host와 Origin은 wildcard가 없는 exact allowlist이며 CORS preflight, 1 MiB request-body 상한과 60초당 120회 기본 rate limit을 적용한다. CLI의 기본 role은 `ANALYST`, 기본 scope는 `apex:mcp`, `apex:read`, `apex:write`, `apex:confirm`, `apex:raw`이고 approval/export scope는 명시적으로 추가해야 한다. CLI smoke provider에는 승인 발급 UI가 없으므로 확인 필요 Tool은 계속 default-deny다. Non-loopback bind는 reverse proxy/TLS termination을 전제로 public issuer/resource URL이 모두 HTTPS여야 시작할 수 있다.

실제 제품 Backend는 `FrontendSecurityProvider`와 SDK `TokenVerifier`를 구현하거나 동일 port를 감싼다. 저장소의 `InMemoryFrontendSecurityProvider`와 `StaticBearerTokenVerifier`는 local integration·test용이다. Backend가 발급하는 approval은 raw token이나 모델 인자로 전달하지 않고 provider의 trusted store에 기록해야 한다.

환경 설정을 직접 사용할 때는 `APEX_MCP_DATABASE`와 `APEX_MCP_SCHEMA_DIR`가 모두 필수다. `APEX_MCP_ALLOWED_TOOLS`는 programmatic 구성용 쉼표 구분 allowlist지만, allowlist만으로 Tool이 노출되지는 않는다. 코드에 명시적 `ToolBinding`이 있고 Core Descriptor·capability·schema 검사를 모두 통과해야 한다. 기본 CLI는 검토가 끝난 고정 M7 allowlist와 binding을 사용한다.

AI provider는 선택 설정이다. 설정하지 않으면 AI Tool discovery와 request read/create는 유지되지만 `ai.request.execute`는 `CAPABILITY_UNAVAILABLE`로 실패한다. OpenAI-compatible endpoint를 사용할 때는 네 필드를 모두 제공한다.

```bash
export APEX_AI_API_KEY='provider-secret'
apex-mcp \
  --database /absolute/path/to/existing-case.db \
  --schema-dir /absolute/path/to/APEX_Digtal_Forensic_Tool/schemas/v1 \
  --ai-provider-id openai-compatible \
  --ai-base-url https://provider.example/v1 \
  --ai-model model-name \
  --ai-api-key-env APEX_AI_API_KEY
```

설정에는 API key 값이 아니라 environment variable 이름만 들어간다. provider id, URL, model, key environment 이름 중 일부만 주면 서버 시작 단계에서 거부한다.

## 3. 호출 경계

```text
MCP client
  -> HTTP bearer/Host/Origin/CORS/body/rate gate (HTTP only)
  -> verified principal -> frontend actor/session/tenant/case allowlist
  -> ToolRegistry
     -> input JSON Schema
     -> Descriptor + phase allowlist
     -> runtime capability
     -> OAuth scope + RBAC + target case/session ownership
     -> server-verified confirmation
     -> rolling call/item/serialized-byte budget
     -> EngineAdapter
        -> ServiceBundle.interface.invoke_read/invoke_mutation
     -> central redaction
     -> api-response.schema.json
  -> MCP structuredContent + TextContent
```

`apex_mcp`는 evidence 파일, SQLite adapter 또는 parser를 직접 호출하지 않는다. 모든 forensic 동작은 `EngineInterfaceService`를 통과한다. MCP SDK import도 `src/apex_mcp`에만 존재한다.

MCP protocol에는 공통 turn identifier가 없으므로 stdio는 연결 단위, HTTP는 raw identity가 아닌 tenant/session hash 단위의 60초 rolling window를 사용한다. 한 호출은 1 MiB, 한 window는 64 calls·4,000 items·4 MiB로 제한하며 Descriptor의 `max_result_items`도 별도로 적용한다. 같은 non-null opaque cursor를 같은 window에서 다시 사용하면 pagination loop로 거부한다.

AI 생성 흐름은 `context.snapshot` → `ai.request.create` → `ai.request.execute` 순서다. execute는 immutable request에 포함된 operation만 허용하고 provider dispatch 직전에 source revision을 재검증한다. 완료된 동일 request/operation은 Core 저장 결과를 replay하므로 provider를 다시 호출하지 않는다. provider 결과는 기존 Core ingest validation을 통과한 뒤 `UNREVIEWED` 및 `NOT_OBSERVED_FACT` 상태로 반환된다.

Human verification 흐름은 review → verification history → promotion preview → promotion 순서다. review와 promotion의 actor는 모델 인자가 아니라 인증된 host가 주입한 identity만 사용한다. case ID, recommendation/summary/keyword-set target, review revision, request fingerprint를 Core와 Confirmation Gate 양쪽에서 결합한다. promotion은 승인된 keyword recommendation과 DRAFT keyword set을 연결해 기록만 남기며 검색을 실행하거나 keyword set을 활성화하지 않는다. Keyword/scope provider ingest operation은 여전히 모델에 직접 노출하지 않는다.

Report 흐름은 AI/analyst draft → immutable version → section review → review complete → approval → custody snapshot → render package → export manifest 순서다. 모든 report object 호출은 invocation의 `case_id`와 Core target의 실제 case를 mutation 전에 비교한다. AI draft는 자동 review/approval을 만들 수 없고, review와 approval actor는 host가 주입한 human identity만 사용한다. Export confirmation은 report version, approval ID, content fingerprint와 custody snapshot ID를 함께 고정하며 Core는 최신 승인과 다시 비교한다. Preview render package는 export 용도로 사용할 수 없고 실제 renderer result 기록은 host-only다.

## 4. 확인과 오류 정책

- `requires_confirmation=false`: 확인 없이 read/mutation 경계로 전달할 수 있다.
- `requires_confirmation=true`: server-side `ConfirmationProvider`가 해당 요청을 검증해야 한다.
- provider가 없거나 요청이 일치하지 않으면 `HUMAN_CONFIRMATION_REQUIRED`로 거부한다.
- approval은 actor/session/case/tool/target/request fingerprint와 만료 시간이 모두 일치해야 하며 기본 1회 사용 후 소진된다.
- HTTP token이 Tool scope/role을 충족하지 않거나 다른 GUI session context를 참조하면 `MCP_AUTHORIZATION_DENIED`로 거부한다.
- target case가 frontend session allowlist 밖이면 Core mutation 전에 `MCP_TENANT_SCOPE_VIOLATION`으로 거부한다.
- actor/approver/captured/created identity와 confirmation metadata는 MCP invocation schema에 없으며 모델이 공급하면 거부한다. `ANONYMOUS`·`UNAUTHENTICATED` 및 AI/LLM/model/bot actor도 human mutation에 사용할 수 없다.
- MCP arguments의 `confirmed` 또는 token 문자열은 invocation schema에서 거부한다.
- unknown exception의 원문은 client에 반환하지 않고 `MCP_INTERNAL_ERROR`로 정규화한다.
- API key, bearer token, credential, prompt, raw provider body, chain-of-thought 및 binary payload는 중앙 redaction 대상이다.

## 5. M0/M1/M2/M3/M4/M5/M6/M7/M8 검증 항목

- 공식 Python MCP SDK `2.1.1`
- negotiated protocol `2026-07-28`
- in-process Tool discovery/call
- 실제 stdio subprocess 초기화와 고정된 M7 Tool 52개 discovery
- authenticated Streamable HTTP에서 protocol `2026-07-28`과 동일 52개 Tool contract
- HTTP 무인증 401, invalid Host 421, invalid Origin 403, exact CORS, oversized 413, rate-limit 429
- case tenant 교차 접근, 같은 case의 다른 frontend session context, analyst approval role 차단
- Backend UI approval과 raw-read fingerprint/target 결합, altered request와 one-time replay 차단
- canonical schema 70개 로드와 Draft 2020-12 검사
- interface/descriptor/capability/confirmation/allowlist/redaction/error tests
- 7개 Context/View Tool의 실제 Core call, TTL, MCP_REQUEST 고정, pagination loop, output contract 및 budget tests
- Raw Read 무승인/모델 confirmation/1 MiB/경로/target/fingerprint/one-time grant tests
- AI provider capability, snapshot-first request, execute/ingest, 완료 결과 replay, operation 제한, secret-field schema 차단, stale revision dispatch 차단 tests
- keyword/scope review default-deny, actor spoof 차단, case/target/revision 결합, verification history, promotion preview와 one-time grant metadata tests
- promotion이 search를 실행하지 않고 DRAFT keyword set을 활성화하지 않는다는 side-effect tests
- Report 29개 Tool discovery, renderer result callback 미노출, actor spoof와 machine actor 차단 tests
- AI draft 무승인 상태, case-bound read/mutation, review revision, section review와 approval 순서 tests
- 승인 전 export 차단, approval/content/custody anchor 불일치 차단, one-time export grant와 citation/custody package 연결 tests
- Annotation/Tag Descriptor와 binding 부재, SHA512 미노출, Search TERM 4096/4097 및 regex 512/513 Core 경계 tests
- KakaoTalk Android unsupported와 external-key-only/automatic-key-acquisition=false Capability tests
- `uv.lock`의 cross-platform artifact hash와 MCP SDK/uvicorn exact pin 검사
- clean environment의 hash-enforced dependency install, wheel console entry point와 version 검사
- 한글 임시 경로에서 stdio EOF 종료, stdout protocol 전용, stderr 분리와 secret marker 비노출 검사
- 공식 MCP Inspector `2.4.0` strict `tools/list`: 52개 Tool, schema portability 오류·경고 0건
- GitHub Actions Ubuntu Inspector 및 Windows Python 3.11/3.12 clean wheel stdio matrix 구성
- MCP-only release gate: contract, stdio, Ruff, strict mypy, design, diff, Bandit manifest drift
- Ruff 및 strict mypy

MCP 전용 테스트는 49건 통과했다. 최종 wheel의 clean install과 실제 `apex-mcp` console에서는 protocol `2026-07-28`, 정확히 52개 Tool, Raw Read default-deny, 한글 database path, EOF 정상 종료, stdout 0-byte idle 종료와 secret 비노출을 확인했다. 공식 Inspector strict 검사도 schema portability 진단 0건으로 통과했다. 실제 localhost HTTP console smoke와 in-process E2E에서는 동일 protocol/Tool 계약과 M6 보안 경계를 확인했다. 전체 298건은 289 passed, 7 skipped, 기존 2건 failed다.

전체 회귀 기준선에는 MCP 변경 전부터 존재한 두 실패가 있다. Firefox NSS decryption result redaction schema 불일치와 synthetic benchmark capability unavailable이며, M7 변경 범위와 무관하다.

## 6. Backend 통합 완료 및 다음 단계

### 6-1. Backend 인증 통합 (Phase 6 완료)

`apex_backend` + `apex_mcp` HTTP 모드 간 end-to-end 인증 체인이 완성됐다.

**구현 완료 항목:**

- `JwtTokenVerifier`: JWKS fetch + TTL 캐시 + RS256 서명 검증 → `AccessToken | None`
- `PersistentFrontendSecurityProvider`: JWT 클레임에서 `FrontendSession` 추출 (DB 불필요)
- `DbFrontendSecurityProvider`: sync SQLAlchemy로 `ConfirmationGrantRow` 조회/소비
- `POST /confirmations`: JWT 검증 후 1회용 5분 grant 발급
- E2E 테스트 4건: JWT → MCP tool (정상), 위조 토큰 → 401, 허용되지 않은 case → TENANT_SCOPE_VIOLATION, InMemory 경로 유지

**보안 체인:**

```
POST /auth/login → access_token (RS256 JWT)
     ↓
MCP HTTP (Bearer <token>) → JwtTokenVerifier → PersistentFrontendSecurityProvider → FrontendSession
     ↓
POST /confirmations (Bearer <token>) → ConfirmationGrantRow (DB)
     ↓
MCP confirm tool → DbFrontendSecurityProvider.confirmation_for/authorize → 1회 소비
```

배포 가이드: [`docs/backend/deployment/README.md`](backend/deployment/README.md)

### 6-2. Windows 검증 상태

MCP protocol과 Tool 동작은 macOS/Linux에서도 동적으로 검증할 수 있으며 M8의 local clean install·stdio·Inspector 검사는 macOS에서 통과했다. Windows가 필요한 지점은 최종 배포/제품 통합이다. GitHub Actions [MCP packaging and Windows run #1](https://github.com/APEX-digtal-forensic-tool/APEX_Digtal_Forensic_Tool/actions/runs/33482524240)에서 Ubuntu contract/security와 Inspector, `windows-latest` Python 3.11/3.12 wheel build, hash-locked clean install, `apex-mcp.exe` stdio/EOF/한글 경로 검증이 모두 통과했다. 이 hosted run을 M8의 package-level Windows evidence로 보존한다.

제품 통합에서는 설치된 Desktop bundle의 console lifecycle, 경로·권한·한국어 환경, Backend/Frontend 연결과 Windows-only provider를 함께 검증해야 한다. 새로운 Domain Tool은 Core에 명시적 Descriptor와 transport contract가 추가된 뒤 별도 단계로 검토한다.
