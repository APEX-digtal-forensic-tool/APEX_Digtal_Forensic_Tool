# 백엔드/MCP 통합 재검토 — 2026-09-15

이전 보고에서 "Phase 1~9 완료, 코드 레벨 문제 없음"이라고 했던 것을 다시 뜯어봤다.
테스트 통과/ruff/mypy/CI green은 다 사실이지만, **테스트가 실제로 검증하지 않는
경로**가 하나 있었고 거기서 진짜 문제를 찾았다. 아래는 전부 코드를 직접 읽고
실행해서 재현한 것만 적었고, 추측이나 "그럴 것 같다"는 안 넣었다. 의심 가는
부분은 먼저 관련 스펙 문서와 서브클래스/호출부까지 다 따라가서 "이게 설계
의도인지 진짜 버그인지"를 확인한 다음에만 문제로 올렸다.

## 요약

| # | 항목 | 심각도 | 상태 |
|---|---|---|---|
| 1 | 프로덕션 CLI(`apex-mcp`)가 새 JWT 인증 체인을 전혀 안 씀 | 높음 | 확인된 문제 |
| 2 | 배포 가이드 4단계 명령어가 실제로 실행 불가 | 높음 (1번과 직결) | 확인된 문제, 재현함 |
| 3 | confirmation grant 1회 소비 로직에 동시성 경쟁 조건 | 중간 | 확인된 문제 |
| 4 | `PersistentFrontendSecurityProvider.confirmation_for`가 항상 `None` | - | 문제 아님 (설계 의도, 검증함) |
| 5 | `JwtTokenVerifier`가 `client_id`에 issuer를 넣음 | - | 문제 아님 (미사용 필드) |
| 6 | Firefox NSS redaction 스키마 vs 코드 화이트리스트 불일치 | - | 확인함, 백엔드/MCP 무관 (Core 이슈, 근본원인 특정함) |
| 7 | refresh token 재사용 탐지/rotation 없음, 로그아웃 엔드포인트 없음 | 낮음 | 참고 (스펙에 명시된 요구사항 아님) |

---

## 1. 프로덕션 CLI가 새 JWT 인증 체인을 전혀 안 씀 (높음)

**주장**: Phase 3~5에서 만든 `JwtTokenVerifier`, `DbFrontendSecurityProvider`
(영속 세션/DB 기반 confirmation)는 실제로 배포해서 띄우는 `apex-mcp` 명령어
안에서는 단 한 줄도 쓰이지 않는다. HTTP 모드는 여전히 예전 그대로
`StaticBearerTokenVerifier` + `InMemoryFrontendSecurityProvider`(CLI 인자로
받은 액터/세션/역할 하나를 고정해서 등록)로만 동작한다.

**증거**:

`src/apex_mcp/__main__.py` (실제 `apex-mcp` 콘솔 스크립트 진입점,
`pyproject.toml`의 `apex-mcp = "apex_mcp.__main__:main"`)의 HTTP 분기
(134~166번째 줄 부근)를 그대로 인용:

```python
access_token = AccessToken(
    token=secret,
    client_id=f"apex-http:{args.http_tenant_id}",
    subject=args.http_actor_id,
    scopes=scopes,
    resource=resource_url,
    claims={"iss": issuer_url},
)
frontend_security = InMemoryFrontendSecurityProvider()
frontend_security.register(access_token, FrontendSession(...))
...
run_http(
    runtime,
    HttpTransportConfig(...),
    token_verifier=StaticBearerTokenVerifier(secret, access_token),
)
```

- `JwtTokenVerifier`, `DbFrontendSecurityProvider`, `PersistentFrontendSecurityProvider`
  중 어느 것도 `__main__.py`에서 import되지 않는다:
  ```
  $ grep -rln "DbFrontendSecurityProvider\|JwtTokenVerifier(" --include="*.py" . | grep -v /tests/
  ./src/apex_backend/auth/db_confirmation.py
  ./src/apex_backend/app.py
  ```
  (`app.py`는 FastAPI 백엔드 자체 앱이지 `apex-mcp` CLI가 아니다.)
- `APEX_JWKS_URI`, `APEX_JWKS_CACHE_TTL` — 배포 가이드가 "apex_mcp 실행 시 필요"라고
  적어놓은 환경변수 — 는 리포 전체에서 `docs/backend/deployment/README.md`
  말고는 어디에도 등장하지 않는다:
  ```
  $ grep -rn "APEX_JWKS_URI\|APEX_JWKS_CACHE_TTL" --include="*.py" .
  (결과 없음)
  ```
- Phase 6의 "E2E 테스트"(`tests/mcp/test_e2e_backend_integration.py`)는
  `apex-mcp` CLI를 실행하지 않는다. `create_http_app()`을 테스트 코드 안에서
  직접 파이썬으로 호출해서 `JwtTokenVerifier`/`PersistentFrontendSecurityProvider`를
  수동으로 조립한다. 즉 "라이브러리 코드가 서로 맞물려 동작한다"는 것만
  검증했지, "실제로 배포하는 바이너리가 그 라이브러리를 쓴다"는 건 검증한 적이
  없다.
- CI(`.github/workflows/mcp-ci.yml`)에도 `apex-mcp` CLI를 실제로 띄워보는
  스텝이 없다 (`grep -n "apex-mcp\|--http\|--transport" .github/workflows/mcp-ci.yml`
  → 결과 없음). 그래서 지금까지 ruff/mypy/pytest/CI가 전부 green이었어도 이
  gap이 한 번도 걸러진 적이 없다.

**결론**: `00_MASTER_PLAN.md` 6절 완료 기준 중 "`src/apex_mcp`가 더 이상
`InMemoryFrontendSecurityProvider`/`StaticBearerTokenVerifier`를 프로덕션
경로에서 쓰지 않음"이 실제로는 충족되지 않았다. 코드는 다 만들어졌는데
마지막 배선(연결) 작업이 빠졌다.

## 2. 배포 가이드 4단계 명령어가 실제로 실행 불가 (높음, 1번과 같은 원인)

`docs/backend/deployment/README.md` 4단계에 적힌 명령어를 그대로 실행해서
재현했다:

```
$ APEX_JWKS_URI="https://example.com/jwks.json" \
  APEX_ISSUER="https://apex.example.com" \
  APEX_MCP_RESOURCE="https://apex.example.com/mcp" \
  python -m apex_mcp --database /tmp/x.db --schema-dir schemas/v1 --http --port 8765

apex-mcp: error: ambiguous option: --http could match --http-host, --http-port,
--http-path, --http-allowed-host, --http-allowed-origin, --http-issuer-url,
--http-resource-url, --http-token-env, --http-actor-id, --http-session-id,
--http-tenant-id, --http-case-id, --http-role, --http-scope,
--http-max-requests, --http-rate-window
```

`--http`라는 플래그 자체가 없다 (`--transport http`가 맞는 이름). 이것도
고쳐서 다시 실행하면 `--http-actor-id`, `--http-session-id`, `--http-tenant-id`,
`--http-case-id`, `APEX_MCP_HTTP_TOKEN`이 필수라서 또 막힌다 — 가이드에 적힌
환경변수(`APEX_JWKS_URI` 등)로는 절대 못 띄운다. 이건 1번 문제의 직접적인
결과다: 가이드를 쓴 사람(또는 세션)이 실제로 그 명령어를 실행해보지 않고
"이렇게 동작해야 한다"는 의도만 적어놓은 것으로 보인다.

## 3. confirmation grant 1회 소비 로직의 동시성 경쟁 조건 (중간)

`src/apex_backend/auth/db_confirmation.py`의 `DbFrontendSecurityProvider.authorize()`:

```python
def authorize(self, request: ConfirmationRequest) -> bool:
    now = datetime.now(UTC)
    with self._sync_factory() as db:
        row = db.get(ConfirmationGrantRow, request.grant_id)
        ...
        if row.uses_count >= row.max_uses:
            return False
        ...
        row.uses_count += 1
        db.commit()
        return True
```

읽기(`db.get`) → 파이썬에서 조건 검사 → 쓰기(`db.commit()`)가 하나의 원자적
연산이 아니다. `SELECT ... FOR UPDATE` 같은 행 잠금도, `UPDATE ... WHERE
uses_count < max_uses` 같은 조건부 원자 업데이트도, 낙관적 잠금용 버전
컬럼도 없다 (`src/apex_backend/models.py`의 `ConfirmationGrantRow`에 그런
컬럼 없음, 직접 확인함). 두 요청이 거의 동시에 같은 `grant_id`로
`authorize()`를 호출하면 둘 다 `uses_count >= max_uses` 검사를 통과한
뒤에야 각자 커밋할 수 있어서, `max_uses=1`짜리 grant가 두 번 소비될 수
있다.

**전제 조건(악용 난이도)**: 이미 유효한 Bearer 토큰(`apex:confirm`/
`apex:approve` 스코프)을 가진 클라이언트가 같은 grant로 거의 동시에 두 번
요청을 보내야 한다. 외부에서 인증 없이 뚫을 수 있는 구멍은 아니다. 다만
"1회용"이 이 기능 전체의 존재 이유(report 승인/반려 같은 되돌리기 힘든
작업을 사람이 한 번만 승인하게 만드는 것)라서, 정확히 그 보장이 깨지는
지점이라는 게 문제다. 클라이언트가 네트워크 재시도로 같은 요청을 두 번
보내는 흔한 상황에서도 발동할 수 있다.

## 4. `PersistentFrontendSecurityProvider.confirmation_for`가 항상 `None` — 확인 결과 문제 아님

처음 봤을 때는 버그처럼 보였다 (`src/apex_mcp/frontend_security.py` 244번째
줄 근처, `confirmation_for`가 무조건 `return None`). 근데 클래스 docstring에
이렇게 명시돼있다:

> `confirmation_for`와 `authorize`는 주입된 `ConfirmationProvider`에 위임한다.
> DB 기반 구현(Phase 5)으로 교체해서 영속적인 confirmation grant를 쓰도록
> 하라.

그리고 실제로 Phase 5에서 만든 `DbFrontendSecurityProvider`(`db_confirmation.py`)가
`PersistentFrontendSecurityProvider`를 상속해서 `confirmation_for`/`authorize`
둘 다 실제 DB 조회 로직으로 오버라이드한다 (위 3번 항목에 인용한 코드가
그거다). 배포 가이드의 아키텍처 다이어그램에도 실제로 쓰이는 건
`DbFrontendSecurityProvider`라고 명시돼있다. 즉 베이스 클래스가 `None`을
반환하는 건 "아직 안 만들어서"가 아니라 "이 클래스 자체는 추상 기반이고
진짜 로직은 서브클래스에 있다"는 의도된 설계다. 문제 없음.

## 5. `JwtTokenVerifier`가 `client_id`에 issuer 문자열을 넣음 — 확인 결과 영향 없음

`src/apex_backend/auth/jwt_verifier.py`에서 `AccessToken.client_id`에
`str(claims.get("iss", ""))`(issuer)를 넣는다. OAuth 개념상 `client_id`와
`issuer`는 다른 값이라 이름만 보면 이상하다. 근데 리포 전체에서
`access_token.client_id`를 실제로 읽는 곳은 `StaticBearerTokenVerifier.__init__`
딱 한 군데뿐이고, 그것도 개발용 스텁이지 JWT 경로에서는 안 쓰인다. 새 JWT
경로(`PersistentFrontendSecurityProvider.resolve_session`)는 `client_id`를
아예 참조하지 않는다. 그래서 이름이 misleading하긴 해도 기능적으로 아무
영향이 없다 — 코드 품질 관점의 사소한 지적이지 "문제"로 올릴 정도는 아니다.

## 6. Firefox NSS 복호화 redaction 스키마 검증 실패 — 백엔드/MCP와 무관, 원인까지 확인함

전체 pytest(`tests/` 전부, 옵션 의존성 다 설치한 상태)에서 유일하게 실패한
테스트: `tests/unit/test_advanced_runtime_decryption.py::test_nss_lib_provider_decrypts_logins_without_primary_password`.
`docs/MCP_SERVER.md`에 "알려진 pre-existing 실패"로만 이름이 적혀있길래,
정확히 뭐가 문제인지 직접 재현 스크립트를 짜서 실패 지점을 특정했다.

**근본 원인**: `schemas/v1/common.schema.json`의 `redactedObject` 정의가
`patternProperties`로 "이름에 `password`가 들어가면 값은 무조건 문자열
`"<redacted>"`여야 한다"는 정규식을 건다. 근데 이 정규식이 단순 부분 문자열
매칭이라 `primary_password_supplied`, `primary_password_required`처럼
"패스워드가 필요했는지/제공됐는지"를 나타내는 boolean 플래그 필드까지
전부 걸려버린다.

반면 `src/apex_forensic/domain/models/secret.py`의 실제 Python 리팩션 로직은
이 두 필드(그리고 `primary_password_emitted`, `password_plaintext_emitted`,
`password_value_present`)를 `_SAFE_INDICATOR_FIELD_NAMES`라는 명시적
화이트리스트에 넣어서 "이건 안전한 boolean 플래그지 진짜 비밀번호가
아니다"라고 일부러 리댁션 대상에서 빼놨다. 즉 **파이썬 코드와 JSON
스키마가 서로 다른 규칙을 쓰고 있다** — 코드는 이 필드들을 안전하다고
보고 `false`/`null` 그대로 내보내는데, 스키마는 이름에 "password"가
있다는 이유만으로 반드시 `"<redacted>"`이어야 한다고 요구해서 검증이
깨진다.

재현해서 직접 확인함 (`NssLibProvider.decrypt_logins()` 실행 결과):

```
PATH: ['metadata', 'primary_password_supplied'] MSG: '<redacted>' was expected
PATH: ['metadata', 'profile']                   MSG: (하위의 primary_password_required: null 때문에 연쇄 실패)
```

다른 정규식 항목들(`pragma_key`, `*_nonce`)은 `(?!_hash$)` 같은 부정형
lookahead로 이런 케이스를 이미 피해가게 만들어놨는데, `password` 패턴만
그 처리가 빠져있다. `redactedObject`는 스키마 6개(`schemas/v1/*.json`)가
공유해서 쓰는 정의라, 이 세이프 인디케이터 필드들이 등장하는 다른 곳
(`src/apex_forensic/adapters/artifacts/browser.py`에도 같은 필드명들이
쓰인다)에서도 같은 문제가 재발할 수 있는 구조적인 gap이다.

**결론**: Core 포렌식 엔진 쪽 문제고 백엔드/MCP 담당 범위 밖인 건 맞다.
다만 "알려진 이슈"라고만 알고 넘어가기보다, Core 담당(권태욱)한테 `common.schema.json`의
`password` 패턴에 `(?!_(?:required|supplied|emitted)$)` 같은 예외를
추가하거나, `_SAFE_INDICATOR_FIELD_NAMES`에 있는 필드는 스키마 쪽에도
동일하게 화이트리스트로 반영해야 한다고 구체적으로 전달할 수 있는
수준까지는 파봤다.

## 7. refresh token 재사용 탐지 없음, 로그아웃 엔드포인트 없음 — 참고 사항 (낮음)

`AuthService.refresh()`(`src/apex_backend/auth/service.py`)는 refresh token을
검증만 하고 소비 처리(1회용 마킹, `jti` 블랙리스트 등)를 하지 않는다. 같은
refresh token으로 세션 만료 전까지 몇 번이든 새 access token을 받을 수
있고, 탈취당했을 때 이상 재사용을 탐지할 방법이 없다. 로그아웃
엔드포인트도 없어서 `UserSession.is_active`를 끌 수 있는 API 경로가 코드
어디에도 없다(모델 필드만 존재).

이건 어떤 스펙 문서에도 "refresh rotation을 구현하라"거나 "로그아웃
엔드포인트를 만들라"는 요구사항이 명시된 적이 없어서, 스펙 대비 "버그"라고
부르긴 어렵다. 프로덕션 체크리스트(`docs/backend/deployment/README.md`)에도
빠져있는 항목이라, 나중에 실제 배포 전에 고려할 사항으로만 남겨둔다.

---

## 권장 조치

1번/2번은 사실상 하나의 문제(CLI 배선 누락)라서 같이 고쳐야 한다. `apex-mcp
--transport http`가 `JwtTokenVerifier`/`DbFrontendSecurityProvider`를 실제로
구성해서 쓰도록 `__main__.py`에 새 인자(`--jwks-uri` 등, 또는 배포 가이드가
말하는 `APEX_JWKS_URI` 환경변수를 실제로 읽게)를 추가하고, 배포 가이드
명령어를 그 실제 인터페이스에 맞게 다시 쓰고, 실행해서 진짜로 뜨는지
확인해야 한다. 3번은 `authorize()`를 `UPDATE confirmation_grants SET
uses_count = uses_count + 1 WHERE grant_id = :id AND uses_count < max_uses`
같은 조건부 원자 업데이트(또는 `SELECT ... FOR UPDATE`)로 바꾸면 해결된다.
6번은 백엔드/MCP 소관이 아니니 Core 담당(권태욱)에게 근본 원인과 함께
전달하면 된다.

원하면 1+2번, 3번을 지금까지 쓰던 형식 그대로 `docs/backend/specs/10_*.md`
스펙으로 만들어서 클로드코드한테 바로 던질 수 있게 준비해줄 수 있다.
