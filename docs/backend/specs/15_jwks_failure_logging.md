# Phase 15 — `JwtTokenVerifier` JWKS 조회 실패 로깅 추가

상태: 완료
선행조건: Phase 14와 같은 로깅 체계를 쓰는 게 이상적 (완전히 독립적으로
진행해도 되지만, Phase 14가 먼저 끝나면 그 로거를 재사용할 것)
분류: fix (중간 우선순위)

## 배경 (코드 확인함, 추측 아님)

`src/apex_backend/auth/jwt_verifier.py`의 `JwtTokenVerifier._fetch_jwks()`:

```python
async def _fetch_jwks(self) -> None:
    """Fetch JWKS and populate *_keys* cache. Silently no-ops on error."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self._jwks_uri)
            resp.raise_for_status()
            body = resp.json()
    except Exception:
        return
    ...
```

JWKS 엔드포인트가 네트워크 문제나 백엔드 장애로 응답 못 하면 이 함수는
아무것도 안 하고 조용히 리턴한다. 로그도 텔레메트리도 전혀 없음.

동작 자체는 안전하게 설계돼있다 — 키 캐시가 비어있으면 `verify_token`이
모든 토큰을 거부(fail-closed)하고, 이미 캐시된 키가 있으면 만료된
캐시를 계속 쓰면서(fail-open to stale cache) 다음 성공적 fetch까지
버틴다. **이 fail-open/fail-closed 동작 자체는 바꾸지 않는다** — 이번
Phase는 오직 "실패했을 때 흔적을 남긴다"에만 집중한다.

문제는 관측 가능성이 0이라는 것 — JWKS 엔드포인트가 계속 다운돼서 MCP
서버가 모든 요청을 401로 거부하고 있어도, 서버 쪽에는 아무 흔적도 안
남아서 운영자가 원인을 전혀 추적할 수 없다.

같은 파일 안 개별 JWK 파싱 실패(`except Exception: continue`, 특정
key 하나가 파싱 안 되면 건너뛰는 부분)도 같은 문제가 있음 — 같이
고칠 것.

## 할 일

1. `_fetch_jwks()`의 `except Exception:` 블록에 로깅 추가. 예:
   ```python
   except Exception:
       logger.warning("JWKS fetch failed for %s; keeping cached keys", self._jwks_uri, exc_info=True)
       return
   ```
   (Phase 14에서 로깅 체계가 먼저 도입됐으면 그 로거 사용, 아니면 이
   Phase에서 최소한의 `logging.getLogger(__name__)` 정도는 직접 추가해도
   됨 — 전면적인 로깅 설계는 Phase 14 소관이니 이 Phase는 이 파일에
   필요한 최소한만.)
2. 개별 JWK 파싱 실패(`for jwk in body.get("keys", []): ... except
   Exception: continue`)에도 어떤 kid가 왜 파싱 실패했는지 로깅 추가.
3. 키 캐시가 비어있는 상태에서 fetch가 실패했을 때와, 이미 캐시가 있는
   상태에서 fetch가 실패했을 때(stale cache 계속 사용)를 로그 메시지로
   구분할 수 있으면 더 좋음 (운영 디버깅에 도움 — 필수는 아님, 시간
   되면).
4. **fail-open/fail-closed 동작 자체는 바꾸지 말 것** — 이 Phase는
   로깅 추가만 한다. 동작을 바꾸고 싶다면 별도로 사람과 상의 후 새
   스펙으로 진행.

## 완료 조건

- [ ] JWKS 조회 실패 시 로그 남음 (경고 레벨 이상)
- [ ] 개별 JWK 파싱 실패 시 로그 남음
- [ ] 기존 fail-open/fail-closed 동작(캐시 유무에 따른 분기)은 변경 없음
      — `tests/backend/test_jwt_verifier.py` 기존 테스트 전부 계속 통과
- [ ] 로깅이 실제로 찍히는지 검증하는 신규 테스트 (`caplog` 사용) 추가
- [ ] ruff/mypy 클린
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `fix/backend-phase-15-jwks-failure-logging`
- PR 제목: `fix(backend): Phase 15 — JWKS 조회 실패 로깅 추가`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
