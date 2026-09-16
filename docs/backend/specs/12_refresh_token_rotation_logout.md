# Phase 12 — refresh token 재사용 탐지(세션 전체 강제 로그아웃) 및 로그아웃 엔드포인트

상태: 대기 (범위 확정 완료, 바로 착수 가능)
선행조건: 없음
분류: feat

## 배경

`AuthService.refresh()`(`src/apex_backend/auth/service.py`)는 refresh
token을 검증만 하고 소비 처리(1회용 마킹, `jti` 블랙리스트 등)를 하지
않는다. 같은 refresh token으로 세션 만료 전까지 몇 번이든 새 access
token을 받을 수 있고, 토큰이 탈취당했을 때 이상 재사용을 탐지할 방법이
없다. 로그아웃 엔드포인트도 없어서 `UserSession.is_active`를 끌 수 있는
API 경로가 코드 어디에도 없다 (모델 필드만 존재).

**범위 확정됨 (2026-09-15, 사람 결정)**: 탈취된 refresh token이 재사용되는
것을 감지하면, 그 토큰 하나만 무효화하는 게 아니라 **해당 세션 전체를
강제 로그아웃**시킨다. refresh token은 항상 rotation(교체) 방식으로
발급하고, 이미 소비된(rotation으로 교체된) refresh token이 다시 들어오면
탈취로 간주해서 그 `session_id`에 연결된 모든 토큰을 즉시 무효화한다.
이 방식이 더 안전하다는 걸 알고 있고, 정상 사용자도 이 경로를 타면
재로그인해야 한다는 트레이드오프를 감수하기로 결정함.

## 할 일

1. **DB 스키마**: `UserSession`(또는 별도 `RefreshTokenRow`)에 refresh
   token을 1회성으로 추적할 수 있는 컬럼을 추가한다. 제안:
   - refresh token 발급 시 매번 새 `jti`(JWT ID)를 생성해서 DB에
     "현재 유효한 jti"로 기록 (세션당 하나).
   - `refresh()` 호출 시: 들어온 토큰의 `jti`가 세션에 기록된 "현재
     유효한 jti"와 일치하면 → 새 access/refresh 쌍 발급, DB의
     "현재 유효한 jti"를 새 jti로 교체(rotation).
   - 들어온 토큰의 `jti`가 세션에 기록된 값과 다르면(이미 교체된 옛날
     토큰이 재사용됨) → **탈취로 간주**, 해당 `UserSession.is_active`를
     `False`로 설정(세션 전체 강제 로그아웃), 요청은 401로 거부.
2. **`POST /auth/logout` 엔드포인트 신규 추가**: 현재 세션의
   `UserSession.is_active`를 `False`로 설정. Bearer access token으로
   본인 세션만 로그아웃 가능하게.
3. **`AuthService.refresh()` 수정**: 위 1번 로직(정상 rotation vs 재사용
   탐지 후 세션 강제 종료)을 구현.
4. **`verify_token`/세션 검증 경로**에서 `UserSession.is_active == False`인
   세션의 토큰은 (아직 만료 안 됐어도) 거부하도록 확인 — 이미 그렇게
   돼있는지 먼저 확인하고, 안 돼있으면 이 Phase에서 같이 고칠 것.
5. 동시성 고려: rotation 판단(읽기-비교-갱신)도 Phase 11에서 했던 것처럼
   원자적으로 처리할 것 (여러 요청이 거의 동시에 같은 refresh token으로
   rotation을 시도하는 경쟁 상황 — 정상적인 재시도와 실제 탈취를 구분하기
   애매한 지점이니, 판단 기준을 테스트로 명확히 남길 것).
6. `docs/backend/deployment/README.md`에 로그아웃/재사용 탐지 관련 운영
   참고 사항 추가 (예: "세션이 갑자기 강제 로그아웃되면 재사용 탐지가
   발동한 것 — 클라이언트 쪽 refresh token 중복 사용 버그 의심").

## 완료 조건

- [ ] refresh token이 매번 rotation되고, 옛 토큰 재사용 시 세션 전체가
      강제 로그아웃됨 (신규 테스트로 검증)
- [ ] `POST /auth/logout` 동작, 세션 비활성화 확인
- [ ] 비활성화된 세션의 access token도 거부되는지 확인 (기존 동작 재확인
      또는 신규 구현)
- [ ] rotation 판단의 동시성 처리 (Phase 11 패턴 참고)
- [ ] 관련 신규 pytest 통과, 기존 `tests/backend` 회귀 없음
- [ ] ruff/mypy 클린 (`ruff check .` 전체 리포 기준 — Phase 15 때처럼
      `tests/backend`만 빠뜨리는 실수 반복하지 말 것)
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `feat/backend-phase-12-refresh-rotation-logout`
- PR 제목: `feat(backend): Phase 12 — refresh token rotation(세션 강제 로그아웃) 및 로그아웃 엔드포인트`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
