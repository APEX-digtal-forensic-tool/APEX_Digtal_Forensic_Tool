# Phase 12 (선택, 낮음) — refresh token 재사용 탐지 및 로그아웃 엔드포인트

상태: 대기 (우선순위 낮음 — Phase 10/11 끝나고 여유 있을 때, 또는 배포 전
체크리스트 시점에 착수)
선행조건: 없음
분류: enhancement (버그 아님 — 기존 스펙에 명시된 요구사항이 없었음)

## 배경

`AuthService.refresh()`(`src/apex_backend/auth/service.py`)는 refresh
token을 검증만 하고 소비 처리(1회용 마킹, `jti` 블랙리스트 등)를 하지
않는다. 같은 refresh token으로 세션 만료 전까지 몇 번이든 새 access
token을 받을 수 있고, 토큰이 탈취당했을 때 이상 재사용을 탐지할 방법이
없다. 로그아웃 엔드포인트도 없어서 `UserSession.is_active`를 끌 수 있는
API 경로가 코드 어디에도 없다 (모델 필드만 존재).

이건 `specs/00~06` 어디에도 "refresh rotation을 구현하라"거나 "로그아웃
엔드포인트를 만들라"는 요구사항이 명시된 적이 없어서 스펙 대비 "버그"는
아니다. 다만 프로덕션 배포 전 체크리스트(`docs/backend/deployment/README.md`)에도
빠져있는 항목이라 언젠가는 다뤄야 한다.

## 할 일 (착수 시)

1. `POST /auth/logout` 엔드포인트 추가 — 세션의 `UserSession.is_active`를
   `False`로 바꾸는 경로 신설.
2. `AuthService.refresh()`가 refresh token을 1회성으로 소비하도록 변경
   (예: 사용한 refresh token의 `jti`를 무효화 테이블에 기록하거나,
   회전(rotation)해서 매번 새 refresh token을 같이 발급하고 이전 것은
   무효화).
3. 이상 재사용 탐지: 이미 소비(또는 무효화)된 refresh token이 다시
   들어오면 해당 세션 전체를 강제 로그아웃시키는 것까지 고려 (탈취
   시나리오 대응). 이 부분은 범위가 커질 수 있으니, 사람과 먼저 범위를
   확정하고 시작할 것 — 이 문서만 보고 임의로 설계 확장하지 말 것.
4. `docs/backend/deployment/README.md` 프로덕션 체크리스트에 로그아웃/
   토큰 회전 관련 항목 추가.

## 완료 조건

- [ ] `POST /auth/logout` 동작, 세션 비활성화 확인
- [ ] refresh token 1회성 소비 또는 회전 구현
- [ ] 관련 신규 pytest 통과, 기존 `tests/backend` 회귀 없음
- [ ] ruff/mypy 클린
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `feat/backend-phase-12-refresh-rotation-logout`
- PR 제목: `feat(backend): Phase 12 — refresh token rotation 및 로그아웃 엔드포인트`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지

## 주의

이 Phase는 **착수 전 사람 확인 필요** — 재사용 탐지 범위(세션 전체 로그아웃
vs 해당 토큰만 무효화)를 확정하지 않은 상태다. Phase 10/11과 달리 바로
시작하지 말고, 스펙 대비 새 요구사항을 추가하는 성격이라 사람에게 먼저
범위를 물어볼 것.
