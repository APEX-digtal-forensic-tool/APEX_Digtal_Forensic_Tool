# Phase 11 — confirmation grant 1회 소비 경쟁 조건 수정

상태: 대기
선행조건: 없음 (Phase 10과 순서 무관, 같이 진행해도 됨)
분류: fix

## 배경 (코드 확인함, 추측 아님)

`src/apex_backend/auth/db_confirmation.py`의
`DbFrontendSecurityProvider.authorize()`가 읽기(`db.get`) → 파이썬에서
`uses_count >= max_uses` 조건 검사 → 쓰기(`row.uses_count += 1; db.commit()`)를
하나의 원자적 연산으로 안 묶고 순서대로 실행한다:

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

`src/apex_backend/models.py`의 `ConfirmationGrantRow`에는 행 잠금이나
낙관적 잠금에 쓸 버전 컬럼이 없다 (직접 확인함). 두 요청이 거의 동시에
같은 `grant_id`로 `authorize()`를 호출하면 둘 다 `uses_count >= max_uses`
검사를 통과한 뒤에야 각자 커밋할 수 있어서, `max_uses=1`짜리 grant가
두 번 이상 소비될 수 있다.

전제 조건(악용 난이도): 이미 유효한 Bearer 토큰(`apex:confirm`/
`apex:approve` 스코프)을 가진 클라이언트가 같은 grant로 거의 동시에 두 번
요청을 보내야 한다. 외부에서 인증 없이 뚫리는 구멍은 아니다. 다만
"1회용"이 confirmation grant 기능 전체의 존재 이유(report 승인/반려 같은
되돌리기 힘든 작업을 사람이 정확히 한 번만 승인하게 만드는 것)라서, 정확히
그 보장이 깨지는 지점이라는 게 문제다. 클라이언트가 네트워크 재시도로
같은 요청을 두 번 보내는 흔한 상황에서도 발동할 수 있다.

## 할 일

1. `authorize()`의 읽기-검사-쓰기를 원자적 연산으로 바꾼다. 둘 중 하나
   선택 (구현하면서 SQLAlchemy sync 세션/사용 중인 DB 방언과 더 잘 맞는
   쪽으로 판단):
   - **조건부 원자 UPDATE**: `UPDATE confirmation_grants SET uses_count =
     uses_count + 1 WHERE grant_id = :id AND uses_count < max_uses`를 직접
     실행하고, 영향받은 row 수(`rowcount`)로 성공/실패 판단. `target_ids`
     비교나 만료 시각 체크처럼 SQL로 표현하기 번거로운 조건이 있으면
     `WHERE` 절에 같이 넣거나, 먼저 조회해서 실패를 걸러낸 뒤 마지막
     소비 단계만 원자 UPDATE로 처리.
   - **`SELECT ... FOR UPDATE`**: `db.get`을 행 잠금 걸린 조회로 바꿔서
     (SQLAlchemy `with_for_update()`) 같은 트랜잭션 안에서 검사→갱신까지
     끝내기.
2. 테스트 DB가 SQLite(단위 테스트 기본)일 경우 `SELECT ... FOR UPDATE`가
   제대로 잠금을 안 걸 수 있다는 점 감안 — 원자 UPDATE 방식이 SQLite/
   PostgreSQL 양쪽에서 더 일관되게 동작할 가능성이 높으니 우선 고려할 것.
   (`specs/00_DECISIONS.md`에 단위=SQLite, 통합=PostgreSQL로 이미 정해져
   있음 — 이 결정과 어긋나지 않는 방식으로 고칠 것.)
3. 동시성 경쟁을 재현하는 테스트를 추가한다: 같은 `grant_id`(`max_uses=1`)에
   대해 `authorize()`를 동시에(또는 스레드/멀티프로세스로 겹치게) 두 번
   호출했을 때 정확히 하나만 `True`를 반환하는지 검증. 완전한 동시 실행을
   흉내내기 어려우면 최소한 "먼저 커밋된 트랜잭션이 있는 상태에서 두 번째
   시도가 최신 `uses_count`를 보고 거부되는지"를 검증하는 순차 테스트라도
   추가.
4. `confirmation_for()`(같은 파일, 위쪽)도 같은 파일 안에서 `uses_count`를
   읽어서 조건에 쓰는데, 이건 grant *발급 가능 여부 조회*용이라 소비
   자체를 하지 않으므로 이번 Phase의 원자성 수정 대상은 아니다 — 헷갈리지
   않게 확인만 하고 건드리지 말 것.

## 완료 조건

- [ ] `authorize()`가 읽기-검사-쓰기를 원자적으로 처리 (조건부 UPDATE 또는
      행 잠금)
- [ ] 동시 소비 재현 테스트 신규 작성, 통과 (수정 전 코드로 돌리면 실패하는
      걸 먼저 확인해서 PR 설명에 포함하면 좋음)
- [ ] 기존 `tests/backend/test_confirmation_grant.py` 등 관련 테스트 전부
      계속 통과
- [ ] ruff/mypy 클린
- [ ] PR 생성

## PR 규칙 (기존과 동일)

- 브랜치: `fix/backend-phase-11-confirmation-grant-race`
- PR 제목: `fix(backend): Phase 11 — confirmation grant 소비 경쟁 조건 수정`
- base: `main`, 머지는 사람이 함, Claude Code는 PR 생성까지만
- PR 설명에 완료 조건 체크리스트, 재현/수정 전후 테스트 결과 포함
- 커밋 author `hyj090915 <hyj090915@gmail.com>`, `Co-Authored-By` 트레일러 금지
