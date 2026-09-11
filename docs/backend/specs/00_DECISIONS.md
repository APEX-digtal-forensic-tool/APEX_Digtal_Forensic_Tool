# 확정된 아키텍처 결정 기록

Phase를 진행하면서 내려진 굵직한 결정을 여기 남긴다. `PROGRESS_LOG.md`의
"결정 대기"에 있던 항목이 확정되면 여기로 옮겨 적는다. 나중에 "왜 이렇게
했더라"를 다시 찾아볼 수 있게 이유까지 반드시 같이 적는다.

형식:

```
## [결정 제목]
- 날짜:
- 결정:
- 이유:
- 영향받는 Phase:
```

---

## 인증 아키텍처
- 날짜: 2026-09-11
- 결정: 옵션 A — JWT 로컬 검증 + 승인 grant는 공유 PostgreSQL
- 이유: 세션/역할은 JWT 클레임으로 로컬 검증(빠름, 백엔드 장애 무관), confirmation_grant처럼 "방금 취소됐을 수도 있는" 상태만 공유 DB 확인(정확함)
- 영향받는 Phase: 2, 3, 4, 5 전체

## DB 엔진
- 날짜: 2026-09-11
- 결정: PostgreSQL (asyncpg 드라이버)
- 이유: 팀 컨벤션 + async 스택과 자연스러운 조합
- 영향받는 Phase: 1~6 전체

## SQLAlchemy 모드
- 날짜: 2026-09-11
- 결정: async (sqlalchemy[asyncio] + asyncpg)
- 이유: MCP verify_token이 async def, FastAPI도 async — sync 혼용하면 event loop 문제 발생
- 영향받는 Phase: 1~6 전체

## 테스트 DB
- 날짜: 2026-09-11
- 결정: 단위 테스트는 SQLite + aiosqlite (in-memory), 통합 테스트는 실제 PostgreSQL
- 이유: CI에서 PostgreSQL 컨테이너 없이도 ORM 로직 검증 가능. target_ids는 SQLAlchemy JSON 타입으로 두 DB 모두 호환.
- 영향받는 Phase: 1, 6
