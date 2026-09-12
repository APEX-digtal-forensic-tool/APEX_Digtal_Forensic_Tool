# 개발 규칙 및 세션 진행 프로세스

이 문서는 Claude Code(또는 다른 세션)가 `docs/backend/` 마스터 플랜을 실행할 때
반드시 지켜야 하는 규칙이다. 코드 스타일 규칙과, 세션이 끊겨도 진행상황을
잃어버리지 않기 위한 프로세스 규칙 두 가지를 다룬다.

## 1. 시작하기 전에

1. `PROGRESS_LOG.md`를 먼저 읽는다. "현재 상태"와 "다음 작업" 섹션이
   지금 뭘 해야 하는지 알려준다.
2. 해당 Phase의 `specs/0N_*.md`를 읽는다. 스펙에 없는 걸 임의로 구현하지 않는다.
3. 스펙에 "결정 필요"라고 표시된 항목이 있으면, 멋대로 하나 골라서 진행하지
   말고 `PROGRESS_LOG.md`의 "결정 대기" 섹션에 질문을 남기고 그 Phase 작업을
   중단한다. 다음 사람이 볼 수 있게.

## 2. 코드 규칙

- Core Forensic Engine(`src/apex_forensic`)의 경계 원칙을 그대로 따른다:
  Core 로직을 재구현하지 않는다. 백엔드도 Core가 필요하면 반드시
  `EngineInterfaceService`(`invoke_read`/`invoke_mutation`)를 거쳐서만 접근한다.
  SQLite나 analyzer를 직접 호출하지 않는다.
- `src/apex_mcp`에 이미 정의된 Protocol(`FrontendSecurityProvider`,
  `ConfirmationProvider`, MCP SDK의 `TokenVerifier`)의 메서드 시그니처는
  절대 수정하지 않는다. 새 구현 클래스를 추가하는 것만 허용된다.
- 기존 `InMemoryFrontendSecurityProvider`, `StaticBearerTokenVerifier`,
  `InMemoryConfirmationProvider`는 삭제하지 않는다. 로컬 개발/테스트 fixture로
  계속 남겨둔다. 새 구현은 별도 클래스(예: `JwtTokenVerifier`,
  `PersistentFrontendSecurityProvider`)로 추가하고, 배포 설정에서만 교체한다.
- 새 백엔드 패키지는 `src/apex_backend/` 밑에 만든다 (기존 `src/apex_forensic`,
  `src/apex_mcp`와 같은 레벨). FastAPI 앱, DB 모델, 인증 로직 전부 여기.
- 기존 코드 스타일을 따른다: `from __future__ import annotations`,
  `@dataclass(frozen=True, slots=True)` 선호, Protocol 기반 설계, docstring 필수.
- 커밋마다 `ruff check`, `mypy` 통과 확인. 안 되면 커밋하지 않는다.
- 새로 만드는 기능마다 대응하는 pytest를 같은 커밋 또는 바로 다음 커밋에 추가한다.
  테스트 없는 구현은 미완료로 취급한다.
- 커밋은 스펙 파일 하나(Phase 하나) 단위보다 잘게, 논리적으로 나눈다.
  예: "DB 모델 추가", "로그인 API 추가", "JwtTokenVerifier 구현"을 각각 커밋.

## 3. 세션 핸드오프 규칙 (제일 중요)

Claude Code 세션은 중간에 끊기고 새 세션이 이어받을 수 있다. 새 세션은 이전
대화를 기억 못 한다. 그래서 파일에 기록을 남기는 것 외엔 연속성을 유지할
방법이 없다. 아래 규칙은 예외 없이 지킨다.

- **세션을 끝내기 직전에는 항상 `PROGRESS_LOG.md`를 갱신한다.** 코드를 아무리
  조금 고쳤어도, 작업을 끝까지 못 끝냈어도 예외 없음.
- 갱신할 때는 반드시 두 가지를 채운다:
  - **마지막 진행 상황**: 지금까지 뭘 했는지, 어느 파일을 건드렸는지, 테스트가
    통과하는지 여부까지 구체적으로. "session 관련 작업함" 같은 뭉뚱그린 문장 금지.
  - **다음 작업**: 바로 다음에 뭘 해야 하는지 명령형으로. 다음 세션이 이 줄만
    읽고 바로 이어서 작업할 수 있을 정도로 구체적으로 쓴다.
- 기존 히스토리는 절대 지우지 않는다. "히스토리" 섹션에 새 항목을 맨 아래
  append만 한다 (날짜별로).
- 진행 중에 계획을 바꿨다면(예: 옵션 A에서 옵션 B로 변경) 그 이유도 히스토리에
  남긴다. 나중에 왜 그렇게 했는지 추적 가능해야 한다.

## 4. 막혔을 때

- 네트워크/패키지 설치가 막히는 등 환경 문제로 못 끝낸 부분은 "미완료"로
  솔직하게 남기고, 왜 못 했는지 `PROGRESS_LOG.md`에 적는다. 억지로 우회하거나
  가짜로 통과시키지 않는다.
- 스펙에 없는 애매한 부분을 발견하면 임의로 결정하지 말고 `PROGRESS_LOG.md`의
  "결정 대기"에 질문으로 남기고 그 부분만 스킵, 나머지는 계속 진행한다.

## 5. Phase 완료 시 규칙

Phase 하나(스펙 파일 하나)의 구현이 끝나면:

1. 해당 스펙 파일(`specs/0N_*.md`) 맨 위 상태를 `완료`로 바꾼다.
2. `docs/backend/<도메인명>/README.md`를 새로 만든다. 도메인명은 스펙 제목에서
   따온다 (예: Phase 3 완료 → `docs/backend/mcp-token-verifier/README.md`).
   내용은 다음을 포함한다:
   - 무엇을 구현했는지 (요약)
   - 만든/수정한 파일 목록
   - 어떤 설계 결정을 내렸는지와 이유
   - 테스트 현황 (몇 개 추가, 다 통과하는지)
   - 남은 제약/알려진 한계
3. `PROGRESS_LOG.md`의 "현재 상태"를 다음 Phase로 넘기고 히스토리에 완료
   사실을 기록한다.

이 세 가지를 다 하기 전까지는 그 Phase를 완료로 치지 않는다.

## 6. PR 규칙 (Phase 완료 후 필수)

Phase 하나가 완료되면 (위 5절 세 가지 끝낸 뒤) GitHub PR을 만든다.

- base branch: `main`
- PR 제목: `feat(backend): Phase N — <스펙 제목 한줄 요약>`
- 머지는 사람이 한다. Claude Code는 PR 생성까지만.
- 같은 Phase 내 여러 커밋은 하나의 PR로 묶는다.
- PR 설명에는 완료 조건 체크리스트, 추가된 테스트 수, ruff/mypy 결과를 포함한다.
