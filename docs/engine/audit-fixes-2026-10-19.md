# 엔진 감사 결함 수정 — 2026-10-19

초기 기준: `ea32b99351ec088204674290b25acc081d958078`.
최종 통합 기준: `106dd424dd1be384803e57e1e55927bd3400919e` (`main`, 백엔드 수정 PR #25 포함).
브랜치: `fix/engine-audit-2026-10`.

2026-09-30 감사 보고서의 엔진 항목 A01, A02, A03, A06, A07, A08, A09, A13을 처리한다. 작업 중 A08이 백엔드 수정 PR #25로 main에 반영되어 해당 구현과 API 계약을 그대로 유지하고 추가 회귀 테스트로 확인했다. 최종 PR의 독립적인 엔진 수정은 나머지 7건이며, 8건 전체를 검증한다. 인증 백엔드와 프런트엔드의 별도 결함을 새로 수정하는 PR은 아니다.

## 수정 내용

| ID | 문제 | 수정 후 동작 |
|---|---|---|
| A01 | 파생 출력으로 원본 증거 덮어쓰기 | range/recovery/slack의 공통 출력 경계에서 현재 DB에 등록된 모든 사건의 원본·EWF 세그먼트·디렉터리 증거와 충돌을 검사한다. 심볼릭 링크 및 원본 파일의 하드링크도 검사한다. 디렉터리 생성 전과 최종 파일 게시 전에 확인하며, 일반 파생 파일의 명시적 덮어쓰기는 유지한다. |
| A02 | 숨김 파일의 점 접두사 제거 | 경로 구성요소를 정규화하되 `.secret`, `.config`, `...name` 같은 실제 파일명은 보존한다. 절대 경로와 상위 디렉터리 탈출은 계속 거부한다. |
| A03 | 삭제 파일 복구의 누락 구간 압축 및 복구량 오보고 | 논리 오프셋과 실제 복구량을 분리한다. 누락 구간을 0으로 채우고 위치와 길이를 기록하며, 후속 바이트의 위치를 보존한다. 중첩·음수·범위 밖 데이터 런을 거부하고 큰 런은 제한된 크기로 읽는다. |
| A06 | 이미지 노드 MIME 값의 Schema 불일치 | provider가 `UNKNOWN`/`LOW`를 출력한다. 기존 pytsk 노드의 `NONE`/`EXTENSION`은 DB 조회 시 호환 변환하므로 재인덱싱 없이 기존 사건도 조회할 수 있다. |
| A07 | 디렉터리·범위 조회마다 전체 이미지 해시 | 읽기 전용 열기와 전체 지문 계산을 분리한다. 등록 및 명시적인 `source_fingerprint` 요청에서는 매번 전체 SHA-256을 계산하고, 해시 도중 관찰된 소스 변경은 거부한다. 디렉터리/범위 조회에서는 전체 해시가 발생하지 않는다. |
| A08 | 다른 사건·증거의 보관 이력에 정정 연결 | PR #25의 공통 서비스 소속 검증을 유지한다. `verify_chain`은 해시 무결성을, `find_semantic_violations`는 잘못된 사건·증거 참조를 검사한다. `custody.verify` 응답의 `verified`와 `violations`를 함께 해석해야 한다. 이력을 삭제하거나 재작성하지 않는다. |
| A09 | 범위 밖 타임스탬프로 파싱 중단 | 시간 변환 예외를 처리하고 원시 값, 해석 불가 경고 및 노드의 partial 상태를 보존한다. 같은 디렉터리의 정상 노드는 계속 처리한다. |
| A13 | 이미지 내부 raw-read 연결 누락 | 최초 수정에서는 미지원 action을 차단했다. 후속 구현에서 RAW/DD/IMG 내부의 할당된 일반 파일을 TSK 논리 스트림으로 읽고 text/Hex 및 미디어·아티팩트 분석에 연결했다. 디렉터리·삭제 파일은 일반 본문 읽기로 표시하지 않는다. 자세한 내용은 `frontend-engine-integration-2026-10-19.md` 참조. |

## 복구 결과 계약

- `recovered_bytes`: 증거에서 실제 읽은 바이트 수. 합성한 0은 포함하지 않는다.
- `logical_size`: 원본 노드의 논리 크기.
- `output_size`: 생성한 파생 파일 크기. 성공 시 `logical_size`와 같다.
- `missing_ranges`: 읽을 수 없거나 데이터 런이 없는 구간의 논리 오프셋과 길이.
- `missing_range_policy`: `ZERO_FILL`. 누락 구간의 0은 원본에서 관찰한 데이터가 아니다.
- `partial`: 누락 구간이 있으면 true.
- `sha256`: 합성 구간을 포함한 실제 출력 파일의 해시.

읽은 데이터가 전혀 없거나 처리 중 오류가 발생하면 결과 파일을 게시하지 않고 임시 파일을 제거한다.

## 최초 감사 수정의 검증

아래 수치는 후속 기능 연결 전 기준이다. 이후 구현과 최종 수치는 `frontend-engine-integration-2026-10-19.md` 및 PR 설명을 참고한다.

- 새 회귀 테스트: `tests/unit/test_engine_audit_regressions.py`, 43개 통과.
- 최종 통합 기준의 전체 Python 테스트: **694 passed, 14 skipped**. Linux/Python 3.12에서 실행했다.
- 충돌 정리 후 엔진·보관 이력·로컬 API 관련 테스트: **66 passed**.
- 초기 기준의 전체 Python 테스트: **640 passed, 14 skipped**.
- 마지막 지문 계산 조정 후 회귀 테스트와 evidence reader 테스트 재실행: **50 passed, 3 skipped**.
- Ruff 전체 검사 통과, mypy strict: 169개 소스 파일 통과, `git diff --check` 통과.
- 설계/Schema 검증: 기본 1,938개 검사, 설계 4,404개 검사, 76개 Schema의 AJV Draft 2020-12 strict 검증 통과.
- 실제 FAT12 이미지 인덱싱 결과 4개 노드를 기존 프런트의 생성된 `validate_file` AJV 검증기에 입력하여 4개 모두 통과.
- 최종 통합 상태의 기존 보안 분류 기준 게이트 통과. 새 미분류 Medium/High 지적 없음.
- 보안 검사 기준표의 기존 SQL 지적 31건은 소스 삽입으로 이동한 행 번호만 갱신했다. 각 위치의 코드가 기존과 동일한 것을 비교했으며 분류와 근거는 변경하지 않았다.

실행 예:

```bash
uv sync --locked --extra desktop --extra backend --extra dev --extra browser-media --extra report-renderer --extra windows-artifacts
uv run --no-sync pytest -q tests/unit/test_engine_audit_regressions.py
uv run --no-sync pytest -q
uv run --no-sync ruff check .
uv run --no-sync mypy --strict src
```

검증 환경에서는 로컬 서버 테스트가 외부 프록시를 사용하지 않도록 프록시 환경변수를 제외했다. 전체 테스트의 건너뛴 항목은 해당 실행 환경의 선택 기능·호스트 조건에 해당한다.

## 적용 범위와 남은 검증

- Windows 설치본 실행과 TB급 실제 이미지 성능은 검증하지 않았다. Windows CI 및 실제 증거의 복사본으로 확인해야 한다.
- 후속 변경으로 RAW/DD/IMG 내부의 할당된 일반 파일에 대한 논리 바이트 읽기를 구현했다. 전체 이미지 물리 범위 읽기와는 별도이다.
- ADS·압축·sparse NTFS 데이터 런의 완전한 지원을 추가한 변경이 아니다. 이번 복구 수정은 기존 provider가 제공한 데이터 런의 오프셋·누락 구간·출력량을 정확히 다루도록 한다.
- 원본 보호는 현재 로컬 DB에 등록된 증거를 기준으로 한다. 별도 DB에만 등록된 증거와 외부 프로세스의 악의적인 동시 파일시스템 변경까지 보호하는 OS 쓰기 방지 장치를 대신하지 않는다.
