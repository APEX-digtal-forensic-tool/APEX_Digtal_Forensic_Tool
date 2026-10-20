# 머지 후 전체 재점검 수정 (2026-10-20)

`APEX_PostMerge_Full_Audit_2026-10-20`(main `64b739d`, PR #28 머지 기준)에서 재현된 코드 결함 6건과
문서 불일치 1건의 수정 내용이다. ID는 해당 점검 문서 기준이며 이전 보고서의 같은 번호와 다르다.

## 수정 항목

| ID | 수정 | 회귀 검사 |
| --- | --- | --- |
| ENG-01 | 증거 등록 시 이미지 파일 기준값(`metadata.source_identity`: 크기·수정 시각·파일 ID, E01은 모든 세그먼트)을 해시 계산 전후로 확인해 저장한다. 모든 이미지 읽기의 공통 진입점 `adapters/evidence/factory.evidence_reader()`가 현재 값과 비교하고 다르면 `RAW_SOURCE_CHANGED`로 거부한다. 파일 내용 읽기·미리보기·ADS·복구·카빙·OCR/STT·AI 발췌·raw 범위 읽기가 모두 이 경로를 쓴다. 등록 중 변경은 `ValidationError`로 거부한다. | `tests/unit/test_image_source_identity.py` (Desktop CI 포함) |
| INT-01 | `runtime`이 잘못된 `APEX_DESKTOP_AI_CONFIG`(문법·필드 누락·필드 타입)를 `ai.configuration_error = {code: "AI_CONFIGURATION_INVALID"}`로 보고하고 200을 유지한다. AI 요청 자체는 계속 거부한다. React 초기화는 `runtime`과 `cases.list`를 독립 처리해 하나가 실패해도 사건 목록을 표시하고, AI 패널에 설정 오류를 안내한다. | `tests/desktop/test_ai_config_isolation.py`, `async-state.test.tsx` |
| BE-01 | 존재하지만 비어 있거나 BOM/공백만 있는 `machine-settings.json`을 `reason: "EMPTY"`로 진단한다. 파일이 없는 첫 실행은 계속 정상 기본값이다. | `test_machine_settings_recovery.py` |
| BE-02 | 작업 완료 후 `tasks.json` 저장에 실패하면 작업 결과를 유지한 채 `receipt_error = {code: "TASK_RECEIPT_NOT_SAVED", retryable: true}`를 표시한다. 이후 `tasks.list`가 저장을 다시 시도하고 성공하면 표시를 지운다. 작업 패널에 안내가 표시된다. | `tests/desktop/test_task_receipt_failure.py` |
| AUTH-01 | JWKS 응답의 최상위 객체·`keys` 배열·각 키의 `kid`를 검증한다. 문서 구조가 잘못되면 네트워크 실패와 같이 기존 캐시를 유지하고, 잘못된 개별 키는 건너뛴다. 검증 실패는 예외 대신 `None`이다. | `tests/backend/test_jwt_verifier.py` |
| BE-03 | 설정 저장이 요청별 임시 파일(`mkstemp`)을 쓰고 백업·교체·초기화를 잠금으로 직렬화한다. 동시 저장은 마지막으로 완료된 저장을 채택한다. | `test_concurrent_settings_saves_must_not_share_temporary_file` |
| DOC-01 | `MODULE_RESPONSIBILITIES.md`가 저장소의 인증·데스크톱·MCP transport를 현재 구성대로 기술한다. `GUIDE_COMPLIANCE_REVIEW.md`에 과거 기록 안내를 붙였다. | — |

## ENG-01 검증 강도

기준값은 파일시스템 식별 정보다. 일반 파일 API를 통한 수정·잘림·교체는 거부한다. 수정 시각까지 원래
값으로 되돌리는 변조는 이 검사로 잡지 못하며, 전체 SHA-256을 다시 계산하는 `custody.verify`가 무결성
판단 근거다. 매 읽기마다 대형 이미지를 해싱하지 않는다. 이 변경 이전에 등록된 증거에는 기준값이 없어
읽기 중 변경 검사만 적용되므로, 변경 감지가 필요하면 증거를 다시 등록한다.

## 아직 연결되지 않은 기능 (변경 없음)

점검 문서 5장의 항목은 이번 수정에 포함하지 않았다. 엔진에는 구현되어 있지만 데스크톱 API·화면에는
없다: 키워드 세트 관리, SELECTED_SCOPE/CUSTOM 분석, 중단 작업 재개, 검색 이력 화면·재실행, 고급 검색
필터, 타임라인 시간 범위·전용 필터, 보고서 버전 비교, 여러 section 편집, 일반 보관 이력 이벤트 입력.
분석가 주석·태그는 엔진 저장 계약부터 없다(AUD-001 CONTRACT ONLY).
