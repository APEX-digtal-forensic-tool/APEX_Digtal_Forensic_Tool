# 2026-10-19 상세 검토 후속 수정

`APEX_Backend_Frontend_Detailed_Review_2026-10-19`(PR #26 병합 커밋 `3937c1b` 기준)에서
새로 재현된 항목의 수정 내용이다. 과거 문서의 단계별 테스트 수치(694/735/770 등)는 당시 기록으로
남겨 두며, 이 문서의 내용이 현재 상태다.

## 수정 항목

| ID | 문제 | 수정 | 검사 |
| --- | --- | --- | --- |
| FE-01 | ADS 버튼이 실제 DTO에 없는 최상위 `provider_id`를 읽어 정상 NTFS 파일에서도 비활성 | `ForensicTools`가 공개 DTO의 `filesystem_provider.id`로 판정 | `ForensicTools.test.tsx`: 실제 DTO에서 활성, 폴더·삭제 파일·논리 폴더 증거에서 비활성 |
| QA-01 | 화면 테스트가 가짜 `provider_id`를 넣어 FE-01을 가림 | `frontend/src/__fixtures__/ntfs-file.json`을 `tools/generate_desktop_fixtures.py`가 실제 Core 직렬화(`streams.img`)로 생성, 가짜 필드 제거 | `tests/desktop/test_forensic_operations.py`가 실제 HTTP `files.list` DTO와 fixture의 키 구조·`filesystem_provider`를 비교하고 최상위 `provider_id`가 없음을 확인 (CI 포함) |
| FE-02 | 파일 트리(`FILE_SYSTEM`)의 `FileViewer`에 영상 프레임 진입점이 없음 | `FileViewer`가 mp4/m4v/mov/3gp/3g2/avi/mkv/webm 또는 `MEDIA_VIDEO` 선택 시 `VideoInspector`를 표시하고 선택별 `key`로 이전 프레임을 폐기 | `workbench/FileViewer.test.tsx`: 버튼 표시, `media.video`에 같은 case/resource ID 전달, 파일 변경 시 이전 프레임 숨김, 비영상·폴더·이미지에는 미표시 |
| BE-01 | `machine-settings.json` 손상 시 `machine.capabilities`가 422, UI·Electron 저장 경로까지 막혀 앱 안에서 복구 불가 | 아래 "분석기 설정 복구" 참고 | `tests/desktop/test_machine_settings_recovery.py`, `MachineSettings.test.tsx` |
| DOC-01 | 현재 상태와 다른 안내 | `REQUIREMENTS_TRACEABILITY.md` CORE-014, `ARCHITECTURE.md` 컨테이너·카빙, `FORENSIC_ENGINE.md`·`IMPLEMENTATION_ROADMAP.md` 카빙, 데스크톱 README 화면 표 갱신 | — |

QA-02(모든 새 응답의 런타임 Schema 검증)와 INT-01(refresh·서버 logout 연동), AI-01(실제 제공자 검증)은
이번 범위에서 변경하지 않았다.

## 분석기 설정 복구 (BE-01)

- `machine.capabilities`는 저장된 설정을 읽지 못해도 HTTP 200으로 응답한다. 이때 `settings`는 기본값,
  `settings_error`는 `{code: "MACHINE_SETTINGS_INVALID", reason, source, fields, resettable}`이고
  `ocr`/`stt`는 `null`이다. 저장된 선택을 알 수 없으므로 기본값으로 준비 상태를 평가하지 않는다.
- `reason`: `JSON_SYNTAX`, `ENCODING`(UTF-8 아님, BOM은 허용), `NOT_OBJECT`, `INVALID_FIELDS`(`fields`에 필드명), `UNREADABLE`.
- `source=ENVIRONMENT`(`APEX_DESKTOP_MACHINE_CONFIG` 관리)는 `resettable=false`이며 UI 복구 대신 실행 환경 수정을 안내한다.
- 설정이 손상된 동안 `machine.run`(OCR/STT)은 기본값으로 조용히 실행하지 않고 `MACHINE_SETTINGS_INVALID`로 실패한다.
- 새 작업 `machine.reset`(`Empty`, 동기 응답): 기존 설정 파일을 `machine-settings.invalid-<UTC>.json`
  (정상 파일이었다면 `machine-settings.previous-<UTC>.json`)로 옮겨 보존한 뒤 기본값으로 돌아간다.
  응답의 `preserved_settings_file`에 보존한 파일 이름이 있다. 관리 설정이면 `MACHINE_SETTINGS_MANAGED`(409).
- `machine.configure`로 손상 설정을 덮어쓸 때도 먼저 손상 파일을 같은 방식으로 보존한다.
- 사건 DB·원본·파생 증거·사용자 모델 파일은 건드리지 않는다.

로컬 작업 allowlist는 **46개**(Electron `operations`와 Python `MODELS` 일치,
`test_electron_and_local_api_operation_contract`)다.

## 현재 화면 진입점

| 기능 | 파일 트리 (`FILE_SYSTEM` → FileViewer) | 아티팩트·미디어 검사기 |
| --- | --- | --- |
| 이미지 채널·비트 분석 | `ImageInspector` | `ImageInspector` (`MEDIA_IMAGE`) |
| 영상 프레임 | `VideoInspector` | `VideoInspector` (`MEDIA_VIDEO`) |
| 복구·ADS·OCR/STT·카빙 | `ForensicTools` (파일 트리 검사기가 열려 있을 때) | — |
| AI 구조/본문 분석 | 전역 AI 패널 `AiAssistant`(현재 선택 자료 기준) | 동일 |
| 분석기 설정·복구 | 설정 → 로컬 OCR·음성 인식 설정 | — |

설치본에서 사람이 직접 확인해야 할 항목(NTFS 이미지 ADS 조회·읽기·내보내기, 파일 트리 영상 프레임,
설정 손상 복구 후 기존 사건 유지)과 새 커밋의 Windows CI 결과는 이 문서로 대신하지 않는다.
