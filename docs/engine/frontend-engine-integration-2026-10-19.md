# 프런트엔드–엔진 연결 점검 및 구현

> **후속 구현 완료:** 이 문서는 초기 수정 시점 기록입니다. 여기서 미완성으로 표시했던 E01/VHD/VHDX·복구 UI·ADS·카빙·OCR/STT 실행·AI 본문 연결은 [후속 구현 문서](completed-connections-2026-10-19.md)를 확인하세요.

대상: `fix/engine-audit-2026-10`, PR #26. 기존 인증을 유지하며 로그인 없이 로컬 분석을 수행한다. main 병합은 담당자가 진행한다.

## 실제 누락과 수정

| 화면 기능 | 기존 문제 | 구현 |
| --- | --- | --- |
| 이미지 내부 파일의 텍스트·Hex | 파일시스템 목록은 있었지만 파일 본문 reader가 없었다. | 인덱싱된 볼륨·inode를 사용해 TSK의 논리 파일 스트림을 읽는다. 파일 상대 오프셋, 크기, 범위 SHA-256과 실제 바이트를 반환한다. |
| 이미지 내부 사진 미리보기·채널·비트·추출 | 호스트 디스크의 일반 파일 경로만 열 수 있었다. | 같은 내용 reader로 원본 이미지 바이트를 읽어 기존 픽셀 분석기에 전달한다. |
| 이미지 내부 브라우저·미디어·Windows·통신 아티팩트 | 분석기는 실제 호스트 경로를 요구했다. | 분석 대상만 임시 파일로 만들고 기존 분석기를 실행한다. SQLite WAL/SHM/journal 보조 파일을 함께 복사하고 종료 시 제거한다. 원본 증거는 쓰지 않는다. |
| 파일 선택의 인용·보고서 근거 | 엔진 파일 projection이 인용을 빈 배열로 반환했다. | 인덱스 revision과 파일 식별자가 포함된 안정적인 출처 인용을 생성한다. citation Schema와 MCP AI 요청 검증도 통과하도록 canonical raw locator를 사용한다. |
| AI 도우미의 현재 선택 분석 요청 | 버튼이 항상 비활성화되어 있었다. | Electron allowlist → 로컬 API → 선택 snapshot → AI request → 정책 평가 → 제공자 → 결과 검증·저장 → 화면 표시를 연결했다. |
| 보고서 다음 목록 | 첫 100개 이후의 cursor를 사용하지 않았다. | 더 보기 버튼으로 다음 페이지를 불러온다. 보고서를 선택할 때 이미 불러온 목록을 유지한다. |
| 파일 전환 후 범위 읽기 | 이전 파일의 오프셋을 새 파일에 적용했다. | 선택 파일이 바뀌면 첫 범위에서 시작하며 이전 응답을 표시하지 않는다. |
| 텍스트와 바이너리 구분 | 실제 NUL 대신 문자 `\\x00`을 검사했다. | 실제 NUL을 검사하고 BOM이 있는 UTF-16 텍스트도 해석한다. |

## 화면 전체 대조

`frontend/src/App.tsx`, `panels.tsx`, `ImageInspector.tsx`, `workbench/*`, `gateway.ts`, Electron allowlist, `apex_desktop.operations.MODELS`를 대조했다.

| 화면·동작 | 로컬 API / 엔진 | 상태 |
| --- | --- | --- |
| 사건 생성·목록, 증거 등록·조회 | `cases.*`, `evidence.*` | 기존 연결 유지 |
| 파일 트리·목록·검색 필터 | `files.roots`, `files.list` / 파일시스템 인덱스 | 기존 연결 유지 |
| 파일 본문·메타데이터·인용 | `view`, `raw.read` | 이미지 본문과 인용 연결 추가 |
| 이미지 픽셀 분석 | `media.inspect` | 이미지 증거 내부 파일 연결 추가 |
| 레지스트리·이벤트·프리패치·브라우저·미디어·통신 목록/분석 | `artifacts.list`, `analysis.start(ARTIFACTS)` | 이미지 내부 파일을 기존 분석기로 전달하도록 확장 |
| 검색·검색 인덱스 | `search.query`, `analysis.start(SEARCH)` | 기존 메타데이터·분석 결과 검색 연결 유지 |
| 타임라인·생성 | `timeline.list`, `analysis.start(TIMELINE)` | 기존 연결 유지 |
| 해시 계산·검증 | `analysis.start(HASH/VERIFY)` | 기존 연결 유지 |
| 자동 추출 후보 조회·검토 | `candidates.list/review` | 기존 연결 유지. OCR/STT 실행 버튼을 새로 추가한 작업은 아님 |
| 보관 이력·정정·검증 | `custody.*` | 기존 연결 유지 |
| 보고서 작성·버전·검토·승인·HTML/PDF 출력 | `reports.*` | 기존 연결 유지, 목록 페이지 이동 추가 |
| AI 정책·감사 | `policy.*` | 기존 연결 유지, 실제 AI 요청 경로에 정책 검사 연결 |
| AI 요청 | `ai.analyze` | 신규 연결 |
| 작업 목록·취소, Context 동기화 | `tasks.*`, `context.*` | 기존 연결 유지 |
| 계정 로그인·로그아웃 | 기존 Electron 계정 경로와 인증 백엔드 | 기존 연결 유지, 로컬 분석의 필수 조건으로 변경하지 않음 |

## 본문 읽기 범위

- 현재 파일시스템 provider가 지원하는 RAW/DD/IMG의 **할당된 일반 파일**을 대상으로 한다. 삭제 파일의 원본 읽기와 삭제 파일 복구는 별도 기능이다.
- 단순히 물리 extent를 이어 붙이지 않는다. NTFS resident/compressed/sparse 처리 등을 파일시스템 라이브러리에 맡기는 `read_random`을 사용한다. NTFS의 모든 실제 변형을 검증했다는 뜻은 아니다.
- 한 번의 raw 범위는 최대 1 MiB이다. Hex/text projection 미리보기는 기존 4 KiB 계약을 유지한다.
- 사진은 기존 64 MiB/2,500만 픽셀 제한을 유지한다. 경로 기반 분석기에 제공하는 임시 파일은 대상과 보조 파일을 합쳐 512 MiB까지이며 큰 파일을 조용히 잘라 분석하지 않는다.
- E01/VHD/VHDX의 파일시스템 provider, ADS 전용 선택 화면, 카빙, 새로운 OCR/STT 모델이나 원격 AI 서버를 이번 변경으로 완성했다고 주장하지 않는다. 기존 UI에 없는 새 기능/새 형식 전체를 만드는 작업과는 범위가 다르다.

## AI 연결

`APEX_DESKTOP_AI_CONFIG` 환경변수에 기존 `AiProviderRuntimeConfig` 형식의 JSON을 설정한다. API 키는 `api_key_env`가 지칭하는 별도 환경변수로 제공한다. 렌더러에서 키나 접속 주소를 전달하지 않는다.

```json
{
  "provider_id": "configured-provider",
  "base_url": "https://YOUR-PROVIDER/v1",
  "model_id": "YOUR-MODEL",
  "api_key_env": "APEX_AI_API_KEY"
}
```

- 설정이 없으면 선택 snapshot과 요청을 저장하고 연결 필요 상태를 반환한다. 로컬 분석은 계속 사용할 수 있다.
- 전송 대상은 보수적으로 EXTERNAL로 평가한다. localhost 프록시가 외부 모델에 전달할 가능성을 임의로 LOCAL로 분류하지 않는다.
- 현재 데스크톱 경로는 **기존 safe projection의 구조 필드만** 전송한다. 파일명·경로·본문·인용 원문은 전송하지 않는다. 알 수 없는 비밀정보가 포함될 수 있는 원본은 SECRET으로 분류하며 안전한 구조 정보로 바꾸어도 등급을 낮추지 않는다.
- 최종 정책 ALLOW가 있어야 호출한다. 기본 정책을 자동으로 느슨하게 변경하지 않는다. 해당 등급의 외부 사용이 허용되지 않으면 사유가 화면에 표시된다.
- AI 결과는 구조 정보에 대한 요약이고 원본 내용을 해석한 관찰 사실이 아니다. 출처 인용은 로컬에서 붙이는 선택 자료의 provenance이며 이 제한을 화면·결과 경고에 표시한다.
- 실제 외부 서비스에 자료를 보내어 테스트하지 않았다. HTTP 경계의 대체 응답을 사용하여 정책 거부 시 0회 호출, 허용 시 정확한 projection만 전송, 결과 검증·저장을 검사했다.

## PR #26의 기존 CI 실패

기존 HEAD `af747d7`의 Desktop workflow `39178601441`에서 Windows-x64와 macOS-arm64는 성공했고 macOS-x64만 실패했다. 실패 위치는 `async-state.test.tsx`의 파일 목록 화면을 기다리는 테스트였다. Intel runner의 cold render에서 testing-library 기본 1초 안에 table이 생성되지 않았다.

준비 helper가 실제 목록 table이 생길 때까지 상태를 기다리도록 수정하고, 해당 비동기 테스트 파일에 실행 상한을 명시했다. 고정 sleep, 실패 무시, CI 제외 또는 테스트 삭제는 사용하지 않았다. 지연 응답과 다른 파일의 응답이 섞이지 않는 기존 검증을 유지한다.

## 회귀 검증

실제 FAT12 이미지의 한글 긴 이름, 분할된 클러스터, 임의 오프셋, 빈 파일, EOF, 원본 해시 보존, 사진 preview/채널/비트 추출, 아티팩트 분석과 로컬 HTTP API를 검증한다. EXT4 fixture에서는 희소 파일의 0 구간과 브라우저 History SQLite의 실제 URL 추출을 검사한다. 다른 사건 참조·위조 locator·취소·임시 파일 정리도 검사한다.

최종 실행 수치와 CI 상태는 PR 설명에 기록한다. Windows 설치본으로 실제 수사 이미지를 수동 검증하거나 TB급 성능을 측정한 결과는 아니다.
