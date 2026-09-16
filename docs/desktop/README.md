# Windows / macOS 앱 및 로컬 API

## 범위와 기준

Windows x64와 macOS Apple Silicon/Intel을 대상으로 하는 Electron + React + TypeScript 앱입니다. 로컬 FastAPI를 통해 기존 Core를 재사용하며, 기존 계정 인증과 비로그인 로컬 분석을 지원합니다.

기준 소스는 `main`의 `d27b19089005becaf80a5ee63ba0e4557130566a`입니다. 첨부된 `APEX_FRONTEND_IMPLEMENTATION_HANDOFF_v2` 및 `APEX_FRONTEND_AI_DATA_GOVERNANCE`, 서비스 아키텍처 이미지, [디자인 레퍼런스](https://apex-forensic-workbench.choieunsu2009.chatgpt.site/#/file-system)를 반영했습니다. 문서 작성 이후 추가된 `apex_backend` 인증과 기존 Core/MCP 구현은 유지합니다.

플랫폼별 빌드와 실행 검증 범위는 아래 검증 절에 기록합니다. 원격 LLM 서버, 계정 서버 재개발, 다운로드 사이트, 자동 업데이트와 서명 배포는 포함하지 않습니다. 모든 하위 기능에 대한 handoff 인수 테스트 완료를 의미하지 않습니다.

## 개발 실행

Windows x64 또는 macOS, Python 3.12, Node.js 24, uv가 필요합니다. 아래 명령은 Windows PowerShell과 macOS 터미널에서 공통으로 실행합니다. Mac에서는 Python과 Node.js의 아키텍처를 일치시키세요(Apple Silicon: arm64, Intel: x64).

```powershell
uv python install 3.12
uv sync --locked --python 3.12 --extra desktop --extra report-renderer
cd frontend
npm ci
npm run dev
```

Electron이 Windows에서는 `.venv/Scripts/python.exe`, macOS에서는 `.venv/bin/python`을 찾아 로컬 API를 자동 실행합니다. 다른 Python 환경을 써야 하는 경우에만 `APEX_PYTHON`을 해당 실행 파일의 절대 경로로 설정합니다. 개발 서버는 `127.0.0.1:5173`을 사용합니다.

앱에서 사건 만들기 → 증거 파일/폴더 선택 → 파일 인덱싱 → 파일 탐색 순으로 시작합니다. 검색·타임라인·아티팩트는 각 화면에서 해당 작업을 실행한 후 조회합니다. 이미 처리한 결과가 있으면 재시작 후에도 Core 데이터베이스에서 조회할 수 있습니다.

데이터는 Electron `app.getPath('userData')` 아래 `local/apex.db`와 같은 폴더의 작업 이력에 저장됩니다. 내보낸 보고서는 `local/exports/<버전 ID>/`에서 관리합니다. 원본 증거는 Core의 읽기 전용 경로로 접근하며, 앱 데이터 디렉터리 자체·상위·하위의 파일과 폴더는 증거로 등록할 수 없습니다. 내보내기 출력과 증거 영역이 겹치는 것도 차단합니다.

## 포함된 화면과 실제 연결

| 화면 | 연결된 동작 |
|---|---|
| 사건·증거 | 사건 생성/선택, 네이티브 증거 선택, 비동기 등록, 해시 계산·재검증 |
| 파일 시스템 | 지연 로딩 폴더 트리, 커서 기반 목록, 현재 페이지 정렬, Simple/Detailed/Raw 조회 |
| 아티팩트·통신·미디어 | 기존 아티팩트 서비스 조회와 분석 작업, 실제 지원 상태 표시 |
| 검색·타임라인 | Core 인덱싱/조회, 결과 출처 및 부분·갱신 필요 상태 표시 |
| 추출 후보 | 기계 추출 후보와 분석자 채택·거부·수정 검토 |
| 보관 이력 | 이벤트 조회, 원본을 보존하는 정정 이벤트 추가 |
| 보고서 | 분석자 초안, 새 버전, 인용 근거, 검토·승인·철회, Core HTML/PDF 내보내기 |
| 설정 | 실제 런타임 지원 상태, 기존 인증 로그인, 사건별 AI 데이터 정책과 감사 이력 |
| 작업 패널 | 진행률, 취소 가능 여부, 오류·작업 결과 확인 |
| AI 패널 | 현재 컨텍스트와 미연결 상태 표시; 원격 실행 버튼 비활성 |

파일 목록 등은 페이지당 최대 100개, Raw 읽기는 최대 1 MiB, 검색 문자열은 4096자(메타데이터 정규식은 512자)입니다. 보고서는 검토·승인 전 내보낼 수 없고, 승인 시 기존 보관 이력 스냅샷을 연결합니다. 동일 파일 이름을 자동 덮어쓰지 않습니다.

## 계정과 AI 데이터 처리

설정에서 사용자가 지정한 기존 인증 서버의 origin, 테넌트 ID, 이메일, 비밀번호를 입력합니다. `src/apex_backend/auth`의 `POST /auth/login` 계약을 사용합니다. 서버 주소나 테넌트를 임의로 하드코딩하지 않았습니다.

비밀번호는 요청 후 입력 상태에서 제거합니다. 접근·갱신 토큰은 Electron main 프로세스 메모리에만 보관하고 renderer, localStorage, 로컬 분석 DB로 전달하지 않습니다. 현재 앱은 만료 후 재로그인 방식이며 자동 refresh는 후속 범위입니다. 로그아웃은 앱의 메모리 세션을 제거합니다. 앱은 서버 logout API를 호출하지 않으므로 서버 측 토큰 폐기를 수행했다고 표시하지 않습니다.

로컬 분석자의 `local:<UUID>`와 서버 계정 권한은 별개입니다. 로그인하거나 정책을 켜는 것만으로 증거가 서버에 전송되지 않습니다. AI 실행 연결이 없어 현재 앱에서 외부 증거 전송은 발생하지 않습니다. 정책 기본값과 수정 충돌 판단은 기존 Core가 수행합니다. `ALLOW_WITH_REDACTION` 등 변환 후 재평가 상태를 최종 허용으로 표시하지 않습니다.

원격 LLM/MCP 실행 연결에는 실제 서비스 주소와 전송·승인 계약 확인이 필요합니다. 첨부 아키텍처의 서버 측 기술 선택을 이번 클라이언트 구현에서 임의로 확정하지 않았습니다.

## 경계와 데이터 계약

`renderer → preload → Electron main → loopback FastAPI → Core` 경로를 사용합니다. Renderer에는 Node.js와 임의 HTTP 호출 권한을 주지 않습니다. context isolation, sandbox, CSP, IPC 발신 프레임 검증, 작업 allowlist를 사용합니다.

로컬 API는 OS가 배정한 `127.0.0.1` 포트와 실행마다 새로 생성하는 토큰을 사용합니다. Origin 요청과 잘못된 Host를 거부하고 요청 본문을 1 MiB로 제한합니다. Swagger/CORS는 노출하지 않습니다. `GET /health`, `POST /v1/operations/{operation}`의 실제 작업 목록과 입력 형식은 `src/apex_desktop/operations.py` 및 `models.py`에 있습니다.

증거 파일 경로는 main의 네이티브 선택 창에서 확정합니다. Renderer에는 일회용 참조와 이름을 반환합니다. Core 객체는 `schemas/v1`의 계약을 그대로 사용합니다. 생성된 TypeScript DTO와 검증 함수를 갱신하려면 `npm run contracts`를 실행하세요. [AJV standalone 방식](https://ajv.js.org/standalone.html)으로 빌드 시 검증 함수를 생성하므로 renderer에서 `eval`이나 `Function`으로 스키마를 컴파일하지 않습니다.

GUI 컨텍스트 수정은 revision 순서로 직렬화합니다. 충돌 시 최신 컨텍스트를 읽고 보류 중인 선택 변경을 유지하며, 사용자가 다시 적용하기 전까지 후속 변경도 쓰지 않습니다. 개발자 오류 메시지와 스택을 사용자 화면에 표시하지 않습니다.

작업은 한 번에 하나씩 실행하고 대기열을 16개로 제한합니다. 각 작업/요청은 자체 SQLite 연결을 사용합니다. 취소는 Core의 협력적 취소를 사용하며 일반적인 일시정지는 제공하지 않습니다. 앱 재시작 시 미완료 작업은 `INTERRUPTED`로 표시하고 자동 재개하지 않습니다. 작업 결과의 임시 응답은 메모리에만 있으며, 영구 분석 결과는 Core DB에서 다시 조회합니다.

## 설치 파일 빌드

해당 OS와 아키텍처에서 먼저 Python 런타임을 빌드합니다. 빌드 스크립트는 생성한 바이너리의 플랫폼·아키텍처를 기록하며, Electron 패키징 시 일치 여부를 검사합니다.

```sh
# 저장소 루트, Windows/macOS 공통
uv sync --locked --python 3.12 --extra desktop --extra desktop-build --extra report-renderer
uv run --no-sync python tools/build_desktop_runtime.py
uv run --no-sync python tools/verify_desktop_runtime.py
cd frontend
npm ci
```

Windows에서는 `npm run dist:win`, Mac에서는 `npm run dist:mac`을 실행합니다. 기존 `pwsh -File tools/build_desktop_runtime.ps1`도 공통 Python 빌더를 호출합니다.

PyInstaller가 Core·로컬 API·기본 파일시스템 의존성·보고서 렌더러를 `desktop-runtime/`에 묶습니다. electron-builder는 Windows NSIS `.exe`, macOS `.dmg` 및 `.zip`을 `frontend/release/`에 만듭니다. Mac은 현재 호스트 아키텍처로 빌드하며, Intel과 Apple Silicon 패키지는 각각 해당 환경에서 생성합니다. Universal 바이너리나 다른 OS로의 교차 빌드는 제공하지 않습니다.

개인 Mac에서 서명 인증서를 사용하지 않고 로컬 빌드를 확인하려면 `CSC_IDENTITY_AUTO_DISCOVERY=false npm run dist:mac`을 사용합니다. 공개 배포를 위한 Developer ID 서명·공증, 자동 업데이트는 별도 설정이 필요합니다. 로컬 빌드 성공은 배포용 서명 검증을 뜻하지 않습니다.

`.github/workflows/desktop-ci.yml`은 Windows x64·macOS arm64·macOS x64에서 테스트, 타입 검사, 런타임 빌드·실행 확인 및 패키징을 수행하도록 구성했습니다. CI 결과물은 서명하지 않은 검증용입니다. Mac runner 선택은 [GitHub 공식 runner 목록](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)을 기준으로 합니다.

## macOS 지원 범위

사건·증거 관리, 폴더 및 지원 이미지 탐색, 해시, 검색·타임라인, 후보 검토, 보고서 검토와 HTML/PDF 내보내기는 공통 Core를 사용합니다. 실제 호스트의 지원 상태는 설정 화면에서 확인할 수 있습니다.

Windows 호스트 API를 사용하는 이벤트 메시지 렌더링 등은 Mac에서 사용할 수 없습니다. 레지스트리·EVTX 같은 파일 기반 분석은 해당 선택적 파서 설치 여부에 따릅니다. E01/VHD, OCR/STT, 외부 도구와 암호 해제 기능도 선택적 의존성·호스트 검증에 영향을 받으며, Mac 지원이 모든 포렌식 기능의 지원을 의미하지 않습니다. 기본 설치가 제공하지 않는 기능은 기존 capability 보고서에 그대로 표시합니다.

## 검증

```powershell
# 저장소 루트
uv sync --locked --extra desktop --extra report-renderer --extra dev
uv run --no-sync pytest tests/desktop tests/unit/test_phase6_context_views.py tests/unit/test_phase8_report_contract.py tests/unit/test_ai_data_governance.py
uv run --no-sync ruff check src/apex_desktop tests/desktop tools/desktop_entry.py tools/build_desktop_runtime.py tools/verify_desktop_runtime.py tools/generate_desktop_fixtures.py
uv run --no-sync mypy --strict src/apex_desktop
cd frontend
npm test
npm run build
```

로컬 API 테스트는 합성 증거로 사건/증거 격리, 컨텍스트 revision 충돌, 커서 조회, 읽기 한도, 검색·타임라인, 해시 일치/불일치, 보관 이력 및 보고서 승인·내보내기를 확인합니다. 경로 중첩 방지 테스트는 앱 데이터 자체·상위·하위 경로의 등록 차단과 유사한 이름의 외부 폴더 허용을 확인합니다. 프런트 회귀 테스트는 늦은 원본 응답·오류 무시, 연속 읽기 순서, 빠른 작업 완료와 다른 작업 진행 중의 목록 갱신, 보고서 충돌 후 입력 보존을 검증합니다. 프런트 테스트는 실제 Core에서 생성한 합성 DTO를 사용하며 로그인 없는 시작, 파일 탐색, 지원 상태, 컨텍스트 충돌 및 동적 코드 평가 없이 동작하는 계약 검증을 확인합니다.

Windows 및 Intel Mac 설치, 키보드·화면 확대, 장시간 대용량 증거, 실제 인증 서버 연결과 전체 인수 테스트는 별도 검증이 필요합니다.

2026-09-16 로컬 macOS arm64 기반 수정 검증: 관련 Python 테스트 264개, 당시 프런트엔드 테스트 39개, 전체 Python 소스 엄격한 타입 검사(167개 파일), Ruff 및 프런트엔드 빌드가 통과했습니다. PyInstaller 실행 파일로 사건·증거 등록, 파일 인덱싱과 검색을 확인했으며, 당시 패키징한 `APEX.app`을 실제 실행해 화면 렌더링과 `분석 엔진 연결됨` 상태를 확인했습니다. `.dmg`와 `.zip`을 로컬 생성했으며, 배포용 서명·공증과 원격 CI 실행은 수행하지 않았습니다.

## 디자인 및 가이드 준수 검토

이미지 뷰어·비트 평면/LSB 추출과 실제 앱 검증에서 발견한 7건의 후속 수정은 [이미지 분석 수정 내역](IMAGE_ANALYSIS_FIXES.md)에 정리했습니다. 사용자 요청으로 최신 패키지의 실제 앱 재검증은 보류했습니다.

같은 날 후속 디자인 수정으로 제공된 APEX 로고, Astryx Icon 컴포넌트와 Material 파일 아이콘을 적용했습니다. 사건 개요·표·검사기를 차콜 다크테마로 정리하고 오류/빈 상태 구분, 원본 접근 권한과 범위 검증, 삭제 후보 표시, AI 감사 이력, 키보드 조작을 보완했습니다. 후속 프런트 테스트는 52개이며 타입 검사와 빌드가 통과했습니다.

두 가이드 전체의 기능 완료 기준은 아직 충족하지 않습니다. 절별 판정, FT-001–030 검증 범위, 미구현 기능, 화면과 최신 패키지 검증 결과는 [가이드 준수 검토](GUIDE_COMPLIANCE_REVIEW.md)에 기록했습니다. 아이콘 출처와 라이선스는 [자산 고지](../../frontend/public/THIRD_PARTY_NOTICES.md)를 확인하세요.
