# PR #33 병합본 재검사 및 실제 HTTP 교차 검증

- 점검일: 2026-10-21
- 기준 main: `22943ef931669a9f9406a717810a4942905febd5`
- 기준 소스 트리: `b291e0e3a43cc64efd144b643ea067cf69ee9409`
- 범위: 프론트/Electron, 로컬 API, 인증 백엔드, 엔진, MCP, AI 연결·정책, 검사·빌드
- 이번 수정은 별도 PR 대상이며, 이 문서가 main 병합 완료를 의미하지 않는다.

## 1. 결론과 검사 방법

PR #33 병합본은 이전에 검사한 PR 소스와 동일했고, 병합 main의 MCP push CI도 성공했다. 새 작업 트리에서 전체 검사를 다시 실행했다. 기존 검사만으로는 드러나지 않던 **로컬 API 요청 검사 결함 두 종류**를 추가로 재현하여 수정했다. 중복 인증 헤더도 같은 경계에서 명확하게 거부하도록 보강했다.

이번에는 두 방법을 구분해 확인했다.

1. 저장소 전체 Python/프론트 시험, 계약·정적 검사, 프론트/Electron 빌드.
2. 별도 과거 결함 재현 시험, 실제 Uvicorn 서버에 직접 보낸 HTTP 바이트, Electron과 같은 Node `fetch` 요청. 테스트 클라이언트 내부의 URL·헤더 보정으로 잘못 판단하지 않도록 실제 전송 결과와 대조했다.

이번 추가 재현에서 엔진·인증 백엔드·프론트·AI 로직의 새로운 확정 결함은 발견하지 않았다. 해당 분야의 모든 가능한 입력과 환경에 문제가 없다는 보증은 아니다. 이번 코드 변경은 로컬 API 미들웨어에 한정한다.

## 2. 추가 발견 및 수정

### MR-01 — 비 ASCII 인증 헤더가 JSON 401 대신 HTTP 500 발생

- 위치: `src/apex_desktop/app.py`, `local_boundary`.
- 재현: `/health`에 `Authorization: Bearer` 뒤로 바이트 `0xff`를 전송한다.
- 변경 전: HTTP 500, 본문 `Internal Server Error`.
- 원인: ASGI가 헤더를 문자열로 전달하고, `compare_digest(str, str)`가 비 ASCII 문자열을 받으면 `TypeError`를 발생시킨다. 라우트의 오류 처리 바깥인 미들웨어에서 예외가 발생한다.
- 수정: 비교 대상 양쪽을 바이트로 변환해 상수 시간 비교를 유지한다. Authorization 헤더는 정확히 하나여야 한다.
- 변경 후: HTTP 401, `{"ok":false,"error":{"code":"LOCAL_SESSION_REQUIRED"}}`.
- 영향: 잘못된 요청의 오류 응답 계약 문제다. 서명/토큰을 우회하거나 서버 프로세스가 종료된 것으로 확인된 문제는 아니다.
- 추가 보강: 유효 토큰과 잘못된 토큰을 두 Authorization 헤더로 함께 보내도 첫 값만 골라 승인하지 않고 401로 거부한다. 이것도 유효 토큰 없이 접근할 수 있다는 의미는 아니다.

### MR-02 — 잘못된 Host가 URL 생성 과정에서 로컬 주소로 보정되어 허용

- 위치: 같은 미들웨어의 `request.url.hostname` 검사.
- 재현: 유효한 시험용 앱 토큰과 `Host: [invalid`를 함께 보낸다. `/health`뿐 아니라 사건 생성 요청도 기존 구현에서 허용된다.
- 변경 전: HTTP 200. 정상 Host와 잘못된 Host를 구분하지 못한다.
- 원인: 잠금 파일의 Starlette 1.6.0은 유효하지 않은 Host로 URL을 만들 때 ASGI 서버 주소를 대신 사용한다. 이 가공된 URL의 hostname은 `127.0.0.1`이므로 애플리케이션 검사를 통과한다. `request.url`을 신뢰하는 방식의 문제이며, Starlette 자체의 취약점이라고 판정한 것은 아니다.
- 수정: 원래 수신한 Host가 정확히 하나인지 검사하고, 설정된 호스트와 선택적인 숫자 포트(1~65535)만 허용한다. URL의 fallback을 사용하지 않는다. Origin 헤더 차단은 유지한다.
- 변경 후: HTTP 403, `LOCAL_ORIGIN_DENIED`. 거부된 사건 생성 요청 이후 `cases.list`가 비어 있는지도 검사한다.
- 검증 입력: 깨진 대괄호, `/`, `@`, `#`, 비숫자 포트, 범위 밖/0/빈 포트, 외부 호스트, 호스트 접미사, Host 누락·중복.
- 영향: Host 검사 규칙이 의도대로 적용되지 않은 문제다. 유효한 앱 토큰 검사와 Origin 검사가 함께 사라진 것은 아니므로 원격 무인증 접근으로 과장하지 않는다.

## 3. 교차 검증 결과

### 실제 HTTP 전송

임시 디렉터리와 시험용 토큰으로 실제 Uvicorn 서버를 `127.0.0.1`의 임시 포트에서 실행했다. 외부 서비스나 실제 사건 자료는 사용하지 않았다.

| 요청 | 변경 전 | 변경 후 |
|---|---|---|
| 정상 Host + 정상 토큰 | 200 | 200 |
| 정상 Host + 잘못된 ASCII 토큰 | JSON 401 | JSON 401 |
| 정상 Host + 비 ASCII 토큰 | 일반 텍스트 500 | JSON 401 |
| 잘못된 Host + 정상 토큰 | 200 | JSON 403 |
| 외부 Host + 정상 토큰 | JSON 403 | JSON 403 |

추가로 Node `fetch`가 자동 생성하는 `Host: 127.0.0.1:<port>`로 상태 조회, 사건 생성, 저장된 사건 목록 재조회가 성공함을 확인했다. Electron 소스도 같은 주소·Authorization 형식으로 호출한다. 전체 Electron GUI를 조작한 시험과는 구분한다.

실행 환경의 FastAPI 0.141.1, Starlette 1.6.0, HTTPX 0.28.1, Uvicorn 0.52.4가 모두 `uv.lock`과 일치했다.

### 회귀 시험 및 전체 검사

신규 시험 파일: `tests/desktop/test_local_boundary_headers.py`.

- 정상 요청과 실패 요청을 합해 신규 20개 시험을 추가했다.
- 검증용 시험 코드 자체의 헤더 구성 오류를 수정한 뒤, 변경 전 코드를 다시 적용하여 **13 failed / 7 passed**를 확인했다. 13개는 입력 변형 수이며 13개의 독립 결함이라는 뜻이 아니다.
- Host가 없으면 Starlette TestClient가 자동으로 삽입하므로, Host 누락·중복 시험은 ASGITransport로 원래 헤더 목록을 전달한다.
- 수정 후 신규 20개 + 기존 로컬 API 16개, 총 36개가 통과했다.

| 검사 | 결과 |
|---|---|
| 병합 main 전체 Python | 880 passed / 5 skipped |
| 수정 후 전체 Python | **900 passed / 5 skipped**, 약 144초 |
| 프론트 전체 | 101 passed / 13 files |
| TypeScript·Vite·Electron 빌드 | 통과 |
| CSP 계약 검증 | 통과 |
| 별도 과거 결함 재현 시험 | 10 passed |
| 실제 HTTP 전송 비교 | 위 5가지 응답 확인 |
| Node fetch 연결 | 상태 확인·사건 생성·저장 후 재조회 통과 |
| Ruff / mypy strict | 통과 / 184개 소스 파일 통과 |
| 설계·Schema·Ajv | 4,405 검사 / 76 schemas, strict 검증 통과 |
| MCP 계약·stdio lifecycle | 통과 |
| Bandit 분류 정책 | 통과, high 0 / medium 44 / low 123 / 미분류 0 |

프론트와 엔진 소스는 이번 수정에서 변경하지 않았다. 프론트 전체 시험·빌드는 이번 재점검에서 직접 실행했다. Python 전체 결과에는 backend, desktop, MCP, unit/integration 시험이 포함되며, 별도 MCP 게이트 실행 수를 다시 더하지 않는다. Bandit 통과는 저장소의 분류 정책을 만족한다는 의미이며 경고가 0이라는 뜻이 아니다.

분야별 확인 근거:

| 분야 | 확인 범위 |
|---|---|
| 프론트/Electron | 사건 전환·늦은 응답, 보고서 출처 보존·내보내기, OCR/STT 설정, API 작업 허용 목록 동등성, TS 빌드, 실제 Node 전송 |
| 로컬 API | Host/Origin/앱 토큰, 크기 제한, 사건 간 범위, 실제 증거 등록·분석·조회·보고서, 신규 잘못된 헤더 경로 |
| 엔진 | 원본/이미지 변경 차단, 파일·컨테이너·복구·검색·타임라인·보고서·보관이력 기존 회귀 시험 |
| 저장·작업 | 동시 설정 저장, 설정 손상, 작업 기록 실패 표시, 재시작·취소 기존 회귀 + 별도 재현 시험 |
| 인증/MCP | 필수 JWT 클레임·JWKS 실패, 로그인·갱신·세션·사건 권한, HTTP/stdio 계약 시험 |
| AI | 선택 설정 오류 격리, 전송 정책·등급·민감정보 제거·안전한 데이터 추출 및 검토 계약. 시험용 제공자 사용 |

인증 라우터에 있는 `NotImplementedError`는 앱 팩토리에서 `dependency_overrides`로 연결하는 의존성 자리다. 선언만 보고 미연결 버그로 분류하지 않았으며, 실제 앱 연결과 기존 인증 시험을 함께 확인했다. MCP의 Host 검사는 원래 헤더에 대한 허용 목록 비교를 사용하므로 MR-02와 동일한 URL fallback 경로는 없다.

재현 가능한 저장소 검사 명령:

```bash
python -m pytest -o addopts= -q -rs tests
python -m pytest -o addopts= -q tests/desktop/test_local_boundary_headers.py
python tools/verify_engine_release.py --mcp-only --json
cd frontend
npm test
npm run build
```

## 4. 남은 확인 및 비차단 경고

다음 다섯 시험은 이 실행 환경에 실제 자료 또는 선택 의존성이 없어 skipped이며 통과로 계산하지 않았다.

1. faster-whisper 로컬 모델 + 실제 영어/한국어 음성 정답 자료.
2. Tesseract/tessdata + 실제 한국어·혼합 OCR 정답 이미지.
3. pyvhdi 선택 백엔드.
4. qemu-img 외부 도구 경로.
5. pyewf 선택 백엔드.

이는 E01/VHD/VHDX가 전부 미구현이라는 뜻은 아니다. 다른 읽기 백엔드와 저장소 컨테이너 fixture 시험은 실행했다. 실제 클라우드 AI는 API 설정을 받은 뒤 응답·지연·실패를 검증해야 한다. 최종 Windows 설치본에서 실제 증거와 모델로 기동→분석→보고서까지 사용해 보는 절차도 남는다.

Vite 번들 크기 경고와 passlib의 Python 3.13 관련 `crypt` 폐기 경고는 현재 실패가 아니다. 향후 최적화·의존성 전환 항목으로 남는다.

기준 main의 MCP CI: [39557034073](https://github.com/APEX-digtal-forensic-tool/APEX_Digtal_Forensic_Tool/actions/runs/39557034073). 기준 소스와 동일한 PR #33의 Windows/macOS 패키징 CI: [39554887750](https://github.com/APEX-digtal-forensic-tool/APEX_Digtal_Forensic_Tool/actions/runs/39554887750). 둘 다 성공을 확인했다. 이번 추가 수정의 CI는 새 PR의 Checks로 구분해야 한다.
