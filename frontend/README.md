# APEX Windows / macOS desktop

Electron + React + TypeScript 데스크톱 앱입니다. 같은 저장소의 `apex_desktop` FastAPI를 자식 프로세스로 실행하여 기존 APEX Core 서비스를 호출합니다. 로그인 없이 로컬 사건 생성과 분석을 시작할 수 있습니다.

개발·패키징·검증 방법과 현재 지원 범위는 [데스크톱 개발 안내](../docs/desktop/README.md)를 확인하세요.

디자인·데이터 거버넌스 요구사항의 구현 상태와 남은 기능은 [가이드 준수 검토](../docs/desktop/GUIDE_COMPLIANCE_REVIEW.md)에 정리했습니다. Astryx UI Icon과 Material 파일 아이콘의 버전·출처·라이선스는 [자산 고지](public/THIRD_PARTY_NOTICES.md)에 있습니다.

```powershell
# 저장소 루트, Python 3.12 / Node.js 24 / uv 필요
uv sync --locked --extra desktop --extra report-renderer
cd frontend
npm ci
npm run dev
```

macOS에서는 `.venv/bin/python`을 사용합니다. Apple Silicon은 arm64 Python/Node.js, Intel Mac은 x64 Python/Node.js를 같은 아키텍처로 설치하세요. Mac 설치 파일은 `npm run dist:mac`으로 생성하며, 먼저 안내 문서의 공통 런타임 빌드를 실행해야 합니다.

브라우저만 실행하는 `npm run dev:web`은 실제 파일 분석용 실행 방식이 아닙니다. `VITE_APEX_DEMO=1`을 개발 환경에서 명시한 경우에만 합성 테스트 자료를 표시하며, 제품 빌드에는 데모가 포함되지 않습니다.

```sh
VITE_APEX_DEMO=1 npm run dev:web
```

미리보기에는 합성 사건 3건, 증거 5개, 파일·폴더 809개(루트 5개 별도), 아티팩트 130개, 타임라인 130개, 추출 후보 20개, 보고서 3개가 있습니다. 사건을 선택한 뒤 폴더를 탐색하거나 `프로젝트`를 검색해 보세요. `보관 자료` 폴더에는 다음 페이지 동작을 확인할 수 있는 문서 124개가 있습니다. 보고서 선택, 검사기, 합성 텍스트의 Hex 보기, 정책 평가 예시도 제공됩니다. 정규식 검색과 데이터 변경·실제 분석·내보내기는 데모에서 실행하지 않습니다.

`src/demoData.ts`는 Core 생성 기본 fixture를 바탕으로 화면용 합성 자료를 확장합니다. 추가 자료는 실제 Core 분석 결과가 아니며, `demoBridge.test.ts`에서 canonical Schema, 사건·증거 분리, 페이지 조회, 선택 결과, 읽기 전용 동작을 검증합니다. 실제 사건 DB와 파일에는 저장하지 않으며 새로고침하면 선택 상태가 초기화됩니다.
