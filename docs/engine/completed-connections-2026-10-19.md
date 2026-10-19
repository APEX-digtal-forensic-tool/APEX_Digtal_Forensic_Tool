# 미구현·미연결 기능 후속 구현

대상: PR #26, `fix/engine-audit-2026-10`. 기존 인증과 비로그인 로컬 분석을 유지한다. main 병합은 담당자가 수행한다.

이 문서는 앞선 `frontend-engine-integration-2026-10-19.md`에서 남아 있던 6개 기능의 후속 구현을 설명한다. 모든 포렌식 형식·암호화·손상 조합에서 오류가 없다는 보증은 아니다.

추가 재점검에서 발견한 결함의 수정 내용과 STT 모델 준비 방법은 [전체 연결 재점검](reaudit-2026-10-19.md)을 함께 확인한다. 아래 검증 수치는 첫 구현 시점의 기록이다.

## 기능별 실제 경로

| 기능 | 엔진 구현 | 로컬 API | 사용 화면 |
| --- | --- | --- | --- |
| E01·VHD·VHDX 내부 파일 | Dissect 읽기 전용 컨테이너 → 외부 TSK 이미지 → 파일시스템 논리 스트림. 전체 RAW 변환·마운트 불필요 | 기존 등록·파일 인덱싱·`raw.read`·분석 경로 | 기존 파일 트리·Hex·텍스트·이미지·아티팩트 |
| 삭제 파일 복구 | TSK의 삭제 inode 기본 데이터 스트림 복구. 읽지 못한 구간·실제 복구량·SHA-256·보관 이력 기록 | `files.recover` 작업 | 파일 선택 → **복구·카빙·OCR·ADS** → 삭제 파일 복구 |
| NTFS ADS | `$DATA` 속성 ID별 목록·범위 읽기·스트리밍 내보내기. 기본 스트림과 ADS를 구분 | `files.streams`, `streams.read`, `streams.export` | 추가 분석 → NTFS 데이터 스트림 |
| 시그니처 카빙 | PNG·JPEG·PDF·ZIP·GIF 연속 바이트 후보. 미할당 영역 또는 전체 이미지 | `evidence.carve` 작업 | 추가 분석 → 파일 시그니처 카빙 |
| OCR·STT 실행 | 이미지 내부 파일도 임시 사본으로 처리하고 원본 node/revision에 후보를 저장 | `machine.capabilities/configure/run` | 설정에서 분석기·모델 선택 → 추가 분석 → 실행 → 자동 추출 후보 검토 |
| AI 본문 분석 | 실제 파일/분석 결과에서 제한된 발췌문 생성 → 비밀값 가림 → 정확한 내용 검토 → 정책 평가 → 제공자 → 검증·저장 | `ai.prepare`, `ai.analyze(mode=CONTENT)` | AI 도우미 → 증거 본문 발췌 분석 → 준비 → 검토 체크 → 요청 |

새 작업은 기존 작업 목록에서 진행·취소·결과를 확인한다. 부분 복구·탐색 한도 도달·미할당 영역 일부 생략은 `PARTIAL`로 표시한다. 취소는 협력적이며 네이티브 OCR/STT 추론 도중에는 즉시 중단되지 않을 수 있다. 취소 후 후보 결과는 저장하지 않는다.

## AI API는 나중에 제공해도 됨

API 없이도 사건·증거·이미지·복구·카빙·OCR/STT·후보 검토와 AI 발췌문 준비를 사용할 수 있다. 원격 AI의 응답을 만들어 내거나 성공으로 표시하지 않는다. 검토를 마친 요청도 API가 없으면 `CONFIGURATION_REQUIRED`가 된다.

추후 Electron을 실행할 환경에 다음 설정을 제공한다. 실제 키는 저장소·렌더러 코드에 넣지 않는다.

```powershell
$env:APEX_DESKTOP_AI_CONFIG = '{"provider_id":"configured-provider","base_url":"https://YOUR-PROVIDER/v1","model_id":"YOUR-MODEL","api_key_env":"APEX_AI_API_KEY"}'
$env:APEX_AI_API_KEY = '실제 키'
```

- 기존 OpenAI-compatible 제공자 계약을 사용한다. 다른 형태의 API를 제공하면 해당 계약에 맞는 어댑터가 필요하다.
- 구조 요약은 기존 safe projection만 보낸다. 본문 모드는 화면에서 검토한 발췌문과 동일한 payload만 보낸다. 두 모드의 결과를 잘못 재사용하지 않도록 본문 fingerprint를 요청 식별에 포함한다.
- UTF-8/CP949 및 BOM 있는 UTF-16 텍스트를 읽는다. 최대 원본 65,536 bytes·본문 12,000자이며 잘림을 표시한다. 이미지·음성은 OCR/STT 후보를 선택해서 분석한다.
- 암호·토큰·개인키 등 자동 가림은 보조 수단이다. 사용자는 발췌문을 확인해야 한다. 원본 파일은 수정하지 않는다.
- 원본은 보수적으로 `SECRET` 등급을 유지한다. 본문 전송에는 사건의 AI/외부 전송 활성화, SECRET 허용, projection-only 제한 해제가 필요하다. 앱이 기본 정책을 자동 변경하지 않는다.
- 검토 후 내용 fingerprint가 바뀌면 재검토를 요구한다. 정책 평가가 최종 `ALLOW`인 경우에만 HTTP 요청을 보낸다. localhost 프록시도 EXTERNAL로 평가한다.
- 원격 제공자 실제 호출은 API를 받은 뒤 별도 확인한다. 자동 테스트의 제공자는 가짜 transport이며 사적 증거를 외부에 보내지 않는다.

## OCR·STT 모델과 패키징

Windows 설치 파일에 RapidOCR·ONNX Runtime·Faster Whisper 라이브러리를 포함한다. 빌드 단계에서 영어/기본 OCR 및 한국어 OCR 모델을 확보·체크섬 검증한 후 묶는다. 설치된 앱의 OCR 실행 시 원본을 외부에 보내지 않는다. 소스 환경의 첫 RapidOCR 초기화는 공개 모델을 다운로드할 수 있다.

- OCR 자동 선택은 설치된 Tesseract를 우선 사용하고, 없으면 RapidOCR를 사용한다. RapidOCR의 한국어 선택은 한국어 인식 모델을 사용한다. Tesseract는 선택한 언어의 traineddata가 있어야 한다.
- STT는 **설정 → 로컬 OCR·음성 인식 → 음성 모델 선택**에서 Faster Whisper/CTranslate2 모델 폴더를 선택한다. 폴더에는 `model.bin`, `config.json`, `tokenizer.json`, `vocabulary.*` 등 해당 모델 파일이 필요하다. whisper.cpp를 선택하면 로컬 실행 파일과 모델 파일이 필요하다.
- STT 모델은 API 키와 별개다. 앱이 임의 모델을 자동 다운로드하지 않는다. 작은 영어 전용 모델은 한국어 음성 인식용 모델을 대신하지 않는다.
- 설정은 앱 데이터 폴더의 `machine-settings.json`에 보관한다. `APEX_DESKTOP_MACHINE_CONFIG`로 관리되는 환경에서는 UI 덮어쓰기를 거부한다.
- PyAV 19가 faster-whisper 1.2의 `metadata_errors` 인자를 제거한 호환성 문제를 실제 실행에서 발견하여 `av<19`로 제한했다.

```sh
uv sync --locked --python 3.12 --extra desktop --extra desktop-build --extra report-renderer --extra browser-media --extra windows-artifacts --extra machine-extraction --extra dev
uv run --no-sync python tools/build_desktop_runtime.py
uv run --no-sync python tools/verify_desktop_runtime.py
cd frontend
npm ci
npm run dist:win
```

## 보존 규칙과 분석 한계

- 원본은 읽기 전용으로 연다. 파생 출력은 기존 원본 충돌 방지·임시 파일 발행·보관 이력 경로를 사용한다. EWF 세그먼트 누락/개수 불일치 및 링크를 거부한다.
- 독립적인 일반 E01/VHD/VHDX를 지원한다. 검증된 부모 체인이 필요한 차등 VHD/VHDX, 암호화된 볼륨, 모든 손상 이미지 복구까지 지원한다고 해석하면 안 된다.
- 삭제 inode의 내용은 이미 덮어써졌을 수 있다. `recovered_bytes`는 읽은 바이트 수이며 원래 내용의 정확성을 보증하지 않는다. 누락 구간은 ZERO_FILL과 위치를 기록한다. 기존 물리 extent 복구는 `use_filesystem=False`로 별도 호출할 수 있다.
- 카빙은 연속 파일 후보를 찾는다. 조각난 파일 자동 재조립, ZIP64, 모든 파일 형식의 심층 복구는 제공하지 않는다. 후보를 관찰된 파일로 승격하지 않고 `UNREVIEWED`로 기록한다.
- 미할당 영역은 NTFS `$Bitmap`, FAT12/16/32 FAT, exFAT bitmap/FAT chain, 일반 EXT bitmap과 파티션 간 빈 공간으로 계산한다. EXT bigalloc/meta_bg는 거부하며 BLOCK_UNINIT 그룹은 생략 경고와 불완전 coverage를 반환한다.
- 기본 카빙 탐색량 256 MiB, 후보당 64 MiB, 최대 1,000개다. 검색 및 후보 검사 I/O를 제한하고 `next_offset`으로 재개한다. 결과 폴더의 `manifest.json`에 오프셋·길이·해시·제한·후보 목록을 남긴다.
- 모든 화면 작업은 기존 사건 범위를 검사한다. 잘못된 사건의 node/evidence를 전달하면 작업 등록 전에 차단한다.

## 검증 자료

- `tests/fixtures/container-images.json`: 실제 ewfacquire/qemu-img/mkntfs/ntfscp로 만든 합성 E01·VHD·VHDX·NTFS 및 OCR 이미지. gzip/base64와 원본 SHA-256을 저장하여 Windows에서도 외부 생성 도구 없이 동일 바이트로 테스트한다.
- E01/VHD/VHDX 내부 한글 파일 내용·원본 해시 보존, NTFS resident/nonresident ADS 범위 읽기·내보내기, 삭제 파일 실제 복구, 카빙 할당 영역 제외·청크 경계·재개를 검증한다.
- HTTP 테스트는 ADS 내보내기 작업, OCR/STT 후보 저장·출처, 사건 간 접근 차단, 부분 카빙 상태를 검증한다.
- AI 테스트는 API 미설정, 검토 fingerprint, 기본 정책 차단, 최종 허용 시 정확한 가림 payload, 구조/본문 결과 재사용 분리를 검증한다.
- 실제 Tesseract/RapidOCR로 `HELLO 123`을 추출했고, Faster Whisper tiny.en으로 공개 음성 샘플을 인식하여 텍스트·시간 구간·원본 SHA-256을 확인했다. 한국어 인식 모델의 로딩도 확인했으나 한국어 음성 정확도 벤치마크를 했다는 뜻은 아니다.
- CI 네이티브 런타임 검증은 포장된 실행 파일에 HTTP로 사건/증거 등록, 검색, E01/VHD/VHDX 본문 읽기와 실제 OCR 실행을 요청한다.

## 로컬 검증 결과

- 전체 Python: **735 passed, 12 skipped**. 건너뛴 항목은 별도 실자료·모델·플랫폼 조건이 필요한 검증이다.
- 프론트: **63 passed**, 동적 코드 실행 없이 계약 검증 통과. TypeScript·Vite·Electron 빌드 통과.
- Ruff 통과, mypy strict **180개 소스** 통과.
- 설계 검증: 기본 1,938개 및 4,404개 검사 통과, Schema 76개. 프론트 빌드에서 AJV 계약 생성·검증 통과.
- Bandit: High 0, Medium 44개는 기존 검토 분류와 일치. 미분류·오래된 분류 0개. 보안 검토 예외를 추가하여 검사를 우회하지 않았다.
- 소스 런타임을 별도 프로세스로 실행해 HTTP 등록·검색·E01/VHD/VHDX 본문·실제 OCR까지 검증했다. 설치 파일 자체의 결과는 PR의 CI 상태를 함께 확인한다.

설치 파일 CI 후속 수정: Intel Mac에 배포되지 않는 최신 ONNX Runtime 대신 해당 플랫폼에 1.23 계열을 선택하고, Windows/Apple Silicon은 기존 버전을 유지하도록 잠금 파일을 분리했다. 데스크톱 Python 3.12의 세 플랫폼을 의존성 해결 조건에 명시했다. 최소 MCP 환경에서는 선택적 Pillow를 동적으로 불러오며 JPEG/GIF 카빙에 Pillow가 없으면 기능 의존성을 명확히 알린다.
