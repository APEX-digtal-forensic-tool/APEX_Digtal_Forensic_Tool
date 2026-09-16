export const errorMessages: Record<string, string> = {
  ARCHIVE_REQUIRES_EXTRACTION:
    "이 파일은 압축 파일입니다. 원본을 보관하고 별도 폴더에 압축을 해제한 뒤 ‘폴더 추가’로 가져오세요. 압축 파일 내부의 파일시스템 분석은 지원하지 않습니다.",
  MEDIA_LIMIT_EXCEEDED:
    "이미지 분석 한도를 초과했습니다. 최대 64 MiB·2,500만 픽셀을 지원합니다. 미리보기 크기를 줄여 다시 시도할 수 있습니다.",
  MEDIA_SOURCE_CHANGED:
    "등록된 분석 결과와 현재 이미지 해시가 다릅니다. 원본을 확인한 뒤 미디어를 다시 분석해주세요.",
  MEDIA_SOURCE_UNAVAILABLE:
    "이미지 원본을 읽을 수 없습니다. 연결된 증거 폴더와 파일을 확인해주세요. 링크 또는 디스크 이미지 내부의 픽셀 분석은 지원하지 않습니다.",
  MEDIA_DECODE_FAILED:
    "이미지를 디코딩하지 못했습니다. 파일 손상 또는 지원하지 않는 이미지 형식인지 확인해주세요.",
  MEDIA_FORMAT_UNSUPPORTED:
    "PNG·JPEG·GIF·TIFF·BMP·WebP 이미지 파일을 선택해주세요.",
  MEDIA_OFFSET_OUT_OF_RANGE: "시작 픽셀이 이미지 범위를 벗어났습니다.",
  DESKTOP_REQUIRED:
    "실제 분석은 Windows 또는 macOS 데스크톱 앱에서 사용할 수 있습니다.",
  SERVICE_NOT_READY: "로컬 분석 엔진을 시작하고 있습니다.",
  PYTHON_RUNTIME_MISSING:
    "분석 런타임이 없습니다. 개발 환경 또는 설치 파일을 확인해주세요.",
  BACKEND_START_FAILED: "로컬 분석 엔진을 시작하지 못했습니다.",
  BACKEND_STOPPED: "분석 엔진이 종료되었습니다. 앱을 다시 실행해주세요.",
  DESKTOP_CONNECTION_FAILED:
    "분석 엔진과 연결할 수 없습니다. 작업 상태를 확인한 후 다시 시도해주세요.",
  CAPABILITY_UNAVAILABLE:
    "현재 환경에서 이 기능을 사용할 수 없습니다. 설정에서 지원 상태를 확인해주세요.",
  VALIDATION_ERROR: "입력값이나 선택한 옵션을 확인해주세요.",
  CONTRACT_MISMATCH: "엔진 응답이 데이터 계약과 일치하지 않습니다.",
  CONTEXT_REVISION_CONFLICT:
    "다른 작업에서 선택 상태가 변경되었습니다. 최신 상태를 확인한 후 다시 적용해주세요.",
  CONTEXT_EXPIRED: "분석 세션이 만료되었습니다. 새 세션을 생성합니다.",
  CONTEXT_SCOPE_MISMATCH:
    "선택한 항목이 현재 사건 또는 증거에 속하지 않습니다.",
  REPORT_NOT_APPROVED: "보고서 승인 후 내보낼 수 있습니다.",
  REPORT_REVIEW_REVISION_CONFLICT:
    "검토 상태가 변경되었습니다. 내용을 보존하고 최신 상태를 불러왔습니다.",
  WORK_QUEUE_FULL:
    "작업 대기열이 가득 찼습니다. 진행 중인 작업이 끝난 후 다시 시도해주세요.",
  PROFILE_REVISION_CONFLICT:
    "분석 설정이 변경되어 재개할 수 없습니다. 새 분석을 시작해주세요.",
  KEYWORD_NOT_APPROVED: "분석자가 승인한 키워드만 실행할 수 있습니다.",
  CUSTODY_CHAIN_CONFLICT:
    "보관 이력이 변경되었습니다. 최신 이력을 확인한 후 다시 시도해주세요.",
  RESOURCE_LIMIT_EXCEEDED:
    "처리할 범위가 제한을 초과했습니다. 범위나 결과 수를 줄여주세요.",
  TIMEZONE_AMBIGUOUS:
    "시각의 시간대를 확정할 수 없습니다. 원본 시각과 시간대 정보를 확인해주세요.",
  DEMO_READ_ONLY:
    "이 미리보기는 모의 데이터로 표시됩니다. 실제 분석은 데스크톱 앱에서 실행하세요.",
  DEMO_SEARCH_MODE_UNSUPPORTED:
    "더미 데이터 검색은 TERM·PHRASE·PREFIX·EXACT를 지원합니다. 정규식 검색은 실제 데스크톱 엔진에서 사용할 수 있습니다.",
  STATE_CONFLICT: "최신 상태와 요청이 충돌합니다. 새로고침 후 확인해주세요.",
  RAW_READ_LIMIT_EXCEEDED: "원본은 한 번에 최대 1 MiB까지 읽을 수 있습니다.",
  RAW_RANGE_NOT_SATISFIABLE: "원본 데이터 범위를 벗어났습니다.",
  AUTH_LOGIN_FAILED: "이메일, 비밀번호 또는 테넌트 ID를 확인해주세요.",
  AUTH_ORIGIN_INVALID:
    "인증 서버 주소는 HTTPS 주소 또는 로컬 HTTP 주소여야 합니다.",
  AUTH_SERVER_UNAVAILABLE:
    "인증 서버에 연결할 수 없습니다. 로컬 분석은 계속 사용할 수 있습니다.",
  PICKER_REFERENCE_REQUIRED: "증거 파일을 다시 선택해주세요.",
};

export const resourceMessages: Record<string, string> = {
  "error.evidence.capability_unavailable": errorMessages.CAPABILITY_UNAVAILABLE,
  "error.capability_unavailable": errorMessages.CAPABILITY_UNAVAILABLE,
  "error.context_scope_mismatch": errorMessages.CONTEXT_SCOPE_MISMATCH,
  "error.context_revision_conflict": errorMessages.CONTEXT_REVISION_CONFLICT,
  "error.context_expired": errorMessages.CONTEXT_EXPIRED,
  "error.validation": errorMessages.VALIDATION_ERROR,
  "error.raw_read_limit_exceeded": errorMessages.RAW_READ_LIMIT_EXCEEDED,
  "error.raw_range_not_satisfiable": errorMessages.RAW_RANGE_NOT_SATISFIABLE,
};
