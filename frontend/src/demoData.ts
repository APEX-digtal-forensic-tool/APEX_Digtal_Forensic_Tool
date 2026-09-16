/** Invented, deterministic presentation data. No evidence is read or persisted. */
import core from "./__fixtures__/core.json";
import reportFixture from "./__fixtures__/report.json";
import type { Row } from "./gateway";

export function createDemoData() {
  let sequence = 1;
  const id = () =>
    `00000000-0000-4000-8000-${String(sequence++).padStart(12, "0")}`;
  const date = (n = 0) => new Date(Date.UTC(2026, 8, 14, 0, n)).toISOString();
  const cases: Row[] = [
    [
      "내부 자료 반출 조사",
      "업무용 PC와 외장 저장장치의 파일 이동을 살펴보는 합성 시나리오",
      "모의 분석가 A",
    ],
    [
      "의심 메일 첨부파일 분석",
      "메일·다운로드·프로그램 실행 기록을 연결하는 합성 시나리오",
      "모의 분석가 B",
    ],
    [
      "프로젝트 문서 보존 검토",
      "문서 보존과 삭제 후보를 확인하는 합성 시나리오",
      "모의 분석가 C",
    ],
  ].map(([name, description, actor], i) => ({
    ...structuredClone(core.cases[0]),
    id: i === 0 ? core.cases[0].id : id(),
    name: `${name} · 데모`,
    description: `${description}. 실제 조사 자료가 아닙니다.`,
    created_by: actor,
    created_at: date(i * 60),
    metadata: { synthetic: true, investigator: actor },
  }));
  const evidence: Row[] = [];
  const files: Row[] = structuredClone(core.files.items);
  const roots: Row[] = [];
  const artifacts: Row[] = [],
    candidates: Row[] = [],
    timeline: Row[] = [];
  const tasks: Row[] = [],
    custody: Row[] = [],
    reports: Row[] = [];
  const reportDetails: Record<string, Row> = {};
  const views: Record<string, Row> = structuredClone(core.views);
  const resources = new Map<string, { type: string; row: Row }>();
  const register = (type: string, row: Row, key = row.id) =>
    resources.set(key, { type, row });
  const fileTemplate = core.files.items[0];
  const folders = [
    "업무 문서",
    "다운로드",
    "브라우저",
    "Windows 기록",
    "미디어",
    "보관 자료",
  ];
  const fileNames: Record<string, string[]> = {
    "업무 문서": [
      "프로젝트_계획서.docx",
      "예산_검토표.xlsx",
      "회의록_0912.pdf",
      "업무_인수인계.md",
      "연락처_목록.csv",
    ],
    다운로드: [
      "자료_묶음.zip",
      "검토요청.eml",
      "설치_이력.log",
      "문서_뷰어.exe",
      "참고자료.html",
    ],
    브라우저: [
      "History",
      "Cookies.sqlite",
      "Login Data",
      "Bookmarks.json",
      "Cache_001.db",
    ],
    "Windows 기록": [
      "NTUSER.DAT",
      "SYSTEM",
      "Security.evtx",
      "Application.evtx",
      "CHROME.EXE.pf",
    ],
    미디어: [
      "회의실_화이트보드.jpg",
      "현장_사진.png",
      "회의_녹음.wav",
      "화면_기록.mp4",
      "녹음_전사_후보.txt",
    ],
    "보관 자료": Array.from(
      { length: 124 },
      (_, i) =>
        `보존문서_${String(i + 1).padStart(3, "0")}.${["pdf", "docx", "xlsx", "txt"][i % 4]}`,
    ),
  };
  const mime: Record<string, string> = {
    txt: "text/plain",
    csv: "text/csv",
    pdf: "application/pdf",
    json: "application/json",
    jpg: "image/jpeg",
    png: "image/png",
    mp4: "video/mp4",
    wav: "audio/wav",
  };
  const makeFile = (
    ev: Row,
    name: string,
    parent: Row,
    directory = false,
    n = 0,
  ): Row => {
    const relative = `${parent.original_relative_path ? `${parent.original_relative_path}/` : ""}${name}`;
    const extension =
      directory || !name.includes(".") ? null : name.split(".").at(-1)!;
    const node = {
      ...structuredClone(fileTemplate),
      id: id(),
      case_id: ev.case_id,
      evidence_id: ev.id,
      original_name: name,
      original_relative_path: relative,
      display_path: `/${relative}`,
      comparison_path: relative.toLowerCase(),
      parent_node_id: parent.id,
      node_type: directory ? "DIRECTORY" : "FILE",
      file_size: directory ? 0 : 2048 + n * 17321,
      extension,
      mime_candidate: directory
        ? null
        : (mime[extension ?? ""] ?? "application/octet-stream"),
      platform: "windows",
      is_deleted: !directory && n % 19 === 18,
      is_traversed: directory,
      fs_metadata: {},
      raw_timestamps: {},
      timestamp_sources: { created: "synthetic", modified: "synthetic" },
      utc_timestamps: {
        created: date(n),
        modified: date(n + 12),
        accessed: date(n + 20),
        changed: date(n + 12),
      },
      raw_locator: {
        evidence_id: ev.id,
        locator_type: "LOGICAL_PATH",
        relative_path: relative,
        synthetic: true,
      },
      provider_metadata: { synthetic: true },
      created_at: date(),
      updated_at: date(),
    };
    files.push(node);
    register("FILE_SYSTEM_NODE", node);
    return node;
  };
  const specs: [string, string, string][] = [
    [
      "REGISTRY_KEY",
      "Software\\Microsoft\\Windows\\CurrentVersion",
      "Windows 기록",
    ],
    ["REGISTRY_VALUE", "최근 문서 경로 · 업무 문서", "Windows 기록"],
    ["REGISTRY_AUTORUN", "시작 프로그램 · 문서 뷰어", "Windows 기록"],
    ["REGISTRY_USB_DEVICE", "USB 저장장치 연결 기록", "Windows 기록"],
    [
      "REGISTRY_TIMEZONE",
      "시스템 시간대 · Korea Standard Time",
      "Windows 기록",
    ],
    ["REGISTRY_USERASSIST", "탐색기 실행 기록", "Windows 기록"],
    ["EVENT_LOG_RECORD", "로그온 성공 · 이벤트 4624", "Windows 기록"],
    ["PREFETCH_EXECUTION", "CHROME.EXE 실행 기록", "Windows 기록"],
    ["BROWSER_PROFILE", "업무용 브라우저 · Default", "브라우저"],
    ["BROWSER_VISIT", "프로젝트 자료실 방문", "브라우저"],
    ["BROWSER_SEARCH", "문서 보존 절차 검색", "브라우저"],
    ["BROWSER_DOWNLOAD", "자료_묶음.zip 다운로드", "브라우저"],
    ["BROWSER_COOKIE", "example.test 쿠키 · 보호됨", "브라우저"],
    ["BROWSER_CREDENTIAL", "샘플 계정 · 보호됨", "브라우저"],
    ["BROWSER_CACHE_ENTRY", "문서 목록 페이지 캐시", "브라우저"],
    ["BROWSER_DELETED_SQLITE_ROW", "삭제된 방문 기록 후보", "브라우저"],
    [
      "BROWSER_PRIVATE_MODE_CANDIDATE",
      "비공개 모드 흔적 후보 · 검증 필요",
      "브라우저",
    ],
    ["MEDIA_IMAGE", "회의실_화이트보드.jpg · 4032 × 3024", "미디어"],
    ["MEDIA_VIDEO", "화면_기록.mp4 · 02:18", "미디어"],
    ["MEDIA_AUDIO", "회의_녹음.wav · 08:42", "미디어"],
    ["COMMUNICATION_PROFILE", "합성 메일 프로필", "다운로드"],
    ["COMMUNICATION_ACCOUNT", "analyst@example.test", "다운로드"],
    ["COMMUNICATION_CONVERSATION", "프로젝트 검토 요청", "다운로드"],
    ["COMMUNICATION_MESSAGE", "문서 수정본 검토 부탁드립니다", "다운로드"],
    ["COMMUNICATION_ATTACHMENT", "검토요청.eml 첨부 문서", "다운로드"],
    [
      "COMMUNICATION_UNSUPPORTED_STORE",
      "암호화 저장소 · 분석 지원 불가 예시",
      "다운로드",
    ],
  ];

  cases.forEach((c, ci) => {
    const names =
      ci === 0
        ? ["업무용 PC · 합성 폴더", "외장 USB · 합성 폴더"]
        : ci === 1
          ? ["메일 수집본 · 합성 폴더", "다운로드 수집본 · 합성 폴더"]
          : ["보존 문서 · 합성 폴더"];
    names.forEach((name, ei) => {
      const ev = {
        ...structuredClone(core.evidence[0]),
        id: ci === 0 && ei === 0 ? core.evidence[0].id : id(),
        case_id: c.id,
        display_name: name,
        status: "READY",
        size_bytes: 534773760 + ci * 123456789,
        acquired_at: date(),
        metadata: {
          synthetic: true,
          source_path: `/synthetic/${ci + 1}/${ei + 1}`,
          source_path_policy: "NO_SYMLINK_FOLLOW",
        },
      };
      evidence.push(ev);
      register("EVIDENCE", ev);
      const root = {
        ...structuredClone(core.roots[0]),
        id: ci === 0 && ei === 0 ? core.roots[0].id : id(),
        case_id: c.id,
        evidence_id: ev.id,
        original_name: name,
        original_relative_path: "",
        display_path: "/",
        comparison_path: "",
        parent_node_id: null,
        raw_locator: {
          evidence_id: ev.id,
          locator_type: "LOGICAL_PATH",
          synthetic: true,
        },
        provider_metadata: { synthetic: true },
      };
      roots.push(root);
      register("FILE_SYSTEM_NODE", root);
      const sources: Record<string, Row> = {};
      folders.forEach((folder, fi) => {
        const dir = makeFile(ev, folder, root, true);
        fileNames[folder].forEach((file, i) => {
          const node = makeFile(ev, file, dir, false, i + fi * 7);
          if (i === 0) sources[folder] = node;
        });
      });
      [
        "증거_목록.csv",
        "수집_기록.pdf",
        "분석_메모.txt",
        "파일_해시.json",
        "업무자료.zip",
        "이동_이력.log",
      ].forEach((name, i) => makeFile(ev, name, root, false, i + 2));
      specs.forEach(([type, title, folder], ai) => {
        const sourceName =
          type === "EVENT_LOG_RECORD"
            ? "Security.evtx"
            : type === "PREFETCH_EXECUTION"
              ? "CHROME.EXE.pf"
              : type === "MEDIA_VIDEO"
                ? "화면_기록.mp4"
                : type === "MEDIA_AUDIO"
                  ? "회의_녹음.wav"
                  : type === "BROWSER_COOKIE"
                    ? "Cookies.sqlite"
                    : type === "BROWSER_CREDENTIAL"
                      ? "Login Data"
                      : type === "BROWSER_CACHE_ENTRY"
                        ? "Cache_001.db"
                        : type.startsWith("COMMUNICATION")
                          ? "검토요청.eml"
                          : type === "REGISTRY_USB_DEVICE" ||
                              type === "REGISTRY_TIMEZONE"
                            ? "SYSTEM"
                            : null;
        const source =
            (sourceName
              ? files.find(
                  (f) =>
                    f.evidence_id === ev.id && f.original_name === sourceName,
                )
              : null) ?? sources[folder],
          artifactId = id();
        const sourceKind = type.startsWith("REGISTRY")
          ? "REGISTRY_HIVE"
          : type === "EVENT_LOG_RECORD"
            ? "EVENT_LOG_EVTX"
            : type.startsWith("PREFETCH")
              ? "PREFETCH_FILE"
              : type === "MEDIA_IMAGE"
                ? "IMAGE_FILE"
                : type === "MEDIA_VIDEO"
                  ? "VIDEO_FILE"
                  : type === "MEDIA_AUDIO"
                    ? "AUDIO_FILE"
                    : type.startsWith("COMMUNICATION")
                      ? "EMAIL_MBOX"
                      : "BROWSER_SQLITE_DB";
        const raw = {
          evidence_id: ev.id,
          source_kind: "FILE",
          source_id: source.id,
          source_path: source.display_path,
          source_reference: null,
          offset: null,
          length: null,
          locator_type: "LOGICAL_PATH",
          encoding: "utf-8",
          view_types: ["TEXT"],
          content_sha256: null,
          limitations: ["SYNTHETIC_DEMO_ONLY"],
          details: { synthetic: true },
        };
        const a: Row = {
          id: artifactId,
          artifact_id: artifactId,
          case_id: c.id,
          evidence_id: ev.id,
          source_file_node_id: source.id,
          source_object_id: null,
          artifact_type: type,
          artifact_subtype: "SYNTHETIC_DEMO",
          schema_version: "1.0.0",
          display_name_key: "demo.artifact",
          description_key: "demo.synthetic",
          analyzer_id: "demo.synthetic",
          analyzer_version: "1.0.0",
          parser_backend: "synthetic",
          parser_backend_version: "1.0.0",
          source_path: source.display_path,
          source_kind: sourceKind,
          observed_at_raw: date(ai * 7),
          observed_at_utc: date(ai * 7),
          timezone_source: "CASE_SETTING",
          timezone_confidence: "HIGH",
          title,
          summary: `${title}. 화면 탐색을 위한 합성 결과이며 실제 관찰 사실이 아닙니다.`,
          fields: {
            synthetic: true,
            description: title,
            ...(type.startsWith("BROWSER")
              ? {
                  url: "https://example.test/project/documents",
                  profile: "Default",
                }
              : {}),
            ...(type === "BROWSER_CREDENTIAL"
              ? { password: "<redacted>" }
              : {}),
            ...(type === "BROWSER_COOKIE" ? { value: "<redacted>" } : {}),
          },
          payload: {},
          raw_locator: raw,
          citations: [],
          warnings: [],
          parse_status: type.endsWith("UNSUPPORTED_STORE")
            ? "UNSUPPORTED"
            : type.includes("CANDIDATE") || type.includes("DELETED")
              ? "PARTIAL"
              : "SUCCESS",
          confidence: type.includes("CANDIDATE") ? 0.48 : 0.94,
          is_partial: type.includes("CANDIDATE") || type.includes("DELETED"),
          index_revision: 1,
          created_at: date(),
          updated_at: date(),
          dedup_key: artifactId.replaceAll("-", "").padEnd(64, "0"),
          timestamp_interpretations: [],
          provenance: {
            evidence_id: ev.id,
            source_object_id: null,
            source_path: source.display_path,
            source_offset: null,
            source_length: null,
            analyzer_run_id: id(),
            analyzer_id: "demo.synthetic",
            analyzer_version: "1.0.0",
            raw_locator: raw,
          },
        };
        artifacts.push(a);
        register("ARTIFACT", a);
        const event = {
          id: id(),
          case_id: c.id,
          evidence_id: ev.id,
          normalized_utc: ai === 16 ? null : date(ai * 7),
          original_timestamp: date(ai * 7),
          event_type: type,
          title,
          source_type: "ARTIFACT",
          source_id: artifactId,
          timezone_confidence: ai === 16 ? "UNKNOWN" : "HIGH",
          synthetic: true,
        };
        timeline.push({ ...event, timeline_event_id: event.id });
        register("TIMELINE_EVENT", event);
      });
      [
        "프로젝트 자료는 내부 검토 후 보관합니다.",
        "회의 일정: 9월 14일 오전 10시",
        "검토 완료 문서 12건",
        "다음 주까지 수정본을 전달해 주세요.",
      ].forEach((text, i) => {
        const candidate = {
          candidate_id: id(),
          case_id: c.id,
          evidence_id: ev.id,
          source_node_id: sources["미디어"].id,
          source_type: "IMAGE_FILE",
          extraction_type: "OCR",
          text,
          language: "ko",
          confidence: [0.94, 0.72, 0.88, 0.51][i],
          provider_id: "demo.synthetic",
          provider_version: "1.0.0",
          model_id: null,
          region: null,
          frame_number: null,
          media_timestamp_ms: null,
          audio_start_ms: null,
          audio_end_ms: null,
          raw_locator: {
            source_node_id: sources["미디어"].id,
            locator_type: "SYNTHETIC",
          },
          citations: [],
          review_status: ["UNREVIEWED", "ACCEPTED", "CORRECTED", "REJECTED"][i],
          reviewed_by: i ? c.created_by : null,
          reviewed_at: i ? date(180) : null,
          correction_text: i === 2 ? "검토 완료 문서 17건" : null,
          source_revision: 1,
          is_partial: i === 3,
          created_at: date(),
          candidate_semantics: "MACHINE_EXTRACTED_CANDIDATE_NOT_OBSERVED_FACT",
        };
        candidates.push(candidate);
        register("MACHINE_CANDIDATE", candidate, candidate.candidate_id);
      });
      ["REGISTER", "FILES", "ARTIFACTS", "TIMELINE"].forEach((kind, i) =>
        tasks.push({
          task_id: id(),
          case_id: c.id,
          evidence_id: ev.id,
          kind,
          status: i === 2 ? "PARTIAL" : "SUCCEEDED",
          actions: [],
          job: {
            progress: {
              progress_percent: 100,
              processed_items:
                i === 1
                  ? files.filter((f) => f.evidence_id === ev.id).length
                  : 26,
            },
            is_partial: i === 2,
            warnings: i === 2 ? [{ code: "SYNTHETIC_PARTIAL_EXAMPLE" }] : [],
            synthetic: true,
          },
        }),
      );
      ["합성 증거 등록", "읽기 전용 인덱싱 완료", "분석 결과 검토"].forEach(
        (action, i) => {
          const event = {
            id: id(),
            case_id: c.id,
            evidence_id: ev.id,
            sequence: i + 1,
            event_type: ["ACQUISITION", "ANALYSIS", "REVIEW"][i],
            action,
            actor: { name: c.created_by },
            occurred_at_utc: date(i * 40),
            event_hash: "합성 예시 · 무결성 검증 대상 아님",
            synthetic: true,
          };
          custody.push(event);
          register("CUSTODY_EVENT", event);
        },
      );
    });
    const report = {
      ...structuredClone(reportFixture.detail.report),
      report_id: id(),
      case_id: c.id,
      title: `${c.name.replace(" · 데모", "")} · 예비 보고서`,
      created_by: c.created_by,
      description: "합성 시나리오를 위한 읽기 전용 보고서",
      active_version_id: id(),
    };
    const version = {
      ...structuredClone(reportFixture.detail.versions[0]),
      report_version_id: report.active_version_id,
      report_id: report.report_id,
      case_id: c.id,
      title: report.title,
      created_by: c.created_by,
      executive_summary: `${c.description} 파일·브라우저·시스템 기록의 연결 관계를 검토하기 위한 데모 초안입니다.`,
      evidence_ids: evidence.filter((e) => e.case_id === c.id).map((e) => e.id),
      limitations: [
        "모든 사건·경로·결과는 합성 데이터입니다.",
        "실제 분석·복구·검토 승인·AI 실행을 수행하지 않았습니다.",
      ],
      sections: ["검토 범위", "주요 확인 사항", "추가 확인 항목"].map(
        (title, i) => ({
          ...structuredClone(reportFixture.detail.versions[0].sections[0]),
          section_id: id(),
          title,
          order: i + 1,
          content: [
            "등록된 합성 증거의 파일 목록과 아티팩트를 대조했습니다. 파일 형식별 탐색과 인용 흐름을 확인할 수 있습니다.",
            "문서 다운로드, 프로그램 실행, 저장장치 연결 순서가 예시 타임라인에 포함되어 있습니다. 이 기록만으로 자료 반출 여부를 단정하지 않습니다.",
            "삭제·비공개 모드 후보와 OCR 추출 텍스트는 원본 확인이 필요한 예시입니다. 시간대 미확정 기록도 별도로 검토해야 합니다.",
          ][i],
        }),
      ),
    };
    reports.push(report);
    reportDetails[report.report_id] = {
      report,
      versions: [version],
      approvals: { [version.report_version_id]: null },
      reviews: { [version.report_version_id]: [] },
    };
  });
  files.forEach((f) => register("FILE_SYSTEM_NODE", f));
  return {
    cases,
    evidence,
    roots,
    files,
    artifacts,
    candidates,
    timeline,
    custody,
    tasks,
    reports,
    reportDetails,
    views,
    resources,
  };
}
