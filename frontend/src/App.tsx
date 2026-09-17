import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { EvidenceTree } from "./workbench/EvidenceTree";
import { Properties } from "./workbench/Properties";
import { FileViewer } from "./workbench/FileViewer";
import { Splitter } from "./workbench/Splitter";
import {
  Activity,
  BrandLogo,
  Archive,
  ArrowDownToLine,
  ChevronRight,
  Clock3,
  Files,
  Folder,
  FolderOpen,
  HardDrive,
  PanelBottomClose,
  PanelBottomOpen,
  Play,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  AssistantIcon,
  X,
} from "./icons";
import { gateway, GatewayError, unwrap, type Row } from "./gateway";
import { ImageInspector } from "./ImageInspector";
import type { CaseRecord } from "./contracts/generated/case";
import type { GuiContext } from "./contracts/generated/gui-session-context";
import {
  Badge,
  labels,
  ArtifactSemantics,
  RawPreview,
  Empty,
  ErrorState,
  Fields,
  FileIcon,
  Loading,
  ResultState,
  Section,
  Table,
  rowId,
  size,
  time,
  type Column,
} from "./ui";
import {
  AccountPanel,
  FormDialog,
  PolicyPanel,
  Reports,
  type FieldSpec,
} from "./panels";
type Route = GuiContext["current_route"];
const routeNames: Partial<Record<Route, string>> = {
  CASE_OVERVIEW: "사건 개요",
  EVIDENCE: "증거 관리",
  FILE_SYSTEM: "파일 시스템",
  ARTIFACTS: "아티팩트",
  REGISTRY: "레지스트리",
  EVENT_LOG: "이벤트 로그",
  PREFETCH: "프리패치",
  BROWSER: "브라우저",
  MEDIA: "미디어",
  SEARCH: "통합 검색",
  TIMELINE: "타임라인",
  CANDIDATES: "추출 후보 검토",
  CHAIN_OF_CUSTODY: "증거 보관 이력",
  REPORT: "보고서",
  SETTINGS: "설정",
};
const investigate: Route[] = [
  "FILE_SYSTEM",
  "ARTIFACTS",
  "REGISTRY",
  "EVENT_LOG",
  "PREFETCH",
  "BROWSER",
  "MEDIA",
];
const categoryTypes: Partial<Record<Route, string[]>> = {
  REGISTRY: [
    "REGISTRY_KEY",
    "REGISTRY_VALUE",
    "REGISTRY_AUTORUN",
    "REGISTRY_USB_DEVICE",
    "REGISTRY_TIMEZONE",
    "REGISTRY_USERASSIST",
  ],
  EVENT_LOG: ["EVENT_LOG_RECORD"],
  PREFETCH: ["PREFETCH_EXECUTION"],
  BROWSER: [
    "BROWSER_PROFILE",
    "BROWSER_VISIT",
    "BROWSER_SEARCH",
    "BROWSER_DOWNLOAD",
    "BROWSER_COOKIE",
    "BROWSER_CREDENTIAL",
    "BROWSER_CACHE_ENTRY",
    "BROWSER_DELETED_SQLITE_ROW",
    "BROWSER_PRIVATE_MODE_CANDIDATE",
  ],
  MEDIA: ["MEDIA_IMAGE", "MEDIA_VIDEO", "MEDIA_AUDIO"],
};
const communicationTypes = [
  "COMMUNICATION_PROFILE",
  "COMMUNICATION_ACCOUNT",
  "COMMUNICATION_CONVERSATION",
  "COMMUNICATION_MESSAGE",
  "COMMUNICATION_ATTACHMENT",
  "COMMUNICATION_UNSUPPORTED_STORE",
];
const typeLabels: Record<string, string> = {
  REGISTRY_KEY: "키",
  REGISTRY_VALUE: "값",
  REGISTRY_AUTORUN: "자동 실행",
  REGISTRY_USB_DEVICE: "USB",
  REGISTRY_TIMEZONE: "시간대",
  REGISTRY_USERASSIST: "UserAssist",
  EVENT_LOG_RECORD: "이벤트",
  PREFETCH_EXECUTION: "실행 기록",
  BROWSER_PROFILE: "프로필",
  BROWSER_VISIT: "방문 기록",
  BROWSER_SEARCH: "검색 기록",
  BROWSER_DOWNLOAD: "다운로드",
  BROWSER_COOKIE: "쿠키",
  BROWSER_CREDENTIAL: "자격 증명",
  BROWSER_CACHE_ENTRY: "캐시",
  BROWSER_DELETED_SQLITE_ROW: "삭제 후보",
  BROWSER_PRIVATE_MODE_CANDIDATE: "비공개 모드 후보",
  MEDIA_IMAGE: "이미지",
  MEDIA_VIDEO: "동영상",
  MEDIA_AUDIO: "오디오",
  COMMUNICATION_PROFILE: "통신 프로필",
  COMMUNICATION_ACCOUNT: "계정",
  COMMUNICATION_CONVERSATION: "대화",
  COMMUNICATION_MESSAGE: "메시지",
  COMMUNICATION_ATTACHMENT: "첨부파일",
  COMMUNICATION_UNSUPPORTED_STORE: "미지원 저장소",
};
const activeTask = (t: Row) =>
  ["QUEUED", "RUNNING", "CANCELLING"].includes(t.status);

export function App() {
  const [runtime, setRuntime] = useState<Row | null>(null),
    [startupError, setStartupError] = useState<unknown>(null),
    [cases, setCases] = useState<CaseRecord[]>([]),
    [caseId, setCaseId] = useState(""),
    [evidence, setEvidence] = useState<Row[]>([]),
    [evidenceId, setEvidenceId] = useState("");
  const [route, setRoute] = useState<Route>("FILE_SYSTEM"),
    [artifactType, setArtifactType] = useState(""),
    [communication, setCommunication] = useState(false),
    [roots, setRoots] = useState<Row[]>([]),
    [folder, setFolder] = useState<Row | null>(null);
  const [page, setPage] = useState<Row | null>(null),
    [rows, setRows] = useState<Row[]>([]),
    [loading, setLoading] = useState(false),
    [error, setError] = useState<unknown>(null),
    [selected, setSelected] = useState<Row | null>(null),
    [projection, setProjection] = useState<Row | null>(null),
    [viewError, setViewError] = useState<unknown>(null),
    [mode, setMode] = useState<"SIMPLE" | "DETAILED" | "RAW">("SIMPLE"),
    [inspector, setInspector] = useState(true),
    [inspectorHeight, setInspectorHeight] = useState(340),
    [raw, setRaw] = useState<Row | null>(null),
    [rawOffset, setRawOffset] = useState(0),
    [rawLength, setRawLength] = useState(4096);
  const [context, setContext] = useState<GuiContext | null>(null),
    [conflict, setConflict] = useState<Row | null>(null),
    [tasks, setTasks] = useState<Row[]>([]),
    [jobsOpen, setJobsOpen] = useState(false),
    [aiOpen, setAiOpen] = useState(false),
    [notice, setNotice] = useState("");
  const [reportCitations, setReportCitations] = useState<Row[]>([]);
  const [sidebarWidth, setSidebarWidth] = useState(280);
  const [folderTrail, setFolderTrail] = useState<Row[]>([]);
  const [query, setQuery] = useState(""),
    [searchText, setSearchText] = useState(""),
    [searchMode, setSearchMode] = useState("TERM"),
    [revision, setRevision] = useState(0),
    [profile, setProfile] = useState("QUICK_TRIAGE"),
    [hash, setHash] = useState("SHA256");
  const [dialog, setDialog] = useState<{
    title: string;
    description?: string;
    fields: FieldSpec[];
    submit?: (f: Row) => Promise<void>;
  } | null>(null);
  const resizeOrigin = useRef<{ y: number; height: number } | null>(null);
  const contextRef = useRef<GuiContext | null>(null),
    conflictRef = useRef<Row | null>(null),
    caseRef = useRef(""),
    syncQueue = useRef(Promise.resolve()),
    requestRevision = useRef(0),
    rawRequestRevision = useRef(0);
  const currentCase = cases.find((c) => c.id === caseId);
  const currentEvidence = evidence.find((e) => e.id === evidenceId);
  const zone = currentCase?.timezone ?? "Asia/Seoul";
  const refresh = () => setRevision((r) => r + 1);
  const bootstrap = useCallback(async () => {
    try {
      const [r, c] = await Promise.all([
        gateway.call("runtime"),
        gateway.call<CaseRecord[]>("cases.list"),
      ]);
      setRuntime(r);
      setCases(c);
      setStartupError(null);
    } catch (err) {
      setStartupError(err);
    }
  }, []);
  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);
  useEffect(() => {
    if (!runtime && window.apex) {
      const t = setInterval(() => void bootstrap(), 2000);
      return () => clearInterval(t);
    }
  }, [runtime, bootstrap]);
  useEffect(() => {
    caseRef.current = caseId;
    contextRef.current = null;
    setContext(null);
    setReportCitations([]);
    setConflict(null);
    conflictRef.current = null;
    setEvidence([]);
    setEvidenceId("");
    setRows([]);
    setPage(null);
    setSelected(null);
    setFolder(null);
    setFolderTrail([]);
    setTasks([]);
    setError(null);
    if (!caseId) return;
    let live = true;
    Promise.all([
      gateway.call<Row[]>("evidence.list", { case_id: caseId }),
      gateway.call<GuiContext>("context.create", { case_id: caseId }),
    ])
      .then(([ev, ctx]) => {
        if (!live) return;
        setEvidence(ev);
        setEvidenceId(ev[0]?.id ?? "");
        setContext(ctx);
        contextRef.current = ctx;
      })
      .catch((err) => live && setError(err));
    return () => {
      live = false;
    };
  }, [caseId]);
  useEffect(() => {
    if (!caseId) return;
    let live = true;
    let polling = false;
    let statuses = new Map<string, string>();
    const poll = async () => {
      if (polling) return;
      polling = true;
      try {
        const [ts, ev] = await Promise.all([
          gateway.call<Row[]>("tasks.list", { case_id: caseId }),
          gateway.call<Row[]>("evidence.list", { case_id: caseId }),
        ]);
        if (live) {
          // A short task can finish before its first poll. Refresh each newly
          // observed terminal state, even while other tasks are still running.
          if (
            ts.some(
              (t) => !activeTask(t) && statuses.get(t.task_id) !== t.status,
            )
          )
            refresh();
          statuses = new Map(ts.map((t) => [t.task_id, t.status]));
          setTasks(ts);
          setEvidence(ev);
          if (!evidenceId && ev.length) setEvidenceId(ev[0].id);
        }
      } catch (err) {
        if (live) setError(err);
      } finally {
        polling = false;
      }
    };
    void poll();
    const timer = setInterval(poll, 1600);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [caseId, evidenceId]);
  const sync = useCallback((patch: Row) => {
    const owner = caseRef.current;
    syncQueue.current = syncQueue.current
      .then(async () => {
        const ctx = contextRef.current;
        if (!ctx || ctx.case_id !== owner || caseRef.current !== owner) return;
        if (conflictRef.current) {
          conflictRef.current = { ...conflictRef.current, ...patch };
          setConflict(conflictRef.current);
          return;
        }
        try {
          const updated = await gateway.call<GuiContext>("context.update", {
            case_id: owner,
            session_context_id: ctx.session_context_id,
            expected_revision: ctx.context_revision,
            patch,
          });
          if (caseRef.current === owner) {
            contextRef.current = updated;
            setContext(updated);
          }
        } catch (err) {
          if (caseRef.current !== owner) return;
          if (
            err instanceof GatewayError &&
            err.code === "CONTEXT_REVISION_CONFLICT"
          ) {
            const latest = await gateway.call<GuiContext>("context.get", {
              case_id: owner,
              session_context_id: ctx.session_context_id,
            });
            if (caseRef.current !== owner) return;
            contextRef.current = latest;
            setContext(latest);
            conflictRef.current = patch;
            setConflict(patch);
          } else if (
            err instanceof GatewayError &&
            err.code === "CONTEXT_EXPIRED"
          ) {
            const next = await gateway.call<GuiContext>("context.create", {
              case_id: owner,
            });
            if (caseRef.current !== owner) return;
            contextRef.current = next;
            setContext(next);
            conflictRef.current = patch;
            setConflict({ ...patch });
            setNotice("세션을 갱신했습니다. 선택 상태를 다시 적용해주세요.");
          } else setError(err);
        }
      })
      .catch(setError);
  }, []);
  useEffect(() => {
    if (context?.context_revision === 1)
      sync({ current_route: route, active_evidence_id: evidenceId || null });
  }, [context?.session_context_id, evidenceId, sync]);
  function navigate(next: Route, comm = false) {
    if (next === route && comm === communication) return;
    setRoute(next);
    setCommunication(comm);
    setArtifactType(
      comm ? communicationTypes[0] : (categoryTypes[next]?.[0] ?? ""),
    );
    setSelected(null);
    setProjection(null);
    setRaw(null);
    setRows([]);
    setPage(null);
    setError(null);
    sync({
      current_route: next,
      current_panel: comm ? "COMMUNICATIONS" : null,
      selected_file_node_ids: [],
      selected_artifact_ids: [],
      selected_media_artifact_ids: [],
      selected_browser_artifact_ids: [],
      selected_timeline_event_ids: [],
      selected_search_result_ids: [],
      selected_candidate_ids: [],
    });
  }
  function chooseEvidence(id: string) {
    setEvidenceId(id);
    setFolder(null);
    setFolderTrail([]);
    setSelected(null);
    setRows([]);
    sync({
      active_evidence_id: id || null,
      selected_file_node_ids: [],
      selected_artifact_ids: [],
      selected_media_artifact_ids: [],
      selected_browser_artifact_ids: [],
      selected_timeline_event_ids: [],
      selected_search_result_ids: [],
      selected_candidate_ids: [],
    });
  }
  function openFolder(n: Row, trail?: Row[]) {
    setFolder(n);
    setSelected(null);
    setFolderTrail((old) => {
      if (trail) return trail;
      const index = old.findIndex((item) => item.id === n.id);
      return index >= 0 ? old.slice(0, index + 1) : [...old, n];
    });
    sync({
      active_filters: { parent_node_id: n.id },
      selected_file_node_ids: [],
      selected_artifact_ids: [],
      selected_media_artifact_ids: [],
      selected_browser_artifact_ids: [],
      selected_timeline_event_ids: [],
      selected_search_result_ids: [],
      selected_candidate_ids: [],
    });
  }
  function openTreeNode(id: string, node: Row, trail: Row[]) {
    if (id !== evidenceId) chooseEvidence(id);
    if (route !== "FILE_SYSTEM") navigate("FILE_SYSTEM");
    if (["ROOT", "DIRECTORY"].includes(node.node_type)) {
      openFolder(node, trail);
    } else {
      const parent = trail.at(-2);
      if (parent) openFolder(parent, trail.slice(0, -1));
      select({
        ...node,
        _resource_type: "FILE_SYSTEM_NODE",
        _resource_id: node.id,
      });
    }
  }
  useEffect(() => {
    if (route !== "FILE_SYSTEM" || !evidenceId) {
      setRoots([]);
      return;
    }
    let live = true;
    gateway
      .call<Row[]>("files.roots", { case_id: caseId, evidence_id: evidenceId })
      .then((r) => {
        if (live) {
          setRoots(r);
          setFolder((prev) => prev ?? r[0] ?? null);
          setFolderTrail((prev) =>
            prev.length ? prev : r.length ? [r[0]] : [],
          );
        }
      })
      .catch((err) => live && setError(err));
    return () => {
      live = false;
    };
  }, [route, evidenceId, caseId, revision]);
  const loadPage = useCallback(
    async (cursor: string | null = null) => {
      if (
        !caseId ||
        ["CASE_OVERVIEW", "EVIDENCE", "REPORT", "SETTINGS"].includes(route)
      )
        return;
      const rid = ++requestRevision.current;
      setLoading(true);
      setError(null);
      const input: Row = {
        case_id: caseId,
        evidence_id: evidenceId || null,
        cursor,
        limit: 100,
      };
      let op = "";
      if (route === "FILE_SYSTEM") {
        if (!evidenceId || !folder) {
          setLoading(false);
          setRows([]);
          return;
        }
        op = "files.list";
        input.parent_node_id = folder.id;
      } else if (investigate.includes(route)) {
        op = "artifacts.list";
        input.artifact_type = artifactType || null;
      } else if (route === "SEARCH") {
        if (!searchText) {
          setLoading(false);
          return;
        }
        op = "search.query";
        input.query_text = searchText;
        input.query_mode = searchMode;
      } else if (route === "TIMELINE") op = "timeline.list";
      else if (route === "CANDIDATES") op = "candidates.list";
      else if (route === "CHAIN_OF_CUSTODY") {
        if (!evidenceId) {
          setLoading(false);
          return;
        }
        op = "custody.list";
        delete input.cursor;
        delete input.limit;
      }
      if (!op) {
        setLoading(false);
        return;
      }
      try {
        const result = await gateway.call(op, input);
        if (rid !== requestRevision.current) return;
        const list = Array.isArray(result)
          ? result
          : (result.items ?? result.results ?? []);
        setPage(Array.isArray(result) ? { items: result } : result);
        setRows(list);
        // A file picked in the tree can precede its parent's list response.
        // Keep that selection while this same directory finishes loading.
        setSelected((previous) =>
          op === "files.list" &&
          previous?.evidence_id === evidenceId &&
          previous?.parent_node_id === folder?.id
            ? previous
            : null,
        );
        if (op === "search.query")
          sync({
            active_search_execution_id: result.execution.execution_id,
            active_filters: { query_mode: searchMode, query_text: searchText },
          });
      } catch (err) {
        if (rid === requestRevision.current) {
          setError(err);
          setRows([]);
        }
      } finally {
        if (rid === requestRevision.current) setLoading(false);
      }
    },
    [
      caseId,
      evidenceId,
      route,
      folder?.id,
      artifactType,
      searchText,
      searchMode,
      sync,
    ],
  );
  useEffect(() => {
    void loadPage();
    return () => {
      requestRevision.current++;
    };
  }, [loadPage, revision]);
  function resource(row: Row): { type: string; id: string } {
    if (row._resource_type)
      return { type: row._resource_type, id: row._resource_id };
    if (route === "FILE_SYSTEM")
      return { type: "FILE_SYSTEM_NODE", id: row.id };
    if (route === "TIMELINE")
      return { type: "TIMELINE_EVENT", id: row.timeline_event_id };
    if (route === "SEARCH")
      return {
        type: "SEARCH_RESULT",
        id: row.result_id ?? row.search_result_id,
      };
    if (route === "CANDIDATES")
      return { type: "MACHINE_CANDIDATE", id: row.candidate_id };
    if (route === "EVIDENCE") return { type: "EVIDENCE", id: row.id };
    if (route === "CHAIN_OF_CUSTODY")
      return { type: "CUSTODY_EVENT", id: row.id ?? row.event_id };
    return { type: "ARTIFACT", id: row.id };
  }
  function select(row: Row) {
    setSelected(row);
    setInspector(true);
    setMode("SIMPLE");
    setRaw(null);
    setRawOffset(0);
    const r = resource(row);
    const keys: Record<string, string> = {
      FILE_SYSTEM_NODE: "selected_file_node_ids",
      ARTIFACT: "selected_artifact_ids",
      TIMELINE_EVENT: "selected_timeline_event_ids",
      SEARCH_RESULT: "selected_search_result_ids",
      MACHINE_CANDIDATE: "selected_candidate_ids",
    };
    if (keys[r.type])
      sync({
        [keys[r.type]]: [r.id],
        ...(r.type === "ARTIFACT" && route === "MEDIA"
          ? { selected_media_artifact_ids: [r.id] }
          : {}),
        ...(r.type === "ARTIFACT" && route === "BROWSER"
          ? { selected_browser_artifact_ids: [r.id] }
          : {}),
      });
  }
  function collectCitations(citations: Row[]) {
    setReportCitations((previous) => {
      const items = new Map(
        previous.map((citation) => [JSON.stringify(citation), citation]),
      );
      for (const citation of citations)
        items.set(JSON.stringify(citation), citation);
      return [...items.values()];
    });
    setNotice("선택한 인용을 새 보고서 버전의 근거로 추가했습니다.");
  }
  useEffect(() => {
    setProjection(null);
    setViewError(null);
    if (!selected || route === "FILE_SYSTEM") return;
    let live = true;
    const r = resource(selected);
    gateway
      .call("view", {
        case_id: caseId,
        resource_type: r.type,
        resource_id: r.id,
        view_mode: mode,
      })
      .then((p) => live && setProjection(p))
      .catch((err) => live && setViewError(err));
    return () => {
      live = false;
    };
  }, [selected, mode, caseId, route]);
  useEffect(() => {
    rawRequestRevision.current++;
    setRaw(null);
    return () => {
      rawRequestRevision.current++;
    };
  }, [selected, caseId, evidenceId, route, mode, rawOffset, rawLength]);
  async function run(kind: string) {
    if (!evidenceId) return;
    try {
      await gateway.call("analysis.start", {
        case_id: caseId,
        evidence_id: evidenceId,
        kind,
        profile_type: profile,
        algorithm: hash,
      });
      setJobsOpen(true);
      refresh();
    } catch (err) {
      setError(err);
    }
  }
  async function addEvidence(kind: "file" | "directory") {
    try {
      if (!window.apex) return;
      const picked = unwrap(await window.apex.pick(kind));
      if (!picked) return;
      await gateway.call("evidence.register", {
        case_id: caseId,
        source_reference: picked.reference,
        display_name: picked.name,
      });
      setJobsOpen(true);
    } catch (err) {
      setError(err);
    }
  }
  function newCase() {
    setDialog({
      title: "새 사건 만들기",
      fields: [
        { key: "name", label: "사건 이름", required: true, max: 255 },
        { key: "investigator", label: "분석자 이름", max: 255 },
        { key: "description", label: "사건 설명", type: "textarea", max: 8192 },
        {
          key: "timezone",
          label: "시간대 (IANA)",
          default: "Asia/Seoul",
          required: true,
        },
      ],
      submit: async (f) => {
        const c = await gateway.call<CaseRecord>("cases.create", {
          ...f,
          locale: "ko-KR",
        });
        await bootstrap();
        setCaseId(c.id);
        setRoute("FILE_SYSTEM");
      },
    });
  }
  const fileColumns: Column[] = [
    {
      key: "original_name",
      label: "이름",
      width: 240,
      render: (r) => (
        <span className="file-name">
          <FileIcon row={r} />
          <span>{r.original_name}</span>
        </span>
      ),
    },
    {
      key: "extension",
      label: "확장자 / 유형",
      width: 100,
      render: (r) =>
        r.node_type === "DIRECTORY" ? "폴더" : (r.extension ?? r.node_type),
    },
    {
      key: "file_size",
      label: "크기",
      width: 100,
      render: (r) => size(r.file_size),
    },
    {
      key: "created",
      label: "생성 시간",
      width: 165,
      render: (r) => time(r.utc_timestamps?.created, zone),
    },
    {
      key: "modified",
      label: "수정 시간",
      width: 165,
      render: (r) => time(r.utc_timestamps?.modified, zone),
    },
    {
      key: "is_deleted",
      label: "삭제 상태",
      width: 100,
      render: (r) => (r.is_deleted ? <Badge value="삭제됨" /> : "—"),
    },
    {
      key: "is_partial",
      label: "분석 상태",
      width: 100,
      render: (r) => (r.is_partial ? <Badge value="PARTIAL" /> : "관찰됨"),
    },
    { key: "mime_candidate", label: "MIME", width: 120 },
  ];
  const artifactColumns: Column[] = [
    {
      key: "title",
      label: "제목",
      width: 250,
      render: (r) => (
        <span className="file-name">
          {r.title} <ArtifactSemantics row={r} />
        </span>
      ),
    },
    { key: "artifact_type", label: "유형", width: 150 },
    {
      key: "observed_at_utc",
      label: "관찰 시간",
      width: 170,
      render: (r) => time(r.observed_at_utc, zone),
    },
    {
      key: "parse_status",
      label: "파싱 상태",
      render: (r) => <Badge value={r.parse_status} />,
    },
    { key: "confidence", label: "신뢰도" },
    { key: "source_path", label: "소스", width: 220 },
    {
      key: "is_partial",
      label: "부분 결과",
      render: (r) => (r.is_partial ? <Badge value="PARTIAL" /> : "—"),
    },
  ];
  const columns =
    route === "FILE_SYSTEM"
      ? fileColumns
      : route === "SEARCH"
        ? [
            {
              key: "result_order",
              label: "검색 순번",
              render: (r: Row) => rows.indexOf(r) + 1,
            },
            {
              key: "rank",
              label: "관련도 점수",
              render: (r: Row) =>
                typeof r.rank === "number" ? (
                  <span title="BM25 점수 · 낮을수록 관련도가 높습니다">
                    {r.rank.toExponential(3)}
                  </span>
                ) : (
                  "—"
                ),
            },
            { key: "source_id", label: "소스 ID", width: 260 },
            { key: "snippet", label: "일치 내용", width: 300 },
            { key: "source_type", label: "소스 유형" },
            { key: "matched_terms", label: "일치 검색어" },
          ]
        : route === "TIMELINE"
          ? [
              {
                key: "normalized_utc",
                label: "표시 시각",
                width: 190,
                render: (r: Row) =>
                  r.normalized_utc
                    ? time(r.normalized_utc, zone)
                    : "시간대 미확정",
              },
              { key: "event_type", label: "이벤트 유형", width: 200 },
              { key: "title", label: "제목", width: 280 },
              { key: "source_type", label: "출처", width: 160 },
              { key: "timezone_confidence", label: "시간대 신뢰도" },
            ]
          : route === "CANDIDATES"
            ? [
                { key: "text", label: "추출 텍스트", width: 320 },
                { key: "extraction_type", label: "유형" },
                {
                  key: "review_status",
                  label: "검토 상태",
                  render: (r: Row) => <Badge value={r.review_status} />,
                },
                { key: "confidence", label: "신뢰도" },
                { key: "source_node_id", label: "소스 ID", width: 220 },
              ]
            : route === "CHAIN_OF_CUSTODY"
              ? [
                  { key: "sequence", label: "순서" },
                  { key: "event_type", label: "유형", width: 130 },
                  { key: "action", label: "행위", width: 230 },
                  {
                    key: "actor",
                    label: "행위자",
                    render: (r: Row) => r.actor?.name ?? r.actor_name,
                  },
                  { key: "occurred_at_utc", label: "시각", width: 180 },
                  { key: "event_hash", label: "이벤트 해시", width: 240 },
                ]
              : artifactColumns;
  return (
    <div
      className="app-shell forensic-workbench"
      style={{ "--evidence-width": `${sidebarWidth}px` } as CSSProperties}
    >
      <a className="skip-link" href="#main-workspace">
        본문으로 건너뛰기
      </a>
      <header className="topbar">
        <button
          className="brand"
          onClick={() => navigate("CASE_OVERVIEW")}
          aria-label="APEX 사건 개요"
        >
          <BrandLogo />
        </button>
        <div className="top-context">
          <span className="context-label">사건</span>
          <select
            aria-label="현재 사건"
            value={caseId}
            onChange={(e) => setCaseId(e.target.value)}
          >
            <option value="">사건 선택</option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
          <span className="divider" />
          <span className="context-label">증거</span>
          <select
            aria-label="현재 증거"
            value={evidenceId}
            onChange={(e) => chooseEvidence(e.target.value)}
            disabled={!caseId}
          >
            <option value="">증거 선택</option>
            {evidence.map((e) => (
              <option key={e.id} value={e.id}>
                {e.display_name}
              </option>
            ))}
          </select>
        </div>
        <div className="top-actions">
          <span className="timezone">
            <Clock3 size={13} />
            {zone}
          </span>
          <button
            onClick={() => setJobsOpen(!jobsOpen)}
            className={tasks.some(activeTask) ? "live" : ""}
          >
            <Activity size={15} /> 작업 {tasks.filter(activeTask).length}
          </button>
          <button title="AI 도우미" onClick={() => setAiOpen(!aiOpen)}>
            <AssistantIcon size={16} />
          </button>
          <span className="local-state">
            <i className={runtime ? "online" : ""} />
            {runtime?.mode === "DEMO_READ_ONLY"
              ? "모의 데이터 · 읽기 전용"
              : "로컬 모드"}
          </span>
        </div>
      </header>
      <div className="command-bar" aria-label="증거 작업">
        <button disabled={!runtime} onClick={newCase}>
          <Plus size={14} />새 사건
        </button>
        <span className="command-divider" />
        <button disabled={!caseId} onClick={() => addEvidence("file")}>
          <HardDrive size={15} />
          이미지 추가
        </button>
        <button disabled={!caseId} onClick={() => addEvidence("directory")}>
          <FolderOpen size={15} />
          폴더 추가
        </button>
        <span className="command-divider" />
        <button disabled={!evidenceId} onClick={() => navigate("EVIDENCE")}>
          <ShieldCheck size={15} />
          증거 관리
        </button>
        <button disabled={!caseId} onClick={() => navigate("SEARCH")}>
          <Search size={15} />
          검색
        </button>
        <button disabled={!caseId} onClick={() => navigate("REPORT")}>
          <Files size={15} />
          보고서
        </button>
        <span className="spacer" />
        <button
          onClick={() => {
            setSidebarWidth(280);
            setInspectorHeight(340);
            setInspector(true);
          }}
        >
          패널 배치 초기화
        </button>
        <button
          aria-label="화면 새로고침"
          title="화면 새로고침"
          onClick={() => {
            refresh();
            void bootstrap();
          }}
        >
          <RefreshCw size={14} />
        </button>
      </div>
      <aside className="evidence-pane" aria-label="증거 탐색 및 속성">
        <section className="tree-pane">
          <header className="pane-title">
            <h2>증거 트리</h2>
            <span className="pane-caption">{evidence.length}개 증거</span>
          </header>
          <div className="tree-case">
            <Archive size={14} />
            <span>{currentCase?.name ?? "사건 미선택"}</span>
          </div>
          <EvidenceTree
            caseId={caseId}
            evidence={evidence}
            evidenceId={evidenceId}
            folderId={folder?.id ?? ""}
            selectedNode={
              route === "FILE_SYSTEM" &&
              selected &&
              resource(selected).type === "FILE_SYSTEM_NODE"
                ? selected
                : null
            }
            trail={folderTrail}
            revision={revision}
            onOpen={openTreeNode}
            onEvidence={(id) => {
              if (route !== "FILE_SYSTEM") navigate("FILE_SYSTEM");
              if (id === evidenceId && roots[0])
                openFolder(roots[0], [roots[0]]);
              else chooseEvidence(id);
            }}
          />
          <div className="tree-readonly">
            <ShieldCheck size={12} />
            원본 증거 읽기 전용
          </div>
        </section>
        <section
          className="properties-pane"
          aria-label="선택 항목 속성"
          style={{ height: inspectorHeight }}
        >
          <Splitter
            axis="horizontal"
            label="속성 패널 높이 조절"
            value={inspectorHeight}
            min={180}
            max={Math.max(180, Math.floor(window.innerHeight * 0.65))}
            onChange={setInspectorHeight}
          />
          <header className="pane-title">
            <h2>속성</h2>
            <span className="pane-caption">Properties</span>
          </header>
          <Properties
            row={selected ?? (route === "FILE_SYSTEM" ? folder : null)}
            evidence={currentEvidence}
            zone={zone}
          />
        </section>
      </aside>
      <Splitter
        axis="vertical"
        label="증거 패널 너비 조절"
        value={sidebarWidth}
        min={210}
        max={Math.max(210, Math.min(480, window.innerWidth * 0.4))}
        onChange={setSidebarWidth}
      />
      <main className="workspace" id="main-workspace" tabIndex={-1}>
        <nav className="workspace-tabs" aria-label="분석 화면">
          {(Object.keys(routeNames) as Route[]).map((r) => (
            <button
              key={r}
              aria-current={route === r && !communication ? "page" : undefined}
              className={route === r && !communication ? "active" : ""}
              onClick={() => navigate(r)}
            >
              {routeNames[r]}
            </button>
          ))}
          <button
            aria-current={communication ? "page" : undefined}
            className={communication ? "active" : ""}
            onClick={() => navigate("ARTIFACTS", true)}
          >
            커뮤니케이션
          </button>
        </nav>
        <header className="workspace-header">
          <h1>
            {route === "FILE_SYSTEM"
              ? "파일 목록"
              : communication
                ? "커뮤니케이션"
                : routeNames[route]}
          </h1>
          <span className="workspace-scope">
            {currentEvidence?.display_name ??
              currentCase?.name ??
              "사건을 선택하세요"}
          </span>
          <span className="pane-caption">
            {route === "FILE_SYSTEM" ? "File List" : "APEX"}
          </span>
        </header>
        {notice && (
          <div className="notice">
            <span>{notice}</span>
            <button aria-label="알림 닫기" onClick={() => setNotice("")}>
              <X size={14} />
            </button>
          </div>
        )}
        {startupError != null && (
          <ErrorState error={startupError} retry={bootstrap} />
        )}{" "}
        {conflict && (
          <div className="notice">
            <span>
              선택 상태가 변경되었습니다. 최신 컨텍스트 r
              {context?.context_revision}을 불러왔습니다.
            </span>
            <button
              onClick={() => {
                const pending = conflictRef.current ?? conflict;
                conflictRef.current = null;
                setConflict(null);
                sync(pending);
              }}
            >
              내 선택 다시 적용
            </button>
            <button
              onClick={() => {
                conflictRef.current = null;
                setConflict(null);
                setSelected(null);
                setFolder(null);
                setFolderTrail([]);
                setRows([]);
                setPage(null);
                setRoute(context?.current_route ?? "CASE_OVERVIEW");
                setEvidenceId(context?.active_evidence_id ?? "");
                setCommunication(context?.current_panel === "COMMUNICATIONS");
                refresh();
              }}
            >
              최신 상태 사용
            </button>
          </div>
        )}
        {route === "CASE_OVERVIEW" ? (
          <div className="overview scroll">
            <section className="case-summary" aria-label="사건 상태">
              <div className="case-intro">
                <h2>{currentCase?.name ?? "조사할 사건을 선택하세요"}</h2>
                <p className="muted">
                  {currentCase
                    ? currentCase.description ||
                      "이 사건에 등록된 증거와 분석 작업을 확인합니다."
                    : "새 사건을 만들고 디스크 이미지 또는 폴더를 등록하세요."}
                </p>
                {!currentCase && (
                  <p className="muted small">로그인 없이 시작할 수 있습니다</p>
                )}
              </div>
              {currentCase && (
                <>
                  <dl className="case-metadata">
                    <div>
                      <dt>사건 ID</dt>
                      <dd className="mono">{currentCase.id}</dd>
                    </div>
                    <div>
                      <dt>상태</dt>
                      <dd>
                        <Badge value={currentCase.status} />
                      </dd>
                    </div>
                    <div>
                      <dt>표시 시간대</dt>
                      <dd>{zone}</dd>
                    </div>
                    <div>
                      <dt>등록된 증거</dt>
                      <dd>
                        {evidence.length}개{" "}
                        <button
                          className="text-button"
                          onClick={() => navigate("EVIDENCE")}
                        >
                          증거 관리 <ChevronRight size={12} />
                        </button>
                      </dd>
                    </div>
                    <div>
                      <dt>분석 작업</dt>
                      <dd>
                        진행 {tasks.filter(activeTask).length} · 완료{" "}
                        {tasks.filter((t) => t.status === "SUCCEEDED").length}
                      </dd>
                    </div>
                    <div>
                      <dt>원본 접근</dt>
                      <dd>읽기 전용</dd>
                    </div>
                  </dl>
                  {tasks.some((t) =>
                    ["PARTIAL", "FAILED", "INTERRUPTED"].includes(t.status),
                  ) && (
                    <div className="notice">
                      <span>
                        확인이 필요한 분석 작업이 있습니다. 작업 상태와 경고를
                        확인하세요.
                      </span>
                      <button onClick={() => setJobsOpen(true)}>
                        작업 보기
                      </button>
                    </div>
                  )}
                </>
              )}
            </section>
            <div className="section-heading">
              <h3>
                사건 목록 <span>{cases.length}</span>
              </h3>
              <span className="muted small">이 장치에 저장된 조사</span>
            </div>
            {cases.length ? (
              <Table
                rows={cases}
                selected={caseId}
                onSelect={(c) => setCaseId(c.id)}
                columns={[
                  { key: "name", label: "사건 이름", width: 260 },
                  {
                    key: "status",
                    label: "상태",
                    render: (r) => <Badge value={r.status} />,
                  },
                  { key: "created_by", label: "분석자" },
                  {
                    key: "created_at",
                    label: "생성 시각",
                    render: (r) => time(r.created_at, zone),
                  },
                  { key: "timezone", label: "시간대" },
                ]}
              />
            ) : (
              <Empty title="저장된 사건이 없습니다">
                상단의 ‘새 사건’에서 조사를 시작하세요.
              </Empty>
            )}
          </div>
        ) : route === "SETTINGS" ? (
          <div className="settings scroll">
            <AccountPanel />
            {caseId && <PolicyPanel key={caseId} caseId={caseId} />}
            <div className="card">
              <h3>런타임 기능</h3>
              <p className="muted">
                각 기능의 실제 설치·검증 상태입니다. 기능이 없으면 결과 0건으로
                표시하지 않습니다.
              </p>
              {runtime && (
                <Table
                  rows={runtime.capabilities.capabilities}
                  columns={[
                    { key: "id", label: "기능", width: 210 },
                    {
                      key: "status",
                      label: "상태",
                      render: (r) => <Badge value={r.status} />,
                    },
                    { key: "version", label: "버전" },
                    { key: "reason", label: "사유", width: 320 },
                    {
                      key: "details",
                      label: "검증 상세",
                      render: (r) => (
                        <details>
                          <summary>상세</summary>
                          <Fields
                            value={{ probe: r.probe, details: r.details }}
                          />
                        </details>
                      ),
                    },
                  ]}
                />
              )}
            </div>
            <div className="card">
              <h3>파생 결과</h3>
              <p className="muted">
                승인된 보고서는 원본 증거와 분리된 폴더에 저장됩니다.
              </p>
              <button
                disabled={!window.apex}
                onClick={() => window.apex?.openExports()}
              >
                <FolderOpen size={15} /> 결과 폴더 열기
              </button>
            </div>
          </div>
        ) : !caseId ? (
          <Empty title="먼저 사건을 선택해주세요">
            상단에서 사건을 선택하거나 새 사건을 만들어주세요.
          </Empty>
        ) : route === "REPORT" ? (
          <Reports
            key={caseId}
            caseId={caseId}
            evidenceId={evidenceId}
            renderer={runtime?.renderer ?? {}}
            citations={reportCitations}
            onNotice={setNotice}
          />
        ) : (
          <>
            <div className="actionbar">
              {route === "EVIDENCE" ? (
                <>
                  <button
                    className="primary"
                    onClick={() => addEvidence("file")}
                  >
                    <Plus size={14} /> 이미지 추가
                  </button>
                  <button onClick={() => addEvidence("directory")}>
                    <FolderOpen size={14} /> 폴더 추가
                  </button>
                  <span className="muted small">형식은 엔진이 판별합니다</span>
                </>
              ) : route === "SEARCH" ? (
                <form
                  className="search-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    setSearchText(query);
                    refresh();
                  }}
                >
                  <Search size={16} />
                  <input
                    aria-label="검색어"
                    placeholder="파일 이름, 경로 또는 아티팩트 검색"
                    maxLength={searchMode === "REGEX_METADATA" ? 512 : 4096}
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    required
                  />
                  <select
                    aria-label="검색 방식"
                    value={searchMode}
                    onChange={(e) => setSearchMode(e.target.value)}
                  >
                    {[
                      "TERM",
                      "PHRASE",
                      "PREFIX",
                      "EXACT",
                      "REGEX_METADATA",
                    ].map((m) => (
                      <option key={m}>{m}</option>
                    ))}
                  </select>
                  <span className="muted small">
                    {query.length}/
                    {searchMode === "REGEX_METADATA" ? 512 : 4096}
                  </span>
                  <button className="primary">검색</button>
                </form>
              ) : route === "FILE_SYSTEM" ? (
                <div className="folder-address">
                  <button
                    aria-label="상위 폴더로 이동"
                    title="상위 폴더로 이동"
                    disabled={folderTrail.length < 2}
                    onClick={() =>
                      openFolder(
                        folderTrail[folderTrail.length - 2],
                        folderTrail.slice(0, -1),
                      )
                    }
                  >
                    <PanelBottomOpen size={14} />
                  </button>
                  <nav aria-label="폴더 경로">
                    {folderTrail.map((item, index) => (
                      <span key={item.id}>
                        {index > 0 && <ChevronRight size={11} />}
                        <button
                          aria-current={
                            index === folderTrail.length - 1
                              ? "location"
                              : undefined
                          }
                          onClick={() =>
                            openFolder(item, folderTrail.slice(0, index + 1))
                          }
                        >
                          {index === 0 ? "/" : item.original_name}
                        </button>
                      </span>
                    ))}
                  </nav>
                </div>
              ) : (
                <span className="path mono">
                  {currentEvidence?.display_name ?? "사건 전체"}
                </span>
              )}
              {[
                "FILE_SYSTEM",
                "EVIDENCE",
                "ARTIFACTS",
                "REGISTRY",
                "EVENT_LOG",
                "PREFETCH",
                "BROWSER",
                "MEDIA",
                "SEARCH",
                "TIMELINE",
              ].includes(route) && (
                <div className="analysis-controls">
                  <select
                    aria-label="분석 범위"
                    value={profile}
                    onChange={(e) => setProfile(e.target.value)}
                  >
                    <option value="QUICK_TRIAGE">빠른 초기 분석</option>
                    <option value="FULL_ANALYSIS">전체 분석</option>
                  </select>
                  <button
                    disabled={!evidenceId}
                    onClick={() =>
                      run(
                        route === "SEARCH"
                          ? "SEARCH"
                          : route === "TIMELINE"
                            ? "TIMELINE"
                            : route === "EVIDENCE" || route === "FILE_SYSTEM"
                              ? "FILES"
                              : "ARTIFACTS",
                      )
                    }
                  >
                    <Play size={13} />
                    {route === "SEARCH"
                      ? "검색 인덱스 생성"
                      : route === "TIMELINE"
                        ? "타임라인 생성"
                        : "분석 시작"}
                  </button>
                </div>
              )}
            </div>
            {(categoryTypes[route] || communication) && (
              <div className="tabs">
                {(communication
                  ? communicationTypes
                  : (categoryTypes[route] ?? [])
                ).map((t) => (
                  <button
                    key={t}
                    className={artifactType === t ? "active" : ""}
                    onClick={() => {
                      setArtifactType(t);
                      sync({ active_filters: { artifact_type: t } });
                    }}
                  >
                    {typeLabels[t] ?? t}
                  </button>
                ))}
              </div>
            )}
            {error != null && (
              <ErrorState error={error} retry={() => loadPage()} />
            )}
            <ResultState data={page?.execution ?? page} />
            {communication && (
              <div className="notice">
                <span>
                  KakaoTalk은 Windows Desktop 2.0.8.990 외부 키 기반의 제한
                  경로입니다. 외부 키가 필요하며, 자동 키 획득과 Android·iOS
                  분석은 지원하지 않습니다. 실제 실행 가능 여부는 런타임 검증
                  상태를 확인하세요.
                </span>
              </div>
            )}
            {route === "EVENT_LOG" &&
              runtime?.capabilities.capabilities.some(
                (c: Row) =>
                  c.id === "windows-event-message-renderer" &&
                  !["AVAILABLE", "AVAILABLE_WITH_LIMITATIONS"].includes(
                    c.status,
                  ),
              ) && (
                <div className="notice">
                  <span>
                    이 환경에서는 Windows 이벤트 메시지를 렌더링할 수 없습니다.
                    이벤트 기록과 원본 필드는 계속 확인할 수 있습니다.
                  </span>
                </div>
              )}
            {route === "CANDIDATES" && (
              <div className="notice">
                OCR·STT 결과는 자동 추출 후보입니다. 관찰 사실과 구분하여 원본을
                검토하세요.
              </div>
            )}
            <div className="results-area">
              {loading ? (
                <Loading />
              ) : route === "EVIDENCE" ? (
                evidence.length ? (
                  <Table
                    rows={evidence}
                    selected={selected ? rowId(selected) : ""}
                    onSelect={select}
                    columns={[
                      { key: "display_name", label: "증거 이름", width: 260 },
                      { key: "format", label: "형식" },
                      {
                        key: "size_bytes",
                        label: "크기",
                        render: (r) => size(r.size_bytes),
                      },
                      {
                        key: "status",
                        label: "상태",
                        render: (r) => <Badge value={r.status} />,
                      },
                      {
                        key: "read_only",
                        label: "접근",
                        render: () => <Badge value="읽기 전용" />,
                      },
                      {
                        key: "reader",
                        label: "리더",
                        render: (r) => r.reader?.id,
                      },
                    ]}
                  />
                ) : (
                  <Empty title="등록된 증거가 없습니다">
                    이미지 추가 또는 폴더 추가로 분석할 증거를 선택하세요.
                  </Empty>
                )
              ) : error != null ? null : rows.length ? (
                <Table
                  rows={rows}
                  columns={columns}
                  onSort={(sort) =>
                    sync({ active_sort: { ...sort, scope: "LOADED_PAGE" } })
                  }
                  selected={selected ? rowId(selected) : ""}
                  onSelect={select}
                  onOpen={(r) => {
                    if (
                      route === "FILE_SYSTEM" &&
                      ["ROOT", "DIRECTORY"].includes(r.node_type)
                    )
                      openFolder(r);
                  }}
                />
              ) : (
                <Empty
                  title={
                    route === "SEARCH" && !searchText
                      ? "검색어를 입력해주세요"
                      : "조회 결과가 없습니다"
                  }
                >
                  {route === "FILE_SYSTEM"
                    ? folder
                      ? "이 폴더에서 확인된 항목이 없습니다. 다른 폴더 또는 분석 범위를 확인하세요."
                      : "증거를 선택하고 파일 인덱스를 생성해주세요."
                    : "선택한 범위의 분석·인덱스 상태를 확인해주세요."}
                </Empty>
              )}
            </div>
            <div className="pagination">
              <span>
                {route === "EVIDENCE" ? evidence.length : rows.length}개 표시 ·
                원본 상태 유지
              </span>
              <div>
                <span className="muted">현재 페이지 정렬</span>
                {page?.page?.has_more && (
                  <button onClick={() => loadPage(page.page.next_cursor)}>
                    다음 결과 <ChevronRight size={13} />
                  </button>
                )}
                <button
                  title={inspector ? "검사기 접기" : "검사기 펼치기"}
                  onClick={() => setInspector(!inspector)}
                >
                  {inspector ? (
                    <PanelBottomClose size={15} />
                  ) : (
                    <PanelBottomOpen size={15} />
                  )}
                </button>
              </div>
            </div>
            {inspector && route === "FILE_SYSTEM" && (
              <FileViewer
                key={`${caseId}:${evidenceId}:${selected?._resource_type ?? "FILE_SYSTEM_NODE"}:${selected?.id ?? "empty"}`}
                caseId={caseId}
                selected={selected}
                height={inspectorHeight}
                onHeight={setInspectorHeight}
                onCollect={collectCitations}
                onSelect={select}
              />
            )}
            {inspector && route !== "FILE_SYSTEM" && (
              <section
                className="inspector"
                aria-label="선택 항목 검사기"
                style={{ height: inspectorHeight }}
              >
                <div
                  className="inspector-resizer"
                  role="separator"
                  aria-label="검사기 높이 조절"
                  aria-orientation="horizontal"
                  aria-valuenow={inspectorHeight}
                  aria-valuemin={150}
                  aria-valuemax={Math.floor(window.innerHeight / 2)}
                  tabIndex={0}
                  onPointerDown={(e) => {
                    resizeOrigin.current = {
                      y: e.clientY,
                      height: inspectorHeight,
                    };
                    e.currentTarget.setPointerCapture(e.pointerId);
                  }}
                  onPointerMove={(e) => {
                    if (resizeOrigin.current)
                      setInspectorHeight(
                        Math.round(
                          Math.max(
                            150,
                            Math.min(
                              window.innerHeight / 2,
                              resizeOrigin.current.height +
                                resizeOrigin.current.y -
                                e.clientY,
                            ),
                          ),
                        ),
                      );
                  }}
                  onPointerUp={() => {
                    resizeOrigin.current = null;
                  }}
                  onPointerCancel={() => {
                    resizeOrigin.current = null;
                  }}
                  onKeyDown={(e) => {
                    if (
                      ["ArrowUp", "ArrowDown", "Home", "End"].includes(e.key)
                    ) {
                      e.preventDefault();
                      setInspectorHeight((h) =>
                        Math.round(
                          Math.max(
                            150,
                            Math.min(
                              window.innerHeight / 2,
                              e.key === "Home"
                                ? 150
                                : e.key === "End"
                                  ? window.innerHeight / 2
                                  : h + (e.key === "ArrowUp" ? 25 : -25),
                            ),
                          ),
                        ),
                      );
                    }
                  }}
                />
                <header>
                  <div>
                    <span className="muted small">선택 항목 검사기</span>
                    <h3>
                      {selected?.original_name ??
                        selected?.title ??
                        selected?.display_name ??
                        "항목을 선택해주세요"}
                    </h3>
                  </div>
                  <div className="tabs compact" aria-label="검사기 보기">
                    {(["SIMPLE", "DETAILED", "RAW"] as const).map((m, i) => (
                      <button
                        key={m}
                        className={mode === m ? "active" : ""}
                        aria-pressed={mode === m}
                        disabled={
                          !selected ||
                          (m === "RAW" &&
                            !!projection &&
                            !projection.available_actions?.includes("view.raw"))
                        }
                        onClick={() => setMode(m)}
                      >
                        {["간단히", "상세히", "원본"][i]}
                      </button>
                    ))}
                  </div>
                </header>
                <div className="inspector-content">
                  {!selected ? (
                    <p className="muted">
                      목록에서 항목을 선택하면 요약·출처·원본을 확인할 수
                      있습니다.
                    </p>
                  ) : viewError != null ? (
                    <ErrorState error={viewError} />
                  ) : !projection ? (
                    <Loading />
                  ) : (
                    <>
                      <ResultState data={projection} />
                      {projection.badges?.length > 0 && (
                        <div className="toolbar projection-badges">
                          {projection.badges.map((b: string) => (
                            <Badge key={b} value={b} />
                          ))}
                        </div>
                      )}
                      {selected && <ArtifactSemantics row={selected} />}
                      {(selected.artifact_type === "MEDIA_IMAGE" ||
                        (resource(selected).type === "FILE_SYSTEM_NODE" &&
                          /\.(png|jpe?g|gif|tiff?|bmp|webp)$/i.test(
                            selected.original_name ?? selected.title ?? "",
                          ))) && (
                        <ImageInspector
                          key={`${caseId}:${resource(selected).type}:${resource(selected).id}`}
                          caseId={caseId}
                          resourceType={resource(selected).type}
                          resourceId={resource(selected).id}
                        />
                      )}
                      <p className="summary-text">
                        {labels[projection.summary] ?? projection.summary}
                      </p>
                      {mode === "RAW" ? (
                        <>
                          <div className="raw-controls">
                            <label>
                              오프셋
                              <input
                                type="number"
                                min={0}
                                value={rawOffset}
                                onChange={(e) =>
                                  setRawOffset(Number(e.target.value))
                                }
                              />
                            </label>
                            <label>
                              길이 (최대 1 MiB)
                              <input
                                type="number"
                                min={1}
                                max={1048576}
                                value={rawLength}
                                onChange={(e) =>
                                  setRawLength(Number(e.target.value))
                                }
                              />
                            </label>
                            <button
                              disabled={
                                !projection.available_actions?.includes(
                                  "view.raw-read",
                                ) ||
                                !Number.isSafeInteger(rawOffset) ||
                                !Number.isSafeInteger(rawLength) ||
                                rawOffset < 0 ||
                                rawLength < 1 ||
                                rawLength > 1048576
                              }
                              onClick={async () => {
                                const revision = ++rawRequestRevision.current;
                                try {
                                  const r = resource(selected);
                                  const result = await gateway.call(
                                    "raw.read",
                                    {
                                      case_id: caseId,
                                      resource_type: r.type,
                                      resource_id: r.id,
                                      offset: rawOffset,
                                      length: rawLength,
                                    },
                                  );
                                  if (revision !== rawRequestRevision.current)
                                    return;
                                  setRaw(result);
                                  setViewError(null);
                                } catch (err) {
                                  if (revision === rawRequestRevision.current)
                                    setViewError(err);
                                }
                              }}
                            >
                              원본 범위 읽기
                            </button>
                          </div>
                          {raw && (
                            <>
                              <ResultState data={raw} />
                              <RawPreview data={raw} />
                            </>
                          )}
                          <Fields value={projection.raw_fields} />
                        </>
                      ) : (
                        <>
                          <Fields value={projection.primary_fields} />
                          {mode === "DETAILED" && (
                            <>
                              <Fields value={projection.secondary_fields} />
                              <Fields value={projection.technical_fields} />
                              <Fields value={projection.timestamps} />
                              <Fields
                                value={{
                                  analyzer_id: projection.analyzer_id,
                                  analyzer_version: projection.analyzer_version,
                                  source_revision: projection.source_revision,
                                  timezone: projection.timezone,
                                  confidence: projection.confidence,
                                }}
                              />
                            </>
                          )}
                        </>
                      )}
                      <Section
                        title={`인용 근거 · ${projection.citations?.length ?? 0}건`}
                        initial
                      >
                        <Fields value={projection.citations} />
                        {projection.citations?.map((c: Row, i: number) => {
                          const types: Record<string, string> = {
                            FILE: "FILE_SYSTEM_NODE",
                            FILE_SYSTEM_NODE: "FILE_SYSTEM_NODE",
                            ARTIFACT: "ARTIFACT",
                            TIMELINE_EVENT: "TIMELINE_EVENT",
                          };
                          const type = types[c.source_kind ?? c.source_type];
                          return type && c.source_id ? (
                            <button
                              key={i}
                              onClick={() =>
                                select({
                                  _resource_type: type,
                                  _resource_id: c.source_id,
                                  id: c.source_id,
                                  title: "인용 원본",
                                })
                              }
                            >
                              인용 {i + 1} 원본 보기
                            </button>
                          ) : null;
                        })}
                        {projection.citations?.length > 0 && (
                          <button
                            onClick={() =>
                              collectCitations(projection.citations)
                            }
                          >
                            보고서 근거로 추가
                          </button>
                        )}
                      </Section>
                      <Section title="원본 위치 및 출처">
                        <Fields value={projection.raw_locator} />
                      </Section>
                      <div className="toolbar">
                        {route === "EVIDENCE" && (
                          <>
                            <select
                              aria-label="해시 알고리즘"
                              value={hash}
                              onChange={(e) => setHash(e.target.value)}
                            >
                              {["SHA256", "SHA1", "MD5"].map((v) => (
                                <option key={v}>{v}</option>
                              ))}
                            </select>
                            <button
                              disabled={selected.format === "DIRECTORY"}
                              onClick={async () => {
                                try {
                                  await gateway.call("analysis.start", {
                                    case_id: caseId,
                                    evidence_id: selected.id,
                                    kind: "HASH",
                                    algorithm: hash,
                                  });
                                  setJobsOpen(true);
                                } catch (err) {
                                  setError(err);
                                }
                              }}
                            >
                              해시 계산
                            </button>
                            <button
                              disabled={
                                selected.format === "DIRECTORY" ||
                                !evidence
                                  .find((e) => e.id === selected.id)
                                  ?.hashes?.some(
                                    (h: Row) => h.algorithm === hash,
                                  )
                              }
                              onClick={async () => {
                                try {
                                  await gateway.call("analysis.start", {
                                    case_id: caseId,
                                    evidence_id: selected.id,
                                    kind: "VERIFY",
                                    algorithm: hash,
                                  });
                                  setJobsOpen(true);
                                } catch (err) {
                                  setError(err);
                                }
                              }}
                            >
                              무결성 재검증
                            </button>
                            <button
                              onClick={() => {
                                chooseEvidence(selected.id);
                                navigate("CHAIN_OF_CUSTODY");
                              }}
                            >
                              보관 이력
                            </button>
                          </>
                        )}
                        {route === "CANDIDATES" &&
                          ["ACCEPTED", "REJECTED", "CORRECTED"].map(
                            (status) => (
                              <button
                                key={status}
                                onClick={() =>
                                  setDialog({
                                    title:
                                      status === "CORRECTED"
                                        ? "추출 후보 수정 검토"
                                        : "추출 후보 검토",
                                    fields: [
                                      {
                                        key: "reason",
                                        label: "검토 사유",
                                        required: true,
                                        type: "textarea",
                                      },
                                      ...(status === "CORRECTED"
                                        ? [
                                            {
                                              key: "correction_text",
                                              label: "수정 내용",
                                              required: true,
                                              type: "textarea",
                                            },
                                          ]
                                        : []),
                                    ],
                                    submit: async (f) => {
                                      await gateway.call("candidates.review", {
                                        case_id: caseId,
                                        candidate_id: selected.candidate_id,
                                        review_status: status,
                                        ...f,
                                      });
                                      refresh();
                                    },
                                  })
                                }
                              >
                                {status === "ACCEPTED"
                                  ? "채택"
                                  : status === "REJECTED"
                                    ? "거부"
                                    : "수정"}
                              </button>
                            ),
                          )}
                        {route === "CHAIN_OF_CUSTODY" && (
                          <button
                            onClick={() =>
                              setDialog({
                                title: "보관 이력 정정",
                                description:
                                  "기존 기록은 유지하고 정정 이벤트를 추가합니다.",
                                fields: [
                                  {
                                    key: "action",
                                    label: "정정 내용",
                                    required: true,
                                  },
                                  {
                                    key: "reason",
                                    label: "정정 사유",
                                    required: true,
                                  },
                                ],
                                submit: async (f) => {
                                  await gateway.call("custody.add", {
                                    case_id: caseId,
                                    evidence_id: evidenceId,
                                    correction_of_event_id:
                                      selected.id ?? selected.event_id,
                                    ...f,
                                  });
                                  refresh();
                                },
                              })
                            }
                          >
                            정정 기록 추가
                          </button>
                        )}
                      </div>
                    </>
                  )}
                </div>
              </section>
            )}
          </>
        )}
      </main>
      <footer className="statusbar">
        <span>
          <i className={runtime ? "online" : ""} />{" "}
          {runtime?.mode === "DEMO_READ_ONLY"
            ? "데모 · 합성 데이터"
            : runtime
              ? "분석 엔진 연결됨"
              : "분석 엔진 연결 대기"}
        </span>
        <span>{currentEvidence?.display_name ?? "증거 미선택"}</span>
        <span className="spacer" />
        <span>
          {context ? `컨텍스트 r${context.context_revision}` : "컨텍스트 없음"}
        </span>
        <span>UTF-8</span>
        <span>{zone}</span>
        <span>APEX 0.1</span>
      </footer>
      {jobsOpen && (
        <aside className="drawer">
          <header>
            <h2>분석 작업</h2>
            <button aria-label="작업 닫기" onClick={() => setJobsOpen(false)}>
              <X size={18} />
            </button>
          </header>
          <p className="muted">분석 중에도 확인된 결과를 탐색할 수 있습니다.</p>
          {!tasks.length ? (
            <Empty title="실행한 작업이 없습니다" />
          ) : (
            [...tasks].reverse().map((t) => (
              <div className="job-card" key={t.task_id}>
                <header>
                  <strong>
                    {{
                      REGISTER: "증거 등록",
                      FILES: "파일 인덱스",
                      ARTIFACTS: "아티팩트 분석",
                      SEARCH: "검색 인덱스",
                      TIMELINE: "타임라인",
                      HASH: "무결성 해시",
                      VERIFY: "무결성 재검증",
                    }[t.kind as string] ?? t.kind}
                  </strong>
                  <Badge value={t.status} />
                </header>
                {activeTask(t) && (
                  <progress
                    value={t.job?.progress?.progress_percent ?? undefined}
                    max={100}
                  />
                )}
                <p className="muted small">
                  {t.job?.progress?.progress_percent == null
                    ? "총량 미확정"
                    : `${t.job.progress.progress_percent.toFixed(1)}%`}{" "}
                  · 처리 {t.job?.progress?.processed_items ?? "—"}개
                </p>
                {t.error && (
                  <ErrorState error={new GatewayError(t.error.code)} />
                )}
                <ResultState data={t.job} />
                {t.actions?.includes("CANCEL") && (
                  <button
                    onClick={async () => {
                      try {
                        await gateway.call("tasks.cancel", {
                          case_id: caseId,
                          task_id: t.task_id,
                        });
                      } catch (err) {
                        setError(err);
                      }
                    }}
                  >
                    작업 취소
                  </button>
                )}
                <Section title="작업 상세">
                  <Fields value={t.job} />
                </Section>
                {t.result && (
                  <Section title="작업 결과">
                    <Fields value={t.result} />
                  </Section>
                )}
              </div>
            ))
          )}
        </aside>
      )}
      {aiOpen && (
        <aside className="drawer ai-drawer">
          <header>
            <h2>
              <AssistantIcon size={20} /> AI 도우미
            </h2>
            <button aria-label="AI 닫기" onClick={() => setAiOpen(false)}>
              <X size={18} />
            </button>
          </header>
          <div className="card">
            <Badge value="EXTERNAL_CONFIGURATION_REQUIRED" />
            <h3>AI 서비스 연결이 필요합니다</h3>
            <p className="muted">
              현재 선택한 자료의 컨텍스트와 엔진의 데이터 정책을 사용합니다.
              실제 AI 실행은 MCP·AI 런타임 연결 후 제공됩니다.
            </p>
          </div>
          <Fields
            value={{
              case_id: caseId || null,
              evidence_id: evidenceId || null,
              session_context_id: context?.session_context_id,
              current_route: route,
              selected_resource: selected ? resource(selected) : null,
            }}
          />
          <button disabled>현재 선택 분석 요청</button>
          <p className="muted small">
            관찰 사실 · 추론 · 권고 · 인용을 구분하여 표시합니다.
          </p>
        </aside>
      )}
      {dialog && (
        <FormDialog
          title={dialog.title}
          description={dialog.description}
          fields={dialog.fields}
          onClose={() => setDialog(null)}
          onSubmit={dialog.submit!}
        />
      )}
    </div>
  );
}
