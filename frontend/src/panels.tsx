import { useEffect, useRef, useState, type ReactNode } from "react";
import { X, ShieldCheck, LogIn, LogOut, Save, FolderOpen, Plus } from "./icons";
import { gateway, unwrap, errorText, type Row } from "./gateway";
import {
  Badge,
  Fields,
  Loading,
  ErrorState,
  ResultState,
  Section,
  time,
} from "./ui";
export type FieldSpec = {
  key: string;
  label: string;
  type?: string;
  required?: boolean;
  max?: number;
  default?: string;
  options?: string[];
};
export function FormDialog({
  title,
  description,
  fields,
  onSubmit,
  onClose,
  submit = "저장",
}: {
  title: string;
  description?: string;
  fields: FieldSpec[];
  onSubmit: (data: Row) => Promise<void>;
  onClose: () => void;
  submit?: string;
}) {
  const [error, setError] = useState<unknown>(null),
    [busy, setBusy] = useState(false);
  const formRef = useRef<HTMLFormElement>(null);
  const previousFocus = useRef(document.activeElement as HTMLElement | null);
  useEffect(() => {
    (
      formRef.current?.querySelector<HTMLElement>("input, textarea, select") ??
      formRef.current?.querySelector<HTMLElement>("button")
    )?.focus();
    return () => previousFocus.current?.focus();
  }, []);
  return (
    <div className="modal-backdrop">
      <form
        className="modal"
        ref={formRef}
        onKeyDown={(e) => {
          if (e.key === "Escape" && !busy) {
            e.preventDefault();
            onClose();
          }
          if (e.key !== "Tab") return;
          const controls = Array.from(
            e.currentTarget.querySelectorAll<HTMLElement>(
              'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]',
            ),
          );
          const first = controls[0],
            last = controls.at(-1);
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last?.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first?.focus();
          }
        }}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          const data = Object.fromEntries(new FormData(e.currentTarget));
          try {
            await onSubmit(data);
            onClose();
          } catch (err) {
            setError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <header>
          <h2>{title}</h2>
          <button
            type="button"
            aria-label="닫기"
            onClick={onClose}
            disabled={busy}
          >
            <X size={18} />
          </button>
        </header>
        {description && <p className="muted">{description}</p>}
        {fields.map((f) => (
          <label key={f.key}>
            {f.label}
            {f.type === "textarea" ? (
              <textarea
                name={f.key}
                defaultValue={f.default}
                required={f.required}
                maxLength={f.max}
                rows={5}
              />
            ) : f.options ? (
              <select name={f.key} defaultValue={f.default}>
                {f.options.map((o) => (
                  <option key={o}>{o}</option>
                ))}
              </select>
            ) : (
              <input
                type={f.type ?? "text"}
                name={f.key}
                defaultValue={f.default}
                required={f.required}
                maxLength={f.max}
              />
            )}
          </label>
        ))}
        {error != null && <ErrorState error={error} />}
        <footer>
          <button type="button" onClick={onClose} disabled={busy}>
            취소
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "처리 중…" : submit}
          </button>
        </footer>
      </form>
    </div>
  );
}
export function AccountPanel() {
  const [state, setState] = useState<Row>({ connected: false }),
    [error, setError] = useState<unknown>(null),
    [busy, setBusy] = useState(false);
  useEffect(() => {
    window.apex?.account().then(unwrap).then(setState).catch(setError);
  }, []);
  return (
    <div className="card">
      <h3>
        <ShieldCheck size={18} /> APEX 계정
      </h3>
      <p className="muted">
        로그인 없이 모든 로컬 분석 작업을 사용할 수 있습니다. 서버 계정은 원격
        서비스 연결에 사용합니다.
      </p>
      {state.connected ? (
        <>
          <p>
            <Badge value="AVAILABLE" /> {state.origin}
          </p>
          <button
            onClick={async () => {
              if (window.apex) {
                unwrap(await window.apex.logout());
                setState({ connected: false });
              }
            }}
          >
            <LogOut size={14} /> 앱에서 로그아웃
          </button>
          <p className="muted small">
            이 앱의 메모리에서 계정 세션을 제거합니다.
          </p>
        </>
      ) : (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(null);
            const form = e.currentTarget;
            const data = Object.fromEntries(new FormData(form));
            try {
              if (window.apex) {
                setState(unwrap(await window.apex.login(data)));
                form.reset();
              }
            } catch (err) {
              setError(err);
            } finally {
              (form.elements.namedItem("password") as HTMLInputElement).value =
                "";
              setBusy(false);
            }
          }}
        >
          <div className="form-grid">
            <label>
              기존 인증 서버 주소
              <input
                name="origin"
                type="url"
                placeholder="https://인증-서버-주소"
                required
              />
            </label>
            <label>
              테넌트 ID
              <input name="tenant_id" required />
            </label>
            <label>
              이메일
              <input name="email" type="email" required />
            </label>
            <label>
              비밀번호
              <input
                name="password"
                type="password"
                autoComplete="current-password"
                required
              />
            </label>
          </div>
          <button disabled={!window.apex || busy}>
            <LogIn size={14} />
            {busy ? "로그인 중…" : "계정 연결"}
          </button>
        </form>
      )}
      {error != null && <ErrorState error={error} />}
    </div>
  );
}
const policyNames: Record<string, string> = {
  ai_enabled: "AI 사용 허용",
  external_allowed: "외부 AI 사용 허용",
  local_only: "로컬 AI만 허용",
  raw_allowed: "원본 데이터 사용 허용",
  redaction_required: "민감정보 제거 필수",
  projection_required: "안전한 투영 필수",
};
export function GovernanceAudit({ audit }: { audit: Row }) {
  const result = audit.result ?? {};
  const source = result.data?.source ?? {};
  const yesNo = (v: unknown) =>
    v === true ? "적용" : v === false ? "미적용" : "확인되지 않음";
  const fields: [string, unknown][] = [
    ["사건", source.case_id],
    ["소스", source.source_id],
    ["소스 유형", source.source_type],
    ["데이터 분류", result.data?.classification],
    ["전송 대상", result.destination],
    ["사유", result.reason],
    ["민감정보 제거", yesNo(audit.redaction_applied)],
    ["안전한 투영", yesNo(audit.projection_applied)],
    ["정책 버전", result.policy_revision],
    ["기록 시각", audit.created_at],
  ];
  return (
    <article className="audit">
      <Badge value={result.decision} />
      <dl className="audit-summary">
        {fields.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{String(value ?? "—")}</dd>
          </div>
        ))}
      </dl>
      <details>
        <summary>평가 기록 상세</summary>
        <Fields value={audit} />
      </details>
    </article>
  );
}
export function PolicyPanel({ caseId }: { caseId: string }) {
  const [policy, setPolicy] = useState<Row | null>(null),
    [audits, setAudits] = useState<Row[]>([]),
    [error, setError] = useState<unknown>(null),
    [loaded, setLoaded] = useState(false),
    [busy, setBusy] = useState(false);
  const reload = async () => {
    try {
      const [p, a] = await Promise.all([
        gateway.call("policy.get", { case_id: caseId }),
        gateway.call<Row[]>("policy.audit", { case_id: caseId }),
      ]);
      setPolicy(p);
      setAudits(a);
      setLoaded(true);
      setError(null);
    } catch (err) {
      setError(err);
    }
  };
  useEffect(() => {
    void reload();
  }, [caseId]);
  return (
    <div className="card">
      <h3>사건 AI 데이터 정책</h3>
      <p className="muted">
        설정과 허용 여부는 엔진이 관리합니다. 민감정보 제거·투영 요구는 최종
        실행 허가가 아닙니다.
      </p>
      {error != null && <ErrorState error={error} retry={reload} />}{" "}
      {!loaded ? (
        error != null ? null : (
          <Loading />
        )
      ) : (
        <form
          key={policy?.revision ?? 0}
          onSubmit={async (e) => {
            e.preventDefault();
            const f = new FormData(e.currentTarget);
            const p: Row = {
              case_id: caseId,
              expected_revision: policy?.revision ?? 0,
              allowed_classifications: f.getAll("classification"),
              secret_handling: f.get("secret_handling"),
            };
            for (const k of Object.keys(policyNames)) p[k] = f.has(k);
            setBusy(true);
            try {
              await gateway.call("policy.save", p);
              await reload();
              setError(null);
            } catch (err) {
              setError(err);
            } finally {
              setBusy(false);
            }
          }}
        >
          <div className="policy-grid">
            {Object.entries(policyNames).map(([k, v]) => (
              <label className="check" key={k}>
                <input
                  name={k}
                  type="checkbox"
                  defaultChecked={
                    policy
                      ? !!policy[k]
                      : [
                          "local_only",
                          "redaction_required",
                          "projection_required",
                        ].includes(k)
                  }
                />
                {v}
              </label>
            ))}
          </div>
          <fieldset>
            <legend>허용할 데이터 분류</legend>
            {["PUBLIC", "INTERNAL", "SENSITIVE", "SECRET"].map((c) => (
              <label className="check inline" key={c}>
                <input
                  name="classification"
                  value={c}
                  type="checkbox"
                  defaultChecked={(
                    policy?.allowed_classifications ?? ["PUBLIC", "INTERNAL"]
                  ).includes(c)}
                />
                {c}
              </label>
            ))}
          </fieldset>
          <label>
            비밀 데이터 처리
            <select
              name="secret_handling"
              defaultValue={policy?.secret_handling ?? "DENY"}
            >
              <option value="DENY">차단</option>
              <option value="REDACT">민감정보 제거</option>
              <option value="ALLOW">허용 (엔진 정책 재평가 적용)</option>
            </select>
          </label>
          <button className="primary" disabled={busy}>
            <Save size={14} /> 정책 저장
          </button>
          <span className="muted small">
            {" "}
            버전 {policy?.revision ?? "미설정"}
          </span>
        </form>
      )}
      <Section title={`AI 데이터 접근 이력 · ${audits.length}건`}>
        {audits.length ? (
          <>
            <p className="muted small">
              엔진의 정책 평가 이력입니다. 실제 전송 또는 AI 실행 완료를
              의미하지 않습니다.
            </p>
            {audits.map((a, i) => (
              <GovernanceAudit key={a.audit_id ?? i} audit={a} />
            ))}
          </>
        ) : (
          <p className="muted">저장된 AI 데이터 접근 이력이 없습니다.</p>
        )}
      </Section>
    </div>
  );
}
export function Reports({
  caseId,
  evidenceId,
  renderer,
  citations = [],
  onNotice,
}: {
  caseId: string;
  evidenceId: string;
  renderer: Row;
  citations?: Row[];
  onNotice: (s: string) => void;
}) {
  const [reports, setReports] = useState<Row[]>([]),
    [selected, setSelected] = useState(""),
    [detail, setDetail] = useState<Row | null>(null),
    [versionId, setVersionId] = useState(""),
    [dialog, setDialog] = useState<
      "new" | "version" | "review" | "export" | null
    >(null),
    [action, setAction] = useState("submit"),
    [sectionId, setSectionId] = useState<string | null>(null),
    [error, setError] = useState<unknown>(null),
    [busy, setBusy] = useState(false);
  const [exportResult, setExportResult] = useState<Row | null>(null);
  // Keep the current version and review dialog mounted during a refresh, but
  // never show the previous report's details under a new selection.
  const data = detail?.report.report_id === selected ? detail : null;
  const loadRevision = useRef(0);
  const load = async (id = selected) => {
    const revision = ++loadRevision.current;
    setBusy(true);
    try {
      const [list, detail] = await Promise.all([
        gateway.call("reports.list", { case_id: caseId }),
        id
          ? gateway.call("reports.get", { case_id: caseId, report_id: id })
          : null,
      ]);
      if (revision !== loadRevision.current) return;
      setReports(list.items);
      setDetail(detail);
      setError(null);
    } catch (err) {
      if (revision === loadRevision.current) setError(err);
    } finally {
      if (revision === loadRevision.current) setBusy(false);
    }
  };
  useEffect(() => {
    void load();
    return () => {
      loadRevision.current++;
    };
  }, [caseId, selected]);
  const versions: Row[] = data?.versions ?? [];
  const version =
    versions.find((v) => v.report_version_id === versionId) ?? versions.at(-1);
  const approved =
    version &&
    data?.approvals?.[version.report_version_id]?.decision === "APPROVED";
  const review = (kind: string, id: string | null = null) => {
    setAction(kind);
    setSectionId(id);
    setDialog("review");
  };
  return (
    <div className="reports-layout">
      <aside className="report-list">
        <div className="section-heading">
          보고서{" "}
          <button title="보고서 만들기" onClick={() => setDialog("new")}>
            <Plus size={15} />
          </button>
        </div>
        {reports.map((r) => (
          <button
            key={r.report_id}
            onClick={() => {
              setSelected(r.report_id);
              setVersionId("");
            }}
            className={selected === r.report_id ? "active" : ""}
          >
            <strong>{r.title}</strong>
            <Badge value={r.status} />
          </button>
        ))}
      </aside>
      <div className="report-body">
        {error != null && <ErrorState error={error} retry={() => load()} />}{" "}
        {busy && <Loading />}
        {!selected ? (
          <div className="empty">
            <h2>보고서를 선택하세요</h2>
            <p>분석자가 작성한 초안을 검토하고 승인한 후 내보내세요.</p>
            <button className="primary" onClick={() => setDialog("new")}>
              보고서 만들기
            </button>
          </div>
        ) : (
          <>
            <div className="report-heading">
              <div>
                <span className="muted small">보고서</span>
                <h2>{data?.report?.title}</h2>
              </div>
              <button onClick={() => setDialog("version")}>
                <Plus size={14} /> 새 버전 작성
              </button>
            </div>
            {versions.length > 0 && (
              <div className="toolbar">
                <select
                  aria-label="보고서 버전"
                  value={version?.report_version_id ?? ""}
                  onChange={(e) => setVersionId(e.target.value)}
                >
                  {versions.map((v) => (
                    <option
                      key={v.report_version_id}
                      value={v.report_version_id}
                    >
                      버전 {v.version_number} · {v.source_kind}
                    </option>
                  ))}
                </select>
                <Badge value={version?.review_state?.status} />
                <Badge
                  value={
                    data?.approvals?.[version?.report_version_id]?.decision ??
                    "DRAFT"
                  }
                />
              </div>
            )}
            {version && (
              <>
                <ResultState data={version} />
                <p className="report-summary">{version.executive_summary}</p>
                {version.sections.map((s: Row) => (
                  <article key={s.section_id} className="report-section">
                    <header>
                      <h3>{s.title}</h3>
                      <Badge value={s.source_kind} />
                    </header>
                    <p>{s.content}</p>
                    <div className="toolbar">
                      <button
                        onClick={() => review("accept_section", s.section_id)}
                      >
                        이 섹션 채택
                      </button>
                      <button
                        onClick={() => review("request_changes", s.section_id)}
                      >
                        수정 요청
                      </button>
                    </div>
                    <Section title="인용 근거">
                      <Fields value={s.citations} />
                    </Section>
                  </article>
                ))}
                <Section title="한계 및 출처" initial>
                  <Fields
                    value={{
                      limitations: version.limitations,
                      content_fingerprint: version.content_fingerprint,
                      created_by: version.created_by,
                    }}
                  />
                </Section>
                <div className="review-actions">
                  <button onClick={() => review("submit")}>검토 제출</button>
                  <button onClick={() => review("complete")}>검토 완료</button>
                  <button onClick={() => review("approve")}>
                    보관이력 포함 승인
                  </button>
                  <button onClick={() => review("reject")}>반려</button>
                  <button onClick={() => review("reopen")}>검토 재개</button>
                  <button disabled={!approved} onClick={() => review("revoke")}>
                    승인 철회
                  </button>
                  <button
                    className="primary"
                    disabled={!approved}
                    onClick={() => setDialog("export")}
                  >
                    내보내기
                  </button>
                </div>
                <Section title="검토 이력">
                  <Fields value={data?.reviews?.[version.report_version_id]} />
                </Section>
              </>
            )}
          </>
        )}
      </div>
      {exportResult && (
        <div className="export-result">
          <h3>내보내기 결과</h3>
          <button
            aria-label="내보내기 결과 닫기"
            onClick={() => setExportResult(null)}
          >
            <X size={16} />
          </button>
          <Badge value={exportResult.manifest?.status} />
          <Fields value={exportResult.artifacts} />
          <Fields value={exportResult.manifest?.warnings} />
          <button onClick={() => window.apex?.openExports()}>
            결과 폴더 열기
          </button>
        </div>
      )}
      {dialog === "new" && (
        <FormDialog
          title="보고서 만들기"
          fields={[
            { key: "title", label: "보고서 제목", required: true, max: 255 },
          ]}
          onClose={() => setDialog(null)}
          onSubmit={async (f) => {
            const r = await gateway.call("reports.create", {
              case_id: caseId,
              ...f,
            });
            setSelected(r.report_id);
            await load(r.report_id);
          }}
        />
      )}
      {dialog === "version" && (
        <FormDialog
          title="새 보고서 버전 작성"
          description="원본 버전은 보존됩니다. 새 버전에는 다시 검토와 승인이 필요합니다."
          fields={[
            {
              key: "title",
              label: "제목",
              required: true,
              max: 255,
              default: data?.report?.title,
            },
            {
              key: "executive_summary",
              label: "요약",
              type: "textarea",
              required: true,
            },
            {
              key: "content",
              label: "주요 발견 사항",
              type: "textarea",
              required: true,
            },
            {
              key: "limitations",
              label: "분석의 한계 (줄마다 하나)",
              type: "textarea",
              required: true,
            },
          ]}
          onClose={() => setDialog(null)}
          onSubmit={async (f) => {
            await gateway.call("reports.version", {
              case_id: caseId,
              report_id: selected,
              title: f.title,
              executive_summary: f.executive_summary,
              evidence_ids: evidenceId ? [evidenceId] : [],
              citations,
              limitations: f.limitations.split("\n").filter(Boolean),
              sections: [
                {
                  section_type: "KEY_FINDINGS",
                  title: "주요 발견 사항",
                  content: f.content,
                  citations,
                  order: 1,
                },
              ],
            });
            setVersionId("");
            await load();
          }}
        />
      )}
      {dialog === "review" && version && (
        <FormDialog
          title="보고서 검토 기록"
          description="현재 버전에 분석자의 결정과 사유를 기록합니다."
          submit="기록"
          fields={[
            {
              key: "reason",
              label: "검토·결정 사유",
              type: "textarea",
              required: true,
              max: 4096,
            },
          ]}
          onClose={() => setDialog(null)}
          onSubmit={async (f) => {
            try {
              await gateway.call("reports.action", {
                case_id: caseId,
                report_version_id: version.report_version_id,
                action,
                reason: f.reason,
                section_id: sectionId,
                expected_review_revision: version.review_state.review_revision,
                expected_approval_revision:
                  version.approval_state?.approval_revision ?? null,
              });
              await load();
            } catch (err) {
              await load();
              throw err;
            }
          }}
        />
      )}{" "}
      {dialog === "export" && version && (
        <FormDialog
          title="승인된 보고서 내보내기"
          description="사건의 파생 결과 폴더에 저장됩니다. 기존 파일은 덮어쓰지 않습니다."
          fields={[
            {
              key: "format",
              label: "파일 형식",
              options: renderer.supported_formats ?? ["HTML"],
            },
            {
              key: "filename",
              label: "파일 이름 (확장자 포함)",
              default: "report.html",
              required: true,
              max: 200,
            },
          ]}
          onClose={() => setDialog(null)}
          onSubmit={async (f) => {
            const r = await gateway.call("reports.export", {
              case_id: caseId,
              report_version_id: version.report_version_id,
              ...f,
            });
            setExportResult(r);
            onNotice(
              r.manifest?.status === "COMPLETED"
                ? "보고서 파일을 생성했습니다. 결과 폴더에서 확인하세요."
                : "보고서 내보내기 상태를 확인해주세요.",
            );
            await load();
          }}
        />
      )}
    </div>
  );
}
