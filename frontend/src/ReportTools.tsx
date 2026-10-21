import { useEffect, useState } from "react";
import { gateway, type Row } from "./gateway";
import { ErrorState, Loading, time } from "./ui";

/**
 * Same rule as Core `ReportService.compare_versions`: a section is unchanged only
 * when its fingerprint (content, order, citations…) appears in both versions.
 */
export function compareVersions(left: Row, right: Row) {
  const prints = (v: Row) =>
    new Set<string>((v.sections ?? []).map((s: Row) => s.section_fingerprint));
  const l = prints(left),
    r = prints(right);
  return {
    same_content: left.content_fingerprint === right.content_fingerprint,
    added: new Set([...r].filter((f) => !l.has(f))),
    removed: new Set([...l].filter((f) => !r.has(f))),
  };
}

export function ReportCompare({ versions }: { versions: Row[] }) {
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const ids = versions.map((v) => v.report_version_id).join(",");
  useEffect(() => {
    setLeft(versions.at(-2)?.report_version_id ?? "");
    setRight(versions.at(-1)?.report_version_id ?? "");
  }, [ids]);
  if (versions.length < 2) return null;
  const byId = (id: string) => versions.find((v) => v.report_version_id === id);
  const a = byId(left),
    b = byId(right);
  const result = a && b && a !== b ? compareVersions(a, b) : null;
  const options = versions.map((v) => (
    <option key={v.report_version_id} value={v.report_version_id}>
      v{v.version_number} · {v.title}
    </option>
  ));
  const ordered = (v: Row) =>
    [...(v.sections ?? [])].sort((x: Row, y: Row) => x.order - y.order);
  return (
    <section className="report-compare" aria-label="보고서 버전 비교">
      <h4>버전 비교</h4>
      <label>
        기준 버전
        <select value={left} onChange={(e) => setLeft(e.target.value)}>
          {options}
        </select>
      </label>
      <label>
        비교 버전
        <select value={right} onChange={(e) => setRight(e.target.value)}>
          {options}
        </select>
      </label>
      {result && a && b && (
        <div>
          <p>
            {result.same_content
              ? "두 버전의 내용이 같습니다."
              : `추가·변경된 섹션 ${result.added.size}개 · 제거·변경된 섹션 ${result.removed.size}개`}
          </p>
          <div className="compare-columns">
            {(
              [
                ["기준", a, result.removed, "removed", "－ "],
                ["비교", b, result.added, "added", "＋ "],
              ] as const
            ).map(([label, version, changed, className, mark]) => (
              <ul key={label} aria-label={label}>
                {ordered(version).map((s: Row) => {
                  const hit = changed.has(s.section_fingerprint);
                  return (
                    <li key={s.section_id} className={hit ? className : ""}>
                      {hit ? mark : ""}
                      {s.title} · {s.section_type}
                    </li>
                  );
                })}
              </ul>
            ))}
          </div>
          <p className="muted small">
            섹션 내용·순서·인용이 하나라도 다르면 다른 섹션으로 표시됩니다.
          </p>
        </div>
      )}
    </section>
  );
}

/** Recent executions from `search.history`; re-searching reuses the stored text and mode. */
export function SearchHistory({
  caseId,
  zone,
  onSearch,
}: {
  caseId: string;
  zone: string;
  onSearch: (text: string, mode: string) => void;
}) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="search-history-panel"
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <summary>검색 이력</summary>
      {open && (
        <SearchHistoryEntries
          key={caseId}
          caseId={caseId}
          zone={zone}
          onSearch={onSearch}
        />
      )}
    </details>
  );
}

function SearchHistoryEntries({
  caseId,
  zone,
  onSearch,
}: {
  caseId: string;
  zone: string;
  onSearch: (text: string, mode: string) => void;
}) {
  const [history, setHistory] = useState<Row[] | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let live = true;
    setHistory(null);
    setError(null);
    gateway.call<Row[]>("search.history", { case_id: caseId }).then(
      (rows) => {
        if (live) setHistory(rows);
      },
      (err) => {
        if (live) setError(err);
      },
    );
    return () => {
      live = false;
    };
  }, [caseId, attempt]);
  return (
    <>
      {error != null && (
        <ErrorState error={error} retry={() => setAttempt((n) => n + 1)} />
      )}
      {history == null ? (
        !error && <Loading />
      ) : !history.length ? (
        <p className="muted">아직 실행한 검색이 없습니다.</p>
      ) : (
        <ul className="search-history">
          {history.map((h) => {
            const text = h.options?.original_query_text ?? h.query_text;
            return (
              <li key={h.execution_id}>
                <span className="mono">{text}</span> · {h.query_mode} · 결과{" "}
                {h.result_count ?? "—"}개 · {time(h.started_at, zone)}
                <button onClick={() => onSearch(text, h.query_mode)}>
                  다시 검색
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}

export const SECTION_TYPES = [
  "KEY_FINDINGS",
  "CASE_OVERVIEW",
  "ANALYSIS_PURPOSE",
  "EVIDENCE",
  "HASH_INTEGRITY",
  "CHAIN_OF_CUSTODY",
  "ANALYSIS_ENVIRONMENT",
  "ANALYSIS_SCOPE",
  "TIMEZONE",
  "FILE_SYSTEM",
  "WINDOWS_ARTIFACT",
  "BROWSER",
  "MEDIA",
  "TIMELINE",
  "KEYWORD_SEARCH",
  "MACHINE_CANDIDATE",
  "LIMITATIONS",
  "CONCLUSION",
  "RECOMMENDATION",
  "TECHNICAL_APPENDIX",
  "OTHER",
];

type DraftSection = {
  key: string;
  section_type: string;
  title: string;
  content: string;
  citations: Row[];
  // Fields the analyst does not edit here but must not lose: table data, AI/analyst
  // origin, partial/stale state and warnings, coverage and source references.
  preserved: Row;
};

/** Section fields carried over unchanged so a new version keeps the source's meaning. */
export const PRESERVED_SECTION_FIELDS = [
  "content_kind",
  "structured_data",
  "source_kind",
  "source_resource_ids",
  "context_snapshot_ids",
  "is_partial",
  "stale_reasons",
  "coverage",
  "warnings",
] as const;

let draftKey = 0;
const draft = (s: Row = {}): DraftSection => ({
  key: `draft-${++draftKey}`,
  section_type: s.section_type ?? "KEY_FINDINGS",
  title: s.title ?? "주요 발견 사항",
  content: s.content ?? "",
  citations: s.citations ?? [],
  preserved: Object.fromEntries(
    PRESERVED_SECTION_FIELDS.filter((key) => s[key] !== undefined).map(
      (key) => [key, s[key]],
    ),
  ),
});

function sectionNotes(preserved: Row): string[] {
  return [
    preserved.source_kind && preserved.source_kind !== "ANALYST_DRAFT"
      ? `출처 ${preserved.source_kind}`
      : "",
    preserved.content_kind && preserved.content_kind !== "PLAIN_TEXT"
      ? `형식 ${preserved.content_kind}`
      : "",
    preserved.is_partial ? "부분 분석" : "",
    preserved.stale_reasons?.length ? "오래된 결과 경고" : "",
  ].filter(Boolean);
}

/** New report version with any number of ordered, typed sections. */
export function ReportVersionDialog({
  caseId,
  reportId,
  evidenceId,
  base,
  reportTitle,
  citations,
  onClose,
  onSaved,
}: {
  caseId: string;
  reportId: string;
  evidenceId: string;
  base: Row | undefined;
  reportTitle: string | undefined;
  citations: Row[];
  onClose: () => void;
  onSaved: () => Promise<void>;
}) {
  const [title, setTitle] = useState(base?.title ?? reportTitle ?? "");
  const [summary, setSummary] = useState(base?.executive_summary ?? "");
  const [limitations, setLimitations] = useState(
    (base?.limitations ?? []).join("\n"),
  );
  // Start from the shown version so editing one section keeps the others.
  const [sections, setSections] = useState<DraftSection[]>(() =>
    base?.sections?.length
      ? [...base.sections]
          .sort((a: Row, b: Row) => a.order - b.order)
          .map((s: Row) => draft(s))
      : [draft()],
  );
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const update = (index: number, patch: Partial<DraftSection>) =>
    setSections((all) =>
      all.map((s, i) => (i === index ? { ...s, ...patch } : s)),
    );
  const move = (index: number, delta: number) =>
    setSections((all) => {
      const next = [...all];
      const [item] = next.splice(index, 1);
      next.splice(index + delta, 0, item);
      return next;
    });
  return (
    <div className="modal-backdrop">
      <form
        className="modal report-version-dialog"
        role="dialog"
        aria-modal="true"
        aria-label="새 보고서 버전 작성"
        onKeyDown={(e) => {
          if (e.key === "Escape" && !busy) onClose();
        }}
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await gateway.call("reports.version", {
              case_id: caseId,
              report_id: reportId,
              title,
              executive_summary: summary,
              // A new version keeps the report's evidence scope; only a first
              // version falls back to the evidence selected on screen.
              evidence_ids: base
                ? (base.evidence_ids ?? [])
                : evidenceId
                  ? [evidenceId]
                  : [],
              citations,
              // Older desktop versions retained section references but dropped
              // report-wide context. Core revalidates all recovered IDs and
              // regenerates source revisions; stored versions stay immutable.
              context_snapshot_ids: [
                ...new Set([
                  ...(base?.context_snapshot_ids ?? []),
                  ...sections.flatMap(
                    (s) => s.preserved.context_snapshot_ids ?? [],
                  ),
                ]),
              ],
              search_execution_ids: base?.search_execution_ids ?? [],
              timeline_revisions: base?.timeline_revisions ?? [],
              ai_assistance_request_ids: base?.ai_assistance_request_ids ?? [],
              ai_result_ids: base?.ai_result_ids ?? [],
              analyzer_versions: base?.analyzer_versions ?? {},
              limitations: limitations
                .split("\n")
                .map((l: string) => l.trim())
                .filter(Boolean),
              sections: sections.map((s, i) => ({
                ...s.preserved,
                section_type: s.section_type,
                title: s.title,
                content: s.content,
                // Newly collected citations go with the first section.
                citations:
                  i === 0 ? [...s.citations, ...citations] : s.citations,
                order: i + 1,
              })),
            });
            await onSaved();
            onClose();
          } catch (err) {
            setError(err);
          } finally {
            setBusy(false);
          }
        }}
      >
        <header>
          <h2>새 보고서 버전 작성</h2>
          <button type="button" aria-label="닫기" onClick={onClose}>
            ✕
          </button>
        </header>
        <p className="muted">
          원본 버전은 보존됩니다. 새 버전에는 다시 검토와 승인이 필요합니다.
        </p>
        <fieldset disabled={busy}>
          <label>
            제목
            <input
              value={title}
              maxLength={255}
              required
              onChange={(e) => setTitle(e.target.value)}
            />
          </label>
          <label>
            요약
            <textarea
              value={summary}
              rows={3}
              required
              onChange={(e) => setSummary(e.target.value)}
            />
          </label>
          {sections.map((s, i) => (
            <fieldset key={s.key} className="section-draft">
              <legend>섹션 {i + 1}</legend>
              <label>
                섹션 유형
                <select
                  aria-label={`섹션 ${i + 1} 유형`}
                  value={s.section_type}
                  onChange={(e) => update(i, { section_type: e.target.value })}
                >
                  {SECTION_TYPES.map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </label>
              <label>
                섹션 제목
                <input
                  aria-label={`섹션 ${i + 1} 제목`}
                  value={s.title}
                  maxLength={255}
                  required
                  onChange={(e) => update(i, { title: e.target.value })}
                />
              </label>
              <label>
                내용
                <textarea
                  aria-label={`섹션 ${i + 1} 내용`}
                  value={s.content}
                  rows={4}
                  required
                  onChange={(e) => update(i, { content: e.target.value })}
                />
              </label>
              {s.citations.length > 0 && (
                <small className="muted">
                  인용 {s.citations.length}개 유지
                </small>
              )}
              {sectionNotes(s.preserved).length > 0 && (
                <small className="muted">
                  유지되는 상태: {sectionNotes(s.preserved).join(" · ")}
                </small>
              )}
              <div className="button-row">
                <button
                  type="button"
                  disabled={i === 0}
                  onClick={() => move(i, -1)}
                >
                  위로
                </button>
                <button
                  type="button"
                  disabled={i === sections.length - 1}
                  onClick={() => move(i, 1)}
                >
                  아래로
                </button>
                <button
                  type="button"
                  disabled={sections.length === 1}
                  onClick={() =>
                    setSections((all) => all.filter((_, j) => j !== i))
                  }
                >
                  섹션 삭제
                </button>
              </div>
            </fieldset>
          ))}
          <button
            type="button"
            disabled={sections.length >= 100}
            onClick={() =>
              setSections((all) => [
                ...all,
                draft({ section_type: "OTHER", title: "" }),
              ])
            }
          >
            섹션 추가
          </button>
          <label>
            분석의 한계 (줄마다 하나)
            <textarea
              value={limitations}
              rows={3}
              required
              onChange={(e) => setLimitations(e.target.value)}
            />
          </label>
        </fieldset>
        {error != null && <ErrorState error={error} />}
        <footer>
          <button type="button" onClick={onClose} disabled={busy}>
            취소
          </button>
          <button className="primary" disabled={busy}>
            {busy ? "처리 중…" : "저장"}
          </button>
        </footer>
      </form>
    </div>
  );
}
