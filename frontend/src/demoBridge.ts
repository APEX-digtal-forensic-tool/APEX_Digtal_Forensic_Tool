/** Explicit development-only demo. Never a fallback for a failed backend. */
import core from "./__fixtures__/core.json";
import { createDemoData } from "./demoData";
import type { DesktopBridge, Row } from "./gateway";

export function createDemoBridge(): DesktopBridge {
  const data = createDemoData();
  let context: Row = structuredClone(core.context);
  const ok = (value: any) => ({
    ok: true as const,
    data: structuredClone(value),
  });
  const fail = (code: string) => ({ ok: false as const, error: { code } });
  const scoped = (rows: Row[], p: Row) =>
    rows.filter(
      (row) =>
        row.case_id === p.case_id &&
        (!p.evidence_id || row.evidence_id === p.evidence_id),
    );
  const page = (rows: Row[], p: Row) => {
    const start = p.cursor == null ? 0 : Number(p.cursor);
    const limit = Math.min(100, Math.max(1, Number(p.limit) || 100));
    if (!Number.isSafeInteger(start) || start < 0 || start > rows.length)
      return null;
    const items = rows.slice(start, start + limit);
    const more = start + items.length < rows.length;
    return {
      items,
      page: {
        returned: items.length,
        has_more: more,
        next_cursor: more ? String(start + items.length) : null,
      },
    };
  };
  const projection = (p: Row) => {
    const resource = data.resources.get(p.resource_id);
    if (
      !resource ||
      resource.row.case_id !== p.case_id ||
      resource.type !== p.resource_type
    )
      return null;
    const row = resource.row;
    const original = data.views[p.resource_id]?.[p.view_mode];
    if (original) return original;
    const template = Object.values(core.views)[0].SIMPLE;
    const canRead =
      resource.type === "FILE_SYSTEM_NODE" &&
      row.node_type === "FILE" &&
      !row.is_deleted;
    return {
      ...template,
      projection_id: `demo-${p.resource_id}-${p.view_mode}`,
      case_id: p.case_id,
      resource_type: resource.type,
      resource_id: p.resource_id,
      view_mode: p.view_mode,
      title:
        row.original_name ??
        row.title ??
        row.display_name ??
        row.text ??
        row.action,
      subtitle: "합성 데이터 · 읽기 전용",
      summary:
        row.summary ??
        row.text ??
        row.action ??
        "화면 확인용 합성 데이터입니다. 실제 증거를 분석한 결과가 아닙니다.",
      badges: [resource.type, ...(row.is_deleted ? ["DELETED"] : [])],
      primary_fields: {
        display_path: row.display_path ?? row.source_path,
        description: row.summary ?? row.text ?? row.action ?? "합성 예시",
        ...(row.fields ?? {}),
        synthetic: true,
      },
      secondary_fields: row,
      technical_fields: { synthetic: true },
      raw_fields: {
        synthetic: true,
        note: "원본 범위 읽기는 이 데모에서 생성한 텍스트만 반환합니다.",
      },
      timestamps: row.utc_timestamps ?? { created_at: row.created_at },
      timezone: "Asia/Seoul",
      confidence: row.confidence ?? null,
      partial_state: { is_partial: row.is_partial ?? false },
      stale_state: { is_stale: false, stale_reasons: [] },
      citations: row.citations ?? [],
      raw_locator: row.raw_locator ?? null,
      available_actions: [
        "view.simple",
        "view.detailed",
        ...(canRead ? ["view.raw", "view.raw-read"] : []),
      ],
      analyzer_id: "demo.synthetic",
      analyzer_version: "1.0.0",
    };
  };
  return {
    async invoke(op, p) {
      if (op === "runtime") return ok(core.runtime);
      if (op === "cases.list") return ok(data.cases);
      if (p.case_id && !data.cases.some((c) => c.id === p.case_id))
        return fail("CASE_NOT_FOUND");
      if (op === "evidence.list")
        return ok(data.evidence.filter((e) => e.case_id === p.case_id));
      if (op === "context.create") {
        context = {
          ...structuredClone(core.context),
          case_id: p.case_id,
          session_context_id: `demo-context-${p.case_id}`,
        };
        return ok(context);
      }
      if (op === "context.get") return ok(context);
      if (op === "context.update") {
        if (
          p.expected_revision != null &&
          p.expected_revision !== context.context_revision
        )
          return fail("CONTEXT_REVISION_CONFLICT");
        context = {
          ...context,
          ...p.patch,
          case_id: context.case_id,
          context_revision: context.context_revision + 1,
        };
        return ok(context);
      }
      if (op === "files.roots") return ok(scoped(data.roots, p));
      if (op === "files.list") {
        const rows = scoped(data.files, p).filter(
          (n) =>
            n.parent_node_id === p.parent_node_id &&
            (!p.directories_only || n.node_type === "DIRECTORY"),
        );
        const result = page(rows, p);
        return result
          ? ok({
              ...result,
              coverage: {
                ...core.files.coverage,
                case_id: p.case_id,
                evidence_id: p.evidence_id,
                discovered_items: scoped(data.files, p).length,
                processed_items: scoped(data.files, p).length,
                current_path: null,
              },
            })
          : fail("CURSOR_INVALID");
      }
      if (op === "view") {
        const value = projection(p);
        return value ? ok(value) : fail("RESOURCE_NOT_FOUND");
      }
      if (op === "raw.read") {
        const resource = data.resources.get(p.resource_id);
        if (
          !resource ||
          resource.row.case_id !== p.case_id ||
          resource.type !== "FILE_SYSTEM_NODE" ||
          resource.row.node_type !== "FILE" ||
          resource.row.is_deleted
        )
          return fail("RESOURCE_NOT_FOUND");
        if (
          !Number.isSafeInteger(p.offset) ||
          p.offset < 0 ||
          !Number.isSafeInteger(p.length) ||
          p.length < 1 ||
          p.length > 1048576
        )
          return fail("RAW_RANGE_NOT_SATISFIABLE");
        const bytes = new TextEncoder().encode(
          `APEX 합성 데이터\n파일: ${resource.row.display_path}\n이 내용은 미리보기용 더미 텍스트입니다. 실제 원본 파일을 읽지 않았습니다.\n`,
        );
        if (p.offset >= bytes.length) return fail("RAW_RANGE_NOT_SATISFIABLE");
        const chunk = bytes.slice(p.offset, p.offset + p.length);
        return ok({
          text_preview: new TextDecoder().decode(chunk),
          hex_preview: Array.from(chunk, (b) =>
            b.toString(16).padStart(2, "0"),
          ).join(" "),
          returned_offset: p.offset,
          returned_length: chunk.length,
          truncated: p.offset + chunk.length < bytes.length,
          total_size_bytes: bytes.length,
          synthetic: true,
        });
      }
      if (op === "tasks.list") return ok(scoped(data.tasks, p));
      if (op === "custody.list") return ok(scoped(data.custody, p));
      if (op === "reports.get") {
        const detail = data.reportDetails[p.report_id];
        return detail?.report.case_id === p.case_id
          ? ok(detail)
          : fail("RESOURCE_NOT_FOUND");
      }
      if (op === "search.query") {
        if (p.query_mode === "REGEX_METADATA")
          return fail("DEMO_SEARCH_MODE_UNSUPPORTED");
        const query = String(p.query_text ?? "")
          .trim()
          .toLocaleLowerCase();
        const matches = (text: string, name: string) => {
          const value = text.toLocaleLowerCase();
          if (p.query_mode === "EXACT")
            return name.toLocaleLowerCase() === query || value === query;
          if (p.query_mode === "PREFIX")
            return value
              .split(/[\s/\\·]+/)
              .some((word) => word.startsWith(query));
          if (p.query_mode === "PHRASE") return value.includes(query);
          return query.split(/\s+/).every((term) => value.includes(term));
        };
        const sources = [
          ...scoped(data.files, p),
          ...scoped(data.artifacts, p),
        ];
        const results = query
          ? sources
              .filter((row) =>
                matches(
                  `${row.display_path ?? row.source_path} ${row.title ?? ""} ${row.summary ?? ""}`,
                  row.original_name ?? row.title,
                ),
              )
              .map((row, i) => ({
                result_id: `demo-search-${row.id}`,
                case_id: row.case_id,
                evidence_id: row.evidence_id,
                rank: i + 1,
                source_id: row.id,
                source_type: row.artifact_type ? "ARTIFACT" : "FILE",
                snippet: row.title ?? row.display_path,
                title: row.title ?? row.original_name,
                matched_terms: [query],
                synthetic: true,
              }))
          : [];
        results.forEach((row) =>
          data.resources.set(row.result_id, { type: "SEARCH_RESULT", row }),
        );
        const result = page(results, p);
        return result
          ? ok({
              ...result,
              execution: {
                execution_id: `demo-search-${p.case_id}`,
                query_text: p.query_text,
                synthetic: true,
              },
            })
          : fail("CURSOR_INVALID");
      }
      const lists: Record<string, Row[]> = {
        "artifacts.list": data.artifacts,
        "candidates.list": data.candidates,
        "timeline.list": data.timeline,
        "reports.list": data.reports,
      };
      if (lists[op]) {
        const rows = scoped(
          lists[op],
          op === "reports.list" ? { case_id: p.case_id } : p,
        ).filter(
          (row) => !p.artifact_type || row.artifact_type === p.artifact_type,
        );
        const result = page(rows, p);
        return result ? ok(result) : fail("CURSOR_INVALID");
      }
      if (op === "policy.get")
        return ok({
          case_id: p.case_id,
          revision: 1,
          ai_enabled: false,
          external_allowed: false,
          local_only: true,
          raw_allowed: false,
          redaction_required: true,
          projection_required: true,
          allowed_classifications: ["PUBLIC"],
          secret_handling: "DENY",
        });
      if (op === "policy.audit")
        return ok([
          {
            audit_id: `demo-audit-${p.case_id}`,
            created_at: "2026-09-14T05:00:00Z",
            redaction_applied: false,
            projection_applied: false,
            result: {
              decision: "DENY",
              destination: "EXTERNAL",
              reason: "합성 정책 평가 예시 · 외부 전송 비활성",
              policy_revision: 1,
              data: {
                classification: "SENSITIVE",
                source: {
                  case_id: p.case_id,
                  source_id: "합성 파일 메타데이터",
                  source_type: "FILE",
                },
              },
            },
            synthetic: true,
          },
        ]);
      return fail("DEMO_READ_ONLY");
    },
    async pick() {
      return ok(null);
    },
    async openExports() {
      return ok(null);
    },
    async account() {
      return ok({ connected: false, origin: null });
    },
    async login() {
      return fail("DEMO_READ_ONLY");
    },
    async logout() {
      return ok(null);
    },
  };
}
