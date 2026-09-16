import { describe, expect, it } from "vitest";
import { createDemoBridge } from "./demoBridge";
import { createDemoData } from "./demoData";
import { unwrap, validateContract, type Row } from "./gateway";

describe("extended read-only demo", () => {
  it("keeps every record and selectable projection within canonical contracts", async () => {
    const data = createDemoData();
    const bridge = createDemoBridge();
    for (const [schema, rows] of [
      ["case", data.cases],
      ["evidence", data.evidence],
      ["file", [...data.roots, ...data.files]],
      ["artifact", data.artifacts],
      ["machine-extracted-candidate", data.candidates],
      ["report-record", data.reports],
      [
        "report-version",
        Object.values(data.reportDetails).flatMap((d) => d.versions),
      ],
    ] as [string, Row[]][]) {
      for (const row of rows)
        expect(
          () => validateContract(schema, row),
          `${schema}: ${row.id ?? row.candidate_id}`,
        ).not.toThrow();
    }
    for (const [resource_id, { type, row }] of data.resources) {
      const view = unwrap(
        await bridge.invoke("view", {
          case_id: row.case_id,
          resource_type: type,
          resource_id,
          view_mode: "SIMPLE",
        }),
      );
      expect(() => validateContract("view-projection", view)).not.toThrow();
    }
    for (const c of data.cases) {
      const context = unwrap(
        await bridge.invoke("context.create", { case_id: c.id }),
      );
      expect(() =>
        validateContract("gui-session-context", context),
      ).not.toThrow();
      expect(context.case_id).toBe(c.id);
      expect(context.selected_file_node_ids).toEqual([]);
    }
  });

  it("filters by case, evidence, artifact type and paginates nested files without duplicates", async () => {
    const data = createDemoData(),
      bridge = createDemoBridge();
    const ev = data.evidence[0],
      other = data.evidence[2];
    const scope = { case_id: ev.case_id, evidence_id: ev.id };
    const folder = data.files.find(
      (f) => f.evidence_id === ev.id && f.original_name === "보관 자료",
    )!;
    const first = unwrap(
      await bridge.invoke("files.list", {
        ...scope,
        parent_node_id: folder.id,
        limit: 100,
      }),
    );
    const second = unwrap(
      await bridge.invoke("files.list", {
        ...scope,
        parent_node_id: folder.id,
        cursor: first.page.next_cursor,
      }),
    );
    expect(first.items).toHaveLength(100);
    expect(second.items).toHaveLength(24);
    expect(
      new Set([...first.items, ...second.items].map((r) => r.id)).size,
    ).toBe(124);
    expect(second.page.has_more).toBe(false);
    const filtered = unwrap(
      await bridge.invoke("artifacts.list", {
        ...scope,
        artifact_type: "BROWSER_VISIT",
      }),
    );
    expect(filtered.items).toHaveLength(1);
    expect(filtered.items[0].evidence_id).toBe(ev.id);
    const crossCase = unwrap(
      await bridge.invoke("files.list", {
        ...scope,
        case_id: other.case_id,
        parent_node_id: folder.id,
      }),
    );
    expect(crossCase.items).toEqual([]);
    expect(
      (
        await bridge.invoke("view", {
          case_id: other.case_id,
          resource_type: "FILE_SYSTEM_NODE",
          resource_id: folder.id,
          view_mode: "SIMPLE",
        })
      ).ok,
    ).toBe(false);
  });

  it("searches synthetic records, opens results and rejects writes and unsupported regex", async () => {
    const data = createDemoData(),
      bridge = createDemoBridge();
    const scope = {
      case_id: data.cases[0].id,
      evidence_id: data.evidence[0].id,
    };
    const result = unwrap(
      await bridge.invoke("search.query", {
        ...scope,
        query_mode: "TERM",
        query_text: "프로젝트",
      }),
    );
    expect(result.items.length).toBeGreaterThan(1);
    const view = unwrap(
      await bridge.invoke("view", {
        ...scope,
        resource_type: "SEARCH_RESULT",
        resource_id: result.items[0].result_id,
        view_mode: "DETAILED",
      }),
    );
    expect(() => validateContract("view-projection", view)).not.toThrow();
    const rawFile = data.files.find(
      (f) =>
        f.evidence_id === scope.evidence_id &&
        f.original_name === "분석_메모.txt",
    )!;
    const raw = unwrap(
      await bridge.invoke("raw.read", {
        ...scope,
        resource_id: rawFile.id,
        offset: 0,
        length: 1024,
      }),
    );
    expect(raw.text_preview).toContain("더미 텍스트");
    expect(raw.synthetic).toBe(true);
    for (const op of [
      "analysis.start",
      "cases.create",
      "candidates.review",
      "policy.save",
      "reports.export",
    ])
      expect(await bridge.invoke(op, scope)).toEqual({
        ok: false,
        error: { code: "DEMO_READ_ONLY" },
      });
    expect(
      (
        await bridge.invoke("search.query", {
          ...scope,
          query_mode: "REGEX_METADATA",
          query_text: "(a+)+$",
        })
      ).ok,
    ).toBe(false);
  });
});
