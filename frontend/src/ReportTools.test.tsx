// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import {
  ReportCompare,
  ReportVersionDialog,
  SearchHistory,
  compareVersions,
} from "./ReportTools";
import { gateway, type Row } from "./gateway";
// Report/version DTOs generated through the real Core services.
import reportFixture from "./__fixtures__/report.json";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const base = reportFixture.detail.versions[0] as Row;
// A later version: same first section plus one more, as Core would fingerprint it.
const next: Row = {
  ...base,
  report_version_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  version_number: base.version_number + 1,
  content_fingerprint: "f".repeat(64),
  sections: [
    ...base.sections,
    {
      ...base.sections[0],
      section_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      section_type: "CONCLUSION",
      title: "결론",
      order: base.sections.length + 1,
      section_fingerprint: "e".repeat(64),
    },
  ],
};

it("compares versions by section fingerprints like Core", () => {
  const same = compareVersions(base, base);
  expect(same.same_content).toBe(true);
  expect(same.added.size + same.removed.size).toBe(0);
  const diff = compareVersions(base, next);
  expect(diff.same_content).toBe(false);
  expect([...diff.added]).toEqual(["e".repeat(64)]);
  expect(diff.removed.size).toBe(0);
});

it("shows the comparison only with two or more versions and marks additions", () => {
  const view = render(<ReportCompare versions={[base]} />);
  expect(screen.queryByText("버전 비교")).toBeNull();
  view.rerender(<ReportCompare versions={[base, next]} />);
  expect(screen.getByText(/추가·변경된 섹션 1개/)).toBeTruthy();
  const added = within(screen.getByLabelText("비교")).getByText(/＋/);
  expect(added.textContent).toContain("결론");
});

it("writes a new version with multiple ordered, typed sections", async () => {
  const call = vi.spyOn(gateway, "call").mockResolvedValue({});
  const onSaved = vi.fn(async () => {});
  render(
    <ReportVersionDialog
      caseId={base.case_id}
      reportId={base.report_id}
      evidenceId={base.evidence_ids[0]}
      base={base}
      reportTitle={base.title}
      citations={[]}
      onClose={vi.fn()}
      onSaved={onSaved}
    />,
  );
  // Starts from the shown version's sections.
  expect((screen.getByLabelText("섹션 1 제목") as HTMLInputElement).value).toBe(
    base.sections[0].title,
  );
  fireEvent.click(screen.getByText("섹션 추가"));
  fireEvent.change(screen.getByLabelText("섹션 2 유형"), {
    target: { value: "CONCLUSION" },
  });
  fireEvent.change(screen.getByLabelText("섹션 2 제목"), {
    target: { value: "결론" },
  });
  fireEvent.change(screen.getByLabelText("섹션 2 내용"), {
    target: { value: "최종 판단" },
  });
  fireEvent.click(
    within(screen.getByRole("group", { name: "섹션 2" })).getByText("위로"),
  );
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(onSaved).toHaveBeenCalled());
  const [op, payload] = call.mock.calls[0] as [string, Row];
  expect(op).toBe("reports.version");
  expect(
    payload.sections.map((s: Row) => [s.order, s.section_type, s.title]),
  ).toEqual([
    [1, "CONCLUSION", "결론"],
    [2, base.sections[0].section_type, base.sections[0].title],
  ]);
  expect(payload.limitations).toEqual(base.limitations);
});

it("keeps at least one section", () => {
  render(
    <ReportVersionDialog
      caseId={base.case_id}
      reportId={base.report_id}
      evidenceId=""
      base={undefined}
      reportTitle="보고서"
      citations={[]}
      onClose={vi.fn()}
      onSaved={vi.fn(async () => {})}
    />,
  );
  expect(screen.getByText("섹션 삭제").hasAttribute("disabled")).toBe(true);
});

it("lists search history and re-searches with the analyst's original text", async () => {
  const execution = {
    execution_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    query_text: "readme",
    query_mode: "PREFIX",
    options: { original_query_text: "README" },
    result_count: 3,
    started_at: "2026-10-20T01:00:00.000000Z",
  };
  vi.spyOn(gateway, "call").mockResolvedValue([execution]);
  const onSearch = vi.fn();
  render(<SearchHistory caseId="case" zone="Asia/Seoul" onSearch={onSearch} />);
  const details = screen.getByText("검색 이력").closest("details")!;
  details.open = true;
  fireEvent(details, new Event("toggle"));
  fireEvent.click(await within(details).findByText("다시 검색"));
  expect(onSearch).toHaveBeenCalledWith("README", "PREFIX");
});

// Review on PR #31: resaving must not downgrade section state or narrow evidence.
const enriched: Row = {
  ...base,
  evidence_ids: [base.evidence_ids[0], "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"],
  sections: [
    {
      ...base.sections[0],
      content_kind: "TABLE_DATA",
      structured_data: { rows: [["a.txt", "2026-10-20"]] },
      source_kind: "AI_DRAFT",
      source_resource_ids: ["resource-1"],
      is_partial: true,
      stale_reasons: ["SOURCE_REVISION_CHANGED"],
      coverage: { status: "SNAPSHOT_DERIVED" },
      warnings: [
        { code: "REPORT_SECTION_PARTIAL" },
        { code: "REPORT_SECTION_STALE" },
      ],
    },
  ],
};

async function saveFrom(
  props: Partial<React.ComponentProps<typeof ReportVersionDialog>>,
) {
  const call = vi.spyOn(gateway, "call").mockResolvedValue({});
  const onSaved = vi.fn(async () => {});
  render(
    <ReportVersionDialog
      caseId={base.case_id}
      reportId={base.report_id}
      evidenceId="ffffffff-ffff-4fff-8fff-ffffffffffff"
      base={enriched}
      reportTitle={base.title}
      citations={[]}
      onClose={vi.fn()}
      onSaved={onSaved}
      {...props}
    />,
  );
  return { call, onSaved };
}

it("keeps table data, AI origin, partial/stale state and warnings of edited sections", async () => {
  const { call, onSaved } = await saveFrom({});
  expect(screen.getByText(/유지되는 상태:/).textContent).toContain("AI_DRAFT");
  fireEvent.change(screen.getByLabelText("섹션 1 내용"), {
    target: { value: "분석자가 고친 내용" },
  });
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(onSaved).toHaveBeenCalled());
  const section = (call.mock.calls[0][1] as Row).sections[0];
  const source = enriched.sections[0];
  for (const key of [
    "content_kind",
    "structured_data",
    "source_kind",
    "source_resource_ids",
    "is_partial",
    "stale_reasons",
    "coverage",
    "warnings",
  ])
    expect(section[key]).toEqual(source[key]);
  expect(section.content).toBe("분석자가 고친 내용");
});

it("keeps the report's evidence scope instead of the on-screen evidence", async () => {
  const { call, onSaved } = await saveFrom({});
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(onSaved).toHaveBeenCalled());
  expect((call.mock.calls[0][1] as Row).evidence_ids).toEqual(
    enriched.evidence_ids,
  );
});

it("uses the selected evidence only for a first version", async () => {
  const { call, onSaved } = await saveFrom({ base: undefined });
  fireEvent.change(screen.getByLabelText("섹션 1 내용"), {
    target: { value: "첫 버전" },
  });
  fireEvent.change(screen.getByLabelText("요약"), {
    target: { value: "요약" },
  });
  fireEvent.change(screen.getByLabelText("분석의 한계 (줄마다 하나)"), {
    target: { value: "합성" },
  });
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(onSaved).toHaveBeenCalled());
  const payload = call.mock.calls[0][1] as Row;
  expect(payload.evidence_ids).toEqual([
    "ffffffff-ffff-4fff-8fff-ffffffffffff",
  ]);
  // A new section has nothing to preserve and lets Core apply its defaults.
  expect(payload.sections[0]).not.toHaveProperty("source_kind");
});

it("preserves report-wide provenance when editing a snapshot-backed version", async () => {
  const provenance = {
    context_snapshot_ids: ["snapshot-a"],
    search_execution_ids: ["search-a"],
    timeline_revisions: [3],
    ai_assistance_request_ids: ["request-a"],
    ai_result_ids: ["result-a"],
    analyzer_versions: { filesystem: "1.0" },
  };
  const { call, onSaved } = await saveFrom({
    base: { ...enriched, ...provenance },
  });
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(onSaved).toHaveBeenCalled());
  expect(call.mock.calls[0][1]).toMatchObject(provenance);
});

it("resubmits legacy section-only snapshots for Core case and revision validation", async () => {
  const { call, onSaved } = await saveFrom({
    base: {
      ...base,
      context_snapshot_ids: [],
      sections: base.sections.map((s: Row) => ({
        ...s,
        context_snapshot_ids: ["snapshot-a"],
      })),
    },
  });
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(onSaved).toHaveBeenCalled());
  expect((call.mock.calls[0][1] as Row).context_snapshot_ids).toEqual([
    "snapshot-a",
  ]);
});
