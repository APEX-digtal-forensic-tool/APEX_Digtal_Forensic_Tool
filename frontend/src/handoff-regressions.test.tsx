// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { ReportVersionDialog, SearchHistory } from "./ReportTools";
import { Reports } from "./panels";
import { gateway, type Row } from "./gateway";
import fixture from "./__fixtures__/report.json";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});
const base = fixture.detail.versions[0] as Row;
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => {
    resolve = done;
    reject = fail;
  });
  return { promise, resolve, reject };
}
const execution = {
  execution_id: "old",
  query_text: "CASE_A_ONLY",
  query_mode: "EXACT",
  started_at: "2026-10-20T01:00:00Z",
  result_count: 1,
};
async function openHistory() {
  const details = screen.getByText("검색 이력").closest("details")!;
  await act(async () => {
    details.open = true;
    await new Promise((done) => setTimeout(done, 0));
  });
}
function editor(version: Row, evidenceId = "") {
  return (
    <ReportVersionDialog
      caseId={version.case_id}
      reportId={version.report_id}
      evidenceId={evidenceId}
      base={version}
      reportTitle={version.title}
      citations={[]}
      onClose={vi.fn()}
      onSaved={vi.fn(async () => {})}
    />
  );
}

it("audit: copying a section preserves structured data, provenance and partial/stale state", async () => {
  const rich = {
    ...base,
    sections: [
      {
        ...base.sections[0],
        content_kind: "TABLE_DATA",
        structured_data: { rows: [{ finding: "preserve me" }] },
        source_kind: "AI_DRAFT",
        is_partial: true,
        stale_reasons: ["SOURCE_CHANGED"],
        warnings: [{ code: "REPORT_SECTION_PARTIAL" }],
        coverage: { status: "PARTIAL" },
      },
    ],
  };
  const call = vi.spyOn(gateway, "call").mockResolvedValue({});
  render(editor(rich));
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(call).toHaveBeenCalled());
  const payload = call.mock.calls[0][1] as Row;
  expect(payload.sections[0]).toMatchObject({
    content_kind: "TABLE_DATA",
    structured_data: rich.sections[0].structured_data,
    source_kind: "AI_DRAFT",
    is_partial: true,
    stale_reasons: ["SOURCE_CHANGED"],
    coverage: { status: "PARTIAL" },
  });
});

it("audit: editing an existing multi-evidence report preserves its evidence scope", async () => {
  const evidence_ids = [
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  ];
  const call = vi.spyOn(gateway, "call").mockResolvedValue({});
  render(editor({ ...base, evidence_ids }, evidence_ids[0]));
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(call).toHaveBeenCalled());
  expect((call.mock.calls[0][1] as Row).evidence_ids).toEqual(evidence_ids);
});

it("audit: an existing empty evidence scope is not replaced by unrelated screen selection", async () => {
  const call = vi.spyOn(gateway, "call").mockResolvedValue({});
  render(
    editor(
      { ...base, evidence_ids: [] },
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    ),
  );
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() => expect(call).toHaveBeenCalled());
  expect((call.mock.calls[0][1] as Row).evidence_ids).toEqual([]);
});

it("audit: switching case rejects the old case history response", async () => {
  const pending = deferred<Row[]>();
  vi.spyOn(gateway, "call").mockImplementation(
    async <T = Row,>(_: string, p?: Row): Promise<T> => {
      const result = p?.case_id === "A" ? await pending.promise : [];
      return result as T;
    },
  );
  const view = render(
    <SearchHistory caseId="A" zone="UTC" onSearch={vi.fn()} />,
  );
  await openHistory();
  view.rerender(<SearchHistory caseId="B" zone="UTC" onSearch={vi.fn()} />);
  await act(async () => pending.resolve([execution]));
  expect(screen.queryByText("CASE_A_ONLY")).toBeNull();
});

it("audit: an open search history reloads on case change", async () => {
  const call = vi.spyOn(gateway, "call").mockResolvedValue([]);
  const view = render(
    <SearchHistory caseId="A" zone="UTC" onSearch={vi.fn()} />,
  );
  await openHistory();
  await screen.findByText("아직 실행한 검색이 없습니다.");
  view.rerender(<SearchHistory caseId="B" zone="UTC" onSearch={vi.fn()} />);
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith("search.history", { case_id: "B" }),
  );
});

it("audit: opening the editor during report loading must preserve the loaded sections", async () => {
  const pending = deferred<Row>();
  vi.spyOn(gateway, "call").mockImplementation(
    async <T = Row,>(op: string): Promise<T> => {
      if (op === "reports.list") return { items: [fixture.report] } as T;
      if (op === "reports.get") return (await pending.promise) as T;
      throw new Error(op);
    },
  );
  render(
    <Reports
      caseId={base.case_id}
      evidenceId=""
      renderer={{}}
      onNotice={vi.fn()}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: new RegExp(fixture.report.title),
    }),
  );
  const button = screen.getByRole("button", { name: "새 버전 작성" });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(button);
  expect(screen.queryByRole("dialog")).toBeNull();
  await act(async () => pending.resolve(fixture.detail));
  expect((button as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(button);
  expect(
    (screen.getByLabelText("섹션 1 내용") as HTMLTextAreaElement).value,
  ).toBe(base.sections[0].content);
});

it("discards an old rejection after rapid case switches and allows current retry", async () => {
  const a = deferred<Row[]>(),
    b = deferred<Row[]>();
  const call = vi
    .spyOn(gateway, "call")
    .mockImplementation(async <T = Row,>(_: string, p?: Row): Promise<T> => {
      return (
        p?.case_id === "A"
          ? await a.promise
          : p?.case_id === "B"
            ? await b.promise
            : []
      ) as T;
    });
  const view = render(
    <SearchHistory caseId="A" zone="UTC" onSearch={vi.fn()} />,
  );
  await openHistory();
  view.rerender(<SearchHistory caseId="B" zone="UTC" onSearch={vi.fn()} />);
  view.rerender(<SearchHistory caseId="C" zone="UTC" onSearch={vi.fn()} />);
  await act(async () => {
    a.reject(new Error("A failed"));
    b.resolve([execution]);
  });
  await screen.findByText("아직 실행한 검색이 없습니다.");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.queryByText("CASE_A_ONLY")).toBeNull();
  call.mockRejectedValueOnce(new Error("current failure"));
  view.rerender(<SearchHistory caseId="D" zone="UTC" onSearch={vi.fn()} />);
  await screen.findByRole("alert");
  call.mockResolvedValueOnce([{ ...execution, query_text: "D_RESULT" }]);
  fireEvent.click(screen.getByText("다시 시도"));
  await screen.findByText("D_RESULT");
});

it("a closed history cancels its pending view and reopening loads fresh history", async () => {
  const pending = deferred<Row[]>();
  const call = vi
    .spyOn(gateway, "call")
    .mockReturnValueOnce(pending.promise)
    .mockResolvedValue([]);
  render(<SearchHistory caseId="A" zone="UTC" onSearch={vi.fn()} />);
  await openHistory();
  const details = screen.getByText("검색 이력").closest("details")!;
  await act(async () => {
    details.open = false;
    await new Promise((done) => setTimeout(done, 0));
  });
  await act(async () => pending.resolve([execution]));
  await openHistory();
  await screen.findByText("아직 실행한 검색이 없습니다.");
  expect(call).toHaveBeenCalledTimes(2);
  expect(screen.queryByText("CASE_A_ONLY")).toBeNull();
});

it("report details failure blocks editing until retry succeeds, including a first version", async () => {
  let fails = true;
  vi.spyOn(gateway, "call").mockImplementation(
    async <T = Row,>(op: string): Promise<T> => {
      if (op === "reports.list") return { items: [fixture.report] } as T;
      if (op === "reports.get") {
        if (fails) throw new Error("detail failure");
        return { ...fixture.detail, versions: [] } as T;
      }
      throw new Error(op);
    },
  );
  render(
    <Reports
      caseId={base.case_id}
      evidenceId=""
      renderer={{}}
      onNotice={vi.fn()}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: new RegExp(fixture.report.title),
    }),
  );
  await screen.findByRole("alert");
  expect(
    (screen.getByText("새 버전 작성").closest("button") as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  fails = false;
  fireEvent.click(screen.getByText("다시 시도"));
  await waitFor(() =>
    expect(
      (screen.getByText("새 버전 작성").closest("button") as HTMLButtonElement)
        .disabled,
    ).toBe(false),
  );
  fireEvent.click(screen.getByText("새 버전 작성"));
  expect(screen.getByRole("dialog")).toBeTruthy();
  expect(
    (screen.getByLabelText("섹션 1 내용") as HTMLTextAreaElement).value,
  ).toBe("");
});

it("pins the editor source and scope while underlying version and selection change", async () => {
  const older = {
    ...base,
    report_version_id: "older",
    version_number: 1,
    evidence_ids: [],
  };
  const newer = {
    ...base,
    report_version_id: "newer",
    version_number: 2,
    evidence_ids: ["new-evidence"],
  };
  const call = vi
    .spyOn(gateway, "call")
    .mockImplementation(async <T = Row,>(op: string): Promise<T> => {
      if (op === "reports.list") return { items: [fixture.report] } as T;
      if (op === "reports.get")
        return { ...fixture.detail, versions: [older, newer] } as T;
      if (op === "reports.version") return {} as T;
      throw new Error(op);
    });
  const view = render(
    <Reports
      caseId={base.case_id}
      evidenceId="screen-one"
      renderer={{}}
      onNotice={vi.fn()}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: new RegExp(fixture.report.title),
    }),
  );
  await screen.findByLabelText("보고서 버전");
  fireEvent.change(screen.getByLabelText("보고서 버전"), {
    target: { value: "older" },
  });
  fireEvent.click(screen.getByText("새 버전 작성"));
  fireEvent.change(screen.getByLabelText("섹션 1 내용"), {
    target: { value: "분석자가 편집한 내용" },
  });
  fireEvent.change(screen.getByLabelText("보고서 버전"), {
    target: { value: "newer" },
  });
  view.rerender(
    <Reports
      caseId={base.case_id}
      evidenceId="screen-two"
      renderer={{}}
      onNotice={vi.fn()}
    />,
  );
  expect(
    (screen.getByLabelText("섹션 1 내용") as HTMLTextAreaElement).value,
  ).toBe("분석자가 편집한 내용");
  fireEvent.submit(screen.getByRole("dialog"));
  await waitFor(() =>
    expect(call.mock.calls.some(([op]) => op === "reports.version")).toBe(true),
  );
  const payload = call.mock.calls.find(
    ([op]) => op === "reports.version",
  )![1] as Row;
  expect(payload.evidence_ids).toEqual([]);
  expect(payload.sections[0].content).toBe("분석자가 편집한 내용");
});
