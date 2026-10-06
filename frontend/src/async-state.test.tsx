// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { App } from "./App";
import { Reports } from "./panels";
import { createDemoBridge } from "./demoBridge";
import type { Reply, Row } from "./gateway";
import core from "./__fixtures__/core.json";
// Synthetic report/version DTOs generated through the real Core services.
import reportFixture from "./__fixtures__/report.json";

afterEach(() => {
  cleanup();
  delete window.apex;
});
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function openFiles() {
  render(<App />);
  await screen.findByText("데모 · 합성 데이터");
  fireEvent.change(screen.getByLabelText("현재 사건"), {
    target: { value: core.cases[0].id },
  });
  await waitFor(() =>
    expect(
      (screen.getByLabelText("현재 증거") as HTMLSelectElement).value,
    ).toBe(core.evidence[0].id),
  );
  fireEvent.click(screen.getByRole("button", { name: "파일 시스템" }));
}

it.each([false, true])(
  "ignores a previous file's delayed raw reply (error=%s)",
  async (error) => {
    const bridge = createDemoBridge();
    const original = bridge.invoke.bind(bridge);
    const raw = deferred<Reply<Row>>();
    let requests = 0;
    bridge.invoke = async (op, payload) => {
      if (op === "raw.read" && ++requests === 1) return raw.promise;
      return original(op, payload);
    };
    window.apex = bridge;
    await openFiles();
    fireEvent.click(
      await within(await screen.findByRole("table")).findByText("README.txt"),
    );
    await waitFor(() => expect(requests).toBe(1));
    fireEvent.click(
      within(screen.getByRole("table")).getByText("한글-분석노트.txt"),
    );
    await waitFor(() => expect(requests).toBe(2));
    await act(async () =>
      raw.resolve(
        error
          ? { ok: false, error: { code: "RAW_RANGE_NOT_SATISFIABLE" } }
          : { ok: true, data: { text_preview: "RAW_BYTES_FROM_FILE_A" } },
      ),
    );
    expect(document.querySelector(".file-viewer")?.textContent).toContain(
      "한글-분석노트.txt",
    );
    expect(screen.queryByText("RAW_BYTES_FROM_FILE_A")).toBeNull();
    expect(screen.queryByText("원본 데이터 범위를 벗어났습니다.")).toBeNull();
  },
);

it("only displays the latest raw request for the current file", async () => {
  const bridge = createDemoBridge();
  const original = bridge.invoke.bind(bridge);
  const first = deferred<Reply<Row>>();
  const second = deferred<Reply<Row>>();
  let requests = 0;
  bridge.invoke = async (op, payload) =>
    op === "raw.read"
      ? ++requests === 1
        ? first.promise
        : second.promise
      : original(op, payload);
  window.apex = bridge;
  await openFiles();
  fireEvent.click(
    await within(await screen.findByRole("table")).findByText("README.txt"),
  );
  await waitFor(() => expect(requests).toBe(1));
  fireEvent.click(screen.getByRole("button", { name: "메타데이터" }));
  await screen.findByRole("button", { name: "원본 위치 및 인용 근거" });
  fireEvent.click(screen.getByRole("button", { name: "Hex" }));
  await waitFor(() => expect(requests).toBe(2));
  fireEvent.click(screen.getByRole("button", { name: "Text" }));
  await act(async () =>
    second.resolve({ ok: true, data: { text_preview: "CURRENT_RAW" } }),
  );
  await act(async () =>
    first.resolve({ ok: true, data: { text_preview: "OLD_RAW" } }),
  );
  expect(screen.getByText("CURRENT_RAW")).toBeTruthy();
  expect(screen.queryByText("OLD_RAW")).toBeNull();
});

it.each([false, true])(
  "refreshes tasks completed between polls (another active=%s)",
  async (anotherActive) => {
    const bridge = createDemoBridge();
    const original = bridge.invoke.bind(bridge);
    let task = false,
      completed = false,
      fileCalls = 0;
    bridge.invoke = async (op, payload) => {
      if (op === "analysis.start") {
        task = true;
        return { ok: true, data: { task_id: "fast", status: "QUEUED" } };
      }
      if (op === "tasks.list")
        return {
          ok: true,
          data: task
            ? [
                {
                  task_id: "fast",
                  kind: "FILES",
                  status: completed ? "SUCCEEDED" : "QUEUED",
                  actions: [],
                },
                ...(anotherActive
                  ? [
                      {
                        task_id: "slow",
                        kind: "ARTIFACTS",
                        status: "RUNNING",
                        actions: [],
                      },
                    ]
                  : []),
              ]
            : [],
        };
      if (op === "files.list") {
        fileCalls++;
        if (!completed)
          return {
            ok: true,
            data: {
              items: [],
              page: { returned: 0, has_more: false, next_cursor: null },
            },
          };
      }
      return original(op, payload);
    };
    window.apex = bridge;
    await openFiles();
    await waitFor(() => expect(fileCalls).toBeGreaterThan(0));
    fireEvent.click(screen.getByRole("button", { name: "분석 시작" }));
    await waitFor(() => expect(fileCalls).toBeGreaterThan(1));
    completed = true;
    await within(
      await screen.findByRole("table", {}, { timeout: 3500 }),
    ).findByText("한글-분석노트.txt");
  },
);

it("preserves review reason and shows the conflict after a delayed refresh", async () => {
  const bridge = createDemoBridge();
  const original = bridge.invoke.bind(bridge);
  const refreshed = deferred<Reply<Row>>();
  let attempts = 0;
  bridge.invoke = async (op, payload) => {
    if (op === "reports.list")
      return {
        ok: true,
        data: {
          items: [reportFixture.report],
          page: { returned: 1, has_more: false, next_cursor: null },
        },
      };
    if (op === "reports.get")
      return attempts
        ? refreshed.promise
        : { ok: true, data: reportFixture.detail };
    if (op === "reports.action") {
      attempts++;
      return { ok: false, error: { code: "REPORT_REVIEW_REVISION_CONFLICT" } };
    }
    return original(op, payload);
  };
  window.apex = bridge;
  render(
    <Reports
      caseId={reportFixture.case_id}
      evidenceId=""
      renderer={{}}
      onNotice={() => {}}
    />,
  );
  fireEvent.click(await screen.findByText("Review repro report"));
  fireEvent.click(await screen.findByRole("button", { name: "검토 제출" }));
  fireEvent.change(screen.getByLabelText("검토·결정 사유"), {
    target: { value: "Preserve my review reason" },
  });
  fireEvent.click(screen.getByRole("button", { name: "기록" }));
  await waitFor(() => expect(attempts).toBe(1));
  expect(
    (screen.getByLabelText("검토·결정 사유") as HTMLTextAreaElement).value,
  ).toBe("Preserve my review reason");
  await act(async () =>
    refreshed.resolve({ ok: true, data: reportFixture.detail }),
  );
  await screen.findByText(/검토 상태가 변경되었습니다/);
  expect(
    (screen.getByLabelText("검토·결정 사유") as HTMLTextAreaElement).value,
  ).toBe("Preserve my review reason");
});
