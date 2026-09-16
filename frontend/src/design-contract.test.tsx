// @vitest-environment jsdom
import React from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { App } from "./App";
import {
  ArtifactSemantics,
  Fields,
  RawPreview,
  Table,
  fileIconName,
} from "./ui";
import { FormDialog, GovernanceAudit } from "./panels";
import { createDemoBridge } from "./demoBridge";
import { errorText, unwrap } from "./gateway";
import core from "./__fixtures__/core.json";

afterEach(() => {
  cleanup();
  delete window.apex;
});
async function openFiles() {
  render(<App />);
  await screen.findByText("분석 엔진 연결됨");
  fireEvent.change(screen.getByLabelText("현재 사건"), {
    target: { value: core.cases[0].id },
  });
  await waitFor(() =>
    expect(
      (screen.getByLabelText("현재 증거") as HTMLSelectElement).value,
    ).toBe(core.evidence[0].id),
  );
  fireEvent.click(screen.getByRole("button", { name: "조사" }));
}
it("keeps unavailable and failed list queries distinct from empty results (FT-003/013)", async () => {
  const bridge = createDemoBridge(),
    original = bridge.invoke.bind(bridge);
  bridge.invoke = async (op, p) =>
    op === "files.list"
      ? { ok: false, error: { code: "CAPABILITY_UNAVAILABLE" } }
      : original(op, p);
  window.apex = bridge;
  await openFiles();
  await screen.findByRole("alert");
  expect(screen.queryByText("조회 결과가 없습니다")).toBeNull();
});
it("gates Raw on the engine's available actions", async () => {
  const bridge = createDemoBridge(),
    original = bridge.invoke.bind(bridge);
  bridge.invoke = async (op, p) => {
    const reply = await original(op, p);
    if (op === "view" && reply.ok)
      return {
        ok: true,
        data: {
          ...reply.data,
          available_actions: ["view.simple", "view.detailed"],
        },
      };
    return reply;
  };
  window.apex = bridge;
  await openFiles();
  fireEvent.click(await screen.findByText("README.txt"));
  await waitFor(() =>
    expect(
      (screen.getByRole("button", { name: "원본" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true),
  );
});
it("blocks fractional and oversized raw ranges (FT-007)", async () => {
  window.apex = createDemoBridge();
  await openFiles();
  fireEvent.click(await screen.findByText("README.txt"));
  fireEvent.click(screen.getByRole("button", { name: "원본" }));
  const read = await screen.findByRole("button", { name: "원본 범위 읽기" });
  for (const [label, value] of [
    ["길이 (최대 1 MiB)", "1048577"],
    ["길이 (최대 1 MiB)", "1.5"],
    ["오프셋", "-1"],
  ]) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
    expect((read as HTMLButtonElement).disabled).toBe(true);
  }
});
it("preserves the engine's hex/text previews and truncation notice", () => {
  render(
    <RawPreview
      data={{
        hex_preview: "41 50 45 58",
        text_preview: "APEX 원본",
        truncated: true,
        returned_offset: 0,
      }}
    />,
  );
  expect(screen.getByLabelText("원본 Hex").textContent).toBe("41 50 45 58");
  fireEvent.click(screen.getByRole("button", { name: "텍스트" }));
  expect(screen.getByLabelText("원본 텍스트").textContent).toBe("APEX 원본");
  expect(screen.getByText(/요청 범위 또는 화면 미리보기/)).toBeTruthy();
});
it.each([
  ["BROWSER_DELETED_SQLITE_ROW", "삭제 후보"],
  ["BROWSER_PRIVATE_MODE_CANDIDATE", "비공개 모드 후보"],
])("marks %s as a candidate (FT-011)", (type, label) => {
  render(<ArtifactSemantics row={{ artifact_type: type }} />);
  expect(screen.getByText(label)).toBeTruthy();
});
it("labels fingerprints without suggesting a secret reveal (FT-027)", () => {
  render(
    <Fields
      value={{
        pragma_key: "<redacted>",
        pragma_key_hash: "a".repeat(64),
        user_nonce_hash: "b".repeat(64),
      }}
    />,
  );
  expect(screen.getByText("Pragma key Fingerprint")).toBeTruthy();
  expect(screen.getByText("User nonce Fingerprint")).toBeTruthy();
  expect(screen.getByText("보호됨 (redacted)")).toBeTruthy();
  expect(screen.queryByRole("button", { name: /보기|reveal/ })).toBeNull();
});
it("displays engine governance decisions as assessments, including transformations", () => {
  render(
    <GovernanceAudit
      audit={{
        audit_id: "test-assessment",
        created_at: "2026-09-16T00:00:00Z",
        redaction_applied: false,
        projection_applied: false,
        result: {
          decision: "ALLOW_PROJECTION_ONLY",
          destination: "EXTERNAL",
          policy_revision: 3,
          reason: "Projection required",
          data: {
            classification: "SENSITIVE",
            source: {
              case_id: "case-a",
              source_id: "source-a",
              source_type: "ARTIFACT",
            },
          },
        },
      }}
    />,
  );
  expect(screen.getAllByText("안전한 투영 생성 후 재평가")[0]).toBeTruthy();
  expect(screen.getAllByText("SENSITIVE")[0]).toBeTruthy();
  expect(screen.getAllByText("EXTERNAL")[0]).toBeTruthy();
  expect(screen.queryByRole("button", { name: /실행/ })).toBeNull();
});
it("bounds rendered rows for 10,000 results and reaches the last rows", () => {
  const rows = Array.from({ length: 10000 }, (_, i) => ({
    id: String(i),
    name: `item-${i}`,
  }));
  const { container } = render(
    <Table rows={rows} columns={[{ key: "name", label: "이름" }]} />,
  );
  expect(
    container.querySelectorAll("tbody tr[data-row-index]").length,
  ).toBeLessThan(50);
  const el = container.querySelector(".table-scroll")!;
  fireEvent.scroll(el, { target: { scrollTop: 9990 * 36 } });
  expect(screen.getByText("item-9999")).toBeTruthy();
  expect(
    container.querySelectorAll("tbody tr[data-row-index]").length,
  ).toBeLessThan(50);
});
it("supports keyboard selection and marks deleted rows (FT-008)", () => {
  const select = vi.fn();
  const { container } = render(
    <Table
      rows={[
        { id: "a", name: "한글.txt" },
        { id: "b", name: "삭제.txt", is_deleted: true },
      ]}
      columns={[{ key: "name", label: "이름" }]}
      onSelect={select}
    />,
  );
  const row = container.querySelector('tr[data-row-index="0"]')!;
  fireEvent.keyDown(row, { key: "ArrowDown" });
  expect(select).toHaveBeenCalledWith(expect.objectContaining({ id: "b" }));
  expect(container.querySelector("tr.deleted")?.textContent).toContain(
    "삭제.txt",
  );
});
it("traps dialog focus and restores the invoking control", () => {
  const close = vi.fn();
  const launch = document.createElement("button");
  document.body.append(launch);
  launch.focus();
  const { unmount } = render(
    <FormDialog
      title="편집"
      fields={[{ key: "value", label: "내용" }]}
      onClose={close}
      onSubmit={async () => {}}
    />,
  );
  const last = screen.getByRole("button", { name: "저장" });
  last.focus();
  fireEvent.keyDown(last, { key: "Tab" });
  expect(document.activeElement).toBe(
    screen.getByRole("button", { name: "닫기" }),
  );
  fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
  expect(close).toHaveBeenCalledOnce();
  unmount();
  expect(document.activeElement).toBe(launch);
  launch.remove();
});
it("honors known Korean message keys and does not expose developer messages", () => {
  try {
    unwrap({
      ok: false,
      error: {
        code: "UNMAPPED",
        message_key: "error.evidence.capability_unavailable",
      },
    });
  } catch (error) {
    expect(errorText(error)).toContain("현재 환경에서 이 기능");
  }
});
it("maps directory, uppercase extension and unknown filenames to bundled icons", () => {
  expect(fileIconName({ node_type: "ROOT" })).toBe("folder-base");
  expect(fileIconName({ extension: ".PDF" })).toBe("pdf");
  expect(fileIconName({ original_name: "검토.SQLite" })).toBe("database");
  expect(fileIconName({ original_name: "한글.unknown" })).toBe("document");
});
