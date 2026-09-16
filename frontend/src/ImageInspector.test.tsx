// @vitest-environment jsdom
import React from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { ImageInspector } from "./ImageInspector";
import { createDemoBridge } from "./demoBridge";
import { RawPreview } from "./ui";

afterEach(() => {
  cleanup();
  delete window.apex;
  vi.restoreAllMocks();
});
beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function () {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function () {
    this.removeAttribute("open");
  };
});
const preview = {
  image_url: "data:image/png;base64,AA==",
  width: 860,
  height: 860,
  preview_width: 860,
  preview_height: 860,
  color_mode: "RGBA",
  format: "PNG",
  channel: "RGB",
  source_sha256: "a".repeat(64),
};
it("uses the engine for original pixel extraction and preserves executed conditions", async () => {
  const bridge = createDemoBridge();
  bridge.invoke = vi.fn(async (_op, p) => ({
    ok: true as const,
    data:
      p.action === "EXTRACT"
        ? {
            ...p,
            text: "TEST{pixels}",
            hex: "54455354",
            returned_bytes: 12,
            available_bytes: 200,
            has_more: true,
            export_relative_path: "image-analysis/result.json",
          }
        : preview,
  }));
  window.apex = bridge;
  render(
    <ImageInspector
      caseId="case-a"
      resourceType="ARTIFACT"
      resourceId="artifact-a"
    />,
  );
  fireEvent.click(
    screen.getByText("이미지 보기 · 비트 분석", { selector: "button" }),
  );
  await screen.findByAltText("증거 이미지 · RGB");
  fireEvent.change(screen.getByLabelText("채널 순서"), {
    target: { value: "RR" },
  });
  expect(
    (screen.getByRole("button", { name: "비트 추출" }) as HTMLButtonElement)
      .disabled,
  ).toBe(true);
  fireEvent.change(screen.getByLabelText("채널 순서"), {
    target: { value: "BGR" },
  });
  fireEvent.click(screen.getByRole("button", { name: "비트 추출" }));
  await screen.findByDisplayValue("TEST{pixels}");
  expect(bridge.invoke).toHaveBeenLastCalledWith(
    "media.inspect",
    expect.objectContaining({
      case_id: "case-a",
      resource_id: "artifact-a",
      action: "EXTRACT",
      channels: "BGR",
      bit: 0,
    }),
  );
  fireEvent.change(screen.getByLabelText("채널 순서"), {
    target: { value: "RGB" },
  });
  expect(screen.getByLabelText("비트 추출 결과").textContent).toContain(
    "BGR · bit 0",
  );
});
it("does not display an old image response after changing the selected resource", async () => {
  let resolveOld!: (value: any) => void;
  const bridge = createDemoBridge();
  bridge.invoke = async (_op, p) =>
    p.resource_id === "old"
      ? new Promise((resolve) => {
          resolveOld = resolve;
        })
      : { ok: true as const, data: { ...preview, width: 12 } };
  window.apex = bridge;
  const view = render(
    <ImageInspector
      key="old"
      caseId="case"
      resourceType="ARTIFACT"
      resourceId="old"
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "이미지 보기 · 비트 분석" }),
  );
  view.rerender(
    <ImageInspector
      key="new"
      caseId="case"
      resourceType="ARTIFACT"
      resourceId="new"
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "이미지 보기 · 비트 분석" }),
  );
  await screen.findByText(/12 × 860/);
  resolveOld({ ok: true as const, data: preview });
  await waitFor(() => expect(screen.queryByText(/860 × 860/)).toBeNull());
});
it("distinguishes remaining bytes from truncated preview at both range and EOF", () => {
  const view = render(
    <RawPreview
      data={{
        total_length: 1000,
        returned_offset: 0,
        returned_length: 256,
        truncated: false,
      }}
    />,
  );
  expect(screen.getByText("744")).toBeTruthy();
  expect(screen.queryByText("추가 원본 있음")).toBeNull();
  view.rerender(
    <RawPreview
      data={{
        total_length: 1000,
        returned_offset: 900,
        returned_length: 100,
        truncated: false,
      }}
    />,
  );
  expect(screen.getByText("0")).toBeTruthy();
});
