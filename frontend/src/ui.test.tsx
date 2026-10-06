// @vitest-environment jsdom
import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { App } from "./App";
import { Badge, ErrorState, Fields, ResultState, size, time } from "./ui";
import { DesktopGateway, GatewayError, validateContract } from "./gateway";
import { createDemoBridge } from "./demoBridge";
import core from "./__fixtures__/core.json";

afterEach(() => {
  cleanup();
  delete window.apex;
});

describe("canonical Core contracts", () => {
  for (const [schema, data] of [
    ["case", core.cases[0]],
    ["evidence", core.evidence[0]],
    ["file", core.files.items[0]],
    ["gui-session-context", core.context],
    ["runtime-capability-report", core.runtime.capabilities],
  ] as const) {
    it(`accepts actual ${schema} DTO`, () =>
      expect(() => validateContract(schema, data)).not.toThrow());
  }
  it("rejects an invented GUI route", () =>
    expect(() =>
      validateContract("gui-session-context", {
        ...core.context,
        current_route: "COMMUNICATIONS",
      }),
    ).toThrow("CONTRACT_MISMATCH"));
  it("rejects writable evidence", () =>
    expect(() =>
      validateContract("evidence", { ...core.evidence[0], read_only: false }),
    ).toThrow());
  it("rejects silently truncated DTOs", () =>
    expect(() => validateContract("file", { id: "fake" })).toThrow());
  it("does not replace unavailable transport with mock data", async () => {
    await expect(new DesktopGateway().call("cases.list")).rejects.toThrow(
      "DESKTOP_REQUIRED",
    );
  });
});

describe("honest forensic result state", () => {
  const states = {
    AVAILABLE: "사용 가능",
    AVAILABLE_WITH_LIMITATIONS: "제한적 사용",
    CAPABILITY_UNAVAILABLE: "사용 불가",
    EXTERNAL_CONFIGURATION_REQUIRED: "외부 설정 필요",
    UNSUPPORTED_PLATFORM: "플랫폼 미지원",
    BLOCKED_EXTERNAL_FIXTURE: "검증 자료 필요",
    HOST_VERIFICATION_REQUIRED: "호스트 검증 필요",
  };
  for (const [value, label] of Object.entries(states))
    it(`distinguishes ${value}`, () => {
      render(<Badge value={value} />);
      expect(screen.getByText(label)).toBeTruthy();
    });
  it("shows partial and stale together", () => {
    render(<ResultState data={{ is_partial: true, is_stale: true }} />);
    expect(screen.getByText("부분 결과")).toBeTruthy();
    expect(screen.getByText("갱신 필요")).toBeTruthy();
  });
  it("shows warnings alongside a populated result", () => {
    render(<ResultState data={{ warnings: [{ code: "PARSER_WARNING" }] }} />);
    expect(screen.getByText("경고 1건")).toBeTruthy();
  });
  it("does not display a developer message", () => {
    render(
      <Fields value={{ developer_message: "private path", code: "FAIL" }} />,
    );
    expect(screen.queryByText("private path")).toBeNull();
  });
  it("does not turn null size into zero", () => expect(size(null)).toBe("—"));
  it("retains an actual zero byte file", () => expect(size(0)).toBe("0 B"));
  it("does not infer UTC for a naive timestamp", () =>
    expect(time("2026-09-15T11:00:00", "Asia/Seoul")).toContain(
      "시간대 미확정",
    ));
  it("retains missing normalized time", () =>
    expect(time(null, "Asia/Seoul")).toBe("—"));
  it("shows explicit time zone conversion", () =>
    expect(time("2026-09-15T00:00:00Z", "Asia/Seoul")).toContain("09:00:00"));
  it("transformation-required is not final ALLOW", () => {
    render(<Badge value="ALLOW_WITH_REDACTION" />);
    expect(screen.getByText("민감정보 제거 후 재평가")).toBeTruthy();
    expect(screen.queryByText("허용")).toBeNull();
  });
  it("capability error is not zero results", () => {
    render(<ErrorState error={new GatewayError("CAPABILITY_UNAVAILABLE")} />);
    expect(screen.queryByText("조회 결과가 없습니다")).toBeNull();
    expect(screen.getByText(/현재 환경에서 이 기능/)).toBeTruthy();
  });
});

describe("desktop screens through the bridge", () => {
  beforeEach(() => {
    window.apex = createDemoBridge();
  });
  it("starts without an account login", async () => {
    render(<App />);
    await screen.findByText("데모 · 합성 데이터");
    expect(screen.getByText("먼저 사건을 선택해주세요")).toBeTruthy();
  });
  it("connects case, evidence, lazy file list and inspector", async () => {
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
    const file = await within(await screen.findByRole("table")).findByText(
      "한글-분석노트.txt",
    );
    fireEvent.click(file);
    await waitFor(() =>
      expect(screen.getAllByText("한글-분석노트.txt").length).toBeGreaterThan(
        1,
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "메타데이터" }));
    await waitFor(() => {
      const el = document.querySelector(".file-viewer");
      expect(el?.textContent).toContain("인용 근거");
    });
  });
  it("exposes no generic pause button", async () => {
    render(<App />);
    await screen.findByText("데모 · 합성 데이터");
    fireEvent.click(screen.getByText("작업 0"));
    expect(screen.queryByRole("button", { name: /일시정지|Pause/ })).toBeNull();
  });
  it("AI stays visibly unconfigured", async () => {
    render(<App />);
    fireEvent.click(screen.getByTitle("AI 도우미"));
    expect(screen.getByText("AI 서비스 연결이 필요합니다")).toBeTruthy();
    expect(
      (
        screen.getByRole("button", {
          name: "현재 선택 분석 요청",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(true);
  });
  it("holds subsequent context edits until a conflict is resolved", async () => {
    const bridge = createDemoBridge();
    const invoke = bridge.invoke.bind(bridge);
    let writes = 0;
    bridge.invoke = async (op, input) => {
      if (op === "context.update" && ++writes === 1)
        return { ok: false, error: { code: "CONTEXT_REVISION_CONFLICT" } };
      return invoke(op, input);
    };
    window.apex = bridge;
    render(<App />);
    await screen.findByText("데모 · 합성 데이터");
    fireEvent.change(screen.getByLabelText("현재 사건"), {
      target: { value: core.cases[0].id },
    });
    await screen.findByRole("button", { name: "내 선택 다시 적용" });
    fireEvent.click(screen.getByRole("button", { name: "파일 시스템" }));
    await within(await screen.findByRole("table")).findByText(
      "한글-분석노트.txt",
    );
    expect(writes).toBe(1);
    fireEvent.click(screen.getByRole("button", { name: "내 선택 다시 적용" }));
    await waitFor(() => expect(writes).toBe(2));
    expect(
      screen.queryByRole("button", { name: "내 선택 다시 적용" }),
    ).toBeNull();
  });
});
