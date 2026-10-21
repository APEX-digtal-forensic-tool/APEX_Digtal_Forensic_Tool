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
import { Reports } from "./panels";
import { gateway, type Row } from "./gateway";
import fixture from "./__fixtures__/report.json";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it.each([true, false])(
  "requires explicit stale-export confirmation only when stale=%s",
  async (stale) => {
    const version = {
      ...fixture.detail.versions[0],
      stale_state: {
        is_stale: stale,
        reasons: stale ? ["SOURCE_CHANGED"] : [],
      },
    };
    const call = vi
      .spyOn(gateway, "call")
      .mockImplementation(async <T = Row,>(op: string): Promise<T> => {
        if (op === "reports.list") return { items: [fixture.report] } as T;
        if (op === "reports.get")
          return {
            ...fixture.detail,
            versions: [version],
            approvals: {
              [version.report_version_id]: { decision: "APPROVED" },
            },
          } as T;
        if (op === "reports.export")
          return { manifest: { status: "COMPLETED" } } as T;
        throw new Error(op);
      });
    render(
      <Reports
        caseId={version.case_id}
        evidenceId=""
        renderer={{ supported_formats: ["HTML"] }}
        onNotice={vi.fn()}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: new RegExp(fixture.report.title),
      }),
    );
    fireEvent.click(await screen.findByRole("button", { name: "내보내기" }));
    if (stale) {
      const checkbox = screen.getByRole("checkbox", {
        name: /최신 상태가 아님/,
      }) as HTMLInputElement;
      expect(checkbox.checked).toBe(false);
      expect(checkbox.required).toBe(true);
      expect(
        (screen.getByRole("dialog") as HTMLFormElement).checkValidity(),
      ).toBe(false);
      fireEvent.click(checkbox);
    } else {
      expect(screen.queryByRole("checkbox")).toBeNull();
    }
    fireEvent.submit(screen.getByRole("dialog"));
    await waitFor(() =>
      expect(call).toHaveBeenCalledWith(
        "reports.export",
        expect.objectContaining({
          report_version_id: version.report_version_id,
          stale_confirmed: stale,
        }),
      ),
    );
  },
);
