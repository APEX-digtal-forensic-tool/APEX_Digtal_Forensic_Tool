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
import { VideoInspector } from "./VideoInspector";
import { gateway } from "./gateway";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

it("reads the requested frame using IDs and hides stale results after source changes", async () => {
  let resolve!: (value: any) => void;
  const call = vi.spyOn(gateway, "call").mockImplementation(
    () =>
      new Promise((r) => {
        resolve = r;
      }),
  );
  const view = render(
    <VideoInspector
      caseId="case"
      resourceType="FILE_SYSTEM_NODE"
      resourceId="video"
    />,
  );
  fireEvent.change(screen.getByLabelText("요청 시각 (초)"), {
    target: { value: "3.5" },
  });
  fireEvent.click(screen.getByText("프레임 읽기"));
  expect(call).toHaveBeenCalledWith("media.video", {
    case_id: "case",
    resource_type: "FILE_SYSTEM_NODE",
    resource_id: "video",
    timestamp_seconds: 3.5,
    max_dimension: 1536,
  });
  view.rerender(
    <VideoInspector
      caseId="other"
      resourceType="FILE_SYSTEM_NODE"
      resourceId="other"
    />,
  );
  resolve({
    image_url: "data:image/png;base64,OLD",
    timestamp_seconds_requested: 3.5,
  });
  await waitFor(() =>
    expect(screen.queryByAltText("선택 시각의 영상 프레임")).toBeNull(),
  );
});
