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
import { FileViewer } from "./FileViewer";
import { gateway, type Row } from "../gateway";
import ntfsFile from "../__fixtures__/ntfs-file.json";

const video = {
  ...ntfsFile,
  id: "video-node",
  original_name: "clip.mp4",
  extension: "mp4",
};

beforeEach(() => {
  HTMLDialogElement.prototype.showModal = function () {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function () {
    this.removeAttribute("open");
  };
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function viewer(selected: Row | null, caseId = ntfsFile.case_id) {
  return (
    <FileViewer
      caseId={caseId}
      selected={selected}
      height={320}
      onHeight={vi.fn()}
      onCollect={vi.fn()}
      onSelect={vi.fn()}
    />
  );
}

it("offers the video frame inspector for a file-tree video node", async () => {
  const call = vi.spyOn(gateway, "call").mockImplementation(async (op) =>
    op === "media.video"
      ? {
          image_url: "data:image/png;base64,FRAME",
          timestamp_seconds_requested: 2,
        }
      : { available_actions: [] },
  );
  const view = render(viewer(video));
  fireEvent.click(screen.getByRole("button", { name: "영상 프레임 보기" }));
  fireEvent.change(screen.getByLabelText("요청 시각 (초)"), {
    target: { value: "2" },
  });
  fireEvent.click(screen.getByText("프레임 읽기"));
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith("media.video", {
      case_id: ntfsFile.case_id,
      resource_type: "FILE_SYSTEM_NODE",
      resource_id: "video-node",
      timestamp_seconds: 2,
      max_dimension: 1536,
    }),
  );
  await screen.findByAltText("선택 시각의 영상 프레임");
  view.rerender(viewer({ ...video, id: "other-video" }));
  expect(screen.queryByAltText("선택 시각의 영상 프레임")).toBeNull();
});

it("does not offer the video inspector for non-video files or folders", () => {
  vi.spyOn(gateway, "call").mockResolvedValue({ available_actions: [] });
  const view = render(viewer(ntfsFile));
  expect(screen.queryByRole("button", { name: "영상 프레임 보기" })).toBeNull();
  view.rerender(viewer({ ...video, node_type: "DIRECTORY" }));
  expect(screen.queryByRole("button", { name: "영상 프레임 보기" })).toBeNull();
  view.rerender(viewer({ ...ntfsFile, original_name: "photo.png" }));
  expect(screen.queryByRole("button", { name: "영상 프레임 보기" })).toBeNull();
});
