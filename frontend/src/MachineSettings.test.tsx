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
import { MachineSettings } from "./MachineSettings";
import { gateway } from "./gateway";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const capabilities = {
  settings: {
    ocr_provider: "auto",
    stt_provider: "faster-whisper",
    stt_model_path: "C:/models/multilingual",
  },
  stt: { is_available: true },
  ocr: { is_available: true },
  managed: false,
};

it("explains local models and clears an incompatible model on provider change", async () => {
  const call = vi.spyOn(gateway, "call").mockResolvedValue(capabilities);
  render(<MachineSettings />);
  await screen.findByText("저장된 STT 설정: 분석기와 모델 파일 준비됨");
  expect(screen.getByText(/API 키가 아닌 음성 인식용/)).toBeTruthy();
  fireEvent.change(screen.getByLabelText("음성 인식"), {
    target: { value: "whisper.cpp" },
  });
  expect(screen.queryByText("C:/models/multilingual")).toBeNull();
  fireEvent.click(screen.getByText("분석기 설정 저장"));
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith("machine.configure", {
      ocr_provider: "auto",
      stt_provider: "whisper.cpp",
      model_reference: null,
      tessdata_reference: undefined,
    }),
  );
});

it("exposes a missing model and disables environment-managed settings", async () => {
  vi.spyOn(gateway, "call").mockResolvedValue({
    ...capabilities,
    managed: true,
    stt: { is_available: false },
  });
  render(<MachineSettings />);
  await screen.findByText("저장된 STT 설정: 모델 또는 분석기 준비 필요");
  expect(
    screen
      .getByRole("group", { name: "분석기와 모델" })
      .hasAttribute("disabled"),
  ).toBe(true);
});

it("uses and restores the bundled model without a file picker or API key", async () => {
  const call = vi.spyOn(gateway, "call").mockResolvedValue({
    ...capabilities,
    settings: { ...capabilities.settings, stt_model_path: null },
    bundled_stt: { available: true, name: "Whisper base · 다국어" },
    media: { ffmpeg: { is_available: true }, ffprobe: { is_available: true } },
    dpapi: { runtime_status: "IMPLEMENTED_RUNTIME" },
  });
  render(<MachineSettings />);
  await screen.findByText("내장 다국어 모델 사용");
  fireEvent.click(screen.getByText("기본 내장 모델로 복원"));
  fireEvent.click(screen.getByText("분석기 설정 저장"));
  await waitFor(() =>
    expect(call).toHaveBeenCalledWith("machine.configure", {
      ocr_provider: "auto",
      stt_provider: "faster-whisper",
      model_reference: null,
      tessdata_reference: undefined,
    }),
  );
});

it("diagnoses unreadable stored settings and resets them without the old file", async () => {
  const call = vi.spyOn(gateway, "call").mockImplementation(async (op) =>
    op === "machine.reset"
      ? {
          ...capabilities,
          settings_error: null,
          preserved_settings_file: "machine-settings.invalid-1.json",
        }
      : {
          ...capabilities,
          ocr: null,
          stt: null,
          settings_error: {
            code: "MACHINE_SETTINGS_INVALID",
            reason: "JSON_SYNTAX",
            source: "FILE",
            fields: [],
            resettable: true,
          },
        },
  );
  render(<MachineSettings />);
  expect((await screen.findByRole("alert")).textContent).toContain(
    "JSON 문법 오류",
  );
  fireEvent.click(screen.getByText("손상된 설정 보존 후 기본값으로 복구"));
  await waitFor(() => expect(call).toHaveBeenCalledWith("machine.reset"));
  await screen.findByText(/machine-settings.invalid-1.json 이름으로/);
  expect(screen.queryByRole("alert")).toBeNull();
});

it("points environment-managed invalid settings to the runtime environment", async () => {
  vi.spyOn(gateway, "call").mockResolvedValue({
    ...capabilities,
    managed: true,
    settings_error: {
      reason: "INVALID_FIELDS",
      source: "ENVIRONMENT",
      fields: ["stt_provider"],
      resettable: false,
    },
  });
  render(<MachineSettings />);
  expect((await screen.findByRole("alert")).textContent).toContain(
    "stt_provider",
  );
  expect(screen.queryByText("손상된 설정 보존 후 기본값으로 복구")).toBeNull();
});
