import { expect, it } from "vitest";
import { join } from "node:path";
import { runtimeExecutable } from "./runtime";

it.each([
  ["win32", "apex-local-api.exe"],
  ["darwin", "apex-local-api"],
] as const)("resolves the bundled %s runtime", (platform, filename) => {
  expect(runtimeExecutable("resources", platform)).toBe(
    join("resources", "runtime", filename),
  );
});
