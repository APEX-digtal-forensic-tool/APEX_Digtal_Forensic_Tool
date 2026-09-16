import { join } from "node:path";

export function runtimeExecutable(
  resources: string,
  platform: NodeJS.Platform,
) {
  return join(
    resources,
    "runtime",
    platform === "win32" ? "apex-local-api.exe" : "apex-local-api",
  );
}
