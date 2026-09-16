import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

const platform = process.argv[2];
if (!["darwin", "win32"].includes(platform) || process.platform !== platform)
  throw new Error("Build on the target OS with its native Python runtime.");
const runtime = JSON.parse(
  await readFile(
    new URL("../../desktop-runtime/runtime-info.json", import.meta.url),
    "utf8",
  ),
);
if (runtime.platform !== platform || runtime.arch !== process.arch)
  throw new Error(
    "Rebuild desktop-runtime using Python matching this Node.js OS and architecture.",
  );
const require = createRequire(import.meta.url);
const result = spawnSync(
  process.execPath,
  [
    require.resolve("electron-builder/cli.js"),
    platform === "darwin" ? "--mac" : "--win",
    `--${process.arch}`,
    "--publish",
    "never",
  ],
  { stdio: "inherit" },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
