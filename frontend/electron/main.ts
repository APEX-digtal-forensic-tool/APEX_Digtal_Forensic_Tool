import {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  shell,
  type IpcMainInvokeEvent,
} from "electron";
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { join, resolve } from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
import { runtimeExecutable } from "./runtime";

const operations = new Set([
  "runtime",
  "cases.list",
  "cases.create",
  "evidence.list",
  "evidence.register",
  "files.list",
  "files.roots",
  "artifacts.list",
  "search.query",
  "search.history",
  "timeline.list",
  "candidates.list",
  "candidates.review",
  "view",
  "raw.read",
  "media.inspect",
  "context.create",
  "context.get",
  "context.update",
  "analysis.start",
  "tasks.list",
  "tasks.cancel",
  "custody.list",
  "custody.add",
  "custody.verify",
  "reports.list",
  "reports.create",
  "reports.get",
  "reports.version",
  "reports.action",
  "reports.export",
  "policy.get",
  "policy.save",
  "policy.audit",
]);
let window: BrowserWindow | undefined;
let backend: ChildProcess | undefined;
let backendURL = "";
let backendError = "SERVICE_NOT_READY";
const token = randomBytes(32).toString("hex");
const picked = new Map<string, string>();
let account:
  | {
      access_token: string;
      refresh_token: string;
      expiresAt: number;
      origin: string;
    }
  | undefined;
let pageURL = "";
const fail = (code: string) => ({ ok: false, error: { code } });

function trusted(event: IpcMainInvokeEvent) {
  return (
    window &&
    event.sender === window.webContents &&
    event.senderFrame === window.webContents.mainFrame &&
    event.senderFrame.url.split("#")[0] === pageURL.split("#")[0]
  );
}
function handle(name: string, callback: (...args: any[]) => unknown) {
  ipcMain.handle(name, async (event, ...args) => {
    if (!trusted(event)) return fail("DESKTOP_SENDER_DENIED");
    try {
      return await callback(...args);
    } catch {
      return fail("DESKTOP_CONNECTION_FAILED");
    }
  });
}
async function local(operation: string, payload: Record<string, unknown>) {
  if (!backendURL) return fail(backendError);
  const response = await fetch(`${backendURL}/v1/operations/${operation}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(operation === "runtime" ? 60000 : 120000),
    redirect: "error",
  });
  return response.json();
}
async function startBackend() {
  const repo = resolve(__dirname, "../..");
  const runtime = runtimeExecutable(process.resourcesPath, process.platform);
  const python =
    process.env.APEX_PYTHON ||
    join(
      repo,
      ".venv",
      process.platform === "win32" ? "Scripts/python.exe" : "bin/python",
    );
  const command = app.isPackaged ? runtime : python;
  if (!existsSync(command)) {
    backendError = "PYTHON_RUNTIME_MISSING";
    return;
  }
  const args = app.isPackaged ? [] : ["-m", "apex_desktop"];
  backend = spawn(
    command,
    [...args, "--data-dir", join(app.getPath("userData"), "local")],
    {
      cwd: app.isPackaged ? process.resourcesPath : repo,
      windowsHide: true,
      env: {
        ...process.env,
        PYTHONPATH: app.isPackaged ? "" : join(repo, "src"),
        APEX_DESKTOP_TOKEN: token,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  backend.on("error", () => {
    backendURL = "";
    backendError = "BACKEND_START_FAILED";
  });
  backend.on("exit", () => {
    backendURL = "";
    backendError = "BACKEND_STOPPED";
  });
  // Raw backend stderr may contain sensitive paths. Never forward it to the renderer/logs.
  backend.stderr?.on("data", () => {});
  const lines = createInterface({ input: backend.stdout! });
  lines.on("line", async (line) => {
    try {
      const data = JSON.parse(line);
      if (
        data.type === "apex-ready" &&
        Number.isInteger(data.port) &&
        data.port > 0 &&
        data.port <= 65535
      ) {
        const origin = `http://127.0.0.1:${data.port}`;
        for (let i = 0; i < 50; i++) {
          try {
            const r = await fetch(`${origin}/health`, {
              headers: { Authorization: `Bearer ${token}` },
              signal: AbortSignal.timeout(1000),
            });
            if (r.ok) {
              backendURL = origin;
              backendError = "";
              break;
            }
          } catch {
            /* Wait for the child's listener, not an unrelated port. */
          }
          await new Promise((r) => setTimeout(r, 100));
        }
      }
    } catch {
      /* Only consume the minimal readiness message. */
    }
  });
}

if (!app.requestSingleInstanceLock()) app.quit();
else {
  app.on("second-instance", () => {
    window?.show();
    window?.focus();
  });
  app.whenReady().then(async () => {
    await startBackend();
    pageURL =
      !app.isPackaged && process.env.APEX_DEV_URL === "http://127.0.0.1:5173"
        ? "http://127.0.0.1:5173/"
        : pathToFileURL(join(__dirname, "../dist/index.html")).href;
    handle("apex:invoke", async (operation: unknown, input: unknown) => {
      if (
        typeof operation !== "string" ||
        !operations.has(operation) ||
        !input ||
        typeof input !== "object" ||
        Array.isArray(input)
      )
        return fail("VALIDATION_ERROR");
      const payload = { ...(input as Record<string, unknown>) };
      if (JSON.stringify(payload).length > 1048576)
        return fail("RESOURCE_LIMIT_EXCEEDED");
      if (operation === "evidence.register") {
        const reference = String(payload.source_reference ?? "");
        const path = picked.get(reference);
        if (!path) return fail("PICKER_REFERENCE_REQUIRED");
        delete payload.source_reference;
        payload.source_path = path;
        const result = await local(operation, payload);
        if (result.ok) picked.delete(reference);
        return result;
      }
      return local(operation, payload);
    });
    handle("apex:pick", async (kind: unknown) => {
      if (kind !== "file" && kind !== "directory")
        return fail("VALIDATION_ERROR");
      const result = await dialog.showOpenDialog(window!, {
        title: "분석할 증거 선택",
        properties: [kind === "directory" ? "openDirectory" : "openFile"],
        filters:
          kind === "file"
            ? [
                {
                  name: "증거 이미지",
                  extensions: ["e01", "dd", "raw", "img", "vhd", "vhdx"],
                },
                { name: "모든 파일", extensions: ["*"] },
              ]
            : undefined,
      });
      if (result.canceled) return { ok: true, data: null };
      const reference = randomUUID();
      if (picked.size > 64) picked.clear();
      picked.set(reference, result.filePaths[0]);
      return {
        ok: true,
        data: { reference, name: result.filePaths[0].split(/[\\/]/).pop() },
      };
    });
    handle("apex:exports", async () => {
      const folder = join(app.getPath("userData"), "local", "exports");
      mkdirSync(folder, { recursive: true });
      const error = await shell.openPath(folder);
      return error ? fail("EXPORT_FOLDER_FAILED") : { ok: true, data: null };
    });
    handle("apex:account", () => ({
      ok: true,
      data: {
        connected: !!account && account.expiresAt > Date.now(),
        origin: account?.origin ?? null,
      },
    }));
    handle(
      "apex:login",
      async (input: {
        origin: string;
        email: string;
        password: string;
        tenant_id: string;
      }) => {
        if (
          !input ||
          typeof input.origin !== "string" ||
          typeof input.email !== "string" ||
          typeof input.password !== "string" ||
          typeof input.tenant_id !== "string"
        )
          return fail("VALIDATION_ERROR");
        const url = new URL(input.origin);
        if (
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          url.pathname !== "/" ||
          (url.protocol !== "https:" &&
            !(
              url.protocol === "http:" &&
              ["127.0.0.1", "localhost"].includes(url.hostname)
            ))
        )
          return fail("AUTH_ORIGIN_INVALID");
        const response = await fetch(`${url.origin}/auth/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: input.email,
            password: input.password,
            tenant_id: input.tenant_id,
          }),
          redirect: "error",
          signal: AbortSignal.timeout(15000),
        });
        if (!response.ok)
          return fail(
            response.status === 401
              ? "AUTH_LOGIN_FAILED"
              : "AUTH_SERVER_UNAVAILABLE",
          );
        const result = await response.json();
        if (
          typeof result.access_token !== "string" ||
          typeof result.refresh_token !== "string" ||
          typeof result.expires_in !== "number"
        )
          return fail("AUTH_CONTRACT_INVALID");
        account = {
          access_token: result.access_token,
          refresh_token: result.refresh_token,
          expiresAt: Date.now() + result.expires_in * 1000,
          origin: url.origin,
        };
        return { ok: true, data: { connected: true, origin: url.origin } };
      },
    );
    handle("apex:logout", () => {
      account = undefined;
      return { ok: true, data: null };
    });
    window = new BrowserWindow({
      width: 1540,
      height: 960,
      minWidth: 1060,
      minHeight: 700,
      backgroundColor: "#111519",
      title: "APEX",
      autoHideMenuBar: true,
      webPreferences: {
        preload: join(__dirname, "preload.cjs"),
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true,
        webSecurity: true,
      },
    });
    window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
    window.webContents.on("will-navigate", (event) => event.preventDefault());
    window.webContents.session.setPermissionRequestHandler(
      (_wc, _permission, callback) => callback(false),
    );
    await window.loadURL(pageURL);
  });
}
app.on("window-all-closed", () => app.quit());
app.on("before-quit", () => {
  account = undefined;
  backend?.kill();
});
