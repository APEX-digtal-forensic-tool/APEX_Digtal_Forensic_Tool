import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { randomBytes } from "node:crypto";
export default defineConfig(({ command }) => {
  const nonce = randomBytes(18).toString("base64");
  return {
    test: {
      setupFiles: ["./src/test-setup.ts"],
      // Multi-screen jsdom flows need a shared budget on slower CI runners.
      // Keep assertions and per-query waits unchanged; do not retry failures.
      testTimeout: 15_000,
      // Avoid competing full-App renders on the Intel macOS hosted runner.
      maxWorkers: process.env.CI ? 2 : undefined,
    },
    plugins: [
      react(),
      ...(command === "serve"
        ? [
            {
              name: "development-csp",
              transformIndexHtml(html: string) {
                return html
                  .replace(
                    "script-src 'self';",
                    `script-src 'self' 'nonce-${nonce}';`,
                  )
                  .replace(
                    "ws://localhost:5173",
                    "ws://localhost:5173 ws://127.0.0.1:5173",
                  );
              },
            },
          ]
        : []),
    ],
    html: command === "serve" ? { cspNonce: nonce } : undefined,
    base: "./",
    server: { host: "127.0.0.1", port: 5173, strictPort: true },
  };
});
