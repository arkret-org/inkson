import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.INKSON_E2E_BASE_URL ?? "http://127.0.0.1:4527";
const shouldStartServer = !process.env.INKSON_E2E_BASE_URL;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 180_000,
  expect: {
    timeout: 20_000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: shouldStartServer
    ? {
        command:
          "dx serve --platform web --features wasm-localstorage-secrets-test --addr 127.0.0.1 --port 4527 --open false --hot-reload false --watch false",
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 240_000,
        // Never let the E2E dx process overwrite the live development server's
        // wasm/CSS-module bundle in target/dx. CSS-module class hashes and
        // stylesheets must be emitted by the same build invocation.
        env: {
          CARGO_TARGET_DIR:
            process.env.INKSON_E2E_CARGO_TARGET_DIR ?? "target/playwright-e2e",
        },
      }
    : undefined,
});
