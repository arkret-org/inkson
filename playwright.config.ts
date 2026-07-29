import { defineConfig, devices } from "@playwright/test";

const requestedServerPort = process.env.INKSON_E2E_PORT ?? "4727";
const baseURL =
  process.env.INKSON_E2E_BASE_URL ?? `http://127.0.0.1:${requestedServerPort}`;
const shouldStartServer = !process.env.INKSON_E2E_BASE_URL;
const serverURL = new URL(baseURL);
const serverPort = serverURL.port || (serverURL.protocol === "https:" ? "443" : "80");
const browserProjects = (
  process.env.INKSON_E2E_BROWSERS ?? "chromium"
)
  .split(",")
  .map((name) => name.trim())
  .filter(Boolean)
  .map((name) => {
    if (name === "chrome") {
      return {
        name: "chrome",
        use: { ...devices["Desktop Chrome"], channel: "chrome" as const },
      };
    }
    if (name === "msedge") {
      return {
        name: "msedge",
        use: { ...devices["Desktop Edge"], channel: "msedge" as const },
      };
    }
    return {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    };
  });

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
  projects: browserProjects,
  webServer: shouldStartServer
    ? {
        command:
          `dx build --platform web --features wasm-localstorage-secrets-test && dx serve --platform web --features wasm-localstorage-secrets-test --addr 127.0.0.1 --port ${serverPort} --open false --hot-reload false --watch false`,
        // `dx serve` binds the HTTP socket before the first WASM build is
        // usable. Probe the generated module rather than `/`, otherwise
        // Playwright can start tests against a shell whose `#main` is empty.
        url: `${baseURL}/wasm/inkson.js`,
        reuseExistingServer: !process.env.CI,
        timeout: 600_000,
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
