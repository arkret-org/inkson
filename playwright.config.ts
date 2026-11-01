import { defineConfig, devices } from "@playwright/test";

const requestedServerPort = process.env.INKSON_E2E_PORT ?? "4727";
const baseURL =
  process.env.INKSON_E2E_BASE_URL ?? `http://127.0.0.1:${requestedServerPort}`;
const shouldStartServer = !process.env.INKSON_E2E_BASE_URL;
const serverURL = new URL(baseURL);
const serverPort =
  serverURL.port || (serverURL.protocol === "https:" ? "443" : "80");
const e2eBuildProfile = process.env.INKSON_E2E_BUILD_PROFILE ?? "joint-e2e";
const browserProjects = (process.env.INKSON_E2E_BROWSERS ?? "chromium")
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
        command: "node scripts/serve_e2e.mjs",
        // Build the complete bundle before binding the socket.
        url: `${baseURL}/assets/pkg/inkson.js`,
        reuseExistingServer: !process.env.CI,
        timeout: 900_000,
        env: {
          INKSON_E2E_BUILD_PROFILE: e2eBuildProfile,
          INKSON_E2E_PORT: serverPort,
        },
      }
    : undefined,
});
