import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.CLIENTX_E2E_BASE_URL ?? "http://127.0.0.1:4527";
const shouldStartServer = !process.env.CLIENTX_E2E_BASE_URL;

export default defineConfig({
  testDir: "./tests/e2e",
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  fullyParallel: true,
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
          "dx serve --platform web --addr 127.0.0.1 --port 4527 --open false --hot-reload false --watch false",
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        timeout: 180_000,
      }
    : undefined,
});
