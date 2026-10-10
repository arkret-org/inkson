// cross-platform deployment test harness for the inkson
// wasm bundle. Drives the same scenario set across Chromium, Firefox,
// and WebKit (Safari) so we catch the SubtleCrypto / PushManager /
// service-worker push receive / LocalStorage / OIDC PKCE divergences
// that the SubtleCrypto secure key store and round 24
// `open_oidc_authorize_url` paths have to cope with.
//
// Each project is gated by a per-browser env flag so the matrix can
// run in CI on a host that only has one engine installed without
// reporting "missing executable" failures. Set `INKSON_CROSS_PLATFORM`
// to a comma-separated list of `chromium,firefox,webkit` to opt in;
// the per-test `test.skip` guards inside the suite mean unset projects
// quietly skip rather than fail.
//
// Run: `npm run test:cross-platform` (skips when node/npx not on
// PATH; the lib-side build is unaffected).

import { defineConfig, devices } from "@playwright/test";

const baseURL =
  process.env.INKSON_CROSS_PLATFORM_BASE_URL ?? "http://127.0.0.1:4528";
const shouldStartServer = !process.env.INKSON_CROSS_PLATFORM_BASE_URL;

const enabled = (process.env.INKSON_CROSS_PLATFORM ?? "chromium,firefox,webkit")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter((s) => s.length > 0);

const allProjects = [
  {
    name: "chromium",
    use: { ...devices["Desktop Chrome"] },
  },
  {
    name: "firefox",
    use: { ...devices["Desktop Firefox"] },
  },
  {
    name: "webkit",
    use: { ...devices["Desktop Safari"] },
  },
];

const projects = allProjects.filter((p) => enabled.includes(p.name));

export default defineConfig({
  testDir: ".",
  // Each scenario is browser-network-light (single page load + a
  // handful of evaluate() calls). 90s is plenty even on a slow CI box
  // and short enough that a hung permission prompt on Safari fails
  // fast.
  timeout: 90_000,
  expect: {
    timeout: 15_000,
  },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
    // Most scenarios only need the page object; the per-test
    // `test.skip` guards ignore browser context concerns.
    headless: true,
  },
  projects,
  webServer: shouldStartServer
    ? {
        // dx serve produces the wasm bundle; the matrix exercises it
        // through the browser's native APIs (SubtleCrypto, PushManager,
        // localStorage). Distinct port from the e2e harness so the two
        // can run side-by-side in CI.
        command:
          "dx serve --platform web --addr 127.0.0.1 --port 4528 --open false --hot-reload false --watch false",
        url: baseURL,
        reuseExistingServer: !process.env.CI,
        // A clean WASM build can take several minutes before the socket opens.
        timeout: 900_000,
      }
    : undefined,
});
