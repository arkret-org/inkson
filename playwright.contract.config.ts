import { defineConfig } from "@playwright/test";

// The mock-vs-spec contract check. Deliberately shares nothing with
// `playwright.config.ts`: no `webServer`, so it never triggers the WASM build,
// and no browser project, because `tests/contract` drives the mock's route
// handler directly. That is the whole point — a stale mock field has to be
// findable in seconds, not after a twenty-minute build.
export default defineConfig({
  testDir: "./tests/contract",
  // Its own output directory, so running it while an e2e run is in flight does
  // not have the two clobbering each other's artifacts.
  outputDir: "./test-results-contract",
  timeout: 120_000,
  fullyParallel: false,
  workers: 1,
  reporter: "list",
});
