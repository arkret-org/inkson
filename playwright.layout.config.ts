import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests/layout",
  outputDir: "./test-results/layout",
  timeout: 30_000,
  workers: 1,
  reporter: "list",
  use: { browserName: "chromium", viewport: { width: 900, height: 650 } },
});
