import { expect, test } from "@playwright/test";
import { dismissBlockingRecoveryModal, openKanban, registerStrandsBeforeEach } from "./strandsHarness";

for (const boundary of ["session", "projection", "authorization"] as const) {
  test.describe(`search ${boundary} deadline`, () => {
    const lifetime = boundary === "session" ? 24 * 60 * 60_000 : 60 * 60_000;
    registerStrandsBeforeEach({
      demoNotification: true,
      deviceProjectionValidityMs: boundary === "authorization" ? 24 * 60 * 60_000 : lifetime,
      deviceAuthorizationValidityMs: boundary === "authorization" ? lifetime : undefined,
    });

    test("visible committed search plaintext disappears without another query", async ({ page }) => {
      const forbidden: string[] = [];
      page.on("request", (request) => {
        const path = new URL(request.url()).pathname;
        if ((path.startsWith("/_arkret/") && path.split("/").includes("search")) || path === "/_arkret/self/events" || path.endsWith("/realm-joins/prepare")) {
          forbidden.push(`${request.method()} ${path}`);
        }
      });
      await openKanban(page);
      await dismissBlockingRecoveryModal(page);
      await page.keyboard.press("Control+F");
      const panel = page.getByTestId("global-search-panel");
      await expect(panel).toBeVisible();
      const query = "Alice sent a message in Demo Realm";
      await panel.getByTestId("global-search-input").fill(query);
      await panel.getByTestId("global-search-submit").click();
      const row = panel.getByTestId("global-search-result-item");
      await expect(row).toHaveCount(1);
      await expect(row.getByTestId("global-search-result-snippet")).toHaveText(query);
      await expect(row).toHaveAttribute("data-event-id", /^ak:event:/);
      await expect(row).toHaveAttribute("data-commit-id", /^ak:realm_commit:/);

      // Freeze the already admitted holder cut. Background refreshes cannot
      // replace it while the browser clock passes the selected boundary.
      await page.route("**/_arkret/self/keys/query", (route) => route.abort());
      await page.route("**/_arkret/self/auth/**", (route) => route.abort());
      // Change wall time while keeping existing Wasm timers at normal speed.
      // The search task rechecks wall time at least every 60 seconds.
      await page.clock.setFixedTime(new Date(Date.now() + (boundary === "session" ? 8 * 60 * 60_000 + 1 : lifetime + 1)));
      await expect(row).toHaveCount(0, { timeout: 70_000 });
      await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
      await expect(panel.getByTestId("global-search-input")).toHaveValue(query);
      // A new request at the expired holder cut also stays empty.
      await panel.getByTestId("global-search-submit").click();
      await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
      await expect(row).toHaveCount(0);
      expect(forbidden).toEqual([]);
    });
  });
}

test.describe("search holder time at a new query", () => {
  registerStrandsBeforeEach({ demoNotification: true });

  test("new query accepts effective holder evidence without remounting the panel", async ({ page }) => {
    const forbidden: string[] = [];
    page.on("request", (request) => {
      const path = new URL(request.url()).pathname;
      if ((path.startsWith("/_arkret/") && path.split("/").includes("search")) || path === "/_arkret/self/events" || path.endsWith("/realm-joins/prepare")) {
        forbidden.push(`${request.method()} ${path}`);
      }
    });
    await openKanban(page);
    await dismissBlockingRecoveryModal(page);
    // Mount Search before its already-admitted device evidence is effective.
    // Only wall time changes; no index or result rows are injected.
    await page.clock.setFixedTime(new Date(Date.now() - 60_000));
    await page.keyboard.press("Control+F");
    const panel = page.getByTestId("global-search-panel");
    await expect(panel).toBeVisible();
    const body = "Alice sent a message in Demo Realm";
    await panel.getByTestId("global-search-input").fill(body);
    await panel.getByTestId("global-search-submit").click();
    await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
    await expect(panel.getByTestId("global-search-result-item")).toHaveCount(0);

    await page.clock.setFixedTime(new Date(Date.now() + 5_000));
    await panel.getByTestId("global-search-submit").click();
    const row = panel.getByTestId("global-search-result-item");
    await expect(row).toHaveCount(1);
    await expect(row.getByTestId("global-search-result-snippet")).toHaveText(body);
    await expect(row).toHaveAttribute("data-event-id", /^ak:event:/);
    await expect(row).toHaveAttribute("data-commit-id", /^ak:realm_commit:/);
    await expect(panel.getByTestId("global-search-input")).toHaveValue(body);
    expect(forbidden).toEqual([]);
  });
});
