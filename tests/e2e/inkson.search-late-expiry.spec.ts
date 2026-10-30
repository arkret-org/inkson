import { expect, test } from "@playwright/test";
import { dismissBlockingRecoveryModal, openKanban, registerStrandsBeforeEach } from "./strandsHarness";

registerStrandsBeforeEach({ demoNotification: true });

test("an actual late IndexedDB search read cannot republish plaintext after holder expiry", async ({ page }) => {
  test.setTimeout(240_000);
  await openKanban(page);
  await dismissBlockingRecoveryModal(page);
  await page.keyboard.press("Control+F");
  const panel = page.getByTestId("global-search-panel");
  const rows = panel.getByTestId("global-search-result-item");
  const body = "Alice sent a message in Demo Realm";
  await panel.getByTestId("global-search-input").fill(body);
  await panel.getByTestId("global-search-submit").click();
  await expect(rows).toHaveCount(1);
  await expect(rows.getByTestId("global-search-result-snippet")).toHaveText(body);
  await page.route("**/_arkret/self/keys/query", route => route.abort());
  await page.route("**/_arkret/self/auth/**", route => route.abort());
  await page.evaluate(() => {
    const pending: Array<() => void> = [];
    const barrier = { observed: 0, armed: true, release: () => {
      barrier.armed = false;
      for (const resume of pending.splice(0)) resume();
    } };
    Object.assign(window, { searchReadBarrier: barrier });
    const decrypt = SubtleCrypto.prototype.decrypt;
    SubtleCrypto.prototype.decrypt = function(this: SubtleCrypto, ...args: Parameters<SubtleCrypto["decrypt"]>) {
      // Perform the real authenticated decryption. Only its Promise delivery
      // is delayed; neither stored bytes, keys nor the returned value changes.
      return decrypt.apply(this, args).then(value => {
        let tuple: unknown;
        try { tuple = JSON.parse(new TextDecoder().decode(value)); } catch { return value; }
        if (barrier.armed && Array.isArray(tuple) && typeof tuple[0] === "string"
          && tuple[0].includes("/search/")) {
          barrier.observed++;
          return new Promise<ArrayBuffer>(resolve => pending.push(() => resolve(value)));
        }
        return value;
      });
    };
  });
  // An automatic refresh may already be paused at the real read barrier.
  // Enter submits when idle; the observed read below proves actual execution.
  await panel.getByTestId("global-search-input").press("Enter");
  await expect.poll(() => page.evaluate(() => (window as unknown as {
    searchReadBarrier: { observed: number };
  }).searchReadBarrier.observed)).toBeGreaterThan(0);
  await expect(panel.getByTestId("global-search-results-loading")).toBeVisible();
  await page.clock.setFixedTime(new Date(Date.now() + 8 * 60 * 60_000 + 1));
  await expect(rows).toHaveCount(0, { timeout: 70_000 });
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await page.evaluate(() => (window as unknown as {
    searchReadBarrier: { release: () => void };
  }).searchReadBarrier.release());
  await page.evaluate(() => new Promise<void>(resolve =>
    requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  // A completed older read and a new form submission both retain the expired
  // holder's refusal. The query and source dataset have never been replaced.
  await panel.getByTestId("global-search-submit").click();
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await expect(rows).toHaveCount(0);
  await expect(panel.getByTestId("global-search-input")).toHaveValue(body);
});
