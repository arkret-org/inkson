import { inputByClass } from "./uiControl";
import { assertSearchSource, searchReference } from "./searchSource";
import { byClass } from "./strandsHarness";
import { expect, test, type Page } from "@playwright/test";
import { CURRENT_ACCOUNT_ACTOR_ID, dismissBlockingRecoveryModal, openKanban, openSettings, registerStrandsBeforeEach } from "./strandsHarness";

registerStrandsBeforeEach({ demoNotification: true });

async function openSearch(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(byClass(page, "global-search-panel")).toBeVisible();
}

test("global search applies personal message blocks and restores retained history after unblock", async ({ page }) => {
  await openKanban(page);
  const body = "Alice sent a message in Demo Realm";
  async function search() {
    await openSearch(page);
    const panel = byClass(page, "global-search-panel");
    await inputByClass(panel, "global-search-input").fill(body);
    await byClass(panel, "global-search-submit").click();
    await expect(byClass(panel, "global-search-results-loading")).toHaveCount(0);
    return panel;
  }
  let panel = await search();
  const original = byClass(panel, "global-search-result-item");
  await expect(original).toHaveCount(1);
  await assertSearchSource(original);
  const event = await searchReference(original, "event").textContent();
  const commit = await searchReference(original, "commit").textContent();
  await openSettings(page);
  await byClass(page, "settings-nav-item-blocklist").click();
  const settings = byClass(page, "settings-content-column");
  await expect(settings.getByRole("heading", { name: "Block list", exact: true })).toBeVisible();
  await inputByClass(settings, "block-target-input").fill(JSON.stringify(CURRENT_ACCOUNT_ACTOR_ID));
  for (const surface of ["mentions", "dm", "calls", "contacts", "applets", "presence", "notifications", "directory"]) {
    await byClass(settings, `block-surface-${surface}`).getByRole("checkbox").click();
  }
  await byClass(settings, "block-user-button").click();
  await expect(byClass(settings, "blocked-user-row")).toHaveCount(1);
  panel = await search();
  await expect(byClass(panel, "global-search-results-no-results")).toBeVisible();
  await expect(byClass(panel, "global-search-result-item")).toHaveCount(0);
  await expect(panel).not.toContainText(body);
  await page.reload();
  await expect(page.locator(".shell.app")).toBeVisible();
  panel = await search();
  await expect(byClass(panel, "global-search-results-no-results")).toBeVisible();
  await expect(byClass(panel, "global-search-result-item")).toHaveCount(0);
  await openSettings(page);
  await byClass(page, "settings-nav-item-blocklist").click();
  await byClass(settings, "unblock-button").click();
  await expect(byClass(settings, "blocked-user-row")).toHaveCount(0);
  panel = await search();
  const restored = byClass(panel, "global-search-result-item");
  await expect(restored).toHaveCount(1);
  await assertSearchSource(restored);
  await expect(searchReference(restored, "event")).toHaveText(event!);
  await expect(searchReference(restored, "commit")).toHaveText(commit!);
  await expect(byClass(restored, "global-search-result-snippet")).toHaveText(body);
});
