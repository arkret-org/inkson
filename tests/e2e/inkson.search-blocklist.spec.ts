import { expect, test, type Page } from "@playwright/test";
import { CURRENT_ACCOUNT_ACTOR_ID, dismissBlockingRecoveryModal, openKanban, openSettings, registerStrandsBeforeEach } from "./strandsHarness";

registerStrandsBeforeEach({ demoNotification: true });

async function openSearch(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(page.getByTestId("global-search-panel")).toBeVisible();
}

test("global search applies personal message blocks and restores retained history after unblock", async ({ page }) => {
  await openKanban(page);
  const body = "Alice sent a message in Demo Realm";
  async function search() {
    await openSearch(page);
    const panel = page.getByTestId("global-search-panel");
    await panel.getByTestId("global-search-input").fill(body);
    await panel.getByTestId("global-search-submit").click();
    await expect(panel.getByTestId("global-search-results-loading")).toHaveCount(0);
    return panel;
  }
  let panel = await search();
  const original = panel.getByTestId("global-search-result-item");
  await expect(original).toHaveCount(1);
  const event = await original.getAttribute("data-event-id");
  const commit = await original.getAttribute("data-commit-id");
  await openSettings(page);
  await page.getByTestId("settings-nav-item-blocklist").click();
  const settings = page.getByTestId("blocked-users-panel");
  await settings.getByTestId("block-target-input").fill(JSON.stringify(CURRENT_ACCOUNT_ACTOR_ID));
  for (const surface of ["mentions", "dm", "calls", "contacts", "applets", "presence", "notifications", "directory"]) {
    await settings.getByTestId(`block-applies-${surface}`).click();
  }
  await settings.getByTestId("block-user-button").click();
  await expect(settings.getByTestId("blocked-user-row")).toHaveCount(1);
  panel = await search();
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await expect(panel.getByTestId("global-search-result-item")).toHaveCount(0);
  await expect(panel).not.toContainText(body);
  await page.reload();
  await expect(page.getByTestId("client-shell")).toBeVisible();
  panel = await search();
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await expect(panel.getByTestId("global-search-result-item")).toHaveCount(0);
  await openSettings(page);
  await page.getByTestId("settings-nav-item-blocklist").click();
  await settings.getByTestId("unblock-button").click();
  await expect(settings.getByTestId("blocked-user-row")).toHaveCount(0);
  panel = await search();
  const restored = panel.getByTestId("global-search-result-item");
  await expect(restored).toHaveCount(1);
  await expect(restored).toHaveAttribute("data-event-id", event!);
  await expect(restored).toHaveAttribute("data-commit-id", commit!);
  await expect(restored.getByTestId("global-search-result-snippet")).toHaveText(body);
});
