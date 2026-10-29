import { expect, test } from "@playwright/test";
import { DEMO_REALM, dismissBlockingRecoveryModal, openKanban, registerStrandsBeforeEach } from "./strandsHarness";
import { deliveredMockAccountBody, observeSuccessfulSignerQueries } from "./mockArkretApi";

let cropped = false;
registerStrandsBeforeEach({ demoNotification: true, demoEventRedaction: () => cropped });
test.beforeEach(() => { cropped = false; });

test("current Event cropping withdraws a visible search body and survives reload", async ({ page }) => {
  // Two cold bootstraps plus signed fixture transport; individual UI
  // assertions and the product's holder validity windows keep their limits.
  test.setTimeout(300_000);
  const forbidden: string[] = [];
  page.on("request", request => {
    const path = new URL(request.url()).pathname;
    if ((path.startsWith("/_arkret/") && path.split("/").includes("search"))
      || path === "/_arkret/self/events" || path.endsWith("/realm-joins/prepare")) {
      forbidden.push(`${request.method()} ${path}`);
    }
  });
  await openKanban(page);
  await dismissBlockingRecoveryModal(page);
  await page.keyboard.press("Control+F");
  const panel = page.getByTestId("global-search-panel");
  const body = "Alice sent a message in Demo Realm";
  await panel.getByTestId("global-search-input").fill(body);
  await panel.getByTestId("global-search-submit").click();
  const row = panel.getByTestId("global-search-result-item");
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("global-search-result-snippet")).toHaveText(body);
  await expect(row).toHaveAttribute("data-event-id", /^ak:event:/);
  await expect(row).toHaveAttribute("data-commit-id", /^ak:realm_commit:/);
  const originalId = await row.getAttribute("data-event-id");
  // The next ordinary Account poll carries an independently signed newer cut.
  // It still retains the old Full source, so only the current crop can hide it.
  const hasSignerQuery = observeSuccessfulSignerQueries(page);
  let croppedBody: string | undefined;
  const croppedCut = page.waitForResponse(async response => {
    if (new URL(response.url()).pathname !== "/_arkret/self/account/subscribe"
      || response.status() !== 200) return false;
    const body = await deliveredMockAccountBody(response);
    if (!body.includes('"object_redaction"')) return false;
    croppedBody = body;
    return true;
  });
  cropped = true;
  await croppedCut;
  expect(croppedBody).toBeDefined();
  const frame = croppedBody!.trim().split("\n").map(line => JSON.parse(line))
    .find(frame => frame.realms?.[DEMO_REALM]);
  const lastEvent = frame.realms[DEMO_REALM].committed_events.at(-1).commit.event_ref;
  // A received frame is not installed until all historical signer material
  // arrives. The fixture CLI validates each proof independently on Windows.
  await expect.poll(() => hasSignerQuery(lastEvent), { timeout: 60_000 }).toBe(true);
  await expect(row).toHaveCount(0);
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await panel.getByTestId("global-search-submit").click();
  await expect(row).toHaveCount(0);
  // A source created only in the new cut must remain readable. A poisoned
  // store, lost holder or rejected frame cannot satisfy this positive control.
  const control = "Independent current control needle";
  await panel.getByTestId("global-search-input").fill(control);
  await panel.getByTestId("global-search-submit").click();
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("global-search-result-snippet")).toHaveText(control);
  await expect(row).not.toHaveAttribute("data-event-id", originalId!);
  await page.reload();
  await dismissBlockingRecoveryModal(page);
  await expect(panel).toBeVisible();
  await panel.getByTestId("global-search-input").fill(body);
  await panel.getByTestId("global-search-submit").click();
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await expect(row).toHaveCount(0);
  await panel.getByTestId("global-search-input").fill(control);
  await panel.getByTestId("global-search-submit").click();
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("global-search-result-snippet")).toHaveText(control);
  expect(originalId).toMatch(/^ak:event:/);
  expect(forbidden).toEqual([]);
});
