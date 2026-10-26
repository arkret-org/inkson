import { inputByClass } from "./uiControl";
import { assertSearchSource, searchReference } from "./searchSource";
import { byClass } from "./strandsHarness";
import { expect, test } from "@playwright/test";
import { DEMO_REALM, dismissBlockingRecoveryModal, openKanban, registerStrandsBeforeEach } from "./strandsHarness";

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
  const panel = byClass(page, "global-search-panel");
  const body = "Alice sent a message in Demo Realm";
  await inputByClass(panel, "global-search-input").fill(body);
  await byClass(panel, "global-search-submit").click();
  const row = byClass(panel, "global-search-result-item");
  await expect(row).toHaveCount(1);
  await assertSearchSource(row);
  await expect(byClass(row, "global-search-result-snippet")).toHaveText(body);
  await expect(searchReference(row, "event")).toHaveText(/^ak:event:/);
  await expect(searchReference(row, "commit")).toHaveText(/^ak:realm_commit:/);
  const originalId = await searchReference(row, "event").textContent();
  // The next ordinary Account poll carries an independently signed newer cut.
  // It still retains the old Full source, so only the current crop can hide it.
  const croppedCut = page.waitForResponse(async response =>
    new URL(response.url()).pathname === "/_arkret/self/account/subscribe"
    && response.status() === 200
    && (await response.text()).includes('"object_redaction"'));
  cropped = true;
  const response = await croppedCut;
  const frame = (await response.text()).trim().split("\n").map(line => JSON.parse(line))
    .find(frame => frame.realms?.[DEMO_REALM]);
  const lastEvent = frame.realms[DEMO_REALM].committed_events.at(-1).commit.event_ref;
  // A received frame is not installed until all historical signer material
  // arrives. The fixture CLI validates each proof independently on Windows.
  await page.waitForResponse(response =>
    new URL(response.url()).pathname === "/_arkret/self/signer-keys/query"
    && response.status() === 200
    && response.request().postDataJSON().queries.some((query: any) =>
      query.committed_event_ref?.event_id === lastEvent), { timeout: 60_000 });
  await expect(row).toHaveCount(0);
  await expect(byClass(panel, "global-search-results-no-results")).toBeVisible();
  await byClass(panel, "global-search-submit").click();
  await expect(row).toHaveCount(0);
  // A source created only in the new cut must remain readable. A poisoned
  // store, lost holder or rejected frame cannot satisfy this positive control.
  const control = "Independent current control needle";
  await inputByClass(panel, "global-search-input").fill(control);
  await byClass(panel, "global-search-submit").click();
  await expect(row).toHaveCount(1);
  await assertSearchSource(row);
  await expect(byClass(row, "global-search-result-snippet")).toHaveText(control);
  await expect(searchReference(row, "event")).not.toHaveText(originalId!);
  await page.reload();
  await dismissBlockingRecoveryModal(page);
  await expect(panel).toBeVisible();
  await inputByClass(panel, "global-search-input").fill(body);
  await byClass(panel, "global-search-submit").click();
  await expect(byClass(panel, "global-search-results-no-results")).toBeVisible();
  await expect(row).toHaveCount(0);
  await inputByClass(panel, "global-search-input").fill(control);
  await byClass(panel, "global-search-submit").click();
  await expect(row).toHaveCount(1);
  await assertSearchSource(row);
  await expect(byClass(row, "global-search-result-snippet")).toHaveText(control);
  expect(originalId).toMatch(/^ak:event:/);
  expect(forbidden).toEqual([]);
});
