import { expect, test } from "@playwright/test";
import { DEMO_REALM, dismissBlockingRecoveryModal, openKanban, registerStrandsBeforeEach } from "./strandsHarness";

let cropped = false;
let croppedBody: string | undefined;
registerStrandsBeforeEach({
  demoNotification: true, demoEventRedaction: () => cropped,
  observeAccountSubscribe: body => {
    if (body.includes('"object_redaction"')) croppedBody = body;
  },
});
test.beforeEach(() => { cropped = false; croppedBody = undefined; });

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
  cropped = true;
  await expect.poll(() => croppedBody, { timeout: 60_000 }).toBeDefined();
  const frame = croppedBody!.trim().split("\n").map(line => JSON.parse(line))
    .find(frame => frame.realms?.[DEMO_REALM]);
  expect(frame.realms[DEMO_REALM].committed_events.length).toBeGreaterThan(0);
  // Fixture observation alone does not prove delivery or verification. This
  // source exists only in the new cut, so require its verified UI publication
  // before checking withdrawal of the old body.
  const control = "Independent current control needle";
  await panel.getByTestId("global-search-input").fill(control);
  await panel.getByTestId("global-search-submit").click();
  await expect(row.getByTestId("global-search-result-snippet"))
    .toHaveText(control, { timeout: 60_000 });
  await expect(row).toHaveCount(1);
  await expect(row).not.toHaveAttribute("data-event-id", originalId!);
  await panel.getByTestId("global-search-input").fill(body);
  await panel.getByTestId("global-search-submit").click();
  await expect(row).toHaveCount(0);
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  await panel.getByTestId("global-search-submit").click();
  await expect(row).toHaveCount(0);
  // A source created only in the new cut must remain readable. A poisoned
  // store, lost holder or rejected frame cannot satisfy this positive control.
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
