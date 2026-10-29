import { expect, test } from "@playwright/test";
import { DEMO_REALM, dismissBlockingRecoveryModal, openKanban, registerStrandsBeforeEach } from "./strandsHarness";
import { deliveredMockAccountBody, observeSuccessfulSignerQueries } from "./mockArkretApi";

let active = false;
registerStrandsBeforeEach({ demoNotification: true, demoSearchPolicy: () => active });
test.beforeEach(() => { active = false; });

test("current retention Policy withdraws and restores the same search body at its validity boundaries", async ({ page }, testInfo) => {
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
  const input = panel.getByTestId("global-search-input");
  const submit = panel.getByTestId("global-search-submit");
  const row = panel.getByTestId("global-search-result-item");
  const body = "Alice sent a message in Demo Realm";
  const control = "Independent policy control needle";
  await input.fill(body);
  await submit.click();
  await expect(row).toHaveCount(1);
  const original = await row.getAttribute("data-event-id");
  const commit = await row.getAttribute("data-commit-id");
  const hasSignerQuery = observeSuccessfulSignerQueries(page);
  let policyBody: string | undefined;
  const update = page.waitForResponse(async response => {
    if (new URL(response.url()).pathname !== "/_arkret/self/account/subscribe"
      || response.status() !== 200) return false;
    const body = await deliveredMockAccountBody(response);
    if (!body.includes('"policy_kind":"retention"')) return false;
    policyBody = body;
    return true;
  });
  active = true;
  await update;
  expect(policyBody).toBeDefined();
  const frame = policyBody!.trim().split("\n").map(line => JSON.parse(line))
    .find(frame => frame.realms?.[DEMO_REALM]);
  const entry = frame.realms[DEMO_REALM];
  const lastEvent = entry.committed_events.at(-1).commit.event_ref;
  await expect.poll(() => hasSignerQuery(lastEvent), { timeout: 60_000 }).toBe(true);
  const policy = entry.current.entries.find((row: any) => row.selector.kind === "policy").value;
  const observed: Record<string, unknown> = { policy, proofsAt: Date.now(), original, commit };
  // This source exists only in the new cut and a different Strand. The Policy
  // must neither poison the entire index nor broaden its exact resource.
  await input.fill(control);
  await submit.click();
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("global-search-result-snippet")).toHaveText(control);
  await input.fill(body);
  await submit.click();
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute("data-event-id", original!);
  const startsAt = Date.parse(policy.not_before);
  expect(Date.now()).toBeLessThan(startsAt);
  // Synchronize to the declared input time on fast and slow fixture hosts.
  // The subsequent UI withdrawal assertion keeps its ordinary 20-second limit.
  await expect.poll(() => Date.now(), { timeout: 90_000, intervals: [1_000] })
    .toBeGreaterThanOrEqual(startsAt - 5_000);
  await expect(row).toHaveCount(0);
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  observed.hiddenAt = Date.now();
  expect(observed.hiddenAt).toBeGreaterThanOrEqual(Date.parse(policy.not_before));
  expect(observed.hiddenAt).toBeLessThan(Date.parse(policy.expires_at));
  await input.fill(control);
  await submit.click();
  await expect(row).toHaveCount(1);
  await input.fill(body);
  await submit.click();
  await expect(panel.getByTestId("global-search-results-no-results")).toBeVisible();
  // No new current cut, store mutation or manual retry releases this result.
  await expect(row).toHaveCount(1);
  observed.restoredAt = Date.now();
  expect(observed.restoredAt).toBeGreaterThanOrEqual(Date.parse(policy.expires_at));
  await expect(row).toHaveAttribute("data-event-id", original!);
  await expect(row).toHaveAttribute("data-commit-id", commit!);
  await expect(row.getByTestId("global-search-result-snippet")).toHaveText(body);
  await page.reload();
  await dismissBlockingRecoveryModal(page);
  await input.fill(body);
  await submit.click();
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute("data-event-id", original!);
  await expect(row).toHaveAttribute("data-commit-id", commit!);
  expect(forbidden).toEqual([]);
  await testInfo.attach("policy-window.json", { body: JSON.stringify(observed, null, 2), contentType: "application/json" });
});
