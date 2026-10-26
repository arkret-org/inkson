import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
import { expect, test, type Page, type Response } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  refreshServer,
  openDiscussion,
  gotoAndDismissRecovery,
  strandWatchControls,
  strandWatchTargets,
  submittedEvent,
  CURRENT_ACCOUNT_ACTOR_ID,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("chat fails closed until this device receives Realm encryption keys", async ({
  page,
}) => {
  await refreshServer(page);
  await openDiscussion(page);

  let messageSubmissions = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_arkret/self/events"
    ) {
      messageSubmissions += 1;
    }
  });

  await expect(page.getByRole("alert")).toContainText(
    "Waiting for this device's encryption keys. Keep this conversation open to receive the MLS Welcome.",
  );
  await inputByClass(page, "chat-input").fill("must not publish yet");
  await expect(byClass(page, "send-chat-button")).toBeDisabled();
  await expect(byClass(page, "chat-message")).toHaveCount(0);
  await expect(inputByClass(page, "chat-input")).toHaveValue("must not publish yet");
  expect(messageSubmissions).toBe(0);
});

const watchPath = "/_arkret/self/strands/watch/current";

async function openWatchCell(page: Page) {
  const { realmId, strands } = strandWatchTargets(page);
  const [response] = await Promise.all([
    page.waitForResponse(response => response.request().method() === "POST"
      && new URL(response.url()).pathname === watchPath
      && response.request().postDataJSON()?.realm_id === realmId
      && response.request().postDataJSON()?.strand_id === strands.review
      && response.status() === 200),
    (async () => {
      await gotoAndDismissRecovery(page, `/chat/${realmId}`);
      // This Realm has real card Strands but no default discussion Strand.
      // Select the existing readable track through its normal product button.
      await byClass(page, "channel-item").filter({ hasText: "Legal review for public beta" }).click();
      await expect(page.getByRole("heading", { name: "Legal review for public beta", exact: true })).toBeVisible();
    })(),
  ]);
  const request = response.request().postDataJSON();
  expect(request.realm_id).toBe(realmId);
  expect(request.strand_id).toBe(strands.review);
  expect(request.watcher_actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
  const target = { realmId: request.realm_id as string, strandId: request.strand_id as string };
  await expect(byClass(page, "watch-level-toggle")).toBeEnabled();
  return target;
}

function isWatchRead(response: Response, target: { realmId: string; strandId: string }) {
  return new URL(response.url()).pathname === watchPath
    && response.request().postDataJSON()?.realm_id === target.realmId
    && response.request().postDataJSON()?.strand_id === target.strandId;
}

async function awaitEntered(entered: Promise<void>) {
  let observed = false;
  void entered.then(() => { observed = true; });
  await expect.poll(() => observed).toBe(true);
}

// Clicking the already selected Strand is a normal product action: it notifies
// the existing selected-channel effect without changing the complete cell or
// session. Only the formal SDK-generated read response is held by the mock.
test("watch menu remains usable during a same-cell background read and ignores its late pre-write value", async ({ page }) => {
  const target = await openWatchCell(page);
  const controls = strandWatchControls(page);
  const gate = controls.holdNext(target);
  const writes: unknown[] = [];
  page.on("request", request => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/events") {
      const event = submittedEvent(request.postDataJSON());
      if (event?.kind === "ak.strand.watch.set") writes.push(event);
    }
  });
  try {
    const [originalRead] = await Promise.all([
      page.waitForRequest(request => request.method() === "POST"
        && new URL(request.url()).pathname === watchPath
        && request.postDataJSON()?.realm_id === target.realmId
        && request.postDataJSON()?.strand_id === target.strandId),
      page.locator('[class~="channel-item"].active').click(),
    ]);
    await awaitEntered(gate.entered);
    await expect(byClass(page, "watch-level-toggle")).toBeEnabled();
    await expect(byClass(page, "watch-level-controls")).toHaveAttribute("aria-busy", "true");
    await byClass(page, "watch-level-toggle").click();
    const option = byClass(page,"watch-level-menu").getByRole("menuitem",{name:"Muted", exact:true});
    await expect(option).toBeEnabled();
    const [accepted] = await Promise.all([
      page.waitForResponse(response => response.request().method() === "POST"
        && new URL(response.url()).pathname === "/_arkret/self/events"
        && submittedEvent(response.request().postDataJSON())?.kind === "ak.strand.watch.set"),
      option.click(),
    ]);
    expect(accepted.status()).toBe(200);
    expect((await accepted.json()).status).toBe("committed");
    const event = submittedEvent(accepted.request().postDataJSON());
    expect(event.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
    expect(event.payload.strand_id).toBe(target.strandId);
    expect(event.payload.watcher_actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
    expect(event.payload.level).toBe("muted");
    expect(Object.hasOwn(event.payload, "expected_value")).toBe(false);
    await expect(byClass(page, "watch-level-toggle")).toContainText("Muted");
    const lateRead = page.waitForResponse(response => response.request() === originalRead);
    gate.release();
    await lateRead;
    await expect(byClass(page, "watch-level-controls")).toHaveAttribute("aria-busy", "false");
    await expect(byClass(page, "watch-level-toggle")).toBeEnabled();
    await expect(byClass(page, "watch-level-toggle")).toContainText("Muted");
    expect(writes).toHaveLength(1);
  } finally {
    gate.release();
  }
});

test("watch read failure clears the observation and disables the menu", async ({ page }) => {
  const target = await openWatchCell(page);
  strandWatchControls(page).failNext(target, 503, "service_unavailable");
  await byClass(page, "watch-level-toggle").click();
  await expect(byClass(page, "watch-level-menu")).toBeVisible();
  const [failed] = await Promise.all([
    page.waitForResponse(response => isWatchRead(response, target) && response.status() === 503),
    page.locator('[class~="channel-item"].active').click(),
  ]);
  expect((await failed.json()).status).toBe(503);
  await expect(byClass(page, "watch-level-toggle")).toBeDisabled();
  await expect(byClass(page, "watch-level-menu")).toBeHidden();
  await expect(byClass(page, "watch-level-retry")).toHaveCount(0);
});

test("watch target replacement cannot publish an old read or release the new target's first read", async ({ page }) => {
  const target = await openWatchCell(page);
  const controls = strandWatchControls(page);
  const oldRead = controls.holdNext(target);
  const { realmId, strands } = strandWatchTargets(page);
  const nextTarget = { realmId, strandId: strands.secondary };
  expect(nextTarget.strandId).not.toBe(target.strandId);
  const nextRead = controls.holdNext(nextTarget);
  try {
    await page.locator('[class~="channel-item"].active').click();
    await awaitEntered(oldRead.entered);
    // The existing all-tracks filter exposes the actual secondary Strand.
    await byClass(page, "discussion-filter-track").click();
    const secondary = byClass(page, "channel-item").filter({ hasText: "Secondary" });
    await secondary.click();
    await expect(byClass(page, "watch-level-toggle")).toBeDisabled();
    oldRead.release();
    await awaitEntered(nextRead.entered);
    await expect(byClass(page, "watch-level-toggle")).toBeDisabled();
    await expect(byClass(page, "watch-level-menu")).toBeHidden();
    await expect(byClass(page, "watch-level-retry")).toHaveCount(0);
    nextRead.release();
    await expect(byClass(page, "watch-level-toggle")).toBeEnabled();
    await expect(byClass(page, "watch-level-toggle")).toContainText("Default");
  } finally {
    oldRead.release();
    nextRead.release();
  }
});
