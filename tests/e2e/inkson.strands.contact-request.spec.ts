import { expect, test } from "@playwright/test";
import { inksonWire } from "./mockArkretApi";
import { registerStrandsBeforeEach, gotoAndDismissRecovery, latestTestId, dismissBlockingRecoveryModal } from "./strandsHarness";

registerStrandsBeforeEach();

// The peer has its own native WebVH/PCR anchor and signing key.
// This does not stand in for remote admission or an incoming Contact round.
const peerAnchor = inksonWire<Record<string, any>>("mock-realm-fixture", {
  salt: 10, title: "Contact peer anchor", seed_b64url: Buffer.alloc(32, 4).toString("base64url"),
});
const peer = { kind: "human", account_id: peerAnchor.identity.account_id };

async function openRequest(page: import("@playwright/test").Page) {
  await gotoAndDismissRecovery(page, "/contacts");
  await dismissBlockingRecoveryModal(page);
  await page.getByTestId("add-contact-button").last().click();
  const modal = page.getByTestId("add-contact-modal").last();
  await expect(modal).toBeVisible();
  await modal.getByTestId("contact-target-input").fill(JSON.stringify(peer.account_id));
  await modal.getByTestId("contact-message-input").fill("Hello from the real client");
  return modal;
}

test("contact request signs the prepared draft and consumes the accepted receipt", async ({ page }) => {
  const modal = await openRequest(page);
  const commitResponse = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/_arkret/self/contacts/request" &&
    response.request().postDataJSON()?.phase === "commit");
  await modal.getByTestId("send-contact-request-button").click();
  const response = await commitResponse;
  const submitted = response.request().postDataJSON();
  const outcome = await response.json();
  expect(outcome.status).toBe("accepted");
  expect(submitted.signed_event.payload.peer).toEqual(peer);
  expect(submitted.signed_event.payload.message).toBe("Hello from the real client");
  expect(inksonWire("contact-request-verify", { outcome, event: submitted.signed_event })).toEqual({ verified: true });
  await expect(modal).toBeHidden();
  const shell = latestTestId(page, "client-shell");
  const outgoing = shell.locator(`[data-testid="contact-row"][data-peer*="${peer.account_id.principal_id}"]`);
  await expect(outgoing.locator('[data-testid^="contact-pending-outgoing-"]')).toBeVisible();
});

test("contact request terminal failure stays visible and creates no contact", async ({ page }) => {
  const modal = await openRequest(page);
  await modal.getByTestId("send-contact-request-button").click();
  await expect(modal.getByTestId("contact-request-status")).toContainText("ContactRoundConflict");
  await expect(modal).toBeVisible();
  await expect(modal.getByTestId("contact-message-input")).toHaveValue("Hello from the real client");
  await expect(latestTestId(page, "client-shell").locator(`[data-testid="contact-row"][data-peer*="${peer.account_id.principal_id}"]`)).toHaveCount(0);
});

test("contact request rejects tampered receipt before reporting UI success", async ({ page }) => {
  const modal = await openRequest(page);
  await modal.getByTestId("send-contact-request-button").click();
  await expect(modal.getByTestId("contact-request-status")).toContainText("exact Event");
  await expect(modal).toBeVisible();
  await expect(modal.getByTestId("contact-message-input")).toHaveValue("Hello from the real client");
});
