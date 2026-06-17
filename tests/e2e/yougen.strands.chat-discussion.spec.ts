import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  refreshServer,
  gotoAndDismissRecovery,
  openTimeline,
  openDiscussion,
  createDiscussion,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("chat reloads sent messages and keeps actor sequence increasing", async ({ page }) => {
  await refreshServer(page);
  await openDiscussion(page);
  await createDiscussion(page, "Reload Discussion");

  const firstSend = page.waitForRequest(
    (request) => request.url().endsWith("/_cokret/self/events") && request.method() === "POST",
  );
  await page.getByTestId("chat-input").fill("message before reload");
  await page.getByTestId("send-chat-button").click();
  const firstBody = await firstSend.then((request) => request.postDataJSON());
  await expect(page.getByTestId("chat-status")).toContainText("Message sent");
  await expect(page.getByTestId("chat-message").last()).toContainText("message before reload");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await page.getByTestId("kanban-card").first().click();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();
  const reloadedMessage = page.getByTestId("chat-message").last();
  await expect(reloadedMessage).toContainText("message before reload");
  await expect(reloadedMessage).toHaveClass(/is-own/);
  await expect(reloadedMessage.locator(".name")).toHaveText("yougen");
  await expect(reloadedMessage).not.toContainText("did:web:alice.example");

  const secondSend = page.waitForRequest(
    (request) => request.url().endsWith("/_cokret/self/events") && request.method() === "POST",
  );
  await page.getByTestId("chat-input").fill("message after reload");
  await page.getByTestId("send-chat-button").click();
  const secondBody = await secondSend.then((request) => request.postDataJSON());

  expect(secondBody.actor_seq).toBeGreaterThan(firstBody.actor_seq);
  await expect(page.getByTestId("chat-status")).toContainText("Message sent");
  await expect(page.getByTestId("chat-message").last()).toContainText("message after reload");
  await expect(page.getByTestId("chat-message").last()).toHaveClass(/is-own/);
});

test("chat send failures mark the message and keep actions quiet until hover", async ({ page }) => {
  await refreshServer(page);
  await openDiscussion(page);
  await createDiscussion(page, "Failure Discussion");
  await page.route("**/_cokret/self/events", async (route) => {
    if (route.request().method() !== "POST") {
      return route.fallback();
    }
    const body = await route.request().postDataJSON();
    if (body.kind !== "ck.message.create") {
      return route.fallback();
    }
    return route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({
        ok: false,
        error: {
          ok: false,
          error: {
            code: "server_unavailable",
            message: "transient send failure",
          },
        },
        request_id: "ck:request:e2e-send-failed",
      }),
    });
  });

  await page.getByTestId("chat-input").fill("message that will fail");
  await page.getByTestId("send-chat-button").click();

  const message = page.getByTestId("chat-message").last();
  await expect(message).toContainText("message that will fail");
  await expect(message).toHaveClass(/is-failed/);
  await expect(page.getByTestId("chat-message-error").last()).toContainText("transient send failure");
  await expect(page.getByTestId("chat-retry-button").last()).toBeVisible();
  await expect(page.getByTestId("chat-reply-button").last()).toBeHidden();

  await message.hover();
  await expect(page.getByTestId("chat-reply-button").last()).toBeVisible();
});

test("chat membership denial restores draft without panicking", async ({ page }) => {
  await openDiscussion(page);
  await createDiscussion(page, "Membership Denied Discussion");
  await page.route("**/_cokret/self/events", async (route) => {
    if (route.request().method() !== "POST") {
      return route.fallback();
    }
    const body = await route.request().postDataJSON();
    if (body.kind !== "ck.message.create") {
      return route.fallback();
    }
    return route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({
        ok: false,
        error: {
          code: "capability_denied",
          message: "actor is not a member of the event Space",
        },
        request_id: "ck:request:01964137-0000-7000-8000-000000000013",
      }),
    });
  });

  await page.getByTestId("chat-input").fill("membership denied message");
  await page.getByTestId("send-chat-button").click();

  await expect(page.getByText("App panicked!")).toHaveCount(0);
  await expect(page.getByTestId("chat-status")).toContainText("not a member");
  await expect(page.getByTestId("chat-input")).toHaveValue("membership denied message");
  await expect(page.getByTestId("chat-message").filter({ hasText: "membership denied message" })).toHaveCount(0);
});

test("chat retries plaintext sends after granting current service visibility", async ({ page }) => {
  await refreshServer(page);
  await openDiscussion(page);
  await createDiscussion(page, "Policy Discussion");

  let attempts = 0;
  await page.route("**/_cokret/self/events", async (route) => {
    if (route.request().method() !== "POST") {
      return route.fallback();
    }
    const body = await route.request().postDataJSON();
    if (body.kind !== "ck.message.create") {
      return route.fallback();
    }
    attempts += 1;
    if (attempts !== 1) {
      return route.fallback();
    }
    return route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({
        ok: false,
        error: {
          ok: false,
          error: {
            code: "policy_denied",
            message:
              "private plaintext message operations require this service in plaintext_visible_services",
          },
        },
        request_id: "ck:request:e2e-policy-denied",
      }),
    });
  });

  const policyUpdate = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/events") &&
      request.method() === "POST" &&
      request.postDataJSON().kind === "ck.realm.update",
  );
  await page.getByTestId("chat-input").fill("policy retry message");
  await page.getByTestId("send-chat-button").click();

  const policyBody = await policyUpdate.then((request) => request.postDataJSON());
  expect(policyBody.payload.patch.plaintext_visible_services).toContain("did:web:server.local");
  await expect(page.getByTestId("chat-status")).toContainText("Message sent");
  await expect(page.getByTestId("chat-message").last()).not.toHaveClass(/is-failed/);
  expect(attempts).toBe(2);
});

test("plaintext compose keeps request ids, revision chains, tombstones, and local MLS entries", async ({ page }) => {
  await openTimeline(page);
  await page.getByTestId("composer-input").fill("draft survives reload");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await openTimeline(page);
  await expect(page.getByTestId("composer-input")).toHaveValue("draft survives reload");

  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("composer-input").fill("plain e2e message");
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message");
  await expect(page.getByTestId("write-status")).toContainText("persisted");

  const editRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/events") &&
      request.method() === "POST" &&
      request.postDataJSON().kind === "ck.message.revise",
  );
  await page.getByTestId("edit-button").last().click();
  await page.getByTestId("edit-composer").locator("textarea").fill("plain e2e message edited");
  await page.getByTestId("save-edit-button").click();
  expect((await editRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message edited");
  await expect(page.getByTestId("revision-chain")).toContainText("plain e2e message");
  await expect(page.getByTestId("event-fact").last()).toContainText("fact");

  const redactRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/events") &&
      request.method() === "POST" &&
      request.postDataJSON().kind === "ck.message.redact",
  );
  await page.getByTestId("redact-button").last().click();
  await page.getByTestId("confirm-redact-button").click();
  expect((await redactRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(page.getByTestId("redacted-tombstone")).toContainText("[Message redacted]");
  await expect(page.getByTestId("event-fact").last()).toContainText("tombstone ck:event:");

  await page.getByTestId("composer-input").fill("secret e2e message");
  await page.getByTestId("encrypt-local-button").click();
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("timeline")).toContainText("encrypted mls-rfc9420 epoch");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-crypto")).toContainText("encrypted local payload");
});

test("plaintext boundary blocks private drafts until exposure is acknowledged", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/timeline");
  await expect(latestTestId(page, "settings-timeline-plain-text")).toBeVisible();
  await expect(latestTestId(page, "settings-timeline-visible-service")).toContainText("configured server");
  await expect(latestTestId(page, "settings-timeline-disclosure")).toContainText("search");
  await latestTestId(page, "settings-timeline-private-plaintext").click();

  await openTimeline(page);
  await latestTestId(page, "composer-input").fill("private plaintext body");
  await latestTestId(page, "send-button").click();
  await expect(latestTestId(page, "write-status")).toContainText("plaintext blocked");
  await expect(latestTestId(page, "plaintext-boundary-warning")).toContainText("blocked");

  await gotoAndDismissRecovery(page, "/settings/timeline");
  await latestTestId(page, "settings-timeline-plaintext-ack").click();
  await openTimeline(page);
  await latestTestId(page, "composer-input").fill("acknowledged private plaintext body");
  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await latestTestId(page, "send-button").click();
  expect((await sendRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(latestTestId(page, "write-status")).toContainText("persisted");
});
