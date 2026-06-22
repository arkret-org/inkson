import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  refreshServer,
  gotoAndDismissRecovery,
  openDiscussion,
  createDiscussion,
  dismissMlsBackupModal,
} from "./strandsHarness";

registerStrandsBeforeEach();

const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";

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

test("chat separates shared pins from private saved account-data", async ({ page }) => {
  await refreshServer(page);
  await gotoAndDismissRecovery(page, `/chat/${DEMO_REALM}`);
  await expect(page.getByTestId("chat-panel")).toBeVisible();
  await createDiscussion(page, "Pin Saved Separation Discussion");
  await dismissMlsBackupModal(page);

  await page.getByTestId("chat-input").fill("pin and save boundaries");
  await page.getByTestId("send-chat-button").click();
  const message = page.getByTestId("chat-message").last();
  await expect(message).toContainText("pin and save boundaries");

  await message.evaluate((element) => {
    element.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, button: 2, buttons: 2 }));
  });
  await expect(page.getByTestId("message-context-menu")).toBeVisible();
  const sharedPinRequest = page.waitForRequest((request) => {
    if (!request.url().endsWith("/_cokret/self/events") || request.method() !== "POST") {
      return false;
    }
    return request.postDataJSON().kind === "ck.pin.add";
  });
  await page.getByTestId("message-shared-pin-button").click();
  const sharedPinBody = await sharedPinRequest.then((request) => request.postDataJSON());

  expect(sharedPinBody.payload.pin_scope.kind).toBe("strand");
  expect(sharedPinBody.payload.target_ref).toMatch(/^ck:message:/);
  expect(sharedPinBody.payload.key).toBeUndefined();
  expect(sharedPinBody.payload.encrypted_payload).toBeUndefined();
  await expect(page.getByTestId("pinned-bar")).toHaveAttribute("data-source", "shared-event");
  await expect(page.getByTestId("pinned-bar-item").last()).toHaveAttribute("data-source", "shared-event");

  await message.evaluate((element) => {
    element.dispatchEvent(new MouseEvent("contextmenu", { bubbles: true, cancelable: true, button: 2, buttons: 2 }));
  });
  await expect(page.getByTestId("message-context-menu")).toBeVisible();
  const savedRequest = page.waitForRequest((request) => {
    if (!request.url().endsWith("/_cokret/self/events") || request.method() !== "POST") {
      return false;
    }
    const body = request.postDataJSON();
    return body.kind === "ck.account_data.set" && String(body.payload?.key ?? "").startsWith("ck.saved.v1:");
  });
  await page.getByTestId("message-private-save-button").click();
  const savedBody = await savedRequest.then((request) => request.postDataJSON());

  expect(savedBody.payload.key).toMatch(/^ck\.saved\.v1:/);
  expect(savedBody.payload.encrypted_payload.kind).toBe("saved_item");
  expect(savedBody.payload.encrypted_payload.target_ref).toMatch(/^ck:message:/);
  expect(savedBody.payload.body).toBeUndefined();
  expect(savedBody.payload.pin_scope).toBeUndefined();
  await expect(page.getByTestId("message-private-saved-indicator").last()).toHaveAttribute(
    "data-source",
    "private-account-data",
  );
});
