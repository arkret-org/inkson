import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  DEMO_BOARD_SPACE,
  refreshServer,
  openDiscussion,
  openKanban,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("kanban card detail embeds discussion without boundary copy", async ({ page }) => {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await expect(page.getByTestId("card-detail-overlay")).toBeVisible();
  await expect(detailPopup).toHaveAttribute("role", "dialog");
  await expect(detailPopup).toContainText("Discussion");
  await expect(detailPopup.getByTestId("card-description-panel")).toBeVisible();
  await expect(detailPopup).not.toContainText("Primary discussion");
  await expect(detailPopup).not.toContainText("Launch discussion");
  await expect(detailPopup).not.toContainText("card visibility != discussion visibility");
  await detailPopup.getByTestId("card-detail-edit-button").click();
  await expect(detailPopup.getByTestId("card-detail-save-button")).toBeVisible();
  await expect(detailPopup.getByTestId("card-detail-cancel-edit-button")).toBeVisible();
  const saveButtonBox = await detailPopup.getByTestId("card-detail-save-button").boundingBox();
  const cancelButtonBox = await detailPopup.getByTestId("card-detail-cancel-edit-button").boundingBox();
  if (!saveButtonBox || !cancelButtonBox) {
    throw new Error("card detail edit action buttons were not measurable");
  }
  expect(saveButtonBox.height).toBeLessThanOrEqual(44);
  expect(cancelButtonBox.height).toBeLessThanOrEqual(44);
  await detailPopup.getByTestId("card-detail-cancel-edit-button").click();
  await expect(detailPopup.getByTestId("card-description-panel")).toBeVisible();
  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  const memberGroup = detailPopup.getByTestId("card-detail-member-group");
  const selfMention = memberGroup
    .getByTestId("card-detail-member-mention-button")
    .filter({ hasText: "ME" });
  const agentRow = memberGroup.getByTestId("card-detail-agent-row");
  const agentMention = agentRow.getByTestId("card-detail-member-mention-button");
  await expect(selfMention).toContainText("alice:local.host");
  await expect(selfMention).not.toContainText("did:web:alice.example");
  await expect(agentRow.getByTestId("card-detail-member-agent-badge")).toHaveText("Agent");
  await expect(agentRow.getByTestId("card-detail-member-agent-selector")).toHaveText(
    "@me/assistant",
  );
  const selfMentionBox = await selfMention.boundingBox();
  const agentMentionBox = await agentMention.boundingBox();
  if (!selfMentionBox || !agentMentionBox) {
    throw new Error("member hierarchy rows were not measurable");
  }
  expect(agentMentionBox.x).toBeGreaterThan(selfMentionBox.x);

  await agentMention.click();
  await expect(detailPopup.getByTestId("card-detail-tab-discussion")).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByTestId("chat-panel")).toBeVisible();
  await expect(page.getByTestId("open-primary-discussion")).toHaveCount(0);
  await expect(detailPopup.getByTestId("chat-input")).toHaveValue("@me/assistant ");
  await detailPopup.getByTestId("mention-chip").getByRole("button").click();
  await detailPopup.getByTestId("chat-input").fill("");
  await selfMention.click();
  await expect(detailPopup.getByTestId("chat-input")).toHaveValue("@me ");
  await expect(detailPopup.getByTestId("chat-input")).toBeFocused();
  const popupBox = await detailPopup.boundingBox();
  if (!popupBox) {
    throw new Error("card detail modal bounding box was unavailable");
  }
  await page.mouse.move(popupBox.x + popupBox.width / 2, popupBox.y + 24);
  await page.mouse.down();
  await page.mouse.move(12, 12, { steps: 4 });
  await page.mouse.up();
  await expect(detailPopup).toBeVisible();
  await page.mouse.click(12, 12);
  await expect(detailPopup).toHaveCount(0);

  await page.getByTestId("kanban-card").first().click();
  await expect(detailPopup).toBeVisible();
  await page.getByTestId("card-detail-close-button").click();
  await expect(detailPopup).toHaveCount(0);
});

test("owned agent sidecar labels private messages in discussion", async ({ page }) => {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  const agentMention = detailPopup
    .getByTestId("card-detail-agent-row")
    .getByTestId("card-detail-member-mention-button");
  await agentMention.click();
  await detailPopup.getByTestId("chat-input").fill("@me/assistant hello");

  await page.route("**/_arkret/self/agent-sidecars:ensure", async (route) => {
    await new Promise((resolve) => setTimeout(resolve, 250));
    await route.fallback();
  });
  const ensureResponse = page.waitForResponse((response) =>
    response.url().includes("/_arkret/self/agent-sidecars:ensure"),
  );
  await detailPopup.getByTestId("send-chat-button").click();

  await expect(detailPopup.getByTestId("chat-status")).toContainText(
    "Activating Private Sidecar",
  );
  await expect(detailPopup.getByTestId("send-chat-button")).toBeDisabled();
  await expect((await ensureResponse).ok()).toBeTruthy();
  await expect(page).toHaveURL(/\/direct\/.*\/ak:strand:/);
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();
  await expect(page.getByTestId("chat-input")).toHaveValue("@me/assistant hello");

  await page.getByTestId("send-chat-button").click();
  const privateMessage = page.getByTestId("chat-message").last();
  await expect(privateMessage).toContainText("@me/assistant hello");
  const privacyBadge = privateMessage.getByTestId("message-private-sidecar-badge");
  await expect(privacyBadge).toBeVisible();
  await expect(privacyBadge).toContainText("Private sidecar");
  await expect(privacyBadge).toHaveAttribute("data-visibility", "private-sidecar");
});

test("pending sidecar reconciliation blocks contextual send without claiming readiness", async ({ page }) => {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  await detailPopup
    .getByTestId("card-detail-agent-row")
    .getByTestId("card-detail-member-mention-button")
    .click();
  await detailPopup.getByTestId("chat-input").fill("@me/assistant inspect privately");

  const ensureResponse = page.waitForResponse(
    (response) => response.url().endsWith("/_arkret/self/agent-sidecars:ensure"),
    { timeout: 20_000 },
  );
  await detailPopup.getByTestId("send-chat-button").click();
  await expect((await ensureResponse).ok()).toBeTruthy();

  await expect(page).toHaveURL(/\/direct\/.*\/ak:strand:/);
  await expect(page.getByTestId("sidecar-security-state")).toHaveText(
    "Reconciling access",
  );
  await expect(page.getByTestId("sidecar-readiness-gate")).toContainText(
    "1 principal",
  );
  await expect(page.getByTestId("send-chat-button")).toBeDisabled();
});

test("kanban hides list creation until a board exists", async ({ page }) => {
  await page.route("**/_arkret/self/realms/*/spaces", async (route) => {
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: [], total: 0, spaces: [] }),
    });
  });
  await page.route("**/_arkret/self/realms/*/strands", async (route) => {
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: [], total: 0, strands: [] }),
    });
  });

  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("kanban-empty-board")).toContainText("No board selected");
  await expect(page.getByTestId("add-column-button")).toHaveCount(0);
  await expect(page.getByTestId("view-renderer-switcher")).toHaveCount(0);
  await expect(page.getByTestId("board-space-selector")).not.toContainText("BOARD");

  await page.getByTestId("new-board-toggle").click();
  await expect(page.getByTestId("new-board-title-input")).toBeVisible();
  await page.mouse.click(12, 12);
  await expect(page.getByTestId("new-board-title-input")).toHaveCount(0);

  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill("Design board");
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("add-column-button")).toBeVisible();
  await expect(page.getByTestId("board-space-selector")).toContainText("Design board");
  await expect(page.getByTestId("kanban-empty-board")).toContainText("No lists yet");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("add-column-button")).toBeVisible();
  await expect(page.getByTestId("board-space-selector")).toContainText("Design board");
  await expect(page.getByTestId("kanban-empty-board")).toContainText("No lists yet");
});

test("kanban queues canonical event submissions and quarantines manual replay", async ({ page }) => {
  await openKanban(page);
  await page.getByTestId("add-card-button").first().click();
  await page.getByTestId("new-card-title-input").fill("Move-backed card");
  const eventSubmit = page.waitForRequest(
    (request) => request.url().includes("/_arkret/self/events") && request.method() === "POST",
  );
  await page.getByTestId("save-card-button").click();
  const eventBody = await eventSubmit.then((request) => request.postDataJSON());
  expect(eventBody.kind).toBe("ak.strand.create");
  const positionComponent = eventBody.payload?.components?.find(
    (component: { family?: string }) => component.family === "ak.component.strand.position.v1",
  );
  expect(positionComponent?.family).toBe("ak.component.strand.position.v1");
  await page.getByTestId("board-queue-toggle").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText("ak.strand.create");
  await expect(page.getByTestId("board-event-record").last()).toContainText("sha256:");
  await expect(page.getByTestId("board-event-record").last()).toContainText("ak.component.strand.position.v1");
  await expect(page.getByTestId("board-conflict-alert")).toHaveCount(0);

  await page.getByTestId("replay-board-queue").click();
  await expect(page.getByTestId("board-status")).toHaveCount(0);

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("kanban-board-grid")).toContainText("Move-backed card");
});

test("kanban board selector swaps projected board columns", async ({ page }) => {
  await openKanban(page);
  await expect(page.getByTestId("view-renderer-switcher")).toHaveCount(0);
  await expect(page.getByTestId("kanban-board-grid")).toContainText("Legal review for public beta");

  // board-space-select 现为 dxc Select(自定义 listbox 弹层,非原生 <select>),
  // 故不能再用 selectOption();改为「点 trigger 按钮打开 → 点 role=option 选项」。
  await page.getByTestId("board-space-select").getByRole("button").click();
  await page.getByRole("option", { name: "Secondary planning board" }).click();

  await expect(page.getByTestId("kanban-column")).toHaveCount(1);
  await expect(page.getByTestId("kanban-board-grid")).toContainText("Secondary board card");
  await expect(page.getByTestId("kanban-board-grid")).not.toContainText("Legal review for public beta");
});

test("kanban card drag queues a strand move", async ({ page }) => {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();

  await page.getByTestId("kanban-card").first().dragTo(page.getByTestId("kanban-column").nth(1));

  await page.getByTestId("board-queue-toggle").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText("ak.strand.move");
  await expect(page.getByTestId("kanban-column").nth(1)).toContainText("Legal review for public beta");
});

test("kanban board routes keep the board Space under its home Realm", async ({ page }) => {
  await refreshServer(page);

  await page.goto(`/kanban/${DEMO_REALM}/board/${DEMO_BOARD_SPACE}`, {
    waitUntil: "domcontentloaded",
  });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("selected-realm-id")).toHaveText(DEMO_REALM);
  expect(new URL(page.url()).pathname).toBe(
    `/kanban/${DEMO_REALM}/board/${DEMO_BOARD_SPACE}`,
  );
});

test("card detail embeds discussion directly without discussion chrome", async ({ page }) => {
  await refreshServer(page);
  await openDiscussion(page);
  await expect(page.getByTestId("discussion-main-panel")).toBeVisible();
  await expect(page.getByTestId("discussion-main-panel")).toContainText("No messages yet");
  await expect(page.getByTestId("discussion-list-panel")).toHaveCount(0);
  await expect(page.getByTestId("discussion-list-rail")).toHaveCount(0);
  await expect(page.getByTestId("open-channel-dialog")).toHaveCount(0);
  await expect(page.getByTestId("discussion-users-toggle")).toHaveCount(0);
  await expect(page.getByTestId("discussion-settings-toggle")).toHaveCount(0);
  await expect(page.getByTestId("channel-create-modal")).toHaveCount(0);
  await expect(page.getByTestId("new-channel-members")).toHaveCount(0);
  await expect(page.getByTestId("open-primary-discussion")).toHaveCount(0);
  await expect(page.getByTestId("card-strand-tracks")).toHaveCount(0);
  await expect(page.getByTestId("discussion-main-panel")).not.toContainText("Launch board discussion");
  await expect(page.getByTestId("discussion-main-panel")).not.toContainText("Primary discussion");

  const chatSend = page.waitForRequest("**/_arkret/self/events");
  await page.getByTestId("chat-input").fill("hello @did:web:bob.example about #ak:task:123");
  await page.getByTestId("send-chat-button").click();
  const chatBody = await chatSend.then((request) => request.postDataJSON());
  expect(chatBody.kind).toBe("ak.message.create");
  expect(chatBody.payload.message_id).toMatch(/^ak:message:/);
  expect(chatBody.payload.strand_id).toContain("ak:strand:");
  expect(chatBody.payload.track_name).toBe("discussion");
  expect(chatBody.payload.content.kind).toBe("ak.content.text");
  expect(chatBody.payload.content.body).toBe("hello @did:web:bob.example about #ak:task:123");
  expect(chatBody.payload.mentions).toBeUndefined();
  expect(Array.isArray(chatBody.payload.content.mention_sidecar_hash)).toBeTruthy();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #ak:task:123");
  await page.getByTestId("card-detail-tab-description").click();
  await expect(page.getByTestId("card-description-panel")).toBeVisible();
  await expect(page.getByTestId("card-discussion-panel")).toHaveCount(1);
  await expect(page.getByTestId("card-discussion-panel")).toBeHidden();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #ak:task:123");
});
