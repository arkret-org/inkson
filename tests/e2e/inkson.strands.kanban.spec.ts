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

test("sidecar display mode persists across tracks and fits a narrow long-agent layout", async ({
  page,
}) => {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  await detailPopup
    .getByTestId("card-detail-agent-row")
    .getByTestId("card-detail-member-mention-button")
    .click();
  await detailPopup.getByTestId("chat-input").fill("@me/assistant keep this private draft");

  const ensureResponse = page.waitForResponse((response) =>
    response.url().includes("/_arkret/self/agent-sidecars:ensure"),
  );
  await detailPopup.getByTestId("send-chat-button").click();
  await expect((await ensureResponse).ok()).toBeTruthy();
  await expect(detailPopup).toBeVisible();
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();

  await detailPopup.getByTestId("card-detail-tab-description").click();
  await expect(detailPopup.getByTestId("sidecar-shared-description-base")).toBeVisible();
  await expect(detailPopup.getByTestId("sidecar-private-description-label")).toBeVisible();

  await page.getByTestId("sidecar-mode-sidecar-only").click();
  await expect(page.getByTestId("sidecar-mode-sidecar-only")).toHaveClass(/active/);
  await expect(detailPopup.getByTestId("sidecar-shared-description-base")).toHaveCount(0);
  await expect(detailPopup.getByTestId("sidecar-private-description-label")).toBeVisible();

  await detailPopup.getByTestId("card-detail-tab-synthesis").click();
  await expect(page.getByTestId("sidecar-mode-sidecar-only")).toHaveClass(/active/);
  await expect(detailPopup.getByTestId("sidecar-shared-synthesis-base")).toHaveCount(0);
  await expect(detailPopup.getByTestId("sidecar-private-synthesis-label")).toBeVisible();

  await page.getByTestId("sidecar-mode-context-merged").click();
  await expect(page.getByTestId("sidecar-mode-context-merged")).toHaveClass(/active/);
  await expect(detailPopup.getByTestId("sidecar-shared-synthesis-base")).toBeVisible();

  await detailPopup.getByTestId("card-detail-tab-discussion").click();
  await expect(detailPopup.getByTestId("chat-input")).toHaveValue(
    "@me/assistant keep this private draft",
  );

  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByTestId("sidecar-addressed-now").locator("strong").evaluate((element) => {
    element.textContent =
      "assistant-with-an-intentionally-very-long-private-agent-handle-that-must-wrap";
  });
  const layout = await page.getByTestId("sidecar-context-strip").evaluate((strip) => {
    const bounds = strip.getBoundingClientRect();
    const children = Array.from(strip.children).map((child) => {
      const rect = child.getBoundingClientRect();
      return { left: rect.left, right: rect.right };
    });
    return {
      clientWidth: strip.clientWidth,
      scrollWidth: strip.scrollWidth,
      left: bounds.left,
      right: bounds.right,
      children,
    };
  });
  expect(layout.scrollWidth).toBeLessThanOrEqual(layout.clientWidth + 1);
  for (const child of layout.children) {
    expect(child.left).toBeGreaterThanOrEqual(layout.left - 1);
    expect(child.right).toBeLessThanOrEqual(layout.right + 1);
  }
});

test("sidecar preserves long-history UI state across tracks and modes with multiple agents", async ({
  page,
}) => {
  const longAgentSlug =
    "research-assistant-with-an-intentionally-long-private-handle";
  const longCardTitle =
    "Legal review for a public beta launch with an intentionally long cross-team approval title";
  await openKanban(page);
  await page.getByTestId("kanban-card").filter({ hasText: longCardTitle }).click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await expect(detailPopup).toContainText(longCardTitle);
  await detailPopup.getByTestId("card-detail-tab-discussion").click();

  const input = detailPopup.getByTestId("chat-input");
  for (let index = 0; index < 18; index += 1) {
    const response = page.waitForResponse(
      (candidate) =>
        candidate.url().endsWith("/_arkret/self/events") &&
        candidate.request().method() === "POST",
    );
    await input.fill(`shared history row ${String(index).padStart(2, "0")}`);
    await detailPopup.getByTestId("send-chat-button").click();
    await expect((await response).ok()).toBeTruthy();
  }
  await expect(detailPopup.getByTestId("chat-message")).toHaveCount(18);

  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  const agentRows = detailPopup.getByTestId("card-detail-agent-row");
  await agentRows
    .filter({ hasText: "Alice Assistant" })
    .getByTestId("card-detail-member-mention-button")
    .click();
  await agentRows
    .filter({ hasText: "Research Assistant" })
    .getByTestId("card-detail-member-mention-button")
    .click();
  const privateDraft =
    "@me/assistant @me/research-assistant-with-an-intentionally-long-private-handle preserve this private draft";
  await input.fill(privateDraft);

  const ensureResponse = page.waitForResponse((response) =>
    response.url().endsWith("/_arkret/self/agent-sidecars:ensure"),
  );
  await detailPopup.getByTestId("send-chat-button").click();
  await expect((await ensureResponse).ok()).toBeTruthy();
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();
  await expect(page.getByTestId("sidecar-addressed-now")).toContainText("assistant");
  await expect(page.getByTestId("sidecar-addressed-now")).toContainText(longAgentSlug);
  await expect(input).toHaveValue(privateDraft);

  await page.setViewportSize({ width: 390, height: 844 });
  const stripMetrics = await page.getByTestId("sidecar-context-strip").evaluate((strip) => ({
    clientWidth: strip.clientWidth,
    scrollWidth: strip.scrollWidth,
  }));
  expect(stripMetrics.scrollWidth).toBeLessThanOrEqual(stripMetrics.clientWidth + 1);

  const feed = detailPopup.getByTestId("message-list");
  const firstMessage = detailPopup.getByTestId("chat-message").first();
  await firstMessage.evaluate((element) => {
    element.setAttribute("data-e2e-preserved-node", "yes");
  });
  const initialScroll = await feed.evaluate((element) => {
    const target = Math.max(1, Math.floor((element.scrollHeight - element.clientHeight) / 2));
    element.scrollTop = target;
    return {
      scrollTop: element.scrollTop,
      scrollHeight: element.scrollHeight,
      clientHeight: element.clientHeight,
    };
  });
  expect(initialScroll.scrollHeight).toBeGreaterThan(initialScroll.clientHeight);
  expect(initialScroll.scrollTop).toBeGreaterThan(0);

  let fullHistoryRequests = 0;
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (request.method() === "GET" && url.pathname === "/_arkret/self/events") {
      fullHistoryRequests += 1;
    }
  });
  await page.waitForTimeout(300);

  await page.getByTestId("sidecar-mode-sidecar-only").click();
  await detailPopup.getByTestId("card-detail-tab-description").click();
  await detailPopup.getByTestId("card-detail-tab-synthesis").click();
  await page.getByTestId("sidecar-mode-context-merged").click();
  await detailPopup.getByTestId("card-detail-tab-discussion").click();
  await page.getByTestId("sidecar-mode-sidecar-only").click();
  await page.getByTestId("sidecar-mode-context-merged").click();

  await expect(input).toHaveValue(privateDraft);
  await expect(firstMessage).toHaveAttribute("data-e2e-preserved-node", "yes");
  const restoredScroll = await feed.evaluate((element) => element.scrollTop);
  expect(restoredScroll).toBe(initialScroll.scrollTop);
  expect(fullHistoryRequests).toBe(0);
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
  expect(Array.isArray(chatBody.payload.content.mention_sidecar_digest)).toBeTruthy();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #ak:task:123");
  await page.getByTestId("card-detail-tab-description").click();
  await expect(page.getByTestId("card-description-panel")).toBeVisible();
  await expect(page.getByTestId("card-discussion-panel")).toHaveCount(1);
  await expect(page.getByTestId("card-discussion-panel")).toBeHidden();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #ak:task:123");
});
