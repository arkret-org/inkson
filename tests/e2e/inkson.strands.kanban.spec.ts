import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  DEMO_BOARD_SPACE,
  dismissBlockingRecoveryModal,
  dismissHistoryRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  openDiscussion,
  openKanban,
  submittedEvent,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("kanban card detail embeds discussion without boundary copy", async ({
  page,
}) => {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await expect(page.getByTestId("card-detail-overlay")).toBeVisible();
  await expect(detailPopup).toHaveAttribute("role", "dialog");
  await expect(detailPopup).toContainText("Discussion");
  await expect(detailPopup).not.toContainText("Primary discussion");
  await expect(detailPopup).not.toContainText("Launch discussion");
  await expect(detailPopup).not.toContainText(
    "card visibility != discussion visibility",
  );
  await detailPopup.getByTestId("card-detail-edit-button").click();
  await expect(
    detailPopup.getByTestId("card-detail-save-button"),
  ).toBeVisible();
  await expect(
    detailPopup.getByTestId("card-detail-cancel-edit-button"),
  ).toBeVisible();
  const descriptionTab = detailPopup.getByTestId("card-detail-tab-description");
  const synthesisTab = detailPopup.getByTestId("card-detail-tab-synthesis");
  const discussionTab = detailPopup.getByTestId("card-detail-tab-discussion");
  await expect(descriptionTab).toBeEnabled();
  await expect(synthesisTab).toBeEnabled();
  await expect(discussionTab).toBeEnabled();
  const saveButtonBox = await detailPopup
    .getByTestId("card-detail-save-button")
    .boundingBox();
  const cancelButtonBox = await detailPopup
    .getByTestId("card-detail-cancel-edit-button")
    .boundingBox();
  if (!saveButtonBox || !cancelButtonBox) {
    throw new Error("card detail edit action buttons were not measurable");
  }
  expect(saveButtonBox.height).toBeLessThanOrEqual(44);
  expect(cancelButtonBox.height).toBeLessThanOrEqual(44);
  await detailPopup.getByTestId("card-detail-cancel-edit-button").click();

  await descriptionTab.click();
  await detailPopup.getByTestId("card-detail-edit-description-button").click();
  await expect(
    detailPopup.locator("#card-detail-description-toast-editor"),
  ).toBeVisible();
  await synthesisTab.click();
  await expect(synthesisTab).toHaveAttribute("aria-selected", "true");
  await expect(
    detailPopup.locator("#card-detail-synthesis-toast-editor"),
  ).toBeVisible();
  await discussionTab.click();
  await expect(discussionTab).toHaveAttribute("aria-selected", "true");
  await synthesisTab.click();
  await expect(
    detailPopup.locator("#card-detail-synthesis-toast-editor"),
  ).toBeVisible();
  await descriptionTab.click();
  await expect(
    detailPopup.locator("#card-detail-description-toast-editor"),
  ).toBeVisible();
  await detailPopup.getByTestId("card-detail-cancel-edit-button").click();
  await synthesisTab.click();
  await expect(detailPopup.getByTestId("card-synthesis-panel")).toBeVisible();
  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  const selfMention = page.getByRole("button", {
    name: "Mention alice:local.host",
    exact: true,
  });
  const agentMention = page.getByRole("button", {
    name: "Mention assistant",
    exact: true,
  });
  await expect(selfMention).toContainText("alice:local.host");
  await expect(selfMention).not.toContainText("did:web:alice.example");
  await expect(agentMention).toContainText("Agent");
  await expect(agentMention).toContainText("@me/assistant");

  await agentMention.click();
  await expect(
    detailPopup.getByTestId("card-detail-tab-discussion"),
  ).toHaveAttribute("aria-selected", "true");
  await expect(page.getByTestId("chat-panel")).toBeVisible();
  await expect(page.getByTestId("open-primary-discussion")).toHaveCount(0);
  await expect(detailPopup.getByTestId("chat-input")).toHaveValue(
    "@me/assistant ",
  );
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

test("sidecar activation fails closed until the Realm content scheme is verified", async ({
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
  await detailPopup.getByTestId("chat-input").fill("@me/assistant hello");

  let ensureRequests = 0;
  page.on("request", (request) => {
    if (request.url().includes("/_arkret/self/agent-sidecars:ensure")) {
      ensureRequests += 1;
    }
  });

  await expect(detailPopup.getByRole("alert")).toContainText(
    "waiting for the verified content scheme",
  );
  await expect(detailPopup.getByTestId("send-chat-button")).toBeDisabled();
  await expect(page.getByTestId("sidecar-context-strip")).toHaveCount(0);
  await page.waitForTimeout(300);
  expect(ensureRequests).toBe(0);
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

  await gotoAndDismissRecovery(page, `/kanban/${DEMO_REALM}`);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("board-projection-toggle")).toHaveCount(0);
  await expect(page.getByTestId("board-queue-toggle")).toHaveCount(0);
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    "No board selected",
  );
  await expect(page.getByTestId("add-column-button")).toHaveCount(0);
  await expect(page.getByTestId("view-renderer-switcher")).toHaveCount(0);
  await expect(page.getByTestId("board-space-selector")).not.toContainText(
    "BOARD",
  );

  await page.getByTestId("new-board-toggle").click();
  await expect(page.getByTestId("new-board-title-input")).toBeVisible();
  await page.mouse.click(12, 12);
  await expect(page.getByTestId("new-board-title-input")).toHaveCount(0);

  let acceptBoardCreate: (() => void) | undefined;
  const boardCreateGate = new Promise<void>((resolve) => {
    acceptBoardCreate = resolve;
  });
  await page.route("**/_arkret/self/events", async (route) => {
    const request = route.request();
    if (request.method() !== "POST") {
      await route.fallback();
      return;
    }
    const event = submittedEvent(request.postDataJSON());
    const object = event?.payload?.object;
    if (event?.kind === "ak.space.create" && object?.kind === "board") {
      await boardCreateGate;
    }
    await route.fallback();
  });

  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill("Design board");
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("add-column-button")).toBeVisible();
  await expect(page.getByTestId("add-column-button")).toBeDisabled();
  await expect(page.getByTestId("board-space-selector")).toContainText(
    "Design board",
  );
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    "No lists yet",
  );
  expect(new URL(page.url()).pathname).not.toContain("/board/");

  acceptBoardCreate?.();
  await expect(page.getByTestId("add-column-button")).toBeEnabled();
});

test("kanban submits canonical card-create events", async ({ page }) => {
  await openKanban(page);
  await page.getByTestId("add-card-button").first().click();
  await page.getByTestId("new-card-title-input").fill("Move-backed card");
  const eventSubmit = page.waitForRequest(
    (request) =>
      request.url().includes("/_arkret/self/events") &&
      request.method() === "POST",
  );
  await page.getByTestId("save-card-button").click();
  const eventBody = submittedEvent(
    await eventSubmit.then((request) => request.postDataJSON()),
  );
  expect(eventBody.kind).toBe("ak.strand.create");
  expect(eventBody.payload.object.metadata.fields.board_space_id).toBe(
    DEMO_BOARD_SPACE,
  );
  expect(eventBody.payload.object.metadata.fields.list_space_id).toMatch(
    /^ak:space:/,
  );
  expect(eventBody.payload.components).toBeUndefined();
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissHistoryRecoveryModal(page);
  await dismissBlockingRecoveryModal(page);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("kanban-board-grid")).toContainText(
    "Move-backed card",
  );
});

test("card create receipt survives opening the optimistic card", async ({
  page,
}) => {
  await openKanban(page);

  let releaseCardCreate: (() => void) | undefined;
  const cardCreateGate = new Promise<void>((resolve) => {
    releaseCardCreate = resolve;
  });
  let submittedCard: Record<string, any> | undefined;
  let observeCardCreate: (() => void) | undefined;
  const cardCreateObserved = new Promise<void>((resolve) => {
    observeCardCreate = resolve;
  });
  await page.route("**/_arkret/self/events", async (route) => {
    const request = route.request();
    if (request.method() !== "POST") {
      await route.fallback();
      return;
    }
    const event = submittedEvent(request.postDataJSON());
    if (
      event?.kind === "ak.strand.create" &&
      event?.payload?.object?.metadata?.title === "Route-safe card"
    ) {
      submittedCard = event;
      observeCardCreate?.();
      await cardCreateGate;
    }
    await route.fallback();
  });

  await page.getByTestId("add-card-button").first().click();
  await page.getByTestId("new-card-title-input").fill("Route-safe card");
  await page.getByTestId("save-card-button").click();
  await cardCreateObserved;

  const optimisticCard = page
    .getByTestId("kanban-card")
    .filter({ hasText: "Route-safe card" });
  await expect(optimisticCard).toHaveAttribute("data-card-draft", "true");
  await optimisticCard.click();
  const detail = page.getByTestId("card-detail-modal");
  await expect(detail).toBeVisible();
  await expect(detail.getByTestId("card-discussion-pending-target")).toHaveCount(
    1,
  );

  const eventId = submittedCard?.event_id;
  expect(eventId).toMatch(/^ak:event:/);
  const strandId = eventId.replace(/^ak:event:/, "ak:strand:");
  releaseCardCreate?.();

  await expect(detail.getByTestId("card-fields").locator("dd").first()).toHaveAttribute(
    "title",
    strandId,
  );
  await detail.getByTestId("card-detail-tab-discussion").click();
  await expect(detail.getByTestId("card-discussion-pending-target")).toHaveCount(
    0,
  );
  await expect(detail.getByTestId("chat-panel")).toBeVisible();
});

test("kanban board selector swaps projected board columns", async ({
  page,
}) => {
  await openKanban(page);
  await expect(page.getByTestId("view-renderer-switcher")).toHaveCount(0);
  await expect(page.getByTestId("kanban-board-grid")).toContainText(
    "Legal review for public beta",
  );

  await page.getByTestId("board-space-select-button").click();
  await page.getByRole("option", { name: "Secondary planning board" }).click();

  await expect(page.getByTestId("kanban-column")).toHaveCount(1);
  await expect(page.getByTestId("kanban-board-grid")).toContainText(
    "Secondary board card",
  );
  await expect(page.getByTestId("kanban-board-grid")).not.toContainText(
    "Legal review for public beta",
  );
});

test("kanban card drag submits a strand move", async ({ page }) => {
  await refreshServer(page);
  await gotoAndDismissRecovery(page, `/kanban/${DEMO_REALM}`);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();

  await page
    .getByTestId("kanban-card")
    .first()
    .dragTo(page.getByTestId("kanban-column").nth(1));

  await expect(page.getByTestId("kanban-column").nth(1)).toContainText(
    "Legal review for public beta",
  );
});

test("kanban board routes keep the board Space under its home Realm", async ({
  page,
}) => {
  await refreshServer(page);

  await gotoAndDismissRecovery(
    page,
    `/kanban/${DEMO_REALM}/board/${DEMO_BOARD_SPACE}`,
  );
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("selected-realm-id")).toHaveText(DEMO_REALM);
  expect(new URL(page.url()).pathname).toBe(
    `/kanban/${DEMO_REALM}/board/${DEMO_BOARD_SPACE}`,
  );
});

test("card detail embeds discussion directly without discussion chrome", async ({
  page,
}) => {
  await refreshServer(page);
  await openDiscussion(page);
  await expect(page.getByTestId("discussion-main-panel")).toBeVisible();
  await expect(page.getByTestId("discussion-main-panel")).toContainText(
    "No messages yet",
  );
  await expect(page.getByTestId("discussion-list-panel")).toHaveCount(0);
  await expect(page.getByTestId("discussion-list-rail")).toHaveCount(0);
  await expect(page.getByTestId("open-channel-dialog")).toHaveCount(0);
  await expect(page.getByTestId("discussion-users-toggle")).toHaveCount(0);
  await expect(page.getByTestId("discussion-settings-toggle")).toHaveCount(0);
  await expect(page.getByTestId("channel-create-modal")).toHaveCount(0);
  await expect(page.getByTestId("new-channel-members")).toHaveCount(0);
  await expect(page.getByTestId("open-primary-discussion")).toHaveCount(0);
  await expect(page.getByTestId("card-strand-tracks")).toHaveCount(0);
  await expect(page.getByTestId("discussion-main-panel")).not.toContainText(
    "Launch board discussion",
  );
  await expect(page.getByTestId("discussion-main-panel")).not.toContainText(
    "Primary discussion",
  );

  let chatSubmitPosts = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith("/_arkret/self/events")
    ) {
      chatSubmitPosts += 1;
    }
  });
  await page
    .getByTestId("chat-input")
    .fill("hello @did:web:bob.example about #ak:task:123");
  await expect(page.getByRole("alert")).toContainText(
    "waiting for the verified content scheme",
  );
  await expect(page.getByTestId("send-chat-button")).toBeDisabled();
  expect(chatSubmitPosts).toBe(0);
  await expect(page.getByTestId("chat-input")).toHaveValue(
    "hello @did:web:bob.example about #ak:task:123",
  );
  await expect(page.getByTestId("chat-message")).toHaveCount(0);
  await page.getByTestId("card-detail-tab-synthesis").click();
  await expect(page.getByTestId("card-synthesis-panel")).toBeVisible();
  await expect(page.getByTestId("card-discussion-panel")).toHaveCount(1);
  await expect(page.getByTestId("card-discussion-panel")).toBeHidden();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-input")).toHaveValue(
    "hello @did:web:bob.example about #ak:task:123",
  );
});
