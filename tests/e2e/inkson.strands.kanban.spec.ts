import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  DEMO_BOARD_SPACE,
  dismissBlockingRecoveryModal,
  dismissRealmKeyMissingModal,
  refreshServer,
  gotoAndDismissRecovery,
  openDiscussion,
  openKanban,
} from "./strandsHarness";

registerStrandsBeforeEach();

function submittedEvent(body: any) {
  const entry = Array.isArray(body.events)
    ? body.events[0]
    : (body.event ?? body);
  return entry?.event ?? entry;
}

test("kanban card detail embeds discussion without boundary copy", async ({
  page,
}) => {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await expect(page.getByTestId("card-detail-overlay")).toBeVisible();
  await expect(detailPopup).toHaveAttribute("role", "dialog");
  await expect(detailPopup).toContainText("Discussion");
  await expect(detailPopup.getByTestId("card-synthesis-panel")).toBeVisible();
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
  await expect(detailPopup.getByTestId("card-synthesis-panel")).toBeVisible();
  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  const memberGroup = detailPopup.getByTestId("card-detail-member-group");
  const selfMention = memberGroup.getByRole("button", {
    name: "Mention alice:local.host",
  });
  const agentRow = memberGroup.getByTestId("card-detail-agent-row");
  const agentMention = agentRow.getByTestId(
    "card-detail-member-mention-button",
  );
  await expect(selfMention).toContainText("alice:local.host");
  await expect(selfMention).not.toContainText("did:web:alice.example");
  await expect(
    agentRow.getByTestId("card-detail-member-agent-badge"),
  ).toHaveText("Agent");
  await expect(
    agentRow.getByTestId("card-detail-member-agent-selector"),
  ).toHaveText("@me/assistant");
  const selfMentionBox = await selfMention.boundingBox();
  const agentMentionBox = await agentMention.boundingBox();
  if (!selfMentionBox || !agentMentionBox) {
    throw new Error("member hierarchy rows were not measurable");
  }
  expect(agentMentionBox.x).toBeGreaterThan(selfMentionBox.x);

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

test("owned agent sidecar labels private messages in discussion", async ({
  page,
}) => {
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
  await expect(page).toHaveURL(/\/kanban\/.*\/task\/ak:strand:/);
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();
  await expect(page.getByTestId("chat-input")).toHaveValue(
    "@me/assistant hello",
  );

  await page.getByTestId("send-chat-button").click();
  const privateMessage = page.getByTestId("chat-message").last();
  await expect(privateMessage).toContainText("@me/assistant hello");
  const privacyBadge = privateMessage.getByTestId(
    "message-private-sidecar-badge",
  );
  await expect(privacyBadge).toBeVisible();
  await expect(privacyBadge).toContainText("Private sidecar");
  await expect(privacyBadge).toHaveAttribute(
    "data-visibility",
    "private-sidecar",
  );

  let sharedPublishPosts = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().endsWith("/_arkret/self/events")
    ) {
      sharedPublishPosts += 1;
    }
  });
  const publishOpen = page.getByTestId("sidecar-publish-open");
  const publishGeometry = await publishOpen.evaluate((button) => {
    const describe = (element: Element | null) => {
      if (!(element instanceof HTMLElement)) return null;
      const bounds = element.getBoundingClientRect();
      const style = getComputedStyle(element);
      return {
        tag: element.tagName,
        className: element.className,
        testId: element.dataset.testid ?? null,
        bounds: {
          left: bounds.left,
          top: bounds.top,
          right: bounds.right,
          bottom: bounds.bottom,
        },
        clientHeight: element.clientHeight,
        scrollHeight: element.scrollHeight,
        display: style.display,
        gridTemplateRows: style.gridTemplateRows,
        position: style.position,
      };
    };
    const rect = button.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;
    const hit = document.elementFromPoint(centerX, centerY);
    return {
      button: {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
      },
      viewport: { width: innerWidth, height: innerHeight },
      hit: hit instanceof HTMLElement ? hit.outerHTML.slice(0, 240) : null,
      containsHit: hit ? button.contains(hit) : false,
      cardMain: describe(button.closest(".card-detail-main")),
      tabsSection: describe(button.closest(".card-detail-tabs-section")),
      discussionPanel: describe(
        button.closest('[data-testid="card-discussion-panel"]'),
      ),
      discussionShell: describe(button.closest(".discussion-shell")),
      mainPanel: describe(button.closest(".discussion-main-panel")),
      composer: describe(
        button
          .closest(".discussion-shell")
          ?.querySelector('[data-testid="chat-composer"]') ?? null,
      ),
      contextStrip: describe(
        document.querySelector('[data-testid="sidecar-context-strip"]'),
      ),
    };
  });
  if (!publishGeometry.containsHit) {
    throw new Error(
      `publish button is covered: ${JSON.stringify(publishGeometry)}`,
    );
  }
  await publishOpen.click();
  const publishModal = page.getByTestId("sidecar-publish-modal");
  await expect(publishModal).toBeVisible();
  await expect(publishModal.getByTestId("sidecar-publish-body")).toHaveValue(
    "@me/assistant hello",
  );
  await publishModal.getByTestId("sidecar-publish-cancel").click();
  await expect(publishModal).toHaveCount(0);
  await page.waitForTimeout(300);
  expect(sharedPublishPosts).toBe(0);

  await page.getByTestId("sidecar-publish-open").click();
  const publishRequestPromise = page
    .waitForRequest(
      (request) =>
        request.method() === "POST" &&
        request.url().endsWith("/_arkret/self/events"),
      { timeout: 20_000 },
    )
    .catch(() => null);
  await page.getByTestId("sidecar-publish-confirm").click();
  const publishRequest = await publishRequestPromise;
  if (publishRequest) {
    const publishBody = publishRequest.postDataJSON();
    const publishedEvent = submittedEvent(publishBody);
    expect(publishedEvent.kind).toBe("ak.message.create");
    expect(publishedEvent.payload.strand_id).toMatch(/^ak:strand:/);
    expect(publishedEvent.payload.content.body).toBe("@me/assistant hello");
    expect(JSON.stringify(publishedEvent)).not.toMatch(
      /sidecar_id|exchange_id|private_history|context_locator/,
    );
    await expect(page.getByTestId("chat-status")).toContainText(
      "Published to shared Strand",
    );
  } else {
    await expect(page.getByTestId("chat-status")).toContainText(
      "Shared publish queued for retry",
    );
    const durableOutbound = await page.evaluate(() =>
      Object.keys(localStorage)
        .filter((key) => key.startsWith("inkson.outbound.v1::"))
        .map((key) => localStorage.getItem(key) ?? "")
        .join("\n"),
    );
    expect(durableOutbound).toContain('"kind":"ak.message.create"');
    expect(durableOutbound).toContain("@me/assistant hello");
    expect(durableOutbound).toContain(DEMO_REALM);
    expect(durableOutbound).not.toMatch(
      /sidecar_id|exchange_id|private_history|context_locator/,
    );
  }
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
  await detailPopup
    .getByTestId("chat-input")
    .fill("@me/assistant keep this private draft");

  const ensureResponse = page.waitForResponse((response) =>
    response.url().includes("/_arkret/self/agent-sidecars:ensure"),
  );
  await detailPopup.getByTestId("send-chat-button").click();
  await expect((await ensureResponse).ok()).toBeTruthy();
  await expect(detailPopup).toBeVisible();
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();

  await detailPopup.getByTestId("card-detail-tab-synthesis").click();
  await expect(
    detailPopup.getByTestId("sidecar-shared-synthesis-base"),
  ).toBeVisible();
  await expect(
    detailPopup.getByTestId("sidecar-private-synthesis-label"),
  ).toBeVisible();

  await page.getByTestId("sidecar-mode-sidecar-only").click();
  await expect(page.getByTestId("sidecar-mode-sidecar-only")).toHaveClass(
    /active/,
  );
  await expect(
    detailPopup.getByTestId("sidecar-shared-synthesis-base"),
  ).toHaveCount(0);
  await expect(
    detailPopup.getByTestId("sidecar-private-synthesis-label"),
  ).toBeVisible();

  await detailPopup.getByTestId("card-detail-tab-synthesis").click();
  await expect(page.getByTestId("sidecar-mode-sidecar-only")).toHaveClass(
    /active/,
  );
  await expect(
    detailPopup.getByTestId("sidecar-shared-synthesis-base"),
  ).toHaveCount(0);
  await expect(
    detailPopup.getByTestId("sidecar-private-synthesis-label"),
  ).toBeVisible();

  await page.getByTestId("sidecar-mode-context-merged").click();
  await expect(page.getByTestId("sidecar-mode-context-merged")).toHaveClass(
    /active/,
  );
  await expect(
    detailPopup.getByTestId("sidecar-shared-synthesis-base"),
  ).toBeVisible();

  await detailPopup.getByTestId("card-detail-tab-discussion").click();
  await expect(detailPopup.getByTestId("chat-input")).toHaveValue(
    "@me/assistant keep this private draft",
  );

  await page.setViewportSize({ width: 390, height: 844 });
  await page
    .getByTestId("sidecar-addressed-now")
    .locator("strong")
    .evaluate((element) => {
      element.textContent =
        "assistant-with-an-intentionally-very-long-private-agent-handle-that-must-wrap";
    });
  const layout = await page
    .getByTestId("sidecar-context-strip")
    .evaluate((strip) => {
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
  await page
    .getByTestId("kanban-card")
    .filter({ hasText: longCardTitle })
    .click();
  const detailPopup = page.getByTestId("card-detail-modal");
  await expect(detailPopup).toContainText(longCardTitle);
  await detailPopup.getByTestId("card-detail-tab-discussion").click();

  const input = detailPopup.getByTestId("chat-input");
  await expect(detailPopup.getByTestId("chat-message")).toHaveCount(18);

  await detailPopup.getByTestId("card-detail-sidebar-tab-members").click();
  await detailPopup
    .locator(
      '[data-testid="card-detail-agent-row"][data-agent-slug="assistant"]',
    )
    .getByTestId("card-detail-member-mention-button")
    .click();
  await detailPopup
    .locator(
      `[data-testid="card-detail-agent-row"][data-agent-slug="${longAgentSlug}"]`,
    )
    .getByTestId("card-detail-member-mention-button")
    .click();
  const privateDraft =
    "@me/assistant @me/research-assistant-with-an-intentionally-long-private-handle preserve this private draft";
  await input.fill(privateDraft);

  const ensureResponse = page.waitForResponse((response) =>
    response.url().endsWith("/_arkret/self/agent-sidecars:ensure"),
  );
  await detailPopup.getByTestId("send-chat-button").click();
  const ensured = await ensureResponse;
  await expect(ensured.ok()).toBeTruthy();
  expect(ensured.request().postDataJSON().addressed_agent_ids).toEqual([
    "did:web:agents.example:assistant",
    "did:web:agents.example:research",
  ]);
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();
  await expect(
    page.getByTestId("sidecar-addressed-now").locator("strong"),
  ).toHaveText("assistant + 1 agents");
  await expect(input).toHaveValue(privateDraft);

  await page.setViewportSize({ width: 390, height: 844 });
  const stripMetrics = await page
    .getByTestId("sidecar-context-strip")
    .evaluate((strip) => ({
      clientWidth: strip.clientWidth,
      scrollWidth: strip.scrollWidth,
    }));
  expect(stripMetrics.scrollWidth).toBeLessThanOrEqual(
    stripMetrics.clientWidth + 1,
  );

  const feed = detailPopup.getByTestId("message-list");
  const messageIds = await detailPopup
    .getByTestId("chat-message")
    .evaluateAll((elements) => elements.map((element) => element.id));
  const initialScroll = await feed.evaluate((element) => {
    const target = Math.max(
      1,
      Math.floor((element.scrollHeight - element.clientHeight) / 2),
    );
    element.scrollTop = target;
    return {
      scrollTop: element.scrollTop,
      scrollHeight: element.scrollHeight,
      clientHeight: element.clientHeight,
    };
  });
  expect(initialScroll.scrollHeight).toBeGreaterThan(
    initialScroll.clientHeight,
  );
  expect(initialScroll.scrollTop).toBeGreaterThan(0);

  const sourceHistoryReplayRequests: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    const requestedRealms = (url.searchParams.get("realms") ?? "").split(",");
    if (
      request.method() === "GET" &&
      url.pathname === "/_arkret/self/events" &&
      requestedRealms.includes(DEMO_REALM)
    ) {
      sourceHistoryReplayRequests.push(url.toString());
    }
  });
  await page.waitForTimeout(300);

  await page.getByTestId("sidecar-mode-sidecar-only").click();
  await detailPopup.getByTestId("card-detail-tab-synthesis").click();
  await page.getByTestId("sidecar-mode-context-merged").click();
  await detailPopup.getByTestId("card-detail-tab-discussion").click();
  await page.getByTestId("sidecar-mode-sidecar-only").click();
  await page.getByTestId("sidecar-mode-context-merged").click();

  await expect(input).toHaveValue(privateDraft);
  expect(
    await detailPopup
      .getByTestId("chat-message")
      .evaluateAll((elements) => elements.map((element) => element.id)),
  ).toEqual(messageIds);
  await expect
    .poll(() => feed.evaluate((element) => element.scrollTop))
    .toBe(initialScroll.scrollTop);
  expect(sourceHistoryReplayRequests).toEqual([]);
});

test("pending sidecar reconciliation blocks contextual send without claiming readiness", async ({
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
  await detailPopup
    .getByTestId("chat-input")
    .fill("@me/assistant inspect privately");

  const ensureResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/_arkret/self/agent-sidecars:ensure"),
    { timeout: 20_000 },
  );
  await detailPopup.getByTestId("send-chat-button").click();
  await expect((await ensureResponse).ok()).toBeTruthy();

  await expect(page).toHaveURL(/\/kanban\/.*\/task\/ak:strand:/);
  await expect(page.getByTestId("sidecar-context-strip")).toBeVisible();
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

  await gotoAndDismissRecovery(page, `/kanban/${DEMO_REALM}`);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
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

  await page.getByTestId("new-board-toggle").click();
  await page.getByTestId("new-board-title-input").fill("Design board");
  await page.getByTestId("create-board-space-button").click();
  await expect(page.getByTestId("add-column-button")).toBeVisible();
  await expect(page.getByTestId("board-space-selector")).toContainText(
    "Design board",
  );
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    "No lists yet",
  );

  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissRealmKeyMissingModal(page);
  await dismissBlockingRecoveryModal(page);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("add-column-button")).toBeVisible();
  await expect(page.getByTestId("board-space-selector")).toContainText(
    "Design board",
  );
  await expect(page.getByTestId("kanban-empty-board")).toContainText(
    "No lists yet",
  );
});

test("kanban queues canonical event submissions and quarantines manual replay", async ({
  page,
}) => {
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
  await page.getByTestId("board-queue-toggle").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText(
    "ak.strand.create",
  );
  await expect(page.getByTestId("board-event-record").last()).toContainText(
    "sha256:",
  );
  await expect(page.getByTestId("board-event-record").last()).toContainText(
    '"strand_kind":"card"',
  );
  await expect(page.getByTestId("board-conflict-alert")).toHaveCount(0);

  await page.getByTestId("replay-board-queue").click();
  await expect(page.getByTestId("board-status")).toContainText(
    "no queued write to quarantine",
  );

  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissRealmKeyMissingModal(page);
  await dismissBlockingRecoveryModal(page);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await expect(page.getByTestId("kanban-board-grid")).toContainText(
    "Move-backed card",
  );
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

test("kanban card drag queues a strand move", async ({ page }) => {
  await refreshServer(page);
  await gotoAndDismissRecovery(page, `/kanban/${DEMO_REALM}`);
  await expect(page.getByTestId("kanban-panel")).toBeVisible();

  await page
    .getByTestId("kanban-card")
    .first()
    .dragTo(page.getByTestId("kanban-column").nth(1));

  await page.getByTestId("board-queue-toggle").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText(
    "ak.strand.move",
  );
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
  await page.getByTestId("send-chat-button").click();
  await expect(page.getByTestId("chat-status")).toContainText(
    "MLS state is not ready",
  );
  expect(chatSubmitPosts).toBe(0);
  await expect(page.getByTestId("chat-input")).toHaveValue(
    "hello @did:web:bob.example about #ak:task:123",
  );
  await expect(page.getByTestId("chat-message").last()).toContainText(
    "hello @did:web:bob.example about #ak:task:123",
  );
  await page.getByTestId("card-detail-tab-synthesis").click();
  await expect(page.getByTestId("card-synthesis-panel")).toBeVisible();
  await expect(page.getByTestId("card-discussion-panel")).toHaveCount(1);
  await expect(page.getByTestId("card-discussion-panel")).toBeHidden();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-message").last()).toContainText(
    "hello @did:web:bob.example about #ak:task:123",
  );
});
