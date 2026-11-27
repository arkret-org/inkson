import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";
import {
  CURRENT_STATION_ID, CURRENT_ACCOUNT_ID, CURRENT_ACCOUNT_ACTOR_ID,
  CURRENT_ASSISTANT_ACCOUNT_ID, BOB_ACCOUNT_ID, BOB_HELPER_ACCOUNT_ID,
  DIRECT_BOB_HELPER_REALM, DIRECT_BOB_HELPER_STRAND, DEMO_REALM, INVITED_REALM,
  DEMO_PARENT_MEMBERSHIP_REVISION, validateMockSchema,
} from "./mockArkretApi";
import {
  registerStrandsBeforeEach,
  latestByClass,
  svgDrawingMarkup,
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,
  refreshServer,
  openSettings,
  writeLocalConfig,
  submittedEvent,
  assertRealmTreeSeeded,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("Realm row menu lists the available Realm actions", async ({ page }) => {
  // Navigation needs the bounded list, not a forged signed detail snapshot.
  const frames = [
    { kind: "delta", cursor: "ak:cursor:realm-menu", realm_list: {
      snapshot_cursor: "ak:cursor:realm-list", snapshot_revision: 1,
      items: [{ realm_id: DEMO_REALM, revision: 1, activity_position: 1, membership: "join", title: "Arkret Demo Realm" }],
    } },
    { kind: "catchup_complete", cursor: "ak:cursor:realm-menu" },
  ];
  for (const frame of frames) validateMockSchema("schemas/account-subscribe-frame.schema.json", frame);
  await page.route("**/_arkret/self/account/subscribe?**", async route => {
    await route.fulfill({ status: 200, contentType: "application/x-ndjson", body: frames.map(frame => JSON.stringify(frame)).join("\n") + "\n" });
  });
  await page.reload();
  await assertRealmTreeSeeded(page);
  const row = page.locator(".shell.app").last().locator(".sidebar-row").filter({ hasText: "Arkret Demo Realm" }).first();
  const trigger = row.getByRole("button", { name: "Realm actions", exact: true });
  const panel = page.locator(".realm-row-actions-panel:visible");
  await row.locator(".realm-tree-item").hover();
  await trigger.click();
  await expect(panel).toBeVisible();
  await expect(page.getByRole("tooltip")).toHaveCount(0);
  for (const name of ["Pin Realm", "New Board", "New Chat"]) {
    const item = panel.getByRole("button", { name, exact: true });
    await expect(item).toBeVisible();
    const lines = await item.evaluate(button => {
      const text = document.createTreeWalker(button, NodeFilter.SHOW_TEXT);
      const label = document.createRange();
      const baselines = new Set<number>();
      while (text.nextNode()) {
        label.selectNodeContents(text.currentNode);
        for (const rect of label.getClientRects()) {
          if (rect.width > 0) baselines.add(Math.round(rect.bottom));
        }
      }
      return baselines.size;
    });
    expect(lines, name).toBe(1);
  }
  const items = panel.locator(".sidebar-row-menu-item");
  await expect(items).toHaveText([
    "Pin Realm", "New Board", "New Chat", "Add Member", "Settings", "Leave",
  ]);
  for (const item of await items.all()) await expect(item.locator(".ui-icon")).toHaveCount(1);

  await page.keyboard.press("Escape");
  await expect(panel).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("Contacts list selects human and agent details before opening their direct conversations", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.locator(".rail-contacts").click();
  const list = page.locator(".contact-list-items");
  await expect(list).toContainText("Alice Assistant");
  await expect(list).toContainText("Bob Helper");
  const bobPrincipalToken = BOB_ACCOUNT_ID.principal_id.split(":").at(-1)!;
  const bobDisplayLabel = `ak:did_core:webvh:${bobPrincipalToken.slice(0, 8)}...${bobPrincipalToken.slice(-6)}`;
  await list.locator(".contact-list-item").filter({ hasText: bobDisplayLabel }).click();
  const detail = page.locator(".contacts-detail-pane .contact-row");
  await expect(detail).toHaveAccessibleDescription(`Principal: ${BOB_ACCOUNT_ID.principal_id} · Station: ${BOB_ACCOUNT_ID.station_id}`);
  const humanRequest = page.waitForRequest(request => request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/direct-conversations/resolve");
  await detail.locator(".contact-message").click();
  expect((await humanRequest).postDataJSON().peer).toEqual({ kind: "human", account_id: BOB_ACCOUNT_ID });
  await expect(page).toHaveURL(/\/direct\//);
  await page.locator(".rail-brand").click();
  await expect(page.locator(".dashboard-panel")).toBeVisible();
  await page.locator(".rail-contacts").click();
  await list.locator(".contact-agent-list-item").filter({ hasText: "Bob Helper" }).click();
  await expect(page.locator(".contact-agent-detail")).toContainText("Bob Helper");
  const agentRequest = page.waitForRequest(request => request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/direct-conversations/resolve");
  await page.locator(".contact-agent-message").click();
  expect((await agentRequest).postDataJSON().peer).toEqual({
    kind: "agent", actor_id: { kind: "account", account_id: BOB_HELPER_ACCOUNT_ID }, controller_account_id: BOB_ACCOUNT_ID,
  });
  await expect(page).toHaveURL(`/direct/${DIRECT_BOB_HELPER_REALM}/${DIRECT_BOB_HELPER_STRAND}`);
});

for (const width of [1280, 390]) {
  test(`Private chats opens the existing conversation workspace at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 844 });
    await dismissBlockingRecoveryModal(page);
    const rail = page.locator(".navigation-rail");
    const entry = rail.getByRole("link", { name: "Private chats", exact: true });
    await expect(rail.locator(".rail-realms + .rail-private-chats")).toHaveCount(1);
    await entry.click();
    await expect(entry).toHaveAttribute("aria-current", "page");
    const rows = page.locator(".private-chat-list");
    await expect(rows).toBeVisible();
    await expect(rows).toContainText("Bob Helper");
    await expect(rows).toContainText("Alice Assistant");
    if (width < 861) await expect(page).toHaveURL(/\/direct$/);
    await rows.getByRole("button", { name: /Bob Helper/ }).click();
    await expect(page).toHaveURL(`/direct/${DIRECT_BOB_HELPER_REALM}/${DIRECT_BOB_HELPER_STRAND}`);
    await expect(page.locator(".chat-panel")).toBeVisible();
    await expect(page.locator(".direct-structure")).toBeVisible();
    if (width > 860) {
      await expect(rows.locator(".is-active")).toContainText("Bob Helper");
      await page.getByRole("link", { name: "New private chat", exact: true }).click();
      await expect(page).toHaveURL(/\/direct\/new$/);
      await expect(page.locator(".contact-sidebar-self-row")).toBeVisible();
    }
  });
}

test("Private chats keeps an empty inbox on the list until a recipient is chosen", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.route("**/_arkret/self/contacts", route => route.fulfill({
    json: { contacts: [], has_more: false },
  }));
  await page.route("**/_arkret/self/direct-conversations/resolve", route => route.fulfill({
    json: { state: "awaiting_founder" },
  }));
  const lookup = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/_arkret/self/direct-conversations/resolve"
  );
  await page.locator(".rail-private-chats").click();
  await lookup;
  const list = page.locator(".private-chat-list");
  await expect(list).toHaveText("No private chats yet.");
  await expect(page).toHaveURL(/\/direct$/);
  await page.getByRole("link", { name: "New private chat", exact: true }).click();
  await expect(page.locator(".contact-sidebar-self-row")).toBeVisible();
});

test("contact badges leave room for the direct conversation title", async ({ page }) => {
  await gotoAndDismissRecovery(page, `/direct/${DIRECT_BOB_HELPER_REALM}/${DIRECT_BOB_HELPER_STRAND}`);
  const row = page.locator(".private-chat-list .direct-conversation-row.is-active");
  await expect(row).toBeVisible();
  await expect.poll(() => row.evaluate(el => {
    const title = el.querySelector(".grow")!.getBoundingClientRect();
    return title.width > 36 && el.scrollWidth <= el.clientWidth + 1;
  })).toBe(true);
});

test("owned agent opens an independent two-principal Direct Conversation Realm", async ({
  page,
}) => {
  const shell = page.locator(".shell.app").last();
  await dismissBlockingRecoveryModal(page);
  await shell.locator(".rail-contacts").click();
  let directRequestBody: Record<string, unknown> | null = null;
  let sidecarEnsureCount = 0;
  await page.route(
    "**/_arkret/self/direct-conversations/resolve",
    async (route) => {
      directRequestBody = await route.request().postDataJSON();
      await route.fallback();
    },
  );
  await page.route("**/_arkret/self/agent-sidecars:ensure", async (route) => {
    sidecarEnsureCount += 1;
    await route.fallback();
  });
  const directResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/_arkret/self/direct-conversations/resolve"),
    { timeout: 20_000 },
  );
  const ownedAgentRow = shell.locator(".contact-agent-list-item").filter({ hasText: "Alice Assistant" });
  await ownedAgentRow.click();
  await shell.locator(".contact-agent-message").click();
  await expect((await directResponse).ok()).toBeTruthy();
  expect(directRequestBody).toEqual({
    peer: {
      kind: "agent",
      actor_id: { kind: "account", account_id: CURRENT_ASSISTANT_ACCOUNT_ID },
      controller_account_id: CURRENT_ACCOUNT_ID,
    },
  });
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP\/ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM$/,
  );
  await expect(shell.locator("[class~=\"chat-panel\"]")).toHaveCount(1);
  await expect(shell.locator("[class~=\"sidecar-context-strip\"]")).toHaveCount(0);
  await page.waitForTimeout(250);
  expect(sidecarEnsureCount).toBe(0);
});

for (const kind of ["Board", "Chat"] as const) {
  test(`Realm row menu creates a new ${kind} in the chosen Realm`, async ({ page }) => {
    await assertRealmTreeSeeded(page);
    await dismissBlockingRecoveryModal(page);
    const row = page.locator(".sidebar-row").filter({ hasText: "Launch Realm" }).first();
    const realmPath = await row.locator(".realm-tree-item").getAttribute("href");
    const realm = realmPath!.split("/").pop()!;
    const open = async () => {
      await row.getByRole("button", { name: "Realm actions", exact: true }).click();
      const menu = page.locator(".realm-row-actions-panel:visible");
      await expect(menu.getByRole("button", { name: "New Space", exact: true })).toHaveCount(0);
      await menu.getByRole("button", { name: `New ${kind}`, exact: true }).click();
    };
    await open();
    const board = kind === "Board";
    const dialog = page.getByRole("dialog", { name: `New ${kind}`, exact: true });
    await expect(dialog).toBeVisible();
    expect(new URL(page.url()).pathname).toBe(`/${board ? "kanban" : "chat"}/${realm}`);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await open();
    await expect(dialog).toBeVisible();
    const title = `Menu ${kind}`;
    await dialog.getByRole("textbox", { name: board ? "Board title" : "Title", exact: true }).fill(title);
    const submitted = page.waitForRequest(request => request.method() === "POST"
      && new URL(request.url()).pathname === "/_arkret/self/events"
      && submittedEvent(request.postDataJSON())?.kind === (board ? "ak.space.create" : "ak.strand.create"));
    await dialog.locator(board ? ".create-board-space-button" : ".create-channel-button").click();
    const event = submittedEvent((await submitted).postDataJSON());
    expect(event.realm_id).toBe(realm);
    if (board) {
      expect(event.payload.object.kind).toBe("board");
    } else {
      expect(event.payload.object.tracks.discussion.is_primary).toBe(true);
      expect(event.payload.object.topic).toBeUndefined();
    }
    await expect(dialog).toBeHidden();
    if (board) {
      await expect(page.locator(".board-space-selector")).toContainText(title);
    } else {
      await expect(page.locator(".chat-panel")).toContainText(title);
    }
  });
}

test("icon rail retains its width and omits the server picker", async ({ page }) => {
  const rail = page.locator(".navigation-rail");
  const width = (await rail.boundingBox())!.width;
  await expect(page.locator(".server-switch-button, .sidebar-resize-handle, .sidebar-collapse-toggle")).toHaveCount(0);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(rail).toBeVisible();
  expect((await rail.boundingBox())!.width).toBe(width);
});

test("topbar breadcrumbs avoid duplicated route and server context", async ({
  page,
}) => {
  await openSettings(page);
  await expect(page.locator(".topbar-context")).toContainText("Settings");
  await expect(page.locator(".topbar-context")).not.toContainText(
    "Settings / Settings",
  );
  await expect(page.locator(".topbar-context")).not.toContainText(
    "Station https://",
  );
});

test("dashboard summarizes unread notifications from sync projection", async ({
  page,
}) => {
  await expect(page.locator("[class~=\"dashboard-unread-notifications\"].val")).toHaveText(
    "2",
  );
  const cursorIndicator = page.locator("[class~=\"sync-cursor\"]");
  await expect(cursorIndicator).toHaveText(/^cursor \S+$/);
  const savedCursor = (await cursorIndicator.textContent() ?? "").slice("cursor ".length);
  const refreshDescribe = page.waitForRequest(request =>
    request.method() === "GET" &&
    new URL(request.url()).pathname === "/_arkret/describe"
  );
  // Inspect the first subscription after this refresh's describe, including a
  // missing after; filtering by the expected cursor would hide a fresh baseline.
  const resumedSubscription = refreshDescribe.then(() =>
    page.waitForRequest(request =>
      request.method() === "GET" &&
      new URL(request.url()).pathname === "/_arkret/self/account/subscribe"
    )
  );
  await refreshServer(page);
  const request = await resumedSubscription;
  expect(new URL(request.url()).searchParams.get("after")).toBe(savedCursor);

  await expect(page.locator("[class~=\"dashboard-unread-notifications\"].val")).toHaveText(
    "2",
  );
  await expect(page.locator("[class~=\"pinned-notifications\"]")).toContainText(
    "New message",
  );
  await expect(page.locator("[class~=\"pinned-notifications\"]")).toContainText(
    "Realm invite",
  );
});

test("server identity lives on the account page", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.locator(".navigation-rail .rail-account").click();
  await expect(page.locator(".account-page__server")).toHaveText("https://local.host");
  await expect(page.locator(".server-switch-menu, .server-switch-button")).toHaveCount(0);
});
