import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  refreshServer,
  openSettings,
  dismissBlockingRecoveryModal,
} from "./strandsHarness";
import { BOB_ACCOUNT_ID, CURRENT_ACCOUNT_ACTOR_ID, CURRENT_ACCOUNT_ID, DEMO_INVITE_ID, INVITED_REALM, PRINCIPAL_CONTROL_REALM } from "./mockArkretApi";
import { openFixtureClientUiValue } from "./clientUiFixture";

registerStrandsBeforeEach();

async function openInviteNotification(page: import("@playwright/test").Page) {
  await dismissBlockingRecoveryModal(page);
  await page.locator(".topbar .topbar-notifications-link").click();
  await expect(page.locator(".notifications-drawer-layer")).toBeVisible();
  const item = page
    .locator("[class~=\"notification-item\"]")
    .filter({ has: page.locator("[class~=\"invite-preview\"]") });
  await expect(item).toBeVisible();
  return item;
}

test("invite preview disclosed stays loading then visible and only Accept joins", async ({
  page,
}) => {
  const writes: Array<{ path: string; body: string }> = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      path === "/_arkret/self/realm-joins/prepare" ||
      path === "/_arkret/self/events"
    ) {
      writes.push({ path, body: request.postData() ?? "" });
    }
  });

  const item = await openInviteNotification(page);
  await expect(item.locator("[class~=\"invite-preview-loading\"]")).toBeVisible();
  await expect(item.locator("[class~=\"invite-preview-disclosed\"]")).toBeVisible();
  await expect(item.locator("[class~=\"invite-preview-name\"]")).toHaveText(
    "Preview-only Realm",
  );
  await expect(
    page.locator(".realm-tree-list .sidebar-row-main").filter({
      hasText: "Preview-only Realm",
    }),
  ).toHaveCount(0);
  expect(writes).toEqual([]);

  const joinedSignerKeys = page.waitForResponse(response =>
    response.request().method() === "POST" && new URL(response.url()).pathname === "/_arkret/self/signer-keys/query",
  );
  await item.locator("[class~=\"notification-action\"]").click();
  await expect
    .poll(() =>
      writes.some((request) =>
        request.path.endsWith("/realm-joins/prepare"),
      ),
    )
    .toBe(true);
  await expect
    .poll(() =>
      writes.some(
        (request) =>
          request.path.endsWith("/events") &&
          request.body.includes("ak.invite.accept"),
      ),
    )
    .toBe(true);
  await expect(page.locator("[class~=\"notifications-status\"]")).toContainText(
    "Joined Realm",
  );
  const request = writes.find(request => request.path.endsWith("/events")
    && request.body.includes("ak.invite.accept"));
  expect(request).toBeDefined();
  const submission = JSON.parse(request!.body);
  const event = submission.event ?? submission;
  expect(event.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
  expect(event.realm_id).toBe(INVITED_REALM);
  expect(event.payload).toEqual({ invite_id: DEMO_INVITE_ID,
    previous_state: "pending", invitee_account_id: CURRENT_ACCOUNT_ID });

  const signerResponse = await joinedSignerKeys;
  expect(signerResponse.status()).toBe(200);
  const signerRequest = signerResponse.request().postDataJSON();
  expect(signerRequest.realm_id).toBe(INVITED_REALM);
  expect(signerRequest.recipient_account_id).toEqual(CURRENT_ACCOUNT_ID);
  const sourceHeaders = signerResponse.request().headers();
  for (const recipient of [
    BOB_ACCOUNT_ID,
    { ...CURRENT_ACCOUNT_ID, station_id: "ak:did_core:web:other.example" },
    { ...CURRENT_ACCOUNT_ID, principal_id: "ak:did_core:web:mallory.example" },
  ]) {
    const rejected = await page.evaluate(async ({ url, headers, body }) => {
      const response = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
      return { status: response.status, media: response.headers.get("content-type"), body: await response.json() };
    }, {
      url: signerResponse.url(),
      headers: {
        "content-type": "application/json", "arkret-operation": sourceHeaders["arkret-operation"],
        authorization: sourceHeaders.authorization, ...(sourceHeaders.dpop ? { dpop: sourceHeaders.dpop } : {}),
      },
      body: { ...signerRequest, recipient_account_id: recipient },
    });
    expect(rejected.status).toBe(403);
    expect(rejected.media).toContain("application/problem+json");
    expect(rejected.body).toMatchObject({ status: 403, detail: "Signer key query is not authorized for this recipient" });
    expect(rejected.body).not.toHaveProperty("resolutions");
  }
});

test("invite preview restricted remains preview-only", async ({ page }) => {
  let prepareRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/realm-joins/prepare")) {
      prepareRequests += 1;
    }
  });

  const item = await openInviteNotification(page);
  await expect(item.locator("[class~=\"invite-preview-restricted\"]")).toBeVisible();
  await expect(item.locator("[class~=\"notification-action\"]")).toBeVisible();
  expect(prepareRequests).toBe(0);
  await expect(
    page.locator(".realm-tree-list .sidebar-row-main").filter({
      hasText: "Preview-only Realm",
    }),
  ).toHaveCount(0);
});

test("invite preview retries a transient failure without joining", async ({
  page,
}) => {
  let prepareRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/realm-joins/prepare")) {
      prepareRequests += 1;
    }
  });

  const item = await openInviteNotification(page);
  await expect(item.locator("[class~=\"invite-preview-unavailable\"]")).toBeVisible();
  await item.locator("[class~=\"invite-preview-retry\"]").click();
  await expect(item.locator("[class~=\"invite-preview-disclosed\"]")).toBeVisible();
  expect(prepareRequests).toBe(0);
  await expect(
    page.locator(".realm-tree-list .sidebar-row-main").filter({
      hasText: "Preview-only Realm",
    }),
  ).toHaveCount(0);
});

test("notifications are derived from index projections and respect per-realm mute rules", async ({
  page,
}) => {
  await refreshServer(page);
  const realmUrl = page.url();
  await page.locator(".topbar .topbar-notifications-link").click();

  expect(page.url()).toBe(realmUrl);
  await expect(page.locator(".notifications-drawer-layer")).toBeVisible();
  await expect(page.locator("[class~=\"notifications-panel\"]")).toBeVisible();
  await expect(page.locator("[class~=\"notifications-panel\"]")).toContainText(
    "Alice sent a message in Demo Realm",
  );

  await page
    .locator("[class~=\"notification-item\"]")
    .filter({ hasText: "Alice sent a message in Demo Realm" })
    .locator("[class~=\"mute-realm-button\"]")
    .click();
  await expect(page.locator("[class~=\"notifications-panel\"]")).not.toContainText(
    "Alice sent a message in Demo Realm",
  );
  await page.locator(".notifications-drawer-actions button").click();
  await expect(page.locator(".notifications-drawer-layer")).toBeHidden();

  await openSettings(page);
  await page.locator("[class~=\"settings-nav-item-notifications\"]").click();
  const mutedRealm = page.locator(".settings-muted-realm-row");
  await expect(mutedRealm).toHaveAccessibleDescription(DEMO_REALM);
  await expect(mutedRealm.locator(".settings-realm-override-identity")).toHaveText(DEMO_REALM);
  await page.locator("[class~=\"settings-realm-override-remove\"]").click();
  await expect(page.locator("[class~=\"settings-muted-realm-row\"]")).toHaveCount(0);
});

test("topbar notifications drawer keeps the active realm navigation visible", async ({
  page,
}) => {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("[class~=\"kanban-panel\"]")).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  const realmUrl = page.url();

  await page.locator(".topbar .topbar-notifications-link").click();

  expect(page.url()).toBe(realmUrl);
  await expect(page.locator(".notifications-drawer-layer")).toBeVisible();
  await expect(page.locator("[class~=\"notifications-drawer-scrim\"]")).toHaveCount(0);
  await expect(page.locator(".notifications-drawer-actions a")).toBeVisible();
  await expect(page.locator("[class~=\"notifications-settings-hint\"]")).toHaveCount(0);
  await expect(page.locator("[class~=\"realm-context-bar\"]")).toBeVisible();
  await expect(page.locator("[class~=\"notifications-panel\"]")).toContainText("Latest");
  await expect(page.locator("[class~=\"notifications-panel\"]")).not.toContainText(
    "Notification settings",
  );

  const drawerLayout = await page.evaluate(() => {
    const header = document
      .querySelector(".realm-header")
      ?.getBoundingClientRect();
    const sidebar = document
      .querySelector("[class~=\"sidebar\"]")
      ?.getBoundingClientRect();
    const panel = document
      .querySelector("[class~=\"notifications-drawer-panel\"]")
      ?.getBoundingClientRect();
    if (!header || !sidebar || !panel) {
      return null;
    }
    const sidebarHit = document.elementFromPoint(
      sidebar.left + Math.min(24, sidebar.width / 2),
      sidebar.top + Math.min(24, sidebar.height / 2),
    );
    return {
      headerBottom: header.bottom,
      sidebarRight: sidebar.right,
      panelTop: panel.top,
      panelLeft: panel.left,
      panelRight: panel.right,
      panelBottom: panel.bottom,
      sidebarHitInsideDrawer: Boolean(
        sidebarHit?.closest(".notifications-drawer-layer"),
      ),
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
    };
  });
  expect(drawerLayout).not.toBeNull();
  expect(
    Math.abs(drawerLayout!.panelTop - drawerLayout!.headerBottom),
  ).toBeLessThanOrEqual(1);
  expect(drawerLayout!.panelLeft).toBeGreaterThanOrEqual(
    drawerLayout!.sidebarRight - 1,
  );
  expect(drawerLayout!.sidebarHitInsideDrawer).toBe(false);
  expect(
    Math.abs(drawerLayout!.panelRight - drawerLayout!.viewportWidth),
  ).toBeLessThanOrEqual(1);
  expect(
    Math.abs(drawerLayout!.panelBottom - drawerLayout!.viewportHeight),
  ).toBeLessThanOrEqual(1);

  await page.locator(".notifications-drawer-actions button").click();
  await expect(page.locator(".notifications-drawer-layer")).toBeHidden();
  expect(page.url()).toBe(realmUrl);
});

test("directory search refuses unindexed Realms and exposes only public Realm metadata", async ({
  page,
}) => {
  const writes: string[] = [];
  const directoryRequests: import("@playwright/test").Request[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    const path = url.pathname;
    if (url.hostname === "directory.example" || path.startsWith("/_arkret/find/directory/")) {
      directoryRequests.push(request);
    }
    if (request.method() === "POST" && (
      path === "/_arkret/self/realm-joins/prepare" ||
      path === "/_arkret/self/events" ||
      path === "/_arkret/self/event-batches"
    )) writes.push(path);
  });
  await page.locator(".topbar-command-search > button").click();
  await page.locator(".topbar-command-search-field input").fill("demo");
  await page.locator(".topbar-command-search-field input").press("Enter");
  await expect(page.locator("[class~=\"directory-panel\"]")).toBeVisible();

  await expect(page.locator("[class~=\"directory-address-input\"]")).toHaveValue("");
  await expect(page.locator("[class~=\"directory-search-button\"]")).toBeDisabled();
  expect(directoryRequests).toEqual([]);
  await page.locator("[class~=\"directory-address-input\"]").fill("https://directory.example");
  await page.locator("[class~=\"directory-search-input\"]").fill("demo");
  const response = page.waitForResponse((value) =>
    value.request().method() === "POST" &&
    new URL(value.url()).hostname === "directory.example" &&
    new URL(value.url()).pathname === "/_arkret/find/directory/search-realms",
  );
  await page.locator("[class~=\"directory-search-button\"]").click();
  const result = await response;
  expect(result.status()).toBe(200);
  expect(result.request().postDataJSON()).toEqual({ query: "demo", limit: 20 });
  expect(await result.json()).toMatchObject({ realms: [] });
  await expect(page.locator("[class~=\"directory-realm-result\"]")).toHaveCount(0);
  // discovery-directory.md sections 1 and 9 exclude identity-object searches.
  await expect(page.locator("[class~=\"tab-organizations\"]")).toHaveCount(0);
  await expect(page.locator("[class~=\"tab-actors\"]")).toHaveCount(0);
  await expect(page.locator("[class~=\"org-result\"]")).toHaveCount(0);
  await expect(page.locator("[class~=\"org-search-members\"]")).toHaveCount(0);
  expect(writes).toEqual([]);
  expect(directoryRequests.some((request) => new URL(request.url()).pathname === "/_arkret/find/directory/describe")).toBe(true);
  expect(directoryRequests.some((request) => new URL(request.url()).pathname === "/.well-known/did.json")).toBe(true);
  for (const request of directoryRequests) {
    const url = new URL(request.url());
    expect(url.hostname).toBe("directory.example");
    expect(url.pathname).not.toMatch(/^\/_arkret\/open\/services\//);
    for (const name of ["authorization", "dpop", "cookie", "signature", "signature-input", "source-service-id", "destination-service-id"]) {
      expect(request.headers()[name], `Directory request leaked ${name}`).toBeUndefined();
    }
  }
});

test("command palette closes with Escape and outside click", async ({
  page,
}) => {
  await page.locator(".topbar-command-search > button").click();
  await expect(page.locator("[class~=\"command-palette\"]")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.locator("[class~=\"command-palette\"]")).toBeHidden();
  await expect(page.locator(".topbar-command-search > button")).toBeVisible();

  await page.locator(".topbar-command-search > button").click();
  await expect(page.locator("[class~=\"command-palette\"]")).toBeVisible();
  await page.locator(".topbar-context").click();

  await expect(page.locator("[class~=\"command-palette\"]")).toBeHidden();
  await expect(page.locator(".topbar-command-search > button")).toBeVisible();
});

test("shortcut help opens from the topbar and the ? key", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.getByRole("button", { name: "Keyboard shortcuts", exact: true }).click();
  await expect(page.locator("[class~=\"shortcut-help-card\"]")).toBeVisible();
  await expect(page.locator("[class~=\"shortcut-help-card\"]")).toContainText("Ctrl");
  await expect(page.locator("[class~=\"shortcut-help-card\"]")).toContainText("F");
  await page.keyboard.press("Escape");
  await expect(page.locator("[class~=\"shortcut-help-card\"]")).toHaveCount(0);

  await page.keyboard.press("Shift+/");
  await expect(page.locator("[class~=\"shortcut-help-card\"]")).toBeVisible();
  await page.keyboard.press("Escape");

  await page.keyboard.press("Control+/");
  await expect(page.locator("[class~=\"shortcut-help-card\"]")).toBeVisible();
});

test("global keyboard shortcuts trigger their target surfaces", async ({
  page,
}) => {
  await dismissBlockingRecoveryModal(page);

  await page.keyboard.press("Control+K");
  await expect(page.locator("[class~=\"command-palette\"]")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("[class~=\"command-palette\"]")).toHaveCount(0);

  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(page.locator("[class~=\"global-search-panel\"]")).toBeVisible();
});

test("notification feed controls and local mute feedback follow the active language", async ({
  page,
}) => {
  await openSettings(page);
  await page.locator("[class~=\"settings-nav-item-theme\"]").click();
  const writes: Array<{ path: string; body: any }> = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      path === "/_arkret/self/events" ||
      path.endsWith("/realm-joins/prepare") ||
      (path.startsWith("/_arkret/self/account_data/") && request.method() === "PUT")
    ) {
      writes.push({ path, body: request.postDataJSON() });
    }
  });
  for (const language of ["en", "zh", "en"] as const) {
    const languageChoice = page.getByRole("button", {
      name: language === "zh" ? "中文" : "English", exact: true,
    });
    const changesLocale = !(await languageChoice.evaluate(node => node.classList.contains("primary")));
    const saved = changesLocale ? page.waitForResponse(response =>
      new URL(response.url()).pathname === "/_arkret/self/account_data/ak.client.ui_state"
        && response.request().method() === "PUT", { timeout: 20_000 }) : undefined;
    await languageChoice.click();
    if (saved) expect((await saved).status()).toBe(200);
    await expect(languageChoice).toHaveClass(/\bprimary\b/);
    await page.locator(".topbar .topbar-notifications-link").click();
    const panel = page.locator("[class~=\"notifications-panel\"]");
    await expect(panel).toHaveAttribute(
      "aria-label", language === "zh" ? "通知" : "Notifications",
    );
    await expect(panel.getByRole("tablist")).toHaveAttribute(
      "aria-label", language === "zh" ? "通知分组" : "Notification grouping",
    );
    await expect(panel.locator("[class~=\"mark-all-read-button\"]")).toHaveAccessibleName(
      language === "zh" ? "全部标为已读" : "Mark all read",
    );
    await expect(panel.locator("[class~=\"archive-button\"]").first()).toHaveAccessibleName(
      language === "zh" ? "归档" : "Archive",
    );
    const message = panel.locator("[class~=\"notification-item\"]").filter({
      hasText: "Alice sent a message in Demo Realm",
    });
    await expect(message).toBeVisible();
    await expect(message.locator("[class~=\"mute-realm-button\"]")).toHaveAccessibleName(
      language === "zh" ? "静音此 Realm" : "Mute this realm",
    );
    await page.locator(".notifications-drawer-actions button").click();
  }
  const savedFinalLocale = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/_arkret/self/account_data/ak.client.ui_state"
      && response.request().method() === "PUT", { timeout: 20_000 });
  await page.getByRole("button", { name: "中文", exact: true }).click();
  expect((await savedFinalLocale).status()).toBe(200);
  const localeWriteCount = writes.length;
  await page.locator(".topbar .topbar-notifications-link").click();
  const message = page.locator("[class~=\"notification-item\"]").filter({
    hasText: "Alice sent a message in Demo Realm",
  });
  await message.locator("[class~=\"mute-realm-button\"]").click();
  await expect(message).toHaveCount(0);
  await expect(page.locator("[class~=\"notifications-status\"]")).toContainText("已静音");
  expect(writes.length).toBe(localeWriteCount);
  expect(writes.map(write => write.path)).toEqual(Array(3).fill("/_arkret/self/account_data/ak.client.ui_state"));
  for (const [index, write] of writes.entries()) {
    const event = write.body.set_event.event;
    expect(event.kind).toBe("ak.account_data.set");
    expect(event.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
    expect(event.scope_ref).toEqual({ kind: "realm", realm_id: PRINCIPAL_CONTROL_REALM });
    expect(event.payload.key).toBe("ak.client.ui_state");
    expect(event.payload.expected_server_revision).toBe(index);
    expect(event.payload.body).toBeUndefined();
    const envelope = event.payload.encrypted_payload;
    expect(envelope.aad.actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
    expect(envelope.aad.account_data_key).toBe("ak.client.ui_state");
    const plaintext = await openFixtureClientUiValue(page, envelope);
    expect(plaintext).toEqual({ language: ["zh", "en", "zh"][index] });
  }
  expect(writes.length).toBe(3);
});
