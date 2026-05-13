import { expect, test } from "@playwright/test";
import { mockContrixApi } from "./mockContrixApi";

function latestTestId(page: import("@playwright/test").Page, testId: string) {
  return page.getByTestId(testId).last();
}

async function openServerSwitcher(page: import("@playwright/test").Page) {
  const menu = latestTestId(page, "server-switch-menu");
  if (await menu.isVisible()) {
    return;
  }
  await latestTestId(page, "server-switch-button").click();
  await expect(menu).toBeVisible();
}

async function refreshServer(page: import("@playwright/test").Page) {
  await openServerSwitcher(page);
  await latestTestId(page, "connect-button").click();
}

async function openSettings(page: import("@playwright/test").Page) {
  await latestTestId(page, "account-menu-button").click();
  await latestTestId(page, "account-menu-settings").click();
}

async function writeLocalConfig(
  page: import("@playwright/test").Page,
  overrides: Partial<{
    server_url: string;
    account_did: string;
    device_id: string;
    session_token: string;
  }>,
) {
  await page.evaluate((nextConfig) => {
    const current = localStorage.getItem("yougen.config.v1");
    const parsed = current ? JSON.parse(current) : {};
    localStorage.setItem(
      "yougen.config.v1",
      JSON.stringify({
        server_url: "https://local.host",
        account_did: "did:web:alice.example",
        device_id: "cx:device:01964137-0000-7000-8000-0000000000a1",
        session_token: "sx:e2e-token",
        ...parsed,
        ...nextConfig,
      }),
    );
  }, overrides);
}

async function readLocalConfig(page: import("@playwright/test").Page) {
  return page.evaluate(() => JSON.parse(localStorage.getItem("yougen.config.v1") ?? "{}"));
}

test.beforeEach(async ({ page }, testInfo) => {
  await mockContrixApi(page);
  if (testInfo.title.startsWith("login page")) {
    return;
  }
  await page.addInitScript(() => {
    if (localStorage.getItem("yougen.config.v1")) {
      return;
    }
    localStorage.setItem(
      "yougen.config.v1",
      JSON.stringify({
        server_url: "https://local.host",
        account_did: "did:web:alice.example",
        device_id: "cx:device:01964137-0000-7000-8000-0000000000a1",
        session_token: "sx:e2e-token",
      }),
    );
  });
  await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
});

test("bootstrap login and sync shows the connected workspace", async ({ page }) => {
  await refreshServer(page);

  await expect(page.getByTestId("status-label")).toContainText("Online");
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");
  await expect(page.getByTestId("space-list")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();

  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked serverx");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-frontier")).toContainText("cx:event:e2e");
  await expect(page.getByTestId("account-menu-push")).toBeVisible();
  await expect(page.getByTestId("account-menu-queue")).toContainText("1");
});

test("topbar account menu shows identity and sync state", async ({ page }) => {
  await refreshServer(page);
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu")).toContainText("did:web:alice.example");
  await expect(page.getByTestId("account-menu")).toContainText("cx:device:");
  await expect(page.getByTestId("account-menu-frontier")).toContainText("cx:event:e2e");
  await expect(page.getByTestId("account-menu-settings")).toBeVisible();
});

test("workspace header collapses and sidebar edge resizes the menu", async ({ page }) => {
  const sidebar = page.getByTestId("sidebar");
  const mainView = page.getByTestId("main-view");
  const toggle = page.getByTestId("sidebar-collapse-toggle");
  const resizeHandle = page.getByTestId("sidebar-resize-handle");
  const initialBox = await sidebar.boundingBox();
  const mainBox = await mainView.boundingBox();
  const toggleBox = await toggle.boundingBox();
  const handleBox = await resizeHandle.boundingBox();

  expect(initialBox).not.toBeNull();
  expect(mainBox).not.toBeNull();
  expect(toggleBox).not.toBeNull();
  expect(handleBox).not.toBeNull();
  expect(toggleBox!.x).toBeLessThan(mainBox!.x + 60);

  await page.mouse.move(handleBox!.x + handleBox!.width / 2, handleBox!.y + 24);
  await page.mouse.down();
  await page.mouse.move(340, handleBox!.y + 24, { steps: 6 });
  await page.mouse.up();

  await expect
    .poll(async () => (await sidebar.boundingBox())?.width ?? 0)
    .toBeGreaterThan((initialBox?.width ?? 0) + 40);
  const resizedWidth = (await sidebar.boundingBox())?.width ?? 0;

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await expect.poll(async () => (await page.getByTestId("sidebar").boundingBox())?.width ?? 0).toBeGreaterThan(300);
  const reloadedWidth = (await page.getByTestId("sidebar").boundingBox())?.width ?? 0;
  expect(Math.abs(reloadedWidth - resizedWidth)).toBeLessThan(16);

  await toggle.click();
  await expect.poll(async () => (await sidebar.boundingBox())?.width ?? 0).toBeLessThan(100);
  await expect(resizeHandle).toBeHidden();
});

test("loopback proxy server aliases are normalized to local.host", async ({ page }) => {
  await writeLocalConfig(page, { server_url: "http://127.0.0.1:8787/" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  await openServerSwitcher(page);
  await expect(latestTestId(page, "server-url-input")).toHaveValue("https://local.host");
  await expect(page.getByTestId("topbar-crumbs")).toContainText("https://local.host");
});

test("topbar breadcrumbs avoid duplicated route and server context", async ({ page }) => {
  await openSettings(page);
  await expect(page.getByTestId("topbar-crumbs")).toContainText("Settings");
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText("Settings / Settings");
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText("Principal Server https://");
});

test("login page delegates account lifecycle to coauth OIDC", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("login-panel")).toBeVisible();
  await expect(page.getByTestId("login-server-url")).toHaveValue("https://local.host");
  await expect(page.getByTestId("login-account-hint")).toHaveCount(0);
  await expect(page.getByTestId("start-server-login-button")).toBeVisible();

  await expect(page.getByTestId("create-account-link")).toHaveCount(0);
  await expect(page.getByTestId("forgot-account-link")).toHaveCount(0);

  await Promise.all([
    page.waitForURL(/https:\/\/auth\.local\.host\/authorize.*/, { waitUntil: "domcontentloaded" }),
    page.getByTestId("start-server-login-button").click(),
  ]);
  const authorizeUrl = new URL(page.url());
  expect(authorizeUrl.searchParams.get("client_id")).toBe("01GFWR28C4KNE04WG3HKXB7C9R");
  expect(authorizeUrl.searchParams.get("login_hint")).toBeNull();
  expect(authorizeUrl.searchParams.get("redirect_uri")).toMatch(/\/auth\/callback$/);
  await expect(page.getByText("coauth")).toBeVisible();
  await expect(page.getByText("Create account")).toBeVisible();
  await expect(page.getByText("Lost password or account")).toBeVisible();
});

test("connect refresh canonicalizes stale account DID but preserves device override", async ({ page }) => {
  const staleDid = "did:web:auth.local.host:users:01KCANONICAL";
  const deviceId = "cx:device:01964137-0000-7000-8000-0000000000b0";
  await writeLocalConfig(page, { account_did: staleDid, device_id: deviceId });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  await refreshServer(page);

  await latestTestId(page, "account-menu-button").click();
  await expect(latestTestId(page, "account-menu-session-crypto")).toContainText(
    `session token loaded for ${deviceId}`,
  );
  await expect(latestTestId(page, "account-menu-did")).toContainText("did:web:alice.example");
  await expect(latestTestId(page, "account-menu-device")).toContainText(deviceId);
  await expect.poll(() => readLocalConfig(page)).toMatchObject({
    account_did: "did:web:alice.example",
    device_id: deviceId,
  });
});

test("session refresh canonicalizes stale account DID in settings", async ({ page }) => {
  const staleDid = "did:web:auth.local.host:users:01KREFRESH";
  await writeLocalConfig(page, { account_did: staleDid });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });

  await latestTestId(page, "account-menu-button").click();
  await expect(latestTestId(page, "account-menu-did")).toContainText(staleDid);
  await latestTestId(page, "account-menu-session-refresh").click();
  await expect(latestTestId(page, "account-menu-session-state")).toContainText(
    "Session refresh ok: did:web:alice.example",
  );
  await expect(latestTestId(page, "account-menu-did")).toContainText("did:web:alice.example");
  await expect.poll(() => readLocalConfig(page)).toMatchObject({
    account_did: "did:web:alice.example",
  });
});

test("settings language selector mirrors shell direction for RTL locales", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await expect(page.getByTestId("language-settings")).toBeVisible();
  await page.getByTestId("theme-night").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "night");
  await page.getByTestId("theme-system").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  await page.getByTestId("language-ar").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "rtl");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-direction", "rtl");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "ar");
  await expect(page.getByTestId("text-direction")).toContainText("rtl");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "rtl");

  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId("language-en").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "en");
});

test("kanban card detail exposes linked discussion and locked discussion boundaries", async ({ page }) => {
  await refreshServer(page);
  await page.getByRole("link", { name: "Kanban" }).click();
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await page.getByTestId("kanban-card").first().click();
  await expect(page.getByTestId("card-detail-modal")).toContainText("Primary discussion");
  await expect(page.getByTestId("card-detail-modal")).toContainText("Locked discussion");
  await expect(page.getByTestId("card-detail-modal")).toContainText("card visibility != discussion visibility");
  await expect(page.getByTestId("locked-discussion-fail-closed")).toContainText("Opaque ref");
});

test("kanban queues Move submissions and replays through move API", async ({ page }) => {
  await refreshServer(page);
  await page.getByRole("link", { name: "Kanban" }).click();
  await page.getByTestId("add-card-button").first().click();
  await page.getByTestId("new-card-title-input").fill("Move-backed card");
  await page.getByTestId("save-card-button").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText("cx.flow.create");
  await expect(page.getByTestId("board-event-record").last()).toContainText("cx:move:sha256:");
  await expect(page.getByTestId("board-event-record").last()).toContainText("cx.component.flow.position.v1");

  const moveSubmit = page.waitForRequest("**/api/v1/moves");
  await page.getByTestId("replay-board-queue").click();
  const moveBody = await moveSubmit.then((request) => request.postDataJSON());
  expect(moveBody.id).toContain("cx:move:sha256:");
  expect(moveBody.body?.cell?.family).toBe("cx.component.flow.position.v1");
  await expect(page.getByTestId("board-status")).toContainText("state=pending");
});

test("settings MIMI facade discovers drafts and runs interop actions", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-mimi").click();
  await expect(page.getByTestId("mimi-interop-panel")).toBeVisible();
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-ietf-mimi-protocol-06");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-ietf-mimi-content-08");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("Discussion Policy");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-ietf-mimi-room-policy-03");
  await expect(page.getByTestId("mimi-draft-pinning")).toContainText("draft-kohbrok-mimi-identifiers-01");

  await page.getByTestId("mimi-refresh-directory").click();
  await expect(page.getByTestId("mimi-directory-result")).toContainText("mimi://mimi.example.com");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("submit_message");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("identifier_query");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("proxy_download");

  await page.getByTestId("mimi-group-info").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("group-info 01JSMIMI participants 2");

  await page.getByTestId("mimi-identifier-query").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("identifier mimi://remote.example/alice reachable true");

  await page.getByTestId("mimi-proxy-download").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("proxy-download cx:blob:sha256:e2e");

  const submit = page.waitForRequest("**/api/v1/mimi/rooms/01JSMIMI/messages");
  await page.getByTestId("mimi-submit-message").click();
  expect((await submit).postDataJSON().source_format).toBe("text/markdown;variant=GFM-MIMI");
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("submit-message mimi-msg-e2e");
});

test("mobile viewport collapses shell chrome and keeps timeline usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/timeline", { waitUntil: "domcontentloaded" });

  await expect(page.getByTestId("client-shell")).toBeVisible();
  await expect(page.getByTestId("sidebar")).toBeHidden();
  await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  await page.getByTestId("mobile-nav-toggle").click();
  await expect(page.getByTestId("mobile-nav-drawer")).toContainText("Board");
  await expect(page.getByTestId("main-view")).toBeVisible();
  await expect(page.getByTestId("composer-input")).toBeVisible();
});

test("accessibility smoke exposes landmarks and live timeline feed", async ({ page }) => {
  await expect(page.getByTestId("sidebar")).toHaveAttribute("role", "navigation");
  await expect(page.getByTestId("main-view")).toHaveAttribute("role", "main");
  await expect(page.getByTestId("account-menu-button")).toHaveAttribute("aria-label", "Account menu");

  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline")).toHaveAttribute("role", "feed");
  await expect(page.getByTestId("timeline")).toHaveAttribute("aria-live", "polite");

  const sendRequest = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("composer-input").fill("a11y smoke message");
  await page.getByTestId("send-button").click();
  await sendRequest;

  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("role", "article");
  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("aria-label", /Timeline event from/);
});

test("directory search resolve and space selection flow works", async ({ page }) => {
  await page.getByTestId("global-search-input").fill("demo");
  await page.getByTestId("global-search-input").press("Enter");
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("index-query-results")).toContainText("Contrix Demo Space");
  await expect(page.getByTestId("generic-entity-card")).toHaveAttribute("data-render-kind", "card");
  await expect(page.getByTestId("entity-type-label")).toContainText("space");
  await expect(page.getByTestId("entity-facets")).toContainText("renderable");
  await expect(page.getByTestId("projection-facets")).toContainText("item: stateful, rankable");
  await expect(page.getByTestId("unknown-facets-debug")).toContainText("com.example.preview");

  await page.getByTestId("directory-select-button").click();
  await page.getByTestId("resolve-selected-button").click();
  await expect(page.getByTestId("status-label")).toContainText("resolved public");
  await expect(page.getByTestId("directory-result").first()).toContainText("Contrix Demo Space");

  await page.getByTestId("tab-objects").click();
  await page.getByTestId("directory-search-input").fill("launch");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("protocol-object-results")).toContainText("Launch checklist card");
  await expect(page.getByTestId("protocol-object-results")).toContainText("Restricted discussion");
  await expect(page.getByTestId("protocol-object-results")).toContainText("locked");

  await page.getByTestId("tab-organizations").click();
  await page.getByTestId("directory-search-input").fill("contrix");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("org-result")).toContainText("Contrix Labs");
  await expect(page.getByTestId("org-result")).toContainText("listed");
  await page.getByTestId("org-search-members").click();
  await expect(page.getByTestId("tab-actors")).toHaveClass(/primary/);
  await expect(page.getByTestId("directory-search-input")).toHaveValue("contrix.example");
});

test("notifications are derived from index projections and respect per-space mute rules", async ({ page }) => {
  await refreshServer(page);
  await page.getByTestId("topbar-notifications-button").click();

  await expect(page.getByTestId("notifications-panel")).toBeVisible();
  await expect(page.getByTestId("notifications-panel")).toContainText("Alice sent a message in Demo Space");
  await expect(page.getByTestId("notifications-status")).toContainText("Loaded 2 notification projection");

  await page.getByTestId("mute-space-button").first().click();
  await expect(page.getByTestId("notifications-muted-empty")).toContainText("hidden by archive, type, or per-space mute rules");

  await openSettings(page);
  await page.getByTestId("settings-nav-item-notifications").click();
  await expect(page.getByTestId("notifications-mute-summary")).toContainText("cx:space:0196419b-0000-7000-8000-000000000000");
  await page.getByTestId("notifications-settings-unmute-space").click();
  await expect(page.getByTestId("status-label")).toContainText("Unmuted");

  await page.getByTestId("topbar-notifications-button").click();
  await expect(page.getByTestId("notifications-panel")).toContainText("You were invited to review Demo Space");
});

test("setup, onboarding, and space timeline flow works", async ({ page }) => {
  await refreshServer(page);
  await expect(page.getByTestId("sync-cursor")).toContainText("sx:e2e:2");

  await page.getByRole("link", { name: "Onboarding" }).click();
  await expect(page.getByTestId("onboarding-panel")).toBeVisible();
  await page.getByTestId("register-account-button").click();
  await expect(page.getByTestId("account-flow")).toContainText("registered alice.example");

  await page.getByTestId("topbar-create-button").click();
  await expect(page.getByTestId("setup-panel")).toBeVisible();

  await page.getByTestId("create-space-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("created cx:space:01js0setupflow000000000000");
  await expect(page.getByTestId("selected-space-id")).toContainText("cx:space:01js0setupflow000000000000");

  await page.getByTestId("add-member-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("members");
  const sendRequest = page.waitForRequest("**/api/v1/events");
  await page.getByRole("link", { name: "Open Current Space" }).first().click();
  await expect(page.getByTestId("timeline")).toBeVisible();
  await page.getByTestId("composer-input").fill("setup flow message");
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("setup flow message");
  await expect(page.getByTestId("write-status")).toContainText("persisted cx:operation:");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-frontier")).toContainText("cx:event:");

  await page.getByTestId("topbar-create-button").click();
  await page.getByTestId("remove-member-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("removed; members");
  await page.getByTestId("delete-space-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("deleted true");
});

test("chat creates discussion entities and sends structured mention payloads", async ({ page }) => {
  await refreshServer(page);
  await page.getByRole("link", { name: "Chat" }).click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();

  await page.getByTestId("new-channel-name").fill("Ops Announce");
  await page.getByTestId("new-channel-topic").fill("Broadcast deploy updates");
  await page.getByTestId("channel-kind-announce").click();
  const channelEvent = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("create-channel-button").click();
  const channelBody = await channelEvent.then((request) => request.postDataJSON());
  expect(channelBody.kind).toBe("cx.flow.create");
  expect(channelBody.payload.kind).toBe("announce");
  expect(channelBody.payload.flow_id).toContain("cx:flow:");
  expect(channelBody.payload.title).toBe("Ops Announce");
  expect(channelBody.payload.rank).toBeTruthy();
  await expect(page.getByTestId("channel-item").last()).toContainText("Ops Announce");
  await expect(page.getByTestId("chat-status")).toContainText("flow event accepted");

  const chatSend = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("chat-input").fill("hello @did:web:bob.example about #cx:task:123");
  await page.getByTestId("send-chat-button").click();
  const chatBody = await chatSend.then((request) => request.postDataJSON());
  expect(chatBody.kind).toBe("cx.message.create");
  expect(chatBody.payload.flow_id).toContain("cx:flow:");
  expect(chatBody.payload.branch).toBe("discussion");
  expect(chatBody.payload.mentions.some((mention: { target: string }) => mention.target === "did:web:bob.example")).toBeTruthy();
  expect(chatBody.payload.mentions.some((mention: { target: string }) => mention.target === "cx:task:123")).toBeTruthy();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #cx:task:123");
  await expect(page.getByTestId("chat-mentions").last()).toContainText("did:web:bob.example");
  await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Revision chain");
  await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Tombstone");
  await expect(page.getByTestId("discussion-timeline-protocol")).toContainText("Linked discussion access");
});

test("plaintext compose keeps request ids, revision chains, tombstones, and local MLS entries", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  await page.getByTestId("composer-input").fill("draft survives reload");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("composer-input")).toHaveValue("draft survives reload");

  const sendRequest = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("composer-input").fill("plain e2e message");
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message");
  await expect(page.getByTestId("write-status")).toContainText("persisted cx:operation:");

  const editRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/api/v1/events") &&
      request.method() === "POST" &&
      request.postDataJSON().kind === "cx.message.revise",
  );
  await page.getByTestId("edit-button").last().click();
  await page.getByTestId("edit-composer").locator("textarea").fill("plain e2e message edited");
  await page.getByTestId("save-edit-button").click();
  expect((await editRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("plain e2e message edited");
  await expect(page.getByTestId("revision-chain")).toContainText("plain e2e message");
  await expect(page.getByTestId("event-fact").last()).toContainText("cx:operation:");

  const redactRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/api/v1/events") &&
      request.method() === "POST" &&
      request.postDataJSON().kind === "cx.message.redact",
  );
  await page.getByTestId("redact-button").last().click();
  await page.getByTestId("confirm-redact-button").click();
  expect((await redactRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("redacted-tombstone")).toContainText("[Message redacted]");
  await expect(page.getByTestId("event-fact").last()).toContainText("tombstone cx:event:");

  await page.getByTestId("composer-input").fill("secret e2e message");
  await page.getByTestId("encrypt-local-button").click();
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("timeline")).toContainText("encrypted mls-rfc9420 epoch");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-crypto")).toContainText("encrypted local payload");
});

test("timeline mark-read sends public receipt and stores private marker", async ({ page }) => {
  await refreshServer(page);
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("timeline-event").first()).toBeVisible();

  const receiptRequest = page.waitForRequest("**/api/v1/receipts");
  await page.getByTestId("mark-read-button").first().click();
  const receiptBody = await receiptRequest.then((request) => request.postDataJSON());

  expect(receiptBody.space_id).toBe("cx:space:0196419b-0000-7000-8000-000000000000");
  expect(receiptBody.receipt_type).toBe("cx.receipt.read");
  expect(receiptBody.event_id).toContain("summary-cx:space");
  await expect(page.getByTestId("read-receipt-status")).toContainText("cx.receipt.read");
  await expect(page.getByTestId("read-marker-status")).toContainText("Read marker:");
  await expect(page.getByTestId("read-marker-badge")).toContainText("Read marker here");
});

test("timeline blob flow verifies hashes and authenticated downloads", async ({ page }) => {
  await refreshServer(page);
  await page.getByRole("link", { name: "Timeline" }).click();

  const uploadRequest = page.waitForRequest("**/api/v1/blob/upload");
  await page.getByTestId("attach-blob-button").click();
  expect((await uploadRequest).headers()["authorization"]).toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("upload hash ok");
  await expect(page.getByTestId("blob-status")).toContainText("no token in media URL");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("unsafe or opaque type opens as attachment");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("Thumbnail: cx:blob:sha256:e2e-thumb");

  const downloadRequest = page.waitForRequest("**/api/v1/blob/get?blob_ref=*");
  await page.getByTestId("verify-blob-download").click();
  const download = await downloadRequest;
  expect(download.headers()["authorization"]).toContain("Bearer");
  expect(download.url()).not.toContain("access_token");
  expect(download.url()).not.toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("download verified sha256");
});

test("plaintext boundary blocks private drafts until exposure is acknowledged", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  await expect(page.getByTestId("plaintext-boundary-panel")).toBeVisible();
  await expect(page.getByTestId("plaintext-visible-services")).toContainText("configured server");
  await expect(page.getByTestId("plaintext-preview-disclosure")).toContainText("search");

  await page.getByTestId("private-plaintext-toggle").check();
  await page.getByTestId("composer-input").fill("private plaintext body");
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("write-status")).toContainText("plaintext blocked");
  await expect(page.getByTestId("plaintext-boundary-warning")).toContainText("not E2EE");

  const sendRequest = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("plaintext-boundary-ack").click();
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-contrix-request-id"]).toBeTruthy();
  await expect(page.getByTestId("write-status")).toContainText("persisted cx:operation:");
});

test("moderation report and to-device queue action hits protocol endpoints", async ({ page }) => {
  await page.getByRole("link", { name: "Timeline" }).click();
  const report = page.waitForRequest("**/api/v1/moderation/report");
  const deviceMessage = page.waitForRequest(
    (request) =>
      request.url().endsWith("/api/v1/device_messages") &&
      request.method() === "POST",
  );

  await page.getByTestId("report-queue-button").click();

  expect((await report).method()).toBe("POST");
  const deviceMessageRequest = await deviceMessage;
  expect(deviceMessageRequest.method()).toBe("POST");
  expect(deviceMessageRequest.headers()["idempotency-key"]).toBe("yougen-txn-1");
});

test("space admin page handles metadata invites members and dangerous lifecycle", async ({ page }) => {
  await page.goto("/space/cx:space:0196419b-0000-7000-8000-000000000000/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("space-admin-panel")).toBeVisible();
  await expect(page.getByTestId("admin-discussion-admission")).toContainText("Discussion-scoped external admission");
  await page.getByTestId("queue-discussion-admission").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("Discussion-scoped external admission");

  await page.getByTestId("space-name-input").fill("Updated Demo Space");
  await page.getByTestId("update-metadata-button").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("updated");

  await page.getByTestId("invite-target-input").fill("did:web:carol.example");
  const inviteCommit = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("send-invite-button").click();
  const inviteBody = await inviteCommit.then((request) => request.postDataJSON());
  expect(inviteBody.kind).toBe("cx.invite.create");
  expect(inviteBody.payload.invite_id).toBe("cx:invite:e2e");
  await expect(page.getByTestId("space-admin-status")).toContainText("invited did:web:carol.example");
  await expect(page.getByTestId("invite-row")).toContainText("pending");

  const acceptCommit = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("accept-invite-button").click();
  const acceptBody = await acceptCommit.then((request) => request.postDataJSON());
  expect(acceptBody.kind).toBe("cx.invite.accept");
  await expect(page.getByTestId("invite-row")).toContainText("accepted");

  const cancelCommit = page.waitForRequest("**/api/v1/events");
  await page.getByTestId("cancel-invite-button").click();
  const cancelBody = await cancelCommit.then((request) => request.postDataJSON());
  expect(cancelBody.kind).toBe("cx.invite.cancel");
  await expect(page.getByTestId("invite-row")).toContainText("canceled");

  await page.getByTestId("rotate-space-epoch").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("rotated to epoch");

  await page.getByTestId("archive-space-button").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("archived");
});

test("legacy audit route now resolves to operational settings", async ({ page }) => {
  await page.goto("/audit", { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/settings\/release$/);
  await expect(page.getByTestId("settings-panel")).toBeVisible();
  await expect(page.getByTestId("release-moved-banner")).toContainText("Operational status");
});

test("legacy applets route now resolves to integrations settings", async ({ page }) => {
  await page.goto("/applets", { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/settings\/mimi$/);
  await expect(page.getByTestId("settings-panel")).toBeVisible();
  await expect(page.getByTestId("settings-nav-item-mimi")).toBeVisible();
  await expect(page.getByTestId("mimi-interop-panel")).toBeVisible();
});

test("legacy devices route now resolves to security and recovery settings", async ({ page }) => {
  await refreshServer(page);
  await page.goto("/devices", { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/settings\/encryption$/);
  await expect(page.getByTestId("settings-panel")).toBeVisible();
  await expect(page.getByTestId("settings-setup-recovery-hub")).toContainText("Verify Device");
});

test("invalid server URL surfaces an error state", async ({ page }) => {
  await openServerSwitcher(page);
  await page.getByTestId("server-url-input").fill("not a url");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("Error: invalid URL");
});

test("insecure remote http endpoint is rejected before connect", async ({ page }) => {
  await openServerSwitcher(page);
  await page.getByTestId("server-url-input").fill("http://contrix.example");
  await page.getByTestId("connect-button").click();

  await expect(page.getByTestId("status-label")).toContainText("HTTPS is required for non-local servers");
});

test("legacy call route now redirects to home", async ({ page }) => {
  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
});

test("visual smoke renders core client pages on desktop and mobile", async ({ page }) => {
  await refreshServer(page);
  for (const [route, testId] of [
    ["/", "dashboard-panel"],
    ["/kanban", "kanban-panel"],
    ["/chat", "chat-panel"],
    ["/settings", "settings-panel"],
  ] as const) {
    await page.goto(route, { waitUntil: "domcontentloaded" });
    await expect(page.getByTestId(testId)).toBeVisible();
    const shot = await page.screenshot();
    expect(shot.length).toBeGreaterThan(10_000);
  }

  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/kanban", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
  const mobileShot = await page.screenshot();
  expect(mobileShot.length).toBeGreaterThan(10_000);
});

test("legacy readiness route now resolves to operational settings", async ({ page }) => {
  await page.goto("/readiness", { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/settings\/release$/);
  await expect(page.getByTestId("settings-panel")).toBeVisible();
  await expect(page.getByTestId("release-moved-banner")).toContainText("tracked blockers");
  await expect(page.getByTestId("release-moved-banner")).toContainText("settings-owned surface");
});
