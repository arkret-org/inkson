import { expect, test } from "@playwright/test";
import { mockCokretApi } from "./mockCokretApi";

const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";
const CHILD_REALM = "ck:realm:01launchchild0000000000000";

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
  await page.getByTestId("server-option").filter({ hasText: "https://local.host" }).click();
}

async function openSettings(page: import("@playwright/test").Page) {
  await latestTestId(page, "account-menu-button").click();
  await latestTestId(page, "account-menu-settings").click();
}

async function openTimeline(page: import("@playwright/test").Page) {
  await page.goto(`/timeline/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("timeline")).toBeVisible();
}

async function openDiscussion(page: import("@playwright/test").Page) {
  await openKanban(page);
  await page.getByTestId("kanban-card").first().click();
  await expect(page.getByTestId("card-detail-modal")).toBeVisible();
  await expect(page.getByTestId("card-description-panel")).toBeVisible();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();
}

async function openKanban(page: import("@playwright/test").Page) {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
}

async function createDiscussion(
  page: import("@playwright/test").Page,
  name = "Test Discussion",
) {
  void name;
  await expect(page.getByTestId("chat-panel")).toBeVisible();
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
        device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
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
  await mockCokretApi(page);
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
        device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
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
  await expect(page.getByTestId("sync-cursor")).toContainText("ck:cursor:e2e-2");
  await expect(page.getByTestId("space-list")).toContainText("Cokret Demo Space");
  await expect(page.getByTestId("space-list")).toContainText("Launch Child Space");
  await expect(
    page.getByTestId("space-button").filter({ hasText: "Cokret Demo Space" }).locator(".sidebar-nav-icon"),
  ).toHaveAttribute("title", "Encrypted Realm");
  await expect(
    page.getByTestId("space-button").filter({ hasText: "Launch Child Space" }).locator(".sidebar-nav-icon"),
  ).toHaveAttribute("title", "Space");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ck:event:e2e");
  await expect(page.getByTestId("account-menu-push")).toBeVisible();
  await expect(page.getByTestId("account-menu-queue")).toContainText("1");
  await page.getByTestId("account-menu-button").click();
  await page.getByTestId("space-scope-descendants").click();
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  await expect(page.getByTestId("spaces-summary")).toContainText("Recent Realms & Spaces");
  await expect(
    page.getByTestId("dashboard-space-card").filter({ hasText: "Cokret Demo Space" }).locator(".pill.muted.xs"),
  ).toHaveText("Realm");
  await expect(
    page.getByTestId("dashboard-space-card").filter({ hasText: "Launch Child Space" }).locator(".pill.muted.xs"),
  ).toHaveText("Space");

  await page.getByTestId("space-button").first().click();
  await expect(page.getByTestId("timeline")).toBeVisible();
  await expect(page.getByTestId("space-context-bar")).not.toContainText("Current + descendants");
  await expect(page.getByTestId("space-context-bar")).not.toContainText("Space views");
  await expect(page.getByTestId("space-context-bar")).not.toContainText("Discussion");
  await expect(page.getByTestId("space-context-bar").getByRole("link", { name: "Timeline" })).toBeVisible();
  await expect(page.getByTestId("timeline")).toContainText("Shared demo Space served by mocked server");
});

test("authenticated login route returns to the workspace", async ({ page }) => {
  await page.goto("/login", { waitUntil: "domcontentloaded" });

  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("login-panel")).toHaveCount(0);
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
});

test("dashboard summarizes unread notifications from sync projection", async ({ page }) => {
  await refreshServer(page);

  await expect(page.getByTestId("dashboard-unread-notifications")).toHaveText("2");
  await expect(page.getByTestId("pinned-notifications")).toContainText("New message");
  await expect(page.getByTestId("pinned-notifications")).toContainText("New invite");
});

test("topbar account menu shows identity and sync state", async ({ page }) => {
  await refreshServer(page);
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu")).toContainText("did:web:alice.example");
  await expect(page.getByTestId("account-menu")).toContainText("ck:device:");
  await expect(page.getByTestId("account-menu-copy-did")).toBeVisible();
  await expect(page.getByTestId("account-menu-copy-device")).toBeVisible();
  await page.getByTestId("account-menu-copy-did").click();
  await expect(page.getByTestId("account-menu-session-state")).toHaveText("DID copied");
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ck:event:e2e");
  await expect(page.getByTestId("account-menu-settings")).toBeVisible();
  const refreshBox = await page.getByTestId("account-menu-session-refresh").boundingBox();
  const logoutBox = await page.getByTestId("account-menu-session-logout").boundingBox();
  const settingsBox = await page.getByTestId("account-menu-settings").boundingBox();
  expect(refreshBox).not.toBeNull();
  expect(logoutBox).not.toBeNull();
  expect(settingsBox).not.toBeNull();
  expect(Math.abs(refreshBox!.y - settingsBox!.y)).toBeLessThan(2);
  expect(Math.abs(logoutBox!.y - settingsBox!.y)).toBeLessThan(2);
  expect(refreshBox!.x).toBeLessThan(logoutBox!.x);
  expect(logoutBox!.x).toBeLessThan(settingsBox!.x);
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
  await expect(page.getByTestId("principal-context")).toContainText("https://local.host");
  await expect(page.getByTestId("server-url-input")).toHaveCount(0);
  await expect(page.getByTestId("connect-button")).toHaveCount(0);
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText("https://local.host");
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
  expect(authorizeUrl.searchParams.get("prompt")).toBe("login");
  expect(authorizeUrl.searchParams.get("max_age")).toBe("0");
  expect(authorizeUrl.searchParams.get("redirect_uri")).toMatch(/\/auth\/callback$/);
  await expect(page.getByText("coauth")).toBeVisible();
  await expect(page.getByText("Create account")).toBeVisible();
  await expect(page.getByText("Lost password or account")).toBeVisible();
});

test("connect refresh canonicalizes stale account DID but preserves device override", async ({ page }) => {
  const staleDid = "did:web:auth.local.host:users:01KCANONICAL";
  const deviceId = "ck:device:01964137-0000-7000-8000-0000000000b0";
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

test("settings avatar upload crops local image before publishing profile URL", async ({ page }) => {
  await openSettings(page);
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();

  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
    "base64",
  );
  await page.getByTestId("settings-avatar-input").setInputFiles({
    name: "avatar.png",
    mimeType: "image/png",
    buffer: png,
  });

  await expect(page.getByTestId("settings-avatar-crop-editor")).toBeVisible();
  await page.getByTestId("settings-avatar-crop-zoom").evaluate((element) => {
    const input = element as HTMLInputElement;
    input.value = "150";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const uploadRequest = page.waitForRequest("**/_cokret/self/blob/upload");
  const profileRequest = page.waitForRequest("**/_soland/self/account/profile");
  await page.getByTestId("settings-avatar-upload-cropped").click();

  const upload = await uploadRequest;
  expect(upload.headers()["content-type"]).toContain("image/jpeg");
  expect(upload.postDataBuffer()?.length ?? 0).toBeGreaterThan(100);

  const profileBody = await profileRequest.then((request) => request.postDataJSON());
  expect(profileBody.avatar_url).toContain("blob_ref=cx%3Ablob%3Asha256%3Ae2e");
  expect(profileBody.avatar_url).toContain("purpose=profile_avatar");
  await expect(page.getByTestId("settings-avatar-crop-editor")).toHaveCount(0);
});

test("light theme renders the sidebar with light navigation colors", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId("theme-light").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "light");

  const sidebarVars = await page.getByTestId("sidebar").evaluate((element) => {
    const styles = getComputedStyle(element);
    return {
      navBg: styles.getPropertyValue("--nav-bg").trim().toLowerCase(),
      navText: styles.getPropertyValue("--nav-text").trim().toLowerCase(),
    };
  });
  expect(sidebarVars).toEqual({
    navBg: "#fff9f3",
    navText: "#2f2723",
  });
});

test("topbar theme toggle takes effect on the first click from system dark", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  const toggle = page.getByTestId("theme-toggle");
  await expect(toggle).toHaveAttribute("title", "Switch to light theme");
  await toggle.click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "light");
  await expect(toggle).toHaveAttribute("title", "Switch to night theme");
});

test("kanban card detail embeds discussion without legacy boundary copy", async ({ page }) => {
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
  await detailPopup.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-panel")).toBeVisible();
  await expect(page.getByTestId("open-primary-discussion")).toHaveCount(0);
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

test("kanban hides list creation until a board exists", async ({ page }) => {
  await page.route("**/_cokret/self/projection/spaces**", async (route) => {
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: [], total: 0, spaces: [] }),
    });
  });
  await page.route("**/_cokret/self/projection/flows**", async (route) => {
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ items: [], total: 0, flows: [] }),
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
    (request) => request.url().includes("/_cokret/self/events") && request.method() === "POST",
  );
  await page.getByTestId("save-card-button").click();
  const eventBody = await eventSubmit.then((request) => request.postDataJSON());
  expect(eventBody.kind).toBe("ck.flow.create");
  const positionComponent = eventBody.payload?.components?.find(
    (component: { family?: string }) => component.family === "ck.component.flow.position.v1",
  );
  expect(positionComponent?.family).toBe("ck.component.flow.position.v1");
  await page.getByTestId("board-queue-toggle").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText("ck.flow.create");
  await expect(page.getByTestId("board-event-record").last()).toContainText("sha256:");
  await expect(page.getByTestId("board-event-record").last()).toContainText("ck.component.flow.position.v1");
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

  await page.getByTestId("board-space-select").selectOption({ label: "Secondary planning board" });

  await expect(page.getByTestId("kanban-column")).toHaveCount(1);
  await expect(page.getByTestId("kanban-board-grid")).toContainText("Secondary board card");
  await expect(page.getByTestId("kanban-board-grid")).not.toContainText("Legal review for public beta");
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
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("proxy-download ck:blob:sha256:e2e");

  const submit = page.waitForRequest("**/_cokret/open/mimi/flows/01JSMIMI/messages");
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
  await expect(page.getByTestId("mobile-nav-drawer")).toContainText("Spaces");
  await expect(page.getByTestId("main-view")).toBeVisible();
  await expect(page.getByTestId("composer-input")).toBeVisible();
});

test("timeline keeps auxiliary panels above the message input", async ({ page }) => {
  await openTimeline(page);
  await expect(page.getByTestId("composer")).toBeVisible();
  await expect(page.getByTestId("moderation-appeal-entrypoint")).toHaveCount(0);
  await expect(page.getByTestId("composer-input")).toBeVisible();

  const metrics = await page.evaluate(() => {
    const timeline = document.querySelector('[data-testid="timeline"]')?.getBoundingClientRect();
    const workspace = document.querySelector(".workspace-body")?.getBoundingClientRect();
    const composer = document.querySelector('[data-testid="composer"]')?.getBoundingClientRect();
    const input = document.querySelector('[data-testid="composer-input"]')?.getBoundingClientRect();

    return timeline && workspace && composer && input
      ? {
          timelineTop: timeline.top,
          workspaceBottom: workspace.bottom,
          composerTop: composer.top,
          composerBottom: composer.bottom,
          inputTop: input.top,
        }
      : null;
  });

  expect(metrics).not.toBeNull();
  expect(metrics!.composerTop).toBeGreaterThanOrEqual(metrics!.timelineTop);
  expect(metrics!.inputTop).toBeGreaterThanOrEqual(metrics!.composerTop);
  expect(metrics!.composerBottom).toBeGreaterThan(metrics!.inputTop);
  expect(metrics!.composerBottom).toBeLessThanOrEqual(metrics!.workspaceBottom);
  expect(metrics!.workspaceBottom - metrics!.composerBottom).toBeLessThanOrEqual(72);
});

test("accessibility smoke exposes landmarks and live timeline feed", async ({ page }) => {
  await expect(page.getByTestId("sidebar")).toHaveAttribute("role", "navigation");
  await expect(page.getByTestId("main-view")).toHaveAttribute("role", "main");
  await expect(page.getByTestId("account-menu-button")).toHaveAttribute("aria-label", "Account menu");

  await openTimeline(page);
  await expect(page.getByTestId("timeline")).toHaveAttribute("role", "feed");
  await expect(page.getByTestId("timeline")).toHaveAttribute("aria-live", "polite");

  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("composer-input").fill("a11y smoke message");
  await page.getByTestId("send-button").click();
  await sendRequest;

  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("role", "article");
  await expect(page.getByTestId("timeline-event").last()).toHaveAttribute("aria-label", /Timeline event from/);
});

test("directory search resolve and space selection flow works", async ({ page }) => {
  await page.getByTestId("topbar-search-button").click();
  await page.getByTestId("global-search-input").fill("demo");
  await page.getByTestId("global-search-input").press("Enter");
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toContainText("Cokret Demo Space");
  await expect(page.getByTestId("index-query-results")).toContainText("Cokret Demo Space");
  await expect(page.getByTestId("generic-entity-card")).toHaveAttribute("data-render-kind", "card");
  await expect(page.getByTestId("entity-type-label")).toContainText("space");
  await expect(page.getByTestId("entity-facets")).toContainText("renderable");
  await expect(page.getByTestId("projection-facets")).toContainText("item: stateful, rankable");
  await expect(page.getByTestId("unknown-facets-debug")).toContainText("com.example.preview");

  await page.getByTestId("directory-select-button").click();
  await page.getByTestId("resolve-selected-button").click();
  await expect(page.getByTestId("status-label")).toContainText("resolved public");
  await expect(page.getByTestId("directory-result").first()).toContainText("Cokret Demo Space");

  await page.getByTestId("directory-advanced-diagnostics-toggle").click();
  await page.getByTestId("tab-objects").click();
  await page.getByTestId("directory-search-input").fill("launch");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("protocol-object-results")).toContainText("Launch checklist card");
  await expect(page.getByTestId("protocol-object-results")).toContainText("Restricted discussion");
  await expect(page.getByTestId("protocol-object-results")).toContainText("locked");

  await page.getByTestId("tab-organizations").click();
  await page.getByTestId("directory-search-input").fill("cokret");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("org-result")).toContainText("Cokret Labs");
  await expect(page.getByTestId("org-result")).toContainText("listed");
  await page.getByTestId("org-search-members").click();
  await expect(page.getByTestId("tab-actors")).toHaveClass(/primary/);
  await expect(page.getByTestId("directory-search-input")).toHaveValue("cokret.example");
});

test("command palette closes with Escape and outside click", async ({ page }) => {
  await page.getByTestId("topbar-search-button").click();
  await expect(page.getByTestId("command-palette")).toBeVisible();

  await page.keyboard.press("Escape");
  await expect(page.getByTestId("command-palette")).toBeHidden();
  await expect(page.getByTestId("topbar-search-button")).toBeVisible();

  await page.getByTestId("topbar-search-button").click();
  await expect(page.getByTestId("command-palette")).toBeVisible();
  await page.getByTestId("topbar-crumbs").click();

  await expect(page.getByTestId("command-palette")).toBeHidden();
  await expect(page.getByTestId("topbar-search-button")).toBeVisible();
});

test("diagnostic and preview surfaces stay behind clear user-facing states", async ({ page }) => {
  await page.goto("/directory", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("directory-panel")).toBeVisible();
  await expect(page.getByTestId("directory-three-axes-banner")).not.toHaveAttribute("open", "");
  await expect(page.getByTestId("directory-advanced-diagnostics")).not.toHaveAttribute("open", "");

  await page.goto("/agents", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute("data-feature", "experimental-agents");

  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("call-panel")).toContainText("Signaling ready");
  await expect(page.getByTestId("deferred-feature-gate")).toHaveAttribute("data-feature", "experimental-webrtc");
});

test("setup realm form stays in the main workspace layout", async ({ page }) => {
  await refreshServer(page);
  await page.goto("/setup/realms", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("setup-panel")).toBeVisible();

  const measureLayout = () => page.evaluate(() => {
    const rectOf = (selector: string) => {
      const rect = document.querySelector(selector)?.getBoundingClientRect();
      return rect
        ? { left: rect.left, right: rect.right, top: rect.top, width: rect.width }
        : null;
    };
    return {
      sidebar: rectOf('[data-testid="sidebar"]'),
      main: rectOf('[data-testid="main-view"]'),
      setup: rectOf('[data-testid="setup-panel"]'),
      header: rectOf(".workspace-header"),
    };
  });

  const assertWorkspaceLayout = (layout: Awaited<ReturnType<typeof measureLayout>>) => {
    expect(layout.sidebar).not.toBeNull();
    expect(layout.main).not.toBeNull();
    expect(layout.setup).not.toBeNull();
    expect(layout.header).not.toBeNull();

    expect(layout.sidebar!.top).toBeLessThanOrEqual(2);
    expect(layout.main!.top).toBeLessThanOrEqual(2);
    expect(Math.abs(layout.main!.top - layout.sidebar!.top)).toBeLessThanOrEqual(2);
    expect(Math.abs(layout.header!.top - layout.main!.top)).toBeLessThanOrEqual(2);

    const horizontalOverlap = Math.max(
      0,
      Math.min(layout.setup!.right, layout.sidebar!.right) -
        Math.max(layout.setup!.left, layout.sidebar!.left),
    );
    expect(horizontalOverlap).toBeLessThanOrEqual(2);
    expect(layout.setup!.left).toBeGreaterThanOrEqual(layout.main!.left - 2);
    expect(layout.setup!.right).toBeLessThanOrEqual(layout.main!.right + 2);
    expect(layout.setup!.top).toBeGreaterThan(layout.header!.top);
    expect(layout.setup!.width).toBeGreaterThan(640);
  };

  const layout = await measureLayout();
  assertWorkspaceLayout(layout);

  await page.evaluate(() => {
    const accountKey = "did:web:alice.example";
    const encrypted = [...new TextEncoder().encode("ar")]
      .map((byte, index) => {
        const keyByte = accountKey.charCodeAt(index % accountKey.length);
        return (byte ^ keyByte).toString(16).padStart(2, "0");
      })
      .join("");
    const state = JSON.parse(localStorage.getItem("yougen.local_state.v1") ?? "{}");
    state.private_data = { ...(state.private_data ?? {}), locale: encrypted };
    localStorage.setItem("yougen.local_state.v1", JSON.stringify(state));
  });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-direction", "rtl");
  await expect(page.getByTestId("setup-panel")).toBeVisible();
  assertWorkspaceLayout(await measureLayout());
});

test("notifications are derived from index projections and respect per-realm mute rules", async ({ page }) => {
  await refreshServer(page);
  await page.getByTestId("topbar-notifications-button").click();

  await expect(page.getByTestId("notifications-panel")).toBeVisible();
  await expect(page.getByTestId("notifications-panel")).toContainText("Alice sent a message in Demo Space");
  await expect(page.getByTestId("notifications-status")).toContainText("Loaded 2 notification(s).");

  await page
    .getByTestId("notification-item")
    .filter({ hasText: "Alice sent a message in Demo Space" })
    .getByTestId("mute-realm-button")
    .click();
  await expect(page.getByTestId("notifications-panel")).not.toContainText("Alice sent a message in Demo Space");

  await openSettings(page);
  await page.getByTestId("settings-nav-item-notifications").click();
  await expect(page.getByTestId("settings-muted-realm-row").locator("span")).toHaveAttribute("title", DEMO_REALM);
  await page.getByTestId("notifications-settings-unmute-realm").click();
  await expect(page.getByTestId("status-label")).toContainText("Unmuted");

  await page.getByTestId("topbar-notifications-button").click();
  await expect(page.getByTestId("notifications-panel")).toContainText("You were invited to review Demo Space");
  const acceptInvite = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/events") &&
      request.method() === "POST",
  );
  await page
    .getByTestId("notification-item")
    .filter({ hasText: "You were invited to review Demo Space" })
    .getByTestId("notification-action")
    .click();
  const acceptBody = await acceptInvite.then((request) => request.postDataJSON());
  expect(acceptBody.kind).toBe("ck.member.state");
  expect(acceptBody.payload.invite_ref).toBe("ck:invite:01904100-0000-7000-8000-000000000099");
  expect(acceptBody.payload).not.toHaveProperty("invite_id");
  await expect(page.getByTestId("notifications-status")).toContainText("Joined Realm");
});

test("setup, onboarding, and space timeline flow works", async ({ page }) => {
  await refreshServer(page);
  await expect(page.getByTestId("sync-cursor")).toContainText("ck:cursor:e2e-2");

  await page.goto("/onboarding", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("onboarding-panel")).toBeVisible();
  await page.getByTestId("register-account-button").click();
  await expect(page.getByTestId("account-flow")).toContainText("registered alice.example");

  await page.getByTestId("sidebar-new-realm-cta").click();
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel).toBeVisible();
  await expect(page.getByTestId("space-title")).toContainText("New Realm");
  await expect(setupPanel.getByRole("link", { name: "Search" })).toHaveCount(0);
  await expect(setupPanel.getByRole("link", { name: "Settings" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Apply Policy" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Add Member" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Remove Member" })).toHaveCount(0);
  await expect(setupPanel.getByRole("button", { name: "Delete Space" })).toHaveCount(0);

  await page.getByTestId("space-title-input").fill("Setup Flow Space");
  await page.getByTestId("space-summary-input").fill("Created from yougen workspace setup");
  await page.getByTestId("new-space-next-button").click();
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("three independent axes");
  await page.getByTestId("new-space-next-button").click();
  await page.getByTestId("seed-members-input").fill("did:web:bob.example");
  await expect(setupPanel.getByRole("button", { name: "Create Realm" })).toBeVisible();
  await expect(setupPanel.getByRole("button", { name: "Create Space" })).toHaveCount(0);
  const realmCreateRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ck.realm.create"),
  );
  const plaintextPolicyRequest = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/events") &&
      request.method() === "POST" &&
      (request.postData() ?? "").includes("ck.realm.plaintext_visible_services"),
  );
  await page.getByTestId("create-space-button").click();
  const [realmCreateBody, plaintextPolicyBody] = await Promise.all([
    realmCreateRequest.then((request) => request.postDataJSON()),
    plaintextPolicyRequest.then((request) => request.postDataJSON()),
  ]);
  expect(JSON.stringify(realmCreateBody)).toContain("ck.realm.create");
  expect(JSON.stringify(plaintextPolicyBody)).toContain("did:web:server.local");
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText(/created ck:realm:/);
  await expect(page.getByTestId("space-lifecycle-flow")).toContainText("canonical policy listed / invite / shared");
  await expect(page.getByTestId("space-setup-done")).toBeVisible();
  await expect(page.getByTestId("mls-backup-banner")).toBeVisible();
  await expect(page.getByTestId("space-lifecycle-flow").getByTestId("selected-space-id")).toContainText("ck:realm:");

  await page.getByTestId("space-setup-done").getByRole("link", { name: "Open Realm", exact: true }).click();
  await expect(page.getByTestId("timeline")).toBeVisible();
  await expect(page.getByTestId("sidebar")).toContainText("Setup Flow Space");
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("sidebar")).toContainText("Setup Flow Space");
  await expect(page.getByTestId("timeline")).toBeVisible();
  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("composer-input").fill("setup flow message");
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(page.getByTestId("timeline")).toContainText("setup flow message");
  await expect(page.getByTestId("write-status")).toContainText("persisted");
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ck:event:");
});

test("card detail embeds discussion directly without legacy discussion chrome", async ({ page }) => {
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
  await expect(page.getByTestId("card-flow-tracks")).toHaveCount(0);
  await expect(page.getByTestId("discussion-main-panel")).not.toContainText("Launch board discussion");
  await expect(page.getByTestId("discussion-main-panel")).not.toContainText("Primary discussion");

  const chatSend = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("chat-input").fill("hello @did:web:bob.example about #ck:task:123");
  await page.getByTestId("send-chat-button").click();
  const chatBody = await chatSend.then((request) => request.postDataJSON());
  expect(chatBody.kind).toBe("ck.message.create");
  expect(chatBody.payload.message_id).toMatch(/^ck:message:/);
  expect(chatBody.payload.flow_id).toContain("ck:flow:");
  expect(chatBody.payload.track_name).toBe("discussion");
  expect(chatBody.payload.content.kind).toBe("ck.content.text");
  expect(chatBody.payload.content.body).toBe("hello @did:web:bob.example about #ck:task:123");
  expect(chatBody.payload.mentions).toBeUndefined();
  expect(Array.isArray(chatBody.payload.content.mention_sidecar_hash)).toBeTruthy();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #ck:task:123");
  await page.getByTestId("card-detail-tab-description").click();
  await expect(page.getByTestId("card-description-panel")).toBeVisible();
  await expect(page.getByTestId("card-discussion-panel")).toHaveCount(1);
  await expect(page.getByTestId("card-discussion-panel")).toBeHidden();
  await page.getByTestId("card-detail-tab-discussion").click();
  await expect(page.getByTestId("chat-message").last()).toContainText("hello @did:web:bob.example about #ck:task:123");
  await expect(page.getByTestId("discussion-timeline-protocol")).toHaveCount(0);
});

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

test("kanban card drag queues a flow move", async ({ page }) => {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();

  await page.getByTestId("kanban-card").first().dragTo(page.getByTestId("kanban-column").nth(1));

  await page.getByTestId("board-queue-toggle").click();
  await expect(page.getByTestId("board-event-record").last()).toContainText("ck.flow.move");
  await expect(page.getByTestId("kanban-column").nth(1)).toContainText("Legal review for public beta");
});

test("kanban projections use home Realm for nested Spaces", async ({ page }) => {
  await refreshServer(page);
  const projectionRealmIds: string[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname === "/_cokret/self/projection/spaces" || url.pathname === "/_cokret/self/projection/flows") {
      projectionRealmIds.push(url.searchParams.get("realm_id") ?? "");
    }
  });

  await page.goto(`/kanban/${CHILD_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();

  await expect.poll(() => projectionRealmIds, { timeout: 20_000 }).toContain(DEMO_REALM);
  expect(projectionRealmIds).not.toContain(CHILD_REALM);
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

test("timeline mark-read sends public receipt and stores private marker", async ({ page }) => {
  await refreshServer(page);
  await openTimeline(page);
  await expect(page.getByTestId("timeline-event").first()).toBeVisible();

  const receiptRequest = page.waitForRequest("**/_cokret/self/ephemeral");
  await page.getByTestId("mark-read-button").first().click();
  const receiptBody = await receiptRequest.then((request) => request.postDataJSON());

  expect(receiptBody.kind).toBe("ck.receipt.read");
  expect(receiptBody.realm_id).toBe("ck:realm:0196419b-0000-7000-8000-000000000000");
  expect(receiptBody.payload.receipt_type).toBe("read");
  expect(receiptBody.payload.schema).toBe("ck.schema.read_receipt.v1");
  expect(receiptBody.payload.event_id).toContain("summary-ck:realm");
  await expect(page.getByTestId("read-receipt-status")).toContainText("ck.receipt.read");
  await expect(page.getByTestId("read-cursor-status")).toContainText("Read marker:");
  await expect(page.getByTestId("read-cursor-badge")).toContainText("Read marker here");
});

test("timeline blob flow verifies hashes and authenticated downloads", async ({ page }) => {
  await refreshServer(page);
  await openTimeline(page);

  const uploadRequest = page.waitForRequest("**/_cokret/self/blob/upload");
  await page.getByTestId("attach-blob-button").click();
  expect((await uploadRequest).headers()["authorization"]).toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("upload hash ok");
  await expect(page.getByTestId("blob-status")).toContainText("no token in media URL");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("unsafe or opaque type opens as attachment");
  await expect(page.getByTestId("blob-policy-panel")).toContainText("Thumbnail: ck:blob:sha256:e2e-thumb");

  const downloadRequest = page.waitForRequest("**/_cokret/self/blob/get?blob_ref=*");
  await page.getByTestId("verify-blob-download").click();
  const download = await downloadRequest;
  expect(download.headers()["authorization"]).toContain("Bearer");
  expect(download.url()).not.toContain("access_token");
  expect(download.url()).not.toContain("Bearer");
  await expect(page.getByTestId("blob-status")).toContainText("download verified digest");
});

test("plaintext boundary blocks private drafts until exposure is acknowledged", async ({ page }) => {
  await openTimeline(page);
  await expect(page.getByTestId("plaintext-boundary-panel")).toBeVisible();
  await expect(page.getByTestId("plaintext-visible-services")).toContainText("configured server");
  await expect(page.getByTestId("plaintext-preview-disclosure")).toContainText("search");

  await page.getByTestId("private-plaintext-toggle").check();
  await page.getByTestId("composer-input").fill("private plaintext body");
  await page.getByTestId("send-button").click();
  await expect(page.getByTestId("write-status")).toContainText("plaintext blocked");
  await expect(page.getByTestId("plaintext-boundary-warning")).toContainText("not E2EE");

  const sendRequest = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("plaintext-boundary-ack").click();
  await page.getByTestId("send-button").click();
  expect((await sendRequest).headers()["x-cokret-request-id"]).toBeTruthy();
  await expect(page.getByTestId("write-status")).toContainText("persisted");
});

test("moderation report and to-device queue action hits protocol endpoints", async ({ page }) => {
  await openTimeline(page);
  const report = page.waitForRequest("**/_cokret/self/moderation/report");
  const deviceMessage = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_cokret/self/device_messages") &&
      request.method() === "POST",
  );

  await page.getByTestId("report-queue-button").click();

  expect((await report).method()).toBe("POST");
  const deviceMessageRequest = await deviceMessage;
  expect(deviceMessageRequest.method()).toBe("POST");
  expect(deviceMessageRequest.headers()["idempotency-key"]).toBe("yougen-txn-1");
});

test("space admin page handles metadata invites members and dangerous lifecycle", async ({ page }) => {
  await page.goto("/space/ck:realm:0196419b-0000-7000-8000-000000000000/admin", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("space-admin-panel")).toBeVisible();
  await expect(page.getByTestId("admin-discussion-admission")).toContainText("Discussion-scoped external admission");
  await page.getByTestId("queue-discussion-admission").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("Discussion-scoped external admission");

  await page.getByTestId("space-name-input").fill("Updated Demo Space");
  await page.getByTestId("update-metadata-button").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("updated");

  await page.getByTestId("invite-target-input").fill("did:web:carol.example");
  const inviteCommit = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("send-invite-button").click();
  const inviteBody = await inviteCommit.then((request) => request.postDataJSON());
  expect(inviteBody.kind).toBe("ck.invite.create");
  expect(inviteBody.payload.invite_id).toBe("ck:invite:e2e");
  await expect(page.getByTestId("space-admin-status")).toContainText("invited did:web:carol.example");
  await expect(page.getByTestId("invite-row")).toContainText("pending");

  const acceptCommit = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("accept-invite-button").click();
  const acceptBody = await acceptCommit.then((request) => request.postDataJSON());
  expect(acceptBody.kind).toBe("ck.invite.accept");
  await expect(page.getByTestId("invite-row")).toContainText("accepted");

  const cancelCommit = page.waitForRequest("**/_cokret/self/events");
  await page.getByTestId("cancel-invite-button").click();
  const cancelBody = await cancelCommit.then((request) => request.postDataJSON());
  expect(cancelBody.kind).toBe("ck.invite.cancel");
  await expect(page.getByTestId("invite-row")).toContainText("canceled");

  await page.getByTestId("rotate-space-epoch").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("rotated to epoch");

  await page.getByTestId("archive-space-button").click();
  await expect(page.getByTestId("space-admin-status")).toContainText("archived");
});

test("server switcher hides custom endpoint controls", async ({ page }) => {
  await openServerSwitcher(page);

  await expect(page.getByTestId("server-url-input")).toHaveCount(0);
  await expect(page.getByTestId("connect-button")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Services" })).toHaveCount(0);
});

test("server switcher keeps only server choices after expand", async ({ page }) => {
  await openServerSwitcher(page);

  await expect(page.getByTestId("server-switch-menu")).toBeVisible();
  await expect(page.getByTestId("server-option")).toHaveCount(1);
  await expect(page.getByTestId("server-switch-menu")).toContainText("https://local.host");
  await expect(page.getByTestId("server-switch-menu")).not.toContainText("Current data home");
  await expect(page.getByTestId("principal-context")).not.toContainText("Refresh");
});

test("visual smoke renders core client pages on desktop and mobile", async ({ page }) => {
  await refreshServer(page);
  for (const [route, testId] of [
    ["/", "dashboard-panel"],
    ["/kanban", "kanban-panel"],
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
