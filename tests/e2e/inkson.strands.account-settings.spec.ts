import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  latestTestId,
  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  openSettings,
  seedLocalRecoveryKeyMetadata,
  writeSessionGrantInjection,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("topbar account menu shows profile identity and current device", async ({ page }) => {
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu")).toContainText("did:web:alice.example");
  await expect(page.getByTestId("account-menu")).toContainText("ak:device:");
  await expect(page.getByTestId("account-menu-copy-did")).toBeVisible();
  await expect(page.getByTestId("account-menu-copy-device")).toBeVisible();
  await page.getByTestId("account-menu-copy-did").click();
  await expect(page.getByTestId("account-menu-display-name")).toHaveText("inkson");
  await expect(page.getByTestId("account-menu-avatar")).toHaveClass(/generated-avatar/);
  await expect(page.getByTestId("account-menu-avatar").locator("svg")).toBeVisible();
  await expect(page.getByTestId("account-menu-device-name")).toHaveText("Current device");
  await expect(page.getByTestId("account-menu-device")).toHaveAttribute(
    "title",
    "ak:device:01964137-0000-7000-8000-0000000000a1",
  );
  await expect(page.getByTestId("account-menu-session-state")).toHaveCount(0);
  await expect(page.getByTestId("account-menu-settings-qr")).toBeVisible();
  await expect(page.getByTestId("account-menu-settings")).toBeVisible();
  const menuBox = await page.getByTestId("account-menu").boundingBox();
  const qrBox = await page.getByTestId("account-menu-settings-qr").boundingBox();
  const refreshBox = await page.getByTestId("account-menu-session-refresh").boundingBox();
  const logoutBox = await page.getByTestId("account-menu-session-logout").boundingBox();
  const settingsBox = await page.getByTestId("account-menu-settings").boundingBox();
  expect(menuBox).not.toBeNull();
  expect(qrBox).not.toBeNull();
  expect(refreshBox).not.toBeNull();
  expect(logoutBox).not.toBeNull();
  expect(settingsBox).not.toBeNull();
  expect(qrBox!.x + qrBox!.width).toBeGreaterThan(menuBox!.x + menuBox!.width - 48);
  expect(Math.abs(refreshBox!.y - settingsBox!.y)).toBeLessThan(2);
  expect(Math.abs(logoutBox!.y - settingsBox!.y)).toBeLessThan(2);
  expect(refreshBox!.x).toBeLessThan(logoutBox!.x);
  expect(logoutBox!.x).toBeLessThan(settingsBox!.x);
  await page.getByTestId("account-menu-settings-qr").click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(page.getByTestId("settings-panel")).toBeVisible();
});

test("account menu falls back to account localpart when handle directory lookup is not advertised", async ({
  page,
}) => {
  let handleDirectoryRequests = 0;
  const pageErrors: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_arkret/find/directory/list-handles-for-subject") {
      handleDirectoryRequests += 1;
    }
  });
  page.on("pageerror", (error) => {
    pageErrors.push(error.message);
  });

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "account-menu-button").click();

  await expect(latestTestId(page, "account-menu-handles")).toHaveText("@alice:local.host");
  await expect(latestTestId(page, "account-menu-handles")).not.toContainText("unavailable");
  expect(handleDirectoryRequests).toBe(0);
  expect(pageErrors).toEqual([]);
});

test("account menu keeps the viewer fallback when the handle directory returns an empty page", async ({
  page,
}) => {
  let handleDirectoryRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_arkret/find/directory/list-handles-for-subject") {
      handleDirectoryRequests += 1;
    }
  });

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "account-menu-button").click();

  await expect(latestTestId(page, "account-menu-handles")).toHaveText("@alice:local.host");
  expect(handleDirectoryRequests).toBeGreaterThan(0);
});

test("settings language selector offers only English and Chinese", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await expect(page.getByTestId("language-settings")).toBeVisible();
  await page.getByTestId("theme-night").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "night");
  await page.getByTestId("theme-system").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  await expect(page.getByTestId("language-ar")).toHaveCount(0);
  await expect(page.getByTestId("current-language")).toHaveCount(0);
  await page.getByTestId("language-zh").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-direction", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "zh");
  await expect(page.getByTestId("text-direction")).toContainText("ltr");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "zh");

  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId("language-en").click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("dir", "ltr");
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", "en");
});

test("account invite locator stays contained and follows the active locale", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("settings-invite-locator-url")).not.toHaveValue("");

  const share = page.getByTestId("settings-invite-locator-url-pane");
  const qr = page.getByTestId("settings-invite-locator-qr");
  const qrPane = share.locator(".qr-share-qr-pane");
  const urlPane = share.locator(".qr-share-url-pane");

  await page.setViewportSize({ width: 1565, height: 858 });
  const wideQrBox = await qr.boundingBox();
  const wideQrPaneBox = await qrPane.boundingBox();
  const wideUrlPaneBox = await urlPane.boundingBox();
  expect(wideQrBox).not.toBeNull();
  expect(wideQrPaneBox).not.toBeNull();
  expect(wideUrlPaneBox).not.toBeNull();
  expect(wideQrBox!.x).toBeGreaterThanOrEqual(wideQrPaneBox!.x);
  expect(wideQrBox!.x + wideQrBox!.width).toBeLessThanOrEqual(
    wideQrPaneBox!.x + wideQrPaneBox!.width + 1,
  );
  expect(wideUrlPaneBox!.x).toBeGreaterThanOrEqual(
    wideQrPaneBox!.x + wideQrPaneBox!.width - 1,
  );

  await page.setViewportSize({ width: 640, height: 900 });
  const narrowQrPaneBox = await qrPane.boundingBox();
  const narrowUrlPaneBox = await urlPane.boundingBox();
  expect(narrowQrPaneBox).not.toBeNull();
  expect(narrowUrlPaneBox).not.toBeNull();
  expect(narrowUrlPaneBox!.y).toBeGreaterThanOrEqual(
    narrowQrPaneBox!.y + narrowQrPaneBox!.height - 1,
  );

  await page.setViewportSize({ width: 1565, height: 858 });
  await gotoAndDismissRecovery(page, "/settings/theme");
  await page.getByTestId("language-zh").click();
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("realm-title")).toHaveText("设置");
  await expect(page.getByTestId("sidebar")).toContainText("主页");
  await expect(page.getByTestId("sidebar")).toContainText("文件");
  await expect(page.getByTestId("realm-sidebar-search-input")).toHaveAttribute(
    "placeholder",
    "搜索领域",
  );
  await expect(page.getByTestId("settings-avatar-card")).toContainText("账号身份");
  await expect(page.getByTestId("settings-invite-locator-card")).toContainText(
    "安全邀请链接",
  );
  await expect(page.getByTestId("settings-invite-locator-card")).toContainText(
    "15 分钟后过期",
  );
  await expect(page.getByTestId("settings-invite-locator-card")).toContainText(
    "扫描二维码",
  );
  await expect(page.getByTestId("settings-invite-locator-card")).toContainText(
    "或使用此链接",
  );
  await expect(page.getByTestId("settings-invite-locator-card")).toContainText(
    "复制链接",
  );
});

test("settings avatar upload crops local image before publishing profile URL", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();
  await expect(page.getByTestId("settings-avatar-upload-label")).toBeVisible();
  await expect(page.getByTestId("settings-avatar-input")).toBeHidden();

  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
    "base64",
  );
  await page.getByTestId("settings-avatar-input").setInputFiles({
    name: "avatar.png",
    mimeType: "image/png",
    buffer: png,
  });

  await expect(page.getByTestId("settings-avatar-crop-stage")).toBeVisible();
  await page.getByTestId("settings-avatar-crop-zoom").evaluate((element) => {
    const input = element as HTMLInputElement;
    input.value = "150";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const uploadRequest = page.waitForRequest("**/_arkret/self/blob/upload");
  const profileRequest = page.waitForRequest("**/_arkret/self/account/profile");
  await page.getByTestId("settings-avatar-upload-cropped").click();

  const upload = await uploadRequest;
  expect(upload.headers()["content-type"]).toContain("multipart/form-data");
  expect(upload.postDataBuffer()?.length ?? 0).toBeGreaterThan(100);
  expect(upload.postData() ?? "").toContain("Content-Type: image/jpeg");

  const profileBody = await profileRequest.then((request) => request.postDataJSON());
  expect(profileBody.patch.avatar_blob_ref).toBe(
    "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
  );
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
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "night");

  const toggle = page.getByTestId("theme-toggle");
  await expect(toggle).toHaveAttribute("title", "Switch to light theme");
  await toggle.click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "light");
  await expect(toggle).toHaveAttribute("title", "Switch to night theme");
});

test("settings MIMI facade discovers drafts and runs interop actions", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/mimi");
  await expect(page.getByTestId("mimi-interop-panel")).toBeVisible();
  await expect(page.getByTestId("mimi-draft-pinning")).toHaveCount(0);

  await page.getByTestId("mimi-refresh-directory").click();
  await expect(page.getByTestId("mimi-directory-result")).toContainText("mimi://mimi.example.com");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("submit_message");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("identifier_query");
  await expect(page.getByTestId("mimi-directory-result")).toContainText("proxy_download");

  await page.getByTestId("mimi-group-info").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    "group-info 01JSMIMI binding ak:event:01964137-0000-8000-8000-00000000d0ab proofs 0",
  );

  await page.getByTestId("mimi-identifier-query").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("identifier results 1");
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    '"mimi_uri":"mimi://remote.example/alice"',
  );

  await page.getByTestId("mimi-proxy-download").click();
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    "proxy-download https://mimi.example.com/proxy/ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460 headers 1",
  );

  const submit = page.waitForRequest("**/_arkret/open/mimi/strands/01JSMIMI/messages");
  await page.getByTestId("mimi-submit-message").click();
  const submitBody = (await submit).postDataJSON();
  expect(submitBody.source_format).toBeUndefined();
  expect(submitBody.sender_actor_id).toBe("did:web:alice.example");
  expect(submitBody.ciphertext.content_type).toBe("application/json");
  expect(submitBody.ciphertext.ciphertext_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(submitBody.ciphertext.payload).toMatch(/^[A-Za-z0-9_-]+$/);
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    "submit-message event ak:event:01964137-0000-8000-8000-00000000d0aa rejected 0",
  );
});

test("account settings split account/server info and surface personal agents", async ({ page }) => {
  const failedApiResponses: string[] = [];
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (url.pathname.startsWith("/_arkret/") && response.status() >= 400) {
      failedApiResponses.push(
        `${response.request().method()} ${url.pathname}${url.search} ${response.status()}`,
      );
    }
  });
  await writeSessionGrantInjection(page);
  await seedLocalRecoveryKeyMetadata(page);
  await dismissBlockingRecoveryModal(page);

  // Account information is its own section (identity + invite locator).
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("settings-nav-item-account")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();
  await expect(page.getByTestId("settings-account-did")).toHaveText("did:web:alice.example");
  await expect(page.getByTestId("settings-account-did")).not.toHaveText("@alice:local.host");
  const inviteLocatorUrl = page.getByTestId("settings-invite-locator-url");
  const inviteLocatorQr = page.getByTestId("settings-invite-locator-qr");
  const inviteLocatorUrlPane = page.getByTestId("settings-invite-locator-url-pane");
  await expect(inviteLocatorUrl).toHaveJSProperty("tagName", "TEXTAREA");
  await expect(inviteLocatorUrl).toHaveCSS("white-space", "pre-wrap");
  await expect(inviteLocatorUrl).not.toHaveValue("");
  const qrBox = await inviteLocatorQr.boundingBox();
  const urlPaneBox = await inviteLocatorUrlPane.boundingBox();
  expect(qrBox).not.toBeNull();
  expect(urlPaneBox).not.toBeNull();
  expect(urlPaneBox!.width).toBeGreaterThan(0);
  expect(urlPaneBox!.height).toBeGreaterThan(0);
  await page.setViewportSize({ width: 640, height: 900 });
  await expect(inviteLocatorQr).toBeVisible();
  await expect(inviteLocatorUrlPane).toBeVisible();
  const narrowOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(narrowOverflow).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 1280, height: 720 });
  await expect(page.getByTestId("settings-nav-item-recovery")).toBeVisible();

  // Server information is a separate section (transport context).
  await page.getByTestId("settings-nav-item-server").click();
  await expect(page).toHaveURL(/\/settings\/server\?filter=$/);
  await expect(page.getByTestId("transport-invariant")).toBeVisible();

  // My Agents lives inside account settings — no feature flag — and
  // exposes the AKP-0010 participation policy editor.
  let agentListRequests = 0;
  page.on("request", (request) => {
    if (
      request.method() === "GET" &&
      new URL(request.url()).pathname === "/_arkret/self/agents"
    ) {
      agentListRequests += 1;
    }
  });
  await page.getByTestId("settings-nav-item-agents").click();
  await expect(page).toHaveURL(/\/settings\/agents\?filter=$/);
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await expect(page.getByTestId("agent-admin-list").getByText(/\d+ shown/)).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-toggle-inactive-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-filter-all")).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByTestId("agent-admin-filter-active")).toBeVisible();
  await expect(page.getByTestId("agent-admin-filter-paused")).toBeVisible();
  await expect(page.getByTestId("agent-admin-filter-deactivated")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-row")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-row").filter({ hasText: "deactivated" })).toHaveCount(0);
  await page.getByTestId("agent-admin-filter-paused").click();
  await expect(page).toHaveURL(/\/settings\/agents\?filter=paused$/);
  await page.getByTestId("agent-admin-filter-all").click();
  await expect(page).toHaveURL(/\/settings\/agents\?filter=all$/);
  await expect.poll(() => agentListRequests, { timeout: 5_000 }).toBe(1);
  await page.waitForTimeout(750);
  expect(agentListRequests).toBe(1);
  await page.getByTestId("agent-admin-create-open-button").click();
  await expect(page.getByTestId("agent-admin-provision")).toBeVisible();
  await expect(page.getByTestId("agent-admin-provision-display-name")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-provision-avatar")).toBeVisible();
  await expect(page.getByTestId("agent-admin-provision-button")).toBeDisabled();
  await page.getByTestId("agent-admin-provision-agent-slug").fill("Summary");
  await expect(page.getByTestId("agent-admin-provision-agent-slug")).toHaveValue("summary");
  await expect(page.getByTestId("agent-admin-provision-avatar-preview")).toHaveClass(
    /generated-avatar/,
  );
  await expect(page.getByTestId("agent-admin-provision-avatar-preview")).toHaveAttribute(
    "aria-label",
    "Generated avatar for summary",
  );
  await expect(page.getByTestId("agent-admin-provision-avatar-preview").locator("svg")).toBeVisible();
  const agentAvatarPng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
    "base64",
  );
  await page.getByTestId("agent-admin-provision-avatar-input").setInputFiles({
    name: "agent-avatar.png",
    mimeType: "image/png",
    buffer: agentAvatarPng,
  });
  await expect(page.getByTestId("agent-admin-provision-avatar-crop-editor")).toBeVisible();
  const agentAvatarUpload = page.waitForRequest("**/_arkret/self/blob/upload");
  await page.getByTestId("agent-admin-provision-avatar-upload-cropped").click();
  await agentAvatarUpload;
  await expect(page.getByTestId("agent-admin-provision-avatar-crop-editor")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-provision-button")).toBeEnabled();
  const scrollLayout = await page.evaluate(() => {
    const root = document.documentElement;
    const workspace = document.querySelector(".workspace-body") as HTMLElement | null;
    const settingsContent = document.querySelector(
      ".settings-page .settings-content-column",
    ) as HTMLElement | null;
    const detailPane = document.querySelector(".agent-admin-detail-pane") as HTMLElement | null;
    if (workspace) {
      workspace.scrollTop = 200;
    }
    if (detailPane) {
      detailPane.scrollTop = 200;
    }
    return {
      rootOverflowY: getComputedStyle(root).overflowY,
      bodyOverflowY: getComputedStyle(document.body).overflowY,
      viewportScrollbarGap: window.innerWidth - root.clientWidth,
      detailOverflowY: detailPane ? getComputedStyle(detailPane).overflowY : null,
      detailScrollTop: detailPane?.scrollTop ?? 0,
      settingsContentOverflowY: settingsContent
        ? getComputedStyle(settingsContent).overflowY
        : null,
      settingsContentScrollTop: settingsContent?.scrollTop ?? 0,
      workspaceOverflowY: workspace ? getComputedStyle(workspace).overflowY : null,
      workspaceScrollTop: workspace?.scrollTop ?? 0,
    };
  });
  expect(scrollLayout.rootOverflowY).toBe("hidden");
  expect(scrollLayout.bodyOverflowY).toBe("hidden");
  expect(scrollLayout.viewportScrollbarGap).toBe(0);
  expect(scrollLayout.workspaceOverflowY).toBe("auto");
  expect(scrollLayout.workspaceScrollTop).toBe(0);
  expect(scrollLayout.settingsContentOverflowY).toBe("hidden");
  expect(scrollLayout.settingsContentScrollTop).toBe(0);
  expect(scrollLayout.detailOverflowY).toBe("auto");
  expect(scrollLayout.detailScrollTop).toBeGreaterThan(0);
  await expect(page.getByTestId("agent-admin-content-preset-row")).toHaveCount(5);
  await expect(page.getByTestId("agent-admin-service-scope-row")).toHaveCount(5);
  const serviceScopeCheckboxes = page.getByTestId("agent-admin-service-scope-checkbox");
  await expect(serviceScopeCheckboxes).toHaveCount(5);
  for (let index = 0; index < 4; index += 1) {
    await expect(serviceScopeCheckboxes.nth(index)).toHaveAttribute("data-state", "checked");
  }
  await expect(serviceScopeCheckboxes.nth(4)).toHaveAttribute("data-state", "unchecked");
  const provisionRequest = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_arkret/self/agents",
  );
  await page.getByTestId("agent-admin-provision-button").click();
  const provisionBody = (await provisionRequest).postDataJSON();
  expect(provisionBody.display_name).toBeUndefined();
  expect(provisionBody.slug).toBe("summary");
  expect(provisionBody.avatar_blob_ref).toBe(
    "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
  );
  expect(provisionBody.requested_scope.actions).toEqual([
    "ak.event.read",
    "ak.message.create",
    "ak.reaction.add",
    "ak.self.events.stream.subscribe",
    "ak.self.events.read.scan",
    "ak.self.events.command.submit",
    "ak.self.keys.keypackages.upload.create",
    "ak.self.keys.keypackages.command.consume",
    "ak.self.keys.keypackages.command.revoke",
    "ak.self.device_messages.query.list",
    "ak.self.device_messages.command.ack",
  ]);
  expect(JSON.stringify(provisionBody.requested_scope.resources)).not.toContain("realm_id");
  try {
    await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  } catch (error) {
    throw new Error(
      `${String(error)}\nfailed Arkret responses: ${JSON.stringify(failedApiResponses)}`,
    );
  }
  await expect(page.getByTestId("agent-admin-pairing-card")).toContainText("Awaiting runtime");
  await expect(page.getByTestId("agent-admin-pairing-qr")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-url")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-url")).not.toHaveValue("");
  await expect(page.getByTestId("agent-admin-copy-pairing-link-button")).toBeVisible();
  await expect(page.getByTestId("agent-admin-copy-pairing-link-button")).toBeEnabled();
  await page.getByTestId("agent-admin-copy-pairing-link-button").click();
  await expect(page.getByTestId("agent-admin-copy-pairing-link-button")).toHaveText("Copied");
  await expect(page.getByTestId("agent-admin-copy-pairing-link-button")).toHaveText("Copy link", {
    timeout: 3_000,
  });
  await expect(page.getByTestId("agent-admin-pairing-agent-display-name")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-code")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-request-id")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-expires-at")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-link")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-bootstrap-json")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-copy-pairing-bootstrap-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-runtime-key-approval")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-runtime-key-request-json")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-runtime-key-request-preview")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-approve-runtime-key-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-rotate-key")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-rotate-vm-input")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-rotate-key-button")).toHaveCount(0);
  await expect(page.getByText("Paste the runtime key request generated by the agent runtime")).toHaveCount(
    0,
  );
  await expect(page.getByText("Copy bootstrap")).toHaveCount(0);
  await expect(page.getByTestId("agent-state-badge")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-slug-title")).toHaveText("summary");
  await expect(page.getByTestId("agent-admin-detail-meta")).not.toContainText("Slug");
  await expect(page.getByTestId("agent-admin-get-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-row").filter({ hasText: "summary" })).toContainText(
    "Pending",
  );
  await expect(page.getByTestId("agent-admin-capabilities")).toBeVisible();
  await expect(page.getByTestId("agent-admin-content-capability-row")).toHaveCount(5);
  await expect(page.getByTestId("agent-admin-service-capability-row")).toHaveCount(5);
  await expect(page.getByTestId("agent-admin-content-capability-checkbox").nth(0)).toHaveAttribute(
    "data-state",
    "checked",
  );
  await expect(page.getByTestId("agent-admin-content-capability-checkbox").nth(1)).toHaveAttribute(
    "data-state",
    "unchecked",
  );
  await expect(page.getByTestId("agent-admin-content-capability-checkbox").nth(2)).toHaveAttribute(
    "data-state",
    "checked",
  );
  await expect(page.getByTestId("agent-admin-content-capability-checkbox").nth(3)).toHaveAttribute(
    "data-state",
    "unchecked",
  );
  await expect(page.getByTestId("agent-admin-content-capability-checkbox").nth(4)).toHaveAttribute(
    "data-state",
    "unchecked",
  );
  await expect(page.getByTestId("agent-admin-service-capability-checkbox").nth(0)).toHaveAttribute(
    "data-state",
    "checked",
  );
  await expect(page.getByTestId("agent-admin-service-capability-checkbox").nth(1)).toHaveAttribute(
    "data-state",
    "checked",
  );
  await expect(page.getByTestId("agent-admin-service-capability-checkbox").nth(2)).toHaveAttribute(
    "data-state",
    "checked",
  );
  await expect(page.getByTestId("agent-admin-service-capability-checkbox").nth(3)).toHaveAttribute(
    "data-state",
    "checked",
  );
  await expect(page.getByTestId("agent-admin-service-capability-checkbox").nth(4)).toHaveAttribute(
    "data-state",
    "unchecked",
  );
  await expect(page.getByTestId("agent-admin-grant-kind-input")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-grant-attach-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-grant-detach-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-lifecycle")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-participation-load-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pause-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-resume-button")).toHaveCount(0);

  await page.evaluate(async () => {
    const response = await fetch("/_arkret/gate/account/agent-key-pair", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        agent_id: "did:web:agents.example:summary",
        verification_method: "did:web:agents.example:summary#runtime-key-1",
        public_key: { kty: "OKP", alg: "Ed25519", key: "test" },
      }),
    });
    if (!response.ok) {
      throw new Error(`mock agent pairing failed: ${response.status}`);
    }
  });
  await page.getByTestId("agent-admin-refresh-button").click();
  await expect(
    page.getByTestId("agent-admin-row").filter({ hasText: "summary" }),
  ).toContainText("Ready", { timeout: 10_000 });
  await expect(page.getByTestId("agent-admin-pairing-card")).toHaveCount(0);

  const deactivateButton = page.getByTestId("agent-admin-deactivate-button");
  await expect(deactivateButton).toBeVisible();
  await deactivateButton.click();
  await expect(page.getByTestId("agent-admin-deactivate-modal")).toBeVisible();
  await expect(page.getByTestId("agent-admin-deactivate-confirm-button")).toBeDisabled();
  await page.getByTestId("agent-admin-deactivate-confirm-input").fill("DEACTIVATE");
  await expect(page.getByTestId("agent-admin-deactivate-confirm-button")).toBeEnabled();
  await page.getByTestId("agent-admin-deactivate-cancel-button").click();
  await expect(page.getByTestId("agent-admin-deactivate-modal")).toHaveCount(0);
});

test("agent deactivation submits controller-signed revocations before the terminal lifecycle event", async ({
  page,
}) => {
  const failedApiResponses: string[] = [];
  page.on("response", (response) => {
    const url = new URL(response.url());
    if (response.status() >= 400 && url.pathname.startsWith("/_arkret/")) {
      failedApiResponses.push(`${response.status()} ${response.request().method()} ${url.pathname}`);
    }
  });
  await gotoAndDismissRecovery(page, "/settings/agents?filter=all");
  const assistantRow = page.getByTestId("agent-admin-row").filter({ hasText: "assistant" });
  await assistantRow.click();
  const deactivateButton = page.getByTestId("agent-admin-deactivate-button");
  await expect(deactivateButton).toBeVisible();
  await deactivateButton.click();
  await page.getByTestId("agent-admin-deactivate-confirm-input").fill("DEACTIVATE");

  let deactivateRequest:
    | import("@playwright/test").Request
    | undefined;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname.endsWith("/deactivate")
    ) {
      deactivateRequest = request;
    }
  });
  await page.getByTestId("agent-admin-deactivate-confirm-button").click();
  await expect(page.getByTestId("agent-admin-last-op")).toContainText(
    /Agent deactivated permanently\.|Deactivate failed:/,
    { timeout: 60_000 },
  );
  const status = await page.getByTestId("agent-admin-last-op").innerText();
  expect(deactivateRequest).toBeDefined();
  const requestBody = deactivateRequest!.postDataJSON();
  expect(requestBody.reason).toBe("controller_deactivated");
  const lifecycleSubmission = requestBody.lifecycle_event;
  const lifecycleEvent = lifecycleSubmission.event;
  expect(lifecycleSubmission.authorization_lease).toBeDefined();
  expect(lifecycleSubmission.control_proposal_receipt).toBeDefined();
  expect(lifecycleEvent.kind).toBe("ak.self.agent.deactivate");
  expect(lifecycleEvent.realm_id).toBe(
    "ak:realm:01964137-0000-8000-8000-000000000006",
  );
  expect(lifecycleEvent.actor_id).toBe(
    "did:web:agents.example:assistant",
  );
  expect(lifecycleEvent.executed_by).toBe("did:web:alice.example");
  expect(lifecycleEvent.authorization_ref).toBe(
    "did:web:agents.example:assistant#managed-controller",
  );
  expect(lifecycleEvent.payload).toMatchObject({
    agent_id: "did:web:agents.example:assistant",
    controller_id: "did:web:alice.example",
    transition: "deactivate",
    previous_status: "active",
    reason: "controller_deactivated",
  });
  expect(lifecycleEvent.effects).toBeUndefined();
  expect(lifecycleEvent.proofs.length).toBeGreaterThan(0);
  expect(requestBody.key_revocation_events).toHaveLength(1);
  expect(requestBody.key_revocation_events[0].authorization_lease).toBeDefined();
  expect(requestBody.key_revocation_events[0].control_proposal_receipt).toBeDefined();
  expect(requestBody.key_revocation_events[0].event.kind).toBe("ak.agent.key.revoke");
  expect(requestBody.key_revocation_events[0].event.payload.key_id).toBe("runtime-key-1");
  expect(requestBody.key_revocation_events[0].event.proofs.length).toBeGreaterThan(0);
  expect(requestBody.capability_revocation_events).toEqual([]);
  expect(status, failedApiResponses.join("\n")).not.toContain("Deactivate failed:");

  await expect(page.getByTestId("agent-admin-last-op")).toContainText(
    "Agent deactivated permanently.",
    { timeout: 15_000 },
  );
  await expect(page.getByTestId("agent-admin-deactivate-modal")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-deactivate-button")).toHaveCount(0);
});

test("deactivated personal agents are available only through the audit deep link", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/agents?filter=deactivated");
  await expect(page).toHaveURL(/\/settings\/agents\?filter=deactivated$/);
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await expect(page.getByTestId("agent-admin-filter-deactivated")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-row")).toHaveCount(1);
  await expect(page.getByTestId("agent-admin-row")).toContainText("deactivated");
  await expect(page.getByTestId("agent-admin-row")).not.toContainText("Deactivated Agent");
  await expect(page.getByTestId("agent-admin-row")).toContainText("Deactivated");
  await expect(page.getByTestId("agent-state-badge")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-deactivated-terminal-note")).toBeVisible();
});

test("active personal agents never expose stale pairing credentials", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();

  await page.getByTestId("agent-admin-row").filter({ hasText: "assistant" }).click();
  await expect(page.getByTestId("agent-admin-enabled-switch")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-card")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-qr")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-url")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-renew-pairing-button")).toHaveCount(0);

  // Two orthogonal axes (key-management.md §3.6.1): the derived runtime
  // readiness badge shows Ready, and an active keyed agent can replace its
  // runtime directly — the forced-pause gate and its guidance are gone.
  await expect(page.getByTestId("agent-admin-runtime-state-badge")).toContainText("Ready");
  await expect(page.getByTestId("agent-admin-replace-runtime-guidance")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-replace-runtime-button")).toBeVisible();

  // Replace runtime asks for explicit confirmation stating the atomic-revoke
  // fact; the lifecycle switch is never interlocked with the open replacement.
  await page.getByTestId("agent-admin-replace-runtime-button").click();
  await expect(page.getByTestId("agent-admin-replace-runtime-confirm")).toContainText(
    "atomically revokes",
  );
  await expect(page.getByTestId("agent-admin-enabled-switch")).toBeEnabled();

  const renewRequestPromise = page.waitForRequest((request) =>
    request
      .url()
      .endsWith(
        "/_arkret/self/agents/did%3Aweb%3Aagents.example%3Aassistant/renew-pairing",
      ),
  );
  await page.getByTestId("agent-admin-replace-runtime-confirm-button").click();
  await renewRequestPromise;
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  // Lifecycle intent is preserved: the agent stays active with no forced pause
  // and no resume, while the replacement handle is open.
  await expect(page.getByTestId("agent-admin-enabled-switch")).toBeChecked();
  await expect(page.getByTestId("agent-admin-enabled-switch")).toBeEnabled();
});

test("expired personal agent pairing renews in place with a fresh handle", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await page.getByTestId("agent-admin-row").filter({ hasText: "summary" }).click();
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-card")).toContainText("Expired");
  await expect(page.getByTestId("agent-admin-pairing-bootstrap-json")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-runtime-key-request-json")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-expired-message")).toContainText(
    "pair again",
  );

  // Pair again renews pairing on the SAME agent: no create form, no
  // replacement principal, and the card returns to awaiting a runtime with a fresh
  // QR + deep link carrying the renewed handle.
  await page.getByTestId("agent-admin-renew-pairing-button").click();
  await expect(page.getByTestId("agent-admin-provision")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-card")).toContainText("Awaiting runtime");
  await expect(page.getByTestId("agent-admin-pairing-expired-message")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-qr")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-url")).not.toHaveValue("");
  await expect(
    page.getByTestId("agent-admin-row").filter({ hasText: "summary" }),
  ).toHaveCount(1);
  await expect(page.getByTestId("agent-admin-last-op")).toContainText("Pairing renewed");
});

test("diagnostic and preview surfaces stay behind clear user-facing states", async ({ page }) => {
  await page.goto("/directory", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("directory-panel")).toBeVisible();
  await expect(page.getByTestId("directory-three-axes-banner")).not.toHaveAttribute("open", "");

  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("call-panel")).toBeVisible();
  await expect(page.getByTestId("deferred-feature-gate")).toHaveCount(0);
  await expect(page.getByTestId("call-start-voice-button")).toBeAttached();
  await expect(page.getByTestId("call-start-group-button")).toBeAttached();
});
