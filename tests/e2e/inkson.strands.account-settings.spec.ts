import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  latestTestId,
  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  openSettings,
  writeSessionGrantInjection,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("topbar account menu shows identity and sync state", async ({ page }) => {
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await page.getByTestId("account-menu-button").click();
  await expect(page.getByTestId("account-menu")).toContainText("did:web:alice.example");
  await expect(page.getByTestId("account-menu")).toContainText("ak:device:");
  await expect(page.getByTestId("account-menu-copy-did")).toBeVisible();
  await expect(page.getByTestId("account-menu-copy-device")).toBeVisible();
  await page.getByTestId("account-menu-copy-did").click();
  await expect(page.getByTestId("account-menu-session-state")).toHaveText("DID copied");
  await expect(page.getByTestId("account-menu-frontier")).toContainText("ak:event:e2e");
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

  await expect(latestTestId(page, "account-menu-handles")).toContainText("@alice.example:local.host");
  await expect(latestTestId(page, "account-menu-handles")).not.toContainText("unavailable");
  expect(handleDirectoryRequests).toBe(0);
  expect(pageErrors).toEqual([]);
});

test("account menu keeps account handle when handle directory returns an empty page", async ({
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

  await expect(latestTestId(page, "account-menu-handles")).toContainText("@alice:local.host");
  await expect(latestTestId(page, "account-menu-handles")).not.toContainText("No handles published");
  expect(handleDirectoryRequests).toBeGreaterThan(0);
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

  await expect(page.getByTestId("settings-avatar-crop-editor")).toBeVisible();
  await page.getByTestId("settings-avatar-crop-zoom").evaluate((element) => {
    const input = element as HTMLInputElement;
    input.value = "150";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });

  const uploadRequest = page.waitForRequest("**/_arkret/self/blob/upload");
  const profileRequest = page.waitForRequest("**/_arkret/self/account/profile");
  await page.getByTestId("settings-avatar-upload-cropped").click();

  const upload = await uploadRequest;
  expect(upload.headers()["content-type"]).toContain("image/jpeg");
  expect(upload.postDataBuffer()?.length ?? 0).toBeGreaterThan(100);

  const profileBody = await profileRequest.then((request) => request.postDataJSON());
  expect(profileBody.patch.avatar_blob_ref).toBe(
    "ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
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
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "system");

  const toggle = page.getByTestId("theme-toggle");
  await expect(toggle).toHaveAttribute("title", "Switch to light theme");
  await toggle.click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-theme", "light");
  await expect(toggle).toHaveAttribute("title", "Switch to night theme");
});

test("settings MIMI facade discovers drafts and runs interop actions", async ({ page }) => {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-mimi").click();
  await expect(page.getByTestId("mimi-interop-panel")).toBeVisible();
  await expect(page.getByTestId("mimi-draft-pinning")).toHaveCount(0);

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
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    "proxy-download ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
  );

  const submit = page.waitForRequest("**/_arkret/open/mimi/strands/01JSMIMI/messages");
  await page.getByTestId("mimi-submit-message").click();
  expect((await submit).postDataJSON().source_format).toBe("text/markdown;variant=GFM-MIMI");
  await expect(page.getByTestId("mimi-action-receipt")).toContainText("submit-message mimi-msg-e2e");
});

test("account settings split account/server info and surface personal agents", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  // Account information is its own section (identity + invite locator).
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("settings-nav-item-account")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();
  await expect(page.getByTestId("settings-account-did")).toBeVisible();
  await expect(page.getByTestId("settings-nav-item-recovery")).toBeVisible();

  // Server information is a separate section (transport context).
  await page.getByTestId("settings-nav-item-server").click();
  await expect(page).toHaveURL(/\/settings\/server$/);
  await expect(page.getByTestId("transport-invariant")).toBeVisible();

  // My Agents lives inside account settings — no feature flag — and
  // exposes the CKP-0010 participation policy editor.
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
  await expect(page).toHaveURL(/\/settings\/agents$/);
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await expect(page.getByTestId("agent-admin-list").getByText(/\d+ shown/)).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-toggle-inactive-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-filter-all")).toHaveAttribute(
    "aria-selected",
    "true",
  );
  await expect(page.getByTestId("agent-admin-filter-active")).toBeVisible();
  await expect(page.getByTestId("agent-admin-filter-pending")).toBeVisible();
  await expect(page.getByTestId("agent-admin-filter-inactive")).toBeVisible();
  await expect.poll(() => agentListRequests, { timeout: 5_000 }).toBe(1);
  await page.waitForTimeout(750);
  expect(agentListRequests).toBe(1);
  await page.getByTestId("agent-admin-create-open-button").click();
  await expect(page.getByTestId("agent-admin-provision")).toBeVisible();
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
  await expect(page.getByTestId("agent-admin-service-scope-row")).toHaveCount(4);
  const provisionRequest = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_arkret/self/agents",
  );
  await page.getByTestId("agent-admin-provision-button").click();
  const provisionBody = (await provisionRequest).postDataJSON();
  expect(provisionBody.requested_scope.actions).toEqual([
    "ak.self.events.stream.subscribe",
    "ak.self.events.query.scan",
    "ak.self.events.command.submit",
  ]);
  expect(JSON.stringify(provisionBody.requested_scope.resources)).not.toContain("realm_id");
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-card")).toContainText("Ready");
  await expect(page.getByTestId("agent-admin-pairing-qr")).toBeVisible();
  await expect(page.getByTestId("agent-admin-copy-pairing-link-button")).toBeVisible();
  await expect(page.getByTestId("agent-admin-copy-pairing-link-button")).toBeEnabled();
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
  await expect(page.getByTestId("agent-state-badge")).toHaveAttribute(
    "data-state",
    "pending_runtime_key",
  );
});

test("expired personal agent pairing shows pair-again guidance", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(page.getByTestId("personal-agent-admin")).toBeVisible();
  await page.getByTestId("agent-admin-create-open-button").click();
  await page.getByTestId("agent-admin-provision-button").click();
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  await expect(page.getByTestId("agent-admin-pairing-card")).toContainText("Expired");
  await expect(page.getByTestId("agent-admin-pairing-bootstrap-json")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-runtime-key-request-json")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-pairing-expired-message")).toContainText(
    "pair again",
  );
  await page.getByTestId("agent-admin-create-replacement-button").click();
  await expect(page.getByTestId("agent-admin-provision")).toBeVisible();
  await expect(page.getByTestId("agent-admin-provision-display-name")).toHaveValue(
    "my-personal-agent",
  );
  await expect(page.getByTestId("agent-admin-provision-agent-slug")).toHaveValue("summary");
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
