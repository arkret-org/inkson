import { expect, test } from "@playwright/test";
import {
  CURRENT_ASSISTANT_ACCOUNT_ID,
  CURRENT_ASSISTANT_PCR,
} from "./mockArkretApi";
import {
  registerStrandsBeforeEach,
  CURRENT_PRINCIPAL_CORE_ID,
  CURRENT_PRINCIPAL_DID,
  CURRENT_ACCOUNT_ACTOR_ID,
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
  await expect(page.getByTestId("account-menu-did")).toHaveAttribute(
    "title",
    CURRENT_PRINCIPAL_CORE_ID,
  );
  await expect(page.getByTestId("account-menu-did")).toHaveText(
    /^ak:did_core:webvh:.+\.\.\..+$/,
  );
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

test("account menu keeps the viewer fallback handle", async ({
  page,
}) => {
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({ timeout: 120_000 });
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await latestTestId(page, "account-menu-button").click();

  await expect(latestTestId(page, "account-menu-handles")).toHaveText("alice:local.host");
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
  await expect(page.getByTestId("realm-sidebar-tab-collaboration")).toHaveText("协作");
  await expect(page.getByTestId("realm-sidebar-tab-direct")).toHaveText("联系人");
  await expect(page.getByTestId("realm-sidebar-search-input")).toHaveAttribute(
    "placeholder",
    "搜索 Realm",
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

test("settings avatar upload fails closed before profile publication without durable authority", async ({ page }) => {
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
  let profileRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_arkret/self/account/profile") {
      profileRequests += 1;
    }
  });
  await page.getByTestId("settings-avatar-upload-cropped").click();

  const upload = await uploadRequest;
  expect(upload.headers()["content-type"]).toContain("multipart/form-data");
  expect(upload.postDataBuffer()?.length ?? 0).toBeGreaterThan(100);
  expect(upload.postData() ?? "").toContain("Content-Type: image/jpeg");

  await expect(page.getByTestId("settings-avatar-card")).toContainText(
    "profile update requires durable accepted PCR authority evidence",
  );
  expect(profileRequests).toBe(0);
  await expect(page.getByTestId("settings-avatar-crop-editor")).toBeHidden();
});

test("avatar file replacement and cancellation ignore late reads", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/account");
  // Dioxus 0.7 WebFileData uses FileReader.readAsArrayBuffer, not Blob.arrayBuffer.
  await page.evaluate(() => {
    const original = FileReader.prototype.readAsArrayBuffer;
    const pending: Array<() => Promise<void>> = [];
    (window as any).__avatarReads = pending;
    FileReader.prototype.readAsArrayBuffer = function (blob: Blob) {
      if (blob instanceof File && blob.name.startsWith("delayed-")) {
        pending.push(() => new Promise<void>((resolve) => {
          this.addEventListener("loadend", () => resolve(), { once: true });
          original.call(this, blob);
        }));
      } else {
        original.call(this, blob);
      }
    };
  });
  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==",
    "base64",
  );
  const input = page.getByTestId("settings-avatar-input");
  await input.setInputFiles({ name: "delayed-invalid.png", mimeType: "image/png", buffer: Buffer.from("invalid image") });
  await expect(page.getByTestId("settings-avatar-read-cancel")).toBeVisible();
  await input.setInputFiles({ name: "replacement.png", mimeType: "image/png", buffer: png });
  await expect(page.getByTestId("settings-avatar-source-size")).toContainText("1 x 1");
  const latestStatus = await page.getByTestId("settings-avatar-upload-progress").textContent();
  await page.evaluate(() => (window as any).__avatarReads.shift()());
  // Let FileReader's load event and the subsequent Dioxus render settle.
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(page.getByTestId("settings-avatar-source-size")).toContainText("1 x 1");
  await expect(page.getByTestId("settings-avatar-upload-progress")).toHaveText(latestStatus!);
  await page.getByTestId("settings-avatar-crop-cancel").click();

  await input.setInputFiles({ name: "delayed-cancel.png", mimeType: "image/png", buffer: png });
  await expect(page.getByTestId("settings-avatar-read-cancel")).toBeVisible();
  await page.getByTestId("settings-avatar-read-cancel").click();
  await page.evaluate(() => (window as any).__avatarReads.shift()());
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(page.getByTestId("settings-avatar-crop-editor")).toHaveCount(0);
  await expect(page.getByTestId("settings-avatar-upload-progress")).toHaveCount(0);

  await input.setInputFiles({ name: "fresh.png", mimeType: "image/png", buffer: png });
  await expect(page.getByTestId("settings-avatar-crop-stage")).toBeVisible();
  // Replay the original inline declarations on this DOM. Computed appearance
  // must match the extracted feature classes, including tokens and cascade.
  const replay = await page.evaluate(() => {
    const probes: Array<[string, string, string[]]> = [
      [".settings-avatar-crop-dialog", "position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%); z-index: var(--layer-modal, 300); display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 16px; align-items: center; width: min(640px, calc(100vw - 32px)); max-height: calc(100vh - 48px); overflow: auto; padding: 18px; border: 1px solid var(--border, #333); border-radius: var(--radius-lg, 12px); background: var(--surface-solid, var(--surface, #1a1d22)); box-shadow: 0 0 0 9999px rgba(20, 22, 30, 0.55), var(--shadow-lg, 0 24px 56px rgba(0, 0, 0, 0.22));", ["position", "left", "top", "transform", "z-index", "display", "grid-template-columns", "gap", "align-items", "width", "max-height", "overflow", "padding", "border", "border-radius", "background-color", "box-shadow"]],
      [".settings-avatar-crop-stage", "position: relative; width: min(180px, 70vw); aspect-ratio: 1; justify-self: center; border-radius: 50%; overflow: hidden; border: 1px solid var(--border-default, #333); background: var(--bg-elevated, #1a1d22);", ["position", "width", "aspect-ratio", "justify-self", "border-radius", "overflow", "border", "background-color"]],
      [".settings-avatar-crop-controls", "display: grid; gap: 10px;", ["display", "gap"]],
      [".settings-avatar-crop-image", "width: 100%; height: 100%; object-fit: cover; transform-origin: center;", ["width", "height", "object-fit", "transform-origin", "transform"]],
      [".settings-avatar-file-input", "display: none;", ["display"]],
    ];
    return probes.map(([selector, legacy, properties]) => {
      const element = document.querySelector<HTMLElement>(selector)!;
      const before = properties.map((property) => getComputedStyle(element).getPropertyValue(property));
      const saved = element.getAttribute("style");
      element.style.cssText += legacy;
      const after = properties.map((property) => getComputedStyle(element).getPropertyValue(property));
      if (saved === null) element.removeAttribute("style"); else element.setAttribute("style", saved);
      return { selector, before, after };
    });
  });
  for (const probe of replay) expect(probe.after, probe.selector).toEqual(probe.before);
  // Invalid replacement must discard the previous valid crop.
  await input.setInputFiles({ name: "invalid.png", mimeType: "image/png", buffer: Buffer.from("invalid image") });
  await expect(page.getByTestId("settings-avatar-crop-editor")).toHaveCount(0);
  await expect(page.getByTestId("settings-avatar-upload-progress")).not.toHaveText(latestStatus!);

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
  // `sender_actor_id` is an `ActorId`: the account variant carries the complete
  // AccountId, and no comparison may fall back to a bare principal id.
  expect(submitBody.sender_actor_id).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
  expect(submitBody.ciphertext.content_type).toBe("application/json");
  expect(submitBody.ciphertext.ciphertext_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  expect(submitBody.ciphertext.payload).toMatch(/^[A-Za-z0-9_-]+$/);
  await expect(page.getByTestId("mimi-action-receipt")).toContainText(
    "submit-message event ak:event:AX-AFSYZHl0U2MQP-Ng7mU-aOm_Flhf0pVBoHYUK6Shg rejected 0",
  );
});

test("MIMI concurrent actions keep separate pending states and late results", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/mimi");
  let releaseQuery!: () => void;
  const heldQuery = new Promise<void>((resolve) => { releaseQuery = resolve; });
  let queryRequests = 0;
  await page.route("**/_arkret/open/mimi/identifiers/query", async (route) => {
    queryRequests += 1;
    await heldQuery;
    await route.fallback();
  });
  await page.getByTestId("mimi-identifier-query").click();
  await expect(page.getByTestId("mimi-identifier-query")).toBeDisabled();
  await expect(page.getByTestId("mimi-submit-message")).toBeEnabled();
  await expect(page.getByTestId("mimi-proxy-download")).toBeEnabled();
  // A duplicate DOM click must not launch another query while pending.
  await page.getByTestId("mimi-identifier-query").evaluate((element) => (element as HTMLElement).click());
  await page.getByTestId("mimi-submit-message").click();
  await page.getByTestId("mimi-proxy-download").click();
  await expect(page.getByTestId("mimi-submit-receipt")).toContainText("submit-message event");
  await expect(page.getByTestId("mimi-proxy-receipt")).toContainText("proxy-download https://");
  const submitted = await page.getByTestId("mimi-submit-receipt").textContent();
  const downloaded = await page.getByTestId("mimi-proxy-receipt").textContent();
  releaseQuery();
  await expect(page.getByTestId("mimi-query-receipt")).toContainText("identifier results 1");
  await expect(page.getByTestId("mimi-identifier-query")).toBeEnabled();
  await expect(page.getByTestId("mimi-submit-receipt")).toHaveText(submitted!);
  await expect(page.getByTestId("mimi-proxy-receipt")).toHaveText(downloaded!);
  expect(queryRequests).toBe(1);
});

test("account settings split account/server info and surface Agents", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await seedLocalRecoveryKeyMetadata(page);
  await dismissBlockingRecoveryModal(page);

  // Account information is its own section (identity + invite locator).
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(page.getByTestId("settings-panel")).toBeVisible({ timeout: 120_000 });
  await expect(page.getByTestId("settings-nav-item-account")).toHaveAttribute("aria-current", "page");
  await expect(page.getByTestId("settings-avatar-card")).toBeVisible();
  await expect(page.getByTestId("settings-account-did")).toHaveText(
    CURRENT_PRINCIPAL_CORE_ID,
  );
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
  const accountCardLayout = await page.evaluate(() => {
    const profile = document.querySelector<HTMLElement>("[data-testid='settings-profile-fields']");
    const displayName = document.querySelector<HTMLInputElement>(
      "[data-testid='settings-profile-display-name']",
    );
    const displayNameLabel = displayName?.closest("label")?.querySelector<HTMLElement>("span");
    const bio = document.querySelector<HTMLTextAreaElement>("[data-testid='settings-profile-bio']");
    const avatar = document.querySelector<HTMLElement>(".settings-avatar-actions");
    const identity = document.querySelector<HTMLElement>(".settings-account-identity-grid");
    if (!profile || !displayName || !displayNameLabel || !bio || !avatar || !identity) {
      return null;
    }
    const profileBox = profile.getBoundingClientRect();
    const displayNameBox = displayName.getBoundingClientRect();
    const displayNameLabelBox = displayNameLabel.getBoundingClientRect();
    const bioBox = bio.getBoundingClientRect();
    const avatarBox = avatar.getBoundingClientRect();
    const identityBox = identity.getBoundingClientRect();
    return {
      profileColumn: getComputedStyle(profile).gridColumnStart,
      avatarColumn: getComputedStyle(avatar).gridColumnStart,
      identityColumn: getComputedStyle(identity).gridColumnStart,
      profileLeft: profileBox.left,
      avatarRight: avatarBox.right,
      identityLeft: identityBox.left,
      identityTop: identityBox.top,
      profileBottom: profileBox.bottom,
      displayNameLeft: displayNameBox.left,
      bioLeft: bioBox.left,
      labelHeight: displayNameLabelBox.height,
      labelLineHeight: Number.parseFloat(getComputedStyle(displayNameLabel).lineHeight),
    };
  });
  expect(accountCardLayout).not.toBeNull();
  expect(accountCardLayout!.profileColumn).toBe("2");
  expect(accountCardLayout!.avatarColumn).toBe("1");
  expect(accountCardLayout!.identityColumn).toBe("2");
  expect(accountCardLayout!.profileLeft).toBeGreaterThanOrEqual(accountCardLayout!.avatarRight);
  expect(accountCardLayout!.identityLeft).toBe(accountCardLayout!.profileLeft);
  expect(accountCardLayout!.identityTop).toBeGreaterThanOrEqual(accountCardLayout!.profileBottom);
  expect(accountCardLayout!.displayNameLeft).toBe(accountCardLayout!.bioLeft);
  expect(accountCardLayout!.labelHeight).toBeLessThanOrEqual(
    accountCardLayout!.labelLineHeight + 1,
  );

  // Server information is a separate section (transport context).
  await page.getByTestId("settings-nav-item-server").click();
  await expect(page).toHaveURL(/\/settings\/server\?filter=$/);
  await expect(page.getByTestId("transport-invariant")).toBeVisible();

  // My Agents lives inside account settings — no feature flag — and
  // exposes the participation policy editor.
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
  await expect(page.getByTestId("agent-admin")).toBeVisible();
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
    const realm = document.querySelector(".realm-body") as HTMLElement | null;
    const settingsContent = document.querySelector(
      ".settings-page .settings-content-column",
    ) as HTMLElement | null;
    const detailPane = document.querySelector(".agent-admin-detail-pane") as HTMLElement | null;
    if (realm) {
      realm.scrollTop = 200;
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
      realmOverflowY: realm ? getComputedStyle(realm).overflowY : null,
      realmScrollTop: realm?.scrollTop ?? 0,
    };
  });
  expect(scrollLayout.rootOverflowY).toBe("hidden");
  expect(scrollLayout.bodyOverflowY).toBe("hidden");
  expect(scrollLayout.viewportScrollbarGap).toBe(0);
  expect(scrollLayout.realmOverflowY).toBe("auto");
  expect(scrollLayout.realmScrollTop).toBe(0);
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
  let provisionRequests = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_arkret/self/agents"
    ) {
      provisionRequests += 1;
    }
  });
  await page.getByTestId("agent-admin-provision-button").click();
  await expect(page.getByTestId("agent-admin-last-op")).toContainText(
    "this device has no controller authority pair",
  );
  expect(provisionRequests).toBe(0);
  await expect(page.getByTestId("agent-admin-provision")).toBeVisible();
});

async function confirmAssistantDeactivation(page: import("@playwright/test").Page) {
  await gotoAndDismissRecovery(page, "/settings/agents?filter=all");
  await page.getByTestId("agent-admin-row").filter({ hasText: "assistant" }).click();
  await page.getByTestId("agent-admin-deactivate-button").click();
  await page.getByTestId("agent-admin-deactivate-confirm-input").fill("DEACTIVATE");
}

test("agent deactivation submits controller-signed lifecycle without revoke bundles", async ({ page }) => {
  await confirmAssistantDeactivation(page);
  const responsePromise = page.waitForResponse((response) =>
    response.request().method() === "POST" &&
    new URL(response.url()).pathname.endsWith("/deactivate"),
  );
  await page.getByTestId("agent-admin-deactivate-confirm-button").click();
  const response = await responsePromise;
  expect(response.status()).toBe(200);
  const body = response.request().postDataJSON();
  expect(Object.keys(body).sort()).toEqual(["lifecycle_event", "reason"]);
  expect(body.lifecycle_event.authorization_lease).toBeUndefined();
  expect(body.lifecycle_event.control_proposal_ack).toBeUndefined();
  const proof = body.lifecycle_event.event.producer_proof;
  expect(proof.kind).toBe("detached_jws");
  expect(proof.verification_method).toBe(
    `${CURRENT_PRINCIPAL_DID}#ak:device:01964137-0000-7000-8000-0000000000a1`,
  );
  expect(proof.event_digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  const [protectedHeader, detachedPayload, signature] = proof.jws.split(".");
  expect(JSON.parse(Buffer.from(protectedHeader, "base64url").toString())).toEqual({
    alg: "Ed25519",
  });
  expect(detachedPayload).toBe("");
  expect(Buffer.from(signature, "base64url")).toHaveLength(64);
  expect(body.lifecycle_event.event.actor_id).toEqual({
    kind: "account",
    account_id: CURRENT_ASSISTANT_ACCOUNT_ID,
  });
  expect(body.lifecycle_event.event.executed_by).toEqual(CURRENT_ACCOUNT_ACTOR_ID);
  expect(body.lifecycle_event.event.scope_ref).toEqual({
    kind: "realm",
    realm_id: CURRENT_ASSISTANT_PCR,
  });
  expect(body.lifecycle_event.event.payload).toMatchObject({
    transition: "deactivate", previous_status: "active", reason: body.reason,
  });
  const outcome = await response.json();
  expect(outcome).toEqual({ status: "deactivated" });
  await expect(page.getByTestId("agent-admin-last-op")).toHaveText("Agent deactivated permanently.");
  await expect(page.getByTestId("agent-admin-deactivate-modal")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-deactivate-button")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-row").filter({ hasText: "assistant" })).toHaveCount(0);
  // Ordinary filters intentionally remove terminal Agents. Inspect the newly
  // deactivated Agent through the existing audit deep link, then select it.
  await gotoAndDismissRecovery(page, "/settings/agents?filter=deactivated");
  const terminalRow = page.getByTestId("agent-admin-row").filter({ hasText: "assistant" });
  await expect(terminalRow).toContainText("Deactivated");
  await terminalRow.click();
  await expect(page.getByTestId("agent-admin-deactivated-terminal-note")).toBeVisible();
  await expect(page.getByTestId("agent-admin-enabled-switch")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-deactivate-button")).toHaveCount(0);
});

for (const [binding, message] of [
  ["missing", "Agent key binding is unavailable"],
  ["mismatched", "Agent key binding does not match the selected Agent and controller"],
] as const) {
  test(`agent deactivation rejects ${binding} key binding without submission`, async ({ page }) => {
    await confirmAssistantDeactivation(page);
    let deactivateRequests = 0;
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname.endsWith("/deactivate")) {
        deactivateRequests += 1;
      }
    });
    await page.getByTestId("agent-admin-deactivate-confirm-button").click();
    await expect(page.getByTestId("agent-admin-last-op")).toContainText(message);
    expect(deactivateRequests).toBe(0);
    await expect(page.getByTestId("agent-admin-deactivate-modal")).toBeVisible();
    await expect(page.getByTestId("agent-admin-deactivate-confirm-button")).toBeEnabled();
  });
}

test("deactivated Agents are available only through the audit deep link", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/agents?filter=deactivated");
  await expect(page).toHaveURL(/\/settings\/agents\?filter=deactivated$/);
  await expect(page.getByTestId("agent-admin")).toBeVisible();
  await expect(page.getByTestId("agent-admin-filter-deactivated")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-row")).toHaveCount(1);
  await expect(page.getByTestId("agent-admin-row")).toContainText("deactivated");
  await expect(page.getByTestId("agent-admin-row")).not.toContainText("Deactivated Agent");
  await expect(page.getByTestId("agent-admin-row")).toContainText("Deactivated");
  await expect(page.getByTestId("agent-state-badge")).toHaveCount(0);
  await expect(page.getByTestId("agent-admin-deactivated-terminal-note")).toBeVisible();
});

test("active Agents never expose stale pairing credentials", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(page.getByTestId("agent-admin")).toBeVisible();

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

  const renewRequestPromise = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname.endsWith("/renew-pairing"),
  );
  await page.getByTestId("agent-admin-replace-runtime-confirm-button").click();
  await renewRequestPromise;
  await expect(page.getByTestId("agent-admin-pairing-card")).toBeVisible();
  // Lifecycle intent is preserved: the agent stays active with no forced pause
  // and no resume, while the replacement handle is open.
  await expect(page.getByTestId("agent-admin-enabled-switch")).toBeChecked();
  await expect(page.getByTestId("agent-admin-enabled-switch")).toBeEnabled();
});

test("expired Agent pairing renews in place with a fresh handle", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(page.getByTestId("agent-admin")).toBeVisible();
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

  // The Garth route-evaluator adapter is wired, so /call renders the real
  // dialer; joins remain fail-closed behind evaluator-verified route material.
  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("call-panel")).toBeVisible();
  await expect(page.getByTestId("call-route-unavailable")).toHaveCount(0);
});
