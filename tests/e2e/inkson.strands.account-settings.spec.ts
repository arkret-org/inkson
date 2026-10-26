import { byClass } from "./strandsHarness";
import { expect, test, type Locator, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
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

  dismissBlockingRecoveryModal,
  refreshServer,
  gotoAndDismissRecovery,
  openSettings,
  seedLocalRecoveryKeyMetadata,
  writeSessionGrantInjection,
} from "./strandsHarness";

registerStrandsBeforeEach();

function accountMenu(page: Page) {
  return byClass(page, "account-menu");
}

function agentCreation(page: Page) {
  return page.locator(".agent-admin-layout > .event").filter({ has: byClass(page, "agent-admin-provision-button") });
}

function agentLastOperation(page: Page) {
  return byClass(page, "agent-admin").locator(":scope > .write-status");
}

function terminalAgentNote(page: Page) {
  return byClass(page, "agent-admin-agent-actions").locator(".agent-admin-terminal-note");
}

function expiredPairingMessage(page: Page) {
  return byClass(page, "agent-admin-pairing-card").locator(".agent-admin-status.error");
}

async function chooseImage(page: Page, trigger: Locator, file: { name: string; mimeType: string; buffer: Buffer }) {
  const directory = test.info().outputPath("avatar-files", randomUUID());
  await mkdir(directory, { recursive: true });
  const path = join(directory, file.name);
  await writeFile(path, file.buffer);
  const chooser = page.waitForEvent("filechooser");
  await trigger.click();
  // CDP's absolute file path is the browser's trusted file selection path.
  // Buffer payloads use a synthetic DOM event and are correctly rejected by
  // the official host's FileToken admission.
  await (await chooser).setFiles(path);
}

async function assertAvatarCropPaint(page: Page) {
  const paint = await page.evaluate(() => {
    const stage = document.querySelector<HTMLElement>(".settings-avatar-crop-stage")!;
    const image = stage.querySelector<HTMLImageElement>(".settings-avatar-crop-image")!;
    const viewport = stage.getBoundingClientRect();
    const rect = image.getBoundingClientRect();
    const sliders = [...document.querySelectorAll<HTMLElement>(".settings-avatar-crop-controls [role=slider]")];
    const [zoom, panX, panY] = sliders.map(slider => Number(slider.getAttribute("aria-valuenow")));
    const scale = zoom / 100;
    const width = stage.clientWidth;
    const height = stage.clientHeight;
    return {
      actual: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
      expected: {
        x: viewport.x + stage.clientLeft + width * (1 - scale) / 2 + width * Math.trunc(panX / 4) / 100,
        y: viewport.y + stage.clientTop + height * (1 - scale) / 2 + height * Math.trunc(panY / 4) / 100,
        width: width * scale,
        height: height * scale,
      },
      fit: getComputedStyle(image).objectFit,
      clip: getComputedStyle(stage).overflow,
      shape: getComputedStyle(stage).borderRadius,
      naturalWidth: image.naturalWidth,
      zoom, panX, panY,
    };
  });
  await test.info().attach("avatar-crop-painted-bounds", { body: JSON.stringify(paint, null, 2), contentType: "application/json" });
  expect(paint.fit).toBe("cover");
  expect(paint.clip).toBe("hidden");
  expect(paint.shape).toBe("50%");
  expect(paint.naturalWidth).toBeGreaterThan(0);
  for (const key of ["x", "y", "width", "height"] as const) {
    expect(Math.abs(paint.actual[key] - paint.expected[key]), `painted crop ${key}`).toBeLessThan(0.5);
  }
}

async function selectLanguage(page: Page, language: "en" | "zh") {
  await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
  await expect(page.locator("html")).toHaveAttribute("lang", language);
}

test("topbar account menu shows profile identity and current device", async ({ page }) => {
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await byClass(page, "account-menu-button").click();
  const menu = accountMenu(page);
  const didRow = byClass(menu, "account-menu__row").first();
  await expect(didRow.locator(".mono")).toHaveText(
    /^ak:did_core:webvh:.+\.\.\..+$/,
  );
  await expect(byClass(page, "account-menu")).toContainText("ak:device:");
  await expect(menu.getByRole("button", { name: "Copy DID", exact: true })).toBeVisible();
  await expect(menu.getByRole("button", { name: "Copy device ID", exact: true })).toBeVisible();
  await page.context().grantPermissions(["clipboard-read", "clipboard-write"]);
  await menu.getByRole("button", { name: "Copy DID", exact: true }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(CURRENT_PRINCIPAL_CORE_ID);
  await expect(byClass(menu, "who")).toHaveText("inkson");
  await expect(byClass(menu, "account-menu__avatar")).toHaveClass(/generated-avatar/);
  await expect(menu.locator("svg.account-menu__avatar")).toBeVisible();
  await expect(byClass(menu, "account-menu__device-name")).toHaveText("Current device");
  await menu.getByRole("button", { name: "Copy device ID", exact: true }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("ak:device:01964137-0000-7000-8000-0000000000a1");
  await expect(byClass(page, "account-menu-session-state")).toHaveCount(0);
  await expect(byClass(menu, "account-menu__qr")).toBeVisible();
  await expect(menu.getByRole("link", { name: "Settings", exact: true })).toBeVisible();
  const menuBox = await byClass(page, "account-menu").boundingBox();
  const qrBox = await byClass(menu, "account-menu__qr").boundingBox();
  const refreshBox = await menu.getByRole("button", { name: "Refresh session", exact: true }).boundingBox();
  const logoutBox = await menu.getByRole("button", { name: "Log out", exact: true }).boundingBox();
  const settingsBox = await menu.getByRole("link", { name: "Settings", exact: true }).boundingBox();
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
  await byClass(menu, "account-menu__qr").click();
  await expect(page).toHaveURL(/\/settings$/);
  await expect(byClass(page, "settings-page")).toBeVisible();
});

test("account menu keeps the viewer fallback handle", async ({
  page,
}) => {
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator(".shell.app").last()).toBeVisible({ timeout: 120_000 });
  await refreshServer(page);
  await dismissBlockingRecoveryModal(page);
  await byClass(page, "account-menu-button").last().click();

  await expect(byClass(accountMenu(page), "account-menu__row").nth(1).locator(".mono")).toHaveText("alice:local.host");
});

test("settings language selector offers only English and Chinese", async ({ page }) => {
  await openSettings(page);
  await byClass(page, "settings-nav-item-theme").click();
  await expect(byClass(page, "language-settings")).toBeVisible();
  await expect(byClass(page, "settings-language-choice")).toHaveCount(2);
  await byClass(page, "settings-theme-night").click();
  await expect(byClass(page, "settings-theme-night")).toHaveAttribute("aria-pressed", "true");
  await expect(byClass(page, "inkson-root")).toHaveClass(/inkson-theme-dark/);
  await byClass(page, "settings-theme-system").click();
  await expect(byClass(page, "settings-theme-system")).toHaveAttribute("aria-pressed", "true");

  await expect(byClass(page, "language-ar")).toHaveCount(0);
  await expect(byClass(page, "current-language")).toHaveCount(0);
  await selectLanguage(page, "zh");
  await expect(page.locator(".shell.app")).toHaveCSS("direction", "ltr");
  await expect(byClass(page, "text-direction")).toContainText("ltr");

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator(".shell.app")).toBeVisible({ timeout: 120_000 });
  await expect(page.locator(".shell.app")).toHaveCSS("direction", "ltr");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh");

  await openSettings(page);
  await byClass(page, "settings-nav-item-theme").click();
  await selectLanguage(page, "en");
  await expect(page.locator(".shell.app")).toHaveCSS("direction", "ltr");
});

test("account invite locator stays contained and follows the active locale", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(byClass(page, "settings-invite-locator-url-pane")).toHaveCount(0);
  await byClass(page, "settings-invite-locator-refresh").click();
  await expect(byClass(page, "settings-invite-locator-url")).not.toHaveValue("");

  const share = byClass(page, "settings-invite-locator-url-pane");
  const qr = byClass(page, "settings-invite-locator-qr");
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
  await selectLanguage(page, "zh");
  await gotoAndDismissRecovery(page, "/settings/account");
  await byClass(page, "settings-invite-locator-refresh").click();
  await expect(byClass(page, "topbar-context-title")).toHaveText("设置");
  await expect(byClass(page, "sidebar")).toContainText("主页");
  await expect(byClass(page, "realm-tabs").getByRole("button", { name: "协作", exact: true })).toBeVisible();
  await expect(byClass(page, "realm-tabs").getByRole("button", { name: "联系人", exact: true })).toBeVisible();
  await expect(byClass(page, "sidebar").getByRole("textbox", { name: "搜索 Realm", exact: true })).toBeVisible();
  await expect(byClass(page, "sidebar-search-placeholder")).toHaveText("搜索 Realm");
  await expect(byClass(page, "settings-avatar-card")).toContainText("账号身份");
  await expect(byClass(page, "settings-invite-locator-card")).toContainText(
    "安全邀请链接",
  );
  await expect(byClass(page, "settings-invite-locator-card")).toContainText(
    "15 分钟后过期",
  );
  await expect(byClass(page, "settings-invite-locator-card")).toContainText(
    "扫描二维码",
  );
  await expect(byClass(page, "settings-invite-locator-card")).toContainText(
    "或使用此链接",
  );
  await expect(byClass(page, "settings-invite-locator-card")).toContainText(
    "复制链接",
  );
});

test("settings avatar upload fails closed before profile publication without durable authority", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(byClass(page, "settings-avatar-card")).toBeVisible();
  await expect(byClass(page, "settings-avatar-input")).toHaveAccessibleName("Upload new avatar");
  await expect(byClass(page, "settings-avatar-input")).toBeVisible();
  await expect(page.locator('input[type="file"]:visible')).toHaveCount(0);

  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
    "base64",
  );
  await chooseImage(page, byClass(page, "settings-avatar-input"), {
    name: "avatar.png",
    mimeType: "image/png",
    buffer: png,
  });

  await expect(byClass(page, "settings-avatar-crop-stage")).toBeVisible();
  const zoom = page.getByRole("slider", { name: "Zoom", exact: true });
  await zoom.press("Home");
  for (let step = 0; step < 10; step += 1) await zoom.press("ArrowRight");
  await expect(zoom).toHaveAttribute("aria-valuenow", "150");

  const uploadRequest = page.waitForRequest("**/_arkret/self/blob/upload");
  let profileRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_arkret/self/account/profile") {
      profileRequests += 1;
    }
  });
  await byClass(page, "settings-avatar-crop-save").click();

  const upload = await uploadRequest;
  expect(upload.headers()["content-type"]).toContain("multipart/form-data");
  expect(upload.postDataBuffer()?.length ?? 0).toBeGreaterThan(100);
  expect(upload.postData() ?? "").toContain("Content-Type: image/jpeg");

  await expect(byClass(page, "settings-avatar-card")).toContainText(
    "profile update requires durable accepted PCR authority evidence",
  );
  expect(profileRequests).toBe(0);
  // The former Dialog shell had zero height despite its fixed surface being
  // visible. Preserve the actual retry draft rather than that false positive.
  await expect(byClass(page, "settings-avatar-crop-dialog")).toBeVisible();
  await expect(byClass(page, "settings-avatar-source-size")).toContainText("12 x 8");
  await expect(zoom).toHaveAttribute("aria-valuenow", "150");
  await expect(byClass(page, "settings-avatar-crop-save")).toBeEnabled();
  await assertAvatarCropPaint(page);
});

test("avatar file replacement and cancellation ignore late reads", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/account");
  // Hold the official host's bounded Blob read, without replacing its FileToken
  // or synthesizing a file-control result.
  await page.evaluate(() => {
    const original = Blob.prototype.arrayBuffer;
    const originalSlice = Blob.prototype.slice;
    const delayed = new WeakSet<Blob>();
    const pending: Array<() => Promise<void>> = [];
    (window as any).__avatarReads = pending;
    Blob.prototype.slice = function (start, end, contentType) {
      const slice = originalSlice.call(this, start, end, contentType);
      if ((this instanceof File && this.name.startsWith("delayed-")) || delayed.has(this)) delayed.add(slice);
      return slice;
    };
    Blob.prototype.arrayBuffer = function () {
      if (!delayed.has(this)) return original.call(this);
      const blob = this;
      return new Promise<ArrayBuffer>((resolve, reject) => {
        pending.push(async () => {
          try { resolve(await original.call(blob)); } catch (error) { reject(error); }
        });
      });
    };
  });
  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==",
    "base64",
  );
  const input = byClass(page, "settings-avatar-input");
  await chooseImage(page, input, { name: "delayed-invalid.png", mimeType: "image/png", buffer: Buffer.from("invalid image") });
  await expect(byClass(page, "settings-avatar-read-cancel")).toBeVisible();
  await chooseImage(page, input, { name: "replacement.png", mimeType: "image/png", buffer: png });
  await expect(byClass(page, "settings-avatar-source-size")).toContainText("1 x 1");
  const progress = byClass(page, "settings-avatar-controls").locator(":scope > .write-status");
  const latestStatus = await progress.textContent();
  await page.evaluate(() => (window as any).__avatarReads.shift()());
  // Allow the host reply and the following presentation frame to settle.
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(byClass(page, "settings-avatar-source-size")).toContainText("1 x 1");
  await expect(progress).toHaveText(latestStatus!);
  await byClass(page, "settings-avatar-crop-cancel").click();

  await chooseImage(page, input, { name: "delayed-cancel.png", mimeType: "image/png", buffer: png });
  await expect(byClass(page, "settings-avatar-read-cancel")).toBeVisible();
  await byClass(page, "settings-avatar-read-cancel").click();
  await page.evaluate(() => (window as any).__avatarReads.shift()());
  await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
  await expect(byClass(page, "settings-avatar-crop-editor")).toHaveCount(0);
  await expect(progress).toHaveCount(0);

  await chooseImage(page, input, { name: "fresh.png", mimeType: "image/png", buffer: png });
  await expect(byClass(page, "settings-avatar-crop-stage")).toBeVisible();
  // Replay the original inline declarations on this DOM. Computed appearance
  // must match the extracted feature classes, including tokens and cascade.
  const replay = await page.evaluate(() => {
    const probes: Array<[string, string, string[]]> = [
      [".settings-avatar-crop-dialog", "position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%); z-index: var(--layer-modal, 300); display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 16px; align-items: center; width: min(640px, calc(100vw - 32px)); max-height: calc(100vh - 48px); overflow: auto; padding: 18px; border: 1px solid var(--border, #333); border-radius: var(--radius-lg, 12px); background: var(--surface-solid, var(--surface, #1a1d22)); box-shadow: 0 0 0 9999px rgba(20, 22, 30, 0.55), var(--shadow-lg, 0 24px 56px rgba(0, 0, 0, 0.22));", ["position", "left", "top", "transform", "z-index", "display", "grid-template-columns", "gap", "align-items", "width", "max-height", "overflow", "padding", "border", "border-radius", "background-color", "box-shadow"]],
      [".settings-avatar-crop-stage", "position: relative; width: min(180px, 70vw); aspect-ratio: 1; justify-self: center; border-radius: 50%; overflow: hidden; border: 1px solid var(--border-default, #333); background: var(--bg-elevated, #1a1d22);", ["position", "width", "aspect-ratio", "justify-self", "border-radius", "overflow", "border", "background-color"]],
      [".settings-avatar-crop-controls", "display: grid; gap: 10px;", ["display", "gap"]],
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
  // Typed bounds and the former CSS transform use different declarations;
  // compare their actual image paint against the same crop/viewport geometry.
  await assertAvatarCropPaint(page);
  // The official host owns the hidden chooser input. Its public button and
  // trusted chooser path replace the former app-owned hidden-input CSS probe.
  await expect(input).toBeVisible();
  await expect(page.locator('input[type="file"]:visible')).toHaveCount(0);
  // Invalid replacement must discard the previous valid crop.
  await chooseImage(page, byClass(page, "settings-avatar-replace-input"), { name: "invalid.png", mimeType: "image/png", buffer: Buffer.from("invalid image") });
  await expect(byClass(page, "settings-avatar-crop-editor")).toHaveCount(0);
  await expect(progress).not.toHaveText(latestStatus!);

});

test("light theme renders the sidebar with light navigation colors", async ({ page }) => {
  await openSettings(page);
  await byClass(page, "settings-nav-item-theme").click();
  await byClass(page, "settings-theme-light").click();
  await expect(byClass(page, "settings-theme-light")).toHaveAttribute("aria-pressed", "true");
  await expect(byClass(page, "inkson-root")).toHaveClass(/inkson-theme-light/);

  const sidebarVars = await byClass(page, "sidebar").evaluate((element) => {
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
  await expect(page.locator(".shell.app").last()).toBeVisible({ timeout: 120_000 });
  await expect(byClass(page, "inkson-root")).toHaveClass(/inkson-theme-dark/);

  const toggle = byClass(page, "theme-toggle-button").filter({ visible: true });
  await expect(toggle).toHaveAccessibleName("Switch to light theme");
  await toggle.click();
  await expect(byClass(page, "inkson-root")).toHaveClass(/inkson-theme-light/);
  await expect(toggle).toHaveAccessibleName("Switch to night theme");
});

test("settings reads its signed own Station directory and refuses provider-only actions", async ({ page }) => {
  const providerPosts: string[] = [];
  page.on("request", request => {
    if (request.method() === "POST" && new URL(request.url()).pathname.startsWith("/_arkret/open/mimi/")) {
      providerPosts.push(request.url());
    }
  });
  await gotoAndDismissRecovery(page, "/settings/mimi");
  await expect(byClass(page, "mimi-interop-panel")).toBeVisible();
  await byClass(page, "mimi-refresh-directory").click();
  await expect(byClass(page, "mimi-directory-result")).toContainText("mimi://mimi.example.com");
  for (const feature of ["submit_message", "identifier_query", "proxy_download"]) {
    await expect(byClass(page, "mimi-directory-result")).toContainText(feature);
  }
  // mimi-interop section 5 requires a provider Service signer. A user session
  // cannot substitute for it, even when the directory advertises the feature.
  for (const [button, receipt] of [
    ["mimi-identifier-query", "mimi-query-receipt"],
    ["mimi-submit-message", "mimi-submit-receipt"],
    ["mimi-proxy-download", "mimi-proxy-receipt"],
  ]) {
    await byClass(page, button).click();
    await expect(byClass(page, receipt)).toContainText("failed:");
    await expect(byClass(page, button)).toBeEnabled();
  }
  expect(providerPosts).toEqual([]);
});

test("a pending directory read preserves independent provider refusals and ignores duplicate clicks", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/settings/mimi");
  let releaseDirectory!: () => void;
  const heldDirectory = new Promise<void>((resolve) => { releaseDirectory = resolve; });
  let directoryRequests = 0;
  await page.route("**/_arkret/open/mimi/provider-directory", async route => {
    directoryRequests += 1;
    await heldDirectory;
    await route.fallback();
  });
  try {
    await byClass(page, "mimi-refresh-directory").click();
    await expect.poll(() => directoryRequests).toBe(1);
    await expect(byClass(page, "mimi-refresh-directory")).toBeDisabled();
    await byClass(page, "mimi-refresh-directory").evaluate(element => (element as HTMLElement).click());
    const receipts = new Map<string, string>();
    for (const [button, receipt] of [
      ["mimi-identifier-query", "mimi-query-receipt"],
      ["mimi-submit-message", "mimi-submit-receipt"],
      ["mimi-proxy-download", "mimi-proxy-receipt"],
    ]) {
      await expect(byClass(page, button)).toBeEnabled();
      await byClass(page, button).click();
      await expect(byClass(page, receipt)).toContainText("failed:");
      receipts.set(receipt, (await byClass(page, receipt).textContent())!);
    }
    releaseDirectory();
    await expect(byClass(page, "mimi-directory-result")).toContainText("mimi://mimi.example.com");
    await expect(byClass(page, "mimi-refresh-directory")).toBeEnabled();
    for (const [receipt, text] of receipts) await expect(byClass(page, receipt)).toHaveText(text);
    expect(directoryRequests).toBe(1);
  } finally {
    releaseDirectory();
  }
});

test("account settings split account/server info and surface Agents", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await seedLocalRecoveryKeyMetadata(page);
  await dismissBlockingRecoveryModal(page);

  // Account information is its own section (identity + invite locator).
  await gotoAndDismissRecovery(page, "/settings/account");
  await expect(byClass(page, "settings-page")).toBeVisible({ timeout: 120_000 });
  await expect(byClass(page, "settings-nav-item-account")).toHaveAttribute("aria-current", "page");
  await expect(byClass(page, "settings-avatar-card")).toBeVisible();
  await expect(byClass(page, "settings-account-did")).toHaveText(
    CURRENT_PRINCIPAL_CORE_ID,
  );
  await expect(byClass(page, "settings-account-did")).not.toHaveText("@alice:local.host");
  await byClass(page, "settings-invite-locator-refresh").click();
  const inviteLocatorUrl = byClass(page, "settings-invite-locator-url");
  const inviteLocatorQr = byClass(page, "settings-invite-locator-qr");
  const inviteLocatorUrlPane = byClass(page, "settings-invite-locator-url-pane");
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
  await expect(byClass(page, "settings-nav-item-recovery")).toBeVisible();
  const accountCardLayout = await page.evaluate(() => {
    const profile = document.querySelector<HTMLElement>(".settings-profile-fields");
    const displayName = document.querySelector<HTMLInputElement>(
      ".settings-profile-display-name input",
    );
    const displayNameLabel = displayName?.closest(".form-field")?.querySelector<HTMLElement>(".sapid-field-label");
    const biography = document.querySelector<HTMLTextAreaElement>(".settings-profile-biography textarea");
    const avatar = document.querySelector<HTMLElement>(".settings-avatar-actions");
    const identity = document.querySelector<HTMLElement>(".settings-account-identity-grid");
    if (!profile || !displayName || !displayNameLabel || !biography || !avatar || !identity) {
      return null;
    }
    const profileBox = profile.getBoundingClientRect();
    const displayNameBox = displayName.getBoundingClientRect();
    const displayNameLabelBox = displayNameLabel.getBoundingClientRect();
    const bioBox = biography.getBoundingClientRect();
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
  await byClass(page, "settings-nav-item-server").click();
  await expect(page).toHaveURL(/\/settings\/server(?:\?filter=)?$/);
  await expect(byClass(page, "transport-invariant")).toBeVisible();

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
  await byClass(page, "settings-nav-item-agents").click();
  await expect(page).toHaveURL(/\/settings\/agents(?:\?filter=)?$/);
  await expect(byClass(page, "agent-admin")).toBeVisible();
  await expect(byClass(page, "agent-admin-list").getByText(/\d+ shown/)).toHaveCount(0);
  await expect(byClass(page, "agent-admin-toggle-inactive-button")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-filter-all")).toHaveAttribute(
    "class",
    /(?:^|\s)active(?:\s|$)/,
  );
  await expect(byClass(page, "agent-admin-filter-active")).toBeVisible();
  await expect(byClass(page, "agent-admin-filter-paused")).toBeVisible();
  await expect(byClass(page, "agent-admin-filter-deactivated")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-row")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-row").filter({ hasText: "deactivated" })).toHaveCount(0);
  await byClass(page, "agent-admin-filter-paused").click();
  await expect(page).toHaveURL(/\/settings\/agents\?filter=paused$/);
  await byClass(page, "agent-admin-filter-all").click();
  await expect(page).toHaveURL(/\/settings\/agents\?filter=all$/);
  await expect.poll(() => agentListRequests, { timeout: 5_000 }).toBe(1);
  await page.waitForTimeout(750);
  expect(agentListRequests).toBe(1);
  await byClass(page, "agent-admin-create-open-button").click();
  await expect(agentCreation(page)).toBeVisible();
  await expect(agentCreation(page).getByRole("textbox")).toHaveCount(1);
  await expect(byClass(page, "agent-admin-provision-display-name")).toHaveCount(0);
  await expect(agentCreation(page).locator(".avatar-uploader")).toBeVisible();
  await expect(byClass(page, "agent-admin-provision-button")).toBeDisabled();
  await byClass(page, "agent-admin-provision-agent-slug").getByRole("textbox").fill("Summary");
  await expect(byClass(page, "agent-admin-provision-agent-slug").getByRole("textbox")).toHaveValue("summary");
  const preview = agentCreation(page).locator(".avatar-uploader-preview .generated-avatar");
  await expect(preview).toHaveClass(
    /generated-avatar/,
  );
  await expect(preview).toHaveAttribute(
    "aria-label",
    "Generated avatar for summary",
  );
  await expect(preview.locator("svg")).toBeVisible();
  const agentAvatarPng = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAwAAAAICAYAAADN5B7xAAAAy0lEQVR4nBXLIRXEMBBAwRURHBwRK6I4OCJWRHFwRXwRxcH18u/d8IkIbIEjMAOvwBVYgXfgE0jgG/gFRnRsHUfH7Hh1XB2r493x6UjHt+PX/yGxJY7ETLwSV2Il3olPIolv4pf/MLFNHBNz4jVxTayJ98RnIhPfid/8h8JWOAqz8CpchVV4Fz6FFL6FX/3DxrZxbMyN18a1sTbeG5+NbHw3fvsfwAYOMMELXGCBN/iAgC/48Q8H28FxMA9eB9fBOngffA5y8D34HfwBl3vzwZTfUBgAAAAASUVORK5CYII=",
    "base64",
  );
  await chooseImage(page, byClass(page, "agent-admin-avatar-input"), {
    name: "agent-avatar.png",
    mimeType: "image/png",
    buffer: agentAvatarPng,
  });
  await expect(agentCreation(page).locator(".avatar-crop-editor")).toBeVisible();
  const agentAvatarUpload = page.waitForRequest("**/_arkret/self/blob/upload");
  await agentCreation(page).locator(".avatar-crop-editor").getByRole("button", { name: "Save avatar", exact: true }).click();
  await agentAvatarUpload;
  await expect(agentCreation(page).locator(".avatar-crop-editor")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-provision-button")).toBeEnabled();
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
  await test.info().attach("agent-creation-scroll-layout", { body: JSON.stringify(scrollLayout, null, 2), contentType: "application/json" });
  expect(scrollLayout.rootOverflowY).toBe("hidden");
  expect(scrollLayout.bodyOverflowY).toBe("hidden");
  expect(scrollLayout.viewportScrollbarGap).toBe(0);
  expect(scrollLayout.realmOverflowY).toBe("auto");
  expect(scrollLayout.realmScrollTop).toBe(0);
  expect(scrollLayout.settingsContentOverflowY).toBe("hidden");
  expect(scrollLayout.settingsContentScrollTop).toBe(0);
  expect(scrollLayout.detailOverflowY).toBe("auto");
  expect(scrollLayout.detailScrollTop).toBeGreaterThan(0);
  const presetLists = agentCreation(page).locator(".agent-admin-preset-list");
  await expect(presetLists.nth(0).locator(".agent-admin-preset-row")).toHaveCount(5);
  await expect(presetLists.nth(1).locator(".agent-admin-preset-row")).toHaveCount(5);
  const serviceScopeCheckboxes = presetLists.nth(1).getByRole("checkbox");
  await expect(serviceScopeCheckboxes).toHaveCount(5);
  for (let index = 0; index < 4; index += 1) {
    await expect(serviceScopeCheckboxes.nth(index)).toBeChecked();
  }
  await expect(serviceScopeCheckboxes.nth(4)).not.toBeChecked();
  let provisionRequests = 0;
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      new URL(request.url()).pathname === "/_arkret/self/agents"
    ) {
      provisionRequests += 1;
    }
  });
  await byClass(page, "agent-admin-provision-button").click();
  await expect(agentLastOperation(page)).toContainText(
    "this device has no controller authority pair",
  );
  expect(provisionRequests).toBe(0);
  await expect(agentCreation(page)).toBeVisible();
});

async function confirmAssistantDeactivation(page: import("@playwright/test").Page) {
  await gotoAndDismissRecovery(page, "/settings/agents?filter=all");
  await byClass(page, "agent-admin-row").filter({ hasText: "assistant" }).click();
  await byClass(page, "agent-admin-deactivate-button").click();
  await byClass(page, "agent-admin-deactivate-confirm-input").getByRole("textbox").fill("DEACTIVATE");
}

test("agent deactivation submits controller-signed lifecycle without revoke bundles", async ({ page }) => {
  await confirmAssistantDeactivation(page);
  const responsePromise = page.waitForResponse((response) =>
    response.request().method() === "POST" &&
    new URL(response.url()).pathname.endsWith("/deactivate"),
  );
  await byClass(page, "agent-admin-deactivate-confirm-button").click();
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
  await expect(agentLastOperation(page)).toHaveText("Agent deactivated permanently.");
  await expect(byClass(page, "agent-admin-deactivate-modal")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-deactivate-button")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-row").filter({ hasText: "assistant" })).toHaveCount(0);
  // Ordinary filters intentionally remove terminal Agents. Inspect the newly
  // deactivated Agent through the existing audit deep link, then select it.
  await gotoAndDismissRecovery(page, "/settings/agents?filter=deactivated");
  const terminalRow = byClass(page, "agent-admin-row").filter({ hasText: "assistant" });
  await expect(terminalRow).toContainText("Deactivated");
  await terminalRow.click();
  await expect(terminalAgentNote(page)).toBeVisible();
  await expect(byClass(page, "agent-admin-enabled-switch")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-deactivate-button")).toHaveCount(0);
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
    await byClass(page, "agent-admin-deactivate-confirm-button").click();
    await expect(agentLastOperation(page)).toContainText(message);
    expect(deactivateRequests).toBe(0);
    await expect(byClass(page, "agent-admin-deactivate-modal")).toBeVisible();
    await expect(byClass(page, "agent-admin-deactivate-confirm-button")).toBeEnabled();
  });
}

test("deactivated Agents are available only through the audit deep link", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/agents?filter=deactivated");
  await expect(page).toHaveURL(/\/settings\/agents\?filter=deactivated$/);
  await expect(byClass(page, "agent-admin")).toBeVisible();
  await expect(byClass(page, "agent-admin-filter-deactivated")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-row")).toHaveCount(1);
  await expect(byClass(page, "agent-admin-row")).toContainText("deactivated");
  await expect(byClass(page, "agent-admin-row")).not.toContainText("Deactivated Agent");
  await expect(byClass(page, "agent-admin-row")).toContainText("Deactivated");
  await expect(byClass(page, "agent-state-badge")).toHaveCount(0);
  await expect(terminalAgentNote(page)).toBeVisible();
});

test("active Agents never expose stale pairing credentials", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(byClass(page, "agent-admin")).toBeVisible();

  await byClass(page, "agent-admin-row").filter({ hasText: "assistant" }).click();
  await expect(byClass(page, "agent-admin-enabled-switch").getByRole("switch")).toBeVisible();
  await expect(byClass(page, "agent-admin-pairing-card")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-pairing-qr")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-pairing-url")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-renew-pairing-button")).toHaveCount(0);

  // Two orthogonal axes (key-management.md §3.6.1): the derived runtime
  // readiness badge shows Ready, and an active keyed agent can replace its
  // runtime directly — the forced-pause gate and its guidance are gone.
  await expect(byClass(page, "agent-admin-runtime-state-badge")).toContainText("Ready");
  await expect(byClass(page, "agent-admin-replace-runtime-guidance")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-replace-runtime-button")).toBeVisible();

  // Replace runtime asks for explicit confirmation stating the atomic-revoke
  // fact; the lifecycle switch is never interlocked with the open replacement.
  await byClass(page, "agent-admin-replace-runtime-button").click();
  await expect(byClass(page, "agent-admin-replace-runtime-confirm")).toContainText(
    "atomically revokes",
  );
  await expect(byClass(page, "agent-admin-enabled-switch").getByRole("switch")).toBeEnabled();

  const renewRequestPromise = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname.endsWith("/renew-pairing"),
  );
  await byClass(page, "agent-admin-replace-runtime-confirm-button").click();
  await renewRequestPromise;
  await expect(byClass(page, "agent-admin-pairing-card")).toBeVisible();
  // Lifecycle intent is preserved: the agent stays active with no forced pause
  // and no resume, while the replacement handle is open.
  await expect(byClass(page, "agent-admin-enabled-switch").getByRole("switch")).toBeChecked();
  await expect(byClass(page, "agent-admin-enabled-switch").getByRole("switch")).toBeEnabled();
});

test("expired Agent pairing renews in place with a fresh handle", async ({ page }) => {
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);

  await gotoAndDismissRecovery(page, "/settings/agents");
  await expect(byClass(page, "agent-admin")).toBeVisible();
  await byClass(page, "agent-admin-row").filter({ hasText: "summary" }).click();
  await expect(byClass(page, "agent-admin-pairing-card")).toBeVisible();
  await expect(byClass(page, "agent-admin-pairing-card")).toContainText("Expired");
  await expect(byClass(page, "agent-admin-pairing-bootstrap-json")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-runtime-key-request-json")).toHaveCount(0);
  await expect(byClass(page, "agent-admin-pairing-card").locator("pre, code")).toHaveCount(0);
  await expect(expiredPairingMessage(page)).toContainText(
    "pair again",
  );

  // Pair again renews pairing on the SAME agent: no create form, no
  // replacement principal, and the card returns to awaiting a runtime with a fresh
  // QR + deep link carrying the renewed handle.
  await byClass(page, "agent-admin-renew-pairing-button").click();
  await expect(agentCreation(page)).toHaveCount(0);
  await expect(byClass(page, "agent-admin-pairing-card")).toContainText("Awaiting runtime");
  await expect(expiredPairingMessage(page)).toHaveCount(0);
  await expect(byClass(page, "agent-admin-pairing-qr")).toBeVisible();
  await expect(byClass(page, "agent-admin-pairing-url")).not.toHaveValue("");
  await expect(
    byClass(page, "agent-admin-row").filter({ hasText: "summary" }),
  ).toHaveCount(1);
  await expect(agentLastOperation(page)).toContainText("Pairing renewed");
});

test("diagnostic and preview surfaces stay behind clear user-facing states", async ({ page }) => {
  await page.goto("/directory", { waitUntil: "domcontentloaded" });
  await expect(byClass(page, "directory-panel")).toBeVisible();

  // The Garth route-evaluator adapter is wired, so /call renders the real
  // dialer; joins remain fail-closed behind evaluator-verified route material.
  await page.goto("/call", { waitUntil: "domcontentloaded" });
  await expect(byClass(page, "call-panel")).toBeVisible();
  await expect(byClass(page, "call-route-unavailable")).toHaveCount(0);
});
