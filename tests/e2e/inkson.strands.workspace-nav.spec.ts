import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  dismissBlockingRecoveryModal,
  openServerSwitcher,
  refreshServer,
  openSettings,
  writeLocalConfig,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("workspace sidebar separates contact-based direct chats", async ({ page }) => {
  const shell = latestTestId(page, "client-shell");
  await expect(shell.getByTestId("realm-tree-list")).toContainText("Arkret Demo Realm");
  await expect(shell.getByTestId("realm-sidebar-toolbar")).toBeVisible();
  await expect(shell.getByTestId("realm-sidebar-search-input")).toBeVisible();
  await expect(shell.getByTestId("sidebar-new-realm-cta")).toBeVisible();
  await expect(shell.getByTestId("realm-sidebar-manage-home-button")).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/realms\/manage$/);
  await expect(shell.getByTestId("realms-manage-page")).toBeVisible();
  await expect(shell.getByTestId("realms-manage-page")).toContainText("Arkret Demo Realm");

  await shell.getByTestId("realm-sidebar-tab-direct").click();

  await expect(shell.getByTestId("contacts-sidebar-search-input")).toBeVisible();
  await expect(shell.getByTestId("sidebar-new-contact-cta")).toBeVisible();
  await expect(shell.getByTestId("contacts-sidebar-summary")).toContainText("Contacts");
  await expect(shell.getByTestId("direct-conversation-row").filter({ hasText: "bob:example.com" })).toContainText(
    "DM",
  );
  await expect(shell.getByTestId("direct-conversation-row").filter({ hasText: "carol:example.com" })).toContainText(
    "pending",
  );
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/contacts\/manage$/);
  await expect(shell.getByTestId("contacts-manage-page")).toBeVisible();
  await expect(shell.getByTestId("contacts-manage-page")).toContainText("bob:example.com");
});

test("new space strand uses sidebar realm context without home realm picker", async ({ page }) => {
  await refreshServer(page);
  const shell = latestTestId(page, "client-shell");
  await expect(shell.getByTestId("realm-tree-list")).toContainText("Arkret Demo Realm");
  await dismissBlockingRecoveryModal(page);

  const demoRealmRow = shell.locator(".sidebar-row").filter({ hasText: "Arkret Demo Realm" }).first();
  await expect(demoRealmRow).toBeVisible();
  await demoRealmRow.hover();
  await demoRealmRow.getByTestId("realm-tree-row-menu-button").click();
  await demoRealmRow.getByTestId("realm-tree-row-add-action").click();

  await expect(page).toHaveURL(/\/setup\/new-space$/);
  const setupPanel = page.getByTestId("setup-panel");
  await expect(setupPanel.getByTestId("space-create-strand")).toBeVisible();
  await expect(setupPanel).not.toContainText("Home Realm");
  await expect(setupPanel.getByTestId("new-space-realm-input")).toHaveCount(0);

  await setupPanel.getByTestId("new-space-title-input").fill("Scoped Space");
  await expect(setupPanel.getByTestId("new-space-submit-button")).toBeEnabled();
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

test("dashboard summarizes unread notifications from sync projection", async ({ page }) => {
  await refreshServer(page);

  await expect(page.getByTestId("dashboard-unread-notifications")).toHaveText("2");
  await expect(page.getByTestId("pinned-notifications")).toContainText("New message");
  await expect(page.getByTestId("pinned-notifications")).toContainText("New invite");
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
