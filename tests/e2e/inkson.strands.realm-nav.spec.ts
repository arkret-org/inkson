import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  latestTestId,
  dismissBlockingRecoveryModal,
  gotoAndDismissRecovery,
  openServerSwitcher,
  refreshServer,
  openSettings,
  writeLocalConfig,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("ordinary Circle list fails closed when the response contains a Sidecar profile", async ({
  page,
}) => {
  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/circles",
  );
  const panel = page.getByTestId("circles-panel");
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId("circle-list-item")).toHaveCount(1);
  await expect(panel).toContainText("Demo Circle");
  await expect(panel).not.toContainText("Alice AI Sidecar");
});

test("Circle creation fails closed without a durable governance checkpoint", async ({
  page,
}) => {
  await gotoAndDismissRecovery(
    page,
    "/realms/ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk/circles",
  );
  const panel = page.getByTestId("circles-panel");
  await panel.getByTestId("circle-create-open").click();
  await page.getByTestId("circle-create-title").fill("Incident Response");
  await page.getByTestId("circle-create-submit").click();

  await expect(panel.getByRole("status")).toContainText(
    "has no durable verified governance checkpoint",
  );
  await expect(page).toHaveURL(/\/realms\/.*\/circles$/);
  await expect(panel.getByTestId("circle-detail")).not.toContainText(
    "Incident Response",
  );
});

test("realm sidebar separates contact-based direct chats", async ({ page }) => {
  const shell = latestTestId(page, "client-shell");
  await expect(shell.getByTestId("realm-tree-list")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(shell.getByTestId("realm-sidebar-toolbar")).toBeVisible();
  await expect(shell.getByTestId("realm-sidebar-search-input")).toBeVisible();
  await expect(shell.getByTestId("sidebar-new-realm-cta")).toBeVisible();
  await expect(
    shell.getByTestId("realm-sidebar-manage-home-button"),
  ).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/realms\/manage$/);
  const realmsManagePage = shell.getByTestId("realms-manage-page");
  await expect(realmsManagePage).toBeVisible();
  await expect(realmsManagePage).toContainText("Arkret Demo Realm");
  await expect(realmsManagePage.locator(".realm-manage-hero")).toHaveCount(0);
  await expect(realmsManagePage.locator('input[type="checkbox"]')).toHaveCount(
    0,
  );
  await expect(realmsManagePage).not.toContainText(/\d+\s+rows/);
  const firstRealmRow = realmsManagePage
    .getByTestId("realms-manage-row")
    .first();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-open"),
  ).toBeHidden();
  await firstRealmRow.hover();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-open"),
  ).toBeVisible();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-settings"),
  ).toBeVisible();
  await expect(
    firstRealmRow.getByTestId("realms-manage-row-leave"),
  ).toBeVisible();

  await shell.getByTestId("realm-sidebar-tab-direct").click();

  await expect(
    shell.getByTestId("contacts-sidebar-search-input"),
  ).toBeVisible();
  await expect(shell.getByTestId("sidebar-new-contact-cta")).toBeVisible();
  await expect(shell.getByTestId("contacts-sidebar-summary")).toHaveCount(0);
  const selfRow = shell.getByTestId("contact-sidebar-self-row");
  await expect(selfRow).toContainText("alice:local.host");
  await expect(shell.getByTestId("contact-sidebar-self-badge")).toHaveText(
    "ME",
  );
  const selfAvatar = selfRow.locator(
    ".contact-sidebar-user-avatar .generated-avatar",
  );
  const topbarAvatar = shell.getByTestId("topbar-account-avatar");
  await expect(selfAvatar.locator("svg")).toBeVisible();
  await expect(topbarAvatar.locator("svg")).toBeVisible();
  expect(await selfAvatar.locator("svg").innerHTML()).toBe(
    await topbarAvatar.locator("svg").innerHTML(),
  );
  await expect(selfRow).not.toContainText("Agents 1");
  await expect(
    shell.getByTestId("contact-sidebar-self-agent-toggle"),
  ).toBeVisible();
  await expect(shell.locator(".contact-sidebar-group").first()).toHaveAttribute(
    "data-testid",
    "contact-sidebar-self-group",
  );
  await expect(shell.getByTestId("contact-sidebar-self-agents")).toContainText(
    "Alice Assistant",
  );
  const ownAgentRow = shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Alice Assistant" });
  await expect(
    ownAgentRow.locator(".contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  await expect(ownAgentRow).not.toContainText("active");
  await expect(ownAgentRow).not.toContainText("paused");
  await expect(ownAgentRow).toHaveCSS("min-height", "34px");
  await expect(
    shell.getByTestId("contact-sidebar-agent-toggle").first(),
  ).toContainText("Agents 1");
  await shell.getByTestId("contact-sidebar-agent-toggle").first().click();
  await expect(
    shell.getByTestId("contact-sidebar-contact-agents"),
  ).toContainText("Bob Helper");
  await expect(
    shell
      .getByTestId("contact-sidebar-agent-row")
      .filter({ hasText: "Bob Helper" })
      .locator(".contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  const bobContactRow = shell
    .getByTestId("direct-conversation-row")
    .filter({ hasText: "ak:did_core:web:bob.example" });
  await expect(bobContactRow).toContainText("DM");
  await expect(bobContactRow).toHaveAttribute(
    "aria-label",
    "Chat with ak:did_core:web:bob.example",
  );
  await expect(
    shell
      .getByTestId("direct-conversation-row")
      .filter({ hasText: "ak:did_core:web:carol.example" }),
  ).toContainText("pending");
  await bobContactRow.click();
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO\/ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd$/,
  );
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  await shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Bob Helper" })
    .click();
  await expect(page).toHaveURL(/\/direct\/ak:realm:[^/]+\/ak:strand:[^/]+$/);
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/contacts\/manage$/);
  const contactsManagePage = shell.getByTestId("contacts-manage-page");
  await expect(contactsManagePage).toBeVisible();
  await expect(contactsManagePage).toContainText("ak:did_core:web:bob.example");
  await expect(contactsManagePage.locator(".realm-manage-hero")).toHaveCount(0);
  await expect(
    contactsManagePage.locator('input[type="checkbox"]'),
  ).toHaveCount(0);
});

test("owned agent opens an independent two-principal Direct Conversation Realm", async ({
  page,
}) => {
  const shell = latestTestId(page, "client-shell");
  await dismissBlockingRecoveryModal(page);
  await shell.getByTestId("realm-sidebar-tab-direct").click();
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
  const ownedAgentRow = shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Alice Assistant" });
  await ownedAgentRow.click();
  await expect((await directResponse).ok()).toBeTruthy();
  expect(directRequestBody).toEqual({
    peer: {
      agent_id: "ak:did_core:web:agents.example:assistant",
      controller_id: "ak:did_core:web:alice.example",
      kind: "agent",
    },
  });
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:AbhO_nhWEZ7jojF3JULUGyzIUTiHNshUWblbkJCr7NbP\/ak:strand:ASy992JMe_xzh5pluAqo5YuyCnAfDdFni4lmeHQldlUM$/,
  );
  await expect(shell.getByTestId("chat-panel")).toHaveCount(1);
  await expect(shell.getByTestId("sidecar-context-strip")).toHaveCount(0);
  await page.waitForTimeout(250);
  expect(sidecarEnsureCount).toBe(0);
});

test("new space strand uses sidebar realm context without home realm picker", async ({
  page,
}) => {
  await refreshServer(page);
  const shell = latestTestId(page, "client-shell");
  await expect(shell.getByTestId("realm-tree-list")).toContainText(
    "Arkret Demo Realm",
  );
  await dismissBlockingRecoveryModal(page);

  const demoRealmRow = shell
    .locator(".sidebar-row")
    .filter({ hasText: "Arkret Demo Realm" })
    .first();
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

test("realm header collapses and sidebar edge resizes the menu", async ({
  page,
}) => {
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
    .toBeGreaterThan(initialBox?.width ?? 0);
  const resizedWidth = (await sidebar.boundingBox())?.width ?? 0;

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });
  await expect
    .poll(
      async () => (await page.getByTestId("sidebar").boundingBox())?.width ?? 0,
    )
    .toBeGreaterThan(300);
  const reloadedWidth =
    (await page.getByTestId("sidebar").boundingBox())?.width ?? 0;
  expect(Math.abs(reloadedWidth - resizedWidth)).toBeLessThan(24);

  await toggle.click();
  await expect
    .poll(async () => (await sidebar.boundingBox())?.width ?? 0)
    .toBeLessThan(100);
  await expect(resizeHandle).toBeHidden();
});

test("loopback proxy server aliases are normalized to local.host", async ({
  page,
}) => {
  await writeLocalConfig(page, { server_url: "http://127.0.0.1:8787/" });
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(latestTestId(page, "client-shell")).toBeVisible({
    timeout: 120_000,
  });

  await openServerSwitcher(page);
  await expect(page.getByTestId("principal-context")).toContainText(
    "https://local.host",
  );
  await expect(page.getByTestId("server-url-input")).toHaveCount(0);
  await expect(page.getByTestId("connect-button")).toHaveCount(0);
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText(
    "https://local.host",
  );
});

test("topbar breadcrumbs avoid duplicated route and server context", async ({
  page,
}) => {
  await openSettings(page);
  await expect(page.getByTestId("topbar-crumbs")).toContainText("Settings");
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText(
    "Settings / Settings",
  );
  await expect(page.getByTestId("topbar-crumbs")).not.toContainText(
    "Station https://",
  );
});

test("dashboard summarizes unread notifications from sync projection", async ({
  page,
}) => {
  await refreshServer(page);

  await expect(page.getByTestId("dashboard-unread-notifications")).toHaveText(
    "2",
  );
  await expect(page.getByTestId("pinned-notifications")).toContainText(
    "New message",
  );
  await expect(page.getByTestId("pinned-notifications")).toContainText(
    "New invite",
  );
});

test("server switcher hides custom endpoint controls", async ({ page }) => {
  await openServerSwitcher(page);

  await expect(page.getByTestId("server-url-input")).toHaveCount(0);
  await expect(page.getByTestId("connect-button")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Services" })).toHaveCount(0);
});

test("server switcher keeps only server choices after expand", async ({
  page,
}) => {
  await openServerSwitcher(page);

  await expect(page.getByTestId("server-switch-menu")).toBeVisible();
  await expect(page.getByTestId("server-option")).toHaveCount(1);
  await expect(page.getByTestId("server-switch-menu")).toContainText(
    "https://local.host",
  );
  await expect(page.getByTestId("server-switch-menu")).not.toContainText(
    "Current data home",
  );
  await expect(page.getByTestId("principal-context")).not.toContainText(
    "Refresh",
  );
});
