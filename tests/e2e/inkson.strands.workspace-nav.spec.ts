import { expect, test } from "@playwright/test";
import {
  DEMO_BOARD_SPACE,
  DEMO_REALM,
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

test("ordinary Circle list fails closed when the response contains a Sidecar profile", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/realms/ak:realm:0196419b-0000-7000-8000-000000000000/circles");
  const panel = page.getByTestId("circles-panel");
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId("circle-list-item")).toHaveCount(1);
  await expect(panel).toContainText("Demo Circle");
  await expect(panel).not.toContainText("Alice AI Sidecar");
});

test("Circle creation establishes initial membership and opens the detail view", async ({ page }) => {
  await gotoAndDismissRecovery(page, "/realms/ak:realm:0196419b-0000-7000-8000-000000000000/circles");
  const panel = page.getByTestId("circles-panel");
  await panel.getByTestId("circle-create-open").click();
  await page.getByTestId("circle-create-title").fill("Incident Response");
  await page.getByTestId("circle-create-submit").click();

  await expect(page).toHaveURL(/\/realms\/.*\/circles\/ak:circle:/);
  await expect(panel.getByTestId("circle-detail")).toContainText("Incident Response");
  await expect(panel.getByTestId("circle-detail")).toContainText("1 active members");
  await expect(panel.getByTestId("circle-detail")).toContainText("Member");
});

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
  await expect(shell.getByTestId("contacts-sidebar-summary")).toHaveCount(0);
  await expect(shell.getByTestId("contact-sidebar-self-row")).toContainText("alice:local.host");
  await expect(shell.getByTestId("contact-sidebar-self-badge")).toHaveText("ME");
  await expect(shell.locator(".contact-sidebar-group").first()).toHaveAttribute(
    "data-testid",
    "contact-sidebar-self-group",
  );
  await expect(shell.getByTestId("contact-sidebar-self-agents")).toContainText("Alice Assistant");
  const ownAgentRow = shell.getByTestId("contact-sidebar-agent-row").filter({ hasText: "Alice Assistant" });
  await expect(ownAgentRow.locator(".contact-sidebar-agent-avatar img")).toHaveCount(1);
  await expect(ownAgentRow).not.toContainText("active");
  await expect(ownAgentRow).not.toContainText("paused");
  await expect(ownAgentRow).toHaveCSS("min-height", "34px");
  await expect(shell.getByTestId("contact-sidebar-agent-toggle").first()).toContainText("Agents 1");
  await shell.getByTestId("contact-sidebar-agent-toggle").first().click();
  await expect(shell.getByTestId("contact-sidebar-contact-agents")).toContainText("Bob Helper");
  await expect(
    shell.getByTestId("contact-sidebar-agent-row").filter({ hasText: "Bob Helper" }).locator(".contact-sidebar-agent-avatar img"),
  ).toHaveCount(1);
  const bobContactRow = shell
    .getByTestId("direct-conversation-row")
    .filter({ hasText: "bob:example.com" });
  await expect(bobContactRow).toContainText("DM");
  await expect(bobContactRow).toHaveAttribute(
    "aria-label",
    "Chat with bob:example.com",
  );
  await expect(shell.getByTestId("direct-conversation-row").filter({ hasText: "carol:example.com" })).toContainText(
    "pending",
  );
  await bobContactRow.click();
  await expect(page).toHaveURL(
    /\/direct\/ak:realm:01964137-0000-7000-8000-00000000d0b1\/ak:strand:01964137-0000-7000-8000-00000000d0b2$/,
  );
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  await shell.getByTestId("contact-sidebar-agent-row").filter({ hasText: "Bob Helper" }).click();
  await expect(page).toHaveURL(/\/direct\/.*0000000000b1\/.*0000000000b2$/);
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  await shell.getByTestId("realm-sidebar-manage-home-button").click();
  await expect(page).toHaveURL(/\/contacts\/manage$/);
  await expect(shell.getByTestId("contacts-manage-page")).toBeVisible();
  await expect(shell.getByTestId("contacts-manage-page")).toContainText("bob:example.com");
});

test("owned agent ensure opens the dedicated private Sidecar shell", async ({ page }) => {
  await gotoAndDismissRecovery(page, `/kanban/${DEMO_REALM}/board/${DEMO_BOARD_SPACE}`);
  const shell = latestTestId(page, "client-shell");
  await shell.getByTestId("realm-sidebar-tab-direct").click();

  let releaseEnsure!: () => void;
  let ensureRequestBody: Record<string, any> | null = null;
  const ensureGate = new Promise<void>((resolve) => {
    releaseEnsure = resolve;
  });
  await page.route("**/_arkret/self/agent-sidecar-threads:ensure", async (route) => {
    ensureRequestBody = await route.request().postDataJSON();
    await ensureGate;
    await route.fallback();
  });

  const ownedAgentRow = shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Alice Assistant" });
  await expect(ownedAgentRow).toHaveAttribute(
    "aria-label",
    "Chat with Alice Assistant",
  );
  const ensureResponse = page.waitForResponse(
    (response) =>
      response.url().includes("/_arkret/self/agent-sidecar-threads:ensure"),
    { timeout: 20_000 },
  );
  const contextResponse = page.waitForResponse(
    (response) =>
      response.url().includes(`/_arkret/self/realms/${DEMO_REALM}/strands`),
    { timeout: 20_000 },
  );
  try {
    await ownedAgentRow.click();
    const projectedStrands = await contextResponse;
    expect(projectedStrands.ok()).toBeTruthy();
    await expect(ownedAgentRow).toHaveAttribute("aria-busy", "true");
    await expect(ownedAgentRow).toBeDisabled();
    await expect(ownedAgentRow).toContainText("Opening...");
  } finally {
    releaseEnsure();
  }
  await expect((await ensureResponse).ok()).toBeTruthy();
  expect(ensureRequestBody?.context_ref).toEqual({
    realm_id: DEMO_REALM,
    strand_id: "ak:strand:0196419b-0000-7000-8000-000000000101",
  });

  await expect(page).toHaveURL(
    /\/direct\/.*\/ak:strand:01964137-0000-7000-8000-0000000000a2$/,
  );
  await expect(shell.getByTestId("sidecar-context-strip")).toBeVisible();
  await expect(shell.getByTestId("sidecar-addressed-now")).toContainText(
    "assistant",
  );
  await expect(shell.getByTestId("sidecar-security-state")).toContainText(
    "E2EE",
  );
  await expect(shell.getByTestId("sidecar-plaintext-disclosure")).toHaveCount(0);
  await expect(shell.getByTestId("send-e2ee-move-button")).toHaveCount(0);
  await expect(shell.getByTestId("send-chat-button")).toBeEnabled();
  await expect(shell.getByTestId("discussion-users-panel")).toHaveCount(0);
  await expect(shell.getByTestId("chat-call-voice-button")).toBeHidden();

  const eventLoopDelay = await page.evaluate(async () => {
    const startedAt = performance.now();
    await new Promise((resolve) => setTimeout(resolve, 100));
    return performance.now() - startedAt;
  });
  expect(eventLoopDelay).toBeLessThan(1_000);
  await expect(shell.getByTestId("chat-panel")).toHaveCount(1);

  await shell.getByRole("button", { name: "Access" }).click();
  await expect(shell.getByTestId("sidecar-access-panel")).toContainText(
    "Addressed now",
  );
  await expect(shell.getByTestId("sidecar-access-panel")).toContainText(
    "assistant",
  );
  await expect(shell.getByTestId("sidecar-agent-row")).toHaveCount(1);

  await shell.getByTestId("mention-trigger-button").click();
  const sidecarMentionButtons = shell.locator(
    '[data-testid="mention-picker"] button[data-testid="mention-suggestion"]',
  );
  await expect(sidecarMentionButtons).toHaveCount(1);
  await expect(sidecarMentionButtons).toHaveAttribute(
    "data-mention-did",
    "did:web:agents.example:assistant",
  );
  await shell.getByTestId("mention-picker-close-button").click();

  await shell.getByTestId("discussion-settings-toggle").click();
  await expect(shell.getByTestId("sidecar-connection-details")).toContainText(
    "Trace ID",
  );
});

test("pending sidecar reconciliation blocks send without claiming readiness", async ({ page }) => {
  const shell = latestTestId(page, "client-shell");
  await dismissBlockingRecoveryModal(page);
  await shell.getByTestId("realm-sidebar-tab-direct").click();
  const ensureResponse = page.waitForResponse(
    (response) =>
      response.url().endsWith("/_arkret/self/agent-sidecar-threads:ensure"),
    { timeout: 20_000 },
  );
  await shell
    .getByTestId("contact-sidebar-agent-row")
    .filter({ hasText: "Alice Assistant" })
    .click();
  await expect((await ensureResponse).ok()).toBeTruthy();

  await expect(shell.getByTestId("sidecar-security-state")).toHaveText(
    "Reconciling access",
  );
  await expect(shell.getByTestId("sidecar-readiness-gate")).toContainText(
    "1 member",
  );
  await expect(shell.getByTestId("send-chat-button")).toBeDisabled();
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
