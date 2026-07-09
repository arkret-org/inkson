import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  refreshServer,
  openSettings,
  dismissBlockingRecoveryModal,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("notifications are derived from index projections and respect per-realm mute rules", async ({
  page,
}) => {
  await refreshServer(page);
  const workspaceUrl = page.url();
  await page.getByTestId("topbar-notifications-button").click();

  expect(page.url()).toBe(workspaceUrl);
  await expect(page.getByTestId("notifications-drawer")).toBeVisible();
  await expect(page.getByTestId("notifications-panel")).toBeVisible();
  await expect(page.getByTestId("notifications-panel")).toContainText(
    "Alice sent a message in Demo Realm",
  );

  await page
    .getByTestId("notification-item")
    .filter({ hasText: "Alice sent a message in Demo Realm" })
    .getByTestId("mute-realm-button")
    .click();
  await expect(page.getByTestId("notifications-panel")).not.toContainText(
    "Alice sent a message in Demo Realm",
  );
  await page.getByTestId("notifications-drawer-close").click();
  await expect(page.getByTestId("notifications-drawer")).toBeHidden();

  await openSettings(page);
  await page.getByTestId("settings-nav-item-notifications").click();
  await expect(page.getByTestId("settings-muted-realm-row")).toHaveAttribute(
    "data-realm-id",
    DEMO_REALM,
  );
  await page.getByTestId("settings-realm-override-remove").click();
  // Operation feedback now surfaces as a toast (unified feedback system
  // Wave 1); the sr-only status-label is connection-status only.
  await expect(
    page.locator('[data-testid="toast-item"][data-i18n-key="feedback.override_removed"]'),
  ).toBeVisible();

  await page.getByTestId("topbar-notifications-button").click();
  await expect(page.getByTestId("notifications-panel")).toContainText(
    "You were invited to review Demo Realm",
  );
  const acceptInvite = page.waitForRequest(
    (request) =>
      request.url().endsWith("/_arkret/self/events") &&
      request.method() === "POST",
  );
  await page
    .getByTestId("notification-item")
    .filter({ hasText: "You were invited to review Demo Realm" })
    .getByTestId("notification-action")
    .click();
  const acceptBody = await acceptInvite.then((request) =>
    request.postDataJSON(),
  );
  expect(acceptBody.kind).toBe("ak.member.state");
  expect(acceptBody.payload.invite_ref).toBe(
    "ak:invite:01904100-0000-7000-8000-000000000099",
  );
  expect(acceptBody.payload).not.toHaveProperty("invite_id");
  await expect(page.getByTestId("notifications-status")).toContainText(
    "Joined Realm",
  );
});

test("topbar notifications drawer keeps the active realm navigation visible", async ({
  page,
}) => {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  const workspaceUrl = page.url();

  await page.getByTestId("topbar-notifications-button").click();

  expect(page.url()).toBe(workspaceUrl);
  await expect(page.getByTestId("notifications-drawer")).toBeVisible();
  await expect(page.getByTestId("notifications-drawer-scrim")).toHaveCount(0);
  await expect(page.getByTestId("notifications-drawer-settings")).toBeVisible();
  await expect(page.getByTestId("notifications-settings-hint")).toHaveCount(0);
  await expect(page.getByTestId("realm-context-bar")).toBeVisible();
  await expect(page.getByTestId("notifications-panel")).toContainText("Latest");
  await expect(page.getByTestId("notifications-panel")).not.toContainText(
    "Notification settings",
  );

  const drawerLayout = await page.evaluate(() => {
    const header = document
      .querySelector(".workspace-header")
      ?.getBoundingClientRect();
    const sidebar = document
      .querySelector('[data-testid="sidebar"]')
      ?.getBoundingClientRect();
    const panel = document
      .querySelector('[data-testid="notifications-drawer-panel"]')
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
        sidebarHit?.closest('[data-testid="notifications-drawer"]'),
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

  await page.getByTestId("notifications-drawer-close").click();
  await expect(page.getByTestId("notifications-drawer")).toBeHidden();
  expect(page.url()).toBe(workspaceUrl);
});

test("directory search resolve and space selection strand works", async ({
  page,
}) => {
  await page.getByTestId("topbar-search-button").click();
  await page.getByTestId("global-search-input").fill("demo");
  await page.getByTestId("global-search-input").press("Enter");
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(page.getByTestId("index-query-results")).toContainText(
    "Arkret Demo Realm",
  );
  await expect(page.getByTestId("generic-entity-card")).toHaveAttribute(
    "data-render-kind",
    "card",
  );
  await expect(page.getByTestId("entity-type-label")).toContainText("space");
  await expect(page.getByTestId("entity-facets")).toContainText("renderable");
  await expect(page.getByTestId("projection-facets")).toContainText(
    "item: stateful, rankable",
  );
  await expect(page.getByTestId("unknown-facets-debug")).toContainText(
    "com.example.preview",
  );

  await page.getByTestId("directory-select-button").click();
  await page.getByTestId("resolve-selected-button").click();
  // Resolve feedback is a toast now; the message carries the join rule.
  await expect(
    page.locator('[data-testid="toast-item"][data-i18n-key="feedback.realm_resolved"]'),
  ).toContainText("public");
  await expect(page.getByTestId("directory-result").first()).toContainText(
    "Arkret Demo Realm",
  );

  await page.getByTestId("directory-advanced-diagnostics-toggle").click();
  await page.getByTestId("tab-objects").click();
  await page.getByTestId("directory-search-input").fill("launch");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("protocol-object-results")).toContainText(
    "Launch checklist card",
  );
  await expect(page.getByTestId("protocol-object-results")).toContainText(
    "Restricted discussion",
  );
  await expect(page.getByTestId("protocol-object-results")).toContainText(
    "locked",
  );

  await page.getByTestId("tab-organizations").click();
  await page.getByTestId("directory-search-input").fill("arkret");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("org-result")).toContainText("Arkret Labs");
  await expect(page.getByTestId("org-result")).toContainText("arkret.example");
  await page.getByTestId("org-search-members").click();
  await expect(page.getByTestId("tab-actors")).toHaveClass(/primary/);
  await expect(page.getByTestId("directory-search-input")).toHaveValue(
    "arkret.example",
  );
});

test("command palette closes with Escape and outside click", async ({
  page,
}) => {
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

test("shortcut help opens from the topbar and the ? key", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);
  await page.getByTestId("topbar-shortcuts-button").click();
  await expect(page.getByTestId("shortcut-help-overlay")).toBeVisible();
  await expect(page.getByTestId("shortcut-help-card")).toContainText("Ctrl");
  await expect(page.getByTestId("shortcut-help-card")).toContainText("F");
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("shortcut-help-overlay")).toHaveCount(0);

  await page.keyboard.press("Shift+/");
  await expect(page.getByTestId("shortcut-help-overlay")).toBeVisible();
});

test("global keyboard shortcuts trigger their target surfaces", async ({ page }) => {
  await dismissBlockingRecoveryModal(page);

  await page.keyboard.press("Control+K");
  await expect(page.getByTestId("command-palette")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("command-palette")).toHaveCount(0);

  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(page.getByTestId("global-search-panel")).toBeVisible();
});
