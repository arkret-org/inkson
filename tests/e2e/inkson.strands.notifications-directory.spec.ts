import { expect, test } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  DEMO_REALM,
  refreshServer,
  openSettings,
  dismissBlockingRecoveryModal,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openInviteNotification(page: import("@playwright/test").Page) {
  await dismissBlockingRecoveryModal(page);
  await page.getByTestId("topbar-notifications-button").click();
  await expect(page.getByTestId("notifications-drawer")).toBeVisible();
  const item = page
    .getByTestId("notification-item")
    .filter({ has: page.getByTestId("invite-preview") });
  await expect(item).toBeVisible();
  return item;
}

test("invite preview disclosed stays loading then visible and only Accept joins", async ({
  page,
}) => {
  const writes: Array<{ path: string; body: string }> = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      path === "/_arkret/self/realm-joins/prepare" ||
      path === "/_arkret/self/events"
    ) {
      writes.push({ path, body: request.postData() ?? "" });
    }
  });

  const item = await openInviteNotification(page);
  await expect(item.getByTestId("invite-preview-loading")).toBeVisible();
  await expect(item.getByTestId("invite-preview-disclosed")).toBeVisible();
  await expect(item.getByTestId("invite-preview-name")).toHaveText(
    "Preview-only Realm",
  );
  await expect(
    page.getByTestId("realm-tree-node-button").filter({
      hasText: "Preview-only Realm",
    }),
  ).toHaveCount(0);
  expect(writes).toEqual([]);

  await item.getByTestId("notification-action").click();
  await expect
    .poll(() =>
      writes.some((request) =>
        request.path.endsWith("/realm-joins/prepare"),
      ),
    )
    .toBe(true);
  await expect
    .poll(() =>
      writes.some(
        (request) =>
          request.path.endsWith("/events") &&
          request.body.includes("ak.invite.accept"),
      ),
    )
    .toBe(true);
  await expect(page.getByTestId("notifications-status")).toContainText(
    "Joined Realm",
  );
});

test("invite preview restricted remains preview-only", async ({ page }) => {
  let prepareRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/realm-joins/prepare")) {
      prepareRequests += 1;
    }
  });

  const item = await openInviteNotification(page);
  await expect(item.getByTestId("invite-preview-restricted")).toBeVisible();
  await expect(item.getByTestId("notification-action")).toBeVisible();
  expect(prepareRequests).toBe(0);
  await expect(
    page.getByTestId("realm-tree-node-button").filter({
      hasText: "Preview-only Realm",
    }),
  ).toHaveCount(0);
});

test("invite preview retries a transient failure without joining", async ({
  page,
}) => {
  let prepareRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/realm-joins/prepare")) {
      prepareRequests += 1;
    }
  });

  const item = await openInviteNotification(page);
  await expect(item.getByTestId("invite-preview-unavailable")).toBeVisible();
  await item.getByTestId("invite-preview-retry").click();
  await expect(item.getByTestId("invite-preview-disclosed")).toBeVisible();
  expect(prepareRequests).toBe(0);
  await expect(
    page.getByTestId("realm-tree-node-button").filter({
      hasText: "Preview-only Realm",
    }),
  ).toHaveCount(0);
});

test("notifications are derived from index projections and respect per-realm mute rules", async ({
  page,
}) => {
  await refreshServer(page);
  const realmUrl = page.url();
  await page.getByTestId("topbar-notifications-button").click();

  expect(page.url()).toBe(realmUrl);
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
  await expect(page.getByTestId("settings-muted-realm-row")).toHaveCount(0);
});

test("topbar notifications drawer keeps the active realm navigation visible", async ({
  page,
}) => {
  await refreshServer(page);
  await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });
  await expect(page.getByTestId("kanban-panel")).toBeVisible();
  await dismissBlockingRecoveryModal(page);
  const realmUrl = page.url();

  await page.getByTestId("topbar-notifications-button").click();

  expect(page.url()).toBe(realmUrl);
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
      .querySelector(".realm-header")
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
  expect(page.url()).toBe(realmUrl);
});

test("directory search refuses unannounced Realms and still resolves organizations", async ({
  page,
}) => {
  await page.getByTestId("topbar-search-button").click();
  await page.getByTestId("global-search-input").fill("demo");
  await page.getByTestId("global-search-input").press("Enter");
  await expect(page.getByTestId("directory-panel")).toBeVisible();

  await page.getByTestId("directory-search-input").fill("demo");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("directory-result")).toHaveCount(0);

  await page.getByTestId("tab-organizations").click();
  await page.getByTestId("directory-search-input").fill("arkret");
  await page.getByTestId("directory-search-button").click();
  await expect(page.getByTestId("org-result")).toContainText("Arkret Labs");
  await expect(page.getByTestId("org-result")).toContainText("arkret.example");
  await page.getByTestId("org-search-members").click();
  await expect(page.getByTestId("tab-actors")).toHaveAttribute(
    "data-style",
    "primary",
  );
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
  await page.keyboard.press("Escape");

  await page.keyboard.press("Control+/");
  await expect(page.getByTestId("shortcut-help-overlay")).toBeVisible();
});

test("global keyboard shortcuts trigger their target surfaces", async ({
  page,
}) => {
  await dismissBlockingRecoveryModal(page);

  await page.keyboard.press("Control+K");
  await expect(page.getByTestId("command-palette")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("command-palette")).toHaveCount(0);

  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(page.getByTestId("global-search-panel")).toBeVisible();
});
