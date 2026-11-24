import { byClass } from "./strandsHarness";
// Responsive viewport coverage for the web build.
//
// Native iOS / Android artifacts are still host-shell stubs, so this
// suite exercises the shared Glory/Sapid UI in web mode at phone and narrow
// tablet widths.

import { expect, test, type Page } from "@playwright/test";
import { DEMO_REALM, mockArkretApi } from "./mockArkretApi";
import { writeSessionGrantInjection } from "./strandsHarness";

const DESKTOP_VIEWPORT = { width: 1440, height: 900 };
const MOBILE_VIEWPORT = { width: 390, height: 844 }; // iPhone 13
const TABLET_VIEWPORT = { width: 820, height: 1180 }; // iPad Air narrow layout

async function bootAuthenticatedShell(page: Page, viewport = MOBILE_VIEWPORT) {
  await page.setViewportSize(viewport);
  await mockArkretApi(page);
  // Session restore requires an injected grant + DPoP key (the secure store
  // is IndexedDB-only); a bare inkson.config.v1 seed lands on Sign in. The
  // writer touches localStorage, so navigate to the origin first, then
  // reload so boot observes both the config and the injection.
  await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
  await writeSessionGrantInjection(page);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator(".shell.app")).toBeVisible({
    timeout: 120_000,
  });
}

async function expectNoHorizontalOverflow(page: Page) {
  const metrics = await page.evaluate(() => {
    const root = document.documentElement;
    const body = document.body;
    return {
      clientWidth: root.clientWidth,
      scrollWidth: Math.max(root.scrollWidth, body.scrollWidth),
    };
  });
  expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.clientWidth + 1);
}

test.describe("responsive viewport — desktop", () => {
  test("the navigation rail sits beside the workspace", async ({ page }) => {
    await bootAuthenticatedShell(page, DESKTOP_VIEWPORT);
    const rail = page.getByRole("navigation", { name: "Main navigation", exact: true });
    await expect(rail.getByRole("link", { name: "Realms", exact: true })).toBeVisible();
    const railBounds = (await rail.boundingBox())!;
    const workspace = (await byClass(page, "workspace").boundingBox())!;
    expect(railBounds.x + railBounds.width).toBeLessThanOrEqual(workspace.x);
  });
});

test.describe("responsive viewport — mobile", () => {
  test("dashboard uses the mobile navigation rail without horizontal overflow", async ({
    page,
  }) => {
    await bootAuthenticatedShell(page);

    await expect(byClass(page, "dashboard-panel")).toBeVisible();
    await expect(page.locator(".topbar").getByRole("button", { name: "More", exact: true })).toBeVisible();
    const rail = page.getByRole("navigation", { name: "Main navigation", exact: true });
    await expect(rail).toBeVisible();
    const railBounds = (await rail.boundingBox())!;
    const workspace = (await byClass(page, "workspace").boundingBox())!;
    expect(workspace.height).toBeGreaterThan(280);
    expect(workspace.y + workspace.height).toBeLessThanOrEqual(railBounds.y);
    expect(railBounds.y + railBounds.height).toBeLessThanOrEqual(MOBILE_VIEWPORT.height + 1);
    await expectNoHorizontalOverflow(page);
  });

  test("board remains reachable at mobile width", async ({ page }) => {
    await bootAuthenticatedShell(page);
    await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });

    await expect(byClass(page, "kanban-panel")).toBeVisible();
    await expect(byClass(page, "kanban-board-grid")).toBeVisible();
    await byClass(page, "kanban-board-grid").scrollIntoViewIfNeeded();

    const metrics = await page.evaluate(() => {
      const realm = document
        .querySelector(".realm-body")
        ?.getBoundingClientRect();
      const board = document
        .querySelector('[class~="kanban-board-grid"]')
        ?.getBoundingClientRect();
      return realm && board
        ? {
            boardRight: board.right,
            boardBottom: board.bottom,
            realmRight: realm.right,
            realmBottom: realm.bottom,
          }
        : null;
    });

    expect(metrics).not.toBeNull();
    expect(metrics!.boardRight).toBeLessThanOrEqual(
      metrics!.realmRight + 1,
    );
    expect(metrics!.boardBottom).toBeLessThanOrEqual(
      metrics!.realmBottom + 1,
    );
    await expectNoHorizontalOverflow(page);
  });
});

test.describe("responsive viewport — narrow tablet", () => {
  test("kanban keeps columns scrollable inside the content pane", async ({
    page,
  }) => {
    await bootAuthenticatedShell(page, TABLET_VIEWPORT);
    await page.goto("/kanban", {
      waitUntil: "domcontentloaded",
      timeout: 120_000,
    });

    await expect(byClass(page, "kanban-panel")).toBeVisible({
      timeout: 60_000,
    });
    await expect(byClass(page, "navigation-rail")).toBeVisible();

    const metrics = await page.evaluate(() => {
      const realm = document
        .querySelector(".realm-body")
        ?.getBoundingClientRect();
      const board = document.querySelector('[class~="kanban-board-grid"]');
      const boardRect = board?.getBoundingClientRect();
      return realm && board && boardRect
        ? {
            boardRight: boardRect.right,
            realmRight: realm.right,
            boardScrollWidth: board.scrollWidth,
            boardClientWidth: board.clientWidth,
          }
        : null;
    });

    expect(metrics).not.toBeNull();
    expect(metrics!.boardRight).toBeLessThanOrEqual(
      metrics!.realmRight + 1,
    );
    expect(metrics!.boardScrollWidth).toBeGreaterThanOrEqual(
      metrics!.boardClientWidth,
    );
    await expectNoHorizontalOverflow(page);
  });
});

test.describe("ARIA — keyboard + screen reader", () => {
  test("mobile navigation links can be activated with the keyboard", async ({ page }) => {
    await bootAuthenticatedShell(page);

    const rail = page.getByRole("navigation", { name: "Main navigation", exact: true });
    const realms = rail.getByRole("link", { name: "Realms", exact: true });
    await expect(realms).toBeVisible();
    await realms.focus();
    await expect(realms).toBeFocused();
    await realms.press("Enter");
    await expect(page).toHaveURL(/\/realms\/manage$/);
    await expect(realms).toHaveAttribute("aria-current", "page");
    await expect(byClass(page, "workspace-list")).toBeVisible();
  });
});
