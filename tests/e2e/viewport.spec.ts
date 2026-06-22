// Responsive viewport coverage for the web build.
//
// Native iOS / Android artifacts are still host-shell stubs, so this
// suite exercises the shared Dioxus UI in web mode at phone and narrow
// tablet widths.

import { expect, test, type Page } from "@playwright/test";
import { mockCokretApi } from "./mockCokretApi";

const DEMO_REALM = "ck:realm:0196419b-0000-7000-8000-000000000000";
const MOBILE_VIEWPORT = { width: 390, height: 844 }; // iPhone 13
const TABLET_VIEWPORT = { width: 820, height: 1180 }; // iPad Air narrow layout

async function bootAuthenticatedShell(page: Page, viewport = MOBILE_VIEWPORT) {
  await page.setViewportSize(viewport);
  await mockCokretApi(page);
  await page.addInitScript(() => {
    localStorage.setItem(
      "yougen.config.v1",
      JSON.stringify({
        server_url: "https://local.host",
        account_did: "did:web:alice.example",
        device_id: "ck:device:01964137-0000-7000-8000-0000000000a1",
        session_credential: "sx:e2e-token",
      }),
    );
  });
  await page.goto("/", { waitUntil: "domcontentloaded", timeout: 120_000 });
  await expect(page.getByTestId("client-shell")).toBeVisible({ timeout: 120_000 });
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

test.describe("responsive viewport — mobile", () => {
  test("dashboard uses the mobile shell without horizontal overflow", async ({ page }) => {
    await bootAuthenticatedShell(page);

    await expect(page.getByTestId("dashboard-panel")).toBeVisible();
    await expect(page.getByTestId("mobile-shellbar")).toBeVisible();
    await expect(page.getByTestId("mobile-theme-toggle")).toBeVisible();
    await expect(page.getByTestId("sidebar")).toBeHidden();
    await expect(page.locator(".workspace-header")).toBeHidden();

    const layout = await page.evaluate(() => {
      const shellbar = document
        .querySelector('[data-testid="mobile-shellbar"]')
        ?.getBoundingClientRect();
      const main = document
        .querySelector('[data-testid="main-view"]')
        ?.getBoundingClientRect();
      return shellbar && main
        ? {
            shellbarBottom: shellbar.bottom,
            mainTop: main.top,
            mainHeight: main.height,
            mainBottom: main.bottom,
            viewportHeight: window.innerHeight,
          }
        : null;
    });
    expect(layout).not.toBeNull();
    expect(layout!.mainTop).toBeGreaterThanOrEqual(layout!.shellbarBottom - 1);
    expect(layout!.mainHeight).toBeGreaterThan(280);
    expect(layout!.mainBottom).toBeLessThanOrEqual(layout!.viewportHeight + 1);
    await expectNoHorizontalOverflow(page);
  });

  test("drawer stays within the phone viewport", async ({ page }) => {
    await bootAuthenticatedShell(page);

    await page.getByTestId("mobile-nav-toggle").click();
    await expect(page.getByTestId("mobile-nav-drawer")).toBeVisible();
    await expect(page.getByTestId("mobile-dashboard-nav-button")).toBeVisible();
    await expect(page.getByTestId("mobile-directory-nav-button")).toBeVisible();

    const drawer = await page.getByTestId("mobile-nav-drawer").boundingBox();
    expect(drawer).not.toBeNull();
    expect(drawer!.y).toBeGreaterThanOrEqual(MOBILE_VIEWPORT.height * 0.05);
    expect(drawer!.y + drawer!.height).toBeLessThanOrEqual(MOBILE_VIEWPORT.height + 1);
    await expectNoHorizontalOverflow(page);
  });

  test("board remains reachable at mobile width", async ({ page }) => {
    await bootAuthenticatedShell(page);
    await page.goto(`/kanban/${DEMO_REALM}`, { waitUntil: "domcontentloaded" });

    await expect(page.getByTestId("kanban-panel")).toBeVisible();
    await expect(page.getByTestId("kanban-board-grid")).toBeVisible();
    await page.getByTestId("kanban-board-grid").scrollIntoViewIfNeeded();

    const metrics = await page.evaluate(() => {
      const workspace = document.querySelector(".workspace-body")?.getBoundingClientRect();
      const board = document
        .querySelector('[data-testid="kanban-board-grid"]')
        ?.getBoundingClientRect();
      return workspace && board
        ? {
            boardRight: board.right,
            boardBottom: board.bottom,
            workspaceRight: workspace.right,
            workspaceBottom: workspace.bottom,
          }
        : null;
    });

    expect(metrics).not.toBeNull();
    expect(metrics!.boardRight).toBeLessThanOrEqual(metrics!.workspaceRight + 1);
    expect(metrics!.boardBottom).toBeLessThanOrEqual(metrics!.workspaceBottom + 1);
    await expectNoHorizontalOverflow(page);
  });
});

test.describe("responsive viewport — narrow tablet", () => {
  test("kanban keeps columns scrollable inside the content pane", async ({ page }) => {
    await bootAuthenticatedShell(page, TABLET_VIEWPORT);
    await page.goto("/kanban", { waitUntil: "domcontentloaded", timeout: 120_000 });

    await expect(page.getByTestId("kanban-panel")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("mobile-shellbar")).toBeVisible();

    const metrics = await page.evaluate(() => {
      const workspace = document.querySelector(".workspace-body")?.getBoundingClientRect();
      const board = document.querySelector('[data-testid="kanban-board-grid"]');
      const boardRect = board?.getBoundingClientRect();
      return workspace && board && boardRect
        ? {
            boardRight: boardRect.right,
            workspaceRight: workspace.right,
            boardScrollWidth: board.scrollWidth,
            boardClientWidth: board.clientWidth,
          }
        : null;
    });

    expect(metrics).not.toBeNull();
    expect(metrics!.boardRight).toBeLessThanOrEqual(metrics!.workspaceRight + 1);
    expect(metrics!.boardScrollWidth).toBeGreaterThanOrEqual(metrics!.boardClientWidth);
    await expectNoHorizontalOverflow(page);
  });
});

test.describe("ARIA — keyboard + screen reader", () => {
  test("mobile navigation controls expose expanded state", async ({ page }) => {
    await bootAuthenticatedShell(page);

    const toggle = page.getByTestId("mobile-nav-toggle");
    await expect(toggle).toHaveAttribute("aria-label", "Open menu");
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(toggle).toHaveAttribute("aria-controls", "mobile-navigation-drawer");
    await page.getByTestId("mobile-nav-toggle").click();
    await expect(toggle).toHaveAttribute("aria-label", "Close menu");
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(page.getByTestId("mobile-nav-drawer")).toBeVisible();
  });
});
