import { expect, test, type Page } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openHome(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.locator('[data-testid="sidebar"] a.sidebar-nav-item[href="/"]').click();
  await expect(page.getByTestId("dashboard-panel")).toBeVisible();
}

test("dashboard operational copy and health results follow the active language", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path === "/_arkret/self/events" || path.endsWith("/realm-joins/prepare")) {
      writes.push(path);
    }
  });
  await refreshServer(page);
  await openHome(page);
  const realmCards = page.getByTestId("dashboard-realm-tree-card");
  await expect(realmCards).toHaveCount(3);
  const originalTitles = await realmCards.locator(".title").allTextContents();
  const originalLinks = await realmCards.evaluateAll((cards) => cards.map((card) => card.getAttribute("href")));
  const originalFrontier = await page.getByTestId("event-frontier-card").getAttribute("title");
  const message = page.locator('[data-testid="dashboard-notification-card"][data-kind="message"]');
  await expect(message).toHaveCount(1);
  const notificationId = await message.getAttribute("data-notification-id");
  expect(notificationId).toMatch(/^ak:notification_projection:/);
  await expect(page.getByTestId("dashboard-contacts-count")).toHaveText("1");

  for (const language of ["en", "zh", "en"] as const) {
    if (language !== await page.getByTestId("client-shell").getAttribute("data-locale")) {
      await openSettings(page);
      await page.getByTestId("settings-nav-item-theme").click();
      await page.getByTestId(`language-${language}`).click();
      await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
      await openHome(page);
    }
    const zh = language === "zh";
    const home = page.getByTestId("dashboard-panel");
    await expect(home.getByText(zh ? "活跃 Strand" : "Active strands", { exact: true })).toBeVisible();
    await expect(page.getByTestId("dashboard-contacts-card").locator(".delta")).toHaveText(
      zh ? "待处理 1 · 私聊 1" : "Pending 1 · Direct 1",
    );
    await expect(page.getByTestId("recent-boards").locator("strong")).toHaveText(zh ? "最近的 Strand" : "Recent Strands");
    await expect(page.getByTestId("recent-boards").locator("thead th")).toHaveText(
      zh ? ["", "标题", "Space", "状态", "更新时间"] : ["", "Title", "Space", "State", "Updated"],
    );
    await expect(page.getByTestId("activity-feed").locator(".section-title")).toHaveText(zh ? "最近活动" : "Recent Activity");
    await expect(page.getByTestId("operations-surface").locator("strong")).toHaveText(zh ? "客户端状态" : "Client Status");
    await expect(message.getByTestId("dashboard-notification-kind")).toHaveText(zh ? "消息" : "message");
    await expect(message).toHaveAttribute("data-kind", "message");
    await expect(message).toHaveAttribute("data-notification-id", notificationId!);
    await expect(message.getByTestId("dashboard-notification-title")).toHaveText("New message");
    await expect(message.getByTestId("dashboard-notification-body")).toHaveText("Alice sent a message in Demo Realm");
    expect(await realmCards.locator(".title").allTextContents()).toEqual(originalTitles);
    expect(await realmCards.evaluateAll((cards) => cards.map((card) => card.getAttribute("href")))).toEqual(originalLinks);
    await expect(page.getByTestId("event-frontier-card")).toHaveAttribute("title", originalFrontier!);

    const health = page.getByTestId("check-health-button");
    await expect(health).toHaveAttribute("title", zh ? "检查运行状况" : "Run health checks");
    await expect(health).toHaveAttribute("aria-label", zh ? "检查运行状况" : "Run health checks");
    // Settings navigation remounts Home. Run the normal sequential public
    // checks in each language; retained same-mount results are covered by VDom.
    await health.click();
    await expect(page.getByTestId("dashboard-health-row")).toHaveCount(3);
    await expect(health).toBeEnabled();
    await expect(page.getByTestId("dashboard-health-name")).toHaveText(
      zh ? ["服务说明", "同步", "身份"] : ["Describe", "Sync", "Identity"],
    );
    await expect(page.getByTestId("dashboard-health-value")).toHaveText(
      zh ? ["station v1.0", "9 个配置档", "identity_registry v1.0"] : ["station v1.0", "9 profiles", "identity_registry v1.0"],
    );
  }
  expect(writes).toEqual([]);
});
