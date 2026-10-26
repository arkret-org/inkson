import { byClass } from "./strandsHarness";
import { expect, test, type Locator, type Page } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openHome(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.locator('[class~="sidebar"] a.sidebar-nav-item[href="/"]').click();
  await expect(byClass(page, "dashboard-panel")).toBeVisible();
}

async function describedSource(row: Locator, className: string) {
  const source = byClass(row, className);
  await expect(source).toHaveCount(1);
  const id = await source.getAttribute("id");
  expect(id).toBeTruthy();
  await expect(row).toHaveAttribute("aria-describedby", id!);
  return source;
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
  const realmCards = byClass(page, "dashboard-realm-tree-card");
  await expect(realmCards).toHaveCount(3);
  const originalTitles = await realmCards.locator(".title").allTextContents();
  const originalLinks = await realmCards.evaluateAll((cards) => cards.map((card) => card.getAttribute("href")));
  const originalFrontier = await (await describedSource(byClass(page, "event-frontier-card"), "dashboard-frontier-provenance")).textContent();
  expect(originalFrontier).toBeTruthy();
  const message = byClass(page, "dashboard-notification-card").filter({ has: byClass(page, "dashboard-notification-source-kind").filter({ hasText: /^message$/ }) });
  await expect(message).toHaveCount(1);
  const source = await describedSource(message, "dashboard-notification-provenance");
  const notificationId = await byClass(source, "dashboard-notification-source-id").textContent();
  expect(notificationId).toMatch(/^ak:notification_projection:/);
  await expect(byClass(page, "dashboard-contacts-count")).toHaveText("1");

  for (const language of ["en", "zh", "en"] as const) {
    if (language !== await page.locator("html").getAttribute("lang")) {
      await openSettings(page);
      await byClass(page, "settings-nav-item-theme").click();
      await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
      await expect(page.locator("html")).toHaveAttribute("lang", language);
      await openHome(page);
    }
    const zh = language === "zh";
    const home = byClass(page, "dashboard-panel");
    await expect(home.getByText(zh ? "活跃 Strand" : "Active strands", { exact: true })).toBeVisible();
    await expect(byClass(page, "dashboard-contacts-card").locator(".delta")).toHaveText(
      zh ? "待处理 1 · 私聊 1" : "Pending 1 · Direct 1",
    );
    await expect(byClass(page, "recent-boards").locator(".surface-head > .dashboard-section-title")).toHaveText(zh ? "最近的 Strand" : "Recent Strands");
    await expect(byClass(page, "recent-boards").locator("thead th")).toHaveText(
      zh ? ["", "标题", "Space", "状态", "更新时间"] : ["", "Title", "Space", "State", "Updated"],
    );
    await expect(byClass(page, "activity-feed").locator(".section-title")).toHaveText(zh ? "最近活动" : "Recent Activity");
    await expect(byClass(page, "operations-surface").locator(".surface-head > .dashboard-section-title")).toHaveText(zh ? "客户端状态" : "Client Status");
    await expect(byClass(message, "dashboard-notification-kind")).toHaveText(zh ? "消息" : "message");
    const currentSource = await describedSource(message, "dashboard-notification-provenance");
    await expect(byClass(currentSource, "dashboard-notification-source-kind")).toHaveText("message");
    await expect(byClass(currentSource, "dashboard-notification-source-id")).toHaveText(notificationId!);
    await expect(byClass(message, "dashboard-notification-title")).toHaveText("New message");
    await expect(byClass(message, "dashboard-notification-body")).toHaveText("Alice sent a message in Demo Realm");
    expect(await realmCards.locator(".title").allTextContents()).toEqual(originalTitles);
    expect(await realmCards.evaluateAll((cards) => cards.map((card) => card.getAttribute("href")))).toEqual(originalLinks);
    await expect(await describedSource(byClass(page, "event-frontier-card"), "dashboard-frontier-provenance")).toHaveText(originalFrontier!);

    const health = byClass(page, "check-health-button");
    await expect(health).toHaveAttribute("aria-label", zh ? "检查运行状况" : "Run health checks");
    await health.hover();
    await expect(page.getByRole("tooltip").filter({ hasText: zh ? "检查运行状况" : "Run health checks" })).toBeVisible();
    await page.mouse.move(0, 0);
    // Settings navigation remounts Home. Run the normal sequential public
    // checks in each language; retained same-mount results are covered by VDom.
    await health.click();
    await expect(byClass(page, "dashboard-health-row")).toHaveCount(3);
    await expect(health).toBeEnabled();
    await expect(byClass(page, "dashboard-health-name")).toHaveText(
      zh ? ["服务说明", "同步", "身份"] : ["Describe", "Sync", "Identity"],
    );
    await expect(byClass(page, "dashboard-health-value")).toHaveText(
      zh ? ["station v1.0", "9 个配置档", "identity_registry v1.0"] : ["station v1.0", "9 profiles", "identity_registry v1.0"],
    );
  }
  expect(writes).toEqual([]);
});
