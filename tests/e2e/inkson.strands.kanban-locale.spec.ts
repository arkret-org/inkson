import { expect, test } from "@playwright/test";
import {
  DEMO_BOARD_SPACE,
  dismissBlockingRecoveryModal,
  openKanban,
  openSettings,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("Kanban local controls and card sections follow the language without changing card content", async ({ page }) => {
  await openKanban(page);
  const boardPath = new URL(page.url()).pathname;
  const writes: string[] = [];
  page.on("request", (request) => {
    if (request.method() === "POST" && new URL(request.url()).pathname === "/_arkret/self/events") {
      writes.push(request.postData() ?? "");
    }
  });
  const original = await page.getByTestId("kanban-card").first().locator(".board-card-title").textContent();
  const originalLabels = await page.getByTestId("kanban-card").first().locator(".board-card-labels .badge").allTextContents();
  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await page.getByTestId("settings-nav-item-theme").click();
    await page.getByTestId(`language-${language}`).click();
    await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
    await page.goBack();
    await page.goBack();
    await expect(page).toHaveURL((url) => url.pathname === boardPath
      || url.pathname === `${boardPath}/board/${DEMO_BOARD_SPACE}`);
    await expect(page.getByTestId("kanban-panel")).toBeVisible();
    await dismissBlockingRecoveryModal(page);
    const zh = language === "zh";
    await expect(page.getByTestId("board-space-select-button")).toHaveAttribute("aria-label", zh ? "切换看板" : "Switch board");
    await expect(page.getByTestId("board-space-select-button")).toHaveAttribute("title", new RegExp(`^${zh ? "切换看板：" : "Switch board: "}`));
    await expect(page.getByTestId("kanban-card").first().locator(".board-card-title")).toHaveText(original ?? "");
    expect(await page.getByTestId("kanban-card").first().locator(".board-card-labels .badge").allTextContents()).toEqual(originalLabels);
    await page.getByTestId("new-board-toggle").click();
    await expect(page.getByTestId("new-board-title-input")).toHaveAttribute("placeholder", zh ? "看板标题" : "Board title");
    await page.getByTestId("new-board-toggle").click();
    await page.getByTestId("kanban-card").first().click();
    const detail = page.getByTestId("card-detail-modal");
    await expect(detail.getByTestId("card-detail-tab-description")).toHaveText(zh ? "描述" : "Description");
    await expect(detail.getByTestId("card-detail-tab-synthesis")).toHaveText(zh ? "总结" : "Synthesis");
    await expect(detail.getByTestId("card-detail-tab-discussion")).toHaveText(zh ? "讨论" : "Discussion");
    await expect(detail.getByTestId("card-detail-close-button")).toHaveAttribute("aria-label", zh ? "关闭卡片详情" : "Close card detail");
    await detail.getByTestId("card-detail-close-button").click();
  }
  expect(writes).toEqual([]);
});
