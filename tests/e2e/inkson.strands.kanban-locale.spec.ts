import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
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
  // Capture the committed fixture content, after its initial metadata read.
  // A transient unavailable placeholder is not the card value under test.
  const firstTitle = byClass(page, "kanban-card").first().locator(".board-card-title");
  await expect(firstTitle).toHaveText("Legal review for public beta");
  const original = await firstTitle.textContent();
  const originalLabels = await byClass(page, "kanban-card").first().locator(".board-card-labels .badge").allTextContents();
  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await byClass(page, "settings-nav-item-theme").click();
    await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    await page.goBack();
    await page.goBack();
    await expect(page).toHaveURL((url) => url.pathname === boardPath
      || url.pathname === `${boardPath}/board/${DEMO_BOARD_SPACE}`);
    await expect(byClass(page, "kanban-panel")).toBeVisible();
    await dismissBlockingRecoveryModal(page);
    const zh = language === "zh";
    await expect(byClass(page, "board-space-select-button")).toHaveAttribute("aria-label", zh ? "切换看板" : "Switch board");
    await byClass(page, "board-space-select-button").hover();
    await expect(page.getByRole("tooltip")).toHaveText(new RegExp(`^${zh ? "切换看板：" : "Switch board: "}`));
    await page.mouse.move(0, 0);
    await expect(byClass(page, "kanban-card").first().locator(".board-card-title")).toHaveText(original ?? "");
    expect(await byClass(page, "kanban-card").first().locator(".board-card-labels .badge").allTextContents()).toEqual(originalLabels);
    await byClass(page, "new-board-toggle").click();
    const boardTitle = inputByClass(page, "new-board-title-input");
    await expect(boardTitle).toHaveAccessibleName(zh ? "看板标题" : "Board title");
    const draft = await boardTitle.inputValue();
    await boardTitle.fill("");
    await expect(page.locator(".board-create-popover .input-empty-prompt")).toHaveText(zh ? "看板标题" : "Board title");
    await boardTitle.fill(draft);
    await byClass(page, "new-board-toggle").click();
    await byClass(page, "kanban-card").first().click();
    const detail = byClass(page, "card-detail-modal");
    await expect(byClass(detail, "card-detail-tab-description")).toHaveText(zh ? "描述" : "Description");
    await expect(byClass(detail, "card-detail-tab-synthesis")).toHaveText(zh ? "总结" : "Synthesis");
    await expect(byClass(detail, "card-detail-tab-discussion")).toHaveText(zh ? "讨论" : "Discussion");
    await expect(byClass(detail, "card-detail-close-button")).toHaveAttribute("aria-label", zh ? "关闭卡片详情" : "Close card detail");
    await byClass(detail, "card-detail-close-button").click();
  }
  expect(writes).toEqual([]);
});
