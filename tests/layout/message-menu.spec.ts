import { expect, test, type Locator } from "@playwright/test";
import { messageMenuFixture } from "./message-menu-fixture.mjs";

const rect = async (locator: Locator) => locator.evaluate((el) => {
  const { x, y, width, height, top, right, bottom, left } = el.getBoundingClientRect();
  return { x, y, width, height, top, right, bottom, left };
});

test("short message keeps the trigger inside its header and the menu beside it", async ({ page }) => {
  await page.setContent(messageMenuFixture());
  const trigger = page.getByRole("button", { name: "消息操作" });
  const button = await rect(trigger);
  const bubble = await rect(page.locator(".msg-body"));
  const header = await rect(page.locator(".msg-head"));
  expect(button.width).toBe(32);
  expect(button.height).toBe(32);
  expect(button.top).toBeGreaterThan(bubble.top);
  expect(button.bottom).toBeLessThanOrEqual(header.bottom + 2);
  expect(button.right).toBeLessThan(bubble.right);
  await trigger.click();
  const menu = await rect(page.getByRole("menu"));
  expect(menu.top).toBe(button.bottom + 6);
  expect(menu.right).toBe(button.right);
  await expect(page.getByRole("menuitem", { name: "回复", exact: true })).toHaveCSS("justify-content", "flex-start");
  const hits = await page.getByRole("menuitem", { name: "回复", exact: true }).evaluate(el => {
    const r = el.getBoundingClientRect();
    return [r.left + 4, r.right - 4].every(x => document.elementFromPoint(x, r.top + r.height / 2) === el);
  });
  expect(hits).toBe(true);
  await page.screenshot({ path: "test-results/layout/message-menu-desktop.png" });
});

test("the first and only message can open upwards near the feed bottom", async ({ page }) => {
  await page.setContent(messageMenuFixture({ bottom: true }));
  const trigger = page.getByRole("button", { name: "消息操作" });
  await trigger.click();
  const button = await rect(trigger);
  const menu = await rect(page.getByRole("menu"));
  expect(menu.bottom).toBe(button.top - 6);
  expect(menu.top).toBeGreaterThan(24);
});

test("a long message still opens below its header, independent of bubble height", async ({ page }) => {
  await page.setContent(messageMenuFixture({ long: true }));
  const trigger = page.getByRole("button", { name: "消息操作" });
  await trigger.click();
  expect((await rect(page.getByRole("menu"))).top).toBe((await rect(trigger)).bottom + 6);
});

test("narrow touch layout preserves badges and usable menu rows", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 360, height: 640 }, isMobile: true, hasTouch: true });
  const mobile = await context.newPage();
  await mobile.setContent(messageMenuFixture({ badges: true }));
  const trigger = mobile.getByRole("button", { name: "消息操作" });
  const button = await rect(trigger);
  expect(button.width).toBe(40);
  expect((await rect(mobile.locator(".message-pin-indicator"))).right).toBeLessThan(button.left);
  expect((await rect(mobile.locator(".message-private-saved-indicator"))).right).toBeLessThan((await rect(mobile.locator(".message-pin-indicator"))).left);
  await trigger.click();
  const menu = await rect(mobile.getByRole("menu"));
  expect(menu.left).toBeGreaterThanOrEqual(32);
  expect(menu.right).toBeLessThanOrEqual(328);
  expect((await rect(mobile.getByRole("menuitem", { name: "回复", exact: true }))).height).toBeGreaterThanOrEqual(44);
  await mobile.screenshot({ path: "test-results/layout/message-menu-mobile.png" });
  await context.close();
});

test("limited height scrolls the menu without covering the trigger", async ({ page }) => {
  await page.setContent(messageMenuFixture({ compact: true }));
  const trigger = page.getByRole("button", { name: "消息操作" });
  await trigger.click();
  const menu = page.getByRole("menu");
  const bounds = await rect(menu);
  const feed = await rect(page.getByTestId("message-list"));
  expect(bounds.bottom).toBeLessThanOrEqual(feed.bottom - 8);
  expect(bounds.top).toBe((await rect(trigger)).bottom + 6);
  expect(await menu.evaluate(el => el.scrollHeight > el.clientHeight)).toBe(true);
  await menu.press("End");
  await expect(page.getByRole("menuitem", { name: "撤回", exact: true })).toBeFocused();
  await expect.poll(() => menu.evaluate(el => el.scrollTop)).toBeGreaterThan(0);
});

test("keyboard navigation skips disabled items and Escape restores the trigger", async ({ page }) => {
  await page.setContent(messageMenuFixture());
  const trigger = page.getByRole("button", { name: "消息操作" });
  await trigger.press("Enter");
  await expect(page.getByRole("menuitem", { name: "回复", exact: true })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("menuitem", { name: "回应", exact: true })).toBeFocused();
  await page.keyboard.press("ArrowDown");
  await expect(page.getByRole("menuitem", { name: "共享钉选", exact: true })).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("menu")).toHaveCount(0);
  await expect(trigger).toBeFocused();
  await trigger.click();
  await page.mouse.click(8, 8);
  await expect(page.getByRole("menu")).toHaveCount(0);
});

test("scroll and window resize keep the menu attached and dismiss offscreen anchors", async ({ page }) => {
  await page.setContent(messageMenuFixture({ bottom: true }));
  const trigger = page.getByRole("button", { name: "消息操作" });
  await trigger.click();
  await page.getByTestId("message-list").evaluate(el => { el.scrollTop = 240; });
  await expect.poll(async () => Math.abs((await rect(page.getByRole("menu"))).top - (await rect(trigger)).bottom - 6)).toBeLessThan(1);
  await page.setViewportSize({ width: 480, height: 650 });
  await expect.poll(async () => (await rect(page.getByRole("menu"))).right).toBeLessThanOrEqual(448);
  await page.getByTestId("message-list").evaluate(el => { el.scrollTop = el.scrollHeight; });
  await expect(page.getByRole("menu")).toHaveCount(0);
});
