import { expect, test } from "@playwright/test";
import { byClass, registerStrandsBeforeEach, gotoAndDismissRecovery, dismissBlockingRecoveryModal } from "./strandsHarness";

registerStrandsBeforeEach();
test.use({ screenshot: "only-on-failure" });

for (const viewport of [{ width: 1440, height: 960 }, { width: 390, height: 844 }, { width: 320, height: 568 }, { width: 844, height: 390 }]) {
  test(`icon rail and list/detail navigation at ${viewport.width}px`, async ({ page }) => {
    const mobile = viewport.width <= 860;
    await page.setViewportSize(viewport);
    await gotoAndDismissRecovery(page, "/settings/theme");
    const rail = byClass(page, "navigation-rail");
    await expect(rail).toBeVisible();
    await expect(rail.locator("a.rail-link")).toHaveCount(5);
    await expect(byClass(page, "server-switch-button")).toHaveCount(0);
    await expect(byClass(page, "sidebar-collapse-toggle")).toHaveCount(0);
    await expect(page.locator(".topbar .account-menu-wrap .sapid-popover-trigger")).toHaveCount(0);
    const logo = byClass(page, "rail-logo");
    if (mobile) {
      await expect(rail.locator("a.rail-link:visible")).toHaveCount(3);
      await expect(logo).toBeHidden();
      await expect(byClass(page, "rail-settings")).toBeHidden();
    } else {
      await expect(logo).toBeVisible();
      await expect.poll(() => logo.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
    }
    await page.screenshot({ path: test.info().outputPath(`settings-${viewport.width}.png`) });
    const settings = byClass(page, "rail-settings");
    const avatar = rail.locator(".account-menu-wrap .sapid-popover-trigger");
    const avatarBox = (await avatar.boundingBox())!;
    if (mobile) {
      const railBox = (await rail.boundingBox())!;
      const workspaceBox = (await byClass(page, "workspace").boundingBox())!;
      expect(railBox.x).toBe(0);
      expect(railBox.width).toBe(viewport.width);
      expect(railBox.y + railBox.height).toBe(viewport.height);
      expect(workspaceBox.x).toBe(0);
      expect(workspaceBox.width).toBe(viewport.width);
      expect(workspaceBox.y + workspaceBox.height).toBeLessThanOrEqual(railBox.y);
      let previousRight = 0;
      for (const target of [byClass(page, "rail-realms"), byClass(page, "rail-contacts"), byClass(page, "rail-agents"), avatar]) {
        const box = (await target.boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(previousRight);
        expect(box.y).toBe(avatarBox.y);
        expect(box.width).toBeGreaterThanOrEqual(44);
        expect(box.height).toBeGreaterThanOrEqual(44);
        previousRight = box.x + box.width;
      }
    } else {
      const settingsBox = (await settings.boundingBox())!;
      expect(settingsBox.y).toBeGreaterThan(viewport.height - 150);
      expect(avatarBox.y).toBeGreaterThan(settingsBox.y);
    }
    await avatar.click();
    const menu = byClass(page, "account-menu");
    await expect(menu).toBeVisible();
    const menuBox = (await menu.boundingBox())!;
    if (!mobile) expect(menuBox.x).toBeGreaterThan(avatarBox.x);
    expect(menuBox.x).toBeGreaterThanOrEqual(0);
    expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(viewport.width);
    expect(menuBox.y).toBeGreaterThanOrEqual(0);
    expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(viewport.height);
    await page.screenshot({ path: test.info().outputPath(`account-${viewport.width}.png`) });
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
    if (mobile) {
      await avatar.click();
      await byClass(page, "account-menu-settings").click();
      await expect(byClass(page, "settings-shell")).toBeVisible();
      await expect(menu).toBeHidden();
    }
    await expect(byClass(page, "settings-nav-item-agents")).toHaveCount(0);
    await byClass(page, "rail-agents").click();
    await expect(page).toHaveURL(/\/agents(?:\?filter=)?$/);
    await expect(byClass(page, "agent-admin-layout")).toBeVisible();
    await expect(byClass(page, "settings-shell")).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath(`agents-${viewport.width}.png`) });
    await byClass(page, "rail-contacts").click();
    await expect(byClass(page, "contacts-layout")).toBeVisible();
    const items = byClass(page, "contact-list-item");
    await expect.poll(() => items.count()).toBeGreaterThan(1);
    await items.last().click();
    await expect(items.last()).toHaveClass(/is-active/);
    await expect(page.locator(".contacts-detail-pane .contact-row")).toHaveCount(1);
    const listBox = (await byClass(page, "contacts-list-pane").boundingBox())!;
    const detailBox = (await byClass(page, "contacts-detail-pane").boundingBox())!;
    if (!mobile) expect(detailBox.x).toBeGreaterThan(listBox.x + listBox.width - 1);
    else expect(detailBox.y).toBeGreaterThanOrEqual(listBox.y + listBox.height - 1);
    await page.screenshot({ path: test.info().outputPath(`contacts-${viewport.width}.png`) });
    await byClass(page, "rail-realms").click();
    await expect(byClass(page, "workspace-list")).toBeVisible();
    await expect(byClass(page, "rail-realms")).toHaveAttribute("aria-current", "page");
    await page.screenshot({ path: test.info().outputPath(`realms-${viewport.width}.png`) });
    if (!mobile) {
      await byClass(page, "rail-brand").click();
      await expect(page).toHaveURL(/\/$/);
      await dismissBlockingRecoveryModal(page);
      await expect(byClass(page, "workspace-list")).toHaveCount(0);
    } else {
      await page.setViewportSize({ width: 1024, height: 768 });
      await expect(logo).toBeVisible();
      await expect(settings).toBeVisible();
      await page.setViewportSize(viewport);
      await expect(logo).toBeHidden();
      await expect(settings).toBeHidden();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  });
}
