import { expect, test } from "@playwright/test";
import { byClass, registerStrandsBeforeEach, gotoAndDismissRecovery, dismissBlockingRecoveryModal } from "./strandsHarness";

registerStrandsBeforeEach({ emptyBoard: true });
test.use({ screenshot: "only-on-failure" });

for (const viewport of [{ width: 1440, height: 960 }, { width: 390, height: 844 }, { width: 320, height: 568 }, { width: 844, height: 390 }]) {
  test(`icon rail and list/detail navigation at ${viewport.width}px`, async ({ page }) => {
    const mobile = viewport.width <= 860;
    await page.setViewportSize(viewport);
    await gotoAndDismissRecovery(page, "/settings/theme");
    const rail = byClass(page, "navigation-rail");
    await expect(rail).toBeVisible();
    await expect(rail.locator("a.rail-link")).toHaveCount(6);
    await expect(byClass(page, "server-switch-button")).toHaveCount(0);
    await expect(byClass(page, "sidebar-collapse-toggle")).toHaveCount(0);
    await expect(page.locator(".topbar .rail-account")).toHaveCount(0);
    const logo = byClass(page, "rail-logo");
    if (mobile) {
      await expect(rail.locator("a.rail-link:visible")).toHaveCount(4);
      await expect(logo).toBeHidden();
      await expect(byClass(page, "rail-settings")).toBeHidden();
    } else {
      await expect(logo).toBeVisible();
      await expect.poll(() => logo.evaluate((img: HTMLImageElement) => img.complete && img.naturalWidth > 0)).toBe(true);
    }
    await page.screenshot({ path: test.info().outputPath(`settings-${viewport.width}.png`) });
    const settings = byClass(page, "rail-settings");
    const avatar = rail.locator(".rail-account");
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
    const account = byClass(page, "account-page");
    const accountSettings = byClass(account, "account-page-settings");
    await expect(page).toHaveURL(/\/account$/);
    await expect(avatar).toHaveAttribute("aria-current", "page");
    await expect(account).toBeVisible();
    const accountBox = (await account.boundingBox())!;
    expect(accountBox.x).toBeGreaterThanOrEqual(0);
    expect(accountBox.x + accountBox.width).toBeLessThanOrEqual(viewport.width);
    await page.screenshot({ path: test.info().outputPath(`account-${viewport.width}.png`) });
    await page.goBack();
    await expect(page).toHaveURL(/\/settings\/theme$/);
    await expect(account).toHaveCount(0);
    await avatar.click();
    if (mobile) {
      await expect(accountSettings).toBeVisible();
      await accountSettings.click();
    } else {
      await expect(accountSettings).toBeHidden();
      await settings.click();
    }
    await expect(page).toHaveURL(/\/settings$/);
    await expect(byClass(page, "settings-shell")).toBeVisible();
    await expect(byClass(page, "settings-nav-item-agents")).toHaveCount(0);
    const backToAccount = page.getByRole("button", { name: "Back to account", exact: true });
    const backToList = page.getByRole("button", { name: "Back to list", exact: true });
    const activeList = page.locator(".workspace-pane-list.is-visible");
    if (mobile) {
      await expect(backToAccount).toBeInViewport();
      await byClass(page, "settings-nav-item-theme").click();
      await expect(backToList).toBeInViewport();
      await expect(backToAccount).toBeHidden();
      await backToList.click();
      await backToAccount.click();
      await expect(page).toHaveURL(/\/account$/);
      await expect(account).toBeVisible();
    } else {
      await expect(backToAccount).toHaveCount(0);
    }
    await byClass(page, "rail-agents").click();
    await expect(page).toHaveURL(/\/agents(?:\?filter=)?$/);
    await expect(byClass(page, "agent-admin-layout")).toBeVisible();
    await expect(byClass(page, "settings-shell")).toHaveCount(0);
    await page.screenshot({ path: test.info().outputPath(`agents-${viewport.width}.png`) });
    if (mobile) {
      await expect(activeList).toHaveCSS("animation-name", "none");
      await byClass(page, "agent-admin-create-open-button").click();
      await expect(backToList).toBeInViewport();
      await expect(page.locator(".topbar-context-title")).toHaveText("My Agents");
      await backToList.click();
      await expect(byClass(page, "agent-admin-list-pane")).toBeVisible();
    }
    await byClass(page, "rail-contacts").click();
    await expect(byClass(page, "contacts-layout")).toBeVisible();
    if (mobile) await expect(activeList).toHaveCSS("animation-name", "none");
    const items = byClass(page, "contact-list-item");
    await expect.poll(() => items.count()).toBeGreaterThan(1);
    await items.last().click();
    await expect(items.last()).toHaveClass(/is-active/);
    await expect(page.locator(".contacts-detail-pane .contact-row")).toHaveCount(1);
    if (mobile) {
      await expect(byClass(page, "contacts-list-pane")).toBeHidden();
      await expect(byClass(page, "contacts-detail-pane")).toBeVisible();
      await expect(backToList).toBeInViewport();
      await expect(page.locator(".topbar-context-title")).toHaveText("Contacts");
    } else {
      const listBox = (await byClass(page, "contacts-list-pane").boundingBox())!;
      const detailBox = (await byClass(page, "contacts-detail-pane").boundingBox())!;
      expect(detailBox.x).toBeGreaterThan(listBox.x + listBox.width - 1);
    }
    await page.screenshot({ path: test.info().outputPath(`contacts-${viewport.width}.png`) });
    await byClass(page, "rail-realms").click();
    await expect(byClass(page, "workspace-list")).toBeVisible();
    await expect(byClass(page, "rail-realms")).toHaveAttribute("aria-current", "page");
    await page.screenshot({ path: test.info().outputPath(`realms-${viewport.width}.png`) });
    if (mobile) await expect(activeList).toHaveCSS("animation-name", "none");
    await page.locator(".workspace-list .realm-tree-item").first().click();
    await expect(byClass(page, "kanban-empty-board")).toBeVisible();
    const realmHeader = page.locator(".main.realm > .topbar.realm-header");
    await expect(realmHeader).toBeInViewport();
    if (mobile) {
      await expect(backToList).toBeInViewport();
      await expect(page.locator(".main.realm")).toHaveCSS("animation-name", "none");
      await expect(page.locator(".main.realm > .realm-body")).toHaveCSS("animation-name", "workspace-detail-enter");
      await backToList.click();
      await expect(byClass(page, "workspace-list")).toBeVisible();
    } else {
      const collapse = page.getByRole("button", { name: "Collapse list", exact: true });
      const expand = page.getByRole("button", { name: "Expand list", exact: true });
      await collapse.click();
      await expect(byClass(page, "workspace-list")).toBeHidden();
      await expand.click();
      await expect(byClass(page, "workspace-list")).toBeVisible();
    }
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
