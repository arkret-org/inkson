import { byClass } from "./strandsHarness";
import { expect, test } from "@playwright/test";
import { openSettings, registerStrandsBeforeEach } from "./strandsHarness";

registerStrandsBeforeEach();

for (const language of ["en", "zh"] as const) {
  test(`signed-out login preserves the publicly selected ${language} language and server input`, async ({ page }) => {
    await openSettings(page);
    await byClass(page, "settings-nav-item-theme").click();
    await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    await byClass(page, "account-menu-button").click();
    const logoutResponse = page.waitForResponse(response => response.request().method() === "POST"
      && new URL(response.url()).pathname === "/_arkret/gate/account/logout");
    await byClass(page, "account-menu").getByRole("button", { name: language === "zh" ? "退出登录" : "Log out", exact: true }).click();
    expect((await logoutResponse).status()).toBe(200);
    await expect(page).toHaveURL(/\/login(?:[?#]|$)/);
    const login = byClass(page, "auth-panel");
    await expect(login).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    const zh = language === "zh";
    await expect(login.getByRole("heading", { level: 1 })).toHaveText(zh ? "登录" : "Sign in");
    await expect(byClass(login, "auth-primary")).toHaveText(zh ? "前往服务器登录" : "Sign in to this server");
    const create = login.locator('a[href="/register"]');
    await expect(create).toHaveText(zh ? "第一次使用？创建可恢复的身份" : "New here? Create a recoverable identity");
    await expect(create).toHaveAttribute("href", "/register");
    const input = byClass(login, "auth-station-field").getByRole("textbox");
    const originalUrl = await input.inputValue();
    expect(originalUrl).not.toBe("");
    await expect(input).toHaveAccessibleName(zh ? "登录服务器地址" : "Sign-in server URL");
    const toggle = byClass(login, "auth-combobox-toggle");
    await expect(toggle).toHaveAttribute("aria-label", zh ? "显示预设服务器" : "Show preset servers");
    await toggle.click();
    await expect(byClass(login, "auth-combobox-menu")).toHaveAccessibleName(zh ? "预设服务器" : "Preset servers");
    const selected = login.locator("button.auth-combobox-option.active");
    await expect(selected).toHaveCount(1);
    await expect(selected).toBeVisible();
    const selectedUrl = await selected.locator(".auth-combobox-option-url").innerText();
    // Presets normalize a root URL's trailing slash; the input remains literal.
    expect(new URL(selectedUrl).href).toBe(new URL(originalUrl).href);
    await expect(input).toHaveValue(originalUrl);
    await toggle.click();
    await expect(input).toHaveValue(originalUrl);
    await expect(byClass(page, "auth-connection-review")).toHaveCount(0);
  });
}
