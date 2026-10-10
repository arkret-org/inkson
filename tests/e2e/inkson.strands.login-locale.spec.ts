import { expect, test } from "@playwright/test";
import { openSettings, registerStrandsBeforeEach } from "./strandsHarness";

registerStrandsBeforeEach();

for (const language of ["en", "zh"] as const) {
  test(`signed-out login preserves the publicly selected ${language} language and server input`, async ({ page }) => {
    await openSettings(page);
    await page.getByTestId("settings-nav-item-theme").click();
    await page.getByTestId(`language-${language}`).click();
    await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
    await page.getByTestId("account-menu-button").click();
    await page.getByTestId("account-menu-session-logout").click();
    await expect(page).toHaveURL(/\/login(?:[?#]|$)/);
    const login = page.getByTestId("login-panel");
    await expect(login).toBeVisible();
    await expect(page.getByTestId("auth-shell")).toHaveAttribute("data-locale", language);
    const zh = language === "zh";
    await expect(login.getByRole("heading", { level: 1 })).toHaveText(zh ? "登录" : "Sign in");
    await expect(login.getByTestId("start-server-login-button")).toHaveText(zh ? "继续" : "Continue");
    const create = login.locator('a[href="/register"]');
    await expect(create).toHaveText(zh ? "第一次使用？创建可恢复的身份" : "New here? Create a recoverable identity");
    await expect(create).toHaveAttribute("href", "/register");
    const input = login.getByTestId("login-server-url");
    const originalUrl = await input.inputValue();
    expect(originalUrl).not.toBe("");
    await expect(input).toHaveAttribute("aria-label", zh ? "登录服务器地址" : "Sign-in server URL");
    const toggle = login.getByTestId("login-server-options-toggle");
    await expect(toggle).toHaveAttribute("aria-label", zh ? "显示预设服务器" : "Show preset servers");
    await toggle.click();
    await expect(login.getByTestId("login-server-options")).toHaveAttribute("aria-label", zh ? "预设服务器" : "Preset servers");
    const selected = login.getByRole("option", { selected: true });
    await expect(selected).toHaveCount(1);
    await expect(selected).toBeVisible();
    const selectedUrl = await selected.locator(".auth-combobox-option-url").innerText();
    // Presets normalize a root URL's trailing slash; the input remains literal.
    expect(new URL(selectedUrl).href).toBe(new URL(originalUrl).href);
    await expect(input).toHaveValue(originalUrl);
    await toggle.click();
    await expect(input).toHaveValue(originalUrl);
    await expect(page.getByTestId("station-connection-review")).toHaveCount(0);
  });
}
