import { expect, test, type Page } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  gotoAndDismissRecovery,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function selectLanguage(page: Page, language: "en" | "zh") {
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId(`language-${language}`).click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute(
    "data-locale",
    language,
  );
}

test("settings notification labels and options switch between Chinese and English", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/notifications");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await page.getByTestId("settings-nav-item-notifications").click();
    const labels = language === "zh"
      ? ["提及通知", "回应通知", "邀请通知", "消息通知"]
      : [
          "Mention notifications",
          "Reaction notifications",
          "Invite notifications",
          "Message notifications",
        ];
    const kinds = ["mention", "reaction", "invite", "message"];
    for (const [index, kind] of kinds.entries()) {
      await expect(
        page.getByTestId(`settings-notification-kind-${kind}`).locator("strong"),
      ).toHaveText(labels[index]);
    }
    const mention = page.getByTestId("settings-notification-kind-mention");
    const checkbox = mention.getByRole("checkbox");
    const wasEnabled = (await checkbox.getAttribute("aria-checked")) === "true";
    await checkbox.click();
    await expect(mention).toContainText(language === "zh"
      ? (wasEnabled ? "已静音" : "已开启")
      : (wasEnabled ? "Muted" : "Enabled"));
    await page.getByTestId("realm-override-level-select").click();
    const options = language === "zh"
      ? ["所有消息", "我参与的讨论和 @", "仅 @ 我", "静音"]
      : [
          "All messages",
          "Participating and @mentions",
          "Mentions only",
          "Muted",
        ];
    for (const name of options) {
      await expect(page.getByRole("option", { name, exact: true })).toBeVisible();
    }
    await page.keyboard.press("Escape");
  }
});

test("settings encrypted recovery status and guidance follow the active language", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/encryption");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await page.getByTestId("settings-nav-item-encryption").click();
    const panel = page.getByTestId("settings-mls-recovery");
    await expect(panel).toBeVisible();
    await expect(panel.locator(".event-head")).toContainText(language === "zh"
      ? "加密历史恢复"
      : "Encrypted history recovery");
    const badge = page.getByTestId("settings-mls-recovery-status-badge");
    await expect(badge).not.toHaveAttribute("data-status", "loading");
    const status = await badge.getAttribute("data-status");
    const labels: Record<string, readonly [string, string]> = {
      "no-local-secret": ["Not ready yet", "尚未就绪"],
      "backed-up": ["Backed up", "已备份"],
      "not-backed-up": ["Not backed up", "未备份"],
    };
    expect(status).not.toBeNull();
    expect(labels[status!]).toBeDefined();
    await expect(badge).toHaveText(labels[status!][language === "zh" ? 1 : 0]);
    await expect(
      page.getByTestId("settings-mls-recovery-warning"),
    ).toContainText(language === "zh"
      ? "恢复词"
      : "recovery words");
    await expect(
      page.getByTestId("settings-mls-keypackages-refill-button"),
    ).toHaveText(language === "zh"
      ? "检查并补充 KeyPackage"
      : "Check and replenish KeyPackages");
  }
});
