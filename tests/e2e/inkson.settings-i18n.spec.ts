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

test("settings storage quota, low space, refresh and errors follow the active language", async ({
  page,
}) => {
  await page.addInitScript(() => {
    const probe = window as Window & {
      storageQuotaProbe?: { fail: boolean; calls: number };
    };
    probe.storageQuotaProbe = { fail: false, calls: 0 };
    Object.defineProperty(StorageManager.prototype, "estimate", {
      configurable: true,
      value: async () => {
        probe.storageQuotaProbe!.calls += 1;
        if (probe.storageQuotaProbe!.fail) {
          throw new Error("storage-quota-detail / 原文");
        }
        return { usage: 9216, quota: 10240 };
      },
    });
  });
  await gotoAndDismissRecovery(page, "/settings/storage");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await page.getByTestId("settings-nav-item-storage").click();
    const quota = page.getByTestId("browser-storage-quota");
    const cache = page.getByTestId("e2ee-plaintext-cache");
    await expect(quota).toContainText(language === "zh"
      ? "浏览器站点存储配额"
      : "Browser origin quota");
    await expect(page.getByTestId("browser-storage-quota-warning")).toHaveText(
      language === "zh" ? "空间不足" : "Low space",
    );
    await expect(quota).toContainText(language === "zh"
      ? "9.0 KiB / 10.0 KiB (90%)"
      : "9.0 KiB of 10.0 KiB (90%)");
    await expect(quota).toContainText(language === "zh"
      ? "请在浏览器开始拒绝写入前检查本地数据。"
      : "Review local data before the browser starts rejecting writes.");
    await expect(cache).toContainText(language === "zh"
      ? "此账号没有缓存受保护的明文。"
      : "No protected plaintext is cached for this account.");
    await expect(cache).toContainText(language === "zh"
      ? "0 个 Realm 中共 0 条"
      : "0 across 0 Realms");
    await expect(page.getByTestId("e2ee-cache-clear-all")).toBeDisabled();
    await expect(page.getByTestId("e2ee-cache-clear-modal")).toHaveCount(0);
    const refresh = page.getByTestId("e2ee-cache-refresh");
    await expect(refresh).toHaveText(language === "zh" ? "刷新" : "Refresh");
    const callsBefore = await page.evaluate(() => {
      const probe = window as Window & {
        storageQuotaProbe?: { fail: boolean; calls: number };
      };
      probe.storageQuotaProbe!.fail = true;
      return probe.storageQuotaProbe!.calls;
    });
    await refresh.click();
    await expect(quota).toContainText(language === "zh"
      ? "无法获取浏览器配额："
      : "Browser quota unavailable:");
    await expect(quota).toContainText("storage-quota-detail / 原文");
    await expect.poll(() => page.evaluate(() => (window as Window & {
      storageQuotaProbe?: { calls: number };
    }).storageQuotaProbe!.calls)).toBeGreaterThan(callsBefore);
    await page.evaluate(() => {
      (window as Window & { storageQuotaProbe?: { fail: boolean } })
        .storageQuotaProbe!.fail = false;
    });
    await refresh.click();
    await expect(page.getByTestId("browser-storage-quota-warning")).toBeVisible();
    await expect(quota).not.toContainText("storage-quota-detail");
  }
});
