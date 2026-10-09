import { expect, test, type Page } from "@playwright/test";
import {
  registerStrandsBeforeEach,
  gotoAndDismissRecovery,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("settings capabilities and consent read surfaces and forms follow the active language", async ({ page }) => {
  await page.route("**/_arkret/self/authz/effective-grants?*", async (route) => {
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ grants: [] }) });
  });
  let failConsent = true;
  let consentReads = 0;
  await page.route("**/_arkret/self/consent/results", async (route) => {
    consentReads += 1;
    await route.fulfill({
      status: failConsent ? 500 : 200,
      contentType: failConsent ? "application/problem+json" : "application/json",
      body: JSON.stringify(failConsent
        ? {
            type: "https://arkret.org/problems/internal_error",
            title: "Internal error",
            status: 500,
            detail: "consent-read-detail / 原文",
            code: "internal_error",
          }
        : { consents: [] }),
    });
  });
  await gotoAndDismissRecovery(page, "/settings/capabilities");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await page.getByTestId("settings-nav-item-capabilities").click();
    const capabilities = page.getByTestId("capability-list-panel");
    await expect(capabilities.locator(".event-head").first()).toHaveText(language === "zh" ? "权限授权" : "Capabilities");
    await expect(page.getByTestId("capability-empty")).toContainText(language === "zh" ? "没有权限授权" : "No capabilities");
    await expect(page.getByTestId("capability-relinquish-button")).toHaveCount(0);
    failConsent = true;
    await page.getByTestId("settings-nav-item-consent").click();
    const error = page.getByTestId("consent-load-error");
    await expect(error).toContainText(language === "zh" ? "无法加载联系许可：" : "Couldn't load consent:");
    await expect(error).toContainText(language === "zh"
      ? "与服务器通信时出现问题。请重试。"
      : "Something went wrong while talking to the server. Try again.");
    await expect(error).not.toContainText("consent-read-detail / 原文");
    failConsent = false;
    const readsBefore = consentReads;
    await page.getByTestId("consent-retry-button").click();
    await expect.poll(() => consentReads).toBeGreaterThan(readsBefore);
    await expect(error).toHaveCount(0);
    await expect(page.getByTestId("consent-grant-empty")).toContainText(language === "zh" ? "尚未设置联系许可" : "No consent decisions yet");
    await page.getByTestId("consent-new-grant-button").click();
    await expect(page.getByTestId("consent-new-grant-submit-button")).toBeDisabled();
    await page.getByTestId("consent-new-grant-scope-input").getByRole("button").click();
    for (const name of language === "zh"
      ? ["群组邀请", "语音通话", "视频通话", "在线状态", "全部联系许可"]
      : ["Group invites", "Voice calls", "Video calls", "Presence", "All consent permissions"]) {
      await expect(page.getByRole("option", { name, exact: true })).toBeVisible();
    }
    await page.keyboard.press("Escape");
    await page.getByTestId("consent-request-button").click();
    await expect(page.getByTestId("consent-request-submit-button")).toBeDisabled();
    await expect(page.getByTestId("consent-request-submit-button")).toHaveText(language === "zh" ? "发送请求" : "Send request");
  }
});

test("settings invite policy labels and options follow the active language without saving", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/_arkret/self/invite-receive-policy" && request.method() === "PUT") {
      writes.push(request.url());
    }
  });
  await gotoAndDismissRecovery(page, "/settings/invite-policy");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await page.getByTestId("settings-nav-item-invite-policy").click();
    await expect(page.getByTestId("invite-policy-panel")).toBeVisible();
    await expect(page.getByTestId("invite-policy-save-button")).toHaveText(language === "zh" ? "保存" : "Save");
    await page.getByTestId("invite-policy-explicit-behavior").getByRole("button").click();
    for (const name of language === "zh" ? ["直接丢弃", "暂存待审", "通知我"] : ["Drop", "Hold for review", "Notify me"]) {
      await expect(page.getByRole("option", { name, exact: true })).toBeVisible();
    }
    await page.keyboard.press("Escape");
    await expect(page.getByTestId("invite-policy-explicit-behavior").getByRole("button")).toHaveText(language === "zh" ? "暂存待审" : "Hold for review");
    await expect(page.getByTestId("invite-policy-panel")).toContainText(language === "zh"
      ? "允许已批准的联系人查看邀请结果" : "Let approved contacts see the invite outcome");
    await expect(page.getByTestId("invite-policy-panel")).toContainText(language === "zh"
      ? "允许发现信任来源查看邀请结果" : "Let discovery-trust sources see the invite outcome");
    // Theme navigation remounts this page; the unchanged server policy restores
    // its blocked row on each visit. Local removal must never issue a PUT.
    const blocked = page.getByTestId("invite-policy-blocked-row");
    await expect(blocked).toHaveCount(1);
    await blocked.getByRole("button").click();
    await expect(page.getByTestId("invite-policy-blocked-empty")).toBeVisible();
    await expect(page.getByTestId("invite-policy-status")).toHaveText(language === "zh"
      ? "已从屏蔽列表移除,记得点击保存。"
      : "Removed from the block list — remember to save.");
  }
  expect(writes).toEqual([]);
});

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
