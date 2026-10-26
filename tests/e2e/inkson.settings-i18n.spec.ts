import { byClass } from "./strandsHarness";
import { expect, test, type Page } from "@playwright/test";
import { CURRENT_ACCOUNT_ID, validateMockSchema } from "./mockArkretApi";
import {
  registerStrandsBeforeEach,
  gotoAndDismissRecovery,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("settings capabilities and consent read surfaces and forms follow the active language", async ({ page }) => {
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
          }
        : { consents: [] }),
    });
  });
  await gotoAndDismissRecovery(page, "/settings/capabilities");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await byClass(page, "settings-nav-item-capabilities").click();
    const capabilities = page.locator(".settings-content-column > .event").filter({ has: byClass(page, "capabilities-empty") });
    await expect(capabilities.locator(".event-head").first()).toHaveText(language === "zh" ? "权限授权" : "Capabilities");
    await expect(byClass(page, "capabilities-empty")).toContainText(language === "zh" ? "没有权限授权" : "No capabilities");
    await expect(byClass(page, "capability-relinquish-open")).toHaveCount(0);
    failConsent = true;
    await byClass(page, "settings-nav-item-consent").click();
    const error = byClass(page, "consent-load-error");
    await expect(error).toContainText(language === "zh" ? "无法加载联系许可：" : "Couldn't load consent:");
    await expect(error).toContainText(language === "zh"
      ? "与服务器通信时出现问题。请重试。"
      : "Something went wrong while talking to the server. Try again.");
    await expect(error).not.toContainText("consent-read-detail / 原文");
    failConsent = false;
    const readsBefore = consentReads;
    await byClass(page, "consent-retry-button").click();
    await expect.poll(() => consentReads).toBeGreaterThan(readsBefore);
    await expect(error).toHaveCount(0);
    await expect(byClass(page, "consent-peer-empty")).toContainText(language === "zh" ? "尚未设置联系许可" : "No consent decisions yet");
    await expect(byClass(page, "consent-read-complete-button")).toBeDisabled();
    await expect(byClass(page, "consent-confirm-replace-button")).toHaveCount(0);
    await expect(byClass(page, "consent-read-complete-button")).toHaveText(language === "zh" ? "读取完整许可" : "Read complete permissions");
    const scopes = byClass(page, "consent-request-scope-input").getByRole("combobox");
    await expect(scopes).toBeVisible();
    await scopes.click();
    for (const name of language === "zh"
      ? ["语音通话", "视频通话", "在线状态"]
      : ["Voice calls", "Video calls", "Presence"]) {
      await expect(page.getByRole("option", { name, exact: true })).toBeVisible();
    }
    await expect(page.getByRole("option")).toHaveCount(3);
    await page.keyboard.press("Escape");
    await expect(byClass(page, "consent-request-submit-button")).toBeDisabled();
    await expect(byClass(page, "consent-request-submit-button")).toHaveText(language === "zh" ? "发送请求" : "Send request");
  }
});

test("invite policy saves the actual Account policy and restores it after reload", async ({ page }) => {
  const policyPath = "/_arkret/self/invite-receive-policy";
  const writes: Array<Record<string, unknown>> = [];
  page.on("request", request => {
    if (request.method() === "PUT" && new URL(request.url()).pathname === policyPath) {
      // Observe every actual write before validating it in the test flow. A
      // callback assertion must not hide an emitted request from the count.
      writes.push(request.postDataJSON());
    }
  });
  await gotoAndDismissRecovery(page, "/settings/invite-policy");
  await expect(byClass(page, "invite-policy-blocked-row")).toHaveCount(1);
  await byClass(page, "invite-policy-explicit-behavior").getByRole("combobox").click();
  await page.getByRole("option", { name: "Notify me", exact: true }).click();
  await byClass(page, "invite-policy-blocked-row").getByRole("button").click();
  await expect(page.getByText("No blocked inviters.", { exact: true })).toBeVisible();
  const saveResponsePromise = page.waitForResponse(response =>
    response.request().method() === "PUT" && new URL(response.url()).pathname === policyPath);
  await byClass(page, "invite-policy-save-button").click();
  const saveResponse = await saveResponsePromise;
  expect(saveResponse.status()).toBe(200);
  const savedPolicy = await saveResponse.json();
  await expect(byClass(page, "write-status")).toHaveText("Saved.");
  expect(writes).toHaveLength(1);
  const written = writes[0];
  validateMockSchema("schemas/invite-receive-policy.schema.json", written);
  expect(written.account_id).toEqual(CURRENT_ACCOUNT_ID);
  expect(written.explicit_address_behavior).toBe("notify");
  // The formal field is optional. The SDK canonical serializer omits an
  // empty denied_actor_ids Vec; omission decodes as the empty block list.
  expect(written).not.toHaveProperty("denied_actor_ids");
  expect(savedPolicy).toEqual(written);
  const reloadResponsePromise = page.waitForResponse(response =>
    response.request().method() === "GET" && new URL(response.url()).pathname === policyPath);
  await page.reload();
  const reloadResponse = await reloadResponsePromise;
  expect(reloadResponse.status()).toBe(200);
  expect(await reloadResponse.json()).toEqual(written);
  await expect(byClass(page, "invite-policy-explicit-behavior").getByRole("combobox")).toHaveText("Notify me");
  await expect(page.getByText("No blocked inviters.", { exact: true })).toBeVisible();
  expect(writes).toHaveLength(1);
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
    await byClass(page, "settings-nav-item-invite-policy").click();
    const policy = page.locator(".settings-content-column > .event").filter({ has: byClass(page, "invite-policy-save-button") });
    await expect(policy).toBeVisible();
    await expect(byClass(page, "invite-policy-save-button")).toHaveText(language === "zh" ? "保存" : "Save");
    const behavior = byClass(page, "invite-policy-explicit-behavior").getByRole("combobox");
    await expect(behavior).toBeVisible();
    await behavior.click();
    for (const name of language === "zh" ? ["直接丢弃", "暂存待审", "通知我"] : ["Drop", "Hold for review", "Notify me"]) {
      await expect(page.getByRole("option", { name, exact: true })).toBeVisible();
    }
    await page.keyboard.press("Escape");
    await expect(behavior).toHaveText(language === "zh" ? "暂存待审" : "Hold for review");
    await expect(policy).toContainText(language === "zh"
      ? "允许已批准的联系人查看邀请结果" : "Let approved contacts see the invite outcome");
    await expect(policy).toContainText(language === "zh"
      ? "允许发现信任来源查看邀请结果" : "Let discovery-trust sources see the invite outcome");
    // Theme navigation remounts this page; the unchanged server policy restores
    // its blocked row on each visit. Local removal must never issue a PUT.
    const blocked = byClass(page, "invite-policy-blocked-row");
    await expect(blocked).toHaveCount(1);
    await blocked.getByRole("button").click();
    await expect(page.getByText(language === "zh" ? "没有被屏蔽的邀请者。" : "No blocked inviters.", { exact: true })).toBeVisible();
    await expect(byClass(page, "write-status")).toHaveText(language === "zh"
      ? "已从屏蔽列表移除,记得点击保存。"
      : "Removed from the block list — remember to save.");
  }
  expect(writes).toEqual([]);
});

async function selectLanguage(page: Page, language: "en" | "zh") {
  await byClass(page, "settings-nav-item-theme").click();
  await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
  await expect(page.locator("html")).toHaveAttribute("lang", language);
}

test("settings notification labels and options switch between Chinese and English", async ({
  page,
}) => {
  await gotoAndDismissRecovery(page, "/settings/notifications");
  for (const language of ["en", "zh", "en"] as const) {
    await selectLanguage(page, language);
    await byClass(page, "settings-nav-item-notifications").click();
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
        byClass(page, `settings-notification-kind-${kind}`).locator(".settings-notification-kind-label"),
      ).toHaveText(labels[index]);
      await expect(byClass(page, `settings-notification-kind-${kind}`).getByRole("checkbox")).toHaveAccessibleName(labels[index]);
    }
    const mention = byClass(page, "settings-notification-kind-mention");
    const checkbox = mention.getByRole("checkbox");
    const wasEnabled = await checkbox.isChecked();
    await checkbox.click();
    await expect(checkbox).toBeChecked({ checked: !wasEnabled });
    await expect(mention).toContainText(language === "zh"
      ? (wasEnabled ? "已静音" : "已开启")
      : (wasEnabled ? "Muted" : "Enabled"));
    const levels = byClass(page, "realm-override-level-select").getByRole("combobox");
    await expect(levels).toBeVisible();
    await levels.click();
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
    await byClass(page, "settings-nav-item-encryption").click();
    const panel = byClass(page, "settings-mls-recovery");
    await expect(panel).toBeVisible();
    await expect(panel.locator(".event-head")).toContainText(language === "zh"
      ? "加密历史恢复"
      : "Encrypted history recovery");
    const badge = byClass(page, "settings-mls-recovery-status-badge");
    await expect(badge).not.toHaveClass(/settings-mls-recovery-status--loading/);
    const status = (await badge.getAttribute("class"))?.match(/settings-mls-recovery-status--([\w-]+)/)?.[1] ?? null;
    const labels: Record<string, readonly [string, string]> = {
      "no-local-secret": ["Not ready yet", "尚未就绪"],
      "backed-up": ["Backed up", "已备份"],
      "not-backed-up": ["Not backed up", "未备份"],
    };
    expect(status).not.toBeNull();
    expect(labels[status!]).toBeDefined();
    await expect(badge).toHaveText(labels[status!][language === "zh" ? 1 : 0]);
    await expect(
      byClass(page, "settings-mls-recovery-warning"),
    ).toContainText(language === "zh"
      ? "恢复词"
      : "recovery words");
    await expect(
      byClass(page, "settings-mls-keypackages-refill-button"),
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
    await byClass(page, "settings-nav-item-storage").click();
    const quota = byClass(page, "browser-storage-quota");
    const cache = byClass(page, "e2ee-plaintext-cache");
    await expect(quota).toContainText(language === "zh"
      ? "浏览器站点存储配额"
      : "Browser origin quota");
    await expect(byClass(page, "browser-storage-quota-warning")).toHaveText(
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
    await expect(byClass(page, "e2ee-cache-clear-all")).toBeDisabled();
    await expect(byClass(page, "e2ee-cache-clear-modal")).toHaveCount(0);
    const refresh = byClass(page, "e2ee-cache-refresh");
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
    await expect(byClass(page, "browser-storage-quota-warning")).toBeVisible();
    await expect(quota).not.toContainText("storage-quota-detail");
  }
});
