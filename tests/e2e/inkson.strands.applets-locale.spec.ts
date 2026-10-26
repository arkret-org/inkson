import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
import { expect, test, type Page } from "@playwright/test";
import {
  dismissBlockingRecoveryModal,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openApplets(page: Page) {
  // The public Applets route requires the existing experimental-applets feature.
  await page.goto("/applets", { waitUntil: "domcontentloaded" });
  await dismissBlockingRecoveryModal(page);
  await expect(byClass(page, "applets-panel")).toBeVisible();
}

test("applet registry and install form copy follow the active language without authoring events", async ({ page }) => {
  const sideEffects: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      path === "/_arkret/self/events" ||
      path.endsWith("/realm-joins/prepare") ||
      (path.startsWith("/_arkret/") && path.split("/").includes("applets"))
    ) {
      sideEffects.push(`${request.method()} ${path}`);
    }
  });
  await refreshServer(page);
  const literalManifest = '{"description":"applets.registry {value} 原文"}';
  const literalCircle = "ak:circle:AQSS_m6w3ODdIeq8Yzac2ghmcQVOGLXWA5PXFcSnVcgN";
  const literalActions = "ak.message.create,\nak.applet.ghost.provision";

  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await byClass(page, "settings-nav-item-theme").click();
    await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    // Normal Settings navigation remounts Applets. Retained helper labels are
    // verified natively; no private state or fabricated registry rows are used.
    await openApplets(page);
    const zh = language === "zh";
    const panel = byClass(page, "applets-panel");
    await expect(panel).toHaveAttribute("aria-label", zh ? "小程序注册表与桥接错误" : "Applet registry and bridge errors");
    await expect(panel.getByText(zh ? "小程序注册表" : "Applet registry", { exact: true })).toBeVisible();
    await expect(panel.getByText(zh ? "已注册 0 个" : "0 registered", { exact: true })).toBeVisible();
    await expect(byClass(panel, "applet-registry-empty")).toHaveText(
      zh ? "尚未注册小程序。请使用下方已签名小程序包的安装流程；注册记录会在提交时生成。" : "No applets registered yet. Use the signed Applet Package install flow below; registration is derived during commit.",
    );
    await expect(byClass(panel, "applet-registration-row")).toHaveCount(0);
    const errors = byClass(panel, "applet-bridge-errors");
    await expect(errors.getByText(zh ? "桥接错误" : "Bridge errors", { exact: true })).toBeVisible();
    await expect(errors.getByText(zh ? "尚未观察到桥接错误。" : "No bridge errors observed.", { exact: true })).toBeVisible();
    await expect(byClass(panel, "applet-empty")).toHaveText(zh ? "此 Realm 尚未观察到小程序 Service。" : "No Applet Services observed in this Realm.");
    await expect(byClass(panel, "applet-row")).toHaveCount(0);
    await expect(byClass(panel, "applet-accountability-modal")).toHaveCount(0);
    const toggle = byClass(panel, "applet-install-button");
    await expect(toggle).toHaveText(zh ? "+ 安装小程序" : "+ Install applet");
    await toggle.click();
    await expect(toggle).toHaveText(zh ? "关闭安装表单" : "Close install");
    const manifest = inputByClass(panel, "applet-install-manifest-input");
    const circle = inputByClass(panel, "applet-install-circle-input");
    const actions = inputByClass(panel, "applet-install-approve-actions-input");
    await expect(byClass(panel, "applet-install-manifest-input-prompt").locator(".input-empty-prompt")).toHaveText( zh ? "清单网址或 JSON 内容" : "manifest URL or JSON body");
    await expect(byClass(panel, "applet-install-circle-input-prompt").locator(".input-empty-prompt")).toHaveText( zh ? "可选 Circle 标识（ak:circle:…）；留空表示整个 Realm" : "optional Circle id (ak:circle:…) — blank = Realm-wide");
    await expect(byClass(panel, "applet-install-approve-actions-input-prompt").locator(".input-empty-prompt")).toHaveText( zh ? "获批操作，以逗号或换行分隔" : "approved actions, comma or newline separated");
    await expect(manifest).toHaveValue("");
    await expect(circle).toHaveValue("");
    await expect(actions).toHaveValue("");
    await manifest.fill(literalManifest);
    await circle.fill(literalCircle);
    await actions.fill(literalActions);
    const ghost = byClass(panel, "applet-install-allow-ghost").getByRole("checkbox");
    await expect(ghost).not.toBeChecked();
    await ghost.click();
    await expect(ghost).toBeChecked();
    await expect(byClass(panel, "applet-install-allow-ghost")).toHaveText(zh ? "允许由小程序管理的 Ghost Actor" : "allow Applet-managed Ghost Actors");
    await expect(byClass(panel, "applet-install-verify-button")).toHaveText(zh ? "预览计划" : "Preview plan");
    const confirm = byClass(panel, "applet-install-confirm-button");
    await expect(confirm).toHaveText(zh ? "安装小程序" : "Install applet");
    await expect(confirm).toBeDisabled();
    await expect(byClass(panel, "applet-install-status")).toHaveCount(0);
    await toggle.click();
    await expect(manifest).toHaveCount(0);
    await toggle.click();
    await expect(manifest).toHaveValue(literalManifest);
    await expect(circle).toHaveValue(literalCircle);
    await expect(actions).toHaveValue(literalActions);
    await expect(ghost).toBeChecked();
    await expect(confirm).toBeDisabled();
    await ghost.click();
    await expect(ghost).not.toBeChecked();
    await toggle.click();
  }
  expect(sideEffects).toEqual([]);
});

test("applet preview validation follows the selected language and preserves literal form input without requests", async ({ page }) => {
  const sideEffects: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      path === "/_arkret/self/events" ||
      path.endsWith("/realm-joins/prepare") ||
      (path.startsWith("/_arkret/") && path.split("/").includes("applets"))
    ) {
      sideEffects.push(`${request.method()} ${path}`);
    }
  });
  await refreshServer(page);
  const literalManifest = '{"description":"applets.feedback.invalid_manifest {error} 原文"}';
  const literalCircle = "applets.registry {value} 原文";
  const literalActions = "ak.message.create,\nak.applet.ghost.provision";
  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await byClass(page, "settings-nav-item-theme").click();
    await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    // Public navigation remounts the panel. Only native VDom coverage claims
    // locale changes for an already retained feedback value.
    await openApplets(page);
    const panel = byClass(page, "applets-panel");
    const toggle = byClass(panel, "applet-install-button");
    await toggle.click();
    const manifest = inputByClass(panel, "applet-install-manifest-input");
    const circle = inputByClass(panel, "applet-install-circle-input");
    const actions = inputByClass(panel, "applet-install-approve-actions-input");
    await manifest.fill(literalManifest);
    await circle.fill(literalCircle);
    await actions.fill(literalActions);
    const ghost = byClass(panel, "applet-install-allow-ghost").getByRole("checkbox");
    await ghost.click();
    await expect(ghost).toBeChecked();
    const confirm = byClass(panel, "applet-install-confirm-button");
    const status = byClass(panel, "applet-install-status");
    await expect(confirm).toBeDisabled();
    await expect(status).toHaveCount(0);
    await byClass(panel, "applet-install-verify-button").click();
    const expected = language === "zh"
      ? "输入必须是完整的 AppletInstallPreviewRequestBody，且注册事件清单携带 registration_epoch_evidence"
      : "input must be a closed AppletInstallPreviewRequestBody whose registration Event manifest carries registration_epoch_evidence";
    await expect(status).toHaveText(expected);
    await expect(manifest).toHaveValue(literalManifest);
    await expect(circle).toHaveValue(literalCircle);
    await expect(actions).toHaveValue(literalActions);
    await expect(ghost).toBeChecked();
    await expect(confirm).toBeDisabled();
    await expect(byClass(panel, "applet-row")).toHaveCount(0);
    await toggle.click();
    await expect(status).toHaveCount(0);
    await toggle.click();
    await expect(status).toHaveText(expected);
    await expect(manifest).toHaveValue(literalManifest);
    await expect(circle).toHaveValue(literalCircle);
    await expect(actions).toHaveValue(literalActions);
    await expect(ghost).toBeChecked();
    await expect(confirm).toBeDisabled();
  }
  expect(sideEffects).toEqual([]);
});
