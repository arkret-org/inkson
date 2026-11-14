import { readFileSync } from "node:fs";
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
    await expect(manifest).toHaveAttribute("placeholder", zh ? "完整注册材料 JSON（AppletInstallPreviewRequestBody）" : "Complete registration material JSON (AppletInstallPreviewRequestBody)");
    await expect(circle).toHaveAttribute("placeholder", zh ? "可选 Circle 标识（ak:circle:…）；留空表示整个 Realm" : "optional Circle id (ak:circle:…) — blank = Realm-wide");
    await expect(panel.locator(".applet-permission-choice")).toHaveCount(0);
    await expect(manifest).toHaveValue("");
    await expect(circle).toHaveValue("");
    await manifest.fill(literalManifest);
    await circle.fill(literalCircle);
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
    await manifest.fill(literalManifest);
    await circle.fill(literalCircle);
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
    await expect(ghost).toBeChecked();
    await expect(confirm).toBeDisabled();
    await expect(byClass(panel, "applet-row")).toHaveCount(0);
    await toggle.click();
    await expect(status).toHaveCount(0);
    await toggle.click();
    await expect(status).toHaveText(expected);
    await expect(manifest).toHaveValue(literalManifest);
    await expect(circle).toHaveValue(literalCircle);
    await expect(ghost).toBeChecked();
    await expect(confirm).toBeDisabled();
  }
  expect(sideEffects).toEqual([]);
});


test("applet permissions are explicit unverified package choices and never imply installation", async ({ page }, info) => {
  await refreshServer(page);await openApplets(page);
  const panel=byClass(page,"applets-panel");await byClass(panel,"applet-install-button").click();
  // Structural disclosure fixture only. No signature, admission or grant is accepted by this test.
  const material=JSON.parse(readFileSync(new URL("./fixtures/applet-permission-proposal.json", import.meta.url),"utf8"));
  const manifest=inputByClass(panel,"applet-install-manifest-input");
  let writes=0;page.on("request",request=>{if(request.method()==="POST"&&request.url().includes("/_arkret/"))writes++;});
  await manifest.fill(JSON.stringify(material));
  const proposal=panel.locator(".applet-permission-proposal");
  await expect(proposal).toContainText(material.applet_package.service_id);
  await expect(proposal).toContainText("package requests, not granted permissions");
  await expect(proposal).toContainText("2026-12-31");
  const choices=proposal.getByRole("checkbox");await expect(choices).toHaveCount(2);
  await expect(choices.first()).not.toBeChecked();await choices.first().check();
  await expect(byClass(panel,"applet-install-confirm-button")).toBeDisabled();
  await page.screenshot({path:info.outputPath("applet-permission-choices.png"),fullPage:true});
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await proposal.screenshot({path:info.outputPath("applet-permission-choices-mobile.png")});
  await manifest.fill(JSON.stringify({...material,applet_package:{...material.applet_package,package_id:"different-package"}}));
  await expect(proposal.getByRole("checkbox").first()).not.toBeChecked();
  await manifest.fill("{}");await expect(panel.locator(".applet-permission-choice")).toHaveCount(0);
  expect(writes).toBe(0);
});
