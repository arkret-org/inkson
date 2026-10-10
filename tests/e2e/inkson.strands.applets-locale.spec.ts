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
  await expect(page.getByTestId("applets-panel")).toBeVisible();
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
    await page.getByTestId("settings-nav-item-theme").click();
    await page.getByTestId(`language-${language}`).click();
    await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
    // Normal Settings navigation remounts Applets. Retained helper labels are
    // verified natively; no private state or fabricated registry rows are used.
    await openApplets(page);
    const zh = language === "zh";
    const panel = page.getByTestId("applets-panel");
    await expect(panel).toHaveAttribute("aria-label", zh ? "小程序注册表与桥接错误" : "Applet registry and bridge errors");
    await expect(panel.getByText(zh ? "小程序注册表" : "Applet registry", { exact: true })).toBeVisible();
    await expect(panel.getByText(zh ? "已注册 0 个" : "0 registered", { exact: true })).toBeVisible();
    await expect(panel.getByTestId("applet-registry-empty")).toHaveText(
      zh ? "尚未注册小程序。请使用下方已签名小程序包的安装流程；注册记录会在提交时生成。" : "No applets registered yet. Use the signed Applet Package install flow below; registration is derived during commit.",
    );
    await expect(panel.getByTestId("applet-registration-row")).toHaveCount(0);
    const errors = panel.getByTestId("applet-bridge-errors");
    await expect(errors.getByText(zh ? "桥接错误" : "Bridge errors", { exact: true })).toBeVisible();
    await expect(errors.getByText(zh ? "尚未观察到桥接错误。" : "No bridge errors observed.", { exact: true })).toBeVisible();
    await expect(panel.getByTestId("applet-empty")).toHaveText(zh ? "尚未安装小程序。" : "No applets installed.");
    await expect(panel.getByTestId("applet-row")).toHaveCount(0);
    await expect(panel.getByTestId("applet-accountability-modal")).toHaveCount(0);
    const toggle = panel.getByTestId("applet-install-button");
    await expect(toggle).toHaveText(zh ? "+ 安装小程序" : "+ Install applet");
    await toggle.click();
    await expect(toggle).toHaveText(zh ? "关闭安装表单" : "Close install");
    const manifest = panel.getByTestId("applet-install-manifest-input");
    const circle = panel.getByTestId("applet-install-circle-input");
    const actions = panel.getByTestId("applet-install-approve-actions-input");
    await expect(manifest).toHaveAttribute("placeholder", zh ? "清单网址或 JSON 内容" : "manifest URL or JSON body");
    await expect(circle).toHaveAttribute("placeholder", zh ? "可选 Circle 标识（ak:circle:…）；留空表示整个 Realm" : "optional Circle id (ak:circle:…) — blank = Realm-wide");
    await expect(actions).toHaveAttribute("placeholder", zh ? "获批操作，以逗号或换行分隔" : "approved actions, comma or newline separated");
    await expect(manifest).toHaveValue("");
    await expect(circle).toHaveValue("");
    await expect(actions).toHaveValue("");
    await manifest.fill(literalManifest);
    await circle.fill(literalCircle);
    await actions.fill(literalActions);
    const ghost = panel.getByTestId("applet-install-allow-ghost");
    await expect(ghost).toHaveAttribute("aria-checked", "false");
    await ghost.click();
    await expect(ghost).toHaveAttribute("aria-checked", "true");
    await expect(panel.getByTestId("applet-install-ghost-row").locator("span").last()).toHaveText(zh ? "允许由小程序管理的 Ghost Actor" : "allow Applet-managed Ghost Actors");
    await expect(panel.getByTestId("applet-install-verify-button")).toHaveText(zh ? "预览计划" : "Preview plan");
    const confirm = panel.getByTestId("applet-install-confirm-button");
    await expect(confirm).toHaveText(zh ? "安装小程序" : "Install applet");
    await expect(confirm).toBeDisabled();
    await expect(panel.getByTestId("applet-install-status")).toHaveCount(0);
    await toggle.click();
    await expect(manifest).toHaveCount(0);
    await toggle.click();
    await expect(manifest).toHaveValue(literalManifest);
    await expect(circle).toHaveValue(literalCircle);
    await expect(actions).toHaveValue(literalActions);
    await expect(ghost).toHaveAttribute("aria-checked", "true");
    await expect(confirm).toBeDisabled();
    await ghost.click();
    await expect(ghost).toHaveAttribute("aria-checked", "false");
    await toggle.click();
  }
  expect(sideEffects).toEqual([]);
});
