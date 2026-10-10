import { expect, test } from "@playwright/test";
import { CURRENT_PRINCIPAL_CORE_ID, DEMO_REALM } from "./mockArkretApi";
import {
  gotoAndDismissRecovery,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("Circle presentation and local creation boundaries follow the active language without authoring events", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/_arkret/") && request.method() !== "GET" && (
      path === "/_arkret/self/events" || path.includes("/circles") || path.endsWith("/realm-joins/prepare")
    )) {
      writes.push(`${request.method()} ${path}`);
    }
  });
  await refreshServer(page);
  const literalTitle = "circles.page.title {member} 原文";
  const literalSummary = "circles.page.summary {value}\n原始简介";
  const literalShortName = "Ops_1-x";

  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await page.getByTestId("settings-nav-item-theme").click();
    await page.getByTestId(`language-${language}`).click();
    await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
    // Normal public navigation remounts the panel. Native coverage separately
    // verifies retained presentation helpers across a locale change.
    await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/circles`);
    const zh = language === "zh";
    const panel = page.getByTestId("circles-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByRole("navigation")).toHaveAttribute("aria-label", zh ? "普通 Circles" : "Ordinary Circles");
    await expect(panel.getByRole("button", { name: zh ? "刷新" : "Refresh", exact: true })).toBeVisible();
    await expect(panel.getByTestId("circle-list-item")).toHaveCount(1);
    const item = panel.getByTestId("circle-list-item");
    await expect(item).toContainText("Demo Circle");
    await expect(item).toContainText(zh ? "活跃" : "Active");
    // The ordinary Realm fixture is plaintext, while this existing Circle
    // independently has an accepted MLS binding. Neither boundary is changed.
    await expect(item).toContainText(zh ? "独立 MLS 群组 · 已启用端到端加密" : "Independent MLS group · E2EE active");
    await expect(panel.getByTestId("circle-detail")).toContainText(zh ? "选择一个 Circle" : "Select a Circle");
    const open = panel.getByTestId("circle-create-open");
    await expect(open).toHaveText(zh ? "新建 Circle" : "New Circle");
    await open.click();
    const modal = panel.getByTestId("circle-create-modal");
    await expect(modal.getByRole("heading")).toHaveText(zh ? "创建 Circle" : "Create Circle");
    const title = modal.getByTestId("circle-create-title");
    const shortName = modal.getByTestId("circle-create-short-name");
    const summary = modal.locator("textarea");
    const submit = modal.getByTestId("circle-create-submit");
    await expect(submit).toHaveText(zh ? "创建 Circle" : "Create Circle");
    await expect(submit).toBeDisabled();
    await expect(shortName).toHaveAttribute("aria-label", zh ? "Circle 简称" : "Circle short name");
    const labels = modal.locator(".workflow-form > label");
    await expect(labels).toContainText([
      zh ? "标题" : "Title",
      zh ? "简称（ASCII 字符，在此 Realm 内唯一）" : "Short name (ASCII, unique in this Realm)",
      zh ? "简介" : "Summary",
      zh ? "目录可见性" : "Directory visibility",
      zh ? "加入规则" : "Join rule",
      zh ? "历史记录" : "History",
      zh ? "端到端加密" : "End-to-end encryption",
    ]);
    const visibility = modal.getByLabel(zh ? "Circle 目录可见性" : "Circle directory visibility", { exact: true });
    const join = modal.getByLabel(zh ? "Circle 加入规则" : "Circle join rule", { exact: true });
    const history = modal.getByLabel(zh ? "Circle 历史记录" : "Circle history", { exact: true });
    await expect(visibility).toHaveValue("members");
    await expect(join).toHaveValue("public");
    await expect(history).toHaveValue("since_join");
    await expect(visibility.locator("option")).toHaveText(zh ? ["仅 Circle 成员", "允许 Realm 成员预览"] : ["Circle members only", "Preview for Realm members"]);
    await expect(join.locator("option")).toHaveText(zh ? ["任何有效的 Realm 成员", "申请批准", "由 Circle 管理者添加"] : ["Any active Realm member", "Request approval", "Added by a Circle manager"]);
    await expect(history.locator("option")).toHaveText(zh ? ["加入之后", "当前成员可查看全部历史"] : ["Since joining", "All history for current members"]);
    await title.fill(literalTitle);
    await summary.fill(literalSummary);
    await expect(submit).toBeEnabled();
    await shortName.fill("circles.page.short_name 原文");
    await expect(submit).toBeDisabled();
    await shortName.fill(literalShortName);
    await visibility.selectOption("realm_members");
    await join.selectOption("knock");
    await history.selectOption("all_history_for_current_members");
    const encrypted = modal.getByTestId("circle-create-encrypted");
    await expect(encrypted).not.toBeChecked();
    await encrypted.check();
    await expect(encrypted).toBeChecked();
    const preview = modal.locator(".circle-boundary-preview");
    await expect(preview.locator("strong")).toHaveText(zh ? "边界预览" : "Boundary preview");
    await expect(preview.locator("p").nth(0)).toHaveText(`${zh ? "初始成员：" : "Initial member: "}${CURRENT_PRINCIPAL_CORE_ID}`);
    await expect(preview.locator("p").nth(1)).toHaveText(zh ? "目录：RealmMembers" : "Directory: RealmMembers");
    await expect(preview.locator("p").nth(2)).toHaveText(zh ? "加入规则：Knock" : "Join rule: Knock");
    await expect(preview.locator("p").nth(3)).toHaveText(zh ? "历史记录：AllHistoryForCurrentMembers" : "History: AllHistoryForCurrentMembers");
    await expect(preview.locator("p").nth(4)).toHaveText(zh
      ? "初始状态只限制投递范围。此 Circle 自己的 MLS 初始事件被接受后，才会启用端到端加密。"
      : "Starts as restricted delivery only. E2EE becomes active only after this Circle's own MLS genesis is accepted.");
    await expect(submit).toBeEnabled();
    await expect(title).toHaveValue(literalTitle);
    await expect(summary).toHaveValue(literalSummary);
    await expect(shortName).toHaveValue(literalShortName);
    await modal.getByRole("button", { name: zh ? "取消" : "Cancel", exact: true }).click();
    await expect(modal).toHaveCount(0);
    await open.click();
    await expect(title).toHaveValue(literalTitle);
    await expect(summary).toHaveValue(literalSummary);
    await expect(shortName).toHaveValue(literalShortName);
    await expect(visibility).toHaveValue("realm_members");
    await expect(join).toHaveValue("knock");
    await expect(history).toHaveValue("all_history_for_current_members");
    await expect(encrypted).toBeChecked();
    await join.selectOption("invite");
    await expect(join).toHaveValue("invite");
    await expect(preview.locator("p").nth(2)).toHaveText(zh ? "加入规则：Invite" : "Join rule: Invite");
    await expect(submit).toBeEnabled();
    // Do not submit. These are real public local controls, with unchanged
    // typed values and validation; no Circle or membership Event is authored.
    await modal.getByRole("button", { name: zh ? "取消" : "Cancel", exact: true }).click();
  }
  expect(writes).toEqual([]);
});
