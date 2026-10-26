import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
import { expect, test } from "@playwright/test";
import { DEMO_REALM } from "./mockArkretApi";
import { gotoAndDismissRecovery, openSettings, refreshServer, registerStrandsBeforeEach } from "./strandsHarness";

registerStrandsBeforeEach();

test("Member sections and local invite drafts follow the active language without membership authoring", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/_arkret/") && request.method() !== "GET" && (
      path === "/_arkret/self/events" || path.includes("/invites") || path.includes("/members") || path.includes("/agents/")
    )) writes.push(`${request.method()} ${path}`);
  });
  await refreshServer(page);
  const originalTarget = "https://original.example/_arkret/open/invite-locators/resolve#token=realm_admin.roster.invite_member%20{target}%20原文";
  let originalIds: string[] | undefined;

  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await byClass(page, "settings-nav-item-theme").click();
    await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    // Public navigation remounts the panel; native coverage retains the typed
    // presentation helpers and exercises the real roster search projection.
    await gotoAndDismissRecovery(page, `/realms/${DEMO_REALM}/members`);
    const zh = language === "zh";
    const panel = byClass(page, "realm-members-panel");
    await expect(panel).toBeVisible();
    await expect(panel.getByRole("navigation")).toHaveAttribute("aria-label", zh ? "成员分区" : "Member sections");
    await expect(panel.locator(".member-head-actions > .member-count-badge")).toHaveText("2");
    // The existing signed fixture has two members, below the production search
    // threshold. Do not invent a larger roster or force private component state.
    await expect(byClass(panel, "member-search-input")).toHaveCount(0);
    await expect(byClass(panel, "open-invite-modal-button")).toHaveAttribute("aria-label", zh ? "邀请成员" : "Invite member");
    await expect(byClass(panel, "refresh-members-button")).toHaveAccessibleName(zh ? "刷新" : "Refresh");
    const ids = await byClass(panel, "member-row").evaluateAll((rows) => rows.map((row) => {
      const references = row.getAttribute("aria-describedby")?.split(/\s+/) ?? [];
      return references.map(id => document.getElementById(id)?.textContent ?? "").join(" ");
    }).sort());
    // The count includes owners/admins; this section shows ordinary members.
    expect(ids.length).toBeGreaterThan(0);
    for (const identity of ids) expect(identity).toMatch(/^Principal: ak:did_core:.+ · Station: ak:did_core:.+$/);
    expect(new Set(ids).size).toBe(ids.length);
    if (originalIds === undefined) originalIds = ids;
    expect(ids).toEqual(originalIds);

    const sections = [
      ["members", "Members", "成员", "Active Realm members without owner or admin authority.", "没有所有者或管理员权限的活跃 Realm 成员。"],
      ["owners", "Owners", "所有者", "Realm owners with top-level governance authority.", "具有最高治理权限的 Realm 所有者。"],
      ["admins", "Admins", "管理员", "Realm admins with management authority.", "具有管理权限的 Realm 管理员。"],
      ["my-agents", "My agents", "我的 Agent", "Manage your agents and their behavior in this Realm.", "管理你的 Agent 及其在此 Realm 中的行为。"],
      ["pending-invites", "Pending invites", "待处理邀请", "Invitations sent for this Realm that have not been accepted yet.", "已为此 Realm 发出且尚未被接受的邀请。"],
    ] as const;
    for (const [id, en, chinese, enDescription, zhDescription] of sections) {
      const button = panel.getByRole("navigation").getByRole("button", { name: zh ? chinese : en, exact: true });
      await expect(button).toContainText(zh ? chinese : en);
      await button.click();
      await expect(button).toHaveClass(/active/);
      const heading = panel.locator(".member-section-head");
      await expect(heading.locator(".entity-title")).toHaveText(zh ? chinese : en);
      await expect(heading.locator(".muted")).toHaveText(zh ? zhDescription : enDescription);
      if (id === "pending-invites") {
        await expect(byClass(panel, "member-pending-invite-empty")).toHaveText(zh ? "没有符合搜索条件的待处理邀请。" : "No pending invites match your search.");
      }
    }
    await panel.getByRole("navigation").getByRole("button", { name: zh ? "成员" : "Members", exact: true }).click();
    await byClass(panel, "open-invite-modal-button").click();
    const dialog = page.getByRole("dialog", { name: zh ? "邀请成员" : "Invite member", exact: true });
    await expect(dialog).toBeVisible();
    await expect(byClass(dialog, "invite-modal-close")).toHaveAttribute("aria-label", zh ? "关闭" : "Close");
    const target = inputByClass(dialog, "invite-target-input");
    await expect(byClass(dialog, "invite-target-input").locator(".input-empty-prompt")).toHaveText("alice:example.com");
    await expect(byClass(dialog, "send-invite-button")).toHaveText(zh ? "发送邀请" : "Send Invite");
    const contact = byClass(dialog, "invite-contact-list").getByRole("checkbox").first();
    await expect(contact).toBeEnabled();
    await contact.check();
    await expect(contact).toBeChecked();
    await target.fill(originalTarget);
    await expect(target).toHaveValue(originalTarget);
    await byClass(dialog, "invite-modal-cancel").click();
    await expect(dialog).toHaveCount(0);
    await byClass(panel, "open-invite-modal-button").click();
    await expect(target).toHaveValue(originalTarget);
    await expect(contact).toBeChecked();
    await byClass(dialog, "invite-modal-close").click();
    await expect(dialog).toHaveCount(0);
  }
  expect(writes).toEqual([]);
});
