import { expect, test } from "@playwright/test";
import {
  gotoAndDismissRecovery,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("Direct structure local controls preserve action values and existing MLS and main-Chat guards across public language navigation", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (request.method() !== "GET" && (
      path === "/_arkret/self/events" ||
      path.startsWith("/_arkret/self/contacts/") ||
      path.endsWith("/realm-joins/prepare") ||
      path.endsWith("/direct-conversations/prepare") ||
      /\/_arkret\/self\/agents\/[^/]+\/participation$/.test(path)
    )) {
      writes.push(`${request.method()} ${path}`);
    }
  });
  await refreshServer(page);
  const actions = [
    "new_chat", "new_topic", "rename_chat", "archive_chat", "restore_chat", "place",
    "unplace", "reorder", "rename_topic_target", "reorder_topic", "archive_topic_target",
    "restore_topic_target", "delete_topic_target",
  ];
  const saveDisabled: Record<string, boolean> = {
    new_chat: true,
    new_topic: true,
    rename_chat: true,
    archive_chat: true,
    restore_chat: true,
    place: false,
    unplace: false,
    reorder: false,
    rename_topic_target: true,
    reorder_topic: false,
    archive_topic_target: false,
    restore_topic_target: false,
    delete_topic_target: false,
  };
  const english = [
    "New Chat", "New Topic", "Rename Chat", "Archive Chat", "Restore Chat", "Move Chat to Topic",
    "Remove Chat from Topic", "Move Chat to end of Topic", "Rename Topic", "Move Topic to end",
    "Archive Topic", "Restore Topic", "Delete empty Topic",
  ];
  const chinese = [
    "新建聊天", "新建话题", "重命名聊天", "归档聊天", "恢复聊天", "将聊天移入话题",
    "将聊天移出话题", "将聊天移到话题末尾", "重命名话题", "将话题移到末尾",
    "归档话题", "恢复话题", "删除空话题",
  ];
  const literalTitle = "chat.direct_structure.new_chat {count} 原文";

  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await page.getByTestId("settings-nav-item-theme").click();
    await page.getByTestId(`language-${language}`).click();
    await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
    // Navigate through the public contact sidebar. The fixture's protected Found
    // result installs a stable binding context, but supplies no typed Current
    // rows or restorable MLS state for metadata encryption.
    await gotoAndDismissRecovery(page, "/contacts/manage");
    const shell = page.getByTestId("client-shell");
    await shell.getByTestId("realm-sidebar-tab-direct").click();
    await shell.getByTestId("direct-conversation-row").filter({ hasText: "ak:did_core:web:bob.example" }).click();
    await expect(page).toHaveURL(/\/direct\/ak:realm:AUEAoXMJeJWBETvkqm7gk4imduk7g-l8bim19OPFQDaO\/ak:strand:Ae9PN2rTd0Dojs9yS8iLnfheJtjSEZ3mgDDyONpztHUd$/);
    const panel = page.getByTestId("direct-structure");
    await expect(panel).toBeVisible();
    const zh = language === "zh";
    const manage = panel.getByRole("button", { name: zh ? "管理聊天和话题" : "Manage chats and topics", exact: true });
    await manage.click();
    const action = panel.getByLabel(zh ? "操作" : "Action", { exact: true });
    await expect(action).toHaveValue("new_chat");
    await expect(action.locator("option")).toHaveText(zh ? chinese : english);
    expect(await action.locator("option").evaluateAll((options) => options.map((option) => (option as HTMLOptionElement).value))).toEqual(actions);
    const title = panel.getByLabel(zh ? "标题" : "Title", { exact: true });
    const save = panel.getByRole("button", { name: zh ? "保存" : "Save", exact: true });
    await expect(title).toHaveValue("");
    await expect(title).toHaveAttribute("placeholder", zh ? "标题" : "Title");
    await expect(save).toBeDisabled();
    await title.fill(literalTitle);
    await expect(save).toBeDisabled();
    for (const value of actions) {
      await action.selectOption(value);
      await expect(action).toHaveValue(value);
      const metadata = ["new_chat", "new_topic", "rename_chat", "rename_topic_target"].includes(value);
      if (metadata) {
        await expect(title).toHaveValue(literalTitle);
        await expect(title).toHaveAttribute("placeholder", zh ? "标题" : "Title");
      } else {
        await expect(title).toHaveCount(0);
      }
      const requiresTopic = ["place", "reorder", "rename_topic_target", "reorder_topic", "archive_topic_target", "restore_topic_target", "delete_topic_target"].includes(value);
      const topic = panel.getByLabel(zh ? "话题" : "Topic", { exact: true });
      if (requiresTopic) {
        await expect(topic).toHaveValue("");
        await expect(topic.locator('option[value=""]')).toHaveText(zh ? "选择话题" : "Select Topic");
      } else {
        await expect(topic).toHaveCount(0);
      }
      // Metadata actions require MLS; archiving/restoring the main Chat is blocked.
      // Other local controls remain enabled. No Save is submitted, and enabled
      // controls do not prove that a command could pass its authoring/admission gates.
      if (saveDisabled[value]) {
        await expect(save).toBeDisabled();
      } else {
        await expect(save).toBeEnabled();
      }
    }
    await action.selectOption("rename_chat");
    await manage.click();
    await expect(action).toHaveCount(0);
    await manage.click();
    await expect(action).toHaveValue("rename_chat");
    await expect(title).toHaveValue(literalTitle);
    await expect(save).toBeDisabled();
    await expect(panel.getByTestId("direct-structure-status")).toHaveText("");
    expect(writes).toEqual([]);
  }
  expect(writes).toEqual([]);
});
