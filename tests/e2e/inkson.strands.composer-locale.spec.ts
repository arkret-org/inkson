import { expect, test } from "@playwright/test";
import {
  openDiscussion,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

test("chat composer copy follows the active language while original drafts and send gates stay intact", async ({ page }) => {
  const writes: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (request.method() === "POST" && (path === "/_arkret/self/events" || path.endsWith("/realm-joins/prepare"))) {
      writes.push(path);
    }
  });
  await refreshServer(page);
  const literalDraft = "chat.composer.sending {strand} {member} 原文\n#task-123";

  for (const language of ["en", "zh", "en"] as const) {
    await openSettings(page);
    await page.getByTestId("settings-nav-item-theme").click();
    await page.getByTestId(`language-${language}`).click();
    await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
    // Settings and normal card navigation remount the discussion. Draft
    // retention below is checked within each mount, not across navigation.
    await openDiscussion(page);
    const zh = language === "zh";
    const composer = page.getByTestId("chat-composer");
    await expect(composer).toBeVisible();
    const input = composer.getByTestId("chat-input");
    await expect(input).toHaveAttribute("placeholder", zh
      ? "在此讨论中发送消息。用 @alice:example.com 提及成员，或用 #task-123 链接卡片。"
      : "Message this discussion. Use @alice:example.com to mention a member or #task-123 to link a card.");
    const scope = composer.getByTestId("composer-send-scope");
    await expect(scope).toHaveAttribute("data-send-route", "Shared");
    await expect(scope).toHaveText(zh
      ? /^原始 Strand：ak:strand:[A-Za-z0-9_-]+。仅限获授权读取此范围的成员。$/
      : /^Original Strand: ak:strand:[A-Za-z0-9_-]+\. Members authorized to read this scope\.$/);
    const originalScope = await scope.textContent();
    const send = composer.getByTestId("send-chat-button");
    await expect(send).toHaveText(zh ? "发送" : "Send");
    // This test title selects the unchanged harness's ordinary plaintext
    // Realm. The public primary action is ready; no encryption gate is pending.
    await expect(send).toBeEnabled();
    await expect(send).toHaveAttribute("title", "");
    await expect(send).toHaveAttribute("data-mls-binding-pending", "false");
    await expect(send).toHaveAttribute("data-creator-bootstrap-pending", "false");
    await expect(page.getByTestId("chat-message")).toHaveCount(0);
    await input.fill(literalDraft);
    await expect(input).toHaveValue(literalDraft);

    const mention = composer.getByTestId("mention-trigger-button");
    await expect(mention).toHaveAttribute("title", zh ? "提及成员" : "Mention member");
    await expect(mention).toHaveAttribute("aria-label", zh ? "提及成员" : "Mention member");
    await mention.click();
    const picker = composer.getByTestId("mention-picker");
    await expect(picker).toBeVisible();
    const query = picker.locator("input.mention-picker-query");
    await expect(query).toHaveAttribute("placeholder", zh ? "搜索成员" : "Search members");
    const literalQuery = "chat.composer.no_matches {member} 原文";
    await query.fill(literalQuery);
    await expect(query).toHaveValue(literalQuery);
    await expect(picker.getByText(zh ? "没有匹配的成员" : "No matches", { exact: true })).toBeVisible();
    const close = picker.getByTestId("mention-picker-close-button");
    await expect(close).toHaveText(zh ? "关闭" : "Close");
    await close.click();
    await expect(picker).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);

    const attachment = composer.getByTestId("attachment-menu-button");
    await expect(attachment).toHaveAttribute("title", zh ? "添加附件" : "Add attachment");
    await expect(attachment).toHaveAttribute("aria-label", zh ? "添加附件" : "Add attachment");
    await attachment.click();
    await expect(composer.locator(".attachment-menu")).toBeVisible();
    const menuPoll = composer.getByTestId("attachment-menu-poll");
    await expect(menuPoll).toHaveText(zh ? "创建投票" : "Create poll");
    await expect(menuPoll).toBeEnabled();
    await attachment.click();
    await expect(composer.locator(".attachment-menu")).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);
    await expect(scope).toHaveText(originalScope!);
    await expect(send).toBeEnabled();
    await expect(send).toHaveAttribute("title", "");

    const pollToggle = composer.getByTestId("open-poll-composer-button");
    await expect(pollToggle).toHaveText(zh ? "投票" : "Poll");
    await expect(pollToggle).toHaveAttribute("title", zh ? "创建投票" : "Create poll");
    await expect(pollToggle).toHaveAttribute("aria-label", zh ? "创建投票" : "Create poll");
    await expect(pollToggle).toBeEnabled();
    await pollToggle.click();
    const poll = composer.getByTestId("poll-composer");
    await expect(poll).toBeVisible();
    const question = poll.getByTestId("poll-question-input");
    const options = poll.getByTestId("poll-option-input");
    await expect(question).toHaveAttribute("placeholder", zh ? "问题" : "Question");
    await expect(options).toHaveCount(2);
    for (let index = 0; index < 2; index += 1) {
      await expect(options.nth(index)).toHaveAttribute("placeholder", zh ? `选项 ${index + 1}` : `Option ${index + 1}`);
    }
    const sendPoll = poll.getByTestId("send-poll-button");
    await expect(sendPoll).toHaveText(zh ? "发送投票" : "Send poll");
    await expect(sendPoll).toBeDisabled();
    const literalQuestion = "chat.composer.poll_question {number} 原文";
    const literalOptions = ["chat.composer.poll_option {number} 选项原文", "second {member} option"];
    await question.fill(literalQuestion);
    await options.nth(0).fill(literalOptions[0]);
    await expect(sendPoll).toBeDisabled();
    await options.nth(1).fill(literalOptions[1]);
    await expect(sendPoll).toBeEnabled();
    await expect(question).toHaveValue(literalQuestion);
    for (let index = 0; index < 2; index += 1) {
      await expect(options.nth(index)).toHaveValue(literalOptions[index]);
    }
    const addOption = poll.getByTestId("poll-add-option-button");
    await expect(addOption).toHaveText(zh ? "添加选项" : "Add option");
    await addOption.click();
    await expect(options).toHaveCount(3);
    await expect(options.nth(2)).toHaveAttribute("placeholder", zh ? "选项 3" : "Option 3");
    await expect(options.nth(2)).toHaveValue("");
    await expect(question).toHaveValue(literalQuestion);
    await expect(options.nth(0)).toHaveValue(literalOptions[0]);
    await expect(options.nth(1)).toHaveValue(literalOptions[1]);
    await expect(sendPoll).toBeEnabled();
    await poll.getByRole("button", { name: zh ? "取消" : "Cancel", exact: true }).click();
    await expect(poll).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);

    const scheduleToggle = composer.getByTestId("open-scheduled-send-panel-button");
    await expect(scheduleToggle).toHaveAttribute("title", zh ? "定时发送消息" : "Schedule message");
    await expect(scheduleToggle).toHaveAttribute("aria-label", zh ? "定时发送消息" : "Schedule message");
    await scheduleToggle.click();
    const schedule = composer.getByTestId("scheduled-send-panel");
    await expect(schedule).toBeVisible();
    await expect(schedule.locator('label[for="scheduled-send-at-input"]')).toHaveText(zh ? "发送时间" : "Send at");
    await expect(schedule.getByTestId("scheduled-send-empty")).toHaveText(zh ? "此讨论暂无定时消息。" : "No scheduled messages for this discussion.");
    const scheduleCreate = schedule.getByTestId("scheduled-send-create-button");
    await expect(scheduleCreate).toHaveText(zh ? "定时发送" : "Schedule message");
    await expect(scheduleCreate).toBeDisabled();
    await schedule.getByTestId("scheduled-send-at-input").fill("2030-12-31T12:30");
    await expect(schedule.getByTestId("scheduled-send-at-input")).toHaveValue("2030-12-31T12:30");
    await expect(scheduleCreate).toBeEnabled();
    await expect(input).toHaveValue(literalDraft);
    // Do not create a scheduled plan or send a poll/message. Only the public
    // local forms change; no account-data write or accepted Event is authored.
    await scheduleToggle.click();
    await expect(schedule).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);
    await expect(scope).toHaveText(originalScope!);
    await expect(send).toBeEnabled();
    await expect(send).toHaveAttribute("title", "");
    await expect(send).toHaveAttribute("data-mls-binding-pending", "false");
    await expect(send).toHaveAttribute("data-creator-bootstrap-pending", "false");
    await expect(page.getByTestId("chat-message")).toHaveCount(0);
    await page.getByTestId("card-detail-close-button").click();
    await expect(page.getByTestId("card-detail-modal")).toHaveCount(0);
  }
  expect(writes).toEqual([]);
});
