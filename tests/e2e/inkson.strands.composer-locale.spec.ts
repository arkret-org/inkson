import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
import { expect, test, type Locator, type Page } from "@playwright/test";
import {
  openDiscussion,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function expectEmptyPrompt(input: Locator, text: string) {
  await expect(input).toHaveAccessibleName(text);
  await expect(input.locator("xpath=..").locator(":scope > .input-empty-prompt")).toHaveText(text);
}

async function expectSendReady(composer: Locator, send: Locator) {
  await expect(send).toBeEnabled();
  await expect(send).toHaveAttribute("aria-busy", "false");
  await expect(composer.locator(".composer-send-diagnostic")).toHaveText("");
}

async function chooseScheduledDate(page: Page, schedule: Locator) {
  await schedule.getByRole("button", { name: "Choose date and time", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Date and time", exact: true });
  await expect(dialog).toBeVisible();
  const month = dialog.locator(".sapid-calendar-month");
  const monthNames = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
  const visibleMonth = (await month.innerText()).trim();
  const chinese = visibleMonth.match(/^(\d{4})年(\d{1,2})月$/);
  const english = visibleMonth.match(/^([A-Za-z]+) (\d{4})$/);
  expect(chinese !== null || english !== null).toBe(true);
  const year = chinese ? Number(chinese[1]) : Number(english![2]);
  const monthNumber = chinese ? Number(chinese[2]) : monthNames.indexOf(english![1]) + 1;
  expect(monthNumber).toBeGreaterThanOrEqual(1);
  let distance = (2030 - year) * 12 + 12 - monthNumber;
  expect(Math.abs(distance)).toBeLessThanOrEqual(120);
  while (Math.abs(distance) >= 12) {
    const backwards = distance < 0;
    await dialog.getByRole("button", { name: backwards ? "Previous year" : "Next year", exact: true }).click();
    distance += backwards ? 12 : -12;
  }
  while (distance !== 0) {
    const backwards = distance < 0;
    await dialog.getByRole("button", { name: backwards ? "Previous month" : "Next month", exact: true }).click();
    distance += backwards ? 1 : -1;
  }
  await expect(month).toHaveText(/^(December 2030|2030年12月)$/);
  await dialog.getByRole("button", { name: /^(Tuesday, December 31, 2030|2030年12月31日 星期二)$/ }).click();
  await dialog.locator("input.sapid-time-hour").fill("12");
  await dialog.locator("input.sapid-time-minute").fill("30");
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(dialog).toBeHidden();
}

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
    await byClass(page, "settings-nav-item-theme").click();
    await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
    await expect(page.locator("html")).toHaveAttribute("lang", language);
    // Settings and normal card navigation remount the discussion. Draft
    // retention below is checked within each mount, not across navigation.
    await openDiscussion(page);
    const zh = language === "zh";
    const composer = byClass(page, "chat-composer");
    await expect(composer).toBeVisible();
    const input = inputByClass(composer, "chat-input");
    await input.fill("");
    await expect(byClass(composer, "chat-input-hint")).toHaveText(zh
      ? "在此讨论中发送消息。用 @alice:example.com 提及成员，或用 #task-123 链接卡片。"
      : "Message this discussion. Use @alice:example.com to mention a member or #task-123 to link a card.");
    const scope = byClass(composer, "composer-send-scope");
    await expect(scope).toHaveText(zh
      ? /^原始 Strand：ak:strand:[A-Za-z0-9_-]+。仅限获授权读取此范围的成员。$/
      : /^Original Strand: ak:strand:[A-Za-z0-9_-]+\. Members authorized to read this scope\.$/);
    const originalScope = await scope.textContent();
    const send = byClass(composer, "send-chat-button");
    await expect(send).toHaveText(zh ? "发送" : "Send");
    // This test title selects the unchanged harness's ordinary plaintext
    // Realm. The public primary action is ready; no encryption gate is pending.
    await expectSendReady(composer, send);
    await expect(byClass(page, "chat-message")).toHaveCount(0);
    await input.fill(literalDraft);
    await expect(input).toHaveValue(literalDraft);

    const mention = byClass(composer, "mention-trigger-button");
    await expect(mention).toHaveAccessibleName(zh ? "提及成员" : "Mention member");
    await mention.click();
    const picker = byClass(composer, "mention-picker");
    await expect(picker).toBeVisible();
    const query = picker.locator("input.mention-picker-query");
    await query.fill("");
    await expectEmptyPrompt(query, zh ? "搜索成员" : "Search members");
    const literalQuery = "chat.composer.no_matches {member} 原文";
    await query.fill(literalQuery);
    await expect(query).toHaveValue(literalQuery);
    await expect(picker.getByText(zh ? "没有匹配的成员" : "No matches", { exact: true })).toBeVisible();
    const close = byClass(picker, "mention-picker-close-button");
    await expect(close).toHaveText(zh ? "关闭" : "Close");
    await close.click();
    await expect(picker).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);

    const attachment = byClass(composer, "attachment-menu-button");
    await expect(attachment).toHaveAccessibleName(zh ? "添加附件" : "Add attachment");
    await attachment.click();
    await expect(composer.locator(".attachment-menu")).toBeVisible();
    const menuPoll = byClass(composer, "attachment-menu-poll");
    await expect(menuPoll).toHaveText(zh ? "创建投票" : "Create poll");
    await expect(menuPoll).toBeEnabled();
    await attachment.click();
    // The official file owner remains mounted for any accepted in-flight read.
    await expect(composer.locator(".attachment-menu")).toBeHidden();
    await expect(input).toHaveValue(literalDraft);
    await expect(scope).toHaveText(originalScope!);
    await expectSendReady(composer, send);

    const pollToggle = byClass(composer, "open-poll-composer-button");
    await expect(pollToggle).toHaveText(zh ? "投票" : "Poll");
    await expect(pollToggle).toHaveAccessibleName(zh ? "创建投票" : "Create poll");
    await expect(pollToggle).toBeEnabled();
    await pollToggle.click();
    const poll = byClass(composer, "poll-composer");
    await expect(poll).toBeVisible();
    const question = inputByClass(poll, "poll-question-input");
    const options = inputByClass(poll, "poll-option-input");
    await expectEmptyPrompt(question, zh ? "问题" : "Question");
    await expect(options).toHaveCount(2);
    for (let index = 0; index < 2; index += 1) {
      await expectEmptyPrompt(options.nth(index), zh ? `选项 ${index + 1}` : `Option ${index + 1}`);
    }
    const sendPoll = byClass(poll, "send-poll-button");
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
    const addOption = byClass(poll, "poll-add-option-button");
    await expect(addOption).toHaveText(zh ? "添加选项" : "Add option");
    await addOption.click();
    await expect(options).toHaveCount(3);
    await expectEmptyPrompt(options.nth(2), zh ? "选项 3" : "Option 3");
    await expect(options.nth(2)).toHaveValue("");
    await expect(question).toHaveValue(literalQuestion);
    await expect(options.nth(0)).toHaveValue(literalOptions[0]);
    await expect(options.nth(1)).toHaveValue(literalOptions[1]);
    await expect(sendPoll).toBeEnabled();
    await poll.getByRole("button", { name: zh ? "取消" : "Cancel", exact: true }).click();
    await expect(poll).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);

    const scheduleToggle = byClass(composer, "open-scheduled-send-panel-button");
    await expect(scheduleToggle).toHaveAccessibleName(zh ? "定时发送消息" : "Schedule message");
    await scheduleToggle.click();
    const schedule = byClass(composer, "scheduled-send-panel");
    await expect(schedule).toBeVisible();
    const scheduledAt = schedule.getByRole("textbox", { name: zh ? "发送时间" : "Send at", exact: true });
    const scheduledId = await scheduledAt.getAttribute("id");
    expect(scheduledId).toBeTruthy();
    await expect(schedule.locator(`label[for="${scheduledId}"]`)).toHaveText(zh ? "发送时间" : "Send at");
    await expect(byClass(schedule, "scheduled-send-empty")).toHaveText(zh ? "此讨论暂无定时消息。" : "No scheduled messages for this discussion.");
    const scheduleCreate = byClass(schedule, "scheduled-send-create-button");
    await expect(scheduleCreate).toHaveText(zh ? "定时发送" : "Schedule message");
    await expect(scheduleCreate).toBeDisabled();
    await expect(scheduledAt).toHaveJSProperty("readOnly", true);
    await chooseScheduledDate(page, schedule);
    await expect(scheduledAt).toHaveValue(/^2030-12-31T12:30(?::00)?$/);
    await expect(scheduleCreate).toBeEnabled();
    await expect(input).toHaveValue(literalDraft);
    // Do not create a scheduled plan or send a poll/message. Only the public
    // local forms change; no account-data write or accepted Event is authored.
    await scheduleToggle.click();
    await expect(schedule).toHaveCount(0);
    await expect(input).toHaveValue(literalDraft);
    await expect(scope).toHaveText(originalScope!);
    await expectSendReady(composer, send);
    await expect(byClass(page, "chat-message")).toHaveCount(0);
    await byClass(page, "card-detail-close-button").click();
    await expect(byClass(page, "card-detail-modal")).toHaveCount(0);
  }
  expect(writes).toEqual([]);
});
