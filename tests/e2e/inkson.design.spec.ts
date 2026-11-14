import { expect, test } from "@playwright/test";
import { writeFileSync } from "node:fs";
import { registerStrandsBeforeEach, openKanban, dismissBlockingRecoveryModal, dismissHistoryRecoveryModal } from "./strandsHarness";

registerStrandsBeforeEach();
async function toggleTheme(page: import("@playwright/test").Page) {
  const more = page.locator(".topbar-more .sapid-popover-trigger");
  if (await more.isVisible()) await more.click();
  await page.locator(".theme-toggle-button:visible").click();
  await page.keyboard.press("Escape");
}

test("theme text and action colors retain contrast on their surfaces", async ({ page }, testInfo) => {
  await openKanban(page);
  const measurements: unknown[] = [];
  for (let index = 0; index < 2; index++) {
    const palette = await page.locator(".board-toolbar").evaluate(element => {
      const style = getComputedStyle(element);
      const read = (name: string) => style.getPropertyValue(name).trim();
      return Object.fromEntries(["--text-3", "--surface-solid", "--surface-2", "--surface-3", "--accent", "--accent-2", "--text-on-accent", "--nav-muted", "--nav-bg-2", "--success", "--warning", "--danger", "--info"].map(name => [name, read(name)]));
    });
    const luminance = (hex: string) => {
      expect(hex).toMatch(/^#[\da-f]{6}$/i);
      return [1, 3, 5].map(offset => parseInt(hex.slice(offset, offset + 2), 16) / 255)
        .map(channel => channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4)
        .reduce((sum, channel, channelIndex) => sum + channel * [0.2126, 0.7152, 0.0722][channelIndex], 0);
    };
    const check = (foreground: string, background: string) => {
      const [low, high] = [luminance(palette[foreground]), luminance(palette[background])].sort((a, b) => a - b);
      const ratio = (high + 0.05) / (low + 0.05);
      measurements.push({ palette: index, foreground, background, ratio });
      expect(ratio, `${foreground} against ${background}`).toBeGreaterThanOrEqual(4.5);
    };
    for (const surface of ["--surface-solid", "--surface-2", "--surface-3"]) {
      check("--text-3", surface);
      for (const foreground of ["--accent", "--success", "--warning", "--danger", "--info"]) check(foreground, surface);
    }
    check("--text-on-accent", "--accent");
    check("--text-on-accent", "--accent-2");
    check("--nav-muted", "--nav-bg-2");
    await toggleTheme(page);
  }
  await testInfo.attach("computed-palette-contrast", { body: JSON.stringify(measurements, null, 2), contentType: "application/json" });
});

for (const width of [1280, 390]) {
  test(`work surfaces prioritize content and retain drafts at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 720 });
    await openKanban(page);
    const options = page.locator(".board-toolbar-options > .sapid-collapsible-trigger");
    const addList = page.locator(".board-toolbar-add-list > .sapid-collapsible-trigger");
    const title = page.locator(".new-column-input");
    await expect(options).toHaveAttribute("aria-expanded", "false");
    await expect(title).toBeHidden();
    await addList.click();
    await title.fill("Retained list draft");
    await addList.click();
    await expect(title).toBeHidden();
    await addList.click();
    await expect(title).toHaveValue("Retained list draft");
    await addList.click();
    await page.screenshot({ path: testInfo.outputPath(`board-dark-${width}.png`) });
    await toggleTheme(page);
    await page.screenshot({ path: testInfo.outputPath(`board-alternate-${width}.png`) });
    const realm = decodeURIComponent(new URL(page.url()).pathname.split("/")[2]);
    await page.goto(`/chat/${encodeURIComponent(realm)}`);
    await dismissHistoryRecoveryModal(page);
    await dismissBlockingRecoveryModal(page);
    const shell = page.locator(".discussion-shell:not(.embedded)");
    await expect(shell).toHaveClass(/right-collapsed/);
    await shell.locator(".channel-item").filter({ hasText: "Legal review for public beta" }).click();
    const input = shell.locator("textarea");
    await expect(input).toBeVisible();
    await expect(shell.locator(".retry-attachment-upload")).toHaveCount(0);
    await expect(shell.locator(".compose-upload-progress")).toBeHidden();
    await input.fill("A draft that must survive opening conversation details");
    await shell.locator(".discussion-users-toggle").click();
    await expect(shell.locator(".discussion-details-panel")).toBeVisible();
    await shell.locator(".discussion-users-toggle").click();
    await expect(shell.locator(".discussion-details-panel")).toBeHidden();
    await expect(shell).toHaveClass(/right-collapsed/);
    await expect(input).toHaveValue("A draft that must survive opening conversation details");
    const area = await shell.locator(".discussion-main-panel").boundingBox();
    const composer = await shell.locator(".discussion-composer").boundingBox();
    expect(area).not.toBeNull();
    if (width >= 1280) expect(area!.width).toBeGreaterThan(600);
    const paint = await input.evaluate(element => ({ bg: getComputedStyle(element).backgroundColor, color: getComputedStyle(element).color }));
    expect(paint.bg).not.toBe("rgb(255, 255, 255)");
    expect(paint.bg).not.toBe(paint.color);
    await page.screenshot({ path: testInfo.outputPath(`discussion-${width}.png`) });
    await testInfo.attach(`layout-${width}`, {
      body: JSON.stringify({ viewport: page.viewportSize(), discussion: area, composer }),
      contentType: "application/json",
    });
    await toggleTheme(page);
    await expect(input).toHaveValue("A draft that must survive opening conversation details");
    await page.screenshot({ path: testInfo.outputPath(`discussion-alternate-${width}.png`) });
  });
}

test("attachment failures expose retry while preserving the message draft", async ({ page }, testInfo) => {
  const diagnostics: string[] = [];
  page.on("console", message => {
    if (/file|attachment|panic|retired/i.test(message.text())) diagnostics.push(message.text().slice(0, 1000));
  });
  await openKanban(page);
  const realm = new URL(page.url()).pathname.split("/")[2];
  await page.goto(`/chat/${realm}`);
  await dismissHistoryRecoveryModal(page);
  await dismissBlockingRecoveryModal(page);
  const shell = page.locator(".discussion-shell:not(.embedded)");
  await shell.locator(".channel-item").filter({ hasText: "Legal review for public beta" }).click();
  const input = shell.locator("textarea");
  await input.fill("Keep this draft when the attachment service is unavailable");
  const retry = shell.locator(".retry-attachment-upload");
  await expect(retry).toHaveCount(0);
  let uploads = 0;
  await page.route(/\/_arkret\/self\/blob\/upload(?:\?.*)?$/, async route => {
    uploads += 1;
    await route.fulfill({ status: 403, contentType: "application/problem+json", body: JSON.stringify({
      type: "https://arkret.org/problems/blob_quota_exceeded", title: "Blob quota exceeded", status: 403,
      detail: "The test account storage quota is exhausted.",
    }) });
  });
  const chooser = page.waitForEvent("filechooser");
  await shell.locator("button.compose-drop-zone").click();
  const attachmentPath = testInfo.outputPath("draft.txt");
  writeFileSync(attachmentPath, "Retain exact attachment input");
  await (await chooser).setFiles(attachmentPath);
  try {
    await expect.poll(() => uploads).toBe(1);
  } catch (error) {
    writeFileSync(testInfo.outputPath("attachment-diagnostics.json"), JSON.stringify({
      diagnostics, status: await shell.locator(".compose-upload-progress").allTextContents(),
      files: await page.locator("input[type=file]").evaluateAll(inputs => inputs.map(input => ({ files: (input as HTMLInputElement).files?.length, disabled: (input as HTMLInputElement).disabled }))),
    }, null, 2));
    throw error;
  }
  await expect(retry).toBeVisible();
  await expect(retry).toBeEnabled();
  await retry.click();
  await expect.poll(() => uploads).toBe(2);
  await expect(retry).toBeVisible();
  await expect(input).toHaveValue("Keep this draft when the attachment service is unavailable");
});
