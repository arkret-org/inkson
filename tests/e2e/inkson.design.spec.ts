import { expect, test } from "@playwright/test";
import { writeFileSync } from "node:fs";
import { registerStrandsBeforeEach, openKanban, dismissBlockingRecoveryModal, dismissHistoryRecoveryModal } from "./strandsHarness";

registerStrandsBeforeEach();

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
    await page.locator(".theme-toggle-button:visible").click();
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
    await page.locator(".theme-toggle-button:visible").click();
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
    await route.fulfill({ status: 503, contentType: "application/problem+json", body: JSON.stringify({
      type: "https://arkret.org/problems/service_unavailable", title: "Service unavailable", status: 503,
      detail: "Temporary attachment service failure",
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
