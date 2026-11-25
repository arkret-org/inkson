import { expect, test } from "@playwright/test";

for (const width of [817, 390, 240]) {
  test(`secure storage message wraps only when space is limited at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 609 });
    await page.setContent(`
      <div class="arkret-startup">
        <h1>Opening secure storage</h1>
        <p class="startup-message">Loading encrypted account and device keys…</p>
      </div>
    `);
    await page.addStyleTag({ path: "web/startup.css" });
    const lines = await page.locator(".startup-message").evaluate(message => {
      const range = document.createRange();
      range.selectNodeContents(message);
      return Array.from(range.getClientRects(), rect => ({ left: rect.left, right: rect.right }));
    });
    if (width === 240) {
      expect(lines.length).toBeGreaterThan(1);
    } else {
      expect(lines).toHaveLength(1);
    }
    for (const line of lines) {
      expect(line.left).toBeGreaterThanOrEqual(0);
      expect(line.right).toBeLessThanOrEqual(width);
    }
  });
}
