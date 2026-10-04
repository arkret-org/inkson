import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const composerCss = readFileSync(new URL("../../src/styles/features/chat-composer.css", import.meta.url), "utf8");

for (const width of [900, 360]) {
  test(`mention chips stay separated and fit the embedded composer at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 650 });
    await page.setContent(`<!doctype html><html><head><style>
      :root { --border:#3b4855; --surface:#1e2935; --surface-2:#25382e; --text:#e0e7e5; --text-2:#b1b8b7; --accent:#efa600; }
      * { box-sizing:border-box; } body { margin:20px; background:var(--surface); color:var(--text); font:14px sans-serif; }
      ${composerCss}
    </style></head><body><div class="discussion-shell embedded"><div class="discussion-composer">
      <div class="compose-drop-zone"><textarea>@me</textarea><div class="mention-chip-row">
        <button class="composer-tool-button">@</button><button class="composer-tool-button">+</button>
        <div class="mention-chip" data-testid="self-chip"><span class="mention-chip-label">@me</span><span class="mention-chip-subtitle">You</span><button class="mention-chip-remove" aria-label="Remove mention @me">×</button></div>
        <div class="mention-chip"><span class="mention-chip-label">@long-agent-name:example.com</span><span class="mention-chip-subtitle">Agent account</span><button class="mention-chip-remove" aria-label="Remove agent mention">×</button></div>
      </div></div>
    </div></div></body></html>`);
    const chip = page.getByTestId("self-chip");
    const label = await chip.locator(".mention-chip-label").boundingBox();
    const subtitle = await chip.locator(".mention-chip-subtitle").boundingBox();
    const remove = chip.getByRole("button");
    const button = await remove.boundingBox();
    expect(label).not.toBeNull(); expect(subtitle).not.toBeNull(); expect(button).not.toBeNull();
    expect(subtitle!.x - (label!.x + label!.width)).toBeGreaterThanOrEqual(5);
    expect(button!.x - (subtitle!.x + subtitle!.width)).toBeGreaterThanOrEqual(5);
    expect(button!.width).toBe(24); expect(button!.height).toBe(24);
    const composer = await page.locator(".compose-drop-zone").boundingBox();
    for (const row of await page.locator(".mention-chip").all()) {
      const bounds = await row.boundingBox();
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(composer!.x + composer!.width);
    }
    await remove.focus(); await expect(remove).toBeFocused();
    await page.screenshot({ path:`test-results/layout/mention-chips-${width}.png` });
  });
}
