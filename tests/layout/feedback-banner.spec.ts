import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const app = readFileSync(new URL("../../src/app/mod.rs", import.meta.url), "utf8");
const css = [...app.matchAll(/include_str!\("\.\.\/(styles\/[^\"]+)"\)/g)]
  .map(match => readFileSync(new URL(`../../src/${match[1]}`, import.meta.url), "utf8"))
  .join("\n");

for (const theme of ["light", "dark"]) {
  for (const width of [1254, 360]) {
    test(`offline banner reserves space above the topbar at ${width}px in ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 650 });
      await page.setContent(`<!doctype html><html data-theme="${theme}"><head><style>${css}</style></head><body>
        <div class="shell app">
          <aside class="sidebar">Inkson | Arkret</aside>
          <div class="mobile-shellbar">Inkson</div>
          <main class="main realm">
            <div class="app-banner app-banner--offline" role="status">You are offline. Changes will sync once the connection is restored.</div>
            <div class="topbar realm-header"><div class="topbar-left">Facebook</div><div class="actions"><button>Board</button></div></div>
            <div class="realm-body">Board content</div>
          </main>
        </div>
      </body></html>`);
      const banner = page.getByRole("status");
      const bounds = await banner.boundingBox();
      const nextSurface = page.locator(width < 720 ? ".realm-body" : ".topbar");
      const topbar = await nextSurface.boundingBox();
      expect(bounds).not.toBeNull();
      expect(topbar!.y).toBeGreaterThanOrEqual(bounds!.y + bounds!.height);
      expect(bounds!.x).toBeGreaterThanOrEqual(0);
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
      const background = await banner.evaluate(el => getComputedStyle(el).backgroundColor);
      expect(background).toMatch(/^rgb\(/);
      if (width >= 720) {
        await page.getByRole("button", { name: "Board", exact: true }).click();
      } else {
        const shellbar = await page.locator(".mobile-shellbar").boundingBox();
        expect(bounds!.y).toBeGreaterThanOrEqual(shellbar!.y + shellbar!.height);
      }
      await page.screenshot({ path: `test-results/layout/offline-banner-${theme}-${width}.png` });
      const previousY = topbar!.y;
      await banner.evaluate(el => el.remove());
      const onlineTopbar = await nextSurface.boundingBox();
      expect(previousY - onlineTopbar!.y).toBeCloseTo(bounds!.height, 1);
    });
  }
}
