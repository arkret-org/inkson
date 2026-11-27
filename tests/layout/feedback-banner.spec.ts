import { expect, test } from "@playwright/test";
import { appCss } from "./app-styles";

for (const theme of ["light", "dark"]) {
  for (const width of [1254, 360]) {
    test(`offline banner reserves space above the topbar at ${width}px in ${theme}`, async ({ page }) => {
      await page.setViewportSize({ width, height: 650 });
      await page.setContent(`<!doctype html><html data-theme="${theme}"><head><style>${appCss}</style></head><body>
        <div class="shell app workspace-shell">
          <nav class="navigation-rail" aria-label="Main navigation">Inkson | Arkret</nav>
          <div class="workspace">
            <main class="main realm">
              <div class="app-banner app-banner--offline" role="status">You are offline. Changes will sync once the connection is restored.</div>
              <div class="topbar realm-header"><div class="topbar-left">Facebook</div><div class="actions"><button>Boards</button></div></div>
              <div class="realm-body">Board content</div>
            </main>
          </div>
        </div>
      </body></html>`);
      const banner = page.getByRole("status");
      const bounds = await banner.boundingBox();
      const nextSurface = page.locator(".topbar");
      const topbar = await nextSurface.boundingBox();
      expect(bounds).not.toBeNull();
      expect(topbar!.y).toBeGreaterThanOrEqual(bounds!.y + bounds!.height);
      expect(bounds!.x).toBeGreaterThanOrEqual(0);
      expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
      const background = await banner.evaluate(el => getComputedStyle(el).backgroundColor);
      expect(background).toMatch(/^rgb\(/);
      await page.getByRole("button", { name: "Boards", exact: true }).click();
      await page.screenshot({ path: test.info().outputPath(`offline-banner-${theme}-${width}.png`) });
      const previousY = topbar!.y;
      await banner.evaluate(el => el.remove());
      const onlineTopbar = await nextSurface.boundingBox();
      expect(previousY - onlineTopbar!.y).toBeCloseTo(bounds!.height, 1);
    });
  }
}
