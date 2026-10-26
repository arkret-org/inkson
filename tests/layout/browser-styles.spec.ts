import { expect, test, type Page } from "@playwright/test";
import { mountMessageMenuFixture } from "./message-menu-fixture.mjs";

const base = process.env.INKSON_LAYOUT_BASE_URL ?? process.env.INKSON_E2E_BASE_URL ?? "http://127.0.0.1:4727";

async function checkCascade(page: Page, requests: string[]) {
  await expect.poll(() => page.evaluate(() => {
    const baseline = document.head.querySelector('style[data-gly-base="v1"]');
    const sapid = document.getElementById("inkson-sapid-css") as HTMLLinkElement | null;
    const app = document.getElementById("inkson-app-css") as HTMLLinkElement | null;
    return Boolean(baseline && sapid?.sheet && app?.sheet
      && (baseline.compareDocumentPosition(sapid) & Node.DOCUMENT_POSITION_FOLLOWING)
      && (sapid.compareDocumentPosition(app) & Node.DOCUMENT_POSITION_FOLLOWING));
  })).toBe(true);
  for (const path of ["/assets/sapid.css", "/assets/app.css"]) {
    expect(requests.filter(url => new URL(url).pathname === path), path).toHaveLength(1);
  }
}

for (const mode of ["production", "message-menu", "attachment-lifetime"] as const) {
  test(`${mode} uses the application cascade without requesting either stylesheet twice`, async ({ page }) => {
    const requests: string[] = [];
    page.on("request", request => {
      if (request.resourceType() === "stylesheet") requests.push(request.url());
    });
    if (mode === "production") {
      await page.goto(new URL("/login", base).href);
      await expect(page.locator(".auth-primary")).toBeVisible();
    } else if (mode === "message-menu") {
      await mountMessageMenuFixture(page);
    } else {
      await page.goto(new URL("/?__inkson_fixture=attachment-lifetime", base).href);
      await page.evaluate(async () => {
        const path = "/assets/pkg/inkson.js";
        const module = await import(path);
        await module.default();
        const root = document.getElementById("app");
        if (!root || typeof module.mountAttachmentLifetimeFixture !== "function") {
          throw new Error("Build the real attachment fixture with spec-conformance");
        }
        module.mountAttachmentLifetimeFixture(root);
      });
      await expect(page.getByRole("button", { name: "Read attachment", exact: true })).toBeVisible();
    }
    await checkCascade(page, requests);
  });
}
