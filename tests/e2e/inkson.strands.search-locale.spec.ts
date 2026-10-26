import { assertSearchSource, searchReference } from "./searchSource";
import { inputByClass } from "./uiControl";
import { byClass } from "./strandsHarness";
import { expect, test, type Page } from "@playwright/test";
import {
  assertRealmTreeSeeded,
  dismissBlockingRecoveryModal,
  openSettings,
  openKanban,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openSearch(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(byClass(page, "global-search-panel")).toBeVisible();
}

async function setLanguage(page: Page, language: "en" | "zh") {
  await openSettings(page);
  await byClass(page, "settings-nav-item-theme").click();
  await byClass(page, "settings-language-choice").filter({ hasText: language === "zh" ? "中文" : "English" }).click();
  await expect(page.locator("html")).toHaveAttribute("lang", language);
  await openSearch(page);
}

function searchSideEffects(page: Page) {
  const requests: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (
      (path.startsWith("/_arkret/") && path.split("/").includes("search")) ||
      path === "/_arkret/self/events" ||
      path.endsWith("/realm-joins/prepare")
    ) {
      requests.push(`${request.method()} ${path}`);
    }
  });
  return requests;
}

test("global search empty and no-match states follow the active language", async ({ page }) => {
  const requests = searchSideEffects(page);
  await refreshServer(page);
  const literalQuery = "missing {query} / search.title / 原文";
  for (const language of ["en", "zh", "en"] as const) {
    // Settings is the public language control. Returning through the shortcut
    // mounts Search again; the retained-snapshot behavior is covered natively.
    await setLanguage(page, language);
    const panel = byClass(page, "global-search-panel");
    const input = inputByClass(panel, "global-search-input");
    await expect(panel).toHaveAttribute("aria-label", language === "zh" ? "搜索消息" : "Search messages");
    await expect(byClass(panel, "global-search-index-label")).toHaveText(language === "zh" ? "搜索索引" : "Search index");
    await expect(byClass(panel, "global-search-back")).toHaveText(language === "zh" ? "返回首页" : "Back to dashboard");
    await expect(input).toHaveValue("");
    await expect(panel.locator(".input-empty-prompt")).toHaveText( language === "zh" ? "在所有 Realm 中搜索消息…" : "Search across all your Realms...");
    await expect(byClass(panel, "global-search-submit")).toBeDisabled();
    await expect(byClass(panel, "global-search-results-empty")).toHaveText(language === "zh" ? "输入查询以在所有 Realm 中搜索。" : "Type a query to search across your Realms.");
    await input.fill(literalQuery);
    await byClass(panel, "global-search-submit").click();
    await expect(input).toHaveValue(literalQuery);
    await expect(byClass(panel, "global-search-results-no-results")).toHaveText(language === "zh" ? "未找到匹配项。" : "No matches found.");
    await expect(byClass(panel, "global-search-result-item")).toHaveCount(0);
    await byClass(panel, "global-search-back").click();
    await expect(byClass(page, "dashboard-panel")).toBeVisible();
  }
  expect(requests).toEqual([]);
});

test("global search results preserve local text and routes across language changes", async ({ page }) => {
  const requests = searchSideEffects(page);
  // The account list deliberately requests no Realm details. Load this
  // authorized Realm through the normal product route before searching its
  // local history; a notification preview is not an accepted message index.
  await openKanban(page);
  const originalBody = "Alice sent a message in Demo Realm";
  const query = `  ${originalBody}  `;
  let originalHref: string | null = null;
  let originalRealm: string | null = null;
  let originalSeal: string | null = null;
  let originalCommit: string | null = null;
  for (const language of ["en", "zh", "en"] as const) {
    await setLanguage(page, language);
    const panel = byClass(page, "global-search-panel");
    const input = inputByClass(panel, "global-search-input");
    await input.fill(query);
    await byClass(panel, "global-search-submit").click();
    await expect(input).toHaveValue(query);
    const row = byClass(panel, "global-search-result-item");
    await expect(row).toHaveCount(1);
    await expect(byClass(row, "global-search-result-snippet")).toHaveText(originalBody);
    await expect(row.locator(".event-head").locator(".global-search-result-kind")).toHaveText(language === "zh" ? "消息" : "Message");
    const link = byClass(row, "global-search-result-link");
    const seal = byClass(row, "global-search-result-seal");
    await assertSearchSource(row);
    await expect(searchReference(row, "commit")).toHaveText(/^ak:realm_commit:/);
    const realm = byClass(row, "global-search-result-realm");
    if (originalHref === null) {
      originalHref = await link.getAttribute("href");
      originalRealm = await searchReference(row, "realm").textContent();
      originalSeal = await searchReference(row, "event").textContent();
      originalCommit = await searchReference(row, "commit").textContent();
      expect(originalRealm).toMatch(/^ak:realm:/);
      expect(originalSeal).toMatch(/^ak:event:/);
      await expect(searchReference(row, "event")).toHaveText( originalSeal!);
      const route = new URL(originalHref!, page.url());
      expect(decodeURIComponent(route.pathname)).toBe(`/chat/${originalRealm}`);
      expect(route.searchParams.get("message")).toBe(originalSeal);
    }
    await expect(searchReference(row, "commit")).toHaveText( originalCommit!);
    await expect(link).toHaveAttribute("href", originalHref!);
    await expect(searchReference(row, "realm")).toHaveText( originalRealm!);
    await expect(searchReference(row, "event")).toHaveText( originalSeal!);
    await expect(seal).toHaveText(`${language === "zh" ? "打开消息" : "Open message"}: ${originalSeal}`);
  }
  // A new Wasm instance must hydrate the committed account records and current
  // cut before the existing local history can authorize this same result.
  await page.reload();
  await expect(page.locator(".shell.app")).toBeVisible();
  await openSearch(page);
  const recovered = byClass(page, "global-search-panel");
  await inputByClass(recovered, "global-search-input").fill(query);
  await byClass(recovered, "global-search-submit").click();
  const recoveredRow = byClass(recovered, "global-search-result-item");
  await expect(recoveredRow).toHaveCount(1);
  await expect(searchReference(recoveredRow, "event")).toHaveText( originalSeal!);
  await expect(searchReference(recoveredRow, "commit")).toHaveText( originalCommit!);
  await expect(byClass(recoveredRow, "global-search-result-snippet")).toHaveText(originalBody);
  await expect(byClass(recoveredRow, "global-search-result-link")).toHaveAttribute("href", originalHref!);
  const destination = new URL(originalHref!, page.url()).toString();
  await byClass(page, "global-search-result-link").click();
  await expect(page).toHaveURL(destination);
  await expect(byClass(page, "chat-panel")).toBeVisible();
  expect(requests).toEqual([]);
});
