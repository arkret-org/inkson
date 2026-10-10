import { expect, test, type Page } from "@playwright/test";
import {
  assertRealmTreeSeeded,
  dismissBlockingRecoveryModal,
  openSettings,
  refreshServer,
  registerStrandsBeforeEach,
} from "./strandsHarness";

registerStrandsBeforeEach();

async function openSearch(page: Page) {
  await dismissBlockingRecoveryModal(page);
  await page.keyboard.press("Control+F");
  await expect(page).toHaveURL(/\/search$/);
  await expect(page.getByTestId("global-search-panel")).toBeVisible();
}

async function setLanguage(page: Page, language: "en" | "zh") {
  await openSettings(page);
  await page.getByTestId("settings-nav-item-theme").click();
  await page.getByTestId(`language-${language}`).click();
  await expect(page.getByTestId("client-shell")).toHaveAttribute("data-locale", language);
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
    const panel = page.getByTestId("global-search-panel");
    const input = panel.getByTestId("global-search-input");
    await expect(panel).toHaveAttribute("aria-label", language === "zh" ? "搜索消息" : "Search messages");
    await expect(panel.getByTestId("global-search-index-label")).toHaveText(language === "zh" ? "搜索索引" : "Search index");
    await expect(panel.getByTestId("global-search-back")).toHaveText(language === "zh" ? "返回首页" : "Back to dashboard");
    await expect(input).toHaveValue("");
    await expect(input).toHaveAttribute("placeholder", language === "zh" ? "在所有 Realm 中搜索消息…" : "Search across all your Realms...");
    await expect(panel.getByTestId("global-search-submit")).toBeDisabled();
    await expect(panel.getByTestId("global-search-results-empty")).toHaveText(language === "zh" ? "输入查询以在所有 Realm 中搜索。" : "Type a query to search across your Realms.");
    await input.fill(literalQuery);
    await panel.getByTestId("global-search-submit").click();
    await expect(input).toHaveValue(literalQuery);
    await expect(panel.getByTestId("global-search-results-no-results")).toHaveText(language === "zh" ? "未找到匹配项。" : "No matches found.");
    await expect(panel.getByTestId("global-search-result-item")).toHaveCount(0);
    await panel.getByTestId("global-search-back").click();
    await expect(page.getByTestId("dashboard-panel")).toBeVisible();
  }
  expect(requests).toEqual([]);
});

test("global search results preserve local text and routes across language changes", async ({ page }) => {
  test.fail(true, "0540: GlobalSearch still consumes retired timeline.events instead of an authorized committed local message projection; migrate with exact Commit and current read authorization before removing this annotation.");
  const requests = searchSideEffects(page);
  await refreshServer(page);
  await assertRealmTreeSeeded(page);
  const originalBody = "Alice sent a message in Demo Realm";
  const query = `  ${originalBody}  `;
  let originalHref: string | null = null;
  let originalRealm: string | null = null;
  let originalSeal: string | null = null;
  for (const language of ["en", "zh", "en"] as const) {
    await setLanguage(page, language);
    const panel = page.getByTestId("global-search-panel");
    const input = panel.getByTestId("global-search-input");
    await input.fill(query);
    await panel.getByTestId("global-search-submit").click();
    await expect(input).toHaveValue(query);
    const row = panel.getByTestId("global-search-result-item");
    await expect(row).toHaveCount(1);
    await expect(row.getByTestId("global-search-result-snippet")).toHaveText(originalBody);
    await expect(row.locator(".event-head > span").first()).toHaveText(language === "zh" ? "消息" : "Message");
    const link = row.getByTestId("global-search-result-link");
    const seal = row.getByTestId("global-search-result-seal");
    const realm = row.getByTestId("global-search-result-realm");
    if (originalHref === null) {
      originalHref = await link.getAttribute("href");
      originalRealm = await realm.getAttribute("title");
      originalSeal = await seal.getAttribute("data-seal");
      expect(originalRealm).toMatch(/^ak:realm:/);
      expect(originalSeal).toMatch(/^ak:event:/);
      const route = new URL(originalHref!, page.url());
      expect(decodeURIComponent(route.pathname)).toBe(`/chat/${originalRealm}`);
      expect(route.searchParams.get("message")).toBe(originalSeal);
    }
    await expect(link).toHaveAttribute("href", originalHref!);
    await expect(realm).toHaveAttribute("title", originalRealm!);
    await expect(seal).toHaveAttribute("data-seal", originalSeal!);
    await expect(seal).toHaveText(`${language === "zh" ? "打开消息" : "Open message"}: ${originalSeal}`);
  }
  const destination = new URL(originalHref!, page.url()).toString();
  await page.getByTestId("global-search-result-link").click();
  await expect(page).toHaveURL(destination);
  await expect(page.getByTestId("chat-panel")).toBeVisible();
  expect(requests).toEqual([]);
});
