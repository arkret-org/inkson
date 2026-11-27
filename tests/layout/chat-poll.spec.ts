import { expect, test } from "@playwright/test";
import { appCss } from "./app-styles";

for (const width of [1600, 1280, 1024, 390]) {
  test(`Chat composer leaves a clickable poll at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 720 });
    await page.setContent(`<!doctype html><html><head><style>${appCss}</style></head><body>
      <div class="shell app workspace-shell ${width <= 860 ? "workspace-mobile" : ""}">
      <nav class="navigation-rail">Inkson</nav><div class="workspace workspace-has-list">
      <aside class="workspace-pane workspace-pane-list ${width <= 860 ? "is-hidden" : "is-visible"}"><div class="workspace-list">Realms</div></aside>
      <main class="main realm workspace-pane workspace-pane-detail is-visible"><header class="topbar realm-header">Realm discussion</header>
      <div class="realm-body"><div class="discussion-shell chat-panel">
        <section class="discussion-panel discussion-sidebar-panel">Strand discussions</section>
        <section class="discussion-panel discussion-main-panel">
          <header class="discussion-chat-head">Poll Strand</header>
          <div class="discussion-chat-feed message-list" data-testid="feed">
            <article class="discussion-message"><div class="msg-body">
              <div class="poll-card"><div class="poll-question">Release this week?</div>
              <div class="poll-result-row"><button data-testid="vote">Now</button><span>0</span></div>
              <div class="poll-result-row"><button>Later</button><span>0</span></div></div>
            </div></article>
          </div>
        </section>
        <section class="discussion-panel discussion-details-panel">Users</section>
        <div class="discussion-composer">
          <textarea rows="3">Message this discussion.</textarea><button>Send</button>
        </div>
      </div></div></main></div></div>
    </body></html>`);
    const feed = await page.getByTestId("feed").boundingBox();
    expect(feed!.height, "the composer must not consume the entire timeline").toBeGreaterThanOrEqual(160);
    const main = await page.locator(".discussion-main-panel").boundingBox();
    const body = await page.locator(".realm-body").boundingBox();
    expect(main!.width).toBeGreaterThanOrEqual(Math.min(360, body!.width - 32));
    await page.getByTestId("vote").click({ timeout: 2_000 });
    await expect(page.locator(".discussion-sidebar-panel")).not.toHaveCSS("display", "none");
    await expect(page.locator(".discussion-details-panel")).not.toHaveCSS("display", "none");
    await page.screenshot({ path: testInfo.outputPath(`chat-poll-${width}.png`) });
  });
}
