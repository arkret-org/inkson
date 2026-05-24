// Round 27: shared helpers for the cross-platform deployment matrix.
//
// The scenario specs (subtle_crypto / push_subscribe / push_receive /
// local_storage / oidc_pkce) all need the same plumbing:
//   1. Resolve the configured browser engine from `browserName`.
//   2. Self-skip when the target engine isn't installed locally
//      (Playwright surfaces this as "Executable doesn't exist" on the
//      first navigation; the `skipIfBrowserUnavailable` helper turns
//      that into a `test.skip` so the matrix stays green on partial
//      installs).
//   3. Wait for the wasm bundle to boot — authenticated sessions expose
//      `client-shell`, while fresh local profiles expose `auth-shell`.
//
// The harness is intentionally light on app-specific knowledge: every
// scenario uses `page.evaluate` to drive the browser API directly
// rather than reaching through the dioxus router. That keeps the
// matrix focused on the platform contract — the Rust unit tests in
// `src/crypto_boundary.rs` / `src/push.rs` / `src/local_state.rs`
// already cover the in-Rust logic.

import { test, type Page } from "@playwright/test";

export type BrowserKind = "chromium" | "firefox" | "webkit";

/** Attempt to navigate to `path`; if the browser executable is
 * missing (Playwright not fully installed in the local checkout)
 * convert the failure into a `test.skip`. */
export async function gotoOrSkip(page: Page, path: string): Promise<void> {
  try {
    await page.goto(path, { waitUntil: "domcontentloaded", timeout: 60_000 });
  } catch (error) {
    const message = String((error as Error).message ?? error);
    if (/Executable doesn't exist|browserType\.launch/.test(message)) {
      test.skip(true, `browser executable not installed: ${message}`);
    } else {
      throw error;
    }
  }
}

/** Wait for either wasm shell to appear. The platform API specs do not
 * need an authenticated client session; they only need a booted bundle
 * and the browser APIs available on the page origin. */
export async function waitForBundleReady(page: Page): Promise<void> {
  await page.waitForSelector(
    "[data-testid=client-shell], [data-testid=auth-shell]",
    { timeout: 120_000 },
  );
}

/** True when the page exposes a working SubtleCrypto. Some Firefox
 * builds disable WebCrypto over `http://` (only secure contexts) —
 * the test self-skips when that's the case rather than reporting a
 * spurious failure. */
export async function ensureSubtleCryptoAvailable(page: Page): Promise<void> {
  const ok = await page.evaluate(() => {
    return typeof crypto !== "undefined"
      && typeof crypto.subtle !== "undefined"
      && typeof crypto.subtle.encrypt === "function";
  });
  test.skip(!ok, "SubtleCrypto not available in this context (insecure origin?)");
}

/** True when the page exposes a `PushManager`. Safari ships a
 * `PushManager` but only on `https://` origins with a service worker;
 * Firefox ships it under the `MOZ_` prefix on older releases. The
 * test self-skips when neither is reachable so the matrix doesn't
 * fail just because the local dev server is on http://. */
export async function ensurePushManagerAvailable(page: Page): Promise<void> {
  const ok = await page.evaluate(() => {
    return (
      typeof PushManager !== "undefined"
      || ("PushSubscription" in window)
    );
  });
  test.skip(!ok, "PushManager not exposed in this context");
}

/** True when a service worker can be registered from the current
 * origin. Push receive smoke only needs the worker message contract;
 * real provider delivery stays in the release-channel staging matrix. */
export async function ensureServiceWorkerAvailable(page: Page): Promise<void> {
  const ok = await page.evaluate(() => {
    return (
      "serviceWorker" in navigator
      && typeof navigator.serviceWorker.register === "function"
    );
  });
  test.skip(!ok, "ServiceWorker not exposed in this context");
}
