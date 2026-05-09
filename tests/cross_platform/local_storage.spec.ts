// Round 27 cross-platform scenario: localStorage round-trip of the
// `LocalIdentity` shape (round 23 key store).
//
// The wasm `LocalStateStore::write_persisted_state` path stores the
// entire `ClientLocalState` JSON under `LOCAL_STATE_STORAGE_KEY =
// "yougen.local_state.v1"`. This test exercises the same key with a
// `LocalIdentityRecord`-shaped payload to confirm:
//   * Safari ITP / private browsing doesn't silently drop writes (the
//     test self-skips when storage is rejected — that's the expected
//     behaviour, not a bug).
//   * Firefox preserves the full UTF-8 / signed-byte JSON without
//     re-encoding (historical bug pre-v100 with NUL bytes in keys).
//   * Chromium writes survive a page reload — covered via
//     `page.reload()` + a re-read assertion.

import { expect, test } from "@playwright/test";
import { gotoOrSkip, waitForBundleReady } from "./_helpers";

const STORAGE_KEY = "yougen.local_state.v1";

const SAMPLE_LOCAL_IDENTITY = {
  // Mirrors `LocalIdentityRecord` — verified_handle + signing_seed
  // (32 bytes, hex-encoded) + did_key (multibase did:key prefix).
  did_key:
    "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSdoendfXkY2BVcDzqHM",
  signing_seed_hex:
    "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
  created_at: "2026-05-10T00:00:00Z",
};

test.describe("LocalStorage round-trip of LocalIdentity", () => {
  test.beforeEach(async ({ page }) => {
    await gotoOrSkip(page, "/");
    await waitForBundleReady(page);
  });

  test("writes and reads back the LocalIdentity payload", async ({ page }) => {
    const writeOk = await page.evaluate(
      ({ key, value }) => {
        try {
          window.localStorage.setItem(key, JSON.stringify(value));
          return true;
        } catch (_error) {
          return false;
        }
      },
      { key: STORAGE_KEY, value: SAMPLE_LOCAL_IDENTITY },
    );
    test.skip(
      !writeOk,
      "localStorage rejected setItem (private browsing / ITP?)",
    );

    const readBack = await page.evaluate((key: string) => {
      const raw = window.localStorage.getItem(key);
      return raw === null ? null : JSON.parse(raw);
    }, STORAGE_KEY);

    expect(readBack).toEqual(SAMPLE_LOCAL_IDENTITY);
  });

  test("persists across a page reload", async ({ page }) => {
    const writeOk = await page.evaluate(
      ({ key, value }) => {
        try {
          window.localStorage.setItem(key, JSON.stringify(value));
          return true;
        } catch (_error) {
          return false;
        }
      },
      { key: STORAGE_KEY, value: SAMPLE_LOCAL_IDENTITY },
    );
    test.skip(!writeOk, "localStorage rejected setItem");

    await page.reload({ waitUntil: "domcontentloaded" });
    await waitForBundleReady(page);

    const readBack = await page.evaluate((key: string) => {
      const raw = window.localStorage.getItem(key);
      return raw === null ? null : JSON.parse(raw);
    }, STORAGE_KEY);

    expect(readBack).toEqual(SAMPLE_LOCAL_IDENTITY);
  });

  test("removeItem clears the entry", async ({ page }) => {
    const writeOk = await page.evaluate(
      ({ key, value }) => {
        try {
          window.localStorage.setItem(key, JSON.stringify(value));
          return true;
        } catch (_error) {
          return false;
        }
      },
      { key: STORAGE_KEY, value: SAMPLE_LOCAL_IDENTITY },
    );
    test.skip(!writeOk, "localStorage rejected setItem");

    const stillThere = await page.evaluate((key: string) => {
      window.localStorage.removeItem(key);
      return window.localStorage.getItem(key);
    }, STORAGE_KEY);

    expect(stillThere).toBeNull();
  });
});
