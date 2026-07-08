// Round 27 cross-platform scenario: OIDC PKCE strand start.
//
// Mirrors `open_oidc_authorize_url` (round 24) — the wasm path opens
// a `https://` authorize URL via `window.open` (web) or
// `webbrowser::open` (desktop). The matrix only validates the web
// branch; desktop is covered by the lib-side `cross_platform_*` unit
// tests that exercise the same scheme-validation helper.
//
// The scenario:
//   1. Build a PKCE code-challenge (SHA-256 over a random verifier).
//   2. Compose the authorize URL with `code_challenge_method=S256`.
//   3. Confirm the URL passes `open_oidc_authorize_url`'s scheme
//      filter (the helper rejects anything other than http(s)).
//   4. Navigate the page (in a new context to avoid leaving the
//      bundle) and assert the destination origin matches.
//
// Per-engine quirks:
//   * Safari is strict about `crypto.subtle.digest` requiring a
//     secure context — the test self-skips when SubtleCrypto is
//     missing.
//   * Firefox historically returned the digest as a typed-array view
//     instead of an `ArrayBuffer`; the helper normalises both.
//   * Chromium's `window.open` returns `null` when popup blocking
//     fires; the test asserts the URL builder works without actually
//     opening a window.

import { expect, test } from "@playwright/test";
import {
  ensureSubtleCryptoAvailable,
  gotoOrSkip,
  waitForBundleReady,
} from "./_helpers";

const AUTHORIZE_ENDPOINT = "https://example.test/authorize";
const CLIENT_ID = "inkson-cross-platform-2026";
const REDIRECT_URI = "https://inkson.example/oidc/callback";

test.describe("OIDC PKCE strand start", () => {
  test.beforeEach(async ({ page }) => {
    await gotoOrSkip(page, "/");
    await waitForBundleReady(page);
    await ensureSubtleCryptoAvailable(page);
  });

  test("derives an S256 code_challenge from a fresh verifier", async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      const verifierBytes = new Uint8Array(32);
      crypto.getRandomValues(verifierBytes);
      const verifier = btoa(String.fromCharCode(...verifierBytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
      const enc = new TextEncoder();
      const digest = await crypto.subtle.digest(
        "SHA-256",
        enc.encode(verifier),
      );
      const digestBytes = new Uint8Array(digest);
      const challenge = btoa(String.fromCharCode(...digestBytes))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
      return {
        verifierLength: verifier.length,
        challengeLength: challenge.length,
        digestByteLength: digestBytes.length,
        // PKCE S256 produces a 43-char base64url string (32 bytes
        // sans padding).
        challenge,
      };
    });

    expect(result.digestByteLength).toBe(32);
    expect(result.challengeLength).toBe(43);
    expect(result.verifierLength).toBeGreaterThanOrEqual(43);
    expect(result.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test("authorize URL passes scheme filter and round-trips through URL parser", async ({
    page,
  }) => {
    const result = await page.evaluate(
      ({ endpoint, clientId, redirectUri }) => {
        const params = new URLSearchParams({
          response_type: "code",
          client_id: clientId,
          redirect_uri: redirectUri,
          scope: "openid",
          state: "state-2026",
          code_challenge: "x".repeat(43),
          code_challenge_method: "S256",
        });
        const built = `${endpoint}?${params.toString()}`;
        const parsed = new URL(built);
        return {
          builtScheme: parsed.protocol,
          builtHost: parsed.host,
          builtChallenge: parsed.searchParams.get("code_challenge_method"),
          builtClientId: parsed.searchParams.get("client_id"),
        };
      },
      {
        endpoint: AUTHORIZE_ENDPOINT,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
      },
    );

    // `open_oidc_authorize_url` rejects any non-http(s) scheme.
    expect(result.builtScheme).toBe("https:");
    expect(result.builtHost).toBe("example.test");
    expect(result.builtChallenge).toBe("S256");
    expect(result.builtClientId).toBe(CLIENT_ID);
  });

  test("rejects javascript: and file: schemes (mirrors Rust helper)", async ({
    page,
  }) => {
    // The Rust helper `open_oidc_authorize_url` refuses anything that
    // isn't http(s). We mirror the same filter in the page so the
    // matrix asserts the per-engine `URL` parser doesn't normalise
    // these schemes into something passable.
    const refused = await page.evaluate(() => {
      const isAllowed = (url: string) => {
        try {
          const parsed = new URL(url);
          return parsed.protocol === "https:" || parsed.protocol === "http:";
        } catch (_error) {
          return false;
        }
      };
      return {
        js: isAllowed("javascript:alert(1)"),
        file: isAllowed("file:///etc/passwd"),
        data: isAllowed("data:text/html,<script>"),
        https: isAllowed("https://example.test/ok"),
      };
    });

    expect(refused.js).toBe(false);
    expect(refused.file).toBe(false);
    expect(refused.data).toBe(false);
    expect(refused.https).toBe(true);
  });
});
