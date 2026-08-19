// Round 27 cross-platform scenario: SubtleCrypto AES-GCM round-trip.
//
// Mirrors the wasm secure key store's SubtleCrypto path
// (`src/secure_key_store/indexed_db.rs`) — those Rust bindings call
// `subtle.importKey` + `subtle.encrypt` / `subtle.decrypt` with
// `AesGcmParams`. This test drives the same call sequence directly
// from the page so we catch per-engine quirks:
//   * Safari requires the `name` field on the imported key algorithm
//     to be exactly "AES-GCM" (case-sensitive); a lowercase form
//     fails with `OperationError`.
//   * Firefox until v128 returned the IV-suffixed ciphertext as a
//     plain `Uint8Array` whereas Chromium returns an `ArrayBuffer`;
//     the assertions below normalise both shapes.
//
// The scenario does NOT exercise the wasm bundle's Rust side — the
// Rust-level test suite in `src/secure_key_store/` already covers
// that. The matrix only validates that the browser's native crypto
// produces the same ciphertext shape across engines.

import { expect, test } from "@playwright/test";
import {
  ensureSubtleCryptoAvailable,
  gotoOrSkip,
  waitForBundleReady,
} from "./_helpers";

test.describe("SubtleCrypto AES-GCM round-trip", () => {
  test.beforeEach(async ({ page }) => {
    await gotoOrSkip(page, "/");
    await waitForBundleReady(page);
    await ensureSubtleCryptoAvailable(page);
  });

  test("encrypts and decrypts a 32-byte payload via AES-GCM", async ({
    page,
  }) => {
    const result = await page.evaluate(async () => {
      const enc = new TextEncoder();
      const dec = new TextDecoder();
      const plaintext = enc.encode("arkret-cross-platform-2026");
      // Fixed key bytes so any engine-specific endian / length issue
      // surfaces deterministically.
      const rawKey = new Uint8Array(32);
      for (let i = 0; i < 32; i += 1) {
        rawKey[i] = i;
      }
      const key = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" }, // Safari: must be the exact upper-case form.
        false,
        ["encrypt", "decrypt"],
      );
      const iv = new Uint8Array(12);
      crypto.getRandomValues(iv);
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: enc.encode("aad-2026") },
        key,
        plaintext,
      );
      const cipherBytes = new Uint8Array(ciphertext);
      const recovered = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: enc.encode("aad-2026") },
        key,
        cipherBytes,
      );
      return {
        cipherLen: cipherBytes.length,
        plainLen: plaintext.length,
        recoveredText: dec.decode(recovered),
      };
    });

    expect(result.recoveredText).toBe("arkret-cross-platform-2026");
    // AES-GCM appends a 16-byte tag.
    expect(result.cipherLen).toBe(result.plainLen + 16);
  });

  test("rejects ciphertext when the AAD doesn't match", async ({ page }) => {
    const ok = await page.evaluate(async () => {
      const enc = new TextEncoder();
      const rawKey = new Uint8Array(32);
      const key = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"],
      );
      const iv = new Uint8Array(12);
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: enc.encode("aad-A") },
        key,
        enc.encode("payload"),
      );
      try {
        await crypto.subtle.decrypt(
          { name: "AES-GCM", iv, additionalData: enc.encode("aad-B") },
          key,
          ciphertext,
        );
        return "no-throw";
      } catch (error) {
        // All three engines throw `OperationError` here, but the
        // `name` field varies — Firefox uses `OperationError`, Safari
        // historically used `AbortError`. We just assert it threw.
        return "threw";
      }
    });

    expect(ok).toBe("threw");
  });
});
