# inkson cross-platform deployment test harness

Drives the five wasm-facing platform contracts
(SubtleCrypto AES-GCM, PushManager + VAPID, opaque push receive,
localStorage round-trip of `LocalIdentity`, OIDC PKCE flow start) across **Chromium**,
**Firefox**, and **WebKit (Safari)** so we catch per-engine drift
before it reaches release.

This harness sits alongside the existing `tests/e2e/` suite (which is
chromium-only and exercises full app flows). The cross-platform matrix
is intentionally narrow: it only validates the platform APIs the
SubtleCrypto secure key store / `web_push_subscribe` paths depend on.
The Rust unit tests in `src/secure_key_store/`, `src/push/`,
`src/state/`, and `src/transport/` cover the in-Rust logic;
this matrix only checks the contract on real engines. Local developer
runs do not exercise real APNs/FCM provider delivery; the receive smoke
pins the service-worker handoff for an opaque `background_sync_needed`
wakeup without exposing notification text or collapse metadata.

## Run

```sh
# Default — all three engines, dx serve auto-started on :4528.
npx playwright test --config tests/cross_platform/playwright.config.ts

# Subset (e.g. CI box with only Firefox installed).
INKSON_CROSS_PLATFORM=firefox npx playwright test \
    --config tests/cross_platform/playwright.config.ts

# Reuse an externally-served bundle (skips the dx serve step).
INKSON_CROSS_PLATFORM_BASE_URL=http://127.0.0.1:9000 \
    npx playwright test --config tests/cross_platform/playwright.config.ts
```

The matrix self-skips when:

* `node` / `npx` are not on PATH — handled by the parent shell, not
  Playwright. The lib-side `cargo test --lib` is unaffected.
* The target browser executable is missing locally
  (`Executable doesn't exist` from `chromium` / `firefox` / `webkit`).
  `gotoOrSkip` in `_helpers.ts` translates this into `test.skip` so
  one missing engine doesn't fail the whole matrix.
* The page is loaded over an insecure origin and the API in question
  requires HTTPS (Safari + Firefox both gate SubtleCrypto and
  PushManager on secure contexts; the helpers in `_helpers.ts`
  detect this and `test.skip` cleanly).

## Run matrix

| Scenario              | Chromium | Firefox | WebKit (Safari) | Maps to Rust |
|-----------------------|----------|---------|-----------------|--------------|
| `subtle_crypto.spec`  | full     | full    | full *           | `secure_key_store::IndexedDbSecureKeyStore` AES-GCM path |
| `push_subscribe.spec` | full     | full    | partial **       | `push::WebPushTokenProvider` (round 26 A3) |
| `push_receive.spec`   | full     | full    | partial **       | Push service-worker receive privacy contract |
| `local_storage.spec`  | full     | full    | partial ***      | `local_state::LocalStateStore` (round 23) |
| `oidc_pkce.spec`      | full     | full    | full             | `coauth::open_oidc_authorize_url` + PKCE helpers (round 24) |

\* Safari requires the page origin to be `https://`. Locally that
means `dx serve` over TLS (not the default); the test self-skips when
SubtleCrypto isn't reachable.

\** Safari + WebKit on `http://localhost` expose `PushManager` but
`subscribe()` rejects with `NotAllowedError`. The matrix only asserts
the contract surface (option-bag shape, VAPID decode); a real subscribe
attempt is out of scope for the local dev box and lives in the
release-channel staging matrix. The receive smoke uses a local service
worker simulation for the same reason: real APNs/FCM delivery needs
provider credentials, TLS origin policy, and OS notification
entitlements.

\*** Safari ITP and private browsing both refuse `localStorage.setItem`
on third-party contexts; the test self-skips when the write returns an
error rather than reporting a flake.

## Known platform-specific quirks

* **Safari `KeyAlgorithm` strict naming.** `crypto.subtle.importKey`
  requires the algorithm `name` to be exactly `"AES-GCM"` —
  lowercase or `"AES_GCM"` fails with `OperationError`. The Rust
  SubtleCrypto callers already pass the canonical form; the matrix
  pins this so a refactor to lowercase canon would be caught here
  rather than at deploy.

* **Firefox `Uint8Array.from` differences.** Pre-v100 Firefox
  shipped `Uint8Array.from(arrayLike, mapFn)` with a different
  default-thisArg behaviour than Chromium. The wasm-bindgen
  `js-sys::Uint8Array::from(slice)` path bypasses this, but the
  in-page test asserts the typed-array round-trips through
  `structuredClone` — that's a stronger guarantee than just `.from`.

* **Firefox WebCrypto on insecure origins.** Pre-v117 builds
  exposed `crypto.subtle` only on `https://` and `http://localhost`.
  The dev server's default `127.0.0.1` host triggered the secure-
  context check; we now bind to `127.0.0.1` explicitly which
  Firefox treats as a secure origin. The helper `ensureSubtleCryptoAvailable`
  detects the gap and skips rather than failing.

* **WebKit `PushManager` reachability.** WebKit ships `PushManager`
  but only fully implements `subscribe()` on https origins with a
  registered service worker AND APNs entitlements. Local dev never
  meets that bar; the test only asserts that the bundle's bridge
  layer can produce a `PushSubscriptionOptionsInit`-shaped object the
  engine round-trips through `structuredClone`. The full subscribe
  is exercised by the staging release channel matrix.

* **Safari ITP on localStorage.** Even the first-party `localStorage`
  bucket can be cleared after 7 days of inactivity (Safari 14+). The
  Rust `LocalStateStore::write_persisted_state` no-ops on a write
  failure; the matrix asserts the same on the JS side.

* **OIDC redirect-URI scheme filtering.** `open_oidc_authorize_url`
  only allows `http://` and `https://`. The matrix asserts
  `javascript:`, `file:`, and `data:` are all refused by the in-page
  helper that mirrors the Rust filter — engines normalise these
  schemes inconsistently (Safari historically classed `data:` URLs
  in `URL.protocol` as `data:` whereas older Firefox stripped them).

## CI integration (forward-looking)

The intended CI shape is a per-OS job:

* **macOS-13** runner: `chromium` + `webkit`. Webkit is the only
  engine bundled with Playwright that approximates Safari's
  WebCrypto strictness.
* **ubuntu-22.04** runner: `chromium` + `firefox`.
* **windows-2022** runner: `chromium` + `firefox`. WebKit on Windows
  is functional but flaky on PushManager; pin to the macOS runner.

A nightly job runs all three matrices serially against the release
candidate `dx build --release` artifact, and the staging release
channel re-runs the matrix against a `https://` URL so the partial
WebKit cases can promote to `full`.

## File layout

```
tests/cross_platform/
  README.md                  this file
  playwright.config.ts       per-engine project list + dx serve hook
  _helpers.ts                shared skip-on-missing helpers
  subtle_crypto.spec.ts      SubtleCrypto AES-GCM platform contract
  push_subscribe.spec.ts     PushManager + VAPID platform contract
  push_receive.spec.ts       service-worker opaque wakeup contract
  local_storage.spec.ts      LocalIdentity round-trip
  oidc_pkce.spec.ts          PKCE S256 + scheme filter
```
