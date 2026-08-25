# inkson — FAQ & Troubleshooting

Common issues and their fixes. Every server-error toast in inkson surfaces
the `x-arkret-request-id` header from soland — capture that ID before
filing a bug.

---

## Discovery fails

**Symptom**: top-bar shows "Server unreachable" or "Discovery error 4xx/5xx".

**Checks**:

1. The soland origin you pasted resolves and serves
   `/.well-known/arkret-discovery`.
2. TLS is valid for that origin (browser builds enforce HTTPS).
3. Your network does not block WebSocket upgrade.

**Fix**: re-enter the URL in the **Server / Switch** menu. If you self-host
soland, run `cargo run -- --bind local.host:443` and add a hosts-file entry.

---

## "Login failed: missing session grant"

**Symptom**: coauth completes OIDC but the dashboard never loads; the
status banner says "missing session grant".

**Cause**: the coauth token bundle did not include `ak.session.grant`.

**Fix**: clear the OIDC bundle under **Settings → Sign out** and retry. If
the issue persists, your coauth instance is on an old release — check that
it ships `ak.session.grant` claims.

---

## Keychain prompt loops on macOS

**Symptom**: macOS Keychain prompts for permission every signing operation
instead of "Always allow".

**Fix**: open Keychain Access → search for `inkson` → double-click the
entry → **Access Control** → "Allow all applications to access this item"
OR add inkson explicitly. The `keyring 3.6` crate cannot bypass the
prompt programmatically.

---

## Windows Credential Manager: "Element not found"

**Symptom**: signing operations fail with the Windows error 1168
("Element not found"). Happens on fresh Windows installs.

**Fix**: the Credential Manager service is disabled. Run
`services.msc` → enable **Credential Manager** → set to Automatic →
restart inkson.

---

## Web build shows "Using browser storage fallback" banner

**Symptom**: a small amber banner persists at the top of the page.

**Cause**: by design. The browser has no OS keychain tier, so signing material
and recovered MLS history material live in LocalStorage / IndexedDB. This does
not mean MLS is disabled in the web build.

**Fix**: switch to the desktop build for sensitive accounts. The web build
is fine for low-stakes testing or read-only browsing.

---

## "FirstBackupGate" blocks me from leaving onboarding

**Symptom**: clicking **Finish** on `/onboarding` stays on step 4.

**Cause**: the account has no accepted genesis recovery policy yet, or this
device has not verified the accepted PCR bootstrap Seal evidence.

**Fix**: complete the recovery-policy step and allow its covering Control Seal
to materialize. The gate requires the first accepted Seal plus the genesis
recovery policy; it does not require a separate DID-recovery backup envelope
(that wire class does not exist in Arkret v1).

---

## Push notifications never arrive (desktop)

**Symptom**: chime is reachable in `/audit`, but no native toast appears.

**Checks**:

1. **Settings → Notifications** shows **Wakeup-only** is enabled.
2. The platform push credentials are set on the chime gateway, not in
   inkson (see [`deployment.md`](deployment.md#push-gateway-wiring)).
3. For local desktop tests you've exported `INKSON_FCM_PUSH_TOKEN`,
   `INKSON_APNS_PUSH_TOKEN`, `FCM_PUSH_TOKEN`, `APNS_DEVICE_TOKEN`, or
   `CHASK_PUSH_KEY`.

**Fix**: check chime logs for a matching `register_device` call. If the
call is rejected with `PlaceholderTokenRejected`, your provider is
returning the dev placeholder — see `push::ensure_production_register_request`.

---

## Push notifications never arrive (web)

**Symptom**: no browser notification banner.

**Checks**:

1. The site origin is permitted to use the Notifications API.
2. The service worker registered (DevTools → Application → Service Workers).
3. The browser shows the site under "Allowed to send notifications".

**Fix**: most often the site permission is **Default** instead of
**Allowed**. Click the lock icon next to the URL → Notifications → Allow.

---

## Offline-pending badge stuck at "Pending N"

**Symptom**: badge in the sidebar persists even after coming back online.

**Cause**: the offline queue still holds writes that the server rejected
(e.g. capability denied).

**Fix**: open the developer panel (`/developer`) → **Offline queue** →
inspect the rejected entries. Each row carries the original `request_id`.
Drop or retry as appropriate.

---

## Recovery vault won't decrypt

**Symptom**: **Settings → Recovery → Restore from vault** returns
"Decryption failed".

**Cause**: wrong passphrase, or the vault blob was uploaded with a
different KDF salt.

**Fix**: passphrase is case-sensitive. There is no second-chance — if
the passphrase is truly lost, fall back to SSS / recovery key, or accept
a fresh identity.

---

## Late-recovery banner persists after re-verification

**Symptom**: the **Late recovery** banner stays visible after running
**Re-verify contacts**.

**Cause**: at least one peer has not yet acknowledged your new key.

**Fix**: wait for each peer's `ak.key.verification.done` event, or
manually escalate by sending them a direct message asking them to open
their **Settings → Verify**.

---

## Lighthouse budget regressed locally

**Symptom**: `scripts/lighthouse-local.ps1` exits non-zero.

**Fix**: check `docs/lighthouse-budget.json` for the current budgets. A
regression usually means a new dependency landed without webpack
splitting; run `cargo build --release` then `dx serve` and inspect the
network panel.

---

## "Policy denied" toast keeps appearing

**Symptom**: a red banner says "Policy denied" with a code like
`policy_denied.realm_class_mismatch`.

**Cause**: the server's policy server rejected your request. The shared
feedback component renders the denial as a toast; see `src/components/feedback.rs`.

**Fix**: read the policy code. Each code in `authz/policy-server.md` §3
has a documented obligation list. Often you simply need to switch to the
correct Realm class.

---

## Crash telemetry: how do I turn it on?

It is **OFF by default**. Open **Settings → Privacy → Crash telemetry**
and toggle it on. The toggle requires an explicit user gesture; no
payload leaves the device until then. See
[`SECURITY.md#telemetry-default-off`](../SECURITY.md#telemetry-default-off).

To opt in to Sentry capture specifically you also need a build-time
`SENTRY_DSN`. See [`observability.md`](observability.md) for the toggle.

---

## How do I capture the request_id for a bug report?

Every error toast renders `request_id: ak:request:...`. Hover the toast
to see the full ID, or click the **Copy ID** button. The same ID appears
in `tracing` log lines emitted by `crate::api` so backend logs cross-
reference cleanly.
