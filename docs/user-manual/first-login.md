# inkson — First Login

> What happens between launching inkson for the first time and reaching the
> dashboard. References `crypto-media/device-lifecycle.md` §1-§3 and the
> coauth OIDC sign-in strand.

The first-login strand has three legs:

1. **Discover the Principal Server** — base URL + capabilities.
2. **Sign in via coauth OIDC** — the only place where account credentials
   are entered.
3. **Bootstrap the local device** — generate a signing key, publish
   `ck.device.authorize`, run optional verification.

The /onboarding view in inkson owns leg 3 and adds an optional recovery
policy step. Legs 1 + 2 belong to coauth.

---

## 1. Discover the Principal Server

On first launch inkson shows the **Server picker** in the top bar.

<!-- TODO(screenshot): server-picker-empty.png -->

1. Click **Server / Switch**.
2. Choose an existing entry or **Add server**.
3. Enter the soland base URL (for local testing: `https://local.host`).
4. inkson pulls `/.well-known/arkret-discovery` and renders the result.

If discovery fails you will see an error toast carrying the
`x-arkret-request-id` from soland. Capture that header before opening
a bug — see [`faq-troubleshooting.md`](../faq-troubleshooting.md#discovery-fails).

<!-- TODO(screenshot): discovery-result.png -->

---

## 2. Sign in via coauth

1. Click **Login** in the top bar (or visit `/login`).
2. inkson redirects to coauth's OIDC page in the same window.
3. Complete the sign-in (passkey / password / TOTP — coauth owns the
   factor set).
4. coauth redirects back to inkson with an OIDC code; inkson exchanges it
   for an access token and persists the bundle in `LocalStateStore`.

<!-- TODO(screenshot): coauth-oidc-page.png -->
<!-- TODO(screenshot): coauth-callback-success.png -->

If the bundle is missing the `ck.session.grant` claim, the device-bootstrap
step (next) will fail closed. Re-attempt the login.

---

## 3. Bootstrap the local device

Open `/onboarding`. The four-step stepper walks through:

### Step 1 — DID method

`did:webvh` is the default. `did:web` is **test-only**; `did:plc` /
`did:keri` are placeholders and cannot be selected.

<!-- TODO(screenshot): onboarding-step-did.png -->

### Step 2 — Handle binding

Pick a local handle. Handles are a human-readable entry point and reverse-
resolve to your DID; they are **not** a permission key.

<!-- TODO(screenshot): onboarding-step-handle.png -->

### Step 3 — Device key

inkson generates a local ed25519 signing key, hands it to the keychain
(desktop) or IndexedDB (web), and publishes
`ck.device.authorize`. You may then run a `KeyVerification` round against
a previously enrolled device to elevate trust.

<!-- TODO(screenshot): onboarding-step-device.png -->
<!-- TODO(screenshot): device-verification-qr.png -->

### Step 4 — Recovery policy

Pick an initial recovery preference:

- **Encrypted Cloud Vault** — Argon2id passphrase + XChaCha20-Poly1305
  upload. Unlocks encrypted backup material; requires you to remember a
  passphrase.
- **Social Recovery (SSS)** — split a recovery secret across N guardians.
- **Recovery Key** — display-once high-entropy recovery phrase.

The choice is persisted to `localState` under `onboarding.recovery_choice`.
Publishing the active `ck.schema.recovery_policy.v1` remains a separate
server-backed follow-up.

<!-- TODO(screenshot): onboarding-step-recovery.png -->

You can change the policy later under **Settings → Recovery**. The
`FirstBackupGate` component blocks you from leaving the inception strand
until at least one `backup_class=did_recovery` envelope is published —
this is non-negotiable.

---

## 4. Verification

After step 4, the dashboard becomes reachable. Confirm:

- [ ] Top bar shows your handle + the verified pill.
- [ ] Settings → Devices lists exactly one device (this one).
- [ ] Settings → Recovery shows your selected policy as **active**.
- [ ] The notification preferences toggle defaults to **wakeup-only**.

If any step fails, every error toast carries the soland `request_id`.
Copy it before retrying.

<!-- TODO(screenshot): dashboard-verified-state.png -->
