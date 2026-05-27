# yougen — Recovery Flow

> How to recover account access when the device that holds your signing key
> is lost, broken, or revoked. Spec source: `crypto-media/device-lifecycle.md`
> §10-§13.

There are three recovery surfaces, picked at onboarding (Step 4):

| Policy | Requires | Recovery time | Threat surface |
| --- | --- | --- | --- |
| **Encrypted Cloud Vault** | Passphrase you remember | ~30 seconds | Passphrase strength (Argon2id stretched). |
| **Social Recovery (SSS)** | N guardians out of K, each contacted out-of-band | Minutes to days | Guardian collusion threshold. |
| **Recovery Key** | One-time 24-word phrase you stored offline | ~10 seconds | Loss / theft of the phrase. |

You can stack policies. The recommended default is **Vault + Recovery Key**.

---

## 1. Encrypted Cloud Vault recovery

Use this when:

- You can install yougen on a new device.
- You remember the passphrase you set at onboarding.

### Steps

1. Install yougen on the recovery device. Sign in via coauth as usual.
2. Open **Settings → Recovery → Restore from vault**.
3. Enter the passphrase. yougen pulls the encrypted blob, runs Argon2id,
   decrypts via XChaCha20-Poly1305, then re-bootstraps the device key.
4. The new device automatically publishes a `cx.device.authorize` envelope
   with `successor_of` pointing at the recovered identity.

<!-- TODO(screenshot): settings-recovery-vault-restore.png -->

If decryption fails, the passphrase is wrong. There is no recovery for a
forgotten passphrase — fall back to SSS or the recovery key.

---

## 2. Social Recovery (SSS)

Use this when:

- You set up guardians at onboarding.
- You can contact at least N of K guardians out-of-band.

### Steps

1. On the new device, open **Settings → Recovery → Social Recovery**.
2. yougen displays a recovery code per guardian. Send each one through a
   trusted channel (in person, signed email, established Signal thread).
3. Each guardian opens **Settings → Guardian Requests** in their yougen
   client and approves with their device signature.
4. Once N approvals reach the new device, yougen reconstructs the
   recovery secret and finishes bootstrap.

<!-- TODO(screenshot): settings-social-recovery-pending.png -->
<!-- TODO(screenshot): guardian-approve-prompt.png -->

The reconstruction never leaves your device — guardians sign individual
shares, not your private key.

---

## 3. Recovery Key

Use this when:

- You stored the 24-word phrase offline at onboarding.
- You can install yougen on a new device.

### Steps

1. Install yougen and sign in via coauth.
2. Open **Settings → Recovery → Restore from recovery key**.
3. Enter the 24-word phrase. yougen derives the master secret and
   re-bootstraps the device.

<!-- TODO(screenshot): settings-recovery-key-restore.png -->

The phrase is **display-once**. If you lose it, this lane is gone — use
Vault or SSS instead, or accept that you need a fresh identity (see
[Late recovery](#5-late-recovery--cross-signing-reset)).

---

## 4. After recovery — clean up

Within 24 hours of recovery:

1. Open **Settings → Devices** on the new device.
2. **Revoke** every device you can no longer reach. Each revocation
   publishes a `cx.device.revoke` envelope.
3. Run **Cross-signing → Re-sign trusted contacts** so your peers
   register the new device as a successor.

<!-- TODO(screenshot): settings-devices-revoke-after-recovery.png -->

---

## 5. Late recovery / cross-signing reset

If you missed the 24-hour successor window the cross-signing chain may
have rotated past you. yougen's `late_recovery` module surfaces a
**Late recovery** banner with one-click flows for:

- **Restart cross-signing** — publishes a fresh CSR with a `reset_reason`.
- **Re-verify contacts** — prompts each peer to confirm the new key.

See `src/late_recovery.rs` for the underlying state machine.

<!-- TODO(screenshot): late-recovery-banner.png -->

---

## Recovery test checklist

Before relying on a recovery policy in production:

- [ ] Run a full recovery on a spare device. Don't trust an untested vault.
- [ ] Verify the recovered device shows up under **Settings → Devices**
      on a peer's client.
- [ ] Send a test message; confirm the receiver sees a clean
      `NeedsVerificationBadge` clear-out within one round of
      re-verification.
