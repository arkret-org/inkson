# inkson — Recovery Strand

> How to recover Arkret Principal access and encrypted backup material when
> the device that holds your signing key is lost, broken, or revoked. Spec
> source: `identity/key-management.md` §7-§8 and
> `crypto-media/device-lifecycle.md` §15.

There are three recovery surfaces, picked at onboarding (Step 4):

| Policy | Requires | Recovery time | Threat surface |
| --- | --- | --- | --- |
| **Encrypted Cloud Vault** | Passphrase you remember | ~30 seconds | Passphrase strength (Argon2id stretched); unlocks backup material, not DID ownership by itself. |
| **Social Recovery (SSS)** | N guardians out of K, each contacted out-of-band | Minutes to days | Guardian collusion threshold. |
| **Recovery Key** | One-time high-entropy phrase you stored offline | ~10 seconds | Loss / theft of the phrase. |

You can stack policies. The recommended default is **Vault + Recovery Key**,
but device authorization is controlled by the active `recovery_policy`.

---

## 1. Encrypted Cloud Vault recovery

Use this when:

- You can install inkson on a new device.
- You remember the passphrase you set at onboarding.

### Steps

1. Install inkson on the recovery device. Sign in via coauth as usual.
2. Open **Settings → Recovery → Restore from vault**.
3. Enter the passphrase. inkson pulls the encrypted blob, runs Argon2id,
   decrypts via XChaCha20-Poly1305, then re-bootstraps the device key and
   imports the account MLS history secret when one is present.
4. After the active `recovery_policy` accepts a bound `recovery_session`
   proof, the device-authorization strand can publish `ck.device.authorize`.

Current inkson status: the restore panel re-hydrates local backup payload and
MLS account-secret material. It does not yet submit the policy proof or
`ck.device.authorize` by itself.

<!-- TODO(screenshot): settings-recovery-vault-restore.png -->

If decryption fails, the passphrase is wrong. There is no recovery for a
forgotten passphrase — fall back to SSS or the recovery key.

For encrypted history, this passphrase is the account-level trust root: anyone
who can unlock the `mls_account_secret` backup can decrypt historical
`mls_history` backups. Revoking a device does not retroactively remove a copy
of the account MLS secret, cached plaintext, or old history backups that were
already stored on that device.

---

## 2. Social Recovery (SSS)

Use this when:

- You set up guardians at onboarding.
- You can contact at least N of K guardians out-of-band.

### Steps

1. On the new device, open **Settings → Recovery → Social Recovery**.
2. inkson displays a recovery code per guardian. Send each one through a
   trusted channel (in person, signed email, established Signal thread).
3. Each guardian opens **Settings → Guardian Requests** in their inkson
   client and approves with their device signature.
4. Once N approvals reach the new device, inkson reconstructs the
   recovery secret and finishes bootstrap.

Current inkson status: guardian configuration and rehearsal timestamps are
stored locally. Server-backed share release, reconstruction, and recovery
receipt writing are still pending implementation.

<!-- TODO(screenshot): settings-social-recovery-pending.png -->
<!-- TODO(screenshot): guardian-approve-prompt.png -->

The reconstruction never leaves your device — guardians sign individual
shares, not your private key.

---

## 3. Recovery Key

Use this when:

- You stored the high-entropy phrase offline at onboarding.
- You can install inkson on a new device.

### Steps

1. Install inkson and sign in via coauth.
2. Open **Settings → Recovery → Restore from recovery key**.
3. Enter the phrase. inkson derives the master secret and
   re-bootstraps the device.

Current inkson status: the app can generate and fingerprint a recovery key.
Fresh-device restore through that key still needs policy proof and
device-authorization wiring.

<!-- TODO(screenshot): settings-recovery-key-restore.png -->

The phrase is **display-once**. If you lose it, this lane is gone — use
Vault or SSS instead, or accept that you need a fresh identity (see
[Late recovery](#5-late-recovery--cross-signing-reset)).

---

## 4. After recovery — clean up

Within 24 hours of recovery:

1. Open **Settings → Devices** on the new device.
2. **Revoke** every device you can no longer reach. Each revocation
   publishes a `ck.device.revoke` envelope, rotates future history backups,
   and removes the device from new MLS epochs.
3. Run **Cross-signing → Re-sign trusted contacts** so your peers
   register the new device as a successor.

Revocation is not a remote wipe. If the old device was stolen, compromised, or
offline before you revoked it, assume any secret or plaintext it had already
cached remains readable on that device.

<!-- TODO(screenshot): settings-devices-revoke-after-recovery.png -->

---

## 5. Late recovery / cross-signing reset

If you missed the 24-hour successor window the cross-signing chain may
have rotated past you. inkson's `late_recovery` module surfaces a
**Late recovery** banner with one-click strands for:

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
