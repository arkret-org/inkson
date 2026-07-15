# inkson — Recovery strand

Recovery uses the offline 24-word Recovery Key (or a policy-approved guardian
path deriving the same role-separated material). A login factor proves account
authentication; it does not authorize a fresh device or unlock encrypted
history by itself.

## 1. Start on a fresh device

1. Sign in to the already-bound principal.
2. Inkson requests a recovery session with the principal, fresh device and
   trust domain. It does not self-report the authority model or generation.
3. The server snapshots the accepted policy and derives either Model A
   (cross-signing) or Model B (external enrollment authority).
4. Enter the Recovery Key locally. Inkson derives independent recovery-proof
   and backup-HPKE keys and verifies them against the accepted policy.

The phrase is never uploaded. Losing it removes this recovery lane unless an
approved guardian alternative exists.

## 2. Prove recovery and authorize the device

The signed proof transcript binds the session id, principal, requesting device,
policy, challenge, expiry, `identity_model`, and authoritative
`model_generation_ref`.

Completion is model-specific:

- Model A references the accepted device authorization and device-list update.
- Model B references the accepted device authorization, `ak.device.reanchor`,
  and the re-anchor batch receipt.

Inkson rejects mixed or incomplete shapes. Model B also fails while the device
generation is conflicted or the registry/frontier snapshot no longer matches.

## 3. Restore encrypted material

After device authorization is accepted, Inkson resolves each active backup
series, validates its chain and active pointer, and opens envelopes locally with
the dedicated HPKE key. A broken chain, stale frontier, wrong principal,
wrong policy reference, or wrong recipient fails closed.

Recovery is not complete until required secret-storage and MLS material is
available on the new device. The server stores ciphertext, not the Recovery Key
or derived private keys.

## 4. Clean up immediately

Revoke devices that are lost or no longer trusted, then advance affected MLS
epochs and create replacement backups. There is no legacy 24-hour inception or
successor window: the generation fence applies as soon as the new generation is
accepted.

Revocation is not remote wipe. Assume a stolen device retains every key,
ciphertext, or plaintext it had already obtained.

## 5. Recovery Key compromise or rotation

Do not generate a new phrase and attach it to the old policy. Inkson requires a
durable staged handoff: custody confirmation, WebVH bridge/new-root entries when
an independent authority exists, re-anchor, new policy, rewrapping every active
`did_recovery`/`secret_storage`/`mls_history` series, active-pointer advance, and
finally old-key revocation.

If no independent authority can bridge a compromised recovery secret safely,
the correct outcome is a new DID, not an unsafe in-place reset.

## Recovery test checklist

- Run a complete recovery on a spare device.
- Confirm the proof transcript and completion shape match exactly one model.
- Confirm an old-generation queued write is quarantined before network send.
- Verify encrypted history can be opened from every active backup class.
- Verify lost devices are revoked and future MLS epochs exclude them.
- Record the historical exposure boundary; rotation cannot erase prior access.
