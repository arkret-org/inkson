# inkson — Recovery strand

Recovery uses the offline 24-word Recovery Key. Account authentication proves
which account is continuing the flow; the Recovery Key proves control of the
identity root, and the replacement device separately proves possession of its
own signing key.

## 1. Start on a fresh device

1. Sign in to the already-bound account and retain the Bound Account Handoff.
2. Inkson requests a recovery session for the principal, replacement device and
   trust domain. The server snapshots the current DID/PCR generation, accepted
   Seal frontier and recovery policy.
3. Enter the Recovery Key locally. Inkson derives independent identity-root,
   recovery-proof and backup-HPKE keys and verifies their public commitments.

The words are never uploaded or persisted in normal client state.

## 2. Re-anchor and authorize the replacement device

Inkson prepares the next WebVH root entry and an atomic PCR unit containing
`ak.device.reanchor` plus replacement `ak.device.authorize`. The root signs the
re-anchor; the replacement device signs its own possession transcript and Event.

The coordinator accepts the unit only if the DID head, PCR registry head,
accepted Seal frontier, previous generation and all payload digests still match
the recovery snapshot. Its terminal receipt binds the resulting DID version,
new active generation and accepted device.

## 3. Restore encrypted material

Inkson resolves every active backup series, validates its chain and current
generation binding, and opens envelopes locally with the dedicated HPKE key. A
broken chain, stale frontier, wrong principal/policy/recipient or incomplete
active-series pointer fails closed.

## 4. Finish the account session

The still-live Bound Account Handoff, its DPoP holder key, the terminal recovery
receipt and the coordinator completion attestation are submitted together to
the Account Authority. When every binding matches, it directly issues a
Standard grant and atomically consumes the handoff. There is no temporary
recovery grant, second OIDC exchange, device approval or administrator approval.

## 5. Security boundary

Revoke lost devices, advance affected MLS epochs and publish replacement
backups immediately. Revocation is not remote wipe: assume a stolen device keeps
every key or plaintext it had already obtained. Recovery Key rotation is a
checkpointed policy/backup migration and cannot erase historical exposure.

## Recovery test checklist

- Complete root recovery on a fresh device with no surviving old device.
- Tamper each DID/PCR/frontier/generation/device/DPoP binding and verify failure.
- Verify encrypted history opens from every required active backup class.
- Verify completion returns one Standard grant and consumes the Bound handoff.
- Verify response-loss replay is byte-identical and creates no second grant.
