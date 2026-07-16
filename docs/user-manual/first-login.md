# inkson — First identity setup

The first identity setup is custody-first. Signing in and creating a principal
identity are separate operations: a session is always bound to an already
verified principal DID and cannot invent one from a handle or OIDC subject.

## 1. Discover and sign in

1. Select the Principal Server and complete discovery.
2. Sign in through coauth.
3. Inkson verifies that the returned session grant contains the exact bound
   `principal_id` and device binding. A missing principal binding fails closed.

If the account has no identity yet, Inkson first asks whether to create a new
identity or link an existing DID. An existing DID must be approved by a device
or DID wallet that already controls it; entering the identifier alone is never
enough. Inkson disables that option when the Account Authority does not
advertise a compatible approval path.

## 2. Confirm cold custody

Before WebVH entry 0 exists, Inkson generates a 24-word Recovery Key locally.
Write it down offline and re-enter the complete phrase. No policy, backup, DID
entry, or ordinary local secret containing the words is written before this
check.

The SDK derives separate keys for the WebVH root, recovery proof, and backup
HPKE recipient. Inkson persists only their public commitments and stable
idempotency keys. If the app restarts, present the same Recovery Key to resume;
Inkson re-derives and compares the public draft.

## 3. Publish entry 0 and bootstrap the PCR

After custody confirmation:

1. Publish the root-signed principal WebVH entry 0. It delegates device
   enrollment but contains no ownerless principal verification key.
2. Atomically submit the two-slot PCR bootstrap unit:
   root-signed `ak.realm.create`, followed by enrollment-authority-signed
   `ak.device.authorize`.
3. Managed Agent PCR creation stays on its controller-delegated path and never
   uses the `did_inception` exception.

The root seed exists only for this explicit cold-signing ceremony and is then
cleared from the online buffer. It is not the device signing key.

## 4. Satisfy the recovery-material gate

Inkson publishes the signed recovery policy and the first recoverable
`did_recovery` envelope. Ordinary durable writes remain blocked until both are
accepted and the backup references the active policy version.

Only after acceptance does Inkson store public local metadata (fingerprint,
accepted time, and HPKE public multikey) and clear the displayed words.

## 5. Verify the result

- The PCR exists with `mls_rfc9420` and both encryption floors set to
  `e2ee_required`.
- Exactly one first device authorization is accepted in the bootstrap batch.
- Settings → Recovery reports accepted recovery material.
- The Recovery Key plaintext is no longer present in device state.
- If setup is interrupted, resuming uses the same draft and operation ids;
  Inkson does not mint a second identity silently.

Direct Recovery Key replacement is disabled after setup. Rotation requires the
durable staged handoff, complete backup-series rewrapping, pointer advance, and
only then old-key revocation.
