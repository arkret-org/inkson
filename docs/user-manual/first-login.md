# inkson — First identity setup

First setup is custody-first and account-first. OIDC authenticates one account;
the new DID remains an identity anchor, while device authorization lives in its
Principal Control Realm (PCR).

## 1. Authenticate the account

1. Select the Principal Server and complete discovery.
2. Sign in through coauth and obtain an Unbound Account Handoff constrained to
   the current DPoP holder and an identity-creation lease.
3. If the account is already bound, Inkson continues the existing-identity path
   instead of creating another principal.

## 2. Confirm cold custody

Inkson generates a 24-word Recovery Key locally. Write it down offline and
re-enter the complete phrase before any DID or PCR side effect. The SDK derives
separate root, recovery-proof and backup-HPKE roles; only public commitments,
stable timestamps and idempotency keys enter the resumable draft.

## 3. Prepare DID and PCR genesis before submission

The client constructs and signs all material first:

1. WebVH entry 0 contains the identity root and no account/device business
   authority.
2. `ak.realm.create` creates the PCR and commits a founding device descriptor.
3. `ak.device.authorize` uses `authorization_binding_kind=root_anchored`, names
   the principal DID as `authorized_by`, and carries the founding device's
   possession signature.
4. The root creation proof also binds the initial Standard-session request and
   DPoP thumbprint.

The first device is trusted because the identity root explicitly binds it and
the device proves possession of the corresponding private key. No other device
or administrator approval is required.

## 4. Submit once and finish

Inkson submits the identity-creation registration through the Bound handoff.
The Account Authority verifies the account/holder/lease/root proof, publishes
the DID operation, relays the exact two-Event PCR unit and returns:

- an account binding receipt;
- a PCR genesis receipt binding both accepted Events and the founding device;
- an initial sender-constrained Standard session grant.

Only after all three validate does Inkson persist the session and enable normal
business writes.

## 5. Interrupted setup and destroyed device

Response loss replays the same canonical request. A restart asks for the same
Recovery Key and re-derives the public draft. If the original device is
physically destroyed after DID creation but before PCR acceptance, a new device
can authenticate the same account and use the Recovery Key to resume the
create-once path or complete a root re-anchor; the destroyed device is never
required to approve its replacement.

## Verification checklist

- DID state contains no account authority or device directory.
- PCR genesis is exactly the ordered create/authorize pair.
- Root, founding-device PoP, handoff holder and initial DPoP bindings all match.
- Receipt/grant validation completes before the handoff credential is cleared.
- Serialized local state contains no Recovery Key or derived private seed.
