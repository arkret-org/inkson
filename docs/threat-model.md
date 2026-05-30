# yougen Threat Model

## Scope

This model covers the yougen client surfaces in the local 1.0 milestone:
desktop and web. Mobile host-bridge references exist for a future phase, but
iOS and Android artifacts are not built or shipped by this plan. Server
authorization, federation, and push gateway internals are owned by soland,
coauth, and chime, but yougen is responsible for preserving their security
properties at the client boundary.

## Assets

- Principal session tokens and refresh state.
- DPoP private keys and proof material.
- Local device identity and cross-signing state.
- Local encryption keys and secure-store handles.
- Recovery keys and recovery-flow state.
- Push tokens and push registration identifiers.
- Cached plaintext message content and attachments.

## Trust boundaries

- Browser or desktop renderer to local storage.
- yougen to soland HTTP API.
- yougen to coauth OIDC and grant endpoints.
- yougen to chime push registration path.
- Local OS secure storage boundary.
- Clipboard, filesystem import/export, and crash/log output.

## Local key storage risks

Threats:

- A renderer XSS or compromised dependency reads IndexedDB/local storage.
- Desktop filesystem compromise reads fallback state.
- A future mobile host forgets to install the secure-store bridge and falls
  back to in-memory secret storage.
- Logs accidentally include DPoP proofs, key identifiers, or recovery data.

Controls:

- Prefer OS secure storage for long-lived keys.
- Keep browser storage scoped and avoid plaintext secret duplication.
- Keep recovery material out of logs, UI telemetry, and crash reports.
- Keep iOS/Android artifacts out of the local milestone until host secure-store
  bridges are owned by a platform shell.

Open phase-3 items:

- IndexedDB key-store hardening is tracked in `_yougen_todos.md` §20.
- Android Keystore and iOS Keychain package work is out of the desktop/web
  local milestone and remains behind the mobile scope gate in §5-§8.

## Push privacy risks

Threats:

- Push payload reveals message content, actor identity, realm name, or recovery
  state to a platform push provider.
- Device tokens leak through logs or diagnostics.
- A stale token continues receiving wakeups after device revocation.

Controls:

- Push payloads are wakeup-only.
- Token values are treated as secrets.
- Device revocation must clear local push registration state.
- Gateway credentials stay server-side.

Controls now in place:

- WebPush uses the browser Push API, and native FCM/APNs providers accept only
  host-supplied or local-env injected real tokens.
- chime registration loads the persisted coauth grant, validates principal
  server and device binding, mints introspection proof headers, and fails
  closed when grant material is missing or mismatched.

## Recovery flow risks

Threats:

- A malicious or stale recovery path restores keys onto the wrong device.
- Partial bootstrap state is accepted as complete.
- Late-recovered content appears without user-visible context.
- The recovery passphrase becomes the effective protection for all
  account-level encrypted-history backups.

Controls:

- Recovery should require explicit user action and device verification.
- Partial snapshot/bootstrap state must fail clearly until chunked import is
  fully implemented.
- Late-recovery banners must remain visible when older content decrypts after
  arrival.
- Recovery passphrases are stretched locally with Argon2id before any
  encrypted vault or account-MLS-secret backup is opened.
- Web builds run the live OpenMLS snapshot/decrypt path through WebAssembly,
  but browser storage remains weaker than native OS keychain storage.

Open phase-3 items:

- Partial bootstrap behavior is tracked in §13.
- OIDC callback and passkey completion is tracked in §18.

## MLS history recovery and account secret

The desktop and web clients now use the same live OpenMLS path for persisted
MLS snapshots. WebAssembly builds no longer treat MLS history as an
unsupported target, but they still store long-lived local material in browser
storage rather than an OS keychain.

Encrypted realm / kanban history recovery uses one account-level MLS snapshot
secret. The secret is wrapped into a `secret_storage` key-backup item with
`item_type = "mls_account_secret"`; the wrapping key is derived from the
user's recovery passphrase with Argon2id and XChaCha20-Poly1305. A fresh device
can fetch that server-side ciphertext, unwrap it locally after the user enters
the passphrase, and then decrypt every `mls_history` backup sealed with the
account secret.

Security consequences:

- A weak or leaked recovery passphrase can expose all historical encrypted MLS
  history backups protected by the account secret.
- Device revocation does not currently erase an account secret already copied
  onto the revoked device. The revoked device may retain access to history it
  already stored or can still fetch through valid server credentials.
- The local 1.0 design intentionally uses one account secret rather than a
  per-realm secret. This keeps backup and restore simple, but compromise of
  the account secret has account-wide impact.

Required follow-up before production hardening: either add account-secret
versioning and rotation on device revoke, or keep the above limitation visible
in product UI and release notes.

## Supply-chain and release risks

Threats:

- A web image is built from an unscanned dependency set.
- A local artifact is mistaken for a signed/notarized public release.
- A workflow pushes an image or publishes a tag unintentionally.

Controls:

- Docker workflow is local-build-only and uploads scan/SBOM evidence.
- Signing dry-run evidence records that remote submit, timestamping, and
  transparency-log upload are disabled.
- Release checklist explicitly forbids tags, registry pushes, and crates.io
  publication for this local phase.

## MLS-Exporter SFrame key derivation flow

yougen's E2EE call layer derives SFrame keying material from an MLS group
via the MLS Exporter interface. This section is the canonical reference
for the derivation chain and the threat-model decisions behind it.

### Derivation chain

```text
[MLS group state]
    │  (epoch_authenticator, group_context)
    ▼
[MLS Exporter API]
    │  - label = "cx-rtc-frame-key/v1"
    │  - context = (empty bytes; the call_id is mixed in via group_context)
    │  - length = 19
    │  - KDF.Nh = 32 (SHA-256-based KDF)
    ▼
[exporter_secret: 19 bytes]
    │
    ▼
[SFrame keying material]
    │  per SFrame draft-ietf-sframe-enc:
    │  - SFrame_KEK = HKDF-Expand-Label(exporter_secret, "SFrame KEK", "", 32)
    │  - SFrame_SALT = HKDF-Expand-Label(exporter_secret, "SFrame Salt", "", 12)
    │  - per-frame: nonce = SFrame_SALT XOR counter_padded
    ▼
[encrypted media frame]
    AEAD(SFrame_KEK, nonce, plaintext_frame, aad)
```

The 19-byte exporter length is the spec-mandated value for SFrame v1 over
MLS. The label `"cx-rtc-frame-key/v1"` namespaces this derivation away
from any other MLS exporter use within the same group (e.g. file-transfer
key derivation, which uses a different label).

### Threat model rationale

The derivation chain is deliberately structured so that:

1. **No backend party can derive the SFrame key.** soland, floria, and
   the media SFU never see the MLS group state. The exporter API runs
   exclusively inside yougen on each participant's device.

2. **Per-epoch key rotation is automatic.** Every MLS epoch advance
   (member add/remove, re-keying) produces a new `exporter_secret`. The
   SFrame key follows; in-flight frames in the old epoch are flushed at
   the SFrame layer and decoders reject mixed-epoch frames.

3. **The label is versioned (`/v1`).** A future SFrame spec or label
   rotation can be introduced without re-deriving existing keys; the
   new label produces a disjoint exporter output.

4. **Backend cloud key escrow is explicitly rejected.** A common
   "convenience" anti-pattern is to have the SFU or the call control
   plane hold a copy of the SFrame key for server-side recording or
   transcoding. yougen refuses this on threat-model grounds:
   - If the SFU holds the key, it can decrypt every frame — the E2EE
     promise reduces to ESEE (encryption *to* the SFU).
   - If a "trusted recording service" holds the key, the recording
     service becomes a high-value target that, if compromised, leaks
     all past calls.
   - Recording IS supported (via the participant-facilitated SFrame key
     hand-off to a recording bot that joins as a participant), but the
     hand-off is an explicit, audited, in-band consent step — not a
     cloud-side escrow.

5. **The error `e2ee_key_source_unauthorised`** (soland-side; surfaced
   to clients) fires when the backend observes any attempt to source
   the SFrame key from outside the MLS-Exporter derivation. This is a
   hard reject on the call-control wire — backend providers that fail
   this check are blocked from the call.

### Out-of-scope (deferred)

- Cross-epoch frame replay protection is delegated to the SFrame
  counter; MLS epoch transitions do not re-key SFrame counter space and
  rely on the AEAD nonce structure for replay defense.
- Key compromise impersonation (KCI) of a single participant is handled
  at the MLS layer; SFrame inherits MLS's KCI posture and adds no
  further mitigation.
- Post-quantum migration: when MLS gains a PQ KEM, yougen will follow.
  The exporter API and SFrame layer are unchanged by that migration.
