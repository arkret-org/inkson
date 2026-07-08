# Platform key-store stub roadmap

`src/key_store.rs` currently ships three stub implementations of the
`KeyStore` trait — one per desktop OS — that compile but report
`KeyStoreError::Unsupported` on every call. They exist so call sites
can wire the platform-specific path now and light up the real
implementation later without churn.

This document tracks what each stub needs to become a real backend,
which upstream SDK changes (in `cokret-rust-sdk`) it depends on, and
the target milestone.

## Current state (excerpt from `src/key_store.rs:197-297`)

| Stub                          | Backend it will wrap                  | Lines      |
| ----------------------------- | ------------------------------------- | ---------- |
| `MacOsKeychainKeyStore`       | macOS Keychain Services               | 197–230    |
| `LinuxSecretServiceKeyStore`  | freedesktop Secret Service (libsecret) | 232–264    |
| `WindowsCredentialKeyStore`   | Windows Credential Manager (wincred)   | 266–297    |

All three implement the same `KeyStore` trait (`load_identity` /
`save_identity`); only the backend differs. The `service_name` /
`collection` / `target_name` field already stores the lookup key the
real implementation needs, so call sites can construct the right
backend today and the body will fill in later.

## macOS Keychain

- **Crate**: [`security-framework`][sf] (Apple's Security.framework
  bindings). Already a known-good choice — used by several Rust
  desktop apps in the same niche.
- **Items**: a single generic-password item per device DID, keyed by
  `(service_name, device_did)`. The seed bytes go in the password
  field; metadata in attributes.
- **Shell integration**: the host shell (Tauri / Dioxus desktop) must
  declare the appropriate Keychain entitlement; without it, every
  read prompts the user. inkson does not currently bundle a macOS
  shell, so this stub stays a stub until the desktop shell crate is
  on the roadmap.
- **SDK dependency**: the upstream `cokret-rust-sdk` does not yet
  publish a `KeyStore` trait — inkson owns the local one. Once the
  SDK trait lands, this implementation will be moved alongside it and
  this crate will re-export.
- **Target**: v1.1+ (after macOS desktop shell exists).

## Linux Secret Service (libsecret)

- **Crate**: [`secret-service`][ss] (pure-Rust DBus client) preferred
  over a direct `libsecret` FFI binding — fewer build-time native
  dependencies, identical wire protocol.
- **Items**: stored in the user's default collection (or one named by
  `LinuxSecretServiceKeyStore::collection`). Each item is labelled
  `<label_prefix>:<device_did>` so multiple inkson-like apps coexist.
- **DBus session**: the backend requires an active DBus session bus,
  which is present in any logged-in GNOME / KDE session but absent
  in headless / SSH environments. The implementation must fail fast
  with `KeyStoreError::Unsupported("linux-secret-service")` when no
  bus is reachable so callers fall back to the software default.
- **SDK dependency**: same as macOS — waits on the upstream
  `KeyStore` trait.
- **Target**: v1.1+ (highest priority of the three because Linux
  desktop is the primary current target).

## Windows Credential Vault

- **Crate**: [`windows`][wrs] (Microsoft's official `windows-rs`),
  using the `Windows::Win32::Security::Credentials` module. Avoid the
  older `winapi` crate — `windows-rs` is the going-forward path and
  is already a transitive dependency.
- **Items**: one `Generic` credential per device DID, with
  `target_name = WindowsCredentialKeyStore::target_name`. The
  credential blob holds the seed; the username field holds the
  device DID for easy `cmdkey /list` inspection.
- **Persistence**: pass `CRED_PERSIST_LOCAL_MACHINE` for per-device
  identities (survives logout) vs `CRED_PERSIST_SESSION` for
  ephemeral. The stub today doesn't expose that knob; the real
  implementation will take a `CredentialPersistence` enum parameter.
- **SDK dependency**: same as macOS / Linux.
- **Target**: v1.1+ (lowest priority — degooglified Windows users
  are a small slice of inkson's audience for now, but the work is
  small once the SDK trait exists).

## SDK trait dependency

All three stubs are blocked on the same upstream change:
`cokret-rust-sdk` currently only exposes
`PlatformKeyStoreDescriptor` / `PlatformKeyStoreKind` — descriptor
types with no trait. Once the SDK ships a real `KeyStore` trait,
inkson's local trait becomes a thin re-export and these three structs
get real bodies in a single sweep.

Until then, the stubs stay tiny on purpose: every line of stub
behaviour is a line that has to change when the SDK lands, and the
`Unsupported` error is the right signal at the call site anyway
(software-key fallback is well-tested).

[sf]: https://crates.io/crates/security-framework
[ss]: https://crates.io/crates/secret-service
[wrs]: https://crates.io/crates/windows
