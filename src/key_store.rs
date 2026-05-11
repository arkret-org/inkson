//! Round 22 (2026-05-09): pluggable per-device signing-key store.
//!
//! `LocalIdentity` (the per-device ed25519 signing key + derived `did:key`)
//! used to live entirely inside `LocalStateStore` — the seed sat in the
//! same `state.json` blob as drafts, sync cursors, and notification
//! preferences. That made the dev path simple but coupled key custody to
//! the same plaintext file every other piece of UI state lives in.
//!
//! This module introduces a [`KeyStore`] trait so the seed can be loaded
//! from a different backend (OS keychain, Secret Service, Windows
//! Credential Manager, hardware key, WebAuthn, ...) without touching any
//! call site downstream. The default backend, [`InMemoryKeyStore`], wraps
//! a `LocalStateStore` reference and round-trips the existing on-disk
//! `state.json` record — semantically identical to Round 21 behaviour, so
//! flipping the trait in is a no-op for current users.
//!
//! ## SDK gap
//!
//! contrix-rust-sdk Round 22 was scheduled to land a sibling `KeyStore`
//! trait + `InMemoryKeyStore` + `MacOsKeychainKeyStore` /
//! `LinuxSecretServiceKeyStore` / `WindowsCredentialKeyStore` stubs. As of
//! this commit the SDK still only exposes `PlatformKeyStoreDescriptor` /
//! `PlatformKeyStoreKind` (a *descriptor* type — no trait, no actual
//! key-loading surface). When the SDK trait lands, this module's
//! [`KeyStore`] will become a thin re-export and the platform stubs here
//! will be deleted.
//!
//! ## Platform stubs
//!
//! [`MacOsKeychainKeyStore`], [`LinuxSecretServiceKeyStore`], and
//! [`WindowsCredentialKeyStore`] are intentionally tiny markers right now
//! — they hold a `service_name` string and report `Unsupported` on every
//! call. They exist so the trait shape is stable: future commits can
//! light up real implementations without changing call sites.

use std::sync::{Arc, Mutex};

use crate::local_state::{LocalIdentity, LocalIdentityRecord, LocalStateStore};

/// Errors a [`KeyStore`] can surface to callers. The split between
/// `Unsupported` (platform store not wired yet) and `Backend` (the
/// platform store *is* wired but failed) is deliberate — UI callers
/// surface the former as "use software key" and the latter as a hard
/// failure.
#[derive(Debug)]
pub enum KeyStoreError {
    /// The platform store hasn't been wired up on this build target. UI
    /// callers should fall back to [`InMemoryKeyStore`] (or whatever
    /// software default they accept).
    Unsupported(&'static str),
    /// The backend was reachable but failed (corrupt entry, permission
    /// denied, biometric prompt cancelled, etc.).
    Backend(String),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(name) => write!(
                f,
                "key store backend `{name}` is not supported on this platform"
            ),
            Self::Backend(msg) => write!(f, "key store backend error: {msg}"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

/// Pluggable signing-key store. Loaders are keyed by an opaque DID-style
/// string (the `device_did` for now); future revisions may key by
/// arbitrary string so we can store multiple identities per device.
///
/// All methods take `&self` so a [`KeyStore`] can be cheaply cloned /
/// shared via `Arc<dyn KeyStore>`. Implementors with mutable state should
/// guard it with their own lock (e.g. [`InMemoryKeyStore`] uses a
/// `Mutex`).
pub trait KeyStore: Send + Sync {
    /// Read the persisted identity record for `device_did`. `None` means
    /// "no record yet" — callers typically follow up with
    /// [`Self::save_identity`] after generating a fresh seed.
    fn load_identity(&self, device_did: &str)
    -> Result<Option<LocalIdentityRecord>, KeyStoreError>;

    /// Persist (or overwrite) the identity record for the device. The
    /// `device_did` argument is redundant with `record.did_key` but lets
    /// the backend index without parsing the record.
    fn save_identity(
        &self,
        device_did: &str,
        record: &LocalIdentityRecord,
    ) -> Result<(), KeyStoreError>;

    /// Optional: return the *primary* identity without a known
    /// `device_did`. Used at boot to find the local device's identity
    /// before any UI surface has resolved a DID. Default impl returns
    /// `None` (caller must know the DID up front).
    fn primary_identity(&self) -> Result<Option<LocalIdentityRecord>, KeyStoreError> {
        Ok(None)
    }

    /// Convenience: load the identity record and convert to a
    /// [`LocalIdentity`], returning `None` when the record is absent or
    /// `Err` when it's corrupt. Default implementation runs through
    /// [`Self::load_identity`].
    fn load_local_identity(
        &self,
        device_did: &str,
    ) -> Result<Option<LocalIdentity>, KeyStoreError> {
        let Some(record) = self.load_identity(device_did)? else {
            return Ok(None);
        };
        match LocalIdentity::from_record(&record) {
            Ok(identity) => Ok(Some(identity)),
            Err(err) => Err(KeyStoreError::Backend(format!(
                "identity record corrupt: {err}"
            ))),
        }
    }
}

/// Default in-memory key store. Wraps a [`LocalStateStore`] reference so
/// the existing on-disk `state.json` record is the source of truth — i.e.
/// flipping yougen onto the [`KeyStore`] trait without changing the
/// backend is a no-op.
///
/// The store is `Clone`-able (cheap `Arc<Mutex<...>>` clone) so multiple
/// UI surfaces can hold their own handle without fighting over a single
/// `&mut`.
#[derive(Clone)]
pub struct InMemoryKeyStore {
    inner: Arc<Mutex<LocalStateStore>>,
}

impl InMemoryKeyStore {
    /// Wrap an existing [`LocalStateStore`]. The store is taken by value
    /// so the [`InMemoryKeyStore`] owns one canonical copy that all
    /// clones share through the [`Arc`].
    pub fn new(store: LocalStateStore) -> Self {
        Self {
            inner: Arc::new(Mutex::new(store)),
        }
    }

    /// Build an [`InMemoryKeyStore`] backed by a fresh default
    /// [`LocalStateStore`]. Useful for tests that don't care about the
    /// other state-store fields.
    ///
    /// NOTE: on the desktop target this resolves to the real
    /// `state.json` path so tests sharing this constructor can step on
    /// each other; prefer
    /// `InMemoryKeyStore::new(LocalStateStore::with_path(tmp))` in tests.
    pub fn with_default_store() -> Self {
        Self::new(LocalStateStore::default())
    }

    /// Lazy-generate and persist the identity if missing. This is the
    /// trait-aware mirror of `LocalStateStore::ensure_local_identity` —
    /// production UI should prefer this so swapping the backend later
    /// (Keychain / Secret Service / etc.) is a one-line change.
    pub fn ensure_identity(&self) -> Result<LocalIdentity, KeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| KeyStoreError::Backend(format!("state store lock poisoned: {err}")))?;
        guard
            .ensure_local_identity()
            .map_err(|err| KeyStoreError::Backend(format!("ensure local identity: {err}")))
    }
}

impl KeyStore for InMemoryKeyStore {
    fn load_identity(
        &self,
        _device_did: &str,
    ) -> Result<Option<LocalIdentityRecord>, KeyStoreError> {
        // The default in-memory backend stores at most one identity per
        // device — `device_did` is logged for forward compatibility but
        // not used as a lookup key.
        let guard = self
            .inner
            .lock()
            .map_err(|err| KeyStoreError::Backend(format!("state store lock poisoned: {err}")))?;
        Ok(guard.local_identity_record())
    }

    fn save_identity(
        &self,
        _device_did: &str,
        record: &LocalIdentityRecord,
    ) -> Result<(), KeyStoreError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|err| KeyStoreError::Backend(format!("state store lock poisoned: {err}")))?;
        guard.set_local_identity_record(Some(record.clone()));
        Ok(())
    }

    fn primary_identity(&self) -> Result<Option<LocalIdentityRecord>, KeyStoreError> {
        // Same single-identity model — the "primary" is whatever the
        // wrapped store holds.
        self.load_identity("")
    }
}

/// Stub for macOS Keychain backend. Holds the service name a future
/// implementation will look up via the `security-framework` crate. All
/// methods report [`KeyStoreError::Unsupported`] today; the type exists
/// so call sites can wire the platform-specific path now and light up the
/// implementation later without churn.
#[derive(Clone, Debug)]
pub struct MacOsKeychainKeyStore {
    pub service_name: String,
}

impl MacOsKeychainKeyStore {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

impl KeyStore for MacOsKeychainKeyStore {
    fn load_identity(
        &self,
        _device_did: &str,
    ) -> Result<Option<LocalIdentityRecord>, KeyStoreError> {
        Err(KeyStoreError::Unsupported("macos-keychain"))
    }

    fn save_identity(
        &self,
        _device_did: &str,
        _record: &LocalIdentityRecord,
    ) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unsupported("macos-keychain"))
    }
}

/// Stub for the freedesktop Secret Service (`secret-service` /
/// `libsecret`) backend. Mirrors [`MacOsKeychainKeyStore`].
#[derive(Clone, Debug)]
pub struct LinuxSecretServiceKeyStore {
    pub collection: String,
    pub label_prefix: String,
}

impl LinuxSecretServiceKeyStore {
    pub fn new(collection: impl Into<String>, label_prefix: impl Into<String>) -> Self {
        Self {
            collection: collection.into(),
            label_prefix: label_prefix.into(),
        }
    }
}

impl KeyStore for LinuxSecretServiceKeyStore {
    fn load_identity(
        &self,
        _device_did: &str,
    ) -> Result<Option<LocalIdentityRecord>, KeyStoreError> {
        Err(KeyStoreError::Unsupported("linux-secret-service"))
    }

    fn save_identity(
        &self,
        _device_did: &str,
        _record: &LocalIdentityRecord,
    ) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unsupported("linux-secret-service"))
    }
}

/// Stub for the Windows Credential Manager (`wincred`) backend. Mirrors
/// [`MacOsKeychainKeyStore`]. The service name is what shows up in
/// `cmdkey /list`.
#[derive(Clone, Debug)]
pub struct WindowsCredentialKeyStore {
    pub target_name: String,
}

impl WindowsCredentialKeyStore {
    pub fn new(target_name: impl Into<String>) -> Self {
        Self {
            target_name: target_name.into(),
        }
    }
}

impl KeyStore for WindowsCredentialKeyStore {
    fn load_identity(
        &self,
        _device_did: &str,
    ) -> Result<Option<LocalIdentityRecord>, KeyStoreError> {
        Err(KeyStoreError::Unsupported("windows-credential"))
    }

    fn save_identity(
        &self,
        _device_did: &str,
        _record: &LocalIdentityRecord,
    ) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Unsupported("windows-credential"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Build a fresh isolated state-store path under `temp_dir` so tests
    /// don't pollute (or read) the developer's actual `state.json`.
    fn temp_state_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("yougen-keystore-{name}-{stamp}.json"))
    }

    fn isolated_store() -> InMemoryKeyStore {
        InMemoryKeyStore::new(LocalStateStore::with_path(temp_state_path("kstore")))
    }

    #[test]
    fn in_memory_key_store_round_trips_identity_via_state_store() {
        let store = isolated_store();
        // Fresh store — no identity yet.
        assert!(store.load_identity("did:key:zUNKNOWN").unwrap().is_none());

        // ensure_identity generates + persists.
        let identity = store.ensure_identity().expect("generate identity");
        assert!(identity.device_did.starts_with("did:key:z"));

        // Reading via the trait surface returns the same record.
        let record = store
            .load_identity(&identity.device_did)
            .unwrap()
            .expect("identity present");
        assert_eq!(record.did_key, identity.device_did);

        // load_local_identity matches.
        let loaded = store
            .load_local_identity(&identity.device_did)
            .unwrap()
            .expect("identity loads");
        assert_eq!(loaded.device_did, identity.device_did);
        assert_eq!(
            loaded.signing_key.to_bytes(),
            identity.signing_key.to_bytes()
        );
    }

    #[test]
    fn in_memory_key_store_save_overrides_existing_record() {
        let store = isolated_store();
        let id_one = LocalIdentity::generate().unwrap();
        let id_two = LocalIdentity::generate().unwrap();

        store
            .save_identity(&id_one.device_did, &id_one.to_record())
            .unwrap();
        let loaded = store
            .load_local_identity(&id_one.device_did)
            .unwrap()
            .expect("first identity");
        assert_eq!(loaded.device_did, id_one.device_did);

        store
            .save_identity(&id_two.device_did, &id_two.to_record())
            .unwrap();
        let loaded = store
            .load_local_identity(&id_two.device_did)
            .unwrap()
            .expect("second identity");
        assert_eq!(loaded.device_did, id_two.device_did);
    }

    #[test]
    fn macos_keychain_stub_reports_unsupported() {
        let store = MacOsKeychainKeyStore::new("yougen.test");
        let err = store.load_identity("did:key:zX").unwrap_err();
        assert!(matches!(err, KeyStoreError::Unsupported("macos-keychain")));
    }

    #[test]
    fn linux_secret_service_stub_reports_unsupported() {
        let store = LinuxSecretServiceKeyStore::new("default", "yougen.identity");
        let err = store.load_identity("did:key:zX").unwrap_err();
        assert!(matches!(
            err,
            KeyStoreError::Unsupported("linux-secret-service")
        ));
    }

    #[test]
    fn windows_credential_stub_reports_unsupported() {
        let store = WindowsCredentialKeyStore::new("yougen/test");
        let err = store
            .save_identity(
                "did:key:zX",
                &LocalIdentity::generate().unwrap().to_record(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            KeyStoreError::Unsupported("windows-credential")
        ));
    }

    #[test]
    fn key_store_dyn_dispatch_works() {
        // A function that only knows the trait can drive the in-memory
        // backend the same way it would drive a future Keychain backend.
        fn ensure_via_trait(store: &dyn KeyStore) -> bool {
            store
                .load_identity("did:key:zANY")
                .map(|opt| opt.is_some())
                .unwrap_or(false)
        }
        let store = isolated_store();
        assert!(!ensure_via_trait(&store));
        store.ensure_identity().unwrap();
        assert!(ensure_via_trait(&store));
    }
}
