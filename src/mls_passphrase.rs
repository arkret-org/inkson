//! Per-Space MLS snapshot passphrase store.
//!
//! chat.rs (encrypt path) and timeline.rs (decrypt-success audit emitter)
//! need to agree on the passphrase used to seal a Space's MLS snapshot.
//! Without a shared store, encryption would use one passphrase and the
//! decrypt-on-render emitter would either use a different one or fall
//! back to the empty default — either way, the `cx.audit.accessed` hook
//! never fires.
//!
//! F-MLS-PASS-PERSIST-1 (2026-05-19): the store stays in-memory by
//! default — the session-scoped behaviour the original prose argued
//! for — but gains an opt-in path that wraps the passphrase via
//! [`SecureKeyStore`] (OS keychain on native, IndexedDB-backed
//! `wrap_secret` on wasm) so a paired-device deployment can silent-
//! unlock the MLS state on app startup instead of forcing the user to
//! re-enter the passphrase every launch. The Settings UI exposes a
//! per-Space toggle; when persistence is OFF this module behaves
//! exactly as before.

use std::collections::HashMap;

use crate::secure_key_store::{SecureKeyStore, SecureKeyStoreError};

/// In-memory per-Space MLS passphrase store, lifetimed to the current
/// app session. Cleared on refresh; the user provides the passphrase
/// again from the chat panel's MLS passphrase input.
#[derive(Clone, Debug, Default)]
pub struct MlsPassphraseStore {
    by_space: HashMap<String, String>,
}

impl MlsPassphraseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up the passphrase for a Space. Returns `None` when the
    /// user has not entered one this session.
    pub fn get(&self, space_id: &str) -> Option<&str> {
        self.by_space.get(space_id).map(String::as_str)
    }

    /// Record / replace the passphrase for a Space. Empty strings are
    /// stored verbatim — callers that want "no passphrase set" semantics
    /// should call `clear` instead so `get` returns `None`.
    pub fn set(&mut self, space_id: impl Into<String>, passphrase: impl Into<String>) {
        self.by_space.insert(space_id.into(), passphrase.into());
    }

    /// Remove the passphrase for a Space (post-lock / per-session reset).
    pub fn clear(&mut self, space_id: &str) {
        self.by_space.remove(space_id);
    }

    /// Number of Spaces with a recorded passphrase. Test/UI convenience.
    pub fn len(&self) -> usize {
        self.by_space.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_space.is_empty()
    }

    /// F-MLS-PASS-PERSIST-1: persist the passphrase for `space_id`
    /// into the supplied [`SecureKeyStore`] (OS keychain wrapper)
    /// **and** keep an in-memory copy. The user must already have
    /// opted in via the Settings toggle — callers gate this on the
    /// per-Space `persist_mls_passphrase` preference.
    ///
    /// Returns the `SecureKeyStore` error verbatim when the backend
    /// rejects the write so the UI can surface the reason (e.g.
    /// `Unsupported` on wasm32 builds without IndexedDB).
    pub fn persist(
        &mut self,
        store: &dyn SecureKeyStore,
        space_id: impl Into<String>,
        passphrase: impl Into<String>,
    ) -> Result<(), SecureKeyStoreError> {
        let space = space_id.into();
        let value = passphrase.into();
        store.store_secret(&persist_key(&space), &value)?;
        self.by_space.insert(space, value);
        Ok(())
    }

    /// F-MLS-PASS-PERSIST-1: best-effort silent unlock from a
    /// [`SecureKeyStore`]. Reads the persisted passphrase for
    /// `space_id` (if present) and primes the in-memory cache.
    /// Returns `Ok(true)` when a passphrase was loaded, `Ok(false)`
    /// when none was stored, and `Err(...)` for backend errors that
    /// the caller should log (we still allow the UI to ask the user
    /// for the passphrase manually after a failure).
    pub fn load_from_store(
        &mut self,
        store: &dyn SecureKeyStore,
        space_id: &str,
    ) -> Result<bool, SecureKeyStoreError> {
        match store.get_secret(&persist_key(space_id))? {
            Some(value) => {
                self.by_space.insert(space_id.to_owned(), value);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// F-MLS-PASS-PERSIST-1: clear both the in-memory cache and the
    /// secure-store-backed copy for `space_id`. Called when the user
    /// flips the per-Space "remember MLS passphrase" toggle off, or
    /// during sign-out cleanup.
    pub fn forget(
        &mut self,
        store: &dyn SecureKeyStore,
        space_id: &str,
    ) -> Result<(), SecureKeyStoreError> {
        self.by_space.remove(space_id);
        store.delete_secret(&persist_key(space_id))
    }
}

/// F-MLS-PASS-PERSIST-1: secure-store key namespace for MLS
/// passphrases. `yougen.mls_passphrase.<space_id>` keeps the bucket
/// distinct from `recovery_key` / `cross_signing.<gen>` entries so a
/// future audit / migration can scan / wipe the MLS slice alone.
fn persist_key(space_id: &str) -> String {
    format!("yougen.mls_passphrase.{space_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_missing_space() {
        let store = MlsPassphraseStore::new();
        assert!(store.get("cx:space:none").is_none());
    }

    #[test]
    fn set_and_get_round_trip() {
        let mut store = MlsPassphraseStore::default();
        store.set("cx:space:a", "alpha");
        store.set("cx:space:b", "beta");
        assert_eq!(store.get("cx:space:a"), Some("alpha"));
        assert_eq!(store.get("cx:space:b"), Some("beta"));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn clear_removes_entry_only_for_one_space() {
        let mut store = MlsPassphraseStore::default();
        store.set("cx:space:a", "alpha");
        store.set("cx:space:b", "beta");
        store.clear("cx:space:a");
        assert!(store.get("cx:space:a").is_none());
        assert_eq!(store.get("cx:space:b"), Some("beta"));
    }

    #[test]
    fn replace_overwrites_existing_passphrase() {
        let mut store = MlsPassphraseStore::default();
        store.set("cx:space:a", "alpha");
        store.set("cx:space:a", "alpha-prime");
        assert_eq!(store.get("cx:space:a"), Some("alpha-prime"));
        assert_eq!(store.len(), 1);
    }

    // ── F-MLS-PASS-PERSIST-1 ─────────────────────────────────────────

    use crate::secure_key_store::MemorySecureKeyStore;

    #[test]
    fn persist_then_load_from_store_returns_value() {
        let secure = MemorySecureKeyStore::default();
        let mut store = MlsPassphraseStore::new();
        store.persist(&secure, "cx:space:a", "alpha").unwrap();
        // Wipe the in-memory cache so load is the only path.
        store.clear("cx:space:a");
        assert!(store.get("cx:space:a").is_none());
        let loaded = store
            .load_from_store(&secure, "cx:space:a")
            .expect("load from store");
        assert!(loaded);
        assert_eq!(store.get("cx:space:a"), Some("alpha"));
    }

    #[test]
    fn load_from_store_returns_false_when_no_persisted_value() {
        let secure = MemorySecureKeyStore::default();
        let mut store = MlsPassphraseStore::new();
        let loaded = store
            .load_from_store(&secure, "cx:space:none")
            .expect("load");
        assert!(!loaded);
        assert!(store.get("cx:space:none").is_none());
    }

    #[test]
    fn forget_clears_both_memory_and_secure_store() {
        let secure = MemorySecureKeyStore::default();
        let mut store = MlsPassphraseStore::new();
        store.persist(&secure, "cx:space:a", "alpha").unwrap();
        store.forget(&secure, "cx:space:a").unwrap();
        assert!(store.get("cx:space:a").is_none());
        // Subsequent silent-unlock should find nothing.
        let loaded = store.load_from_store(&secure, "cx:space:a").expect("load");
        assert!(!loaded);
    }

    #[test]
    fn persist_key_namespaces_under_yougen_mls_passphrase() {
        // Lock the namespace string so a future refactor doesn't
        // collide with `yougen.cross_signing.*` or `yougen.recovery.*`
        // entries the SecureKeyStore also holds.
        assert_eq!(
            persist_key("cx:space:a"),
            "yougen.mls_passphrase.cx:space:a"
        );
    }
}
