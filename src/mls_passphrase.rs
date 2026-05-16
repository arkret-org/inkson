//! Per-Space MLS snapshot passphrase store.
//!
//! Sprint Q1 第十二增量: chat.rs (encrypt path) and timeline.rs (decrypt-
//! success audit emitter) need to agree on the passphrase used to
//! seal a Space's MLS snapshot. Without a shared store, encryption
//! would use one passphrase and the decrypt-on-render emitter would
//! either use a different one or fall back to the empty default — either
//! way, the `cx.audit.accessed` hook (B7) never fires.
//!
//! This is an in-memory only store; passphrases are never persisted
//! to disk. The user re-enters them on each session. That intentionally
//! keeps the durable state store zero-knowledge of MLS keys (the
//! encrypted snapshot in `state_store.mls_snapshot_for(space)` is the
//! only thing that survives a refresh, and it's opaque without the
//! passphrase).

use std::collections::HashMap;

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
}
