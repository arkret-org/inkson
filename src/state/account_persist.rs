//! Boot reconciliation for independently stored account records.
#![cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
use serde_json::Value;

use super::ClientLocalState;

/// Restore secure-store-only session material without replacing a grant that
/// was minted in the live session while the durable wasm tier was opening.
fn merge_secure_session_grant_into_live(
    live: &mut ClientLocalState,
    secure_grant: Option<super::PersistedSessionGrant>,
) {
    if live.session_grant.is_none() {
        live.session_grant = secure_grant;
    }
}

/// Recursively merge `stored` UNDER `live`: object keys are unioned (recursing
/// into shared keys), a `null`/absent live value adopts the stored value, and a
/// present live scalar or array wins outright.
///
/// This is deliberately map-oriented: `ClientLocalState` is overwhelmingly a bag
/// of `BTreeMap`/`Vec` projections, so unioning object keys recovers every
/// stored-only realm/cursor/snapshot entry the live blob has not re-observed
/// yet, while the live session's own writes stay authoritative. The only lossy
/// case is a scalar both sessions set to *different non-null* values inside the
/// narrow pre-init window; there live wins (this session's intent) and the
/// stored value re-materialises on the next sync. That window is only reachable
/// when a real main-state write happened before the IndexedDB tier initialised,
/// which the bootstrap ordering makes vanishingly rare.
fn json_merge_live_priority(live: Value, stored: Value) -> Value {
    match (live, stored) {
        (Value::Object(mut live_map), Value::Object(stored_map)) => {
            for (key, stored_value) in stored_map {
                match live_map.remove(&key) {
                    Some(live_value) => {
                        live_map.insert(key, json_merge_live_priority(live_value, stored_value));
                    }
                    None => {
                        live_map.insert(key, stored_value);
                    }
                }
            }
            Value::Object(live_map)
        }
        // A live `null` means "the live session never set this"; adopt stored.
        (Value::Null, stored) => stored,
        // Any other present live value (scalar or array) is authoritative.
        (live, _) => live,
    }
}

/// Reconcile a freshly-loaded `stored` blob (previous session, from the durable
/// backend) with the `live` in-memory state accumulated before the durable tier
/// was ready.
///
/// Fast paths keep the common cases exact:
///   * `live` is structurally default → adopt `stored` wholesale (the ordinary reload: nothing
///     wrote main state before hydration).
///   * `stored` is default → keep `live` (an empty durable tier catches the writes made before it
///     initialised, including when the secure store starts empty).
///
/// Otherwise both are non-default (a real live write raced hydration) and the
/// field-wise [`json_merge_live_priority`] union runs.
///
/// The memory-only sidecars (`mls_private_plaintext`,
/// `mls_decrypted_plaintext`, `authenticated_identity_links`, `composer_drafts`)
/// are `#[serde(skip_serializing)]`
/// and never appear in a stored account snapshot, so they are lifted out of `live` before
/// the JSON round-trip and restored afterwards — the JSON merge would otherwise
/// deserialize them back to empty and drop the live plaintext caches.
pub(super) fn merge_persisted_into_live(
    live: ClientLocalState,
    stored: ClientLocalState,
) -> ClientLocalState {
    let default_state = ClientLocalState::default();
    if live == default_state {
        return stored;
    }
    if stored == default_state {
        return live;
    }
    // Preserve the memory-only sidecars from the live state; a JSON round-trip
    // drops them (they are skip_serializing) and stored never carries them.
    let live_private_plaintext = live.mls_private_plaintext.clone();
    let live_decrypted_plaintext = live.mls_decrypted_plaintext.clone();
    let live_authenticated_identity_links = live.authenticated_identity_links.clone();
    let live_composer_drafts = live.composer_drafts.clone();

    let merged_value = match (serde_json::to_value(&live), serde_json::to_value(&stored)) {
        (Ok(live_value), Ok(stored_value)) => json_merge_live_priority(live_value, stored_value),
        _ => {
            // Serialization cannot realistically fail for these types; if it
            // somehow did, keep the live session's state rather than risk
            // adopting a partial merge.
            return live;
        }
    };
    let mut merged: ClientLocalState = match serde_json::from_value(merged_value) {
        Ok(merged) => merged,
        Err(_) => return live,
    };
    merged.mls_private_plaintext = live_private_plaintext;
    merged.mls_decrypted_plaintext = live_decrypted_plaintext;
    merged.authenticated_identity_links = live_authenticated_identity_links;
    merged.composer_drafts = live_composer_drafts;
    merged
}

#[cfg(target_arch = "wasm32")]
mod wasm_bootstrap {
    use std::sync::atomic::Ordering;

    use super::super::LocalStateStore;
    use super::{merge_persisted_into_live, merge_secure_session_grant_into_live};

    impl LocalStateStore {
        /// Hydrate the active account's records from the initialized transaction backend
        /// into `cached`, reconciling with any live writes made
        /// before the durable tier was ready (live wins, stored fills gaps). Must
        /// run before `secure_store_bootstrap_ready` is published so the account
        /// state is authoritative before session/connect starts. Persists the
        /// merged result so IndexedDB reflects any pre-init live writes.
        pub(crate) fn hydrate_active_account_state_from_secure_store(
            &mut self,
            _secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        ) {
            self.ensure_cached_loaded();
            let effective_did = self.effective_account_key();
            // The root key cannot prove a AccountId, so it is not
            // an acceptable source for restoring an account-local session
            // secret. Session credentials are committed explicitly before
            // publication and are never repaired by account-state hydration.
            let secure_grant = None;
            let Some(stored) = self.read_account_state(&effective_did) else {
                // No durable entry yet; keep the live state and mark loaded so the
                // first flush persists it under the active account key.
                merge_secure_session_grant_into_live(&mut self.cached, secure_grant);
                self.loaded.store(true, Ordering::Relaxed);
                let _ = self.flush();
                return;
            };
            let live = std::mem::take(&mut self.cached);
            self.cached = merge_persisted_into_live(live, stored);
            merge_secure_session_grant_into_live(&mut self.cached, secure_grant);
            self.loaded.store(true, Ordering::Relaxed);
            let _ = self.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_grant(jwt: &str) -> crate::state::PersistedSessionGrant {
        crate::state::PersistedSessionGrant {
            grant_jwt: jwt.to_owned(),
            session_private_key_pem: String::new(),
            grant_id: "ak:session_grant:AY6DJbBwavsGTQuBZZiqqw9MVcqPZ8QX8invQ3i2kpi7".to_owned(),
            audience_id: arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture:coland.example")
                .unwrap(),
            granted_scope: Vec::new(),
            account_id: arkret_sdk::AccountId::new(
                arkret_sdk::DidCoreId::new(
                    "ak:did_core:webvh:z6mkfixture:alice.example".to_owned(),
                )
                .unwrap(),
                arkret_sdk::DidCoreId::new("ak:did_core:web:coland.example").unwrap(),
            ),
            device_id: arkret_sdk::DeviceId::new(
                "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
            )
            .unwrap(),
            station_url: url::Url::parse("https://coland.example").unwrap(),
            grant_expires_at: None,
            stored_at: chrono::Utc::now(),
        }
    }

    fn state_with_cursor(cursor: &str) -> ClientLocalState {
        ClientLocalState {
            sync_cursor: Some(cursor.to_owned()),
            ..ClientLocalState::default()
        }
    }

    #[test]
    fn merge_adopts_stored_when_live_is_default() {
        let stored = state_with_cursor("sx:stored");
        let merged = merge_persisted_into_live(ClientLocalState::default(), stored.clone());
        assert_eq!(merged, stored);
    }

    #[test]
    fn merge_keeps_live_when_stored_is_default() {
        let live = state_with_cursor("sx:live");
        let merged = merge_persisted_into_live(live.clone(), ClientLocalState::default());
        assert_eq!(merged, live);
    }

    #[test]
    fn secure_session_grant_fills_hydrated_state_but_never_replaces_live_grant() {
        let mut hydrated = ClientLocalState::default();
        merge_secure_session_grant_into_live(&mut hydrated, Some(session_grant("stored")));
        assert_eq!(
            hydrated
                .session_grant
                .as_ref()
                .map(|grant| grant.grant_jwt.as_str()),
            Some("stored")
        );

        merge_secure_session_grant_into_live(&mut hydrated, Some(session_grant("stale")));
        assert_eq!(
            hydrated
                .session_grant
                .as_ref()
                .map(|grant| grant.grant_jwt.as_str()),
            Some("stored")
        );
    }

    #[test]
    fn merge_prefers_live_scalar_but_unions_stored_only_map_entries() {
        let mut live = state_with_cursor("sx:live");
        live.realm_tree_projections.insert(
            "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned(),
            serde_json::json!({"name": "A-live"}),
        );

        let mut stored = state_with_cursor("sx:stored");
        // Same-key projection: live must win.
        stored.realm_tree_projections.insert(
            "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned(),
            serde_json::json!({"name": "A-stored"}),
        );
        // Stored-only projection: must be recovered into the merge.
        stored.realm_tree_projections.insert(
            "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned(),
            serde_json::json!({"name": "B-stored"}),
        );
        // Stored-only cursor entry: must be recovered.
        stored
            .commit_stream_cursors
            .insert("realm-b-stream".to_owned(), "cursor-b".to_owned());

        let merged = merge_persisted_into_live(live, stored);

        // Live wins the scalar and the shared projection key.
        assert_eq!(merged.sync_cursor.as_deref(), Some("sx:live"));
        assert_eq!(
            merged.realm_tree_projections["ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk"]
                ["name"],
            "A-live"
        );
        // Stored-only entries are recovered.
        assert_eq!(
            merged.realm_tree_projections["ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo"]
                ["name"],
            "B-stored"
        );
        assert_eq!(
            merged
                .commit_stream_cursors
                .get("realm-b-stream")
                .map(String::as_str),
            Some("cursor-b")
        );
    }

    #[test]
    fn merge_preserves_live_memory_only_plaintext_sidecars() {
        let mut live = state_with_cursor("sx:live");
        live.mls_decrypted_plaintext
            .entry("ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned())
            .or_default()
            .insert("digest-1".to_owned(), "plaintext-1".to_owned());

        let stored = state_with_cursor("sx:stored");
        let merged = merge_persisted_into_live(live, stored);

        // The skip_serializing sidecar survived the JSON round-trip merge.
        assert_eq!(
            merged.mls_decrypted_plaintext["ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk"]
                ["digest-1"],
            "plaintext-1"
        );
    }
}
