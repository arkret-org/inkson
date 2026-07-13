use anyhow::Context as _;

use super::*;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct E2eePlaintextCacheV1 {
    #[serde(default)]
    mls_snapshots: BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope>,
    #[serde(default)]
    private_plaintext: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(default)]
    decrypted_plaintext: BTreeMap<String, BTreeMap<String, String>>,
}

impl E2eePlaintextCacheV1 {
    fn from_state(state: &ClientLocalState) -> Self {
        Self {
            mls_snapshots: state.mls_snapshots.clone(),
            private_plaintext: state.mls_private_plaintext.clone(),
            decrypted_plaintext: state.mls_decrypted_plaintext.clone(),
        }
    }

    fn is_empty(&self) -> bool {
        self.mls_snapshots.is_empty()
            && self.private_plaintext.is_empty()
            && self.decrypted_plaintext.is_empty()
    }

    fn merge_into(
        self,
        state: &mut ClientLocalState,
        live_receive_snapshot_keys: &BTreeSet<String>,
        recovery_snapshot_keys: &BTreeSet<String>,
    ) -> bool {
        let mut changed = false;
        for (realm_id, snapshot) in self.mls_snapshots {
            match state.mls_snapshots.entry(realm_id.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(snapshot);
                    changed = true;
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let current = entry.get();
                    let keep_live = live_receive_snapshot_keys.contains(&realm_id);
                    let secure_checkpoint_is_authoritative =
                        recovery_snapshot_keys.contains(&realm_id);
                    if !keep_live
                        && (secure_checkpoint_is_authoritative || snapshot.epoch >= current.epoch)
                        && snapshot != *current
                    {
                        entry.insert(snapshot);
                        changed = true;
                    }
                }
            }
        }
        for (realm_id, strands) in self.private_plaintext {
            let local_strands = state.mls_private_plaintext.entry(realm_id).or_default();
            for (strand_id, fields) in strands {
                let local_fields = local_strands.entry(strand_id).or_default();
                for (field_path, plaintext) in fields {
                    if plaintext.is_empty() {
                        continue;
                    }
                    local_fields.entry(field_path).or_insert_with(|| {
                        changed = true;
                        plaintext
                    });
                }
            }
        }
        for (realm_id, entries) in self.decrypted_plaintext {
            let local_entries = state.mls_decrypted_plaintext.entry(realm_id).or_default();
            for (payload_digest, plaintext) in entries {
                if plaintext.is_empty() {
                    continue;
                }
                local_entries.entry(payload_digest).or_insert_with(|| {
                    changed = true;
                    plaintext
                });
            }
        }
        changed
    }
}

impl LocalStateStore {
    fn active_e2ee_plaintext_cache_key(&self) -> Option<String> {
        self.read_root()
            .active_did
            .filter(|did| !did.trim().is_empty())
            .map(|did| crate::secure_key_store::e2ee_plaintext_cache_store_key(&did))
    }

    pub(crate) fn e2ee_plaintext_cache_secure_write(
        &self,
    ) -> anyhow::Result<Option<(String, Option<String>)>> {
        let Some(key) = self.active_e2ee_plaintext_cache_key() else {
            return Ok(None);
        };
        let cache = E2eePlaintextCacheV1::from_state(&self.effective_state_for_persist());
        let json = if cache.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&cache).context("encode E2EE plaintext cache")?)
        };
        Ok(Some((key, json)))
    }

    pub(crate) fn persist_e2ee_plaintext_cache_with_secure_store(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<bool> {
        let Some((key, json)) = self.e2ee_plaintext_cache_secure_write()? else {
            return Ok(false);
        };
        if let Some(json) = json {
            secure_store
                .store_secret(&key, &json)
                .context("persist E2EE plaintext cache in secure store")?;
        } else {
            secure_store
                .delete_secret(&key)
                .context("delete E2EE plaintext cache from secure store")?;
        }
        Ok(true)
    }

    pub(crate) fn hydrate_e2ee_plaintext_cache_with_secure_store(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<bool> {
        let Some(key) = self.active_e2ee_plaintext_cache_key() else {
            return Ok(false);
        };
        let persisted = match secure_store
            .get_secret(&key)
            .context("load E2EE plaintext cache from secure store")?
        {
            Some(json) => serde_json::from_str(&json).context("decode E2EE plaintext cache")?,
            None => E2eePlaintextCacheV1::default(),
        };

        self.ensure_cached_loaded();
        let (live_receive_snapshot_keys, overlay_recovery_snapshot_keys) = {
            let overlay = self.lock_mls_receive_overlay();
            (
                overlay.snapshots.keys().cloned().collect::<BTreeSet<_>>(),
                overlay
                    .recovery_snapshots
                    .keys()
                    .cloned()
                    .collect::<BTreeSet<_>>(),
            )
        };
        let mut recovery_snapshot_keys: BTreeSet<String> = self
            .cached
            .mls_receive_recovery_snapshots
            .keys()
            .cloned()
            .collect();
        recovery_snapshot_keys.extend(overlay_recovery_snapshot_keys);
        self.absorb_mls_receive_overlay();
        let changed = persisted.clone().merge_into(
            &mut self.cached,
            &live_receive_snapshot_keys,
            &recovery_snapshot_keys,
        );
        let secure_snapshot_keys: BTreeSet<String> =
            persisted.mls_snapshots.keys().cloned().collect();
        let mut changed = changed;
        for (realm_id, recovery_snapshot) in self.cached.mls_receive_recovery_snapshots.clone() {
            if live_receive_snapshot_keys.contains(&realm_id)
                || secure_snapshot_keys.contains(&realm_id)
            {
                continue;
            }
            if self.cached.mls_snapshots.get(&realm_id) != Some(&recovery_snapshot) {
                self.cached
                    .mls_snapshots
                    .insert(realm_id, recovery_snapshot);
                changed = true;
            }
        }
        let merged = E2eePlaintextCacheV1::from_state(&self.cached);

        // Writes made before IndexedDB initialization stay in memory. If that
        // live cache contains newer or additional entries, persist the merged
        // result now without allowing the older stored value to overwrite it.
        if merged != persisted {
            self.persist_e2ee_plaintext_cache_with_secure_store(secure_store)?;
        }
        Ok(changed)
    }

    pub(crate) fn clear_mls_receive_recovery_snapshots(&mut self) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
        if self.cached.mls_receive_recovery_snapshots.is_empty() {
            return Ok(());
        }
        self.cached.mls_receive_recovery_snapshots.clear();
        self.flush()
    }

    pub(super) fn clear_e2ee_plaintext_from_memory(&mut self) {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
        self.cached.mls_private_plaintext.clear();
        self.cached.mls_decrypted_plaintext.clear();
    }

    pub(super) fn persist_e2ee_plaintext_cache_if_ready(&self) {
        #[cfg(target_arch = "wasm32")]
        {
            if !crate::secure_key_store::wasm_secure_store_ready() {
                return;
            }
            let write = match self.e2ee_plaintext_cache_secure_write() {
                Ok(Some(write)) => write,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(?error, "E2EE plaintext cache encode failed");
                    return;
                }
            };
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            match write {
                (key, Some(json)) => {
                    wasm_bindgen_futures::spawn_local(async move {
                        if let Err(error) = secure_store.store_secret_durable(&key, &json).await {
                            tracing::warn!(
                                ?error,
                                "E2EE plaintext cache durable IndexedDB persist failed",
                            );
                        }
                    });
                }
                (key, None) => {
                    if let Err(error) = secure_store.delete_secret(&key) {
                        tracing::warn!(?error, "E2EE plaintext cache secure-store delete failed");
                    }
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = self;
    }

    pub(super) fn hydrate_e2ee_plaintext_cache_if_ready(&mut self) {
        #[cfg(target_arch = "wasm32")]
        {
            if !crate::secure_key_store::wasm_secure_store_ready() {
                return;
            }
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            if let Err(error) =
                self.hydrate_e2ee_plaintext_cache_with_secure_store(secure_store.as_ref())
            {
                tracing::warn!(?error, "E2EE plaintext cache secure-store hydrate failed");
                return;
            }
            self.persist_e2ee_plaintext_cache_if_ready();
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = self;
    }
}
