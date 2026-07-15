use anyhow::Context as _;

use super::*;

const BROWSER_STORAGE_WARNING_RATIO: f64 = 0.8;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct E2eePlaintextCacheRealmUsage {
    pub(crate) plaintext_bytes: usize,
    pub(crate) authored_entries: usize,
    pub(crate) received_entries: usize,
}

impl E2eePlaintextCacheRealmUsage {
    pub(crate) fn entry_count(&self) -> usize {
        self.authored_entries + self.received_entries
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct E2eePlaintextCacheUsage {
    pub(crate) realms: BTreeMap<String, E2eePlaintextCacheRealmUsage>,
    pub(crate) plaintext_bytes: usize,
    pub(crate) authored_entries: usize,
    pub(crate) received_entries: usize,
}

pub(crate) struct PendingE2eePlaintextClear {
    key: String,
    json: String,
    previous_private: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    previous_decrypted: BTreeMap<String, BTreeMap<String, String>>,
}

impl PendingE2eePlaintextClear {
    pub(crate) async fn persist(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<()> {
        secure_store
            .store_secret_durable(&self.key, &self.json)
            .await
            .context("persist cleared E2EE plaintext cache")
    }
}

impl E2eePlaintextCacheUsage {
    pub(crate) fn entry_count(&self) -> usize {
        self.authored_entries + self.received_entries
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum E2eePlaintextCacheClearScope {
    All,
    Realm(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BrowserStorageEstimate {
    pub(crate) usage_bytes: u64,
    pub(crate) quota_bytes: u64,
}

impl BrowserStorageEstimate {
    pub(crate) fn usage_ratio(&self) -> Option<f64> {
        (self.quota_bytes != 0).then(|| self.usage_bytes as f64 / self.quota_bytes as f64)
    }

    pub(crate) fn is_near_quota(&self) -> bool {
        self.usage_ratio()
            .is_some_and(|ratio| ratio >= BROWSER_STORAGE_WARNING_RATIO)
    }
}

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

    fn plaintext_usage(&self) -> E2eePlaintextCacheUsage {
        let mut usage = E2eePlaintextCacheUsage::default();
        for (realm_id, strands) in &self.private_plaintext {
            let realm = usage.realms.entry(realm_id.clone()).or_default();
            for fields in strands.values() {
                realm.authored_entries += fields.len();
                realm.plaintext_bytes += fields.values().map(|value| value.len()).sum::<usize>();
            }
        }
        for (realm_id, entries) in &self.decrypted_plaintext {
            let realm = usage.realms.entry(realm_id.clone()).or_default();
            realm.received_entries += entries.len();
            realm.plaintext_bytes += entries.values().map(|value| value.len()).sum::<usize>();
        }
        for realm in usage.realms.values() {
            usage.plaintext_bytes += realm.plaintext_bytes;
            usage.authored_entries += realm.authored_entries;
            usage.received_entries += realm.received_entries;
        }
        usage
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

    pub(crate) fn e2ee_plaintext_cache_usage(&self) -> E2eePlaintextCacheUsage {
        E2eePlaintextCacheV1::from_state(&self.effective_state_for_persist()).plaintext_usage()
    }

    /// Apply the in-memory clear and return the owned durable write. Callers
    /// using a shared state lock must release that lock before awaiting
    /// [`PendingE2eePlaintextClear::persist`].
    pub(crate) fn prepare_e2ee_plaintext_cache_clear(
        &mut self,
        scope: &E2eePlaintextCacheClearScope,
    ) -> anyhow::Result<Option<PendingE2eePlaintextClear>> {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();

        let previous_private = self.cached.mls_private_plaintext.clone();
        let previous_decrypted = self.cached.mls_decrypted_plaintext.clone();
        let changed = match scope {
            E2eePlaintextCacheClearScope::All => {
                let changed = !self.cached.mls_private_plaintext.is_empty()
                    || !self.cached.mls_decrypted_plaintext.is_empty();
                self.cached.mls_private_plaintext.clear();
                self.cached.mls_decrypted_plaintext.clear();
                changed
            }
            E2eePlaintextCacheClearScope::Realm(realm_id) => {
                let removed_private = self.cached.mls_private_plaintext.remove(realm_id).is_some();
                let removed_decrypted = self
                    .cached
                    .mls_decrypted_plaintext
                    .remove(realm_id)
                    .is_some();
                removed_private || removed_decrypted
            }
        };
        if !changed {
            return Ok(None);
        }

        let Some((key, json)) = self.e2ee_plaintext_cache_secure_write()? else {
            self.cached.mls_private_plaintext = previous_private;
            self.cached.mls_decrypted_plaintext = previous_decrypted;
            anyhow::bail!("cannot clear E2EE plaintext cache without an active account");
        };
        // Keep a minimal encrypted empty object instead of deleting the entry.
        Ok(Some(PendingE2eePlaintextClear {
            key,
            json: json.unwrap_or_else(|| "{}".to_owned()),
            previous_private,
            previous_decrypted,
        }))
    }

    pub(crate) fn rollback_e2ee_plaintext_cache_clear(
        &mut self,
        pending: PendingE2eePlaintextClear,
    ) {
        // Preserve writes that arrived while the durable request was in
        // flight; restore only entries removed by the failed clear.
        for (realm_id, strands) in pending.previous_private {
            let current_strands = self
                .cached
                .mls_private_plaintext
                .entry(realm_id)
                .or_default();
            for (strand_id, fields) in strands {
                let current_fields = current_strands.entry(strand_id).or_default();
                for (field, plaintext) in fields {
                    current_fields.entry(field).or_insert(plaintext);
                }
            }
        }
        for (realm_id, entries) in pending.previous_decrypted {
            let current_entries = self
                .cached
                .mls_decrypted_plaintext
                .entry(realm_id)
                .or_default();
            for (digest, plaintext) in entries {
                current_entries.entry(digest).or_insert(plaintext);
            }
        }
    }

    /// Convenience wrapper for callers that exclusively own the state value.
    pub(crate) async fn clear_e2ee_plaintext_cache_with_secure_store(
        &mut self,
        scope: &E2eePlaintextCacheClearScope,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<bool> {
        let Some(pending) = self.prepare_e2ee_plaintext_cache_clear(scope)? else {
            return Ok(false);
        };
        if let Err(error) = pending.persist(secure_store).await {
            self.rollback_e2ee_plaintext_cache_clear(pending);
            return Err(error);
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

#[cfg(target_arch = "wasm32")]
pub(crate) async fn browser_storage_estimate() -> anyhow::Result<Option<BrowserStorageEstimate>> {
    use js_sys::Reflect;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_futures::JsFuture;

    let window = web_sys::window().context("browser window is unavailable")?;
    let promise = window
        .navigator()
        .storage()
        .estimate()
        .map_err(|error| anyhow::anyhow!("browser storage estimate failed: {error:?}"))?;
    let estimate = JsFuture::from(promise)
        .await
        .map_err(|error| anyhow::anyhow!("browser storage estimate rejected: {error:?}"))?;
    let read_bytes = |field: &str| -> anyhow::Result<u64> {
        let value = Reflect::get(&estimate, &JsValue::from_str(field))
            .map_err(|error| anyhow::anyhow!("browser storage {field} read failed: {error:?}"))?
            .as_f64()
            .with_context(|| format!("browser storage {field} is missing"))?;
        anyhow::ensure!(
            value.is_finite() && value >= 0.0,
            "browser storage {field} is invalid"
        );
        Ok(value as u64)
    };
    Ok(Some(BrowserStorageEstimate {
        usage_bytes: read_bytes("usage")?,
        quota_bytes: read_bytes("quota")?,
    }))
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn browser_storage_estimate() -> anyhow::Result<Option<BrowserStorageEstimate>> {
    Ok(None)
}
