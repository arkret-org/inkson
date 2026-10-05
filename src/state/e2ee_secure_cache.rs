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
    previous_identity_links: BTreeMap<String, LocallyAuthenticatedIdentityLink>,
}

impl PendingE2eePlaintextClear {
    pub(crate) async fn persist(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<()> {
        LocalStateStore::persist_e2ee_plaintext_cache_write_durable(
            secure_store,
            &self.key,
            Some(&self.json),
        )
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
    // Persisted key, unchanged: this entry is already written in every
    // device's secure store, and an at-rest key is not a wire name.
    #[serde(default, rename = "mls_snapshots")]
    mls_local_checkpoints: BTreeMap<String, crate::mls::persistence::MlsLocalCheckpointEnvelope>,
    #[serde(default)]
    private_plaintext: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    #[serde(default)]
    decrypted_plaintext: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    authenticated_identity_links: BTreeMap<String, LocallyAuthenticatedIdentityLink>,
}

impl E2eePlaintextCacheV1 {
    fn from_state(state: &ClientLocalState) -> Self {
        Self {
            mls_local_checkpoints: state.mls_local_checkpoints.clone(),
            private_plaintext: state.mls_private_plaintext.clone(),
            decrypted_plaintext: state.mls_decrypted_plaintext.clone(),
            authenticated_identity_links: state.authenticated_identity_links.clone(),
        }
    }

    fn is_empty(&self) -> bool {
        self.mls_local_checkpoints.is_empty()
            && self.private_plaintext.is_empty()
            && self.decrypted_plaintext.is_empty()
            && self.authenticated_identity_links.is_empty()
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

    #[cfg(any(test, target_arch = "wasm32"))]
    fn merge_into(
        self,
        state: &mut ClientLocalState,
        live_receive_snapshot_keys: &BTreeSet<String>,
        recovery_snapshot_keys: &BTreeSet<String>,
    ) -> bool {
        let mut changed = false;
        for (realm_id, snapshot) in self.mls_local_checkpoints {
            match state.mls_local_checkpoints.entry(realm_id.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(snapshot);
                    changed = true;
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let current = entry.get();
                    let keep_live = live_receive_snapshot_keys.contains(&realm_id);
                    let secure_checkpoint_is_authoritative =
                        recovery_snapshot_keys.contains(&realm_id);
                    // The secure cache may still hold an earlier creator
                    // attempt at the same epoch. Never replace an accepted
                    // private checkpoint with unbound or differently bound
                    // bytes merely because its epoch matches.
                    let accepted_checkpoint_conflicts = current.epoch == snapshot.epoch
                        && current.group_state_event_id.is_some()
                        && (current.group_id != snapshot.group_id
                            || current.group_state_event_id != snapshot.group_state_event_id);
                    if !keep_live
                        && !accepted_checkpoint_conflicts
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
        for (key, identity_link) in self.authenticated_identity_links {
            state
                .authenticated_identity_links
                .entry(key)
                .or_insert_with(|| {
                    changed = true;
                    identity_link
                });
        }
        changed
    }
}

impl LocalStateStore {
    fn active_e2ee_plaintext_cache_key(&self) -> Option<String> {
        let root = self.read_root();
        let namespace = account_storage_scope(&root.active_entry()?.authority).ok()?;
        Some(crate::secure_key_store::e2ee_plaintext_cache_store_key(
            &namespace,
        ))
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

    #[cfg(test)]
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

    /// Wait for this exact cache snapshot, including an explicit clear, to
    /// commit. Background snapshots share the same writer, but cannot replace
    /// an awaited snapshot or satisfy its barrier with different bytes.
    pub(crate) async fn persist_e2ee_plaintext_cache_write_durable(
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        key: &str,
        json: Option<&str>,
    ) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = secure_store;
            cache_persist_driver::persist_exact(key.to_owned(), json.map(str::to_owned)).await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            match json {
                Some(json) => secure_store.store_secret_durable(key, json).await?,
                None => secure_store.delete_secret_durable(key).await?,
            }
            Ok(())
        }
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
        let previous_identity_links = self.cached.authenticated_identity_links.clone();
        let changed = match scope {
            E2eePlaintextCacheClearScope::All => {
                let changed = !self.cached.mls_private_plaintext.is_empty()
                    || !self.cached.mls_decrypted_plaintext.is_empty()
                    || !self.cached.authenticated_identity_links.is_empty();
                self.cached.mls_private_plaintext.clear();
                self.cached.mls_decrypted_plaintext.clear();
                self.cached.authenticated_identity_links.clear();
                changed
            }
            E2eePlaintextCacheClearScope::Realm(realm_id) => {
                let removed_private = self.cached.mls_private_plaintext.remove(realm_id).is_some();
                let removed_decrypted = self
                    .cached
                    .mls_decrypted_plaintext
                    .remove(realm_id)
                    .is_some();
                let retained = self.cached.authenticated_identity_links.len();
                self.cached
                    .authenticated_identity_links
                    .retain(|_, entry| entry.identity_link.realm_id.as_str() != realm_id);
                removed_private
                    || removed_decrypted
                    || retained != self.cached.authenticated_identity_links.len()
            }
        };
        if !changed {
            return Ok(None);
        }

        let Some((key, json)) = self.e2ee_plaintext_cache_secure_write()? else {
            self.cached.mls_private_plaintext = previous_private;
            self.cached.mls_decrypted_plaintext = previous_decrypted;
            self.cached.authenticated_identity_links = previous_identity_links;
            anyhow::bail!("cannot clear E2EE plaintext cache without an active account");
        };
        // Keep a minimal encrypted empty object instead of deleting the entry.
        Ok(Some(PendingE2eePlaintextClear {
            key,
            json: json.unwrap_or_else(|| "{}".to_owned()),
            previous_private,
            previous_decrypted,
            previous_identity_links,
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
        for (key, identity_link) in pending.previous_identity_links {
            self.cached
                .authenticated_identity_links
                .entry(key)
                .or_insert(identity_link);
        }
    }

    /// Convenience wrapper for callers that exclusively own the state value.
    #[cfg(test)]
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

    #[cfg(any(test, target_arch = "wasm32"))]
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
            .mls_receive_recovery_checkpoints
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
            persisted.mls_local_checkpoints.keys().cloned().collect();
        let mut changed = changed;
        for (realm_id, recovery_snapshot) in self.cached.mls_receive_recovery_checkpoints.clone() {
            if live_receive_snapshot_keys.contains(&realm_id)
                || secure_snapshot_keys.contains(&realm_id)
            {
                continue;
            }
            if self.cached.mls_local_checkpoints.get(&realm_id) != Some(&recovery_snapshot) {
                self.cached
                    .mls_local_checkpoints
                    .insert(realm_id, recovery_snapshot);
                changed = true;
            }
        }
        let merged = E2eePlaintextCacheV1::from_state(&self.cached);

        // Writes made before IndexedDB initialization stay in memory. If that
        // live cache contains newer or additional entries, persist the merged
        // result now without allowing the older stored value to overwrite it.
        if merged != persisted {
            #[cfg(target_arch = "wasm32")]
            self.persist_e2ee_plaintext_cache_if_ready();
            #[cfg(not(target_arch = "wasm32"))]
            self.persist_e2ee_plaintext_cache_with_secure_store(secure_store)?;
        }
        Ok(changed)
    }

    #[cfg(test)]
    pub(crate) fn clear_mls_receive_recovery_checkpoints(&mut self) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
        if self.cached.mls_receive_recovery_checkpoints.is_empty() {
            return Ok(());
        }
        self.cached.mls_receive_recovery_checkpoints.clear();
        self.flush()
    }

    /// Clear only the exact recovery-checkpoint set covered by a completed
    /// durable cache write. A concurrent receive changes the encoded cache and
    /// therefore keeps every checkpoint for the next persistence pass instead
    /// of allowing an older background task to erase newer recovery state.
    #[cfg(any(test, target_arch = "wasm32"))]
    pub(crate) fn clear_mls_receive_recovery_checkpoints_if_cache_unchanged(
        &mut self,
        persisted_key: &str,
        persisted_json: &str,
    ) -> anyhow::Result<bool> {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
        let current_write = self.e2ee_plaintext_cache_secure_write()?;
        if current_write
            .as_ref()
            .map(|(key, json)| (key.as_str(), json.as_deref()))
            != Some((persisted_key, Some(persisted_json)))
        {
            return Ok(false);
        }
        if self.cached.mls_receive_recovery_checkpoints.is_empty() {
            return Ok(true);
        }
        self.cached.mls_receive_recovery_checkpoints.clear();
        self.flush()?;
        Ok(true)
    }

    pub(super) fn clear_e2ee_plaintext_from_memory(&mut self) {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
        self.cached.mls_private_plaintext.clear();
        self.cached.mls_decrypted_plaintext.clear();
        self.cached.authenticated_identity_links.clear();
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
            cache_persist_driver::enqueue_background(write.0, write.1);
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

#[cfg(any(test, target_arch = "wasm32"))]
type CachePersistReply = tokio::sync::oneshot::Sender<Result<(), String>>;

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Default)]
struct CachePersistLane {
    active: Option<CachePersistWrite>,
    pending: std::collections::VecDeque<CachePersistWrite>,
    committed: Option<Option<[u8; 32]>>,
}

#[cfg(any(test, target_arch = "wasm32"))]
struct CachePersistWrite {
    json: Option<String>,
    replies: Vec<CachePersistReply>,
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Default)]
struct CachePersistQueue {
    lanes: BTreeMap<String, CachePersistLane>,
}

#[cfg(any(test, target_arch = "wasm32"))]
impl CachePersistQueue {
    fn digest(json: &Option<String>) -> Option<[u8; 32]> {
        use sha2::{Digest as _, Sha256};
        json.as_ref()
            .map(|json| Sha256::digest(json.as_bytes()).into())
    }

    /// Coalesce only background tail writes. A waiter makes its exact bytes
    /// immutable until they commit; it never accepts a newer snapshot instead.
    fn enqueue(
        &mut self,
        key: String,
        json: Option<String>,
        reply: Option<CachePersistReply>,
        durable_matches: bool,
    ) -> bool {
        let lane = self.lanes.entry(key).or_default();
        if lane.active.is_none()
            && lane.pending.is_empty()
            && lane.committed == Some(Self::digest(&json))
            && durable_matches
        {
            if let Some(reply) = reply {
                let _ = reply.send(Ok(()));
            }
            return false;
        }
        if let Some(tail) = lane.pending.back_mut() {
            if tail.json == json {
                tail.replies.extend(reply);
                return false;
            }
            if tail.replies.is_empty() {
                lane.pending.pop_back();
            }
        } else if let Some(active) = &mut lane.active
            && active.json == json
        {
            active.replies.extend(reply);
            return false;
        }
        let start = lane.active.is_none() && lane.pending.is_empty();
        lane.pending.push_back(CachePersistWrite {
            json,
            replies: reply.into_iter().collect(),
        });
        start
    }

    fn take_next(&mut self, key: &str) -> Option<Option<String>> {
        let lane = self.lanes.get_mut(key)?;
        assert!(lane.active.is_none());
        lane.active = lane.pending.pop_front();
        lane.active.as_ref().map(|write| write.json.clone())
    }

    fn complete(&mut self, key: &str, result: Result<(), String>) {
        let lane = self.lanes.get_mut(key).expect("active cache lane");
        let write = lane.active.take().expect("active cache write");
        // A failed write invalidates the byte shortcut. The next publication
        // must retry rather than claiming the previous cache entry is durable.
        lane.committed = if result.is_ok() {
            Some(Self::digest(&write.json))
        } else {
            None
        };
        for reply in write.replies {
            let _ = reply.send(result.clone());
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod cache_persist_driver {
    use std::sync::{Mutex, OnceLock};

    use anyhow::Context as _;

    use super::CachePersistQueue;

    fn queue() -> &'static Mutex<CachePersistQueue> {
        static QUEUE: OnceLock<Mutex<CachePersistQueue>> = OnceLock::new();
        QUEUE.get_or_init(|| Mutex::new(CachePersistQueue::default()))
    }

    fn enqueue(key: String, json: Option<String>, reply: Option<super::CachePersistReply>) {
        let store = crate::secure_key_store::default_secure_key_store("inkson");
        let durable_matches = store.get_secret(&key).ok().as_ref() == Some(&json);
        let start = queue()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .enqueue(key.clone(), json, reply, durable_matches);
        if start {
            // Reserve the active slot before spawning so two synchronous
            // publications cannot launch competing writers for the same key.
            let next = queue()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take_next(&key)
                .expect("new cache drain has a pending write");
            wasm_bindgen_futures::spawn_local(drain(key, next));
        }
    }

    pub(super) fn enqueue_background(key: String, json: Option<String>) {
        enqueue(key, json, None);
    }

    pub(super) async fn persist_exact(key: String, json: Option<String>) -> anyhow::Result<()> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        enqueue(key, json, Some(sender));
        receiver
            .await
            .context("E2EE cache durable writer stopped")?
            .map_err(|error| anyhow::anyhow!(error))
    }

    async fn drain(key: String, mut json: Option<String>) {
        loop {
            let store = crate::secure_key_store::default_secure_key_store("inkson");
            let result = match &json {
                Some(json) => store.store_secret_durable(&key, json).await,
                None => store.delete_secret_durable(&key).await,
            }
            .map_err(|error| error.to_string());
            if let Err(error) = &result {
                tracing::warn!(%error, "E2EE plaintext cache durable IndexedDB persist failed");
            }
            let next = {
                let mut queue = queue()
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                queue.complete(&key, result);
                queue.take_next(&key)
            };
            let Some(next) = next else { return };
            json = next;
        }
    }
}

#[cfg(test)]
mod cache_persist_tests {
    use super::*;

    fn json(value: &str) -> Option<String> {
        Some(value.to_owned())
    }

    #[tokio::test]
    async fn cache_single_writer_coalesces_background_burst_and_waits_for_exact_tail() {
        use crate::secure_key_store::SecureKeyStore as _;

        let mut queue = CachePersistQueue::default();
        let store = crate::secure_key_store::MemorySecureKeyStore::default();
        let key = "account-a";
        assert!(queue.enqueue(key.into(), json("first"), None, false));
        assert_eq!(queue.take_next(key), Some(json("first")));
        assert!(!queue.enqueue(key.into(), json("middle"), None, false));
        assert!(!queue.enqueue(key.into(), json("latest"), None, false));
        let (sender, mut latest) = tokio::sync::oneshot::channel();
        assert!(!queue.enqueue(key.into(), json("latest"), Some(sender), false));
        store.store_secret_durable(key, "first").await.unwrap();
        queue.complete(key, Ok(()));
        assert!(matches!(
            latest.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(queue.take_next(key), Some(json("latest")));
        store.store_secret_durable(key, "latest").await.unwrap();
        queue.complete(key, Ok(()));
        latest.await.unwrap().unwrap();
        assert_eq!(queue.take_next(key), None);
        assert_eq!(store.get_secret(key).unwrap(), json("latest"));
    }

    #[tokio::test]
    async fn cache_clear_barrier_is_not_replaced_by_a_new_receive() {
        let mut queue = CachePersistQueue::default();
        let key = "account-a";
        assert!(queue.enqueue(key.into(), json("old"), None, false));
        assert_eq!(queue.take_next(key), Some(json("old")));
        let (sender, mut cleared) = tokio::sync::oneshot::channel();
        queue.enqueue(key.into(), json("{}"), Some(sender), false);
        queue.enqueue(key.into(), json("received-after-clear"), None, false);
        queue.complete(key, Ok(()));
        assert!(matches!(
            cleared.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(queue.take_next(key), Some(json("{}")));
        queue.complete(key, Ok(()));
        cleared.await.unwrap().unwrap();
        assert_eq!(queue.take_next(key), Some(json("received-after-clear")));
        queue.complete(key, Ok(()));
        assert_eq!(queue.take_next(key), None);
    }

    #[tokio::test]
    async fn cache_identical_inflight_barriers_share_a_commit_and_real_failure() {
        let mut queue = CachePersistQueue::default();
        let key = "account-a";
        let (sender, first) = tokio::sync::oneshot::channel();
        assert!(queue.enqueue(key.into(), json("snapshot"), Some(sender), false));
        assert_eq!(queue.take_next(key), Some(json("snapshot")));
        let (sender, duplicate) = tokio::sync::oneshot::channel();
        assert!(!queue.enqueue(key.into(), json("snapshot"), Some(sender), false));
        queue.complete(key, Err("IndexedDB quota denied".into()));
        assert_eq!(first.await.unwrap(), Err("IndexedDB quota denied".into()));
        assert_eq!(
            duplicate.await.unwrap(),
            Err("IndexedDB quota denied".into())
        );
        assert_eq!(queue.take_next(key), None);
        let (sender, retried) = tokio::sync::oneshot::channel();
        assert!(queue.enqueue(key.into(), json("snapshot"), Some(sender), true));
        assert_eq!(queue.take_next(key), Some(json("snapshot")));
        queue.complete(key, Ok(()));
        retried.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cache_commit_shortcut_is_account_scoped_and_invalidated_by_backend_change() {
        let mut queue = CachePersistQueue::default();
        queue.enqueue("account-a".into(), json("snapshot"), None, false);
        queue.take_next("account-a");
        queue.complete("account-a", Ok(()));
        assert_eq!(queue.take_next("account-a"), None);
        let (sender, committed) = tokio::sync::oneshot::channel();
        assert!(!queue.enqueue("account-a".into(), json("snapshot"), Some(sender), true));
        committed.await.unwrap().unwrap();
        assert!(queue.enqueue("account-b".into(), json("snapshot"), None, true));
        assert!(queue.enqueue("account-a".into(), json("snapshot"), None, false));
        assert_eq!(queue.take_next("account-b"), Some(json("snapshot")));
        assert_eq!(queue.take_next("account-a"), Some(json("snapshot")));
    }

    #[tokio::test]
    async fn cache_delete_and_replacement_have_distinct_exact_barriers() {
        let mut queue = CachePersistQueue::default();
        let (sender, deleted) = tokio::sync::oneshot::channel();
        assert!(queue.enqueue("account-a".into(), None, Some(sender), false));
        assert_eq!(queue.take_next("account-a"), Some(None));
        let (sender, mut replacement) = tokio::sync::oneshot::channel();
        assert!(!queue.enqueue("account-a".into(), json("new"), Some(sender), false));
        queue.complete("account-a", Ok(()));
        deleted.await.unwrap().unwrap();
        assert!(matches!(
            replacement.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(queue.take_next("account-a"), Some(json("new")));
        queue.complete("account-a", Ok(()));
        replacement.await.unwrap().unwrap();
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
