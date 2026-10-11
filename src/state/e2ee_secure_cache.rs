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
    previous_drafts: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    hydration_fence: Arc<CacheClearFence>,
    lifecycle_epoch: u64,
    registry: Arc<Mutex<CacheClearFences>>,
}

#[derive(Debug, Default)]
pub(super) struct CacheClearFences {
    active: BTreeMap<String, CacheClearLease>,
    lifecycle_epoch: u64,
    generations: BTreeMap<String, u64>,
    recoveries: BTreeMap<String, CacheRecoveryRecord>,
    capture_sequence: u64,
    cleared_scopes: BTreeMap<String, BTreeMap<Option<String>, u64>>,
}

#[derive(Debug)]
struct CacheClearLease {
    key: String,
    scope: E2eePlaintextCacheClearScope,
    recovering: bool,
}

#[derive(Clone, Debug)]
struct CacheRecoveryRecord {
    key: String,
    lifecycle_epoch: u64,
    backup: E2eePlaintextCacheV1,
    fence: Option<Arc<CacheClearFence>>,
}

#[derive(Clone)]
struct CacheCaptureProvenance {
    key: String,
    registry: Arc<Mutex<CacheClearFences>>,
    lifecycle_epoch: u64,
    generation: u64,
    pending_clear: Option<String>,
    sequence: u64,
}

/// The provenance of an authored UI intent before it waits behind another
/// durable write. A clear in the same session must not re-label old input.
#[derive(Clone)]
pub(crate) struct E2eeCacheWriteIntent {
    key: String,
    realm: String,
    lifecycle_epoch: u64,
    generation: u64,
    registry: Arc<Mutex<CacheClearFences>>,
}

pub(crate) struct CapturedE2eeCacheWrite {
    pub(crate) key: String,
    pub(crate) json: Option<String>,
    provenance: CacheCaptureProvenance,
}

#[derive(Debug)]
struct CacheClearFence {
    id: String,
    registry: std::sync::Weak<Mutex<CacheClearFences>>,
}

impl Drop for CacheClearFence {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .remove(&self.id);
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
async fn complete_cache_clear(
    committed: tokio::sync::oneshot::Receiver<Result<(), String>>,
    fence: Arc<CacheClearFence>,
    reply: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    let result = committed
        .await
        .map_err(|error| error.to_string())
        .and_then(|result| result);
    drop(fence);
    let _ = reply.send(result);
}

impl PendingE2eePlaintextClear {
    fn recovery(&self) -> CacheClearRecovery {
        CacheClearRecovery {
            key: self.key.clone(),
            cleared_json: self.json.clone(),
            backup: E2eePlaintextCacheV1 {
                private_plaintext: self.previous_private.clone(),
                decrypted_plaintext: self.previous_decrypted.clone(),
                authenticated_identity_links: self.previous_identity_links.clone(),
                composer_drafts: self.previous_drafts.clone(),
                ..Default::default()
            },
            lifecycle_epoch: self.lifecycle_epoch,
            registry: self.registry.clone(),
            clear_id: self.hydration_fence.id.clone(),
            fence: Some(self.hydration_fence.clone()),
        }
    }

    pub(crate) async fn persist(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            // A page navigation can cancel the UI waiter. Keep the hydration
            // fence until the shared writer commits, independently of that scope.
            // Enqueue before spawning the waiter so later authored input is
            // always persisted after this exact clear snapshot.
            let committed = cache_persist_driver::enqueue_clear_exact(
                self.key.clone(),
                Some(self.json.clone()),
                self.recovery(),
            );
            let fence = self.hydration_fence.clone();
            let (reply, wait) = tokio::sync::oneshot::channel();
            wasm_bindgen_futures::spawn_local(complete_cache_clear(committed, fence, reply));
            let _ = secure_store;
            return wait
                .await
                .context("secure-cache clear writer stopped")?
                .map_err(anyhow::Error::msg)
                .context("persist cleared E2EE plaintext cache");
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let result = LocalStateStore::persist_e2ee_plaintext_cache_write_durable(
                secure_store,
                &self.key,
                Some(&self.json),
            )
            .await
            .context("persist cleared E2EE plaintext cache");
            if result.is_err() {
                let owner = self.recovery();
                owner.publish();
                if owner.current(&self.key) {
                    // Native default writes are synchronous Keyring operations.
                    // Re-read the backend so any newer input wins over the backup.
                    let recovery = secure_store
                        .get_secret(&self.key)
                        .map_err(|error| error.to_string())
                        .and_then(|current| owner.reconcile(&current).map(|json| (current, json)));
                    if let Ok((current, json)) = recovery {
                        if current == json
                            || LocalStateStore::persist_e2ee_plaintext_cache_write_durable(
                                secure_store,
                                &self.key,
                                json.as_deref(),
                            )
                            .await
                            .is_ok()
                        {
                            owner.release_recovery_lease();
                        }
                    }
                }
            }
            result
        }
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
    #[serde(default)]
    composer_drafts: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
}

impl E2eePlaintextCacheV1 {
    fn retain_committed_fields(&mut self, current: &Self) {
        fn nested(
            old: &mut BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
            current: &BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
        ) {
            old.retain(|outer, middle| {
                let Some(now) = current.get(outer) else {
                    return false;
                };
                middle.retain(|key, fields| {
                    let Some(now) = now.get(key) else {
                        return false;
                    };
                    fields.retain(|field, value| {
                        if let Some(latest) = now.get(field) {
                            *value = latest.clone();
                            true
                        } else {
                            false
                        }
                    });
                    !fields.is_empty()
                });
                !middle.is_empty()
            });
        }
        nested(&mut self.private_plaintext, &current.private_plaintext);
        nested(&mut self.composer_drafts, &current.composer_drafts);
        self.decrypted_plaintext.retain(|realm, entries| {
            let Some(now) = current.decrypted_plaintext.get(realm) else {
                return false;
            };
            entries.retain(|key, value| {
                if let Some(latest) = now.get(key) {
                    *value = latest.clone();
                    true
                } else {
                    false
                }
            });
            !entries.is_empty()
        });
        self.authenticated_identity_links.retain(|key, value| {
            if let Some(latest) = current.authenticated_identity_links.get(key) {
                *value = latest.clone();
                true
            } else {
                false
            }
        });
    }

    fn fill_missing_from(&mut self, backup: &Self) {
        for (realm, strands) in &backup.private_plaintext {
            for (strand, fields) in strands {
                let current = self
                    .private_plaintext
                    .entry(realm.clone())
                    .or_default()
                    .entry(strand.clone())
                    .or_default();
                for (field, body) in fields {
                    current.entry(field.clone()).or_insert_with(|| body.clone());
                }
            }
        }
        for (realm, entries) in &backup.decrypted_plaintext {
            let current = self.decrypted_plaintext.entry(realm.clone()).or_default();
            for (event, body) in entries {
                current.entry(event.clone()).or_insert_with(|| body.clone());
            }
        }
        for (id, link) in &backup.authenticated_identity_links {
            self.authenticated_identity_links
                .entry(id.clone())
                .or_insert_with(|| link.clone());
        }
        for (device, realms) in &backup.composer_drafts {
            for (realm, strands) in realms {
                let current = self
                    .composer_drafts
                    .entry(device.clone())
                    .or_default()
                    .entry(realm.clone())
                    .or_default();
                for (strand, body) in strands {
                    current
                        .entry(strand.clone())
                        .or_insert_with(|| body.clone());
                }
            }
        }
    }

    fn exclude_clear_scope(&mut self, scope: &E2eePlaintextCacheClearScope) {
        match scope {
            E2eePlaintextCacheClearScope::All => {
                self.private_plaintext.clear();
                self.decrypted_plaintext.clear();
                self.authenticated_identity_links.clear();
                self.composer_drafts.clear();
            }
            E2eePlaintextCacheClearScope::Realm(realm) => {
                self.private_plaintext.remove(realm);
                self.decrypted_plaintext.remove(realm);
                self.authenticated_identity_links
                    .retain(|_, entry| entry.identity_link.realm_id.as_str() != realm);
                for realms in self.composer_drafts.values_mut() {
                    realms.remove(realm);
                }
            }
        }
    }

    fn from_state(state: &ClientLocalState) -> Self {
        Self {
            mls_local_checkpoints: state.mls_local_checkpoints.clone(),
            private_plaintext: state.mls_private_plaintext.clone(),
            decrypted_plaintext: state.mls_decrypted_plaintext.clone(),
            authenticated_identity_links: state.authenticated_identity_links.clone(),
            composer_drafts: state.composer_drafts.clone(),
        }
    }

    /// Copy only this secure entry's fields, with the same receive-overlay
    /// precedence as the complete state used by durable account persistence.
    fn from_receive_fields(state: &ClientLocalState, overlay: &MlsReceiveOverlay) -> Self {
        let mut cache = Self::from_state(state);
        cache.apply_receive_overlay(overlay);
        cache
    }

    fn apply_receive_overlay(&mut self, overlay: &MlsReceiveOverlay) {
        for (key, checkpoint) in &overlay.snapshots {
            self.mls_local_checkpoints
                .insert(key.clone(), checkpoint.clone());
        }
        for (realm, entries) in &overlay.plaintexts {
            self.decrypted_plaintext
                .entry(realm.clone())
                .or_default()
                .extend(entries.clone());
        }
        self.authenticated_identity_links
            .extend(overlay.identity_links.clone());
    }

    fn is_empty(&self) -> bool {
        self.mls_local_checkpoints.is_empty()
            && self.private_plaintext.is_empty()
            && self.decrypted_plaintext.is_empty()
            && self.authenticated_identity_links.is_empty()
            && self.composer_drafts.is_empty()
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
        for realms in self.composer_drafts.values() {
            for (realm_id, strands) in realms {
                let realm = usage.realms.entry(realm_id.clone()).or_default();
                realm.authored_entries +=
                    strands.values().filter(|draft| !draft.is_empty()).count();
                realm.plaintext_bytes += strands.values().map(String::len).sum::<usize>();
            }
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
        for (device, realms) in self.composer_drafts {
            for (realm, strands) in realms {
                let current = state
                    .composer_drafts
                    .entry(device.clone())
                    .or_default()
                    .entry(realm)
                    .or_default();
                for (strand, draft) in strands {
                    current.entry(strand).or_insert_with(|| {
                        changed = true;
                        draft
                    });
                }
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
    pub(crate) fn capture_e2ee_cache_write_intent(
        &self,
        realm: &str,
    ) -> anyhow::Result<E2eeCacheWriteIntent> {
        let key = self
            .active_e2ee_plaintext_cache_key()
            .context("composer account cache is unavailable")?;
        let registry = self
            .e2ee_cache_clears
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        Ok(E2eeCacheWriteIntent {
            realm: realm.to_owned(),
            lifecycle_epoch: registry.lifecycle_epoch,
            generation: registry.generations.get(&key).copied().unwrap_or_default(),
            key,
            registry: self.e2ee_cache_clears.clone(),
        })
    }

    pub(crate) fn validate_e2ee_cache_write_intent(
        &self,
        intent: &E2eeCacheWriteIntent,
        realm: &str,
    ) -> anyhow::Result<()> {
        let registry = self
            .e2ee_cache_clears
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        anyhow::ensure!(
            Arc::ptr_eq(&self.e2ee_cache_clears, &intent.registry)
                && self.active_e2ee_plaintext_cache_key().as_ref() == Some(&intent.key)
                && registry.lifecycle_epoch == intent.lifecycle_epoch
                && intent.realm == realm
                && !registry
                    .cleared_scopes
                    .get(&intent.key)
                    .into_iter()
                    .flat_map(|scopes| scopes.iter())
                    .any(
                        |(cleared_realm, generation)| *generation > intent.generation
                            && (cleared_realm.is_none() || cleared_realm.as_deref() == Some(realm))
                    ),
            "composer intent predates a cache clear or account lifecycle change"
        );
        Ok(())
    }

    pub(super) fn initialize_e2ee_cache_generation(&mut self) {
        // Fresh account loads are not old in-memory clones. Historical clears
        // cannot delete secure values written durably after those clears.
        if let Some(key) = self.active_e2ee_plaintext_cache_key() {
            let generation = self
                .e2ee_cache_clears
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .generations
                .get(&key)
                .copied()
                .unwrap_or_default();
            self.e2ee_cache_clear_generations_seen
                .insert(key, generation);
        }
    }

    pub(super) fn absorb_e2ee_cache_recoveries(&mut self) {
        let Some(key) = self.active_e2ee_plaintext_cache_key() else {
            return;
        };
        let (generation, scopes, records) = {
            let registry = self
                .e2ee_cache_clears
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let generation = registry.generations.get(&key).copied().unwrap_or_default();
            let seen = self
                .e2ee_cache_clear_generations_seen
                .get(&key)
                .copied()
                .unwrap_or_default();
            let scopes = registry
                .cleared_scopes
                .get(&key)
                .into_iter()
                .flat_map(|scopes| scopes.iter())
                .filter(|(_, generation)| **generation > seen)
                .map(|(realm, _)| {
                    realm
                        .as_ref()
                        .map(|realm| E2eePlaintextCacheClearScope::Realm(realm.clone()))
                        .unwrap_or(E2eePlaintextCacheClearScope::All)
                })
                .collect::<Vec<_>>();
            let records = registry
                .recoveries
                .iter()
                .filter(|(id, record)| {
                    record.key == key
                        && record.lifecycle_epoch == registry.lifecycle_epoch
                        && !self.e2ee_cache_reconciliations_seen.contains(*id)
                })
                .map(|(id, record)| (id.clone(), record.backup.clone()))
                .collect::<Vec<_>>();
            (generation, scopes, records)
        };
        if !scopes.is_empty() {
            let mut cache = E2eePlaintextCacheV1::from_state(&self.cached);
            for scope in scopes {
                cache.exclude_clear_scope(&scope);
            }
            self.cached.mls_private_plaintext = cache.private_plaintext;
            self.cached.mls_decrypted_plaintext = cache.decrypted_plaintext;
            self.cached.authenticated_identity_links = cache.authenticated_identity_links;
            self.cached.composer_drafts = cache.composer_drafts;
        }
        self.e2ee_cache_clear_generations_seen
            .insert(key, generation);
        for (id, backup) in records {
            backup.merge_into(&mut self.cached, &BTreeSet::new(), &BTreeSet::new());
            self.e2ee_cache_reconciliations_seen.insert(id);
        }
    }

    fn capture_cache_write(
        &self,
        key: String,
        json: Option<String>,
    ) -> anyhow::Result<CapturedE2eeCacheWrite> {
        let mut registry = self
            .e2ee_cache_clears
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let seen = self
            .e2ee_cache_clear_generations_seen
            .get(&key)
            .copied()
            .unwrap_or_default();
        let scopes = registry
            .cleared_scopes
            .get(&key)
            .into_iter()
            .flat_map(|scopes| scopes.iter())
            .filter(|(_, generation)| **generation > seen)
            .map(|(realm, _)| {
                realm
                    .as_ref()
                    .map(|realm| E2eePlaintextCacheClearScope::Realm(realm.clone()))
                    .unwrap_or(E2eePlaintextCacheClearScope::All)
            })
            .collect::<Vec<_>>();
        let unseen = registry
            .recoveries
            .iter()
            .filter(|(id, record)| {
                record.key == key
                    && record.lifecycle_epoch == registry.lifecycle_epoch
                    && !self.e2ee_cache_reconciliations_seen.contains(*id)
            })
            .map(|(_, record)| record.backup.clone())
            .collect::<Vec<_>>();
        registry.capture_sequence = registry
            .capture_sequence
            .checked_add(1)
            .expect("secure-cache capture sequence exhausted");
        let provenance = CacheCaptureProvenance {
            key: key.clone(),
            registry: self.e2ee_cache_clears.clone(),
            lifecycle_epoch: registry.lifecycle_epoch,
            generation: registry.generations.get(&key).copied().unwrap_or_default(),
            pending_clear: registry
                .active
                .iter()
                .find(|(_, lease)| lease.key == key && !lease.recovering)
                .map(|(id, _)| id.clone()),
            sequence: registry.capture_sequence,
        };
        drop(registry);
        let mut json = json;
        if !scopes.is_empty() {
            let cache = self.with_mls_receive_fields(|state, overlay| {
                let mut cache = E2eePlaintextCacheV1::from_state(state);
                for scope in &scopes {
                    cache.exclude_clear_scope(scope);
                }
                for backup in &unseen {
                    cache.fill_missing_from(backup);
                }
                cache.apply_receive_overlay(overlay);
                cache
            });
            json = Some(serde_json::to_string(&cache)?);
        } else if !unseen.is_empty() {
            let mut cache: E2eePlaintextCacheV1 = json
                .as_ref()
                .map(|json| serde_json::from_str(json))
                .transpose()?
                .unwrap_or_default();
            for backup in unseen {
                cache.fill_missing_from(&backup);
            }
            json = Some(serde_json::to_string(&cache)?);
        }
        Ok(CapturedE2eeCacheWrite {
            key,
            json,
            provenance,
        })
    }

    pub(crate) fn capture_e2ee_plaintext_cache_secure_write(
        &self,
    ) -> anyhow::Result<Option<CapturedE2eeCacheWrite>> {
        self.e2ee_plaintext_cache_secure_write()?
            .map(|(key, json)| self.capture_cache_write(key, json))
            .transpose()
    }

    pub(crate) fn prepare_composer_draft_write_captured(
        &mut self,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        realm: &str,
        strand: &str,
        draft: String,
    ) -> anyhow::Result<CapturedE2eeCacheWrite> {
        let (key, json) =
            self.prepare_composer_draft_write(authority, device, realm, strand, draft)?;
        self.capture_cache_write(key, json)
    }

    /// Commit this authored snapshot through the shared writer. Failed-clear
    /// reconciliation can add missing prior scoped fields before activation;
    /// it never changes authored values. The waiter observes that actual
    /// transaction, or an explicit stale/superseded error, not another write.
    pub(crate) async fn persist_captured_e2ee_cache_write_durable(
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        write: CapturedE2eeCacheWrite,
    ) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = secure_store;
            cache_persist_driver::persist_captured(write).await
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let json = write
                .provenance
                .reconcile(&write.key, &write.json)
                .map_err(anyhow::Error::msg)?;
            Self::persist_e2ee_plaintext_cache_write_durable(
                secure_store,
                &write.key,
                json.as_deref(),
            )
            .await?;
            write.provenance.committed(&write.key, &json);
            Ok(())
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn clear_stored_composer_drafts(
        &self,
        secure: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<()> {
        let Some(key) = self.active_e2ee_plaintext_cache_key() else {
            return Ok(());
        };
        let Some(json) = secure.get_secret(&key)? else {
            return Ok(());
        };
        let mut cache: E2eePlaintextCacheV1 = serde_json::from_str(&json)?;
        if cache.composer_drafts.is_empty() {
            return Ok(());
        }
        cache.composer_drafts.clear();
        secure.store_secret(&key, &serde_json::to_string(&cache)?)?;
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn clear_stored_composer_drafts_on_reset(&self) {
        #[cfg(not(test))]
        if let Err(error) = self.clear_stored_composer_drafts(
            crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
        ) {
            tracing::warn!(
                ?error,
                "composer drafts could not be cleared from this device"
            );
        }
    }

    pub(crate) fn composer_draft(
        &mut self,
        device: &arkret_sdk::DeviceId,
        realm: &str,
        strand: &str,
    ) -> String {
        self.ensure_cached_loaded();
        self.cached
            .composer_drafts
            .get(device.as_str())
            .and_then(|realms| realms.get(realm))
            .and_then(|strands| strands.get(strand))
            .cloned()
            .unwrap_or_default()
    }

    /// The caller must bind the device and session to the authenticated context.
    pub(crate) fn prepare_composer_draft_write(
        &mut self,
        authority: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
        realm: &str,
        strand: &str,
        draft: String,
    ) -> anyhow::Result<(String, Option<String>)> {
        anyhow::ensure!(
            self.active_authority().as_ref() == Some(authority),
            "composer account is no longer active"
        );
        self.ensure_cached_loaded();
        self.cached_account_key_for_persist()?;
        anyhow::ensure!(
            !realm.is_empty() && !strand.is_empty(),
            "composer target is missing"
        );
        // Empty strings are explicit clears. Keeping the entry prevents a late
        // secure-cache hydration from resurrecting text already sent or erased.
        self.cached
            .composer_drafts
            .entry(device.to_string())
            .or_default()
            .entry(realm.to_owned())
            .or_default()
            .insert(strand.to_owned(), draft);
        self.e2ee_plaintext_cache_secure_write()?
            .ok_or_else(|| anyhow::anyhow!("composer account cache is unavailable"))
    }

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
        let cache = self.with_mls_receive_fields(E2eePlaintextCacheV1::from_receive_fields);
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
    #[cfg(any(test, not(target_arch = "wasm32")))]
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
        self.with_mls_receive_fields(E2eePlaintextCacheV1::from_receive_fields)
            .plaintext_usage()
    }

    /// Include all entries known only to the encrypted backend before clearing.
    /// Hydration applies pending clear fences and preserves newer live values.
    pub(crate) fn prepare_e2ee_plaintext_cache_clear_with_secure_store(
        &mut self,
        scope: &E2eePlaintextCacheClearScope,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<Option<PendingE2eePlaintextClear>> {
        self.ensure_e2ee_cache_clear_idle()?;
        self.hydrate_e2ee_plaintext_cache_with_secure_store(secure_store)?;
        self.prepare_e2ee_plaintext_cache_clear(scope)
    }

    /// Apply the in-memory clear and return the owned durable write. Callers
    /// using a shared state lock must release that lock before awaiting
    /// [`PendingE2eePlaintextClear::persist`].
    pub(crate) fn prepare_e2ee_plaintext_cache_clear(
        &mut self,
        scope: &E2eePlaintextCacheClearScope,
    ) -> anyhow::Result<Option<PendingE2eePlaintextClear>> {
        self.ensure_e2ee_cache_clear_idle()?;
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();

        let mut previous_private = self.cached.mls_private_plaintext.clone();
        let mut previous_decrypted = self.cached.mls_decrypted_plaintext.clone();
        let mut previous_identity_links = self.cached.authenticated_identity_links.clone();
        let mut previous_drafts = self.cached.composer_drafts.clone();
        let changed = match scope {
            E2eePlaintextCacheClearScope::All => {
                let changed = !self.cached.mls_private_plaintext.is_empty()
                    || !self.cached.mls_decrypted_plaintext.is_empty()
                    || !self.cached.authenticated_identity_links.is_empty()
                    || !self.cached.composer_drafts.is_empty();
                self.cached.mls_private_plaintext.clear();
                self.cached.mls_decrypted_plaintext.clear();
                self.cached.authenticated_identity_links.clear();
                self.cached.composer_drafts.clear();
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
                let mut removed_draft = false;
                for realms in self.cached.composer_drafts.values_mut() {
                    removed_draft |= realms.remove(realm_id).is_some();
                }
                removed_private
                    || removed_draft
                    || removed_decrypted
                    || retained != self.cached.authenticated_identity_links.len()
            }
        };
        if !changed {
            return Ok(None);
        }

        let write = self.e2ee_plaintext_cache_secure_write();
        if !matches!(&write, Ok(Some(_))) {
            self.cached.mls_private_plaintext = previous_private;
            self.cached.mls_decrypted_plaintext = previous_decrypted;
            self.cached.authenticated_identity_links = previous_identity_links;
            self.cached.composer_drafts = previous_drafts;
            if let Err(error) = write {
                return Err(error);
            }
            anyhow::bail!("cannot clear E2EE plaintext cache without an active account");
        }
        let (key, json) = write?.expect("checked secure-cache clear write");
        // Keep a minimal encrypted empty object instead of deleting the entry.
        if let E2eePlaintextCacheClearScope::Realm(realm) = scope {
            previous_private.retain(|id, _| id == realm);
            previous_decrypted.retain(|id, _| id == realm);
            previous_identity_links
                .retain(|_, entry| entry.identity_link.realm_id.as_str() == realm);
            for realms in previous_drafts.values_mut() {
                realms.retain(|id, _| id == realm);
            }
        }
        let id = crate::operation::uuid_v7();
        let mut fences = self
            .e2ee_cache_clears
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lifecycle_epoch = fences.lifecycle_epoch;
        let generation = fences.generations.entry(key.clone()).or_default();
        *generation = generation
            .checked_add(1)
            .expect("secure-cache clear generation exhausted");
        let generation = *generation;
        let realm = match scope {
            E2eePlaintextCacheClearScope::All => None,
            E2eePlaintextCacheClearScope::Realm(realm) => Some(realm.clone()),
        };
        fences
            .cleared_scopes
            .entry(key.clone())
            .or_default()
            .insert(realm, generation);
        for record in fences
            .recoveries
            .values_mut()
            .filter(|record| record.key == key)
        {
            record.backup.exclude_clear_scope(scope);
        }
        self.e2ee_cache_clear_generations_seen
            .insert(key.clone(), generation);
        fences.active.insert(
            id.clone(),
            CacheClearLease {
                key: key.clone(),
                scope: scope.clone(),
                recovering: false,
            },
        );
        Ok(Some(PendingE2eePlaintextClear {
            key,
            json: json.unwrap_or_else(|| "{}".to_owned()),
            previous_private,
            previous_decrypted,
            previous_identity_links,
            previous_drafts,
            hydration_fence: Arc::new(CacheClearFence {
                id,
                registry: Arc::downgrade(&self.e2ee_cache_clears),
            }),
            lifecycle_epoch,
            registry: self.e2ee_cache_clears.clone(),
        }))
    }

    pub(crate) fn rollback_e2ee_plaintext_cache_clear(
        &mut self,
        pending: PendingE2eePlaintextClear,
    ) {
        if self.active_e2ee_plaintext_cache_key().as_ref() != Some(&pending.key)
            || self
                .e2ee_cache_clears
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .lifecycle_epoch
                != pending.lifecycle_epoch
        {
            // A settings waiter may outlive an account change. Its failed clear
            // must never merge the previous account's plaintext into the new one.
            return;
        }
        self.ensure_cached_loaded();
        let id = pending.hydration_fence.id.clone();
        // A mutation may already have absorbed the independently published
        // backup and then legitimately removed a field. Never restore twice.
        if self.e2ee_cache_reconciliations_seen.insert(id) {
            pending.recovery().backup.merge_into(
                &mut self.cached,
                &BTreeSet::new(),
                &BTreeSet::new(),
            );
        }
    }

    fn ensure_e2ee_cache_clear_idle(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.active_authority().is_some(),
            "cannot clear an inactive account cache"
        );
        let Some(key) = self.active_e2ee_plaintext_cache_key() else {
            anyhow::bail!("cannot clear E2EE plaintext cache without an active account");
        };
        anyhow::ensure!(
            !self
                .e2ee_cache_clears
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .active
                .values()
                .any(|lease| lease.key == key),
            "an E2EE plaintext cache clear is already in progress for this account"
        );
        Ok(())
    }

    pub(super) fn invalidate_e2ee_cache_clear_rollback(&self) {
        let mut fences = self
            .e2ee_cache_clears
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        fences.lifecycle_epoch = fences
            .lifecycle_epoch
            .checked_add(1)
            .expect("secure-cache lifecycle epoch exhausted");
        let retired = std::mem::take(&mut fences.recoveries);
        drop(fences);
        drop(retired);
    }

    /// Convenience wrapper for callers that exclusively own the state value.
    #[cfg(test)]
    pub(crate) async fn clear_e2ee_plaintext_cache_with_secure_store(
        &mut self,
        scope: &E2eePlaintextCacheClearScope,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> anyhow::Result<bool> {
        let Some(pending) =
            self.prepare_e2ee_plaintext_cache_clear_with_secure_store(scope, secure_store)?
        else {
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
        let mut persisted: E2eePlaintextCacheV1 = match secure_store
            .get_secret(&key)
            .context("load E2EE plaintext cache from secure store")?
        {
            Some(json) => serde_json::from_str(&json).context("decode E2EE plaintext cache")?,
            None => E2eePlaintextCacheV1::default(),
        };
        for lease in self
            .e2ee_cache_clears
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .values()
        {
            if lease.key == key {
                persisted.exclude_clear_scope(&lease.scope);
            }
        }

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
            #[cfg(all(test, not(target_arch = "wasm32")))]
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
        self.cached.composer_drafts.clear();
    }

    pub(super) fn persist_e2ee_plaintext_cache_if_ready(&self) {
        #[cfg(target_arch = "wasm32")]
        {
            if !crate::secure_key_store::wasm_secure_store_ready() {
                return;
            }
            let write = match self.capture_e2ee_plaintext_cache_secure_write() {
                Ok(Some(write)) => write,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(?error, "E2EE plaintext cache encode failed");
                    return;
                }
            };
            cache_persist_driver::enqueue_captured_background(write);
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

struct CacheClearRecovery {
    key: String,
    cleared_json: String,
    backup: E2eePlaintextCacheV1,
    lifecycle_epoch: u64,
    registry: Arc<Mutex<CacheClearFences>>,
    clear_id: String,
    fence: Option<Arc<CacheClearFence>>,
}

impl CacheClearRecovery {
    fn recovery_provenance(&self) -> CacheCaptureProvenance {
        let registry = self.registry.lock().unwrap_or_else(|p| p.into_inner());
        CacheCaptureProvenance {
            key: self.key.clone(),
            registry: self.registry.clone(),
            lifecycle_epoch: self.lifecycle_epoch,
            generation: registry
                .generations
                .get(&self.key)
                .copied()
                .unwrap_or_default(),
            pending_clear: Some(self.clear_id.clone()),
            // Synthetic recovery is not an authored capture. It still obeys
            // key/epoch/generation validation, but has no supersession order.
            sequence: 0,
        }
    }
    fn publish(&self) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.lifecycle_epoch != self.lifecycle_epoch {
            return;
        }
        registry.recoveries.insert(
            self.clear_id.clone(),
            CacheRecoveryRecord {
                key: self.key.clone(),
                lifecycle_epoch: self.lifecycle_epoch,
                backup: self.backup.clone(),
                fence: self.fence.clone(),
            },
        );
        if let Some(lease) = registry.active.get_mut(&self.clear_id) {
            lease.recovering = true;
        }
    }

    fn release_recovery_lease(&self) {
        let lease = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry
                .recoveries
                .get_mut(&self.clear_id)
                .and_then(|record| record.fence.take())
        };
        drop(lease);
    }
    fn current(&self, key: &str) -> bool {
        self.key == key
            && self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .lifecycle_epoch
                == self.lifecycle_epoch
    }

    fn reconcile(&self, json: &Option<String>) -> Result<Option<String>, String> {
        // A later draft or an explicit empty-string tombstone wins. Restore
        // only fields removed by the failed clear, never MLS checkpoints.
        let mut cache: E2eePlaintextCacheV1 = match json {
            Some(json) => serde_json::from_str(json).map_err(|error| error.to_string())?,
            None => E2eePlaintextCacheV1::default(),
        };
        cache.fill_missing_from(&self.backup);
        serde_json::to_string(&cache)
            .map(Some)
            .map_err(|error| error.to_string())
    }
}

impl CacheCaptureProvenance {
    fn committed(&self, key: &str, json: &Option<String>) {
        let Ok(current) = json
            .as_ref()
            .map(|json| serde_json::from_str::<E2eePlaintextCacheV1>(json))
            .transpose()
        else {
            return;
        };
        let current = current.unwrap_or_default();
        let leases = {
            let mut registry = self
                .registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.key != key || registry.lifecycle_epoch != self.lifecycle_epoch {
                return;
            }
            registry
                .recoveries
                .values_mut()
                .filter(|record| {
                    record.key == key && record.lifecycle_epoch == self.lifecycle_epoch
                })
                .filter_map(|record| {
                    // Keep only surviving original fields, with their latest
                    // committed values. An unseen clone must not restore a
                    // field that a later normal mutation durably removed.
                    record.backup.retain_committed_fields(&current);
                    record.fence.take()
                })
                .collect::<Vec<_>>()
        };
        drop(leases);
    }
    fn reconcile(&self, key: &str, json: &Option<String>) -> Result<Option<String>, String> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.key != key
            || registry.lifecycle_epoch != self.lifecycle_epoch
            || registry.generations.get(key).copied().unwrap_or_default() != self.generation
        {
            return Err("secure-cache snapshot was captured before a clear or lifecycle change; capture current state again".into());
        }
        let Some(record) = self
            .pending_clear
            .as_ref()
            .and_then(|id| registry.recoveries.get(id))
        else {
            return Ok(json.clone());
        };
        if record.key != key || record.lifecycle_epoch != self.lifecycle_epoch {
            return Ok(json.clone());
        }
        let mut cache: E2eePlaintextCacheV1 = json
            .as_ref()
            .map(|json| serde_json::from_str(json))
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        cache.fill_missing_from(&record.backup);
        serde_json::to_string(&cache)
            .map(Some)
            .map_err(|error| error.to_string())
    }
}

#[cfg(any(test, target_arch = "wasm32"))]
#[derive(Default)]
struct CachePersistLane {
    active: Option<CachePersistWrite>,
    pending: std::collections::VecDeque<CachePersistWrite>,
    committed: Option<Option<[u8; 32]>>,
    recovery_attempted: bool,
    // Retains the lease only until a recovery really commits. Snapshot repair
    // provenance lives in the account registry, independently of UI scopes.
    recovery: Option<CacheClearRecovery>,
    newest_capture: u64,
}

#[cfg(any(test, target_arch = "wasm32"))]
struct CachePersistWrite {
    json: Option<String>,
    replies: Vec<CachePersistReply>,
    clear: Option<CacheClearRecovery>,
    provenance: Option<CacheCaptureProvenance>,
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

    /// Coalesce only background tail writes. Captured writes retain their
    /// authored fields and provenance; failed-clear recovery may fill missing
    /// old fields before activation. A newer capture never satisfies an older
    /// waiter, and stale provenance is rejected instead of reporting success.
    fn enqueue(
        &mut self,
        key: String,
        json: Option<String>,
        reply: Option<CachePersistReply>,
        durable_matches: bool,
    ) -> bool {
        self.enqueue_captured(key, json, reply, durable_matches, None)
    }

    fn enqueue_captured(
        &mut self,
        key: String,
        json: Option<String>,
        reply: Option<CachePersistReply>,
        durable_matches: bool,
        provenance: Option<CacheCaptureProvenance>,
    ) -> bool {
        let lane = self.lanes.entry(key).or_default();
        if let Some(provenance) = &provenance {
            if provenance.sequence != 0 && provenance.sequence < lane.newest_capture {
                if let Some(reply) = reply {
                    let _ = reply.send(Err(
                        "secure-cache snapshot was superseded by a newer capture".into(),
                    ));
                }
                return false;
            }
            lane.newest_capture = lane.newest_capture.max(provenance.sequence);
            if lane
                .pending
                .back()
                .is_some_and(|tail| tail.replies.is_empty() && tail.clear.is_none())
            {
                lane.pending.pop_back();
            }
        }
        if lane.active.is_none()
            && lane.pending.is_empty()
            && lane.committed == Some(Self::digest(&json))
            && durable_matches
            && lane.recovery.is_none()
            && provenance.is_none()
        {
            if let Some(reply) = reply {
                let _ = reply.send(Ok(()));
            }
            return false;
        }
        if provenance.is_none()
            && let Some(tail) = lane.pending.back_mut()
        {
            if tail.json == json {
                tail.replies.extend(reply);
                return false;
            }
            if tail.replies.is_empty() {
                lane.pending.pop_back();
            }
        } else if provenance.is_none()
            && let Some(active) = &mut lane.active
            && active.json == json
        {
            active.replies.extend(reply);
            return false;
        }
        let start = lane.active.is_none() && lane.pending.is_empty();
        lane.pending.push_back(CachePersistWrite {
            json,
            replies: reply.into_iter().collect(),
            clear: None,
            provenance,
        });
        start
    }

    fn enqueue_clear(
        &mut self,
        key: String,
        json: Option<String>,
        clear: CacheClearRecovery,
        reply: CachePersistReply,
    ) -> bool {
        let lane = self.lanes.entry(key).or_default();
        let start = lane.active.is_none() && lane.pending.is_empty();
        // Never coalesce a clear with an ordinary identical snapshot: its
        // failure owns a distinct recovery transaction and scope backup.
        lane.pending.push_back(CachePersistWrite {
            json,
            replies: vec![reply],
            clear: Some(clear),
            provenance: None,
        });
        start
    }

    fn take_next(&mut self, key: &str) -> Option<Option<String>> {
        let lane = self.lanes.get_mut(key)?;
        assert!(lane.active.is_none());
        loop {
            let mut next = if let Some(next) = lane.pending.pop_front() {
                next
            } else if !lane.recovery_attempted {
                let Some(clear) = lane.recovery.as_ref().filter(|clear| clear.current(key)) else {
                    lane.recovery = None;
                    break;
                };
                lane.recovery_attempted = true;
                CachePersistWrite {
                    json: Some(clear.cleared_json.clone()),
                    replies: Vec::new(),
                    clear: None,
                    provenance: Some(clear.recovery_provenance()),
                }
            } else {
                break;
            };
            if next.clear.is_some()
                || lane
                    .recovery
                    .as_ref()
                    .is_some_and(|clear| !clear.current(key))
            {
                lane.recovery = None;
            }
            if let Some(provenance) = &next.provenance {
                if provenance.sequence != 0 && provenance.sequence < lane.newest_capture {
                    for reply in next.replies {
                        let _ = reply.send(Err(
                            "secure-cache snapshot was superseded by a newer capture".into(),
                        ));
                    }
                    continue;
                }
                match provenance.reconcile(key, &next.json) {
                    Ok(json) => next.json = json,
                    Err(error) => {
                        for reply in next.replies {
                            let _ = reply.send(Err(error.clone()));
                        }
                        continue;
                    }
                }
            }
            lane.active = Some(next);
            break;
        }
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
        if result.is_err()
            && let Some(clear) = write.clear
        {
            if clear.current(key) {
                clear.publish();
                lane.recovery = Some(clear);
                lane.recovery_attempted = false;
            }
        } else if result.is_ok()
            && let Some(clear) = &mut lane.recovery
        {
            clear.release_recovery_lease();
            clear.fence.take();
            lane.recovery = None;
        }
        if result.is_ok()
            && let Some(provenance) = &write.provenance
        {
            provenance.committed(key, &write.json);
        }
        for reply in write.replies {
            let _ = reply.send(result.clone());
        }
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

#[cfg(target_arch = "wasm32")]
mod cache_persist_driver {
    use std::sync::{Mutex, OnceLock};

    use anyhow::Context as _;

    use super::CachePersistQueue;

    fn queue() -> &'static Mutex<CachePersistQueue> {
        static QUEUE: OnceLock<Mutex<CachePersistQueue>> = OnceLock::new();
        QUEUE.get_or_init(|| Mutex::new(CachePersistQueue::default()))
    }

    fn enqueue(
        key: String,
        json: Option<String>,
        reply: Option<super::CachePersistReply>,
        provenance: Option<super::CacheCaptureProvenance>,
        clear: Option<super::CacheClearRecovery>,
    ) {
        let store = crate::secure_key_store::default_secure_key_store("inkson");
        let durable_matches = store.get_secret(&key).ok().as_ref() == Some(&json);
        let mut queued = queue()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let start = if let Some(clear) = clear {
            queued.enqueue_clear(
                key.clone(),
                json,
                clear,
                reply.expect("clear has durable waiter"),
            )
        } else {
            queued.enqueue_captured(key.clone(), json, reply, durable_matches, provenance)
        };
        drop(queued);
        if start {
            // Reserve the active slot before spawning so two synchronous
            // publications cannot launch competing writers for the same key.
            let next = queue()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take_next(&key);
            if let Some(next) = next {
                wasm_bindgen_futures::spawn_local(drain(key, next));
            }
        }
    }

    pub(super) fn enqueue_captured_background(write: super::CapturedE2eeCacheWrite) {
        enqueue(write.key, write.json, None, Some(write.provenance), None);
    }

    pub(super) fn enqueue_clear_exact(
        key: String,
        json: Option<String>,
        clear: super::CacheClearRecovery,
    ) -> tokio::sync::oneshot::Receiver<Result<(), String>> {
        let (reply, wait) = tokio::sync::oneshot::channel();
        enqueue(key, json, Some(reply), None, Some(clear));
        wait
    }

    pub(super) async fn persist_captured(
        write: super::CapturedE2eeCacheWrite,
    ) -> anyhow::Result<()> {
        let (reply, wait) = tokio::sync::oneshot::channel();
        enqueue(
            write.key,
            write.json,
            Some(reply),
            Some(write.provenance),
            None,
        );
        wait.await
            .context("E2EE cache durable writer stopped")?
            .map_err(anyhow::Error::msg)
    }

    #[cfg(test)]
    pub(super) fn enqueue_exact(
        key: String,
        json: Option<String>,
    ) -> tokio::sync::oneshot::Receiver<Result<(), String>> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        enqueue(key, json, Some(sender), None, None);
        receiver
    }

    #[cfg(test)]
    pub(super) async fn persist_exact(key: String, json: Option<String>) -> anyhow::Result<()> {
        let receiver = enqueue_exact(key, json);
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

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn cancelled_clear_waiter_keeps_key_fence_until_writer_commit() {
        use crate::secure_key_store::{MemorySecureKeyStore, SecureKeyStore};

        let secure = MemorySecureKeyStore::default();
        let mut state = super::super::storage_util::isolated_store_for_tests("cancelled-clear");
        state.switch_test_account("did:web:alice.example");
        let authority = state.active_authority().unwrap();
        let device =
            crate::test_support::device_id("ak:device:01964137-0000-7000-8000-000000000001");
        state
            .prepare_composer_draft_write(&authority, &device, "realm", "chat", "old draft".into())
            .unwrap();
        state
            .persist_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        let pending = state
            .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                &E2eePlaintextCacheClearScope::All,
                &secure,
            )
            .unwrap()
            .unwrap();
        let key = pending.key.clone();
        let json = pending.json.clone();
        let (commit, committed) = tokio::sync::oneshot::channel();
        let (reply, waiter) = tokio::sync::oneshot::channel();
        let writer = tokio::spawn(complete_cache_clear(
            committed,
            pending.hydration_fence.clone(),
            reply,
        ));
        // Dioxus drops the page-local waiter and Pending on navigation. The
        // shared completion task still owns the key-bound read fence.
        drop(waiter);
        drop(pending);
        state.switch_test_account("did:web:bob.example");
        assert!(
            state
                .prepare_e2ee_plaintext_cache_clear(&E2eePlaintextCacheClearScope::All)
                .unwrap()
                .is_none()
        );
        state.switch_test_account("did:web:alice.example");
        state
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(state.composer_draft(&device, "realm", "chat"), "");
        assert!(
            state
                .prepare_e2ee_plaintext_cache_clear(&E2eePlaintextCacheClearScope::All)
                .is_err()
        );
        state
            .prepare_composer_draft_write(&authority, &device, "realm", "chat", "new draft".into())
            .unwrap();
        // Publish completion only after the actual backend commit.
        secure.store_secret_durable(&key, &json).await.unwrap();
        commit.send(Ok(())).unwrap();
        writer.await.unwrap();
        state
            .hydrate_e2ee_plaintext_cache_with_secure_store(&secure)
            .unwrap();
        assert_eq!(state.composer_draft(&device, "realm", "chat"), "new draft");
        assert!(
            state
                .prepare_e2ee_plaintext_cache_clear(&E2eePlaintextCacheClearScope::All)
                .unwrap()
                .is_some()
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    struct RecoveryTestStore {
        inner: crate::secure_key_store::MemorySecureKeyStore,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
        failures: std::sync::atomic::AtomicUsize,
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl crate::secure_key_store::SecureKeyStore for RecoveryTestStore {
        fn store_secret_bytes(
            &self,
            key: &str,
            value: &[u8],
        ) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
            self.inner.store_secret_bytes(key, value)
        }
        fn store_secret_bytes_durable<'a>(
            &'a self,
            key: &'a str,
            value: &'a [u8],
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<(), crate::secure_key_store::SecureKeyStoreError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let release = self.release.lock().unwrap().take();
                if let Some(release) = release {
                    release.await.unwrap();
                }
                if self
                    .failures
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                        left.checked_sub(1)
                    })
                    .is_ok()
                {
                    return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                        "injected cache transaction failure".into(),
                    ));
                }
                self.inner.store_secret_bytes(key, value)
            })
        }
        fn get_secret_bytes(
            &self,
            key: &str,
        ) -> Result<Option<arkret_sdk::KeyBytes>, crate::secure_key_store::SecureKeyStoreError>
        {
            self.inner.get_secret_bytes(key)
        }
        fn delete_secret(
            &self,
            key: &str,
        ) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
            self.inner.delete_secret(key)
        }
        fn list_secret_keys(
            &self,
            prefix: Option<&str>,
        ) -> Result<Vec<String>, crate::secure_key_store::SecureKeyStoreError> {
            self.inner.list_secret_keys(prefix)
        }
        fn backend_info(&self) -> garth::SecureKeyStoreBackendInfo {
            self.inner.backend_info()
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn recovery_fixture(
        label: &str,
        failures: usize,
    ) -> (LocalStateStore, RecoveryTestStore, arkret_sdk::DeviceId) {
        let mut state = super::super::storage_util::isolated_store_for_tests(label);
        state.switch_test_account("did:web:alice.example");
        let device =
            crate::test_support::device_id("ak:device:01964137-0000-7000-8000-000000000001");
        let authority = state.active_authority().unwrap();
        state
            .prepare_composer_draft_write(&authority, &device, "realm-a", "chat-a", "old A".into())
            .unwrap();
        state
            .prepare_composer_draft_write(
                &authority,
                &device,
                "realm-other",
                "chat-c",
                "untouched C".into(),
            )
            .unwrap();
        state.save_private_plaintext("realm-a", "chat-a", "body", "old plaintext A");
        let store = RecoveryTestStore {
            inner: Default::default(),
            release: Mutex::new(None),
            failures: failures.into(),
        };
        state
            .persist_e2ee_plaintext_cache_with_secure_store(&store)
            .unwrap();
        (state, store, device)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn queued_capture(
        queue: &mut CachePersistQueue,
        write: CapturedE2eeCacheWrite,
    ) -> tokio::sync::oneshot::Receiver<Result<(), String>> {
        let (reply, wait) = tokio::sync::oneshot::channel();
        queue.enqueue_captured(
            write.key,
            write.json,
            Some(reply),
            false,
            Some(write.provenance),
        );
        wait
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn queued_clear(
        queue: &mut CachePersistQueue,
        pending: &PendingE2eePlaintextClear,
    ) -> tokio::sync::oneshot::Receiver<Result<(), String>> {
        let (reply, wait) = tokio::sync::oneshot::channel();
        queue.enqueue_clear(
            pending.key.clone(),
            Some(pending.json.clone()),
            pending.recovery(),
            reply,
        );
        wait
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn commit_next(
        queue: &mut CachePersistQueue,
        key: &str,
        store: &RecoveryTestStore,
    ) -> Result<(), String> {
        use crate::secure_key_store::SecureKeyStore as _;
        let json = queue.take_next(key).expect("a real queued transaction");
        let result = match json {
            Some(json) => store.store_secret_durable(key, &json).await,
            None => store.delete_secret_durable(key).await,
        }
        .map_err(|e| e.to_string());
        queue.complete(key, result.clone());
        result
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn cold_reader(state: &LocalStateStore, store: &RecoveryTestStore) -> LocalStateStore {
        let mut cold = LocalStateStore::with_path(state.path.clone());
        cold.switch_test_account("did:web:alice.example");
        cold.hydrate_e2ee_plaintext_cache_with_secure_store(store)
            .unwrap();
        cold
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn failed_clear_restores_old_chat_and_queued_new_chat_even_if_ui_is_cancelled() {
        use crate::secure_key_store::SecureKeyStore as _;
        for scope in [
            E2eePlaintextCacheClearScope::All,
            E2eePlaintextCacheClearScope::Realm("realm-a".into()),
        ] {
            for cancel in [false, true] {
                let (mut state, store, device) = recovery_fixture("clear-recovery-trailing", 1);
                let authority = state.active_authority().unwrap();
                let pending = state
                    .prepare_e2ee_plaintext_cache_clear_with_secure_store(&scope, &store)
                    .unwrap()
                    .unwrap();
                let key = pending.key.clone();
                let mut queue = CachePersistQueue::default();
                let committed = queued_clear(&mut queue, &pending);
                let (reply, waiter) = tokio::sync::oneshot::channel();
                let completion = tokio::spawn(complete_cache_clear(
                    committed,
                    pending.hydration_fence.clone(),
                    reply,
                ));
                let mut pending = Some(pending);
                let mut waiter = Some(waiter);
                if cancel {
                    drop(waiter.take());
                    drop(pending.take());
                }
                let first = queue.take_next(&key).unwrap().unwrap();
                let (release, held) = tokio::sync::oneshot::channel();
                *store.release.lock().unwrap() = Some(held);
                let mut backend = Box::pin(store.store_secret_durable(&key, &first));
                assert!(futures_util::poll!(backend.as_mut()).is_pending());
                let write = state
                    .prepare_composer_draft_write_captured(
                        &authority,
                        &device,
                        "realm-a",
                        "chat-b",
                        "new B".into(),
                    )
                    .unwrap();
                let new_b = queued_capture(&mut queue, write);
                release.send(()).unwrap();
                let failure = backend.await.map_err(|e| e.to_string());
                assert!(failure.is_err());
                queue.complete(&key, failure);
                completion.await.unwrap();
                if let Some(waiter) = waiter {
                    assert!(waiter.await.unwrap().is_err());
                }
                assert!(state.ensure_e2ee_cache_clear_idle().is_err());
                commit_next(&mut queue, &key, &store).await.unwrap();
                new_b.await.unwrap().unwrap();
                if let Some(pending) = pending {
                    state.rollback_e2ee_plaintext_cache_clear(pending);
                }
                assert_eq!(state.composer_draft(&device, "realm-a", "chat-a"), "old A");
                assert_eq!(state.composer_draft(&device, "realm-a", "chat-b"), "new B");
                state.ensure_e2ee_cache_clear_idle().unwrap();
                let mut cold = cold_reader(&state, &store);
                assert_eq!(cold.composer_draft(&device, "realm-a", "chat-a"), "old A");
                assert_eq!(cold.composer_draft(&device, "realm-a", "chat-b"), "new B");
                assert_eq!(
                    cold.composer_draft(&device, "realm-other", "chat-c"),
                    "untouched C"
                );
                assert_eq!(
                    cold.cached.mls_private_plaintext["realm-a"]["chat-a"]["body"],
                    "old plaintext A"
                );
                assert_eq!(queue.take_next(&key), None);
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn failure_recovery_is_absorbed_once_before_real_delete_and_late_ui_rollback() {
        let (mut state, store, device) = recovery_fixture("clear-recovery-delete", 1);
        let authority = state.active_authority().unwrap();
        let pending = state
            .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                &E2eePlaintextCacheClearScope::All,
                &store,
            )
            .unwrap()
            .unwrap();
        let key = pending.key.clone();
        let mut not_yet_absorbed = state.clone();
        let mut queue = CachePersistQueue::default();
        let clear = queued_clear(&mut queue, &pending);
        // This whole snapshot was captured in the failed clear generation,
        // but reaches the writer after newer input and a legitimate deletion.
        let late = state
            .prepare_composer_draft_write_captured(
                &authority,
                &device,
                "realm-a",
                "chat-b",
                "early B".into(),
            )
            .unwrap();
        assert!(commit_next(&mut queue, &key, &store).await.is_err());
        assert!(clear.await.unwrap().is_err());
        state.save_private_plaintext("realm-a", "chat-a", "body", "");
        state
            .prepare_composer_draft_write(&authority, &device, "realm-a", "chat-a", String::new())
            .unwrap();
        let current = state
            .prepare_composer_draft_write_captured(
                &authority,
                &device,
                "realm-a",
                "chat-b",
                "latest B".into(),
            )
            .unwrap();
        state.rollback_e2ee_plaintext_cache_clear(pending);
        assert!(!state.cached.mls_private_plaintext.contains_key("realm-a"));
        let accepted = queued_capture(&mut queue, current);
        commit_next(&mut queue, &key, &store).await.unwrap();
        accepted.await.unwrap().unwrap();
        assert!(queued_capture(&mut queue, late).await.unwrap().is_err());
        assert_eq!(queue.take_next(&key), None);
        // A clone that missed completion sees surviving committed backup
        // fields, never the private field durably removed after recovery.
        assert_eq!(
            not_yet_absorbed.composer_draft(&device, "realm-a", "chat-a"),
            ""
        );
        assert!(
            !not_yet_absorbed
                .cached
                .mls_private_plaintext
                .contains_key("realm-a")
        );
        let mut cold = cold_reader(&state, &store);
        assert_eq!(cold.composer_draft(&device, "realm-a", "chat-a"), "");
        assert_eq!(
            cold.composer_draft(&device, "realm-a", "chat-b"),
            "latest B"
        );
        assert!(!cold.cached.mls_private_plaintext.contains_key("realm-a"));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn failed_recovery_stops_until_a_real_publication_then_restores_cold_cache() {
        for failures in [1, 2] {
            let (mut state, store, device) = recovery_fixture("clear-recovery-retry", failures);
            let authority = state.active_authority().unwrap();
            let before = state
                .capture_e2ee_plaintext_cache_secure_write()
                .unwrap()
                .unwrap();
            let pending = state
                .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                    &E2eePlaintextCacheClearScope::All,
                    &store,
                )
                .unwrap()
                .unwrap();
            let key = pending.key.clone();
            let mut queue = CachePersistQueue::default();
            let clear = queued_clear(&mut queue, &pending);
            // Filtering the only invalid successor must still schedule the
            // independent recovery, even with the page-local owner cancelled.
            let stale = queued_capture(&mut queue, before);
            drop(pending);
            assert!(commit_next(&mut queue, &key, &store).await.is_err());
            assert!(clear.await.unwrap().is_err());
            let restored = commit_next(&mut queue, &key, &store).await;
            assert!(stale.await.unwrap().is_err());
            assert_eq!(queue.take_next(&key), None);
            if failures == 2 {
                assert!(restored.is_err());
                assert!(state.ensure_e2ee_cache_clear_idle().is_err());
                let write = state
                    .prepare_composer_draft_write_captured(
                        &authority,
                        &device,
                        "realm-a",
                        "chat-b",
                        "retry B".into(),
                    )
                    .unwrap();
                let published = queued_capture(&mut queue, write);
                commit_next(&mut queue, &key, &store).await.unwrap();
                published.await.unwrap().unwrap();
            } else {
                restored.unwrap();
            }
            state.ensure_e2ee_cache_clear_idle().unwrap();
            let mut cold = cold_reader(&state, &store);
            assert_eq!(cold.composer_draft(&device, "realm-a", "chat-a"), "old A");
            if failures == 2 {
                assert_eq!(cold.composer_draft(&device, "realm-a", "chat-b"), "retry B");
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn successful_clear_rejects_old_capture_and_fresh_account_load_keeps_new_durable_input() {
        let (mut state, store, device) = recovery_fixture("clear-success-late", 0);
        let authority = state.active_authority().unwrap();
        let old = state
            .capture_e2ee_plaintext_cache_secure_write()
            .unwrap()
            .unwrap();
        let pending = state
            .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                &E2eePlaintextCacheClearScope::Realm("realm-a".into()),
                &store,
            )
            .unwrap()
            .unwrap();
        let key = pending.key.clone();
        let mut queue = CachePersistQueue::default();
        let clear = queued_clear(&mut queue, &pending);
        commit_next(&mut queue, &key, &store).await.unwrap();
        clear.await.unwrap().unwrap();
        drop(pending);
        let rejected = queued_capture(&mut queue, old);
        assert_eq!(queue.take_next(&key), None);
        assert!(rejected.await.unwrap().is_err());
        let write = state
            .prepare_composer_draft_write_captured(
                &authority,
                &device,
                "realm-a",
                "chat-a",
                "after clear".into(),
            )
            .unwrap();
        let saved = queued_capture(&mut queue, write);
        commit_next(&mut queue, &key, &store).await.unwrap();
        saved.await.unwrap().unwrap();
        state.switch_test_account("did:web:bob.example");
        state.switch_test_account("did:web:alice.example");
        state
            .hydrate_e2ee_plaintext_cache_with_secure_store(&store)
            .unwrap();
        assert_eq!(
            state.composer_draft(&device, "realm-a", "chat-a"),
            "after clear"
        );
        let mut cold = cold_reader(&state, &store);
        assert_eq!(
            cold.composer_draft(&device, "realm-a", "chat-a"),
            "after clear"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn lifecycle_change_rejects_queued_failure_recovery_without_cross_account_restore() {
        use crate::secure_key_store::SecureKeyStore as _;
        for reset in [false, true] {
            let (mut state, store, device) = recovery_fixture("clear-recovery-epoch", 1);
            let pending = state
                .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                    &E2eePlaintextCacheClearScope::All,
                    &store,
                )
                .unwrap()
                .unwrap();
            let key = pending.key.clone();
            let mut queue = CachePersistQueue::default();
            let clear = queued_clear(&mut queue, &pending);
            assert!(commit_next(&mut queue, &key, &store).await.is_err());
            assert!(clear.await.unwrap().is_err());
            let before = store.get_secret(&key).unwrap();
            if reset {
                state.clear_device_scoped();
            } else {
                state.switch_test_account("did:web:bob.example");
                state.switch_test_account("did:web:alice.example");
            }
            state.rollback_e2ee_plaintext_cache_clear(pending);
            assert_eq!(queue.take_next(&key), None);
            assert_eq!(store.get_secret(&key).unwrap(), before);
            assert_eq!(state.composer_draft(&device, "realm-a", "chat-a"), "");
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn delayed_composer_drain_rejects_old_intent_but_saves_real_input_after_clear() {
        use crate::secure_key_store::SecureKeyStore as _;
        let (mut state, store, device) = recovery_fixture("clear-pending-intent", 0);
        let authority = state.active_authority().unwrap();
        let initial = state
            .capture_e2ee_plaintext_cache_secure_write()
            .unwrap()
            .unwrap();
        let key = initial.key.clone();
        let mut queue = CachePersistQueue::default();
        let first = queued_capture(&mut queue, initial);
        let bytes = queue.take_next(&key).unwrap().unwrap();
        let (release, held) = tokio::sync::oneshot::channel();
        *store.release.lock().unwrap() = Some(held);
        let mut backend = Box::pin(store.store_secret_durable(&key, &bytes));
        assert!(futures_util::poll!(backend.as_mut()).is_pending());
        // The UI has queued raw text while its drain awaits a previous write.
        let old_intent = state.capture_e2ee_cache_write_intent("realm-a").unwrap();
        let other_realm_intent = state
            .capture_e2ee_cache_write_intent("realm-other")
            .unwrap();
        let pending = state
            .prepare_e2ee_plaintext_cache_clear_with_secure_store(
                &E2eePlaintextCacheClearScope::Realm("realm-a".into()),
                &store,
            )
            .unwrap()
            .unwrap();
        let cleared = queued_clear(&mut queue, &pending);
        let after_clear = state.e2ee_plaintext_cache_secure_write().unwrap();
        assert!(
            state
                .validate_e2ee_cache_write_intent(&old_intent, "realm-a")
                .is_err()
        );
        // Rejected intent never reaches hydrate/prepare, so old text is not
        // installed in memory or re-labeled with the new clear generation.
        assert_eq!(
            state.e2ee_plaintext_cache_secure_write().unwrap(),
            after_clear
        );
        state
            .validate_e2ee_cache_write_intent(&other_realm_intent, "realm-other")
            .unwrap();
        state
            .hydrate_e2ee_plaintext_cache_with_secure_store(&store)
            .unwrap();
        let other_write = state
            .prepare_composer_draft_write_captured(
                &authority,
                &device,
                "realm-other",
                "chat-c",
                "queued other Realm input".into(),
            )
            .unwrap();
        let other_saved = queued_capture(&mut queue, other_write);
        release.send(()).unwrap();
        queue.complete(&key, backend.await.map_err(|e| e.to_string()));
        first.await.unwrap().unwrap();
        commit_next(&mut queue, &key, &store).await.unwrap();
        cleared.await.unwrap().unwrap();
        drop(pending);
        commit_next(&mut queue, &key, &store).await.unwrap();
        other_saved.await.unwrap().unwrap();
        let new_intent = state.capture_e2ee_cache_write_intent("realm-a").unwrap();
        state
            .validate_e2ee_cache_write_intent(&new_intent, "realm-a")
            .unwrap();
        let write = state
            .prepare_composer_draft_write_captured(
                &authority,
                &device,
                "realm-a",
                "chat-a",
                "genuine new input".into(),
            )
            .unwrap();
        let saved = queued_capture(&mut queue, write);
        commit_next(&mut queue, &key, &store).await.unwrap();
        saved.await.unwrap().unwrap();
        let mut cold = cold_reader(&state, &store);
        assert_eq!(
            cold.composer_draft(&device, "realm-a", "chat-a"),
            "genuine new input"
        );
        assert_eq!(
            cold.composer_draft(&device, "realm-other", "chat-c"),
            "queued other Realm input"
        );
    }

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
