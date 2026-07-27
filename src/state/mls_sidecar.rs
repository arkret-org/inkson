use super::*;

const MAX_HISTORICAL_MLS_AUTHOR_STATES: usize = 32;

fn historical_mls_state_key(effective_scope_key: &str, group_id: &str, epoch: u64) -> String {
    format!("{epoch:020}\u{1f}{effective_scope_key}\u{1f}{group_id}")
}

fn prune_historical_mls_author_states(state: &mut ClientLocalState) {
    while state.mls_historical_group_state_refs.len() > MAX_HISTORICAL_MLS_AUTHOR_STATES
        || state.mls_historical_snapshots.len() > MAX_HISTORICAL_MLS_AUTHOR_STATES
    {
        let oldest = state
            .mls_historical_group_state_refs
            .keys()
            .chain(state.mls_historical_snapshots.keys())
            .min()
            .cloned();
        let Some(oldest) = oldest else {
            break;
        };
        state.mls_historical_group_state_refs.remove(&oldest);
        state.mls_historical_snapshots.remove(&oldest);
    }
}

fn attach_group_state_ref_to_snapshot(
    state: &mut ClientLocalState,
    effective_scope_key: &str,
    record: &MlsGroupStateRefRecord,
) -> bool {
    let Some(snapshot) = state.mls_snapshots.get_mut(effective_scope_key) else {
        return false;
    };
    if snapshot.group_id != record.group_id
        || snapshot.epoch != record.epoch
        || snapshot.group_state_event_id.as_ref() == Some(&record.event_id)
    {
        return false;
    }
    snapshot.group_state_event_id = Some(record.event_id.clone());
    true
}

fn projection_mls_genesis_event_id(
    state: &ClientLocalState,
    realm_id: &str,
    circle_id: Option<&str>,
    group_id: &str,
) -> Option<arkret_sdk::EventId> {
    let projection = state.realm_tree_projections.get(realm_id)?;
    let events = projection
        .get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)?;
    events.iter().find_map(|event| {
        let kind = event
            .get("kind")
            .or_else(|| event.get("event_kind"))
            .and_then(Value::as_str)?;
        if kind != arkret_sdk::events::EventKind::MLS_GENESIS {
            return None;
        }
        if event
            .get("realm_id")
            .and_then(Value::as_str)
            .is_some_and(|event_realm_id| event_realm_id != realm_id)
        {
            return None;
        }
        let payload = event
            .get("payload")
            .or_else(|| event.get("content"))
            .unwrap_or(event);
        if payload.get("epoch").and_then(Value::as_u64) != Some(0) {
            return None;
        }
        let event_group_id = payload
            .get("mls_group_id")
            .or_else(|| event.get("target_ref"))
            .and_then(Value::as_str)?;
        if event_group_id != group_id {
            return None;
        }
        let effective_scope = payload.get("effective_scope")?;
        if effective_scope.get("realm_id").and_then(Value::as_str) != Some(realm_id) {
            return None;
        }
        match circle_id {
            Some(circle_id) => {
                if effective_scope.get("kind").and_then(Value::as_str) != Some("circle")
                    || effective_scope.get("circle_id").and_then(Value::as_str) != Some(circle_id)
                {
                    return None;
                }
            }
            None => {
                if effective_scope.get("kind").and_then(Value::as_str) != Some("realm") {
                    return None;
                }
            }
        }
        event
            .get("event_id")
            .and_then(Value::as_str)
            .and_then(|event_id| arkret_sdk::EventId::new(event_id.to_owned()).ok())
    })
}

/// A history-secret update assembled but not yet published. The owned value
/// survives while the durable secure-store write is in flight without making
/// the secret observable through `LocalStateStore` prematurely.
#[derive(Clone, Debug)]
pub(crate) struct PendingHistorySecrets {
    realm_id: String,
    by_epoch: BTreeMap<u64, Vec<u8>>,
    new_secret_count: usize,
}

impl PendingHistorySecrets {
    pub(crate) fn new_secret_count(&self) -> usize {
        self.new_secret_count
    }

    pub(crate) async fn persist(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> Result<(), crate::secure_key_store::SecureKeyStoreError> {
        // Serialize the read/merge/write sequence so two concurrent installs
        // from the same process cannot overwrite different epochs that were
        // both prepared from an older durable snapshot.
        static HISTORY_SECRET_WRITE_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        let _guard = HISTORY_SECRET_WRITE_LOCK
            .get_or_init(|| tokio::sync::Mutex::new(()))
            .lock()
            .await;
        let key = crate::secure_key_store::mls_history_secret_store_key(&self.realm_id);
        let mut merged = secure_store
            .get_secret(&key)?
            .as_deref()
            .map(crate::secure_key_store::decode_history_secrets_json)
            .unwrap_or_default();
        merged.extend(self.by_epoch.clone());
        crate::secure_key_store::persist_realm_history_secrets(
            secure_store,
            &self.realm_id,
            &merged,
        )
        .await
    }
}

impl LocalStateStore {
    // ── MLS group state persistence ─────────────────────────────────

    /// Persist (or replace) the MLS snapshot envelope for a Realm.
    /// Idempotent: a re-snapshot at the same epoch overwrites the
    /// previous record. The on-disk envelope is opaque to soland —
    /// device-secret-derived encryption keeps the server zero-knowledge
    /// of the underlying group keys.
    pub fn save_mls_snapshot(
        &mut self,
        realm_id: impl Into<String>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) {
        self.save_mls_snapshot_for_effective_scope(realm_id, None, envelope);
    }

    pub fn save_mls_snapshot_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        mut envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) {
        // YOU-02-004: order this write after any decrypt write-backs so the
        // overlay can never shadow it (overlay snapshots always derive from
        // the state this caller just read via `mls_snapshot_for`).
        self.absorb_mls_receive_overlay();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        if let Some(record) = self.cached.mls_group_state_refs.get(&key)
            && record.group_id == envelope.group_id
            && record.epoch == envelope.epoch
        {
            envelope.group_state_event_id = Some(record.event_id.clone());
        }
        if let Some(current) = self.cached.mls_snapshots.get(&key)
            && current.group_id == envelope.group_id
            && current.epoch < envelope.epoch
        {
            let history_key = historical_mls_state_key(&key, &current.group_id, current.epoch);
            self.cached
                .mls_historical_snapshots
                .insert(history_key, current.clone());
        }
        self.cached.mls_snapshots.insert(key, envelope);
        prune_historical_mls_author_states(&mut self.cached);
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
    }

    /// Look up the latest MLS snapshot envelope for a Realm, if any.
    /// Returns `None` when the Realm has not yet been snapshotted (a
    /// fresh group on this device, or a group that has not committed
    /// yet so there is no state to persist).
    pub fn mls_snapshot_for(
        &self,
        realm_id: &str,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        self.mls_snapshot_for_effective_scope(realm_id, None)
    }

    pub fn mls_snapshot_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load().mls_snapshots.get(&key).cloned()
    }

    pub fn historical_mls_snapshot_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
        group_id: &str,
        epoch: u64,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        let scope_key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        let history_key = historical_mls_state_key(&scope_key, group_id, epoch);
        self.load()
            .mls_historical_snapshots
            .get(&history_key)
            .cloned()
    }

    // ── MLS history-secret persistence (history sharing) ────────────

    /// Assemble an aggregated update without publishing it. The caller must
    /// await [`PendingHistorySecrets::persist`] and only then call
    /// [`Self::publish_history_secrets`].
    pub(crate) fn prepare_history_secrets(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        realm_id: impl Into<String>,
        secrets: impl IntoIterator<Item = (u64, Vec<u8>)>,
    ) -> Result<Option<PendingHistorySecrets>, crate::secure_key_store::SecureKeyStoreError> {
        let realm_id = realm_id.into();
        let key = crate::secure_key_store::mls_history_secret_store_key(&realm_id);
        let mut by_epoch = secure_store
            .get_secret(&key)?
            .as_deref()
            .map(crate::secure_key_store::decode_history_secrets_json)
            .unwrap_or_default();
        if let Some(inline) = self.cached.history_secrets.get(&realm_id) {
            by_epoch.extend(
                inline
                    .iter()
                    .map(|(epoch, secret)| (*epoch, secret.clone())),
            );
        }
        let mut new_secret_count = 0;
        for (epoch, secret) in secrets {
            if !secret.is_empty() {
                by_epoch.insert(epoch, secret);
                new_secret_count += 1;
            }
        }
        Ok((new_secret_count > 0).then_some(PendingHistorySecrets {
            realm_id,
            by_epoch,
            new_secret_count,
        }))
    }

    /// Publish an update after its secure-store write succeeds.
    pub(crate) fn publish_history_secrets(&mut self, pending: PendingHistorySecrets) {
        self.cached
            .history_secrets
            .entry(pending.realm_id)
            .or_default()
            .extend(pending.by_epoch);
    }

    /// All installed `history_secret`s for `realm_id`, as `(epoch, secret)`
    /// pairs ordered by epoch. Used by the tier-3 history decrypt retry to
    /// try every granted epoch key against a pre-join ciphertext.
    pub fn history_secrets_for(&self, realm_id: &str) -> Vec<(u64, Vec<u8>)> {
        let realm_id = realm_id.trim();
        let mut merged: BTreeMap<u64, Vec<u8>> =
            crate::secure_key_store::load_realm_history_secrets(realm_id).unwrap_or_default();
        if let Some(inline) = self.load().history_secrets.get(realm_id) {
            for (epoch, secret) in inline {
                // The in-process copy is the value most recently accepted by
                // this client. It must override a stale durable value when the
                // preceding secure-store write failed after an older value had
                // already been persisted.
                merged.insert(*epoch, secret.clone());
            }
        }
        merged.into_iter().collect()
    }

    /// The installed `history_secret` for an exact `(realm, epoch)`, if any.
    pub fn history_secret_for(&self, realm_id: &str, epoch: u64) -> Option<Vec<u8>> {
        let realm_id = realm_id.trim();
        // The in-process copy is newer than any durable value read after a
        // failed secure-store update, so consult it first. It is never written
        // into account-state JSON; the hardened store remains the restart
        // source of truth.
        if let Some(secret) = self
            .load()
            .history_secrets
            .get(realm_id)
            .and_then(|by_epoch| by_epoch.get(&epoch))
        {
            return Some(secret.clone());
        }
        if let Some(by_epoch) = crate::secure_key_store::load_realm_history_secrets(realm_id)
            && let Some(secret) = by_epoch.get(&epoch)
        {
            return Some(secret.clone());
        }
        None
    }

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known Realm's group in one pass and by
    /// device-recovery strands to enumerate the encrypted snapshots that
    /// can be restored for this device.
    pub fn mls_snapshots(&self) -> BTreeMap<String, crate::mls::persistence::MlsSnapshotEnvelope> {
        self.load().mls_snapshots
    }

    /// Drop the MLS snapshot for a Realm — used after a successful
    /// "rotate group" / "leave group" Move so the next boot doesn't
    /// try to rehydrate a stale leaf.
    pub fn drop_mls_snapshot(&mut self, realm_id: &str) {
        self.drop_mls_snapshot_for_effective_scope(realm_id, None);
    }

    pub fn drop_mls_snapshot_for_effective_scope(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) {
        self.absorb_mls_receive_overlay();
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        let dropped_snapshot = self.cached.mls_snapshots.remove(&key).is_some();
        let dropped_recovery = self
            .cached
            .mls_receive_recovery_snapshots
            .remove(&key)
            .is_some();
        // The decrypted-plaintext cache is keyed to ciphertext minted under
        // the dropped group state; it stays readable history (same lifetime
        // policy as the author sidecar) and is NOT wiped here.
        if dropped_snapshot || dropped_recovery {
            let _ = self.flush();
            self.persist_e2ee_plaintext_cache_if_ready();
        }
    }

    // ── YOU-02-004: MLS receive-chain persistence + plaintext cache ──
    //
    // `encryption-and-audit.md` §5.6 (normative): after every successful
    // decrypt of an application message the advanced MLS group state MUST
    // be persisted — the ratchet must never be replayed from an earlier
    // snapshot on the next decrypt. These entry points are deliberately
    // `&self` (interior mutability through [`MlsReceiveOverlay`]) because
    // the decrypt-on-read callers run inside render passes that only hold
    // a read borrow of the `SyncSignal<LocalStateStore>`.

    /// Acquire the receive-chain serialization guard. The caller holds it
    /// across the whole restore→decrypt→export→[`Self::advance_mls_receive_chain`]
    /// sequence so concurrent views can't both advance the same group from
    /// the same base snapshot.
    pub fn mls_decrypt_serial_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.lock_mls_decrypt_serial()
    }

    /// Look up a previously decrypted plaintext by the envelope's canonical
    /// `payload_digest`. Render paths consult this BEFORE attempting an MLS
    /// decrypt — after the receive chain advanced past a message, this cache
    /// is the only way to re-render it.
    pub fn mls_decrypted_plaintext_for(
        &self,
        realm_id: &str,
        payload_digest: &str,
    ) -> Option<Vec<u8>> {
        use base64::Engine as _;
        let encoded = {
            let overlay = self.lock_mls_receive_overlay();
            overlay
                .plaintexts
                .get(realm_id)
                .and_then(|entries| entries.get(payload_digest))
                .cloned()
        };
        let encoded = match encoded {
            Some(encoded) => encoded,
            None => self
                .load()
                .mls_decrypted_plaintext
                .get(realm_id)?
                .get(payload_digest)?
                .clone(),
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .ok()
    }

    /// Drop a cached remote-member MLS plaintext by payload digest.
    pub fn drop_mls_decrypted_plaintext(&mut self, realm_id: &str, payload_digest: &str) -> bool {
        let realm_id = realm_id.trim();
        let payload_digest = payload_digest.trim();
        if realm_id.is_empty() || payload_digest.is_empty() {
            return false;
        }
        self.absorb_mls_receive_overlay();
        let changed = remove_decrypted_plaintext_entry(
            &mut self.cached.mls_decrypted_plaintext,
            realm_id,
            payload_digest,
        );
        if changed {
            let _ = self.flush();
            self.persist_e2ee_plaintext_cache_if_ready();
        }
        changed
    }

    /// Drop local plaintext retained for a disappearing message.
    ///
    /// This removes the author's sidecar (`message:<message_id>`) and, when the
    /// encrypted envelope digest is known, the remote decrypt cache entry.
    pub fn drop_disappearing_message_plaintext(
        &mut self,
        realm_id: &str,
        strand_id: &str,
        message_id: &str,
        payload_digest: Option<&str>,
    ) -> bool {
        let realm_id = realm_id.trim();
        let strand_id = strand_id.trim();
        let message_id = message_id.trim();
        if realm_id.is_empty() || strand_id.is_empty() || message_id.is_empty() {
            return false;
        }
        self.absorb_mls_receive_overlay();
        let field_path = if message_id.starts_with("message:") {
            message_id.to_owned()
        } else {
            format!("message:{message_id}")
        };
        let mut changed = remove_private_plaintext_entry(
            &mut self.cached.mls_private_plaintext,
            realm_id,
            strand_id,
            &field_path,
        );
        if let Some(payload_digest) = payload_digest
            .map(str::trim)
            .filter(|payload_digest| !payload_digest.is_empty())
        {
            changed |= remove_decrypted_plaintext_entry(
                &mut self.cached.mls_decrypted_plaintext,
                realm_id,
                payload_digest,
            );
        }
        if changed {
            let _ = self.flush();
            self.persist_e2ee_plaintext_cache_if_ready();
        }
        changed
    }

    /// Persist a successful decrypt: the advanced (post-decrypt) snapshot
    /// envelope AND the decrypted plaintext (cached under `payload_digest`).
    /// Both are recorded through the shared overlay and immediately flushed
    /// to the backing store, so a restart never replays the ratchet from
    /// the pre-decrypt snapshot (§5.6 MUST) and the message stays readable.
    pub fn advance_mls_receive_chain(
        &self,
        realm_id: &str,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        self.advance_mls_receive_chain_for_effective_scope(
            realm_id,
            None,
            envelope,
            payload_digest,
            plaintext,
        );
    }

    pub fn advance_mls_receive_chain_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
        let scope_key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        let previous_snapshot = self.mls_snapshot_for_effective_scope(realm_id, circle_id);
        {
            let mut overlay = self.lock_mls_receive_overlay();
            if let Some(previous_snapshot) = previous_snapshot {
                overlay
                    .recovery_snapshots
                    .entry(scope_key.clone())
                    .or_insert(previous_snapshot);
            }
            overlay.snapshots.insert(scope_key, envelope);
            overlay
                .plaintexts
                .entry(realm_id.to_owned())
                .or_default()
                .insert(payload_digest.to_owned(), encoded);
        }
        // Persist NOW (merged via `effective_state_for_persist`). Failures
        // are latched into `persist_health` like every other persist; the
        // overlay still holds the advancement in memory so the session
        // itself never regresses.
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
    }

    /// True once a `ak.mls.genesis` event has been submitted for this Realm.
    pub fn mls_genesis_emitted_for(&self, realm_id: &str) -> bool {
        self.mls_genesis_emitted_for_effective_scope(realm_id, None)
    }

    pub fn mls_genesis_emitted_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> bool {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load().mls_genesis_emitted.contains(&key)
    }

    pub fn pending_mls_genesis_event_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<arkret_sdk::Event> {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load()
            .pending_mls_genesis_events
            .get(&key)
            .and_then(|event| serde_json::from_str(event).ok())
    }

    pub fn save_pending_mls_genesis_event_for_effective_scope(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
        event: arkret_sdk::Event,
    ) -> Result<(), serde_json::Error> {
        self.ensure_cached_loaded();
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.cached
            .pending_mls_genesis_events
            .insert(key, serde_json::to_string(&event)?);
        let _ = self.flush();
        Ok(())
    }

    pub fn clear_pending_mls_genesis_event_for_effective_scope(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) {
        self.ensure_cached_loaded();
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        if self
            .cached
            .pending_mls_genesis_events
            .remove(&key)
            .is_some()
        {
            let _ = self.flush();
        }
    }

    /// Record that a `ak.mls.genesis` event has been submitted for this
    /// Realm so it is never re-emitted (idempotent).
    pub fn mark_mls_genesis_emitted(&mut self, realm_id: impl Into<String>) {
        self.mark_mls_genesis_emitted_for_effective_scope(realm_id, None);
    }

    /// Record a successfully accepted `ak.mls.genesis` event and seed the
    /// local MLS group-state frontier with that accepted Event id. This lets an
    /// immediately-following self-update or AddMember commit cite a real
    /// `ak:event:*` base group-state ref before the next sync response arrives.
    pub fn mark_mls_genesis_emitted_with_event(
        &mut self,
        realm_id: impl Into<String>,
        genesis_event_id: &arkret_sdk::EventId,
    ) {
        self.mark_mls_genesis_emitted_for_effective_scope_with_event(
            realm_id,
            None,
            genesis_event_id,
        );
    }

    pub fn mark_mls_genesis_emitted_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        if self.cached.mls_genesis_emitted.insert(key) {
            let _ = self.flush();
        }
    }

    pub fn mark_mls_genesis_emitted_for_effective_scope_with_event(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        genesis_event_id: &arkret_sdk::EventId,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        let mut changed = self.cached.mls_genesis_emitted.insert(key);
        let pending_key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        changed |= self
            .cached
            .pending_mls_genesis_events
            .remove(&pending_key)
            .is_some();
        if let Some(snapshot) = self.cached.mls_snapshots.get(&pending_key) {
            let record = MlsGroupStateRefRecord {
                group_id: snapshot.group_id.clone(),
                epoch: 0,
                event_id: genesis_event_id.clone(),
            };
            if self.cached.mls_group_state_refs.get(&pending_key) != Some(&record) {
                self.cached
                    .mls_group_state_refs
                    .insert(pending_key.clone(), record.clone());
                changed = true;
            }
            changed |= attach_group_state_ref_to_snapshot(&mut self.cached, &pending_key, &record);
        }
        if changed {
            let _ = self.flush();
        }
    }

    /// Resolve the only valid MLS group-state reference for an exact local
    /// `(effective scope, group, epoch)` snapshot.
    pub fn mls_group_state_ref_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
        group_id: &str,
        epoch: u64,
    ) -> Result<arkret_sdk::EventId, String> {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        let state = self.load();
        let record = state
            .mls_group_state_refs
            .get(&key)
            .filter(|record| record.group_id == group_id && record.epoch == epoch)
            .cloned()
            .or_else(|| {
                let history_key = historical_mls_state_key(&key, group_id, epoch);
                state
                    .mls_historical_group_state_refs
                    .get(&history_key)
                    .cloned()
            })
            .or_else(|| {
                state
                    .mls_snapshots
                    .get(&key)
                    .filter(|snapshot| snapshot.group_id == group_id && snapshot.epoch == epoch)
                    .and_then(|snapshot| {
                        snapshot.group_state_event_id.clone().map(|event_id| {
                            MlsGroupStateRefRecord {
                                group_id: snapshot.group_id.clone(),
                                epoch: snapshot.epoch,
                                event_id,
                            }
                        })
                    })
            })
            .or_else(|| {
                let history_key = historical_mls_state_key(&key, group_id, epoch);
                state
                    .mls_historical_snapshots
                    .get(&history_key)
                    .filter(|snapshot| snapshot.group_id == group_id && snapshot.epoch == epoch)
                    .and_then(|snapshot| {
                        snapshot.group_state_event_id.clone().map(|event_id| {
                            MlsGroupStateRefRecord {
                                group_id: snapshot.group_id.clone(),
                                epoch: snapshot.epoch,
                                event_id,
                            }
                        })
                    })
            })
            .or_else(|| {
                (epoch == 0)
                    .then(|| projection_mls_genesis_event_id(&state, realm_id, circle_id, group_id))
                    .flatten()
                    .map(|event_id| MlsGroupStateRefRecord {
                        group_id: group_id.to_owned(),
                        epoch,
                        event_id,
                    })
            })
            .ok_or_else(|| {
                format!(
                    "accepted MLS group-state Event is unavailable for scope {key} at epoch {epoch}"
                )
            })?;
        if record.group_id != group_id || record.epoch != epoch {
            return Err(format!(
                "accepted MLS group-state Event does not match group {group_id} epoch {epoch}"
            ));
        }
        Ok(record.event_id)
    }

    /// Repair legacy/local state that remembers only the genesis-emitted flag.
    ///
    /// Older duplicate-genesis handling could set that flag without recording
    /// the already-accepted Event id. A durable Realm projection is accepted
    /// server state, so recover the exact epoch-0 reference only when its group
    /// and effective scope match the local executable snapshot.
    pub fn reconcile_mls_genesis_group_state_ref_from_projection(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Result<bool, String> {
        self.ensure_cached_loaded();
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        let Some(snapshot) = self.cached.mls_snapshots.get(&key).cloned() else {
            return Ok(false);
        };
        if snapshot.epoch != 0 {
            return Ok(false);
        }
        let Some(event_id) =
            projection_mls_genesis_event_id(&self.cached, realm_id, circle_id, &snapshot.group_id)
        else {
            return Ok(false);
        };
        self.record_mls_group_state_ref_for_effective_scope(
            realm_id.to_owned(),
            circle_id,
            &snapshot.group_id,
            0,
            event_id,
        )?;
        Ok(true)
    }

    /// Advance the canonical group-state reference after the matching genesis
    /// or commit Event has been accepted. Rollback and same-epoch forks fail
    /// closed and never overwrite the known winning reference.
    pub fn record_mls_group_state_ref_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        group_id: &str,
        epoch: u64,
        event_id: arkret_sdk::EventId,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id);
        if let Some(current) = self.cached.mls_group_state_refs.get(&key) {
            if current.group_id != group_id {
                return Err(format!(
                    "MLS group-state group conflict for scope {key}: {} != {group_id}",
                    current.group_id
                ));
            }
            if epoch < current.epoch {
                return Err(format!(
                    "MLS group-state rollback for scope {key}: {epoch} < {}",
                    current.epoch
                ));
            }
            if epoch == current.epoch {
                if current.event_id != event_id {
                    return Err(format!(
                        "MLS group-state fork for scope {key} epoch {epoch}"
                    ));
                }
                let current = current.clone();
                if attach_group_state_ref_to_snapshot(&mut self.cached, &key, &current) {
                    self.flush()
                        .map_err(|error| format!("persist MLS group-state reference: {error}"))?;
                }
                return Ok(());
            }
            let history_key = historical_mls_state_key(&key, &current.group_id, current.epoch);
            self.cached
                .mls_historical_group_state_refs
                .insert(history_key, current.clone());
        }
        let record = MlsGroupStateRefRecord {
            group_id: group_id.to_owned(),
            epoch,
            event_id,
        };
        self.cached
            .mls_group_state_refs
            .insert(key.clone(), record.clone());
        attach_group_state_ref_to_snapshot(&mut self.cached, &key, &record);
        prune_historical_mls_author_states(&mut self.cached);
        self.flush()
            .map_err(|error| format!("persist MLS group-state reference: {error}"))
    }

    /// X5.1 — persist the author's own plaintext for an encrypted private
    /// strand field into the local-only sidecar. `field_path` is the dotted
    /// private patch path (e.g. `"body"`, `"synthesis"`); `plaintext` is
    /// the JSON-serialized patch value the writer encrypted. Empty values
    /// are removed rather than stored so a cleared field doesn't keep a
    /// stale plaintext around (consistent with the `unset` write path).
    ///
    /// This data NEVER leaves the device — it is the only place the
    /// author's own encrypted content survives a re-projection, since the
    /// author can never decrypt their own MLS ciphertext.
    pub fn save_private_plaintext(
        &mut self,
        realm_id: &str,
        strand_id: &str,
        field_path: &str,
        plaintext: &str,
    ) {
        let realm_id = realm_id.trim();
        let strand_id = strand_id.trim();
        let field_path = field_path.trim();
        if realm_id.is_empty() || strand_id.is_empty() || field_path.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        if plaintext.is_empty() {
            // Cleared field: drop the sidecar entry (and prune empty maps).
            if let Some(strands) = self.cached.mls_private_plaintext.get_mut(realm_id)
                && let Some(fields) = strands.get_mut(strand_id)
            {
                if fields.remove(field_path).is_some() {
                    changed = true;
                }
                if fields.is_empty() {
                    strands.remove(strand_id);
                }
            }
            if let Some(strands) = self.cached.mls_private_plaintext.get(realm_id)
                && strands.is_empty()
            {
                self.cached.mls_private_plaintext.remove(realm_id);
            }
        } else {
            let slot = self
                .cached
                .mls_private_plaintext
                .entry(realm_id.to_owned())
                .or_default()
                .entry(strand_id.to_owned())
                .or_default()
                .entry(field_path.to_owned())
                .or_default();
            if *slot != plaintext {
                *slot = plaintext.to_owned();
                changed = true;
            }
        }
        if changed {
            let _ = self.flush();
            self.persist_e2ee_plaintext_cache_if_ready();
        }
    }

    /// X5.1 — read back a single author-owned plaintext field from the
    /// local sidecar, if present. Returns `None` when no plaintext was
    /// ever stored for this (Realm, strand, field) — the read path then
    /// falls back to decrypting another member's ciphertext.
    pub fn private_plaintext_for(
        &self,
        realm_id: &str,
        strand_id: &str,
        field_path: &str,
    ) -> Option<String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|strands| strands.get(strand_id.trim()))
            .and_then(|fields| fields.get(field_path.trim()))
            .filter(|plaintext| !plaintext.is_empty())
            .cloned()
    }

    /// X5.1 — all sidecar plaintext fields for a single strand (`field_path
    /// -> plaintext`). Convenience for callers that want to enumerate
    /// every stored field at once.
    pub fn private_plaintext_fields(
        &self,
        realm_id: &str,
        strand_id: &str,
    ) -> BTreeMap<String, String> {
        self.load()
            .mls_private_plaintext
            .get(realm_id.trim())
            .and_then(|strands| strands.get(strand_id.trim()))
            .cloned()
            .unwrap_or_default()
    }

    /// X5.3 — serialize the ENTIRE local-plaintext sidecar map
    /// (`realm -> strand -> field -> plaintext`) to JSON bytes for the encrypted
    /// cross-device backup. Returns the serialization of an empty map (`{}`)
    /// when no sidecar entries exist, so callers can cheaply detect "nothing to
    /// back up" via [`Self::private_plaintext_is_empty`] first.
    pub fn private_plaintext_snapshot_json(&self) -> Vec<u8> {
        serde_json::to_vec(&self.load().mls_private_plaintext).unwrap_or_else(|_| b"{}".to_vec())
    }

    /// X5.3 — true when the sidecar holds no plaintext for any Realm/strand/field.
    /// Used to skip the cross-device backup upload when there is nothing to
    /// protect.
    pub fn private_plaintext_is_empty(&self) -> bool {
        self.load().mls_private_plaintext.is_empty()
    }

    /// X5.3 — merge an incoming sidecar map (decrypted from a cross-device
    /// backup) into the local cache, then flush.
    ///
    /// Merge semantics: incoming entries only FILL fields that are missing
    /// locally; on a (Realm, strand, field) conflict the EXISTING LOCAL value is
    /// kept. Rationale: the local sidecar is written synchronously on every
    /// encrypted write by the author on THIS device, so a locally-present value
    /// is at least as fresh as the backup (which is only re-uploaded
    /// periodically). On a brand-new browser the local cache is empty, so the
    /// backup populates everything — the common restore case.
    pub fn merge_private_plaintext_map(
        &mut self,
        incoming: BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    ) {
        if incoming.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let mut changed = false;
        for (realm_id, strands) in incoming {
            let local_strands = self
                .cached
                .mls_private_plaintext
                .entry(realm_id)
                .or_default();
            for (strand_id, fields) in strands {
                let local_fields = local_strands.entry(strand_id).or_default();
                for (field_path, plaintext) in fields {
                    if plaintext.is_empty() {
                        continue;
                    }
                    // Keep existing local value on conflict; only fill gaps.
                    local_fields.entry(field_path).or_insert_with(|| {
                        changed = true;
                        plaintext
                    });
                }
            }
        }
        if changed {
            let _ = self.flush();
            self.persist_e2ee_plaintext_cache_if_ready();
        }
    }

    /// The genesis-locked MLS `policy_root` for this Realm's group, if recorded.
    ///
    /// See [`crate::state::types::PersistedState::mls_genesis_policy_root`]:
    /// every `ak.mls.commit` MUST declare the exact `policy_root` that
    /// `ak.mls.genesis` locked, or soland rejects it with
    /// `governance_binding_mismatch`. Commit builders read this so they reuse the
    /// locked bytes instead of recomputing from the moving Seal `state_root`.
    pub fn genesis_policy_root_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<String> {
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id);
        self.load().mls_genesis_policy_root.get(&key).cloned()
    }

    /// Record the genesis-locked MLS `policy_root` for this Realm's group.
    ///
    /// First-writer-wins: the value is locked at genesis and never changes for
    /// the life of the group (soland carries it forward unchanged), so a later
    /// call with a drifted root MUST NOT overwrite the genuine genesis value.
    pub fn record_genesis_policy_root_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        policy_root: &str,
    ) {
        let policy_root = policy_root.trim();
        if policy_root.is_empty() {
            return;
        }
        self.ensure_cached_loaded();
        let key = mls_effective_scope_snapshot_key(&realm_id.into(), circle_id);
        if self.cached.mls_genesis_policy_root.contains_key(&key) {
            return;
        }
        self.cached
            .mls_genesis_policy_root
            .insert(key, policy_root.to_owned());
        let _ = self.flush();
    }
}

pub(crate) fn mls_effective_scope_snapshot_key(realm_id: &str, circle_id: Option<&str>) -> String {
    match circle_id
        .map(str::trim)
        .filter(|circle_id| !circle_id.is_empty())
    {
        Some(circle_id) => circle_id.to_owned(),
        None => realm_id.to_owned(),
    }
}

fn remove_decrypted_plaintext_entry(
    plaintexts: &mut BTreeMap<String, BTreeMap<String, String>>,
    realm_id: &str,
    payload_digest: &str,
) -> bool {
    let Some(entries) = plaintexts.get_mut(realm_id) else {
        return false;
    };
    let changed = entries.remove(payload_digest).is_some();
    if entries.is_empty() {
        plaintexts.remove(realm_id);
    }
    changed
}

fn remove_private_plaintext_entry(
    plaintexts: &mut BTreeMap<String, BTreeMap<String, BTreeMap<String, String>>>,
    realm_id: &str,
    strand_id: &str,
    field_path: &str,
) -> bool {
    let Some(strands) = plaintexts.get_mut(realm_id) else {
        return false;
    };
    let Some(fields) = strands.get_mut(strand_id) else {
        return false;
    };
    let changed = fields.remove(field_path).is_some();
    if fields.is_empty() {
        strands.remove(strand_id);
    }
    if strands.is_empty() {
        plaintexts.remove(realm_id);
    }
    changed
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::LocalStateStore;
    use serde_json::json;

    #[test]
    fn persisted_snapshot_recovers_exact_group_state_reference_without_side_index() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-snapshot-reference-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let group_id = "010203";
        let event_id =
            arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000099").unwrap();
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 1,
            group_state_event_id: Some(event_id.clone()),
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };

        LocalStateStore::with_path(&path).save_mls_snapshot(realm_id, snapshot);
        let restored = LocalStateStore::with_path(&path);

        assert_eq!(
            restored
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 1)
                .unwrap(),
            event_id
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn accepted_genesis_projection_repairs_legacy_missing_group_state_reference() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-reference-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let group_id = "010203";
        let event_id =
            arkret_sdk::EventId::new("ak:event:01904100-0000-7000-8000-000000000099").unwrap();
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 0,
            group_state_event_id: None,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };
        let mut store = LocalStateStore::with_path(&path);
        store.save_mls_snapshot(realm_id, snapshot);
        store.save_realm_tree_projection(
            realm_id,
            json!({
                "state": {
                    "events": [{
                        "event_id": event_id,
                        "realm_id": realm_id,
                        "kind": "ak.mls.genesis",
                        "target_ref": group_id,
                        "payload": {
                            "mls_group_id": group_id,
                            "epoch": 0,
                            "effective_scope": {
                                "kind": "realm",
                                "realm_id": realm_id
                            }
                        }
                    }]
                }
            }),
        );

        assert_eq!(
            store
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 0)
                .unwrap(),
            event_id
        );
        assert!(
            store
                .reconcile_mls_genesis_group_state_ref_from_projection(realm_id, None)
                .unwrap()
        );
        let restored = LocalStateStore::with_path(&path);
        assert_eq!(
            restored
                .mls_snapshot_for(realm_id)
                .unwrap()
                .group_state_event_id,
            Some(event_id)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn genesis_projection_with_another_group_is_not_used_as_authoring_reference() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-mismatch-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let group_id = "010203";
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 0,
            group_state_event_id: None,
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };
        let mut store = LocalStateStore::with_path(&path);
        store.save_mls_snapshot(realm_id, snapshot);
        store.save_realm_tree_projection(
            realm_id,
            json!({
                "state": {
                    "events": [{
                        "event_id": "ak:event:01904100-0000-7000-8000-000000000099",
                        "realm_id": realm_id,
                        "kind": "ak.mls.genesis",
                        "payload": {
                            "mls_group_id": "different-group",
                            "epoch": 0,
                            "effective_scope": {
                                "kind": "realm",
                                "realm_id": realm_id
                            }
                        }
                    }]
                }
            }),
        );

        assert!(
            store
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 0)
                .is_err()
        );
        assert!(
            !store
                .reconcile_mls_genesis_group_state_ref_from_projection(realm_id, None)
                .unwrap()
        );
        let _ = std::fs::remove_file(path);
    }
}
