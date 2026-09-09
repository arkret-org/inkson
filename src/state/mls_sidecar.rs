use super::*;

const MAX_HISTORICAL_MLS_AUTHOR_STATES: usize = 32;

/// Whether two records retain the same epoch secret under the same accepted
/// MLS transition. `local_state_ref` is deliberately excluded: application
/// messages advance the within-epoch ratchet and therefore change the durable
/// snapshot digest without changing the epoch's exporter secret or its
/// Genesis/Commit winner tuple.
fn same_local_authoritative_history_secret(
    left: &arkret_sdk::LocalAuthoritativeHistorySecret,
    right: &arkret_sdk::LocalAuthoritativeHistorySecret,
) -> bool {
    left.effective_scope == right.effective_scope
        && left.mls_group_id == right.mls_group_id
        && left.epoch == right.epoch
        && left.mls_ciphersuite == right.mls_ciphersuite
        && left.transition_ref == right.transition_ref
        && left.transition_event_digest == right.transition_event_digest
        && left.mls_transition_digest == right.mls_transition_digest
        && left.secret_b64u == right.secret_b64u
}

fn merge_local_authoritative_history_secret(
    by_epoch: &mut BTreeMap<u64, arkret_sdk::LocalAuthoritativeHistorySecret>,
    epoch: u64,
    record: arkret_sdk::LocalAuthoritativeHistorySecret,
) -> Result<bool, crate::secure_key_store::SecureKeyStoreError> {
    if let Some(existing) = by_epoch.get(&epoch) {
        if same_local_authoritative_history_secret(existing, &record) {
            // Keep the first durable evidence handle. It already proves this
            // exact epoch secret and transition; a later within-epoch snapshot
            // is another valid handle, not a competing history secret.
            return Ok(false);
        }
        return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
            format!("conflicting local-authoritative history records for epoch {epoch}"),
        ));
    }
    by_epoch.insert(epoch, record);
    Ok(true)
}

fn historical_mls_state_key(effective_scope_key: &str, group_id: &str, epoch: u64) -> String {
    format!("{epoch:020}\u{1f}{effective_scope_key}\u{1f}{group_id}")
}

fn prune_historical_mls_author_states(state: &mut ClientLocalState) {
    while state.mls_historical_group_state_refs.len() > MAX_HISTORICAL_MLS_AUTHOR_STATES
        || state.mls_historical_checkpoints.len() > MAX_HISTORICAL_MLS_AUTHOR_STATES
    {
        let oldest = state
            .mls_historical_group_state_refs
            .keys()
            .chain(state.mls_historical_checkpoints.keys())
            .min()
            .cloned();
        let Some(oldest) = oldest else {
            break;
        };
        state.mls_historical_group_state_refs.remove(&oldest);
        state.mls_historical_checkpoints.remove(&oldest);
    }
}

fn attach_group_state_ref_to_snapshot(
    state: &mut ClientLocalState,
    effective_scope_key: &str,
    record: &MlsGroupStateRefRecord,
) -> bool {
    let Some(snapshot) = state.mls_local_checkpoints.get_mut(effective_scope_key) else {
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

#[derive(Clone, Debug)]
pub(crate) struct AcceptedMlsTransitionEvidence {
    pub(crate) effective_scope: arkret_sdk::HistoryEffectiveScope,
    pub(crate) local_state_ref: String,
    pub(crate) transition_ref: arkret_sdk::EventId,
    pub(crate) transition_event_digest: arkret_sdk::Hash,
    pub(crate) mls_transition_digest: arkret_sdk::Hash,
}

/// A history-secret update assembled but not yet published. The owned value
/// survives while the durable secure-store write is in flight without making
/// the secret observable through `LocalStateStore` prematurely.
#[derive(Clone, Debug)]
pub(crate) struct PendingHistorySecrets {
    scope_group_key: String,
    by_epoch: BTreeMap<u64, arkret_sdk::LocalAuthoritativeHistorySecret>,
}

impl PendingHistorySecrets {
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
        let key = crate::secure_key_store::mls_history_secret_store_key(&self.scope_group_key);
        let mut merged = secure_store
            .get_secret(&key)?
            .as_deref()
            .map(crate::secure_key_store::decode_history_secrets_json)
            .unwrap_or_default();
        for (epoch, record) in &self.by_epoch {
            merge_local_authoritative_history_secret(&mut merged, *epoch, record.clone())?;
        }
        crate::secure_key_store::persist_history_secrets(
            secure_store,
            &self.scope_group_key,
            &merged,
        )
        .await
    }
}

impl LocalStateStore {
    // ── MLS group state persistence ─────────────────────────────────

    pub(crate) fn accepted_mls_artifact_snapshot(
        &self,
    ) -> garth::VersionedAcceptedMlsArtifactState {
        self.load().accepted_mls_artifacts
    }

    /// Atomically publish the Station-accepted Garth artifact snapshot and
    /// mirror its ready states into the existing MLS lookup indexes. The
    /// returned barrier is the only success boundary used by the Garth CAS
    /// adapter; callers must await it before treating the group as ready.
    pub(crate) fn compare_and_swap_accepted_mls_artifacts(
        &mut self,
        expected_revision: u64,
        snapshot: &garth::AcceptedMlsArtifactState,
    ) -> Result<Option<LocalStatePersistBarrier>, String> {
        self.ensure_cached_loaded();
        if self.cached.accepted_mls_artifacts.revision != expected_revision {
            return Ok(None);
        }
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| "accepted MLS artifact revision overflow".to_owned())?;

        for (group_key, event_id) in &snapshot.ready_groups {
            let artifact = snapshot.artifacts.get(event_id).ok_or_else(|| {
                "accepted MLS ready index references a missing artifact".to_owned()
            })?;
            if artifact.snapshot.aead_version != 1
                || artifact.snapshot.group_state_event_id.as_ref()
                    != Some(&artifact.winning_transition_ref)
            {
                return Err("accepted MLS ready artifact is not winner-bound".to_owned());
            }
            // An unrelated artifact publication must not rewind this group's
            // receive ratchets or overwrite a locally staged next epoch.
            let previous = &self.cached.accepted_mls_artifacts.snapshot;
            if previous.ready_groups.get(group_key) == Some(event_id)
                && previous.artifacts.get(event_id) == Some(artifact)
            {
                continue;
            }
            let payload = serde_json::to_value(&artifact.event.payload)
                .map_err(|error| format!("encode accepted MLS Event payload: {error}"))?;
            let effective_scope = match artifact.event.kind {
                arkret_sdk::EventKind::MlsGenesis => {
                    serde_json::from_value::<arkret_sdk::MlsGenesisPayload>(payload)
                        .map_err(|error| format!("decode accepted MLS Genesis: {error}"))?
                        .effective_scope
                }
                arkret_sdk::EventKind::MlsCommit => {
                    serde_json::from_value::<arkret_sdk::MlsCommitPayload>(payload)
                        .map_err(|error| format!("decode accepted MLS Commit: {error}"))?
                        .governance_binding()
                        .effective_scope()
                        .clone()
                }
                arkret_sdk::EventKind::MlsWelcome => {
                    serde_json::from_value::<arkret_sdk::MlsWelcomePayload>(payload)
                        .map_err(|error| format!("decode accepted MLS Welcome: {error}"))?
                        .governance_binding
                        .effective_scope()
                        .clone()
                }
                _ => return Err("accepted MLS artifact has a non-MLS Event kind".to_owned()),
            };
            let scope_key =
                mls_scope_checkpoint_key_for_group(&effective_scope, &artifact.snapshot.group_id)?;
            let envelope = crate::mls::persistence::MlsLocalCheckpointEnvelope::from(
                artifact.snapshot.clone(),
            );
            if let Some(current) = self.cached.mls_local_checkpoints.get(&scope_key)
                && current.group_id == envelope.group_id
                && current.epoch != envelope.epoch
            {
                self.cached.mls_historical_checkpoints.insert(
                    historical_mls_state_key(&scope_key, &current.group_id, current.epoch),
                    current.clone(),
                );
            }
            self.cached
                .mls_local_checkpoints
                .insert(scope_key.clone(), envelope);
            self.cached.mls_group_state_refs.insert(
                scope_key,
                MlsGroupStateRefRecord {
                    group_id: artifact.snapshot.group_id.clone(),
                    epoch: artifact.snapshot.epoch,
                    event_id: artifact.winning_transition_ref.clone(),
                },
            );
        }
        prune_historical_mls_author_states(&mut self.cached);
        self.cached.accepted_mls_artifacts = garth::VersionedAcceptedMlsArtifactState {
            revision: next_revision,
            snapshot: snapshot.clone(),
        };
        self.begin_durable_flush()
            .map(Some)
            .map_err(|error| error.to_string())
    }

    /// Persist (or replace) the MLS snapshot envelope for a Realm.
    /// Idempotent: a re-snapshot at the same epoch overwrites the
    /// previous record. The on-disk envelope is opaque to soland —
    /// device-secret-derived encryption keeps the server zero-knowledge
    /// of the underlying group keys.
    pub fn save_mls_checkpoint(
        &mut self,
        realm_id: impl Into<String>,
        envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    ) -> Result<(), String> {
        self.save_mls_checkpoint_for_effective_scope(realm_id, None, envelope)
    }

    pub fn save_mls_checkpoint_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    ) -> Result<(), String> {
        let realm_id = realm_id.into();
        let scope = mls_realm_or_circle_scope(&realm_id, circle_id)?;
        self.save_mls_checkpoint_for_scope(&scope, envelope)
    }

    pub fn save_mls_checkpoint_for_scope(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        mut envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    ) -> Result<(), String> {
        // Order this write after any decrypt write-backs so the
        // overlay can never shadow it (overlay snapshots always derive from
        // the state this caller just read via `mls_checkpoint_for`).
        self.absorb_mls_receive_overlay();
        let key = mls_scope_checkpoint_key_for_group(effective_scope, &envelope.group_id)?;
        if let Some(current) = self.cached.mls_local_checkpoints.get(&key)
            && current.group_id == envelope.group_id
        {
            envelope.admission_epoch = current.admission_epoch;
            // Ratchet/history write-backs do not change the accepted epoch.
            // Re-encrypting the local state must retain its accepted-event
            // anchor even when the auxiliary group-state index is absent.
            if current.epoch == envelope.epoch && envelope.group_state_event_id.is_none() {
                envelope.group_state_event_id = current.group_state_event_id.clone();
            }
        }
        if let Some(record) = self.cached.mls_group_state_refs.get(&key)
            && record.group_id == envelope.group_id
            && record.epoch == envelope.epoch
        {
            envelope.group_state_event_id = Some(record.event_id.clone());
        }
        if let Some(current) = self.cached.mls_local_checkpoints.get(&key)
            && current.group_id == envelope.group_id
            && current.epoch < envelope.epoch
        {
            let history_key = historical_mls_state_key(&key, &current.group_id, current.epoch);
            self.cached
                .mls_historical_checkpoints
                .insert(history_key, current.clone());
        }
        self.cached.mls_local_checkpoints.insert(key, envelope);
        prune_historical_mls_author_states(&mut self.cached);
        let _ = self.flush();
        self.persist_e2ee_plaintext_cache_if_ready();
        Ok(())
    }

    /// Look up the latest MLS snapshot envelope for a Realm, if any.
    /// Returns `None` when the Realm has not yet been snapshotted (a
    /// fresh group on this device, or a group that has not committed
    /// yet so there is no state to persist).
    pub fn mls_checkpoint_for(
        &self,
        realm_id: &str,
    ) -> Option<crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        self.mls_checkpoint_for_effective_scope(realm_id, None)
    }

    pub fn mls_checkpoint_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        let scope = mls_realm_or_circle_scope(realm_id, circle_id).ok()?;
        self.mls_checkpoint_for_scope(&scope)
    }

    pub fn mls_checkpoint_for_scope(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
    ) -> Option<crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        match effective_scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{}\u{1f}", mls_scope_checkpoint_key(effective_scope).ok()?);
                self.load()
                    .mls_local_checkpoints
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .map(|(_, snapshot)| snapshot)
                    .max_by_key(|snapshot| snapshot.epoch)
                    .cloned()
            }
            _ => {
                let key = mls_scope_checkpoint_key(effective_scope).ok()?;
                self.load().mls_local_checkpoints.get(&key).cloned()
            }
        }
    }

    pub fn mls_checkpoint_for_scope_and_group(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
    ) -> Option<crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        let key = mls_scope_checkpoint_key_for_group(effective_scope, group_id).ok()?;
        self.load().mls_local_checkpoints.get(&key).cloned()
    }

    pub(crate) fn staged_mls_checkpoint_for_scope_and_group(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
    ) -> Option<crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        let key = mls_scope_checkpoint_key_for_group(effective_scope, group_id).ok()?;
        self.load().mls_local_checkpoints.get(&key).cloned()
    }

    pub fn historical_mls_checkpoint_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
        group_id: &str,
        epoch: u64,
    ) -> Option<crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        let scope_key = mls_effective_scope_checkpoint_key(realm_id, circle_id).ok()?;
        let history_key = historical_mls_state_key(&scope_key, group_id, epoch);
        self.load()
            .mls_historical_checkpoints
            .get(&history_key)
            .cloned()
    }

    // ── Local-authoritative MLS history-secret persistence ─────────

    /// Resolve the exact accepted transition tuple for a durable local MLS
    /// snapshot, using the Station result committed atomically with the crypto state.
    pub(crate) fn accepted_current_realm_mls_transition_evidence(
        &self,
        realm_id: &str,
    ) -> Result<AcceptedMlsTransitionEvidence, String> {
        let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
            .map_err(|error| format!("invalid Realm id for MLS transition evidence: {error}"))?;
        let effective_scope = arkret_sdk::ScopeRef::Realm { realm_id };
        let snapshot = self
            .mls_checkpoint_for_scope(&effective_scope)
            .ok_or_else(|| "Realm has no durable MLS snapshot".to_owned())?;
        self.accepted_mls_transition_evidence(
            &effective_scope,
            snapshot.group_id.as_str(),
            snapshot.epoch,
        )
    }

    /// Resolve the exact accepted transition tuple for a durable local MLS
    /// snapshot, using the Station result committed atomically with the crypto state.
    pub(crate) fn accepted_mls_transition_evidence(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Result<AcceptedMlsTransitionEvidence, String> {
        let history_scope = arkret_sdk::HistoryEffectiveScope::try_from(effective_scope.clone())
            .map_err(|error| error.to_string())?;
        if history_scope
            .canonical_mls_group_id()
            .map_err(|error| error.to_string())?
            != group_id
        {
            return Err("local MLS snapshot group id is not canonical for its scope".to_owned());
        }
        let snapshot = self
            .mls_checkpoint_for_scope_and_group(effective_scope, group_id)
            .ok_or_else(|| "local-authoritative export has no durable MLS snapshot".to_owned())?;
        if snapshot.epoch != epoch {
            return Err(
                "local-authoritative export epoch differs from durable MLS state".to_owned(),
            );
        }
        let transition_ref = snapshot.group_state_event_id.clone().ok_or_else(|| {
            "local-authoritative export has no accepted transition reference".to_owned()
        })?;
        let head = self
            .accepted_mls_epoch_head(effective_scope, group_id, epoch)?
            .ok_or_else(|| "Station-accepted MLS transition metadata is unavailable".to_owned())?;
        if head.transition_ref != transition_ref {
            return Err(
                "durable MLS snapshot differs from the Station-accepted transition".to_owned(),
            );
        }
        let transition_event_digest = head.transition_event_digest;
        let mls_transition_digest = head.mls_transition_digest;
        let snapshot_digest = arkret_sdk::canonical::canonical_sha256(&snapshot)
            .map_err(|error| error.to_string())?;
        Ok(AcceptedMlsTransitionEvidence {
            effective_scope: history_scope,
            local_state_ref: format!("inkson.mls_snapshot.v1:{snapshot_digest}"),
            transition_ref,
            transition_event_digest,
            mls_transition_digest,
        })
    }

    /// Assemble an aggregated update without publishing it. The caller must
    /// await [`PendingHistorySecrets::persist`] and only then call
    /// [`Self::publish_history_secrets`].
    pub(crate) fn prepare_history_secrets(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        records: impl IntoIterator<Item = arkret_sdk::LocalAuthoritativeHistorySecret>,
    ) -> Result<Option<PendingHistorySecrets>, crate::secure_key_store::SecureKeyStoreError> {
        let scope_group_key = mls_scope_checkpoint_key_for_group(effective_scope, group_id)
            .map_err(crate::secure_key_store::SecureKeyStoreError::Backend)?;
        let history_scope = arkret_sdk::HistoryEffectiveScope::try_from(effective_scope.clone())
            .map_err(|error| {
                crate::secure_key_store::SecureKeyStoreError::Backend(error.to_string())
            })?;
        let key = crate::secure_key_store::mls_history_secret_store_key(&scope_group_key);
        let mut by_epoch = secure_store
            .get_secret(&key)?
            .as_deref()
            .map(crate::secure_key_store::decode_history_secrets_json)
            .unwrap_or_default();
        let mut durable_update_needed = false;
        if let Some(inline) = self.cached.history_secrets.get(&scope_group_key) {
            for (epoch, secret) in inline {
                durable_update_needed |= merge_local_authoritative_history_secret(
                    &mut by_epoch,
                    *epoch,
                    secret.clone(),
                )?;
            }
        }
        for record in records {
            record.validate().map_err(|error| {
                crate::secure_key_store::SecureKeyStoreError::Backend(error.to_string())
            })?;
            if record.effective_scope != history_scope || record.mls_group_id != group_id {
                return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    "local-authoritative history record crosses its scope/group partition"
                        .to_owned(),
                ));
            }
            let epoch = record.epoch;
            durable_update_needed |=
                merge_local_authoritative_history_secret(&mut by_epoch, epoch, record)?;
        }
        Ok(durable_update_needed.then_some(PendingHistorySecrets {
            scope_group_key,
            by_epoch,
        }))
    }

    /// Publish an update after its secure-store write succeeds.
    pub(crate) fn publish_history_secrets(&mut self, pending: PendingHistorySecrets) {
        let suites = pending
            .by_epoch
            .iter()
            .map(|(epoch, record)| (*epoch, record.mls_ciphersuite.clone()))
            .collect::<Vec<_>>();
        self.cached
            .history_secrets
            .entry(pending.scope_group_key.clone())
            .or_default()
            .extend(pending.by_epoch);
        let by_epoch_suite = self
            .cached
            .history_epoch_cipher_suites
            .entry(pending.scope_group_key)
            .or_default();
        for (epoch, cipher_suite) in suites {
            by_epoch_suite.insert(epoch, cipher_suite);
        }
        let _ = self.flush();
    }

    /// The local-authoritative `history_secret` for an exact
    /// `(effective_scope, group_id, epoch)`, if any.
    pub fn history_secret_for(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Option<Vec<u8>> {
        let scope_group_key = mls_scope_checkpoint_key_for_group(effective_scope, group_id).ok()?;
        // The in-process copy is newer than any durable value read after a
        // failed secure-store update, so consult it first. It is never written
        // into account-state JSON; the hardened store remains the restart
        // source of truth.
        if let Some(secret) = self
            .load()
            .history_secrets
            .get(&scope_group_key)
            .and_then(|by_epoch| by_epoch.get(&epoch))
        {
            return arkret_sdk::base64url_decode(secret.secret_b64u.as_bytes()).ok();
        }
        if let Some(by_epoch) = crate::secure_key_store::load_history_secrets(&scope_group_key)
            && let Some(secret) = by_epoch.get(&epoch)
        {
            return arkret_sdk::base64url_decode(secret.secret_b64u.as_bytes()).ok();
        }
        self.accepted_local_authoritative_history_secret(effective_scope, group_id, epoch)
            .and_then(|secret| arkret_sdk::base64url_decode(secret.secret_b64u.as_bytes()).ok())
    }

    /// Return the replay-verified MLS ciphersuite bound to one retained epoch.
    pub fn history_epoch_cipher_suite(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Option<String> {
        let scope_group_key = mls_scope_checkpoint_key_for_group(effective_scope, group_id).ok()?;
        self.load()
            .history_epoch_cipher_suites
            .get(&scope_group_key)
            .and_then(|by_epoch| by_epoch.get(&epoch))
            .cloned()
            .or_else(|| {
                self.accepted_local_authoritative_history_secret(effective_scope, group_id, epoch)
                    .map(|secret| secret.mls_ciphersuite)
            })
    }

    fn accepted_local_authoritative_history_secret(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Option<arkret_sdk::LocalAuthoritativeHistorySecret> {
        let local = self.load();
        let queued = local
            .accepted_mls_artifacts
            .snapshot
            .history_secrets
            .values()
            .find(|secret| secret.group_id == group_id && secret.epoch == epoch)?;
        let envelope =
            serde_json::from_slice::<crate::mls::persistence::MlsLocalCheckpointEnvelope>(
                &queued.ciphertext,
            )
            .ok()?;
        let active = crate::secure_key_store::active_device_seed_scope()?;
        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
        let secret =
            crate::mls::runtime::load_account_mls_secret(secure_store.as_ref(), &active.authority)
                .ok()??;
        let plaintext =
            crate::mls::persistence::decrypt_envelope(&envelope, &secret.secret).ok()?;
        let record =
            serde_json::from_slice::<arkret_sdk::LocalAuthoritativeHistorySecret>(&plaintext)
                .ok()?;
        let expected_scope =
            arkret_sdk::HistoryEffectiveScope::try_from(effective_scope.clone()).ok()?;
        (record.effective_scope == expected_scope
            && record.mls_group_id == group_id
            && record.epoch == epoch
            && queued.transition_ref == record.transition_ref)
            .then_some(record)
    }

    /// Enumerate only secrets committed atomically by the accepted-artifact
    /// consumer. External candidates and Event-local plaintext bindings live
    /// in separate ledgers and cannot enter this return type.
    pub(crate) fn local_authoritative_history_secrets_for_backup(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        authority: &arkret_sdk::AccountId,
    ) -> Result<
        Vec<(
            arkret_sdk::HistoryEffectiveScope,
            Vec<arkret_sdk::LocalAuthoritativeHistorySecret>,
        )>,
        String,
    > {
        let account_secret = crate::mls::runtime::load_account_mls_secret(secure_store, authority)
            .map_err(|error| format!("load account MLS secret for history backup: {error}"))?
            .ok_or_else(|| "account MLS secret is required for history backup".to_owned())?;
        let accepted = &self.load().accepted_mls_artifacts.snapshot;
        let mut grouped = BTreeMap::<
            String,
            (
                arkret_sdk::HistoryEffectiveScope,
                BTreeMap<u64, arkret_sdk::LocalAuthoritativeHistorySecret>,
            ),
        >::new();

        for queued in accepted.history_secrets.values() {
            if !accepted.artifacts.values().any(|artifact| {
                artifact.history_secret == *queued
                    && artifact.winning_transition_ref == queued.transition_ref
            }) {
                return Err("history backup secret is not bound to an accepted artifact".to_owned());
            }
            let envelope = serde_json::from_slice::<
                crate::mls::persistence::MlsLocalCheckpointEnvelope,
            >(&queued.ciphertext)
            .map_err(|error| format!("decode accepted history-secret envelope: {error}"))?;
            let plaintext =
                crate::mls::persistence::decrypt_envelope(&envelope, &account_secret.secret)
                    .map_err(|error| format!("open accepted history-secret envelope: {error}"))?;
            let record = serde_json::from_slice::<arkret_sdk::LocalAuthoritativeHistorySecret>(
                &plaintext,
            )
            .map_err(|error| format!("decode local-authoritative history secret: {error}"))?;
            record
                .validate()
                .map_err(|error| format!("validate local-authoritative history secret: {error}"))?;
            let canonical_group = record
                .effective_scope
                .canonical_mls_group_id()
                .map_err(|error| error.to_string())?;
            if canonical_group != record.mls_group_id
                || queued.group_id != record.mls_group_id
                || queued.epoch != record.epoch
                || queued.transition_ref != record.transition_ref
            {
                return Err(
                    "accepted history-secret envelope crosses its canonical scope/group/epoch transition partition"
                        .to_owned(),
                );
            }
            let scope_key = serde_json::to_string(&record.effective_scope)
                .map_err(|error| format!("encode history backup scope: {error}"))?;
            let (_, epochs) = grouped
                .entry(scope_key)
                .or_insert_with(|| (record.effective_scope.clone(), BTreeMap::new()));
            if let Some(existing) = epochs.insert(record.epoch, record.clone())
                && existing != record
            {
                return Err(format!(
                    "conflicting local-authoritative history secrets for epoch {}",
                    record.epoch
                ));
            }
        }

        Ok(grouped
            .into_values()
            .map(|(scope, epochs)| (scope, epochs.into_values().collect()))
            .collect())
    }

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known Realm's group in one pass and by
    /// device-recovery strands to enumerate the encrypted snapshots that
    /// can be restored for this device.
    pub fn mls_local_checkpoints(
        &self,
    ) -> BTreeMap<String, crate::mls::persistence::MlsLocalCheckpointEnvelope> {
        self.load().mls_local_checkpoints
    }

    /// Test-only scenario helper: drop the persisted MLS snapshot for a
    /// Realm scope (rotate/leave simulation) so receive-chain tests can
    /// verify behaviour without group state.
    #[cfg(test)]
    pub(crate) fn drop_mls_checkpoint_for_test(&mut self, realm_id: &str) {
        self.absorb_mls_receive_overlay();
        let Ok(scope) = mls_realm_or_circle_scope(realm_id, None) else {
            return;
        };
        let Ok(key) = mls_scope_checkpoint_key(&scope) else {
            return;
        };
        let dropped = self.cached.mls_local_checkpoints.remove(&key).is_some()
            | self
                .cached
                .mls_receive_recovery_checkpoints
                .remove(&key)
                .is_some();
        if dropped {
            let _ = self.flush();
        }
    }

    // ── MLS receive-chain persistence + plaintext cache ──
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

    /// Persist a successful decrypt: the advanced (post-decrypt) snapshot
    /// envelope AND the decrypted plaintext (cached under `payload_digest`).
    /// Both are recorded through the shared overlay and immediately flushed
    /// to the backing store, so a restart never replays the ratchet from
    /// the pre-decrypt snapshot (§5.6 MUST) and the message stays readable.
    pub fn advance_mls_receive_chain(
        &self,
        realm_id: &str,
        envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
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
        envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        let Ok(scope) = mls_realm_or_circle_scope(realm_id, circle_id) else {
            return;
        };
        self.advance_mls_receive_chain_for_scope(&scope, envelope, payload_digest, plaintext);
    }

    pub fn advance_mls_receive_chain_for_scope(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
        let Ok(scope_key) = mls_scope_checkpoint_key_for_group(effective_scope, &envelope.group_id)
        else {
            return;
        };
        let previous_snapshot =
            self.mls_checkpoint_for_scope_and_group(effective_scope, &envelope.group_id);
        let Some(realm_id) = effective_scope.realm_id_opt().map(ToString::to_string) else {
            return;
        };
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
                .entry(realm_id)
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

    /// Persist plaintext opened by an Event-local external history candidate.
    /// No MLS receive state advances on this path; the immutable candidate
    /// outcome is committed separately before this cache becomes visible.
    pub fn cache_external_history_plaintext(
        &self,
        realm_id: &str,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
        self.lock_mls_receive_overlay()
            .plaintexts
            .entry(realm_id.to_owned())
            .or_default()
            .insert(payload_digest.to_owned(), encoded);
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
        let Ok(scope) = mls_realm_or_circle_scope(realm_id, circle_id) else {
            return false;
        };
        self.mls_genesis_emitted_for_scope(&scope)
    }

    pub fn mls_genesis_emitted_for_scope(&self, effective_scope: &arkret_sdk::ScopeRef) -> bool {
        let Ok(key) = mls_scope_checkpoint_key(effective_scope) else {
            return false;
        };
        match effective_scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{key}\u{1f}");
                self.load()
                    .mls_genesis_emitted
                    .iter()
                    .any(|candidate| candidate.starts_with(&prefix))
            }
            _ => self.load().mls_genesis_emitted.contains(&key),
        }
    }

    /// Record that a `ak.mls.genesis` event has been submitted for this
    /// Realm so it is never re-emitted (idempotent).
    pub fn mark_mls_genesis_emitted(&mut self, realm_id: impl Into<String>) -> Result<(), String> {
        self.mark_mls_genesis_emitted_for_effective_scope(realm_id, None)
    }

    /// Record a successfully accepted `ak.mls.genesis` event and seed the
    /// local MLS group-state frontier with that accepted Event id. This lets an
    /// immediately-following self-update or AddMember commit cite a real
    /// `ak:event:*` base group-state ref before the next sync response arrives.
    pub fn mark_mls_genesis_emitted_with_event(
        &mut self,
        realm_id: impl Into<String>,
        genesis_event_id: &arkret_sdk::EventId,
    ) -> Result<(), String> {
        self.mark_mls_genesis_emitted_for_effective_scope_with_event(
            realm_id,
            None,
            genesis_event_id,
        )
    }

    pub fn mark_mls_genesis_emitted_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let key = mls_effective_scope_checkpoint_key(&realm_id, circle_id)?;
        if self.cached.mls_genesis_emitted.insert(key) {
            let _ = self.flush();
        }
        Ok(())
    }

    pub fn mark_mls_genesis_emitted_for_effective_scope_with_event(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        genesis_event_id: &arkret_sdk::EventId,
    ) -> Result<(), String> {
        let realm_id = realm_id.into();
        let scope = mls_realm_or_circle_scope(&realm_id, circle_id)?;
        self.mark_mls_genesis_emitted_for_scope_with_event(&scope, genesis_event_id)
    }

    pub fn mark_mls_genesis_emitted_for_scope_with_event(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        genesis_event_id: &arkret_sdk::EventId,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let scope_key = mls_scope_checkpoint_key(effective_scope)?;
        // A Sidecar scope keys its state per group, and the accepted genesis
        // names the group whose snapshot this device already holds.
        let scoped_key = match effective_scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{scope_key}\u{1f}");
                self.cached
                    .mls_local_checkpoints
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .max_by_key(|(_, snapshot)| snapshot.epoch)
                    .map(|(key, _)| key.clone())
            }
            _ => Some(scope_key.clone()),
        };
        let scoped_key = scoped_key.ok_or_else(|| {
            "Sidecar MLS genesis persistence requires an existing group snapshot".to_owned()
        })?;
        let mut changed = self.cached.mls_genesis_emitted.insert(scoped_key.clone());
        if let Some(snapshot) = self.cached.mls_local_checkpoints.get(&scoped_key) {
            let record = MlsGroupStateRefRecord {
                group_id: snapshot.group_id.clone(),
                epoch: 0,
                event_id: genesis_event_id.clone(),
            };
            if self.cached.mls_group_state_refs.get(&scoped_key) != Some(&record) {
                self.cached
                    .mls_group_state_refs
                    .insert(scoped_key.clone(), record.clone());
                changed = true;
            }
            changed |= attach_group_state_ref_to_snapshot(&mut self.cached, &scoped_key, &record);
        }
        if changed {
            let _ = self.flush();
        }
        Ok(())
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
        let scope = mls_realm_or_circle_scope(realm_id, circle_id)?;
        self.mls_group_state_ref_for_scope(&scope, group_id, epoch)
    }

    pub fn mls_group_state_ref_for_scope(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Result<arkret_sdk::EventId, String> {
        let key = mls_scope_checkpoint_key_for_group(effective_scope, group_id)?;
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
                    .mls_local_checkpoints
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
                    .mls_historical_checkpoints
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
            });
        let record = record.ok_or_else(|| {
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

    /// Read metadata retained with an applied MLS transition, without governance history.
    pub(crate) fn accepted_mls_epoch_head(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Result<Option<arkret_sdk::MlsEpochHead>, String> {
        let local = self.load();
        let mut selected = None;
        for artifact in local.accepted_mls_artifacts.snapshot.artifacts.values() {
            let head = &artifact.transition_head;
            if &head.effective_scope != effective_scope
                || head.mls_group_id.as_str() != group_id
                || head.next_epoch != epoch
            {
                continue;
            }
            head.validate().map_err(|error| error.to_string())?;
            if head.transition_ref != artifact.winning_transition_ref
                || artifact.snapshot.group_state_event_id.as_ref() != Some(&head.transition_ref)
                || artifact.snapshot.group_id != group_id
                || artifact.snapshot.epoch != epoch
            {
                return Err(
                    "accepted MLS metadata differs from its durable crypto snapshot".to_owned(),
                );
            }
            if selected.as_ref().is_some_and(|current| current != head) {
                return Err("durable MLS artifacts disagree on the exact transition".to_owned());
            }
            selected = Some(head.clone());
        }
        Ok(selected)
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
        let realm_id = realm_id.into();
        let scope = mls_realm_or_circle_scope(&realm_id, circle_id)?;
        self.record_mls_group_state_ref_for_scope(&scope, group_id, epoch, event_id)
    }

    pub fn record_mls_group_state_ref_for_scope(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
        event_id: arkret_sdk::EventId,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let key = mls_scope_checkpoint_key_for_group(effective_scope, group_id)?;
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

    /// Persist an exact replay-derived ciphersuite for externally received
    /// candidate material. A conflicting value is a cryptographic transcript
    /// contradiction and must not overwrite the first verified binding.
    pub(crate) fn record_history_epoch_cipher_suite(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
        cipher_suite: &str,
    ) -> Result<(), String> {
        let scope_group_key = mls_scope_checkpoint_key_for_group(effective_scope, group_id)?;
        let by_epoch = self
            .cached
            .history_epoch_cipher_suites
            .entry(scope_group_key)
            .or_default();
        if let Some(existing) = by_epoch.get(&epoch) {
            if existing != cipher_suite {
                return Err(
                    "verified history epoch ciphersuite conflicts with durable state".to_owned(),
                );
            }
            return Ok(());
        }
        by_epoch.insert(epoch, cipher_suite.to_owned());
        self.flush().map_err(|error| error.to_string())
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

    /// The receiver's `mls_governance_binding_stale` message for this effective
    /// scope, when its last E2EE application DataEvent was refused for
    /// governance-Seal coverage (`encryption-and-audit.md` §2.4.1
    /// `epoch_update_required`). `None` means no receiver has reported a
    /// coverage gap.
    pub fn mls_coverage_stale_reason(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Option<String> {
        let key = mls_effective_scope_checkpoint_key(realm_id, circle_id).ok()?;
        self.load()
            .mls_coverage_stale
            .get(&key)
            .map(|stale| stale.reason.clone())
    }

    /// Every effective scope of `realm_id` a receiver has paused, as the
    /// `circle_id` argument the repair pass takes (`None` = Realm-default
    /// group). Circle groups are independent MLS groups with their own
    /// accumulator, so each one needs its own commit.
    pub fn stale_mls_coverage_scopes(&self, realm_id: &str) -> Vec<Option<String>> {
        self.load()
            .mls_coverage_stale
            .values()
            .filter(|stale| stale.realm_id == realm_id)
            .map(|stale| stale.circle_id.clone())
            .collect()
    }

    /// Record a receiver's coverage refusal. Last-writer-wins so the stored
    /// message always names the currently missing governance Seals.
    pub fn record_mls_coverage_stale(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        reason: &str,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let circle_id = circle_id
            .map(str::trim)
            .filter(|circle_id| !circle_id.is_empty());
        let key = mls_effective_scope_checkpoint_key(&realm_id, circle_id)?;
        self.cached.mls_coverage_stale.insert(
            key,
            crate::state::types::MlsCoverageStale {
                realm_id,
                circle_id: circle_id.map(str::to_owned),
                reason: reason.to_owned(),
            },
        );
        let _ = self.flush();
        Ok(())
    }

    /// Clear the coverage refusal after an `ak.mls.commit` carrying a freshly
    /// verified governance binding was accepted.
    ///
    /// Cleared on acceptance rather than on a successful resend: the accepted
    /// commit binds the latest projected Security Frontier. If it still was not
    /// enough, the next send is refused again and re-arms the
    /// flag with the receiver's new message — the repair never silently
    /// declares itself finished.
    pub fn clear_mls_coverage_stale(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let key = mls_effective_scope_checkpoint_key(realm_id, circle_id)?;
        if self.cached.mls_coverage_stale.remove(&key).is_some() {
            let _ = self.flush();
        }
        Ok(())
    }
}

pub(crate) fn mls_effective_scope_checkpoint_key(
    realm_id: &str,
    circle_id: Option<&str>,
) -> Result<String, String> {
    mls_realm_or_circle_scope(realm_id, circle_id)
        .and_then(|scope| mls_scope_checkpoint_key(&scope))
}

pub(crate) fn mls_scope_checkpoint_key(
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<String, String> {
    let bytes = effective_scope
        .canonical_effective_scope_key_bytes()
        .map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|error| format!("MLS scope key is not UTF-8: {error}"))
}

pub(crate) fn mls_scope_checkpoint_key_for_group(
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
) -> Result<String, String> {
    let key = mls_scope_checkpoint_key(effective_scope)?;
    match effective_scope {
        arkret_sdk::ScopeRef::Sidecar { .. } => {
            let group_id = group_id.trim();
            if group_id.is_empty() {
                return Err("Sidecar MLS storage requires mls_group_id".to_owned());
            }
            Ok(format!("{key}\u{1f}{group_id}"))
        }
        _ => Ok(key),
    }
}

fn mls_realm_or_circle_scope(
    realm_id: &str,
    circle_id: Option<&str>,
) -> Result<arkret_sdk::ScopeRef, String> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())
        .map_err(|error| format!("invalid MLS Realm id: {error}"))?;
    match circle_id.map(str::trim).filter(|value| !value.is_empty()) {
        Some(circle_id) => Ok(arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(circle_id.to_owned())
                .map_err(|error| format!("invalid MLS Circle id: {error}"))?,
        }),
        None => Ok(arkret_sdk::ScopeRef::Realm { realm_id }),
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use serde_json::json;

    use super::LocalStateStore;

    #[test]
    fn accepted_publication_preserves_staging_and_unchanged_receive_state() {
        let path = std::env::temp_dir().join(format!(
            "inkson-accepted-cas-{}.json",
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let id = arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
            .unwrap();
        let group = "AQID";
        let binding = arkret_sdk::MlsGovernanceBindingPayload::realm(
            arkret_sdk::RealmId::new(realm).unwrap(),
            group,
            0,
            1,
            arkret_sdk::Hash::new(format!("sha256:{}", "a5".repeat(32))).unwrap(),
            arkret_sdk::ContentScheme::MlsExporterAeadV1,
            Some(arkret_sdk::DurabilityPolicy::None),
            arkret_sdk::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            arkret_sdk::CORE_REDUCER_PROFILE,
        )
        .unwrap();
        let commit = arkret_sdk::MlsCommitEnvelope {
            group_id: group.into(),
            epoch: 1,
            commit: arkret_sdk::base64url_encode(b"commit"),
            commit_digest: arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(b"commit"))
                .unwrap(),
            ratchet_tree: None,
        };
        let payload =
            arkret_sdk::MlsCommitPayload::new(0, id.to_string(), Vec::new(), &commit, binding)
                .unwrap();
        let event = serde_json::from_value(json!({
            "event_id": id, "kind": "ak.mls.commit", "realm_id": realm,
            "scope_ref": {"kind":"realm", "realm_id":realm},
            "actor_id": {"kind":"account", "account_id": {"principal_id":"ak:did_core:web:alice.example", "station_id":"ak:did_core:web:station.example"}},
            "actor_seq": 1, "created_at":"2026-05-19T00:00:00.000Z",
            "hlc":"01970e589d21-0001-a13f9c2e", "prev_refs":[], "payload":payload, "proofs":[]
        })).unwrap();
        let mut accepted = crate::mls::persistence::encrypt_state(
            realm,
            group,
            1,
            b"accepted",
            "test-secret",
            &[7; 16],
        );
        accepted.group_state_event_id = Some(id.clone());
        let staged = crate::mls::persistence::encrypt_state(
            realm,
            group,
            2,
            b"staged",
            "test-secret",
            &[8; 16],
        );
        let mut store = LocalStateStore::with_path(&path);
        store.save_mls_checkpoint(realm, staged.clone()).unwrap();
        let artifact = garth::DurableAcceptedMlsArtifact {
            transition_head: arkret_sdk::MlsEpochHead {
                transition_ref: id.clone(),
                transition_event_digest: id.event_digest(),
                mls_transition_digest: commit.commit_digest.clone(),
                effective_scope: arkret_sdk::ScopeRef::Realm {
                    realm_id: arkret_sdk::RealmId::new(realm).unwrap(),
                },
                mls_group_id: arkret_sdk::Base64UrlString::new(group).unwrap(),
                previous_epoch: 0,
                next_epoch: 1,
                content_scheme: arkret_sdk::ContentScheme::MlsExporterAeadV1,
            },
            event,
            event_digest: arkret_sdk::Hash::new(format!("sha256:{}", "a5".repeat(32))).unwrap(),
            winning_transition_ref: id.clone(),
            snapshot: accepted.into_queued(),
            history_secret: garth::QueuedMlsHistorySecret {
                group_id: group.into(),
                epoch: 1,
                transition_ref: id.clone(),
                ciphertext: vec![1],
            },
        };
        let mut state = garth::AcceptedMlsArtifactState::default();
        state.artifacts.insert(id.to_string(), artifact);
        state.ready_groups.insert(group.into(), id.to_string());
        assert!(
            store
                .compare_and_swap_accepted_mls_artifacts(0, &state)
                .unwrap()
                .is_some()
        );
        let archived = store
            .cached
            .mls_historical_checkpoints
            .values()
            .find(|value| value.epoch == 2)
            .unwrap();
        assert_eq!(archived, &staged);
        let mut ratcheted = store
            .cached
            .mls_local_checkpoints
            .get(realm)
            .unwrap()
            .clone();
        ratcheted.ciphertext_hex = "ad".repeat(32);
        store
            .cached
            .mls_local_checkpoints
            .insert(realm.into(), ratcheted.clone());
        assert!(
            store
                .compare_and_swap_accepted_mls_artifacts(1, &state)
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store.cached.mls_local_checkpoints.get(realm),
            Some(&ratcheted)
        );
        assert!(
            store
                .compare_and_swap_accepted_mls_artifacts(1, &state)
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_file(path);
    }

    fn history_secret_fixture(
        local_state_ref: &str,
        secret: &[u8],
    ) -> (
        arkret_sdk::ScopeRef,
        arkret_sdk::LocalAuthoritativeHistorySecret,
    ) {
        let realm_id = arkret_sdk::RealmId::new(
            "ak:realm:AXT4J1l4F3ziDJgbW0eaFtcLosoRKMG4tLzy3ImP2xL6".to_owned(),
        )
        .unwrap();
        let effective_scope = arkret_sdk::HistoryEffectiveScope::Realm {
            realm_id: realm_id.clone(),
        };
        let record = arkret_sdk::LocalAuthoritativeHistorySecret {
            mls_group_id: effective_scope.canonical_mls_group_id().unwrap(),
            effective_scope,
            epoch: 0,
            mls_ciphersuite: arkret_sdk::ARKRET_MLS_CIPHERSUITE_CANONICAL_ID.to_owned(),
            local_state_ref: local_state_ref.to_owned(),
            transition_ref: arkret_sdk::EventId::new(
                "ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )
            .unwrap(),
            transition_event_digest: arkret_sdk::Hash::new(format!("sha256:{}", "1".repeat(64)))
                .unwrap(),
            mls_transition_digest: arkret_sdk::Hash::new(format!("sha256:{}", "2".repeat(64)))
                .unwrap(),
            secret_b64u: arkret_sdk::base64url_encode(secret),
        };
        (arkret_sdk::ScopeRef::Realm { realm_id }, record)
    }

    #[tokio::test]
    async fn same_epoch_secret_with_new_realm_state_snapshot_ref_is_idempotent() {
        let path = std::env::temp_dir().join(format!(
            "inkson-history-secret-snapshot-refresh-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let mut state = LocalStateStore::with_path(&path);
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let (scope, first) =
            history_secret_fixture("inkson.mls_snapshot.v1:first", b"same-epoch-secret");
        let group_id = first.mls_group_id.clone();
        let pending = state
            .prepare_history_secrets(&secure, &scope, &group_id, [first])
            .unwrap()
            .expect("first retain must be persisted");
        pending.persist(&secure).await.unwrap();
        state.publish_history_secrets(pending);

        let (_, refreshed) = history_secret_fixture(
            "inkson.mls_snapshot.v1:after-description",
            b"same-epoch-secret",
        );
        assert!(
            state
                .prepare_history_secrets(&secure, &scope, &group_id, [refreshed])
                .unwrap()
                .is_none(),
            "a within-epoch ratchet snapshot must not compete with the already-retained epoch secret"
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn concurrent_same_epoch_retains_with_distinct_realm_state_snapshot_refs_converge() {
        let path = std::env::temp_dir().join(format!(
            "inkson-history-secret-concurrent-refresh-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let state = LocalStateStore::with_path(&path);
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let (scope, first) =
            history_secret_fixture("inkson.mls_snapshot.v1:first", b"same-epoch-secret");
        let (_, second) =
            history_secret_fixture("inkson.mls_snapshot.v1:second", b"same-epoch-secret");
        let group_id = first.mls_group_id.clone();
        let first = state
            .prepare_history_secrets(&secure, &scope, &group_id, [first])
            .unwrap()
            .unwrap();
        let second = state
            .prepare_history_secrets(&secure, &scope, &group_id, [second])
            .unwrap()
            .unwrap();

        first.persist(&secure).await.unwrap();
        second.persist(&secure).await.unwrap();
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn same_epoch_retain_still_rejects_different_secret_material() {
        let path = std::env::temp_dir().join(format!(
            "inkson-history-secret-real-conflict-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let mut state = LocalStateStore::with_path(&path);
        let secure = crate::secure_key_store::MemorySecureKeyStore::new();
        let (scope, first) =
            history_secret_fixture("inkson.mls_snapshot.v1:first", b"first-secret");
        let group_id = first.mls_group_id.clone();
        let pending = state
            .prepare_history_secrets(&secure, &scope, &group_id, [first])
            .unwrap()
            .unwrap();
        state.publish_history_secrets(pending);
        let (_, conflicting) =
            history_secret_fixture("inkson.mls_snapshot.v1:second", b"different-secret");

        let error = state
            .prepare_history_secrets(&secure, &scope, &group_id, [conflicting])
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicting local-authoritative history records for epoch 0")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persisted_snapshot_recovers_exact_group_state_reference_without_side_index() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-snapshot-reference-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        let event_id =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        let snapshot = crate::mls::persistence::MlsLocalCheckpointEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 1,
            admission_epoch: 0,
            group_state_event_id: Some(event_id.clone()),
            salt_hex: "00".repeat(16),
            ciphertext_hex: "11".repeat(32),
            mac_hex: "22".repeat(12),
            recorded_at: chrono::Utc::now(),
            epoch_started_at: chrono::Utc::now(),
            app_messages_observed: 0,
            aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
        };

        LocalStateStore::with_path(&path)
            .save_mls_checkpoint(realm_id, snapshot)
            .unwrap();
        let mut restored = LocalStateStore::with_path(&path);
        let mut rewritten = restored.mls_checkpoint_for(realm_id).unwrap();
        rewritten.group_state_event_id = None;
        rewritten.app_messages_observed = 1;
        restored.save_mls_checkpoint(realm_id, rewritten).unwrap();
        assert_eq!(
            restored
                .mls_checkpoint_for(realm_id)
                .unwrap()
                .group_state_event_id,
            Some(event_id.clone())
        );

        assert_eq!(
            restored
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 1)
                .unwrap(),
            event_id
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn realm_projection_is_not_mls_group_state_authority() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-reference-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        let event_id =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        let snapshot = crate::mls::persistence::MlsLocalCheckpointEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 0,
            admission_epoch: 0,
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
        store.save_mls_checkpoint(realm_id, snapshot).unwrap();
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

        assert!(
            store
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 0)
                .is_err()
        );
        let restored = LocalStateStore::with_path(&path);
        assert_eq!(
            restored
                .mls_checkpoint_for(realm_id)
                .unwrap()
                .group_state_event_id,
            None
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn realm_projection_cannot_replace_a_local_group_state_reference() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-phantom-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        let phantom_event_id =
            arkret_sdk::EventId::new("ak:event:ASeq_1SMGFgL0OgySv7t3u5l9Sr1eV_HZwUb7tMFwZON")
                .unwrap();
        let accepted_event_id =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        let snapshot = crate::mls::persistence::MlsLocalCheckpointEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 0,
            admission_epoch: 0,
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
        store.save_mls_checkpoint(realm_id, snapshot).unwrap();
        store
            .record_mls_group_state_ref_for_effective_scope(
                realm_id,
                None,
                group_id,
                0,
                phantom_event_id.clone(),
            )
            .unwrap();
        store.save_realm_tree_projection(
            realm_id,
            json!({
                "state": {
                    "events": [{
                        "event_id": accepted_event_id,
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
            phantom_event_id
        );
        let restored = LocalStateStore::with_path(&path);
        assert_eq!(
            restored
                .mls_checkpoint_for(realm_id)
                .unwrap()
                .group_state_event_id,
            Some(phantom_event_id)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn contested_projection_cannot_influence_mls_group_state() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-contested-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        let local_event_id =
            arkret_sdk::EventId::new("ak:event:ASeq_1SMGFgL0OgySv7t3u5l9Sr1eV_HZwUb7tMFwZON")
                .unwrap();
        let genesis_event = |event_id: &str| {
            json!({
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
            })
        };
        let snapshot = crate::mls::persistence::MlsLocalCheckpointEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 0,
            admission_epoch: 0,
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
        store.save_mls_checkpoint(realm_id, snapshot).unwrap();
        store
            .record_mls_group_state_ref_for_effective_scope(
                realm_id,
                None,
                group_id,
                0,
                local_event_id.clone(),
            )
            .unwrap();
        store.save_realm_tree_projection(
            realm_id,
            json!({
                "state": {
                    "events": [
                        genesis_event("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk"),
                        genesis_event("ak:event:AbDgdKpIr6eCN_pZGaRIGogOAMC2eqTqmN_mgOVTZ4Oh"),
                    ]
                }
            }),
        );

        assert_eq!(
            store
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 0)
                .unwrap(),
            local_event_id
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unrelated_projection_group_is_not_an_authoring_reference() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-mismatch-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        let snapshot = crate::mls::persistence::MlsLocalCheckpointEnvelope {
            realm_id: realm_id.to_owned(),
            group_id: group_id.to_owned(),
            epoch: 0,
            admission_epoch: 0,
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
        store.save_mls_checkpoint(realm_id, snapshot).unwrap();
        store.save_realm_tree_projection(
            realm_id,
            json!({
                "state": {
                    "events": [{
                        "event_id": "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk",
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
        let _ = std::fs::remove_file(path);
    }
}
