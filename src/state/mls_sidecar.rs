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
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
) -> Option<arkret_sdk::EventId> {
    projection_mls_genesis_event_ids(state, effective_scope, group_id)
        .into_iter()
        .next()
}

/// Every accepted `ak.mls.genesis` Event id the durable Realm projection
/// carries for this exact `(effective_scope, group_id)`, in projection order.
///
/// The genesis cell is `cas_register`, so a healthy Realm exposes exactly one;
/// more than one means the scope's genesis is contested and callers must fail
/// closed instead of picking a winner locally.
fn projection_mls_genesis_event_ids(
    state: &ClientLocalState,
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
) -> Vec<arkret_sdk::EventId> {
    let Some(realm_id) = effective_scope.realm_id_opt() else {
        return Vec::new();
    };
    let realm_id = realm_id.as_str();
    let Some(projection) = state.realm_tree_projections.get(realm_id) else {
        return Vec::new();
    };
    let Some(events) = projection
        .get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    events
        .iter()
        .filter_map(|event| {
            let kind = event
                .get("kind")
                .or_else(|| event.get("event_kind"))
                .and_then(Value::as_str)?;
            if kind != arkret_sdk::EventKind::MlsGenesis.as_str() {
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
            let projected_scope = payload.get("effective_scope")?;
            let expected_scope = serde_json::to_value(effective_scope).ok()?;
            if projected_scope != &expected_scope {
                return None;
            }
            event
                .get("event_id")
                .and_then(Value::as_str)
                .and_then(|event_id| arkret_sdk::EventId::new(event_id.to_owned()).ok())
        })
        .collect()
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
            if let Some(existing) = merged.get(epoch)
                && existing != record
            {
                return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                    format!("conflicting local-authoritative history records for epoch {epoch}"),
                ));
            }
            merged.insert(*epoch, record.clone());
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

    /// Persist (or replace) the MLS snapshot envelope for a Realm.
    /// Idempotent: a re-snapshot at the same epoch overwrites the
    /// previous record. The on-disk envelope is opaque to soland —
    /// device-secret-derived encryption keeps the server zero-knowledge
    /// of the underlying group keys.
    pub fn save_mls_snapshot(
        &mut self,
        realm_id: impl Into<String>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) -> Result<(), String> {
        self.save_mls_snapshot_for_effective_scope(realm_id, None, envelope)
    }

    pub fn save_mls_snapshot_for_effective_scope(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) -> Result<(), String> {
        let realm_id = realm_id.into();
        let scope = mls_realm_or_circle_scope(&realm_id, circle_id)?;
        self.save_mls_snapshot_for_scope(&scope, envelope)
    }

    pub fn save_mls_snapshot_for_scope(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        mut envelope: crate::mls::persistence::MlsSnapshotEnvelope,
    ) -> Result<(), String> {
        // YOU-02-004: order this write after any decrypt write-backs so the
        // overlay can never shadow it (overlay snapshots always derive from
        // the state this caller just read via `mls_snapshot_for`).
        self.absorb_mls_receive_overlay();
        let key = mls_scope_snapshot_key_for_group(effective_scope, &envelope.group_id)?;
        if let Some(current) = self.cached.mls_snapshots.get(&key)
            && current.group_id == envelope.group_id
        {
            envelope.admission_epoch = current.admission_epoch;
        }
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
        Ok(())
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
        let scope = mls_realm_or_circle_scope(realm_id, circle_id).ok()?;
        self.mls_snapshot_for_scope(&scope)
    }

    pub fn mls_snapshot_for_scope(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        match effective_scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{}\u{1f}", mls_scope_snapshot_key(effective_scope).ok()?);
                self.load()
                    .mls_snapshots
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .map(|(_, snapshot)| snapshot)
                    .max_by_key(|snapshot| snapshot.epoch)
                    .cloned()
            }
            _ => {
                let key = mls_scope_snapshot_key(effective_scope).ok()?;
                self.load().mls_snapshots.get(&key).cloned()
            }
        }
    }

    pub fn mls_snapshot_for_scope_and_group(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        let key = mls_scope_snapshot_key_for_group(effective_scope, group_id).ok()?;
        self.load().mls_snapshots.get(&key).cloned()
    }

    pub fn historical_mls_snapshot_for_effective_scope(
        &self,
        realm_id: &str,
        circle_id: Option<&str>,
        group_id: &str,
        epoch: u64,
    ) -> Option<crate::mls::persistence::MlsSnapshotEnvelope> {
        let scope_key = mls_effective_scope_snapshot_key(realm_id, circle_id).ok()?;
        let history_key = historical_mls_state_key(&scope_key, group_id, epoch);
        self.load()
            .mls_historical_snapshots
            .get(&history_key)
            .cloned()
    }

    // ── Local-authoritative MLS history-secret persistence ─────────

    /// Resolve the exact accepted transition tuple for a durable local MLS
    /// snapshot. Only the locally verified governance checkpoint is accepted;
    /// a projection row or current Event id alone cannot manufacture
    /// `local_authoritative` status.
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
            .mls_snapshot_for_scope_and_group(effective_scope, group_id)
            .ok_or_else(|| "local-authoritative export has no durable MLS snapshot".to_owned())?;
        if snapshot.epoch != epoch {
            return Err(
                "local-authoritative export epoch differs from durable MLS state".to_owned(),
            );
        }
        let transition_ref = snapshot.group_state_event_id.clone().ok_or_else(|| {
            "local-authoritative export has no accepted transition reference".to_owned()
        })?;
        let realm_id = effective_scope
            .realm_id_opt()
            .ok_or_else(|| "history export requires Realm or Circle scope".to_owned())?;
        let checkpoint = self
            .trusted_mls_governance_checkpoint(realm_id.as_str())
            .ok_or_else(|| {
                "local-authoritative export has no verified governance checkpoint".to_owned()
            })?;
        checkpoint
            .validate_checkpoint()
            .map_err(|error| error.to_string())?;
        let event = checkpoint
            .accepted_events
            .iter()
            .find(|event| event.event_id == transition_ref)
            .ok_or_else(|| {
                "accepted transition is absent from the verified governance checkpoint".to_owned()
            })?;
        let transition_event_digest =
            arkret_sdk::signed_event_digest_claim(event).map_err(|error| error.to_string())?;
        let payload_value =
            serde_json::to_value(&event.payload).map_err(|error| error.to_string())?;
        let mls_transition_digest = match event.kind.as_str() {
            arkret_wire::event_kind_str::MLS_GENESIS => {
                let payload =
                    serde_json::from_value::<arkret_sdk::MlsGenesisPayload>(payload_value)
                        .map_err(|error| format!("invalid accepted MLS Genesis: {error}"))?;
                if epoch != 0
                    || payload.mls_group_id.as_str() != group_id
                    || payload.effective_scope != *effective_scope
                {
                    return Err(
                        "accepted MLS Genesis does not match the durable local state".to_owned(),
                    );
                }
                payload
                    .transition_digest()
                    .map_err(|error| error.to_string())?
            }
            arkret_wire::event_kind_str::MLS_COMMIT => {
                let payload = serde_json::from_value::<arkret_sdk::MlsCommitPayload>(payload_value)
                    .map_err(|error| format!("invalid accepted MLS Commit: {error}"))?;
                if payload.next_epoch() != epoch
                    || payload.mls_group_id() != group_id
                    || payload.governance_binding().effective_scope() != effective_scope
                {
                    return Err(
                        "accepted MLS Commit does not match the durable local state".to_owned()
                    );
                }
                payload.commit_digest().clone()
            }
            _ => {
                return Err(
                    "durable MLS group-state reference names a non-transition Event".to_owned(),
                );
            }
        };
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
        let scope_group_key = mls_scope_snapshot_key_for_group(effective_scope, group_id)
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
        if let Some(inline) = self.cached.history_secrets.get(&scope_group_key) {
            by_epoch.extend(
                inline
                    .iter()
                    .map(|(epoch, secret)| (*epoch, secret.clone())),
            );
        }
        let mut new_secret_count = 0;
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
            if let Some(existing) = by_epoch.get(&record.epoch) {
                if existing != &record {
                    return Err(crate::secure_key_store::SecureKeyStoreError::Backend(
                        format!(
                            "conflicting local-authoritative history records for epoch {}",
                            record.epoch
                        ),
                    ));
                }
            } else {
                by_epoch.insert(record.epoch, record);
                new_secret_count += 1;
            }
        }
        Ok((new_secret_count > 0).then_some(PendingHistorySecrets {
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

    /// All local-authoritative `history_secret`s for an exact scope/group, as
    /// `(epoch, secret)`
    /// pairs ordered by epoch. Used by the tier-3 history decrypt retry to
    /// try every granted epoch key against a pre-join ciphertext.
    pub fn history_secrets_for(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
    ) -> Vec<(u64, Vec<u8>)> {
        let Ok(scope_group_key) = mls_scope_snapshot_key_for_group(effective_scope, group_id)
        else {
            return Vec::new();
        };
        let mut merged: BTreeMap<u64, arkret_sdk::LocalAuthoritativeHistorySecret> =
            crate::secure_key_store::load_history_secrets(&scope_group_key).unwrap_or_default();
        if let Some(inline) = self.load().history_secrets.get(&scope_group_key) {
            for (epoch, secret) in inline {
                // The in-process copy is the value most recently accepted by
                // this client. It must override a stale durable value when the
                // preceding secure-store write failed after an older value had
                // already been persisted.
                merged.insert(*epoch, secret.clone());
            }
        }
        merged
            .into_iter()
            .filter_map(|(epoch, record)| {
                let secret = arkret_sdk::base64url_decode(record.secret_b64u.as_bytes()).ok()?;
                Some((epoch, secret))
            })
            .collect()
    }

    /// Closed records eligible for portable `mls_history` backup. External
    /// candidates never enter this map, so the SDK packer cannot be fed a
    /// response/RRK/portable candidate through this boundary.
    pub(crate) fn local_authoritative_history_records_for(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
    ) -> Vec<arkret_sdk::LocalAuthoritativeHistorySecret> {
        let Ok(history_scope) =
            arkret_sdk::HistoryEffectiveScope::try_from(effective_scope.clone())
        else {
            return Vec::new();
        };
        let Ok(scope_group_key) = mls_scope_snapshot_key_for_group(effective_scope, group_id)
        else {
            return Vec::new();
        };
        let mut merged =
            crate::secure_key_store::load_history_secrets(&scope_group_key).unwrap_or_default();
        if let Some(inline) = self.load().history_secrets.get(&scope_group_key) {
            for (epoch, record) in inline {
                merged.insert(*epoch, record.clone());
            }
        }
        merged
            .into_values()
            .filter(|record| {
                record.effective_scope == history_scope
                    && record.mls_group_id == group_id
                    && record.validate().is_ok()
            })
            .collect()
    }

    /// The local-authoritative `history_secret` for an exact
    /// `(effective_scope, group_id, epoch)`, if any.
    pub fn history_secret_for(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Option<Vec<u8>> {
        let scope_group_key = mls_scope_snapshot_key_for_group(effective_scope, group_id).ok()?;
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
        None
    }

    /// Return the replay-verified MLS ciphersuite bound to one retained epoch.
    pub fn history_epoch_cipher_suite(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
        epoch: u64,
    ) -> Option<String> {
        let scope_group_key = mls_scope_snapshot_key_for_group(effective_scope, group_id).ok()?;
        self.load()
            .history_epoch_cipher_suites
            .get(&scope_group_key)
            .and_then(|by_epoch| by_epoch.get(&epoch))
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
        let scope_group_key = mls_scope_snapshot_key_for_group(effective_scope, group_id)?;
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
        let Ok(scope) = mls_realm_or_circle_scope(realm_id, circle_id) else {
            return;
        };
        self.drop_mls_snapshot_for_scope(&scope);
    }

    pub fn drop_mls_snapshot_for_scope(&mut self, effective_scope: &arkret_sdk::ScopeRef) {
        self.absorb_mls_receive_overlay();
        let Ok(key) = mls_scope_snapshot_key(effective_scope) else {
            return;
        };
        let keys = match effective_scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{key}\u{1f}");
                self.cached
                    .mls_snapshots
                    .keys()
                    .chain(self.cached.mls_receive_recovery_snapshots.keys())
                    .filter(|candidate| candidate.starts_with(&prefix))
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>()
            }
            _ => [key].into_iter().collect(),
        };
        let mut dropped_snapshot = false;
        let mut dropped_recovery = false;
        for key in keys {
            dropped_snapshot |= self.cached.mls_snapshots.remove(&key).is_some();
            dropped_recovery |= self
                .cached
                .mls_receive_recovery_snapshots
                .remove(&key)
                .is_some();
        }
        // The decrypted-plaintext cache is keyed to ciphertext minted under
        // the dropped group state; it stays readable history (same lifetime
        // policy as the author sidecar) and is NOT wiped here.
        if dropped_snapshot || dropped_recovery {
            let _ = self.flush();
            self.persist_e2ee_plaintext_cache_if_ready();
        }
    }

    pub fn drop_mls_snapshot_for_scope_and_group(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        group_id: &str,
    ) {
        self.absorb_mls_receive_overlay();
        let Ok(key) = mls_scope_snapshot_key_for_group(effective_scope, group_id) else {
            return;
        };
        let dropped_snapshot = self.cached.mls_snapshots.remove(&key).is_some();
        let dropped_recovery = self
            .cached
            .mls_receive_recovery_snapshots
            .remove(&key)
            .is_some();
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
        let Ok(scope) = mls_realm_or_circle_scope(realm_id, circle_id) else {
            return;
        };
        self.advance_mls_receive_chain_for_scope(&scope, envelope, payload_digest, plaintext);
    }

    pub fn advance_mls_receive_chain_for_scope(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        envelope: crate::mls::persistence::MlsSnapshotEnvelope,
        payload_digest: &str,
        plaintext: &[u8],
    ) {
        use base64::Engine as _;
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext);
        let Ok(scope_key) = mls_scope_snapshot_key_for_group(effective_scope, &envelope.group_id)
        else {
            return;
        };
        let previous_snapshot =
            self.mls_snapshot_for_scope_and_group(effective_scope, &envelope.group_id);
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
        let Ok(key) = mls_scope_snapshot_key(effective_scope) else {
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
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id)?;
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
        let scope_key = mls_scope_snapshot_key(effective_scope)?;
        // A Sidecar scope keys its state per group, and the accepted genesis
        // names the group whose snapshot this device already holds.
        let scoped_key = match effective_scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{scope_key}\u{1f}");
                self.cached
                    .mls_snapshots
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
        if let Some(snapshot) = self.cached.mls_snapshots.get(&scoped_key) {
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
        let key = mls_scope_snapshot_key_for_group(effective_scope, group_id)?;
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
                    .then(|| projection_mls_genesis_event_id(&state, effective_scope, group_id))
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

    /// Stamp the accepted epoch-0 Event id onto a local snapshot that does not
    /// carry one yet.
    ///
    /// [`crate::mls::persistence`] always mints a snapshot with
    /// `group_state_event_id: None`, and the id is stamped
    /// separately once the genesis Event comes back accepted. A device that
    /// loses that accept response — or re-syncs the group before the local
    /// stamp lands — therefore holds a genuine epoch-0 snapshot with no
    /// reference. A durable Realm projection is accepted server state, so
    /// recover the exact epoch-0 reference from it, but only when its group and
    /// effective scope match the local executable snapshot.
    pub fn reconcile_mls_genesis_group_state_ref_from_projection(
        &mut self,
        realm_id: &str,
        circle_id: Option<&str>,
    ) -> Result<bool, String> {
        self.ensure_cached_loaded();
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id)?;
        let Some(snapshot) = self.cached.mls_snapshots.get(&key).cloned() else {
            return Ok(false);
        };
        if snapshot.epoch != 0 {
            return Ok(false);
        }
        let scope = mls_realm_or_circle_scope(realm_id, circle_id)?;
        let genesis_ids =
            projection_mls_genesis_event_ids(&self.cached, &scope, &snapshot.group_id);
        let Some(event_id) = genesis_ids.first().cloned() else {
            return Ok(false);
        };
        // A locally recorded epoch-0 reference whose Event id appears nowhere
        // in the accepted projection was never on the wire — the classic case
        // is a build-time id persisted before the durable submit queue
        // re-authored the envelope (actor chain, HLC, CBA basis are all in the
        // digest preimage, so authoring changes the id). That is bookkeeping
        // damage, not a fork: the local group state is the very state the
        // accepted genesis exported. Repair it from the projection, but only
        // while the projection shows exactly one genesis for this scope —
        // a contested genesis still fails closed below.
        if genesis_ids.len() == 1
            && let Some(current) = self.cached.mls_group_state_refs.get(&key)
            && current.group_id == snapshot.group_id
            && current.epoch == 0
            && !genesis_ids.contains(&current.event_id)
        {
            tracing::warn!(
                %realm_id,
                stale_event_id = %current.event_id,
                accepted_event_id = %event_id,
                "repairing MLS genesis group-state reference that never matched an accepted Event",
            );
            let record = MlsGroupStateRefRecord {
                group_id: snapshot.group_id.clone(),
                epoch: 0,
                event_id,
            };
            self.cached
                .mls_group_state_refs
                .insert(key.clone(), record.clone());
            attach_group_state_ref_to_snapshot(&mut self.cached, &key, &record);
            self.flush()
                .map_err(|error| format!("persist repaired MLS group-state reference: {error}"))?;
            return Ok(true);
        }
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
        let key = mls_scope_snapshot_key_for_group(effective_scope, group_id)?;
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
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id).ok()?;
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
        let key = mls_effective_scope_snapshot_key(&realm_id, circle_id)?;
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
        let key = mls_effective_scope_snapshot_key(realm_id, circle_id)?;
        if self.cached.mls_coverage_stale.remove(&key).is_some() {
            let _ = self.flush();
        }
        Ok(())
    }
}

pub(crate) fn mls_effective_scope_snapshot_key(
    realm_id: &str,
    circle_id: Option<&str>,
) -> Result<String, String> {
    mls_realm_or_circle_scope(realm_id, circle_id).and_then(|scope| mls_scope_snapshot_key(&scope))
}

pub(crate) fn mls_scope_snapshot_key(
    effective_scope: &arkret_sdk::ScopeRef,
) -> Result<String, String> {
    let bytes = effective_scope
        .canonical_effective_scope_key_bytes()
        .map_err(|error| error.to_string())?;
    String::from_utf8(bytes).map_err(|error| format!("MLS scope key is not UTF-8: {error}"))
}

pub(crate) fn mls_scope_snapshot_key_for_group(
    effective_scope: &arkret_sdk::ScopeRef,
    group_id: &str,
) -> Result<String, String> {
    let key = mls_scope_snapshot_key(effective_scope)?;
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
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
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
            .save_mls_snapshot(realm_id, snapshot)
            .unwrap();
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
    fn accepted_genesis_projection_repairs_missing_group_state_reference() {
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
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
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
        store.save_mls_snapshot(realm_id, snapshot).unwrap();
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
    fn phantom_local_genesis_reference_is_repaired_from_projection() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-phantom-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        // The build-time id persisted before the durable queue re-authored the
        // envelope — it never reached the server.
        let phantom_event_id =
            arkret_sdk::EventId::new("ak:event:ASeq_1SMGFgL0OgySv7t3u5l9Sr1eV_HZwUb7tMFwZON")
                .unwrap();
        let accepted_event_id =
            arkret_sdk::EventId::new("ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl43vyk")
                .unwrap();
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
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
        store.save_mls_snapshot(realm_id, snapshot).unwrap();
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

        assert!(
            store
                .reconcile_mls_genesis_group_state_ref_from_projection(realm_id, None)
                .unwrap()
        );
        assert_eq!(
            store
                .mls_group_state_ref_for_effective_scope(realm_id, None, group_id, 0)
                .unwrap(),
            accepted_event_id
        );
        let restored = LocalStateStore::with_path(&path);
        assert_eq!(
            restored
                .mls_snapshot_for(realm_id)
                .unwrap()
                .group_state_event_id,
            Some(accepted_event_id)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn contested_genesis_projection_still_fails_closed() {
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
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
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
        store.save_mls_snapshot(realm_id, snapshot).unwrap();
        store
            .record_mls_group_state_ref_for_effective_scope(
                realm_id,
                None,
                group_id,
                0,
                local_event_id.clone(),
            )
            .unwrap();
        // Two accepted genesis events for the same scope: the genesis cell is
        // contested, so the local reference must NOT be silently rewritten.
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

        assert!(
            store
                .reconcile_mls_genesis_group_state_ref_from_projection(realm_id, None)
                .is_err()
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
    fn genesis_projection_with_another_group_is_not_used_as_authoring_reference() {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-projection-genesis-mismatch-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let group_id = "010203";
        let snapshot = crate::mls::persistence::MlsSnapshotEnvelope {
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
        store.save_mls_snapshot(realm_id, snapshot).unwrap();
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
        assert!(
            !store
                .reconcile_mls_genesis_group_state_ref_from_projection(realm_id, None)
                .unwrap()
        );
        let _ = std::fs::remove_file(path);
    }
}
