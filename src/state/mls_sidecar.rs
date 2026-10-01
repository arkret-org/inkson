use super::*;

const MAX_HISTORICAL_MLS_AUTHOR_STATES: usize = 32;

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

impl LocalStateStore {
    // ── MLS group state persistence ─────────────────────────────────

    /// Install the group a Welcome joined together with the signed
    /// `keypackages/consume` command its endpoint owes for it, in one durable
    /// flush (device-lifecycle.md §9, decision 0121). The command is sent
    /// only once the returned barrier resolves; a failed flush is undone with
    /// [`Self::forget_pending_keypackage_consume`] so it is never sent.
    pub(crate) fn install_accepted_mls_welcome(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
        accepted_event_id: &arkret_sdk::EventId,
        consume: &arkret_sdk::KeyPackagesConsumeRequestBody,
    ) -> Result<LocalStatePersistBarrier, String> {
        self.ensure_cached_loaded();
        let claim_id = consume.claim_id.as_str().to_owned();
        let signed = arkret_sdk::canonical::canonical_json_string(consume)
            .map_err(|error| format!("KeyPackage consume command encoding: {error}"))?;
        let previous = self
            .cached
            .mls_pending_keypackage_consumes
            .insert(claim_id.clone(), signed);
        self.install_accepted_mls_transition(effective_scope, envelope, accepted_event_id)
            .inspect_err(|_| {
                match previous {
                    Some(previous) => self
                        .cached
                        .mls_pending_keypackage_consumes
                        .insert(claim_id.clone(), previous),
                    None => self
                        .cached
                        .mls_pending_keypackage_consumes
                        .remove(&claim_id),
                };
            })
    }

    /// Every durably owed `keypackages/consume` command, exactly as signed.
    pub(crate) fn pending_keypackage_consumes(
        &self,
    ) -> Vec<(String, arkret_sdk::KeyPackagesConsumeRequestBody)> {
        self.load()
            .mls_pending_keypackage_consumes
            .iter()
            .filter_map(|(claim_id, signed)| {
                serde_json::from_str(signed)
                    .ok()
                    .map(|request| (claim_id.clone(), request))
            })
            .collect()
    }

    /// Drop one owed consume command, settled by its Station or never made
    /// durable, and flush.
    pub(crate) fn forget_pending_keypackage_consume(
        &mut self,
        claim_id: &str,
    ) -> Result<LocalStatePersistBarrier, String> {
        self.ensure_cached_loaded();
        self.cached.mls_pending_keypackage_consumes.remove(claim_id);
        self.begin_durable_flush()
            .map_err(|error| error.to_string())
    }

    /// Install one Station-accepted MLS transition: the provider state the
    /// installer produced for it, and the accepted Event that materialized the
    /// exact `(group, epoch)` pair.
    ///
    /// The two writes belong together. A checkpoint without its accepted Event
    /// reference cannot be used as the base of the next transition, and an
    /// Event reference without the checkpoint names state this device cannot
    /// execute. Callers must await the returned barrier before treating the
    /// group as ready, so a crash never exposes a half-installed epoch.
    pub(crate) fn install_accepted_mls_transition(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        mut envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
        accepted_event_id: &arkret_sdk::EventId,
    ) -> Result<LocalStatePersistBarrier, String> {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
        envelope.group_state_event_id = Some(accepted_event_id.clone());
        let scope_key = mls_scope_checkpoint_key_for_group(effective_scope, &envelope.group_id)?;
        if let Some(current) = self.cached.mls_local_checkpoints.get(&scope_key) {
            if current.group_id == envelope.group_id && current.epoch > envelope.epoch {
                return Err(format!(
                    "refusing to install MLS epoch {} over durable epoch {}",
                    envelope.epoch, current.epoch
                ));
            }
            envelope.admission_epoch = current.admission_epoch;
            if current.group_id == envelope.group_id && current.epoch != envelope.epoch {
                self.cached.mls_historical_checkpoints.insert(
                    historical_mls_state_key(&scope_key, &current.group_id, current.epoch),
                    current.clone(),
                );
            }
        }
        let record = MlsGroupStateRefRecord {
            group_id: envelope.group_id.clone(),
            epoch: envelope.epoch,
            event_id: accepted_event_id.clone(),
        };
        if let Some(current) = self.cached.mls_group_state_refs.get(&scope_key) {
            if current.group_id != record.group_id {
                return Err(format!(
                    "MLS group-state group conflict for scope {scope_key}: {} != {}",
                    current.group_id, record.group_id
                ));
            }
            if current.epoch > record.epoch {
                return Err(format!(
                    "MLS group-state rollback for scope {scope_key}: {} < {}",
                    record.epoch, current.epoch
                ));
            }
            if current.epoch == record.epoch && current.event_id != record.event_id {
                return Err(format!(
                    "MLS group-state fork for scope {scope_key} epoch {}",
                    record.epoch
                ));
            }
            if current.epoch < record.epoch {
                let history_key =
                    historical_mls_state_key(&scope_key, &current.group_id, current.epoch);
                self.cached
                    .mls_historical_group_state_refs
                    .insert(history_key, current.clone());
            }
        }
        self.cached
            .mls_local_checkpoints
            .insert(scope_key.clone(), envelope);
        self.cached.mls_group_state_refs.insert(scope_key, record);
        prune_historical_mls_author_states(&mut self.cached);
        self.begin_durable_flush()
            .map_err(|error| error.to_string())
    }

    /// The authority-signed typed current results of `realm_id` in the
    /// installed product view; empty while no view of that Realm is installed.
    pub(crate) fn realm_current_state_entries(
        &self,
        realm_id: &str,
    ) -> Vec<arkret_wire::TypedCurrentResult> {
        self.realm_current_view_entries(realm_id)
            .unwrap_or_default()
    }

    /// The scope's current MLS group state, i.e. the authority-signed evidence
    /// that this scope has an accepted `ak.mls.genesis` and is therefore
    /// irreversibly encrypted. `None` means "not delivered yet", never
    /// "definitely plaintext".
    pub fn current_mls_group_for_scope(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
    ) -> Option<arkret_wire::MlsGroupCurrent> {
        let realm_id = effective_scope.realm_id_opt()?;
        let entries = self.realm_current_view_entries(realm_id.as_str())?;
        crate::current_projection::current_mls_group(&entries, effective_scope)
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

    /// Read committed provider state, excluding the live cache and queued writes.
    pub(crate) fn durable_mls_checkpoint_for_scope(
        &self,
        scope: &arkret_sdk::ScopeRef,
    ) -> anyhow::Result<Option<crate::mls::persistence::MlsLocalCheckpointEnvelope>> {
        let namespace = self.effective_account_key();
        anyhow::ensure!(
            self.cached_account_key
                .as_deref()
                .is_none_or(|cached| cached == namespace),
            "active account changed before the durable MLS checkpoint read"
        );
        #[cfg(not(target_arch = "wasm32"))]
        let bytes = match std::fs::read(self.account_state_path(&namespace)) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        #[cfg(target_arch = "wasm32")]
        let bytes = {
            anyhow::ensure!(
                crate::secure_key_store::wasm_secure_store_ready(),
                "secure account-state store is not ready"
            );
            let store = crate::secure_key_store::default_secure_key_store("inkson");
            let Some(bytes) = store.get_secret_bytes(&account_state_key(&namespace))? else {
                return Ok(None);
            };
            bytes.as_ref().to_vec()
        };
        let state: ClientLocalState = serde_json::from_slice(&bytes)?;
        let key = mls_scope_checkpoint_key(scope).map_err(anyhow::Error::msg)?;
        Ok(match scope {
            arkret_sdk::ScopeRef::Sidecar { .. } => {
                let prefix = format!("{key}\u{1f}");
                state
                    .mls_local_checkpoints
                    .iter()
                    .filter(|(key, _)| key.starts_with(&prefix))
                    .max_by_key(|(_, snapshot)| snapshot.epoch)
                    .map(|(_, snapshot)| snapshot.clone())
            }
            _ => state.mls_local_checkpoints.get(&key).cloned(),
        })
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

    /// Snapshot of every persisted MLS envelope. Used by the boot
    /// path to rehydrate every known Realm's group in one pass and by
    /// device-recovery flows to enumerate the encrypted snapshots that
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

    /// Retain locally authored application bytes by their exact ciphertext digest.
    /// MLS cannot decrypt a normal echo from its own leaf after the send ratchet
    /// advances. The existing secure cache supplies rendering without ratchet replay.
    pub(crate) fn retain_authored_mls_plaintext(
        &mut self,
        realm_id: &str,
        payload_digest: &arkret_sdk::Hash,
        plaintext: &[u8],
    ) -> anyhow::Result<()> {
        use base64::Engine as _;
        self.absorb_mls_receive_overlay();
        self.cached
            .mls_decrypted_plaintext
            .entry(realm_id.to_owned())
            .or_default()
            .insert(
                payload_digest.to_string(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(plaintext),
            );
        self.flush()?;
        self.persist_e2ee_plaintext_cache_if_ready();
        Ok(())
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
        mut envelope: crate::mls::persistence::MlsLocalCheckpointEnvelope,
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
        if previous_snapshot
            .as_ref()
            .is_some_and(|previous| previous.epoch == envelope.epoch)
        {
            // Application decrypt advances only the receive ratchet. Keep the
            // already verified Event anchor for this exact group and epoch;
            // encrypt_state() creates a new envelope with that field empty.
            envelope.group_state_event_id = self
                .mls_group_state_ref_for_scope(effective_scope, &envelope.group_id, envelope.epoch)
                .ok();
        }
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
    pub(crate) fn mark_mls_genesis_emitted_with_event(
        &mut self,
        realm_id: impl Into<String>,
        genesis_event_id: &arkret_sdk::EventId,
    ) -> Result<LocalStatePersistBarrier, String> {
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

    pub(crate) fn mark_mls_genesis_emitted_for_effective_scope_with_event(
        &mut self,
        realm_id: impl Into<String>,
        circle_id: Option<&str>,
        genesis_event_id: &arkret_sdk::EventId,
    ) -> Result<LocalStatePersistBarrier, String> {
        let realm_id = realm_id.into();
        let scope = mls_realm_or_circle_scope(&realm_id, circle_id)?;
        self.mark_mls_genesis_emitted_for_scope_with_event(&scope, genesis_event_id)
    }

    pub(crate) fn mark_mls_genesis_emitted_for_scope_with_event(
        &mut self,
        effective_scope: &arkret_sdk::ScopeRef,
        genesis_event_id: &arkret_sdk::EventId,
    ) -> Result<LocalStatePersistBarrier, String> {
        self.ensure_cached_loaded();
        self.absorb_mls_receive_overlay();
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
        let snapshot = self
            .cached
            .mls_local_checkpoints
            .get(&scoped_key)
            .cloned()
            .ok_or_else(|| {
                "accepted MLS Genesis publication requires its private checkpoint".to_owned()
            })?;
        if snapshot.epoch > 0 {
            let current = self
                .cached
                .mls_group_state_refs
                .get(&scoped_key)
                .ok_or_else(|| "later MLS epoch has no accepted state reference".to_owned())?;
            if current.group_id != snapshot.group_id
                || current.epoch != snapshot.epoch
                || snapshot.group_state_event_id.as_ref() != Some(&current.event_id)
            {
                return Err("later MLS epoch is not bound to its accepted state reference".into());
            }
        } else {
            let record = MlsGroupStateRefRecord {
                group_id: snapshot.group_id.clone(),
                epoch: 0,
                event_id: genesis_event_id.clone(),
            };
            if self
                .cached
                .mls_group_state_refs
                .get(&scoped_key)
                .is_some_and(|current| current != &record)
            {
                return Err(
                    "accepted MLS Genesis conflicts with the installed state reference".into(),
                );
            }
            if self.cached.mls_group_state_refs.get(&scoped_key) != Some(&record) {
                self.cached
                    .mls_group_state_refs
                    .insert(scoped_key.clone(), record.clone());
            }
            attach_group_state_ref_to_snapshot(&mut self.cached, &scoped_key, &record);
        }
        self.cached.mls_genesis_emitted.insert(scoped_key);
        self.persist_e2ee_plaintext_cache_if_ready();
        self.begin_durable_flush()
            .map_err(|error| error.to_string())
    }

    /// Remove a creator-side Genesis completion marker after the authenticated
    /// Station authoritatively reports that no accepted Genesis exists.
    ///
    /// This is intentionally limited to an epoch-0 Realm snapshot and refuses
    /// to discard a transition that the accepted-artifact consumer has made
    /// durable. Callers must perform the remote absence check before entering
    /// this local repair boundary.
    pub(crate) fn clear_unaccepted_creator_mls_genesis(
        &mut self,
        realm_id: &str,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let scope = mls_realm_or_circle_scope(realm_id, None)?;
        let key = mls_scope_checkpoint_key(&scope)?;
        let snapshot = self
            .cached
            .mls_local_checkpoints
            .get(&key)
            .ok_or_else(|| "cannot repair a missing creator MLS snapshot".to_owned())?;
        if snapshot.epoch != 0 {
            return Err("refusing to repair creator MLS state beyond epoch 0".to_owned());
        }
        // The scope's own current MLS group state is the authority on whether a
        // Genesis was accepted. Repair is only ever the removal of an
        // unaccepted local marker, never the discarding of a transition the
        // Station has already committed.
        if self.current_mls_group_for_scope(&scope).is_some() {
            return Err("refusing to discard an accepted creator MLS transition".to_owned());
        }

        let mut changed = self.cached.mls_genesis_emitted.remove(&key);
        changed |= self.cached.mls_group_state_refs.remove(&key).is_some();
        if let Some(snapshot) = self.cached.mls_local_checkpoints.get_mut(&key)
            && snapshot.group_state_event_id.take().is_some()
        {
            changed = true;
        }
        if changed {
            self.flush().map_err(|error| error.to_string())?;
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

    /// The installed product view's answer about `effective_scope`'s MLS
    /// activation.
    ///
    /// The view is read from the durable current index; its `mls_group`
    /// absence answers only when it was read at a complete verified cut. A
    /// Realm without such a view is [`ScopeMlsCurrent::Unknown`], never
    /// plaintext. New application bodies are gated by
    /// [`crate::mls::send_gate`], which reads the durable index directly.
    ///
    /// [`ScopeMlsCurrent::Unknown`]: crate::current_projection::ScopeMlsCurrent::Unknown
    pub(crate) fn installed_scope_mls_current(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
    ) -> crate::current_projection::ScopeMlsCurrent {
        self.current_product_view()
            .map(|view| view.scope_mls_current(effective_scope))
            .unwrap_or(crate::current_projection::ScopeMlsCurrent::Unknown)
    }

    /// Installed groups behind their own verified public current. Unknown
    /// scopes remain pending; enumeration grants no membership or send right.
    pub(crate) fn mls_scopes_needing_tail_recovery(&self) -> Vec<arkret_sdk::ScopeRef> {
        let realms = self
            .load()
            .mls_local_checkpoints
            .values()
            .map(|checkpoint| checkpoint.realm_id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        realms
            .iter()
            .flat_map(|realm| self.local_mls_scopes_in_realm(realm))
            .filter(|scope| {
                let Some(current) = self.current_mls_group_for_scope(scope) else {
                    return false;
                };
                let Ok(group_id) = scope.canonical_mls_group_id() else {
                    return false;
                };
                self.mls_checkpoint_for_scope_and_group(scope, group_id.as_str())
                    .is_some_and(|base| {
                        base.group_state_event_id.is_some() && base.epoch < current.epoch
                    })
            })
            .collect()
    }

    /// Every local effective scope inside this Realm, the Realm first.
    pub(crate) fn local_mls_scopes_in_realm(&self, realm_id: &str) -> Vec<arkret_sdk::ScopeRef> {
        let Ok(realm) = arkret_sdk::RealmId::new(realm_id.trim().to_owned()) else {
            return Vec::new();
        };
        let mut scopes = vec![arkret_sdk::ScopeRef::Realm {
            realm_id: realm.clone(),
        }];
        let mut circles = std::collections::BTreeSet::new();
        for entry in self.realm_current_state_entries(realm.as_str()) {
            if let arkret_wire::TypedCurrentResult::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                ..
            } = &entry
                && let arkret_sdk::ScopeRef::Circle {
                    realm_id: scope_realm,
                    circle_id,
                } = scope_ref
                && scope_realm == &realm
            {
                circles.insert(circle_id.clone());
            }
        }
        // A Circle scope keys its local checkpoint by the bare Circle id
        // (`canonical_effective_scope_key_bytes`), so a Circle group installed
        // on this device is visible even before its current entry arrives.
        for key in self.load().mls_local_checkpoints.keys() {
            if let Ok(circle_id) = arkret_sdk::CircleId::new(key.clone()) {
                circles.insert(circle_id);
            }
        }
        scopes.extend(
            circles
                .into_iter()
                .map(|circle_id| arkret_sdk::ScopeRef::Circle {
                    realm_id: realm.clone(),
                    circle_id,
                }),
        );
        scopes
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
    /// scope, when its last E2EE application ordinary Event was refused for
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

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn temp_store(name: &str) -> (LocalStateStore, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "inkson-mls-sidecar-{name}-{}-{}.json",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        (LocalStateStore::with_path(&path), path)
    }

    fn realm_scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM.to_owned()).unwrap(),
        }
    }

    fn event_id(suffix: &str) -> arkret_sdk::EventId {
        arkret_sdk::EventId::new(format!(
            "ak:event:AXBcp13trH3bPXvj0eHppCpGqJZWL9yqE3cf2Tl4{suffix}"
        ))
        .unwrap()
    }

    fn checkpoint(epoch: u64, body: &[u8]) -> crate::mls::persistence::MlsLocalCheckpointEnvelope {
        crate::mls::persistence::encrypt_state(REALM, "AQID", epoch, body, "test-secret", &[7; 16])
    }

    #[tokio::test]
    async fn installing_a_transition_archives_the_superseded_epoch_and_binds_its_event() {
        let (mut store, path) = temp_store("install");
        let scope = realm_scope();
        store
            .install_accepted_mls_transition(&scope, checkpoint(1, b"one"), &event_id("aaaa"))
            .unwrap()
            .wait()
            .await
            .unwrap();
        store
            .install_accepted_mls_transition(&scope, checkpoint(2, b"two"), &event_id("bbbb"))
            .unwrap()
            .wait()
            .await
            .unwrap();

        assert_eq!(
            store
                .mls_group_state_ref_for_scope(&scope, "AQID", 2)
                .unwrap(),
            event_id("bbbb")
        );
        // The superseded epoch stays addressable as the base of the accepted
        // transition that replaced it.
        assert_eq!(
            store
                .mls_group_state_ref_for_scope(&scope, "AQID", 1)
                .unwrap(),
            event_id("aaaa")
        );
        assert_eq!(store.mls_checkpoint_for_scope(&scope).unwrap().epoch, 2);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn a_rollback_or_a_same_epoch_fork_is_refused() {
        let (mut store, path) = temp_store("fork");
        let scope = realm_scope();
        store
            .install_accepted_mls_transition(&scope, checkpoint(2, b"two"), &event_id("bbbb"))
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert!(
            store
                .install_accepted_mls_transition(&scope, checkpoint(1, b"one"), &event_id("aaaa"))
                .is_err()
        );
        assert!(
            store
                .install_accepted_mls_transition(&scope, checkpoint(2, b"other"), &event_id("cccc"))
                .is_err()
        );
        assert_eq!(store.mls_checkpoint_for_scope(&scope).unwrap().epoch, 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_undelivered_current_view_never_reads_as_no_accepted_genesis() {
        use crate::current_projection::{RealmCurrentView, ScopeMlsCurrent};
        let (mut store, path) = temp_store("pending");
        let scope = realm_scope();
        assert_eq!(
            store.installed_scope_mls_current(&scope),
            ScopeMlsCurrent::Unknown
        );
        store.save_realm_tree_projection(REALM, json!({"summary": {"title": "r"}}));
        assert_eq!(
            store.installed_scope_mls_current(&scope),
            ScopeMlsCurrent::Unknown
        );
        // A view read outside a complete verified cut does not answer absence.
        store
            .install_current_product_view(RealmCurrentView::new(REALM, Vec::new(), false).unwrap())
            .unwrap();
        assert_eq!(
            store.installed_scope_mls_current(&scope),
            ScopeMlsCurrent::Unknown
        );
        // A complete cut without this scope's MLS group entry is the
        // authoritative "still plaintext" answer.
        crate::test_support::install_current_entries(&mut store, REALM, Vec::new());
        assert_eq!(
            store.installed_scope_mls_current(&scope),
            ScopeMlsCurrent::NotActivated
        );
        assert!(store.current_mls_group_for_scope(&scope).is_none());
        let _ = std::fs::remove_file(path);
    }
}
