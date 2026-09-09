use super::*;

impl LocalStateStore {
    pub fn trusted_mls_governance_checkpoint(
        &self,
        realm_id: &str,
    ) -> Option<arkret_sdk::MlsGovernanceVerificationCheckpoint> {
        self.load()
            .mls_governance_checkpoints
            .get(realm_id)
            .cloned()
    }

    pub fn pin_mls_governance_checkpoint(
        &mut self,
        realm_id: &str,
        checkpoint: arkret_sdk::MlsGovernanceVerificationCheckpoint,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        checkpoint
            .validate_checkpoint()
            .map_err(|error| format!("invalid MLS governance checkpoint: {error}"))?;
        if checkpoint.realm_id.as_str() != realm_id {
            return Err("MLS governance checkpoint belongs to another Realm".to_owned());
        }
        if let Some(existing) = self.cached.mls_governance_checkpoints.get(realm_id) {
            existing
                .validate_checkpoint()
                .map_err(|error| format!("invalid existing MLS governance checkpoint: {error}"))?;
            if existing == &checkpoint {
                return Ok(());
            }
            return Err(
                "a different MLS governance checkpoint is already pinned for this Realm".to_owned(),
            );
        }
        self.invalidate_agent_contexts_for_governance(&checkpoint);
        self.cached
            .mls_governance_checkpoints
            .insert(realm_id.to_owned(), checkpoint);
        self.flush()
            .map_err(|error| format!("persist MLS governance checkpoint: {error}"))
    }

    /// Install a newly verified full governance closure over the currently
    /// pinned one. This is used after a locally authored Control Seal: the
    /// complete target closure has been resolved and cryptographically
    /// verified, so advancing the pin is valid only when it retains every
    /// byte-exact Seal and Event trusted by the previous checkpoint.
    pub fn advance_verified_mls_governance_checkpoint(
        &mut self,
        realm_id: &str,
        checkpoint: arkret_sdk::MlsGovernanceVerificationCheckpoint,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        checkpoint
            .validate_checkpoint()
            .map_err(|error| format!("invalid advanced MLS governance checkpoint: {error}"))?;
        if checkpoint.realm_id.as_str() != realm_id {
            return Err("advanced MLS governance checkpoint belongs to another Realm".to_owned());
        }
        if let Some(existing) = self.cached.mls_governance_checkpoints.get(realm_id) {
            existing
                .validate_checkpoint()
                .map_err(|error| format!("invalid existing MLS governance checkpoint: {error}"))?;
            if existing == &checkpoint {
                return Ok(());
            }
            if !existing.accepted_seals.iter().all(|trusted| {
                checkpoint
                    .accepted_seals
                    .iter()
                    .any(|candidate| candidate == trusted)
            }) || !existing.accepted_events.iter().all(|trusted| {
                checkpoint
                    .accepted_events
                    .iter()
                    .any(|candidate| candidate == trusted)
            }) {
                return Err(
                    "advanced MLS governance checkpoint does not extend the pinned closure"
                        .to_owned(),
                );
            }
        }
        self.invalidate_agent_contexts_for_governance(&checkpoint);
        self.cached
            .mls_governance_checkpoints
            .insert(realm_id.to_owned(), checkpoint);
        self.flush()
            .map_err(|error| format!("persist advanced MLS governance checkpoint: {error}"))
    }

    pub(crate) fn cache_realm_governance_frontier(
        &mut self,
        frontier: arkret_sdk::RealmSealFrontierView,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        frontier
            .validate_protocol_bounds()
            .map_err(|error| error.to_string())?;
        let realm = frontier.realm_id.to_string();
        if let Some((_, _, current)) = self.cached.realm_governance_frontiers.get(&realm) {
            if current.observation_coordinate.service_id
                == frontier.observation_coordinate.service_id
                && current.observation_coordinate.sequence
                    > frontier.observation_coordinate.sequence
            {
                return Err(
                    "older Station frontier response arrived after a newer result".to_owned(),
                );
            }
        }
        let mut view = self.seal_view_for_realm(&realm);
        view.frontier = frontier
            .seal_basis
            .leaves
            .iter()
            .map(ToString::to_string)
            .collect();
        view.state_root = None;
        self.set_realm_seal_view(realm.clone(), view);
        self.cached.realm_governance_frontiers.insert(
            realm,
            (
                crate::identity::device_directory::cache_epoch(),
                Utc::now(),
                frontier,
            ),
        );
        while self.cached.realm_governance_frontiers.len() > 64 {
            let key = self
                .cached
                .realm_governance_frontiers
                .iter()
                .min_by_key(|(_, (_, time, _))| *time)
                .map(|(key, _)| key.clone())
                .expect("nonempty frontier cache");
            self.cached.realm_governance_frontiers.remove(&key);
        }
        Ok(())
    }

    pub(crate) fn station_realm_digest_suite(
        &self,
        realm: &str,
    ) -> Option<arkret_sdk::DigestSuite> {
        let local = self.load();
        let (epoch, time, frontier) = local.realm_governance_frontiers.get(realm)?;
        (*epoch == crate::identity::device_directory::cache_epoch()
            && *time + chrono::Duration::minutes(5) > Utc::now()
            && self.seal_view_for_realm(realm).frontier
                == frontier
                    .seal_basis
                    .leaves
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>())
        .then_some(frontier.live_digest_suite)
    }

    pub(crate) fn cache_mls_governance_result(
        &mut self,
        request: arkret_sdk::MlsGovernanceFrontierRequest,
        outcome: arkret_sdk::MlsGovernanceFrontierOutcome,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        outcome
            .validate_for_request(&request)
            .map_err(|error| error.to_string())?;
        let key = request
            .query_digest()
            .map_err(|error| error.to_string())?
            .to_string();
        self.cached.mls_governance_results.retain(|_, entry| {
            entry.request.effective_scope != request.effective_scope
                || entry.request.mls_group_id != request.mls_group_id
                || entry.request.previous_epoch != request.previous_epoch
                || entry.request.next_epoch != request.next_epoch
        });
        self.cached.mls_governance_results.insert(
            key,
            CachedMlsGovernanceResult {
                request,
                outcome,
                session_epoch: crate::identity::device_directory::cache_epoch(),
                received_at: Utc::now(),
            },
        );
        while self.cached.mls_governance_results.len() > 16
            || serde_json::to_vec(&self.cached.mls_governance_results)
                .map_err(|error| error.to_string())?
                .len()
                > 32 * 1024 * 1024
        {
            let key = self
                .cached
                .mls_governance_results
                .iter()
                .min_by_key(|(_, entry)| entry.received_at)
                .map(|(key, _)| key.clone())
                .ok_or_else(|| "MLS result cache is empty".to_owned())?;
            self.cached.mls_governance_results.remove(&key);
        }
        Ok(())
    }

    pub(crate) fn mls_frontier_input_for_authored_event(
        &self,
        event: &arkret_sdk::Event,
    ) -> Result<Vec<arkret_sdk::MlsSecurityFrontierLeaf>, String> {
        let binding: arkret_sdk::MlsGovernanceBindingPayload = serde_json::from_value(
            event
                .payload
                .get("governance_binding")
                .cloned()
                .ok_or_else(|| "MLS authored Event has no binding".to_owned())?,
        )
        .map_err(|error| error.to_string())?;
        for entry in self.load().mls_governance_results.values() {
            if entry.outcome.governance_binding == binding
                && event.seal_basis.as_ref() == Some(&entry.request.seal_basis)
            {
                if let Some(entry) =
                    self.cached_mls_governance_result_entry(&entry.request, Utc::now())?
                {
                    return Ok(entry.request.local_mls_leaves);
                }
            }
        }
        Err("MLS authored Event has no exact current Station leaf intent".to_owned())
    }

    pub(crate) fn cached_mls_governance_result_entry(
        &self,
        request: &arkret_sdk::MlsGovernanceFrontierRequest,
        now: DateTime<Utc>,
    ) -> Result<Option<CachedMlsGovernanceResult>, String> {
        let key = request
            .query_digest()
            .map_err(|error| error.to_string())?
            .to_string();
        let local = self.load();
        let Some(entry) = local.mls_governance_results.get(&key) else {
            return Ok(None);
        };
        let realm = request
            .effective_scope
            .realm_id_opt()
            .ok_or_else(|| "MLS request has no Realm".to_owned())?;
        if entry.session_epoch != crate::identity::device_directory::cache_epoch()
            || entry.received_at + chrono::Duration::minutes(5) <= now
            || self.seal_view_for_realm(realm.as_str()).frontier
                != request
                    .seal_basis
                    .leaves
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
        {
            return Ok(None);
        }
        entry
            .outcome
            .validate_for_request(request)
            .map_err(|error| error.to_string())?;
        Ok(Some(entry.clone()))
    }

    pub fn cached_mls_governance_binding_for_transition(
        &self,
        scope: &arkret_sdk::ScopeRef,
        group: &str,
        previous: u64,
        next: u64,
        now: DateTime<Utc>,
    ) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
        let local = self.load();
        let mut matches = local
            .mls_governance_results
            .values()
            .filter(|entry| {
                &entry.request.effective_scope == scope
                    && entry.request.mls_group_id.as_str() == group
                    && entry.request.previous_epoch == previous
                    && entry.request.next_epoch == next
            })
            .filter_map(|entry| {
                self.cached_mls_governance_result_entry(&entry.request, now)
                    .transpose()
            });
        let entry = matches
            .next()
            .transpose()?
            .ok_or_else(|| "MLS authoring requires a current Station result".to_owned())?;
        if matches.next().is_some() {
            return Err("MLS authoring intent has conflicting results".to_owned());
        }
        Ok(entry.outcome.governance_binding)
    }
}

impl LocalStateStore {
    pub(crate) fn cached_mls_accepted_artifact(
        &self,
        event_id: &arkret_sdk::EventId,
    ) -> Option<CachedMlsAcceptedArtifact> {
        let local = self.load();
        let entry = local.mls_accepted_artifacts.get(event_id.as_str())?;
        (self.active_authority().as_ref() == Some(&entry.authority)
            && entry.session_epoch == crate::identity::device_directory::cache_epoch()
            && entry.received_at + chrono::Duration::minutes(5) > Utc::now()
            && self
                .seal_view_for_realm(entry.event.realm_id.as_str())
                .frontier
                == entry.observed_frontier)
            .then(|| entry.clone())
    }

    pub(crate) fn cache_mls_accepted_artifact(
        &mut self,
        entry: CachedMlsAcceptedArtifact,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        if self.active_authority().as_ref() != Some(&entry.authority)
            || entry.session_epoch != crate::identity::device_directory::cache_epoch()
            || self
                .seal_view_for_realm(entry.event.realm_id.as_str())
                .frontier
                != entry.observed_frontier
        {
            return Err(
                "MLS acceptance response arrived after its account or observed frontier changed"
                    .to_owned(),
            );
        }
        entry
            .outcome
            .validate_for_request(&entry.request)
            .map_err(|error| error.to_string())?;
        let bytes = serde_json::to_vec(&entry)
            .map_err(|error| error.to_string())?
            .len();
        const MAX_BYTES: usize = 32 * 1024 * 1024;
        if bytes > MAX_BYTES {
            return Err(
                "MLS artifact and exact crypto inputs exceed the local 32 MiB budget".to_owned(),
            );
        }
        self.cached
            .mls_accepted_artifacts
            .insert(entry.event.event_id.to_string(), entry);
        while self.cached.mls_accepted_artifacts.len() > 16
            || serde_json::to_vec(&self.cached.mls_accepted_artifacts)
                .map_err(|error| error.to_string())?
                .len()
                > MAX_BYTES
        {
            let key = self
                .cached
                .mls_accepted_artifacts
                .iter()
                .min_by_key(|(_, entry)| entry.received_at)
                .map(|(key, _)| key.clone())
                .expect("nonempty cache");
            self.cached.mls_accepted_artifacts.remove(&key);
        }
        Ok(())
    }
}
