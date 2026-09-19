use super::*;

const HISTORICAL_AGENT_CANDIDATE_MAX: usize = 4096;
const HISTORICAL_AGENT_KEY_CACHE_MAX: usize = 4096;

fn canonical_cache_key(value: &impl serde::Serialize) -> Result<String, String> {
    String::from_utf8(
        arkret_sdk::canonical::canonical_json_bytes(value).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())
}

impl LocalStateStore {
    fn historical_agent_candidate_index(
        &self,
    ) -> std::borrow::Cow<'_, BTreeMap<String, HistoricalAgentEventCandidate>> {
        if self.loaded.load(std::sync::atomic::Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(self.effective_account_key().as_str())
        {
            std::borrow::Cow::Borrowed(&self.cached.historical_agent_event_candidates)
        } else {
            std::borrow::Cow::Owned(self.load().historical_agent_event_candidates)
        }
    }

    fn historical_agent_key_cache(
        &self,
    ) -> std::borrow::Cow<'_, BTreeMap<String, CachedHistoricalAgentSignerKey>> {
        if self.loaded.load(std::sync::atomic::Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(self.effective_account_key().as_str())
        {
            std::borrow::Cow::Borrowed(&self.cached.historical_agent_signer_keys_v2)
        } else {
            std::borrow::Cow::Owned(self.load().historical_agent_signer_keys_v2)
        }
    }

    pub(crate) fn historical_agent_event_candidates(&self) -> Vec<HistoricalAgentEventCandidate> {
        let recipient = self.active_authority();
        self.historical_agent_candidate_index()
            .values()
            .filter(|entry| recipient.as_ref() == Some(&entry.recipient_account_id))
            .cloned()
            .collect()
    }

    pub(crate) fn historical_agent_event_candidates_for_event(
        &self,
        event_id: &arkret_sdk::EventId,
    ) -> Vec<HistoricalAgentEventCandidate> {
        self.historical_agent_event_candidates()
            .into_iter()
            .filter(|entry| entry.target_ref.event_id == *event_id)
            .collect()
    }

    pub(crate) fn index_historical_agent_event_candidate(
        &mut self,
        entry: HistoricalAgentEventCandidate,
    ) -> Result<bool, String> {
        if self.active_authority().as_ref() != Some(&entry.recipient_account_id)
            || entry.receiver_id != entry.recipient_account_id.station_id
        {
            return Err("historical Agent candidate belongs to another recipient".to_owned());
        }
        if entry.realm_id != entry.accepted_event.realm_id
            || entry.target_ref.event_id != entry.accepted_event.event_id
            || entry.target_ref.stream_ref.realm_id() != &entry.realm_id
        {
            return Err(
                "historical Agent candidate does not match its exact committed Event".to_owned(),
            );
        }
        let expected_stream = arkret_wire::CommitStreamRef::from_scope(
            &entry.accepted_event.scope_ref,
            Some(entry.realm_id.clone()),
        )
        .map_err(|error| error.to_string())?;
        if entry.target_ref.stream_ref != expected_stream {
            return Err("historical Agent candidate names the wrong stream".to_owned());
        }
        let key = canonical_cache_key(&serde_json::json!([
            entry.recipient_account_id,
            entry.target_ref,
        ]))?;
        self.ensure_cached_loaded();
        if let Some(previous) = self.cached.historical_agent_event_candidates.get(&key) {
            let mut replay = entry.clone();
            replay.indexed_at_unix_ms = previous.indexed_at_unix_ms;
            if previous != &replay {
                return Err(
                    "historical Agent candidate conflicts at one committed coordinate".to_owned(),
                );
            }
            return Ok(false);
        }
        self.cached
            .historical_agent_event_candidates
            .insert(key, entry);
        while self.cached.historical_agent_event_candidates.len() > HISTORICAL_AGENT_CANDIDATE_MAX {
            let Some(oldest) = self
                .cached
                .historical_agent_event_candidates
                .iter()
                .min_by_key(|(_, entry)| entry.indexed_at_unix_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached
                .historical_agent_event_candidates
                .remove(&oldest);
        }
        self.flush()
            .map_err(|error| format!("persist historical Agent candidate: {error}"))?;
        Ok(true)
    }

    pub(crate) fn historical_agent_signer_keys(
        &self,
        actor: &arkret_sdk::ActorId,
        method: &arkret_sdk::DidUrl,
    ) -> Vec<CachedHistoricalAgentSignerKey> {
        let recipient = self.active_authority();
        self.historical_agent_key_cache()
            .values()
            .filter(|entry| {
                recipient.as_ref() == Some(&entry.recipient_account_id)
                    && entry.actor == *actor
                    && entry.verification_method == *method
            })
            .cloned()
            .collect()
    }

    pub(crate) fn historical_agent_signer_keys_for_realm(
        &self,
        realm: &str,
    ) -> Vec<CachedHistoricalAgentSignerKey> {
        let recipient = self.active_authority();
        self.historical_agent_key_cache()
            .values()
            .filter(|entry| {
                recipient.as_ref() == Some(&entry.recipient_account_id)
                    && entry.realm_id.as_str() == realm
            })
            .cloned()
            .collect()
    }

    pub(crate) fn store_historical_agent_signer_key(
        &mut self,
        entry: CachedHistoricalAgentSignerKey,
    ) -> Result<bool, String> {
        if self.active_authority().as_ref() != Some(&entry.recipient_account_id)
            || entry.receiver_id != entry.recipient_account_id.station_id
        {
            return Err("historical Agent key belongs to another recipient".to_owned());
        }
        if entry.target_ref.stream_ref.realm_id() != &entry.realm_id
            || entry.authorization_ref.stream_ref.realm_id() != &entry.realm_id
            || entry.authorization_ref.stream_position > entry.revision.stream_position
        {
            return Err("historical Agent key carries inconsistent commit coordinates".to_owned());
        }
        let key_bytes = arkret_sdk::base64url_decode(entry.public_key_b64u.as_str().as_bytes())
            .map_err(|error| error.to_string())?;
        if key_bytes.len() != 32 {
            return Err("historical Agent key must be 32 bytes".to_owned());
        }
        let candidate_matches =
            self.historical_agent_event_candidates()
                .into_iter()
                .any(|candidate| {
                    candidate.recipient_account_id == entry.recipient_account_id
                        && candidate.realm_id == entry.realm_id
                        && candidate.target_ref == entry.target_ref
                        && candidate.receiver_id == entry.receiver_id
                        && candidate.agent_actor_id == entry.actor
                        && candidate.verification_method == entry.verification_method
                });
        if !candidate_matches {
            return Err("historical Agent key has no exact committed target candidate".to_owned());
        }
        let identity = serde_json::json!([
            entry.recipient_account_id,
            entry.realm_id,
            entry.target_ref,
            entry.receiver_id,
            entry.actor,
            entry.verification_method,
        ]);
        let key = canonical_cache_key(&identity)?;
        self.ensure_cached_loaded();
        if let Some(previous) = self.cached.historical_agent_signer_keys_v2.get(&key) {
            let mut replay = entry.clone();
            replay.cached_at_unix_ms = previous.cached_at_unix_ms;
            if previous != &replay {
                return Err(
                    "historical Agent signing result conflicts for the same exact target"
                        .to_owned(),
                );
            }
            return Ok(false);
        }
        self.cached
            .historical_agent_signer_keys_v2
            .insert(key, entry);
        while self.cached.historical_agent_signer_keys_v2.len() > HISTORICAL_AGENT_KEY_CACHE_MAX {
            let Some(oldest) = self
                .cached
                .historical_agent_signer_keys_v2
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at_unix_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached.historical_agent_signer_keys_v2.remove(&oldest);
        }
        self.flush()
            .map_err(|error| format!("persist historical Agent key: {error}"))?;
        Ok(true)
    }
}
