use super::*;

const HISTORICAL_AGENT_KEY_CACHE_MAX: usize = 4096;

impl LocalStateStore {
    fn historical_agent_key_cache(
        &self,
    ) -> std::borrow::Cow<'_, BTreeMap<String, CachedHistoricalAgentSignerKey>> {
        if self.loaded.load(std::sync::atomic::Ordering::Relaxed)
            && self.cached_account_key.as_deref() == Some(self.effective_account_key().as_str())
        {
            std::borrow::Cow::Borrowed(&self.cached.historical_agent_signer_keys)
        } else {
            std::borrow::Cow::Owned(self.load().historical_agent_signer_keys)
        }
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
                    && entry.key.actor == *actor
                    && entry.key.verification_method == *method
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
    ) -> Result<(), String> {
        entry.key.validate().map_err(|error| error.to_string())?;
        if self.active_authority().as_ref() != Some(&entry.recipient_account_id)
            || entry.receiver_id != entry.recipient_account_id.station_id
        {
            return Err("historical Agent key belongs to another recipient".to_owned());
        }
        let identity = serde_json::json!([
            entry.recipient_account_id,
            entry.realm_id,
            entry.event_id,
            entry.receiver_id,
            entry.accepted_at,
            entry.producer_signer_evidence_ref,
            entry.key.actor,
            entry.key.verification_method,
        ]);
        let key = String::from_utf8(
            arkret_sdk::canonical::canonical_json_bytes(&identity)
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        self.ensure_cached_loaded();
        if let Some(previous) = self.cached.historical_agent_signer_keys.get(&key)
            && previous.key != entry.key
        {
            return Err(
                "historical Agent signing result conflicts for the same admission".to_owned(),
            );
        }
        self.cached.historical_agent_signer_keys.insert(key, entry);
        while self.cached.historical_agent_signer_keys.len() > HISTORICAL_AGENT_KEY_CACHE_MAX {
            let Some(oldest) = self
                .cached
                .historical_agent_signer_keys
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at_unix_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached.historical_agent_signer_keys.remove(&oldest);
        }
        self.flush()
            .map_err(|error| format!("persist historical Agent key: {error}"))
    }
}
