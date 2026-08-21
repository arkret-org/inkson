use arkret_sdk::{
    EventCandidateBinding, EventCandidateBindingKey, HistoryCandidateMaterialKey,
    HistoryCandidateMaterialRecord, HistoryCandidateOriginAttribution, HistoryEffectiveScope,
};
use chrono::{DateTime, Utc};

use super::*;

struct WritableCandidateState<'a>(&'a mut LocalStateStore);

impl garth::HistoryCandidateStateStore for WritableCandidateState<'_> {
    fn load_history_candidate_state(&self) -> garth::Result<garth::HistoryCandidateStoreSnapshot> {
        Ok(self.0.load().history_candidate_state)
    }

    fn save_history_candidate_state(
        &mut self,
        snapshot: &garth::HistoryCandidateStoreSnapshot,
    ) -> garth::Result<()> {
        self.0.ensure_cached_loaded();
        self.0.cached.history_candidate_state = snapshot.clone();
        self.0
            .flush()
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

struct ReadOnlyCandidateState<'a>(&'a LocalStateStore);

impl garth::HistoryCandidateStateStore for ReadOnlyCandidateState<'_> {
    fn load_history_candidate_state(&self) -> garth::Result<garth::HistoryCandidateStoreSnapshot> {
        Ok(self.0.load().history_candidate_state)
    }

    fn save_history_candidate_state(
        &mut self,
        _snapshot: &garth::HistoryCandidateStoreSnapshot,
    ) -> garth::Result<()> {
        Err(garth::Error::Protocol(
            "read-only history candidate state cannot be mutated".to_owned(),
        ))
    }
}

fn candidate_error(error: garth::Error) -> anyhow::Error {
    anyhow::anyhow!(error.to_string())
}

impl LocalStateStore {
    pub(crate) fn history_candidate_binding(
        &self,
        event_binding_key: &EventCandidateBindingKey,
        candidate_digest: &arkret_sdk::Hash,
    ) -> Option<EventCandidateBinding> {
        garth::HistoryCandidateEngine::new(ReadOnlyCandidateState(self))
            .event_binding(event_binding_key, candidate_digest)
            .ok()
            .flatten()
    }

    /// Durably receive an external candidate into Garth's bounded ledger.
    /// External material never enters the authoritative local MLS history.
    pub(crate) async fn receive_history_candidate(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        material_key: HistoryCandidateMaterialKey,
        secret: &[u8],
        attribution: HistoryCandidateOriginAttribution,
        now: DateTime<Utc>,
    ) -> anyhow::Result<bool> {
        garth::HistoryCandidateEngine::new(WritableCandidateState(self))
            .receive_external_candidate(secure_store, material_key, secret, attribution, now)
            .await
            .map_err(candidate_error)
    }

    /// Persist one immutable Event-local candidate result through Garth.
    pub(crate) fn record_history_candidate_binding(
        &mut self,
        binding: EventCandidateBinding,
        now: DateTime<Utc>,
    ) -> anyhow::Result<()> {
        garth::HistoryCandidateEngine::new(WritableCandidateState(self))
            .record_event_binding(binding, now)
            .map_err(candidate_error)
    }

    pub(crate) fn history_candidates_for(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        effective_scope: &HistoryEffectiveScope,
        mls_group_id: &str,
        epoch: u64,
    ) -> anyhow::Result<Vec<HistoryCandidateMaterialRecord>> {
        garth::HistoryCandidateEngine::new(ReadOnlyCandidateState(self))
            .candidates_for_epoch(secure_store, effective_scope, mls_group_id, epoch)
            .map_err(candidate_error)
    }
}
