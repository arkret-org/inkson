use arkret_sdk::{
    EventCandidateBinding, HistoryCandidateMaterialRecord, HistoryCandidateOriginAttribution,
    HistoryEffectiveScope,
};
use chrono::{DateTime, Utc};

use super::*;

struct WritableCandidateState<'a>(&'a mut LocalStateStore);

impl garth::HistoryCandidateStateStore for WritableCandidateState<'_> {
    fn load_history_candidate_state(
        &self,
    ) -> garth::Result<arkret_sdk::history_store::HistoryMaterialLedger> {
        Ok(self.0.load().history_candidate_state)
    }

    fn save_history_candidate_state(
        &mut self,
        ledger: &arkret_sdk::history_store::HistoryMaterialLedger,
    ) -> garth::Result<()> {
        self.0.ensure_cached_loaded();
        self.0.cached.history_candidate_state = ledger.clone();
        self.0
            .flush()
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

struct ReadOnlyCandidateState<'a>(&'a LocalStateStore);

impl garth::HistoryCandidateStateStore for ReadOnlyCandidateState<'_> {
    fn load_history_candidate_state(
        &self,
    ) -> garth::Result<arkret_sdk::history_store::HistoryMaterialLedger> {
        Ok(self.0.load().history_candidate_state)
    }

    fn save_history_candidate_state(
        &mut self,
        _ledger: &arkret_sdk::history_store::HistoryMaterialLedger,
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
    /// Plan the durable receipt of an external candidate into Garth's bounded
    /// ledger. External material never enters the authoritative local MLS
    /// history.
    ///
    /// The admission is two-phase because its durable half writes the exact
    /// secret bytes asynchronously, and the store borrow must be released while
    /// that runs. Callers stage here, await
    /// [`garth::persist_staged_history_candidate_secret`], then
    /// [`Self::commit_history_candidate`] — normally through
    /// [`crate::runtime::input::StateStoreHandle::stage_then_commit`].
    pub(crate) fn stage_history_candidate(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        secret: &[u8],
        attribution: HistoryCandidateOriginAttribution,
        now: DateTime<Utc>,
    ) -> anyhow::Result<garth::StagedHistoryCandidate> {
        garth::HistoryCandidateEngine::new(ReadOnlyCandidateState(self))
            .stage_external_candidate(secure_store, secret, attribution, now)
            .map_err(candidate_error)
    }

    /// Publish a staged candidate whose bytes are already durable.
    pub(crate) fn commit_history_candidate(
        &mut self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
        staged: garth::StagedHistoryCandidate,
    ) -> anyhow::Result<bool> {
        garth::HistoryCandidateEngine::new(WritableCandidateState(self))
            .commit_staged_candidate(secure_store, staged)
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
