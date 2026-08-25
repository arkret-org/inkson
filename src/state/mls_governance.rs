use super::*;

const MLS_GOVERNANCE_PROOF_CACHE_MAX: usize = 16;
const MLS_GOVERNANCE_PROOF_CACHE_TTL_MINUTES: i64 = 5;

fn proof_cache_key(request: &arkret_sdk::MlsGovernanceProofRequestBody) -> Result<String, String> {
    request
        .query_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| format!("hash MLS governance proof identity: {error}"))
}

impl LocalStateStore {
    /// Installs a post-verification fixture for tests whose subject starts
    /// after governance verification. Cryptographic proof tests must exercise
    /// the SDK verifier and must not use this shortcut.
    #[cfg(test)]
    pub(crate) fn seed_test_verified_mls_governance_cache(
        &mut self,
        request: arkret_sdk::MlsGovernanceProofRequestBody,
        governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
        bundle: arkret_sdk::MlsGovernanceProofBundle,
        checkpoint: arkret_sdk::MlsGovernanceVerificationCheckpoint,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let realm_id = request
            .effective_scope
            .realm_id_opt()
            .ok_or_else(|| "test governance proof has no Realm scope".to_owned())?;
        let key = proof_cache_key(&request)?;
        self.cached
            .mls_governance_checkpoints
            .insert(realm_id.to_string(), checkpoint);
        self.cached.mls_governance_proofs.insert(
            key,
            CachedMlsGovernanceProof {
                proof_base_basis: request.proof_base_basis.clone(),
                proof_target_basis: request.proof_target_basis.clone(),
                request,
                governance_binding,
                bundle,
                verified_at: Utc::now(),
            },
        );
        self.flush()
            .map_err(|error| format!("persist test MLS governance state: {error}"))
    }

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
        self.cached
            .mls_governance_checkpoints
            .insert(realm_id.to_owned(), checkpoint);
        self.flush()
            .map_err(|error| format!("persist MLS governance checkpoint: {error}"))
    }

    pub fn cache_verified_mls_governance_proof(
        &mut self,
        request: arkret_sdk::MlsGovernanceProofRequestBody,
        governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
        bundle: &arkret_sdk::MlsGovernanceProofBundle,
        target_checkpoint: arkret_sdk::MlsGovernanceVerificationCheckpoint,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|error| format!("invalid MLS governance proof request: {error}"))?;
        bundle
            .validate_for_request(&request)
            .map_err(|error| format!("invalid MLS governance proof outcome: {error}"))?;
        let realm_id = request
            .effective_scope
            .realm_id_opt()
            .ok_or_else(|| "MLS governance proof has no Realm scope".to_owned())?
            .to_string();
        target_checkpoint
            .validate_checkpoint()
            .map_err(|error| format!("invalid verified MLS governance checkpoint: {error}"))?;
        if target_checkpoint.realm_id.as_str() != realm_id
            || target_checkpoint.basis != request.proof_target_basis
        {
            return Err("verified MLS governance checkpoint target mismatch".to_owned());
        }
        let Some(current_checkpoint) = self
            .cached
            .mls_governance_checkpoints
            .get(realm_id.as_str())
        else {
            return Err("MLS governance checkpoint is not pinned".to_owned());
        };
        if current_checkpoint.basis != request.proof_base_basis {
            return Err("MLS governance proof base is not the currently pinned basis".to_owned());
        }
        let key = proof_cache_key(&request)?;
        let entry = CachedMlsGovernanceProof {
            proof_base_basis: request.proof_base_basis.clone(),
            proof_target_basis: request.proof_target_basis.clone(),
            request,
            governance_binding,
            bundle: bundle.clone(),
            verified_at: Utc::now(),
        };
        self.cached.mls_governance_proofs.insert(key, entry);
        // T3 pin-forward is part of the same local durable commit as the
        // verified cache entry. A later proof starts from this complete target
        // antichain, so the near-current 1 MiB proof never has to replay an
        // ever-growing genesis-to-head closure.
        self.cached
            .mls_governance_checkpoints
            .insert(realm_id, target_checkpoint);
        while self.cached.mls_governance_proofs.len() > MLS_GOVERNANCE_PROOF_CACHE_MAX {
            let Some(oldest_key) = self
                .cached
                .mls_governance_proofs
                .iter()
                .min_by_key(|(_, entry)| entry.verified_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached.mls_governance_proofs.remove(&oldest_key);
        }
        self.flush()
            .map_err(|error| format!("persist MLS governance proof cache: {error}"))
    }

    pub fn cached_mls_governance_proof_entry(
        &self,
        request: &arkret_sdk::MlsGovernanceProofRequestBody,
        now: DateTime<Utc>,
    ) -> Result<Option<CachedMlsGovernanceProof>, String> {
        let key = proof_cache_key(request)?;
        let state = self.load();
        let Some(entry) = state.mls_governance_proofs.get(&key) else {
            return Ok(None);
        };
        if entry.verified_at + chrono::Duration::minutes(MLS_GOVERNANCE_PROOF_CACHE_TTL_MINUTES)
            <= now
        {
            return Ok(None);
        }
        if entry.request != *request
            || entry.proof_base_basis != request.proof_base_basis
            || entry.proof_target_basis != request.proof_target_basis
        {
            return Err("cached MLS governance proof identity changed".to_owned());
        }
        Ok(Some(entry.clone()))
    }

    pub fn cached_mls_governance_binding_for_transition(
        &self,
        effective_scope: &arkret_sdk::ScopeRef,
        mls_group_id: &str,
        previous_epoch: u64,
        next_epoch: u64,
        now: DateTime<Utc>,
    ) -> Result<arkret_sdk::MlsGovernanceBindingPayload, String> {
        let realm_id = effective_scope
            .realm_id_opt()
            .ok_or_else(|| "MLS governance transition has no Realm scope".to_owned())?;
        let state = self.load();
        let checkpoint = state
            .mls_governance_checkpoints
            .get(realm_id.as_str())
            .ok_or_else(|| "MLS governance checkpoint is not pinned".to_owned())?;
        let mut matches = state.mls_governance_proofs.values().filter(|entry| {
            entry.verified_at + chrono::Duration::minutes(MLS_GOVERNANCE_PROOF_CACHE_TTL_MINUTES)
                > now
                && &entry.request.effective_scope == effective_scope
                && entry.request.mls_group_id.as_str() == mls_group_id
                && entry.request.previous_epoch == previous_epoch
                && entry.request.next_epoch == next_epoch
                && entry.proof_target_basis == checkpoint.basis
        });
        let Some(entry) = matches.next() else {
            return Err("MLS governance proof is not cached for this exact transition".to_owned());
        };
        if matches.next().is_some() {
            return Err(
                "multiple MLS governance leaf sets are cached for this transition".to_owned(),
            );
        }
        Ok(entry.governance_binding.clone())
    }
}
