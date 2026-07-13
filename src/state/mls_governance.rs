use super::*;

const MLS_GOVERNANCE_PROOF_CACHE_MAX: usize = 16;
const MLS_GOVERNANCE_PROOF_CACHE_TTL_MINUTES: i64 = 5;

fn proof_cache_key(request: &arkret_sdk::MlsGovernanceProofRequest) -> Result<String, String> {
    crate::canonical::canonical_sha256(
        &serde_json::to_value(request)
            .map_err(|error| format!("serialize MLS governance proof request: {error}"))?,
    )
    .map_err(|error| format!("hash MLS governance proof request: {error}"))
}

impl LocalStateStore {
    pub fn trusted_mls_governance_anchor(&self, realm_id: &str) -> Option<arkret_sdk::SealId> {
        self.load()
            .mls_governance_trust_anchors
            .get(realm_id)
            .cloned()
    }

    pub fn pin_mls_governance_anchor(
        &mut self,
        realm_id: &str,
        anchor: &arkret_sdk::SealId,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        if let Some(existing) = self.cached.mls_governance_trust_anchors.get(realm_id) {
            if existing != anchor {
                return Err(format!(
                    "MLS governance trust anchor mismatch for {realm_id}: pinned {existing}, received {anchor}"
                ));
            }
            return Ok(());
        }
        self.cached
            .mls_governance_trust_anchors
            .insert(realm_id.to_owned(), anchor.clone());
        self.flush()
            .map_err(|error| format!("persist MLS governance trust anchor: {error}"))
    }

    pub fn cache_verified_mls_governance_proof(
        &mut self,
        request: arkret_sdk::MlsGovernanceProofRequest,
        bundle: &arkret_sdk::MlsGovernanceProofBundle,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let pinned = self
            .cached
            .mls_governance_trust_anchors
            .get(request.realm_id.as_str())
            .ok_or_else(|| "MLS governance trust anchor is not pinned".to_owned())?;
        if pinned != &bundle.trust_anchor_seal_id {
            return Err("MLS governance proof trust anchor differs from the local pin".to_owned());
        }
        let key = proof_cache_key(&request)?;
        let entry = CachedMlsGovernanceProof {
            request,
            governance_binding: bundle.governance_binding.clone(),
            trust_anchor_seal_id: bundle.trust_anchor_seal_id.clone(),
            accepted_seal_id: bundle.accepted_seal_id.clone(),
            bundle: serde_json::to_value(bundle)
                .map_err(|error| format!("serialize verified MLS governance proof: {error}"))?,
            verified_at: Utc::now(),
        };
        self.cached.mls_governance_proofs.insert(key, entry);
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

    pub fn cached_mls_governance_proof(
        &self,
        request: &arkret_sdk::MlsGovernanceProofRequest,
        now: DateTime<Utc>,
    ) -> Result<Option<arkret_sdk::MlsGovernanceProofBundle>, String> {
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
        serde_json::from_value(entry.bundle.clone())
            .map(Some)
            .map_err(|error| format!("decode cached MLS governance proof: {error}"))
    }

    pub fn invalidate_mls_governance_proofs_for_realm(&mut self, realm_id: &str) {
        self.ensure_cached_loaded();
        let before = self.cached.mls_governance_proofs.len();
        self.cached
            .mls_governance_proofs
            .retain(|_, entry| entry.request.realm_id.as_str() != realm_id);
        if self.cached.mls_governance_proofs.len() != before {
            let _ = self.flush();
        }
    }
}
