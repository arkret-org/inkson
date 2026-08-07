use super::*;

const MLS_GOVERNANCE_PROOF_CACHE_MAX: usize = 16;
const MLS_GOVERNANCE_ACQUISITION_CACHE_MAX: usize = 2;
const MLS_GOVERNANCE_PROOF_CACHE_TTL_MINUTES: i64 = 5;

fn proof_cache_key(
    request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
) -> Result<String, String> {
    request
        .proof_request_digest()
        .map(|digest| digest.to_string())
        .map_err(|error| format!("hash MLS governance proof identity: {error}"))
}

impl LocalStateStore {
    pub fn cached_mls_governance_acquisition(
        &self,
        request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
    ) -> Result<Vec<arkret_sdk::MlsGovernanceProofBundle>, String> {
        let key = proof_cache_key(request)?;
        let state = self.load();
        let Some(entry) = state.mls_governance_proof_acquisitions.get(&key) else {
            return Ok(Vec::new());
        };
        let mut chunks = entry
            .chunks
            .iter()
            .map(|(index, value)| {
                serde_json::from_value::<arkret_sdk::MlsGovernanceProofBundle>(value.clone())
                    .map(|chunk| (*index, chunk))
                    .map_err(|error| format!("decode cached MLS governance proof chunk: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        chunks.sort_by_key(|(index, _)| *index);
        if chunks
            .iter()
            .enumerate()
            .any(|(position, (index, _))| position as u32 != *index)
        {
            return Err("cached MLS governance acquisition has a chunk gap".to_owned());
        }
        Ok(chunks.into_iter().map(|(_, chunk)| chunk).collect())
    }

    pub fn persist_mls_governance_acquisition_chunk(
        &mut self,
        request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
        chunk: &arkret_sdk::MlsGovernanceProofBundle,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let key = proof_cache_key(request)?;
        let value = serde_json::to_value(chunk)
            .map_err(|error| format!("serialize MLS governance proof chunk: {error}"))?;
        let entry = self
            .cached
            .mls_governance_proof_acquisitions
            .entry(key)
            .or_insert_with(|| MlsGovernanceProofAcquisition {
                proof_request_digest: chunk.proof_request_digest.clone(),
                bundle_digest: chunk.bundle_digest.clone(),
                chunks: BTreeMap::new(),
                updated_at: Utc::now(),
            });
        if entry.proof_request_digest != chunk.proof_request_digest
            || entry.bundle_digest != chunk.bundle_digest
        {
            entry.proof_request_digest = chunk.proof_request_digest.clone();
            entry.bundle_digest = chunk.bundle_digest.clone();
            entry.chunks.clear();
        }
        entry.chunks.insert(chunk.chunk.chunk_index(), value);
        entry.updated_at = Utc::now();
        while self.cached.mls_governance_proof_acquisitions.len()
            > MLS_GOVERNANCE_ACQUISITION_CACHE_MAX
        {
            let Some(oldest) = self
                .cached
                .mls_governance_proof_acquisitions
                .iter()
                .min_by_key(|(_, entry)| entry.updated_at)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached
                .mls_governance_proof_acquisitions
                .remove(&oldest);
        }
        self.flush()
            .map_err(|error| format!("persist MLS governance proof acquisition: {error}"))
    }

    pub fn clear_mls_governance_acquisition(
        &mut self,
        request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let key = proof_cache_key(request)?;
        if self
            .cached
            .mls_governance_proof_acquisitions
            .remove(&key)
            .is_some()
        {
            self.flush()
                .map_err(|error| format!("clear MLS governance proof acquisition: {error}"))?;
        }
        Ok(())
    }

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
        request: arkret_sdk::MlsGovernanceProofRequestBodyBody,
        governance_binding: arkret_sdk::MlsGovernanceBindingPayload,
        bundle: &arkret_sdk::MaterializedMlsGovernanceProofBundle,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let pinned = self
            .cached
            .mls_governance_trust_anchors
            .get(request.realm_id.as_str())
            .ok_or_else(|| "MLS governance trust anchor is not pinned".to_owned())?;
        if pinned != &bundle.trusted_anchor_seal_id {
            return Err("MLS governance proof trust anchor differs from the local pin".to_owned());
        }
        let key = proof_cache_key(&request)?;
        let entry = CachedMlsGovernanceProof {
            request,
            governance_binding,
            trusted_anchor_seal_id: bundle.trusted_anchor_seal_id.clone(),
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
        request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
        now: DateTime<Utc>,
    ) -> Result<Option<arkret_sdk::MaterializedMlsGovernanceProofBundle>, String> {
        let Some(entry) = self.cached_mls_governance_proof_entry(request, now)? else {
            return Ok(None);
        };
        serde_json::from_value(entry.bundle.clone())
            .map(Some)
            .map_err(|error| format!("decode cached MLS governance proof: {error}"))
    }

    pub fn cached_mls_governance_proof_entry(
        &self,
        request: &arkret_sdk::MlsGovernanceProofRequestBodyBody,
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
        Ok(Some(entry.clone()))
    }
}
