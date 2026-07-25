use super::*;

const AGENT_EVIDENCE_CACHE_MAX: usize = 4096;

impl LocalStateStore {
    pub fn cached_agent_signer_evidence_for_agent(
        &self,
        agent_id: &arkret_sdk::Did,
    ) -> Vec<CachedAgentSignerEvidence> {
        self.load()
            .agent_signer_evidence
            .values()
            .filter(|entry| entry.evidence.signing_key_binding.agent_id == *agent_id)
            .cloned()
            .collect()
    }

    pub fn cached_agent_signer_evidence(
        &self,
        agent_id: &arkret_sdk::Did,
        verification_method: &arkret_sdk::DidUrl,
        authorization_event_id: Option<&arkret_sdk::EventId>,
    ) -> Vec<CachedAgentSignerEvidence> {
        self.load()
            .agent_signer_evidence
            .values()
            .filter(|entry| {
                let binding = &entry.evidence.signing_key_binding;
                binding.agent_id == *agent_id
                    && binding.verification_method == *verification_method
                    && authorization_event_id
                        .is_none_or(|event_id| binding.agent_key_authorize_event_id == *event_id)
            })
            .cloned()
            .collect()
    }

    pub fn store_verified_agent_signer_evidence(
        &mut self,
        entry: CachedAgentSignerEvidence,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let binding = &entry.evidence.signing_key_binding;
        let new_head = entry
            .evidence
            .freshness_attestation
            .observed_frontier
            .as_str();
        for existing in self.cached.agent_signer_evidence.values() {
            let existing_binding = &existing.evidence.signing_key_binding;
            if existing_binding.agent_id != binding.agent_id
                || existing_binding.verification_method != binding.verification_method
                || existing_binding.agent_key_authorize_event_id
                    != binding.agent_key_authorize_event_id
            {
                continue;
            }
            let old_head = existing
                .evidence
                .freshness_attestation
                .observed_frontier
                .as_str();
            if old_head == new_head {
                continue;
            }
            let new_covers_old =
                seal_lineage_covers(&entry.evidence.seal_lineage, new_head, old_head);
            let old_covers_new =
                seal_lineage_covers(&existing.evidence.seal_lineage, old_head, new_head);
            if !new_covers_old {
                return Err(if old_covers_new {
                    "Agent signer evidence frontier rollback".to_owned()
                } else {
                    "Agent signer evidence frontier conflict".to_owned()
                });
            }
        }
        let key = crate::canonical::canonical_sha256(&serde_json::json!({
            "agent_id": binding.agent_id,
            "verification_method": binding.verification_method,
            "authorization_event_id": binding.agent_key_authorize_event_id,
            "state_root": entry.evidence.state_witness.state_root,
            "frontier": entry.evidence.state_witness.accepted_frontier,
        }))
        .map_err(|error| format!("Agent signer evidence cache key: {error}"))?;
        self.cached.agent_signer_evidence.insert(key, entry);
        while self.cached.agent_signer_evidence.len() > AGENT_EVIDENCE_CACHE_MAX {
            let Some(oldest) = self
                .cached
                .agent_signer_evidence
                .iter()
                .min_by_key(|(_, entry)| entry.cached_at_unix_ms)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached.agent_signer_evidence.remove(&oldest);
        }
        self.flush()
            .map_err(|error| format!("persist Agent signer evidence: {error}"))
    }
}

fn seal_lineage_covers(lineage: &[arkret_sdk::Seal], descendant: &str, ancestor: &str) -> bool {
    let by_id = lineage
        .iter()
        .map(|seal| (seal.id.as_str(), seal))
        .collect::<BTreeMap<_, _>>();
    let mut pending = vec![descendant];
    let mut seen = BTreeSet::new();
    while let Some(current) = pending.pop() {
        if current == ancestor {
            return true;
        }
        if !seen.insert(current) {
            continue;
        }
        let Some(seal) = by_id.get(current) else {
            continue;
        };
        pending.extend(seal.predecessor_refs.iter().map(arkret_sdk::SealId::as_str));
    }
    false
}
