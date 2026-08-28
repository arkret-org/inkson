use super::*;

const AGENT_EVIDENCE_CACHE_MAX: usize = 4096;

impl LocalStateStore {
    pub fn cached_agent_signer_evidence_for_agent(
        &self,
        agent_id: &arkret_sdk::DidCoreId,
    ) -> Vec<CachedAgentSignerEvidence> {
        self.load()
            .agent_signer_evidence
            .values()
            .filter(|entry| agent_signer_evidence_binding(&entry.evidence).agent_id == *agent_id)
            .cloned()
            .collect()
    }

    pub fn cached_agent_signer_evidence(
        &self,
        agent_id: &arkret_sdk::DidCoreId,
        verification_method: &arkret_sdk::DidUrl,
    ) -> Vec<CachedAgentSignerEvidence> {
        self.load()
            .agent_signer_evidence
            .values()
            .filter(|entry| {
                let binding = agent_signer_evidence_binding(&entry.evidence);
                binding.agent_id == *agent_id && binding.verification_method == *verification_method
            })
            .cloned()
            .collect()
    }

    pub fn store_verified_agent_signer_evidence(
        &mut self,
        entry: CachedAgentSignerEvidence,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        let binding = agent_signer_evidence_binding(&entry.evidence);
        if matches!(
            &entry.verification_context,
            CachedAgentSignerEvidenceContext::CurrentSignal { .. }
        ) {
            let new_head = agent_signer_evidence_frontier(&entry.evidence).as_str();
            for existing in self.cached.agent_signer_evidence.values() {
                if !matches!(
                    &existing.verification_context,
                    CachedAgentSignerEvidenceContext::CurrentSignal { .. }
                ) {
                    continue;
                }
                let existing_binding = agent_signer_evidence_binding(&existing.evidence);
                if existing_binding.agent_id != binding.agent_id
                    || existing_binding.verification_method != binding.verification_method
                    || existing_binding.agent_key_authorize_event_id
                        != binding.agent_key_authorize_event_id
                {
                    continue;
                }
                let old_head = agent_signer_evidence_frontier(&existing.evidence).as_str();
                if old_head == new_head {
                    continue;
                }
                let new_covers_old = seal_lineage_covers(
                    agent_signer_evidence_lineage(&entry.evidence),
                    new_head,
                    old_head,
                );
                let old_covers_new = seal_lineage_covers(
                    agent_signer_evidence_lineage(&existing.evidence),
                    old_head,
                    new_head,
                );
                if !new_covers_old {
                    return Err(if old_covers_new {
                        "Agent signer evidence frontier rollback".to_owned()
                    } else {
                        "Agent signer evidence frontier conflict".to_owned()
                    });
                }
            }
        }
        let key = crate::canonical::canonical_sha256(&serde_json::json!({
            "agent_id": binding.agent_id,
            "verification_method": binding.verification_method,
            "authorization_event_id": binding.agent_key_authorize_event_id,
            "state_root": agent_signer_evidence_snapshot(&entry.evidence).core.frontier_state_root,
            "frontier": agent_signer_evidence_frontier(&entry.evidence),
            "verification_context": &entry.verification_context,
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

fn agent_signer_evidence_snapshot(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &arkret_sdk::AgentAuthoritySnapshot {
    match evidence {
        arkret_sdk::AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        }
        | arkret_sdk::AgentSignerEvidence::HistoricalEvent {
            admission_evidence, ..
        } => &admission_evidence.agent_authority_snapshot,
    }
}

fn agent_signer_evidence_binding(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &arkret_sdk::AgentSigningKeyBinding {
    &agent_signer_evidence_snapshot(evidence)
        .core
        .signing_key_binding
}

fn agent_signer_evidence_frontier(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &arkret_sdk::SealId {
    &agent_signer_evidence_snapshot(evidence)
        .core
        .frontier_seal_id
}

fn agent_signer_evidence_lineage(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &[arkret_sdk::Seal] {
    &agent_signer_evidence_snapshot(evidence).core.seal_lineages
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
