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
            .filter(|entry| {
                !entry.invalidated
                    && agent_signer_evidence_binding(&entry.evidence).agent_id == *agent_id
            })
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
                !entry.invalidated
                    && binding.agent_id == *agent_id
                    && binding.verification_method == *verification_method
            })
            .cloned()
            .collect()
    }

    pub(crate) fn invalidate_agent_current_contexts(
        &mut self,
        actor: &arkret_sdk::ActorId,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        for entry in self.cached.agent_signer_evidence.values_mut() {
            if matches!(&entry.verification_context, CachedAgentSignerEvidenceContext::CurrentRelation { agent_actor_id, .. } if agent_actor_id == actor)
            {
                entry.invalidated = true;
                entry.verified_current_key = None;
            }
        }
        self.flush()
            .map_err(|error| format!("persist Agent authorization invalidation: {error}"))
    }

    pub(super) fn invalidate_agent_contexts_for_governance(
        &mut self,
        checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
    ) {
        for entry in self.cached.agent_signer_evidence.values_mut() {
            if !agent_context_matches_checkpoint(entry, checkpoint) {
                entry.invalidated = true;
                entry.verified_current_key = None;
            }
        }
    }

    fn agent_context_has_no_observed_invalidation(
        &self,
        entry: &CachedAgentSignerEvidence,
    ) -> bool {
        !entry.invalidated
            && self
                .load()
                .mls_governance_checkpoints
                .values()
                .all(|checkpoint| agent_context_matches_checkpoint(entry, checkpoint))
    }

    pub fn store_verified_agent_signer_evidence(
        &mut self,
        entry: CachedAgentSignerEvidence,
    ) -> Result<(), String> {
        self.ensure_cached_loaded();
        if !self.agent_context_has_no_observed_invalidation(&entry) {
            return Err("Agent authorization predates an observed governance change".to_owned());
        }
        let binding = agent_signer_evidence_binding(&entry.evidence);
        if matches!(
            &entry.verification_context,
            CachedAgentSignerEvidenceContext::CurrentRelation { .. }
        ) {
            let new_head = agent_signer_evidence_frontier(&entry.evidence).as_str();
            for existing in self.cached.agent_signer_evidence.values() {
                if !matches!(
                    &existing.verification_context,
                    CachedAgentSignerEvidenceContext::CurrentRelation { .. }
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
                if existing.invalidated
                    && agent_signer_evidence_authority_state(&existing.evidence).state_digest
                        == agent_signer_evidence_authority_state(&entry.evidence).state_digest
                {
                    return Err(
                        "Agent state was already invalidated; a new lease cannot revive it"
                            .to_owned(),
                    );
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
            "state_root": agent_signer_evidence_authority_state(&entry.evidence).state.frontier_state_root,
            "frontier": agent_signer_evidence_frontier(&entry.evidence),
            "verification_context": &entry.verification_context,
        }))
        .map_err(|error| format!("Agent signer evidence cache key: {error}"))?;
        if matches!(
            &entry.verification_context,
            CachedAgentSignerEvidenceContext::CurrentRelation { .. }
        ) {
            for existing in self.cached.agent_signer_evidence.values_mut() {
                let existing_binding = agent_signer_evidence_binding(&existing.evidence);
                if matches!(
                    &existing.verification_context,
                    CachedAgentSignerEvidenceContext::CurrentRelation { .. }
                ) && existing_binding.agent_id == binding.agent_id
                    && existing_binding.verification_method == binding.verification_method
                    && agent_signer_evidence_frontier(&existing.evidence)
                        != agent_signer_evidence_frontier(&entry.evidence)
                {
                    existing.invalidated = true;
                    existing.verified_current_key = None;
                }
            }
        }
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

fn agent_signer_evidence_authority_state(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &arkret_sdk::AgentAuthorityStateEvidence {
    match evidence {
        arkret_sdk::AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        }
        | arkret_sdk::AgentSignerEvidence::HistoricalEvent {
            admission_evidence, ..
        } => &admission_evidence.agent_authority_state_evidence,
    }
}

fn agent_signer_evidence_binding(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &arkret_sdk::AgentSigningKeyBinding {
    &agent_signer_evidence_authority_state(evidence)
        .state
        .signing_key_binding
}

fn agent_signer_evidence_frontier(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &arkret_sdk::SealId {
    &agent_signer_evidence_authority_state(evidence)
        .state
        .frontier_seal_id
}

fn agent_signer_evidence_lineage(
    evidence: &arkret_sdk::AgentSignerEvidence,
) -> &[arkret_sdk::Seal] {
    &agent_signer_evidence_authority_state(evidence)
        .state
        .seal_lineages
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

struct AgentCacheSubjects<'a> {
    actor: &'a arkret_sdk::ActorId,
    pcr: &'a arkret_sdk::RealmId,
    key_id: &'a str,
}

impl AgentCacheSubjects<'_> {
    fn matches_change(&self, event: &arkret_sdk::Event) -> bool {
        match event.kind.as_str() {
            "ak.agent.key.authorize" | "ak.agent.key.revoke" => {
                event.realm_id == *self.pcr
                    && event
                        .payload
                        .get("agent_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(self.actor.signing_principal_id().as_str())
                    && event
                        .payload
                        .get("key_id")
                        .and_then(serde_json::Value::as_str)
                        == Some(self.key_id)
            }
            "ak.self.agent.pause" | "ak.self.agent.resume" | "ak.self.agent.deactivate" => {
                event.realm_id == *self.pcr && event.actor_id == *self.actor
            }
            _ => false,
        }
    }
}

fn agent_context_matches_checkpoint(
    entry: &CachedAgentSignerEvidence,
    checkpoint: &arkret_sdk::MlsGovernanceVerificationCheckpoint,
) -> bool {
    let CachedAgentSignerEvidenceContext::CurrentRelation { agent_actor_id, .. } =
        &entry.verification_context
    else {
        return true;
    };
    let authority = agent_signer_evidence_authority_state(&entry.evidence);
    let subjects = AgentCacheSubjects {
        actor: agent_actor_id,
        pcr: &authority.state.principal_control_realm_id,
        key_id: authority.state.signing_key_binding.agent_key_id.as_str(),
    };
    !checkpoint.accepted_events.iter().any(|event| {
        subjects.matches_change(event)
            && checkpoint.accepted_seals.iter().any(|seal| {
                seal.sealed_at > authority.lease.issued_at
                    && seal
                        .covered_event_digests
                        .contains(&event.event_id.event_digest())
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(label: &str) -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{label}.example")).unwrap()
    }

    fn actor(label: &str, station: &str) -> arkret_sdk::ActorId {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(did(label), did(station)))
    }

    fn realm() -> arkret_sdk::RealmId {
        crate::test_support::realm_id("ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6")
    }

    fn change(
        kind: &str,
        actor: arkret_sdk::ActorId,
        payload: serde_json::Value,
    ) -> arkret_sdk::Event {
        let mut event = arkret_wire::test_support::raw_event(
            kind,
            arkret_sdk::ScopeRef::Realm { realm_id: realm() },
            actor.signing_principal_id().clone(),
            actor.route_service_id().clone(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap();
        event.actor_id = actor;
        event
    }

    #[test]
    fn agent_cache_invalidation_uses_exact_key_and_lifecycle_subjects() {
        let agent = actor("agent", "station");
        let realm = realm();
        let subjects = AgentCacheSubjects {
            actor: &agent,
            pcr: &realm,
            key_id: "runtime-key",
        };
        for kind in ["ak.agent.key.revoke", "ak.agent.key.authorize"] {
            assert!(subjects.matches_change(&change(
                kind,
                actor("owner", "station"),
                serde_json::json!({"agent_id": did("agent"), "key_id": "runtime-key"})
            )));
            assert!(!subjects.matches_change(&change(
                kind,
                actor("owner", "station"),
                serde_json::json!({"agent_id": did("other-agent"), "key_id": "runtime-key"})
            )));
            assert!(!subjects.matches_change(&change(
                kind,
                actor("owner", "station"),
                serde_json::json!({"agent_id": did("agent"), "key_id": "other-key"})
            )));
        }
        for kind in [
            "ak.self.agent.pause",
            "ak.self.agent.resume",
            "ak.self.agent.deactivate",
        ] {
            assert!(subjects.matches_change(&change(kind, agent.clone(), serde_json::json!({}))));
            assert!(!subjects.matches_change(&change(
                kind,
                actor("other-agent", "station"),
                serde_json::json!({})
            )));
            assert!(!subjects.matches_change(&change(
                kind,
                actor("agent", "other-station"),
                serde_json::json!({})
            )));
        }
    }

    #[test]
    fn agent_cache_membership_changes_do_not_refresh_signing_authority() {
        let agent = actor("agent", "station");
        let realm = realm();
        let subjects = AgentCacheSubjects {
            actor: &agent,
            pcr: &realm,
            key_id: "runtime-key",
        };
        for membership in ["join", "leave", "ban"] {
            for member in [
                agent.clone(),
                actor("controller", "station"),
                actor("recipient", "station"),
            ] {
                assert!(!subjects.matches_change(&change(
                    "ak.member.state",
                    actor("moderator", "station"),
                    serde_json::json!({"member_id": member, "membership": membership})
                )));
            }
            for member in [
                actor("stranger", "station"),
                actor("controller", "other-station"),
            ] {
                assert!(!subjects.matches_change(&change(
                    "ak.member.state",
                    actor("moderator", "station"),
                    serde_json::json!({"member_id": member, "membership": membership})
                )));
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn agent_cache_known_revocation_survives_restore_and_preserves_historical_evidence() {
        let entry =
            crate::identity::agent_signer_evidence::cache_tests::signed_fixture_entry().await;
        let authority = agent_signer_evidence_authority_state(&entry.evidence);
        let CachedAgentSignerEvidenceContext::CurrentRelation {
            agent_actor_id,
            realm_id,
            ..
        } = &entry.verification_context
        else {
            panic!("current fixture")
        };
        let mut revoke = change(
            "ak.agent.key.revoke",
            agent_actor_id.clone(),
            serde_json::json!({"agent_id":authority.state.signing_key_binding.agent_id,
                "key_id":authority.state.signing_key_binding.agent_key_id}),
        );
        revoke.realm_id = authority.state.principal_control_realm_id.clone();
        revoke.scope_ref = arkret_sdk::ScopeRef::Realm {
            realm_id: revoke.realm_id.clone(),
        };
        // This fixture enters the cache after governance verification. The
        // later Seal time, not an earlier Station receipt, is the change point.
        let mut covering_seal = authority.state.agent_lifecycle_witness.seal.clone();
        covering_seal.sealed_at = authority.lease.issued_at + chrono::Duration::seconds(1);
        covering_seal.covered_event_digests = vec![revoke.event_id.event_digest()];
        let checkpoint = arkret_sdk::MlsGovernanceVerificationCheckpoint {
            realm_id: revoke.realm_id.clone(),
            basis: arkret_sdk::SealBasis {
                leaves: vec![covering_seal.id.clone()],
            },
            live_digest_suite: arkret_sdk::DigestSuite::Sha256,
            accepted_seals: vec![covering_seal],
            accepted_events: vec![revoke.clone()],
            governance_dependencies: vec![],
        };
        let mut historical = entry.clone();
        historical.verified_historical_key =
            Some(*entry.verified_current_key.as_ref().unwrap().key().key());
        historical.verified_current_key = None;
        historical.verification_context = CachedAgentSignerEvidenceContext::HistoricalEvent {
            realm_id: realm_id.clone(),
            event_id: revoke.event_id.clone(),
            producer_accepted_at: authority.lease.issued_at,
            producer_signer_resolution_evidence_ref: entry
                .signer_evidence_root
                .evidence_ref()
                .unwrap(),
            receiver_id: agent_actor_id.route_service_id().clone(),
        };
        let arkret_sdk::AgentSignerEvidence::CurrentAdmission {
            schema,
            admission_evidence,
            transparency,
        } = &entry.evidence
        else {
            panic!("current fixture")
        };
        historical.evidence = arkret_sdk::AgentSignerEvidence::HistoricalEvent {
            schema: schema.clone(),
            admission_evidence: admission_evidence.clone(),
            event_admission: arkret_sdk::AgentEventAdmission::StationAdmission {
                accepted_event: revoke,
            },
            transparency: transparency.clone(),
        };
        let arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            receiver_signer_evidence_ref,
            attester_signer_evidence_ref,
            ..
        } = &mut historical.signer_evidence_root
        else {
            panic!("Agent root")
        };
        *agent_signer_evidence = Box::new(historical.evidence.clone());
        *receiver_signer_evidence_ref = Some(attester_signer_evidence_ref.clone());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut store = LocalStateStore::with_path(&path);
        store
            .store_verified_agent_signer_evidence(entry.clone())
            .unwrap();
        store
            .store_verified_agent_signer_evidence(historical.clone())
            .unwrap();
        store
            .invalidate_agent_current_contexts(&actor("unrelated-agent", "station"))
            .unwrap();
        assert_eq!(
            store
                .cached_agent_signer_evidence(
                    &authority.state.signing_key_binding.agent_id,
                    &authority.state.signing_key_binding.verification_method
                )
                .len(),
            2
        );
        // An acknowledged lifecycle change invalidates the current token before
        // any subsequent Seal refresh completes, and survives persistence.
        store
            .invalidate_agent_current_contexts(agent_actor_id)
            .unwrap();
        assert!(
            store
                .store_verified_agent_signer_evidence(entry.clone())
                .is_err()
        );
        store.invalidate_agent_contexts_for_governance(&checkpoint);
        store
            .cached
            .mls_governance_checkpoints
            .insert(checkpoint.realm_id.to_string(), checkpoint);
        store.flush().unwrap();
        assert!(
            store
                .store_verified_agent_signer_evidence(entry.clone())
                .is_err()
        );
        let mut restored = LocalStateStore::with_path(&path);
        let hits = restored.cached_agent_signer_evidence(
            &authority.state.signing_key_binding.agent_id,
            &authority.state.signing_key_binding.verification_method,
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(
            hits[0].verification_context,
            historical.verification_context
        );
        assert!(!hits[0].invalidated);
        assert!(
            restored
                .store_verified_agent_signer_evidence(entry)
                .is_err()
        );
    }
}
