use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::signatures::agent_evidence::{
    AgentSignerEvidenceValidationContext, AgentSignerEvidenceVerdict,
    agent_signing_key_binding_digest, validate_agent_signer_evidence,
    verify_agent_evidence_freshness_attestation, verify_agent_signing_key_binding,
};
use arkret_sdk::signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_sdk::{
    AgentAuthorizationAdmission, AgentSignerEvidence, AgentSignerEvidenceQueryRequestBodyBody,
    AgentSignerEvidenceQuerySelector, Did, DidUrl, NotarySig, RealmId,
};
use serde_json::Value;

use crate::identity::device_directory::DidAnchor as _;
use crate::state::{CachedAgentSignerEvidence, LocalStateStore};

const MAX_SCAN_DEPTH: usize = 32;

#[derive(Clone)]
struct EventAgentSelector {
    realm_id: RealmId,
    admission: AgentAuthorizationAdmission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CachedAgentEventVerdict {
    NotAgent,
    Verified,
    Rejected,
    Unresolved,
}

pub(crate) struct OrdinaryAgentMlsBinding<'a> {
    pub view: &'a arkret_sdk::mls::AgentMlsSignerView,
    pub group_id: &'a str,
    pub epoch: u64,
    pub group_state_ref: &'a str,
}

pub(crate) async fn prefetch_from_realm_projections(
    http: &arkret_sdk::http_client::Client,
    projections: &BTreeMap<String, Value>,
    bundled_evidence: &[AgentSignerEvidence],
    state_store: &crate::runtime::input::StateStoreHandle,
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
) -> bool {
    let mut selectors = BTreeSet::new();
    for (realm_id, projection) in projections {
        collect_selectors(projection, realm_id, 0, &mut selectors);
    }
    if selectors.is_empty() {
        return false;
    }

    let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        did_cache.get(),
    );
    let mut changed = false;
    let mut satisfied = BTreeSet::new();
    for evidence in bundled_evidence {
        let candidates = selectors.iter().filter(|selector| {
            selector.admission.agent_id == evidence.signing_key_binding.agent_id
                && selector.admission.verification_method
                    == evidence.signing_key_binding.verification_method
                && selector.admission.authorization_event_id
                    == evidence.signing_key_binding.agent_key_authorize_event_id
        });
        for selector in candidates {
            let Some(entry) = verify_for_cache(http, &anchor, evidence.clone(), selector).await
            else {
                continue;
            };
            if state_store
                .write(|store| store.store_verified_agent_signer_evidence(entry))
                .is_ok()
            {
                changed = true;
                satisfied.insert(selector_cache_key(selector));
            }
            break;
        }
    }
    let mut by_realm = BTreeMap::<String, Vec<EventAgentSelector>>::new();
    for selector in selectors {
        if satisfied.contains(&selector_cache_key(&selector)) {
            continue;
        }
        by_realm
            .entry(selector.realm_id.as_str().to_owned())
            .or_default()
            .push(selector);
    }
    for (realm_id, mut pending_selectors) in by_realm {
        let Ok(realm_id) = RealmId::new(realm_id) else {
            continue;
        };
        for attempt in 0..4 {
            let queries = pending_selectors
                .iter()
                .map(|selector| AgentSignerEvidenceQuerySelector {
                    agent_id: selector.admission.agent_id.clone(),
                    verification_method: selector.admission.verification_method.clone(),
                    agent_key_authorize_event_id: Some(
                        selector.admission.authorization_event_id.clone(),
                    ),
                    event_accepted_frontier: Some(selector.admission.accepted_frontier.clone()),
                })
                .collect();
            let request = AgentSignerEvidenceQueryRequestBodyBody {
                realm_id: realm_id.clone(),
                queries,
            };
            match http.agent_signer_evidence_query(&request).await {
                Ok(outcome) => {
                    for evidence in outcome.evidence {
                        let Some(selector_index) = pending_selectors.iter().position(|selector| {
                            selector.admission.agent_id == evidence.signing_key_binding.agent_id
                                && selector.admission.verification_method
                                    == evidence.signing_key_binding.verification_method
                                && selector.admission.authorization_event_id
                                    == evidence.signing_key_binding.agent_key_authorize_event_id
                        }) else {
                            continue;
                        };
                        let Some(entry) = verify_for_cache(
                            http,
                            &anchor,
                            evidence,
                            &pending_selectors[selector_index],
                        )
                        .await
                        else {
                            continue;
                        };
                        if state_store
                            .write(|store| store.store_verified_agent_signer_evidence(entry))
                            .is_ok()
                        {
                            changed = true;
                            pending_selectors.remove(selector_index);
                        }
                    }
                    if pending_selectors.is_empty() {
                        break;
                    }
                    if attempt == 3 {
                        tracing::warn!(
                            realm_id = %realm_id,
                            unresolved = pending_selectors.len(),
                            failures = ?outcome.failures,
                            "agent signer evidence remained unresolved after bounded verification retries",
                        );
                    }
                }
                Err(error) if attempt == 3 => {
                    tracing::warn!(
                        realm_id = %realm_id,
                        unresolved = pending_selectors.len(),
                        %error,
                        "agent signer evidence query failed after bounded retries",
                    );
                }
                Err(_) => {}
            }
            if attempt < 3 {
                // The accepted Event can reach the account stream a few
                // milliseconds before either the evidence projection or its
                // DID key material is observable. Stop only after evidence is
                // fully verified and cached, not merely after a non-empty
                // query response.
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(500)).await;
            }
        }
    }
    did_cache.set(anchor.into_cache());
    changed
}

fn selector_cache_key(selector: &EventAgentSelector) -> (String, String, String) {
    (
        selector.admission.agent_id.as_str().to_owned(),
        selector.admission.verification_method.as_str().to_owned(),
        selector
            .admission
            .authorization_event_id
            .as_str()
            .to_owned(),
    )
}

pub(crate) fn verify_cached_event(
    envelope: &Value,
    store: &LocalStateStore,
    mls_binding: Option<OrdinaryAgentMlsBinding<'_>>,
) -> CachedAgentEventVerdict {
    let Some(selector) = selector_from_event(envelope, None) else {
        return CachedAgentEventVerdict::NotAgent;
    };
    let entries = store.cached_agent_signer_evidence(
        &selector.admission.agent_id,
        &selector.admission.verification_method,
        Some(&selector.admission.authorization_event_id),
    );
    if entries.is_empty() {
        return CachedAgentEventVerdict::Unresolved;
    }
    let mut saw_rejected = false;
    for entry in entries {
        if !verify_cached_crypto(&entry) {
            saw_rejected = true;
            continue;
        }
        let evidence = &entry.evidence;
        let binding = &evidence.signing_key_binding;
        let Ok(binding_digest) = agent_signing_key_binding_digest(binding) else {
            saw_rejected = true;
            continue;
        };
        let context = AgentSignerEvidenceValidationContext {
            signer_id: &selector.admission.agent_id,
            agent_key_id: &binding.agent_key_id,
            authorization_realm_id: &evidence.state_witness.seal.realm_id,
            controller_id: &binding.controller_id,
            verification_method: &selector.admission.verification_method,
            agent_key_authorize_event_id: &selector.admission.authorization_event_id,
            authorize_public_key_digest: &binding.public_key_digest,
            authorize_signing_key_binding_digest: &binding_digest,
            event_accepted_frontier: &selector.admission.accepted_frontier,
            event_accepted_at: selector.admission.accepted_at,
            now: crate::clock::now_utc(),
            controller_public_key: &entry.controller_public_key,
            seal_lineage_signatures_verified: true,
            freshness_signature_verified: true,
            require_transparency: false,
            transparency_verified: false,
        };
        match validate_agent_signer_evidence(Some(evidence), &context) {
            AgentSignerEvidenceVerdict::Verified(verified) => {
                if let Some(mls_binding) = &mls_binding {
                    let claim = arkret_sdk::mls::AgentMlsSignerClaim {
                        group_id: mls_binding.group_id,
                        epoch: mls_binding.epoch,
                        group_state_ref: mls_binding.group_state_ref,
                        signer_id: &selector.admission.agent_id,
                        signing_key: &verified.key,
                        agent_key_authorize_event_id: &selector.admission.authorization_event_id,
                    };
                    if arkret_sdk::mls::verify_ordinary_agent_mls_binding(mls_binding.view, &claim)
                        .is_err()
                    {
                        saw_rejected = true;
                        continue;
                    }
                }
                let material = PublicKeyMaterial::Ed25519Raw {
                    bytes: verified.key.to_vec(),
                };
                if crate::identity::device_directory::verify_persistent_envelope_proofs(
                    envelope, &material,
                ) {
                    return CachedAgentEventVerdict::Verified;
                }
                saw_rejected = true;
            }
            AgentSignerEvidenceVerdict::Rejected(_) => saw_rejected = true,
            AgentSignerEvidenceVerdict::Unresolved(_) => {}
        }
    }
    if saw_rejected {
        CachedAgentEventVerdict::Rejected
    } else {
        CachedAgentEventVerdict::Unresolved
    }
}

async fn verify_for_cache(
    http: &arkret_sdk::http_client::Client,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
    evidence: AgentSignerEvidence,
    selector: &EventAgentSelector,
) -> Option<CachedAgentSignerEvidence> {
    let entry = materialize_verified_cache_entry(http, anchor, evidence).await?;
    let binding = &entry.evidence.signing_key_binding;
    let binding_digest = agent_signing_key_binding_digest(binding).ok()?;
    let context = AgentSignerEvidenceValidationContext {
        signer_id: &selector.admission.agent_id,
        agent_key_id: &binding.agent_key_id,
        authorization_realm_id: &entry.evidence.state_witness.seal.realm_id,
        controller_id: &binding.controller_id,
        verification_method: &selector.admission.verification_method,
        agent_key_authorize_event_id: &selector.admission.authorization_event_id,
        authorize_public_key_digest: &binding.public_key_digest,
        authorize_signing_key_binding_digest: &binding_digest,
        event_accepted_frontier: &selector.admission.accepted_frontier,
        event_accepted_at: selector.admission.accepted_at,
        now: crate::clock::now_utc(),
        controller_public_key: &entry.controller_public_key,
        seal_lineage_signatures_verified: true,
        freshness_signature_verified: true,
        require_transparency: false,
        transparency_verified: false,
    };
    matches!(
        validate_agent_signer_evidence(Some(&entry.evidence), &context),
        AgentSignerEvidenceVerdict::Verified(_)
    )
    .then_some(entry)
}

async fn materialize_verified_cache_entry(
    http: &arkret_sdk::http_client::Client,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
    evidence: AgentSignerEvidence,
) -> Option<CachedAgentSignerEvidence> {
    let controller_public_key = resolve_method_key(
        http,
        anchor,
        &evidence
            .signing_key_binding
            .controller_proof
            .verification_method,
    )
    .await?;
    let source_public_key = resolve_source_service_method_key(
        http,
        anchor,
        &evidence.freshness_attestation.source_service_id,
        &evidence
            .freshness_attestation
            .source_proof
            .verification_method,
    )
    .await?;
    let mut seal_signer_public_keys = BTreeMap::new();
    for seal in &evidence.seal_lineage {
        for method in seal_signature_methods(seal)? {
            if seal_signer_public_keys.contains_key(method.as_str()) {
                continue;
            }
            let key = resolve_method_key(http, anchor, &method).await?;
            seal_signer_public_keys.insert(method.as_str().to_owned(), key);
        }
    }
    let entry = CachedAgentSignerEvidence {
        evidence,
        controller_public_key,
        source_public_key,
        seal_signer_public_keys,
        cached_at_unix_ms: crate::clock::now_unix_ms(),
    };
    if !verify_cached_crypto(&entry) {
        return None;
    }
    Some(entry)
}

/// Query and cache the current Native Agent signing evidence needed to admit
/// a live Signal. Unlike a durable Event, a Signal has no reducer-stamped
/// `agent_authorization_admission`, so the query deliberately omits Event
/// frontier selectors and validates the returned evidence against its own
/// current accepted authorization witness.
pub(crate) async fn prefetch_for_signal(
    http: &arkret_sdk::http_client::Client,
    realm_id: &RealmId,
    agent_id: &Did,
    verification_method: &DidUrl,
    state_store: &crate::runtime::input::StateStoreHandle,
    did_cache: crate::runtime::input::ValueCell<arkret_sdk::identity::DidResolutionCache>,
) -> bool {
    if state_store
        .read(|store| resolve_cached_signal_key(store, agent_id, verification_method).is_some())
    {
        return true;
    }
    let request = signal_evidence_query(realm_id, agent_id, verification_method);
    let outcome = match http.agent_signer_evidence_query(&request).await {
        Ok(outcome) => outcome,
        Err(error) => {
            tracing::warn!(
                target_realm_id = %realm_id,
                %agent_id,
                %verification_method,
                %error,
                "live Signal Agent signer evidence query failed",
            );
            return false;
        }
    };
    if outcome.evidence.is_empty() {
        tracing::warn!(
            target_realm_id = %realm_id,
            %agent_id,
            %verification_method,
            failures = ?outcome.failures,
            "live Signal Agent signer evidence query returned no evidence",
        );
    }
    let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        did_cache.get(),
    );
    for evidence in outcome.evidence {
        let binding = &evidence.signing_key_binding;
        if &binding.agent_id != agent_id || &binding.verification_method != verification_method {
            continue;
        }
        let Some(entry) = materialize_verified_cache_entry(http, &anchor, evidence).await else {
            tracing::warn!(
                target_realm_id = %realm_id,
                %agent_id,
                %verification_method,
                "live Signal Agent signer evidence failed cryptographic materialization",
            );
            continue;
        };
        let evidence = &entry.evidence;
        let binding = &evidence.signing_key_binding;
        // `realm_id` is the Signal's target/shared-context Realm. The
        // authorization witness is intentionally anchored in the Agent's
        // principal-control Realm instead (signal.md's two independent state
        // domains). The authenticated evidence-query endpoint already gates
        // disclosure on the requested target Realm; comparing the witness
        // Realm with that target here would reject every correctly authorised
        // Agent whose PCR is distinct from the conversation Realm.
        let authorization_realm_id =
            live_signal_authorization_realm(realm_id, &evidence.state_witness.seal.realm_id);
        let Ok(binding_digest) = agent_signing_key_binding_digest(binding) else {
            continue;
        };
        let context = AgentSignerEvidenceValidationContext {
            signer_id: agent_id,
            agent_key_id: &binding.agent_key_id,
            authorization_realm_id,
            controller_id: &binding.controller_id,
            verification_method,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            authorize_public_key_digest: &binding.public_key_digest,
            authorize_signing_key_binding_digest: &binding_digest,
            event_accepted_frontier: &evidence.authorization.accepted_frontier,
            event_accepted_at: evidence.authorization.accepted_at,
            now: crate::clock::now_utc(),
            controller_public_key: &entry.controller_public_key,
            seal_lineage_signatures_verified: true,
            freshness_signature_verified: true,
            require_transparency: false,
            transparency_verified: false,
        };
        let verdict = validate_agent_signer_evidence(Some(evidence), &context);
        if !matches!(verdict, AgentSignerEvidenceVerdict::Verified(_)) {
            tracing::warn!(
                target_realm_id = %realm_id,
                authorization_realm_id = %authorization_realm_id,
                %agent_id,
                %verification_method,
                ?verdict,
                "live Signal Agent signer evidence failed validation",
            );
            continue;
        }
        match state_store.write(|store| store.store_verified_agent_signer_evidence(entry)) {
            Ok(()) => {
                did_cache.set(anchor.into_cache());
                return true;
            }
            Err(error) => {
                tracing::debug!(
                    target_realm_id = %realm_id,
                    %agent_id,
                    %verification_method,
                    %error,
                    "live Signal Agent signer evidence cache write failed",
                );
            }
        }
    }
    did_cache.set(anchor.into_cache());
    false
}

/// Select the Realm that anchors the portable signer evidence used for a live
/// Signal. The target Realm proves shared Signal context at the query endpoint;
/// the returned state witness proves Agent-key authorization in the Agent's
/// principal-control Realm. They are orthogonal and commonly differ.
fn live_signal_authorization_realm<'a>(
    _target_realm_id: &RealmId,
    witness_realm_id: &'a RealmId,
) -> &'a RealmId {
    witness_realm_id
}

fn signal_evidence_query(
    realm_id: &RealmId,
    agent_id: &Did,
    verification_method: &DidUrl,
) -> AgentSignerEvidenceQueryRequestBodyBody {
    AgentSignerEvidenceQueryRequestBodyBody {
        realm_id: realm_id.clone(),
        queries: vec![AgentSignerEvidenceQuerySelector {
            agent_id: agent_id.clone(),
            verification_method: verification_method.clone(),
            agent_key_authorize_event_id: None,
            event_accepted_frontier: None,
        }],
    }
}

#[cfg(test)]
mod signal_query_tests {
    use super::*;

    #[test]
    fn live_signal_query_does_not_invent_event_admission_fields() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let agent_id = Did::new("did:webvh:z6mkfixture:agent.example").unwrap();
        let method = DidUrl::new("did:webvh:z6mkfixture:agent.example#agent-runtime").unwrap();
        let request = signal_evidence_query(&realm_id, &agent_id, &method);

        assert_eq!(request.queries.len(), 1);
        assert!(request.queries[0].agent_key_authorize_event_id.is_none());
        assert!(request.queries[0].event_accepted_frontier.is_none());
    }

    #[test]
    fn live_signal_validates_signer_evidence_in_the_agent_pcr() {
        let target = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let agent_pcr = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000002").unwrap();

        assert_ne!(target, agent_pcr);
        assert_eq!(
            live_signal_authorization_realm(&target, &agent_pcr),
            &agent_pcr
        );
    }
}

/// Resolve a live Signal signer through the same verified Native Agent
/// evidence used for durable Events. Signals have no server-stamped Event
/// admission object, so the evidence's current accepted authorization basis is
/// used directly; stale, revoked, superseded, conflicted, or cryptographically
/// invalid evidence fails closed.
pub(crate) fn resolve_cached_signal_key(
    store: &LocalStateStore,
    agent_id: &Did,
    verification_method: &DidUrl,
) -> Option<PublicKeyMaterial> {
    for entry in store.cached_agent_signer_evidence(agent_id, verification_method, None) {
        if !verify_cached_crypto(&entry) {
            continue;
        }
        let evidence = &entry.evidence;
        let binding = &evidence.signing_key_binding;
        let Ok(binding_digest) = agent_signing_key_binding_digest(binding) else {
            continue;
        };
        let context = AgentSignerEvidenceValidationContext {
            signer_id: agent_id,
            agent_key_id: &binding.agent_key_id,
            authorization_realm_id: &evidence.state_witness.seal.realm_id,
            controller_id: &binding.controller_id,
            verification_method,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            authorize_public_key_digest: &binding.public_key_digest,
            authorize_signing_key_binding_digest: &binding_digest,
            event_accepted_frontier: &evidence.authorization.accepted_frontier,
            event_accepted_at: evidence.authorization.accepted_at,
            now: crate::clock::now_utc(),
            controller_public_key: &entry.controller_public_key,
            seal_lineage_signatures_verified: true,
            freshness_signature_verified: true,
            require_transparency: false,
            transparency_verified: false,
        };
        if let AgentSignerEvidenceVerdict::Verified(verified) =
            validate_agent_signer_evidence(Some(evidence), &context)
        {
            return Some(PublicKeyMaterial::Ed25519Raw {
                bytes: verified.key.to_vec(),
            });
        }
    }
    None
}

fn verify_cached_crypto(entry: &CachedAgentSignerEvidence) -> bool {
    let binding = &entry.evidence.signing_key_binding;
    let Ok(binding_digest) = agent_signing_key_binding_digest(binding) else {
        return false;
    };
    if verify_agent_signing_key_binding(
        binding,
        &binding.agent_id,
        &binding.agent_key_id,
        &binding.controller_id,
        &binding.verification_method,
        &binding.agent_key_authorize_event_id,
        &binding.public_key_digest,
        &binding_digest,
        &entry.controller_public_key,
    )
    .is_err()
        || verify_agent_evidence_freshness_attestation(
            &entry.evidence.freshness_attestation,
            &entry.source_public_key,
        )
        .is_err()
    {
        return false;
    }
    verify_seal_lineage_signatures(entry)
}

fn verify_seal_lineage_signatures(entry: &CachedAgentSignerEvidence) -> bool {
    let allowed = [
        entry
            .evidence
            .freshness_attestation
            .source_service_id
            .as_str(),
        entry.evidence.signing_key_binding.controller_id.as_str(),
    ];
    entry.evidence.seal_lineage.iter().all(|seal| {
        let Ok(canonical) = seal.canonical_bytes_for_id() else {
            return false;
        };
        let Ok(expected_digest) =
            arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&canonical))
        else {
            return false;
        };
        let signatures = match &seal.notary_signature {
            NotarySig::Single(signature) => vec![signature],
            NotarySig::Multi(multi) if !multi.signatures.is_empty() => {
                multi.signatures.iter().collect()
            }
            NotarySig::Multi(_) | NotarySig::Threshold(_) => return false,
        };
        signatures.into_iter().all(|signature| {
            let controller = signature
                .verification_method
                .split_once('#')
                .map_or(signature.verification_method.as_str(), |(did, _)| did);
            signature.alg == "EdDSA"
                && signature.payload_digest == expected_digest
                && allowed.contains(&controller)
                && entry
                    .seal_signer_public_keys
                    .get(signature.verification_method.as_str())
                    .is_some_and(|key| {
                        Ed25519DetachedJwsVerifier::new()
                            .verify_detached_jws(&signature.jws, &canonical, key)
                            .is_ok()
                    })
        })
    })
}

/// The Seal's notary verification methods, typed. `PayloadSignature`'s
/// `verification_method` is a `DidUrl` since the P0-A migration, so no
/// re-parsing is needed here.
fn seal_signature_methods(seal: &arkret_sdk::Seal) -> Option<Vec<DidUrl>> {
    match &seal.notary_signature {
        NotarySig::Single(signature) => Some(vec![signature.verification_method.clone()]),
        NotarySig::Multi(multi) if !multi.signatures.is_empty() => Some(
            multi
                .signatures
                .iter()
                .map(|signature| signature.verification_method.clone())
                .collect(),
        ),
        NotarySig::Multi(_) | NotarySig::Threshold(_) => None,
    }
}

async fn resolve_method_key(
    http: &arkret_sdk::http_client::Client,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
    method: &DidUrl,
) -> Option<PublicKeyMaterial> {
    let (controller, fragment) = method.as_str().split_once('#')?;
    let fragment = fragment.split_once('?').map_or(fragment, |(head, _)| head);
    let controller_did = Did::new(controller.to_owned()).ok()?;
    if arkret_sdk::DeviceId::new(fragment.to_owned()).is_ok() {
        return crate::identity::device_directory::resolve_device_signing_key_with_http(
            http, anchor, controller, fragment,
        )
        .await
        .ok()
        .flatten();
    }
    let fetch_client = reqwest::Client::new();
    if !anchor
        .ensure_actor_document(&fetch_client, &controller_did)
        .await
    {
        return None;
    }
    let document = anchor.resolve_did_document(&controller_did)?;
    let value = document
        .verification_methods
        .get(method.as_str())
        .or_else(|| document.verification_methods.get(fragment))
        .or_else(|| document.verification_methods.get(&format!("#{fragment}")))?;
    public_key_material_from_document(value)
}

async fn resolve_source_service_method_key(
    http: &arkret_sdk::http_client::Client,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
    source_service_id: &Did,
    method: &DidUrl,
) -> Option<PublicKeyMaterial> {
    if method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        != Some(source_service_id.as_str())
    {
        return None;
    }
    if let Some(key) = resolve_method_key(http, anchor, method).await {
        return Some(key);
    }
    let description = http.describe().await.ok()?;
    if description.service_id != *source_service_id {
        return None;
    }
    let fetch_client = reqwest::Client::new();
    if !anchor
        .ensure_trusted_same_origin_service_document(
            &fetch_client,
            http.base_url(),
            source_service_id,
        )
        .await
    {
        return None;
    }
    let document = anchor.resolve_did_document(source_service_id)?;
    let fragment = method.as_str().split_once('#')?.1;
    let fragment = fragment.split_once('?').map_or(fragment, |(head, _)| head);
    let value = document
        .verification_methods
        .get(method.as_str())
        .or_else(|| document.verification_methods.get(fragment))
        .or_else(|| document.verification_methods.get(&format!("#{fragment}")))?;
    public_key_material_from_document(value)
}

fn public_key_material_from_document(value: &str) -> Option<PublicKeyMaterial> {
    crate::identity::device_directory::public_key_from_directory_value(value).or_else(|| {
        serde_json::from_str::<Value>(value)
            .ok()
            .map(|value| PublicKeyMaterial::Jwk { value })
            .filter(|key| key.ed25519_bytes().is_ok())
    })
}

fn collect_selectors(
    value: &Value,
    realm_id: &str,
    depth: usize,
    out: &mut BTreeSet<EventAgentSelector>,
) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some(selector) = selector_from_object(object, Some(realm_id)) {
                out.insert(selector);
            }
            for child in object.values() {
                collect_selectors(child, realm_id, depth + 1, out);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_selectors(child, realm_id, depth + 1, out);
            }
        }
        _ => {}
    }
}

fn selector_from_event(
    event: &Value,
    fallback_realm_id: Option<&str>,
) -> Option<EventAgentSelector> {
    selector_from_object(event.as_object()?, fallback_realm_id)
}

fn selector_from_object(
    object: &serde_json::Map<String, Value>,
    fallback_realm_id: Option<&str>,
) -> Option<EventAgentSelector> {
    if object.get("applet_id").is_some() {
        return None;
    }
    let realm_id = object
        .get("realm_id")
        .and_then(Value::as_str)
        .or(fallback_realm_id)
        .and_then(|value| RealmId::new(value.to_owned()).ok())?;
    let admission: AgentAuthorizationAdmission = serde_json::from_value(
        object
            .get("unsigned")?
            .get("agent_authorization_admission")?
            .clone(),
    )
    .ok()?;
    let actor = object.get("actor_id").and_then(Value::as_str)?;
    let signer = object
        .get("executed_by")
        .and_then(Value::as_str)
        .unwrap_or(actor);
    if admission.agent_id.as_str() != signer {
        return None;
    }
    let proofs = object.get("proofs").and_then(Value::as_array)?;
    if proofs.is_empty()
        || !proofs.iter().any(|proof| {
            proof.get("verification_method").and_then(Value::as_str)
                == Some(admission.verification_method.as_str())
        })
    {
        return None;
    }
    Some(EventAgentSelector {
        realm_id,
        admission,
    })
}

impl Ord for EventAgentSelector {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.realm_id.as_str(),
            self.admission.agent_id.as_str(),
            self.admission.verification_method.as_str(),
            self.admission.authorization_event_id.as_str(),
            self.admission.accepted_frontier.as_str(),
        )
            .cmp(&(
                other.realm_id.as_str(),
                other.admission.agent_id.as_str(),
                other.admission.verification_method.as_str(),
                other.admission.authorization_event_id.as_str(),
                other.admission.accepted_frontier.as_str(),
            ))
    }
}

impl PartialOrd for EventAgentSelector {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for EventAgentSelector {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for EventAgentSelector {}
