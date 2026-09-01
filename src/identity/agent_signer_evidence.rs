use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::signatures::agent_evidence::{
    AgentEvidenceCommonContext, AgentEvidenceRejectedReason, AgentEvidenceStateVerificationContext,
    AgentSignerEvidenceVerdict, CurrentAgentSignerEvidenceValidationContext,
    HistoricalAgentSignerEvidenceValidationContext, agent_authorization_dot_matches_event,
    validate_current_agent_signer_evidence, validate_historical_agent_signer_evidence,
    verify_agent_evidence_state,
};
use arkret_sdk::signatures::{Ed25519DetachedJwsVerifier, PublicKeyMaterial};
use arkret_sdk::{
    AgentSignerEvidence, AgentSignerEvidenceQueryRequestBody, AgentSignerEvidenceQuerySelector,
    Did, DidCoreId, DidUrl, Hash, NonEmptyString, NotarySig, ProtocolOperationId, RealmId,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::identity::device_directory::DidAnchor as _;
use crate::state::{CachedAgentSignerEvidence, CachedAgentSignerEvidenceContext, LocalStateStore};

const MAX_SCAN_DEPTH: usize = 32;

#[derive(Clone)]
struct EventAgentSelector {
    realm_id: RealmId,
    agent_actor_id: arkret_sdk::ActorId,
    agent_id: DidCoreId,
    verification_method: DidUrl,
    event_id: arkret_sdk::EventId,
    producer_accepted_at: chrono::DateTime<chrono::Utc>,
    producer_signer_resolution_evidence_ref: arkret_sdk::SignerEvidenceRef,
    producer_signer_resolution_evidence_digest: Hash,
    receiver_id: DidCoreId,
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
    let Ok(receiver_id) = http.describe().await.map(|view| view.service_id) else {
        tracing::warn!(
            "Agent signer evidence prefetch could not resolve the receiving service identity"
        );
        return false;
    };
    let mut selectors = BTreeSet::new();
    for projection in projections.values() {
        collect_selectors(projection, &receiver_id, 0, &mut selectors);
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
        let Some(receipt) = historical_receipt(evidence) else {
            continue;
        };
        let candidates = selectors
            .iter()
            .filter(|selector| historical_receipt_matches_selector(receipt, selector));
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
                .map(
                    |selector| AgentSignerEvidenceQuerySelector::HistoricalEvent {
                        agent_id: selector.agent_id.clone(),
                        verification_method: selector.verification_method.clone(),
                        event_id: selector.event_id.clone(),
                        receiver_id: selector.receiver_id.clone(),
                    },
                )
                .collect();
            let request = AgentSignerEvidenceQueryRequestBody {
                realm_id: realm_id.clone(),
                queries,
            };
            match http.agent_signer_evidence_query(&request).await {
                Ok(outcome) => {
                    for root in outcome.evidence_items {
                        let arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
                            agent_signer_evidence: evidence,
                            ..
                        } = root
                        else {
                            continue;
                        };
                        let Some(receipt) = historical_receipt(&evidence) else {
                            continue;
                        };
                        let Some(selector_index) = pending_selectors.iter().position(|selector| {
                            historical_receipt_matches_selector(receipt, selector)
                        }) else {
                            continue;
                        };
                        let Some(entry) = verify_for_cache(
                            http,
                            &anchor,
                            *evidence,
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
        selector.agent_id.as_str().to_owned(),
        selector.verification_method.as_str().to_owned(),
        selector.event_id.as_str().to_owned(),
    )
}

fn signal_request_digest(envelope: &arkret_wire::SignalEnvelope) -> Option<Hash> {
    Hash::new(crate::canonical::canonical_sha256(envelope).ok()?).ok()
}

/// Resolve and verify a current Agent authority object for this exact Signal.
///
/// Current observations are deliberately request-bound and acquired through
/// the standard self-to-peer proxy. The origin-signed response is verified
/// before its inner Agent root can enter the exact-context cache.
pub(crate) async fn resolve_current_signal_sender_evidence(
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
) -> Option<CachedAgentSignerEvidence> {
    if envelope.sender_device_id.is_some() {
        return None;
    }
    let (request, outcome) = crate::identity::current_signer_evidence::query_for_signal(
        http,
        envelope,
        recipient_account_id,
        anchor,
    )
    .await?;
    let operation_id = request.agent_observation_operation_id().ok()?;
    let context = CachedAgentSignerEvidenceContext::CurrentSignal {
        operation_id,
        request_digest: request.request_digest.clone(),
        verifier_id: request.recipient_account_id.station_id.clone(),
        audience: request.recipient_account_id.principal_id.clone(),
        challenge: request.challenge.clone(),
    };
    let agent_id = envelope.sender_actor_id.signing_principal_id().clone();
    let verification_method = envelope.proof.verification_method.clone();
    let mut verified = Vec::new();
    for item in outcome.response.evidences {
        let arkret_models_collaboration::CurrentSignerEvidenceItem::Agent {
            authenticated_signer_evidence:
                arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
                    signer_id,
                    verification_method: resolved_method,
                    agent_signer_evidence,
                    ..
                },
            ..
        } = item
        else {
            continue;
        };
        if signer_id != agent_id || resolved_method != verification_method {
            continue;
        }
        let evidence = *agent_signer_evidence;
        if !current_evidence_matches_context(&evidence, &context) {
            continue;
        }
        let Some(entry) =
            materialize_verified_cache_entry(http, anchor, evidence, context.clone()).await
        else {
            continue;
        };
        let Some(key) =
            validate_current_entry(&entry, &envelope.sender_actor_id, &verification_method)
        else {
            continue;
        };
        verified.push((key, entry));
    }
    let (first_key, first_entry) = verified.pop()?;
    if verified.iter().any(|(key, _)| key != &first_key) {
        return None;
    }
    Some(first_entry)
}

/// Read the exact-context Agent key prepared for this Signal admission.
pub(crate) fn cached_current_signal_sender_evidence(
    store: &LocalStateStore,
    envelope: &arkret_wire::SignalEnvelope,
) -> Option<(PublicKeyMaterial, arkret_sdk::EventId)> {
    if envelope.sender_device_id.is_some() {
        return None;
    }
    let request_digest = signal_request_digest(envelope)?;
    let agent_actor_id = &envelope.sender_actor_id;
    let agent_id = agent_actor_id.signing_principal_id();
    let verification_method = &envelope.proof.verification_method;
    let mut verified = Vec::new();
    for entry in store.cached_agent_signer_evidence(agent_id, verification_method) {
        let CachedAgentSignerEvidenceContext::CurrentSignal {
            request_digest: cached_digest,
            ..
        } = &entry.verification_context
        else {
            continue;
        };
        if cached_digest != &request_digest {
            continue;
        }
        let Some(key) = validate_current_entry(&entry, agent_actor_id, verification_method) else {
            continue;
        };
        verified.push((
            key,
            signing_key_binding(&entry.evidence)
                .agent_key_authorize_event_id
                .clone(),
        ));
    }
    let (first_key, first_event) = verified.pop()?;
    if verified.iter().any(|(key, _)| key != &first_key) {
        return None;
    }
    Some((
        PublicKeyMaterial::Ed25519Raw {
            bytes: first_key.to_vec(),
        },
        first_event,
    ))
}

pub(crate) fn verify_cached_event(
    envelope: &Value,
    store: &LocalStateStore,
    mls_binding: Option<OrdinaryAgentMlsBinding<'_>>,
) -> CachedAgentEventVerdict {
    let Some((event, agent_id, verification_method)) = event_agent_identity(envelope) else {
        return CachedAgentEventVerdict::NotAgent;
    };
    let entries = store.cached_agent_signer_evidence(&agent_id, &verification_method);
    if entries.is_empty() {
        return CachedAgentEventVerdict::Unresolved;
    }
    let mut saw_rejected = false;
    for entry in entries {
        let Some(receipt) = historical_receipt(&entry.evidence) else {
            saw_rejected = true;
            continue;
        };
        let Some(admission) = origin_admission(&event) else {
            saw_rejected = true;
            continue;
        };
        let Ok(signed_digest) = arkret_sdk::signed_event_digest_claim(&event) else {
            saw_rejected = true;
            continue;
        };
        if signed_digest != event.event_id.identity_key().event_digest() {
            saw_rejected = true;
            continue;
        }
        let selector = EventAgentSelector {
            realm_id: event.realm_id.clone(),
            agent_actor_id: event.actor_id.clone(),
            agent_id: agent_id.clone(),
            verification_method: verification_method.clone(),
            event_id: event.event_id.clone(),
            producer_accepted_at: admission.accepted_at,
            producer_signer_resolution_evidence_ref: match admission
                .producer_signer_resolution_evidence_ref
                .clone()
            {
                Some(value) => value,
                None => {
                    saw_rejected = true;
                    continue;
                }
            },
            producer_signer_resolution_evidence_digest: match admission
                .producer_signer_resolution_evidence_digest
                .clone()
            {
                Some(value) => value,
                None => {
                    saw_rejected = true;
                    continue;
                }
            },
            receiver_id: receipt.receiver_id.clone(),
        };
        if !historical_receipt_matches_selector(receipt, &selector) {
            saw_rejected = true;
            continue;
        }
        let CachedAgentSignerEvidenceContext::HistoricalEvent {
            realm_id,
            event_id,
            producer_accepted_at,
            producer_signer_resolution_evidence_ref,
            producer_signer_resolution_evidence_digest,
            receiver_id,
        } = &entry.verification_context
        else {
            saw_rejected = true;
            continue;
        };
        if realm_id != &selector.realm_id
            || event_id != &selector.event_id
            || producer_accepted_at != &selector.producer_accepted_at
            || producer_signer_resolution_evidence_ref
                != &selector.producer_signer_resolution_evidence_ref
            || producer_signer_resolution_evidence_digest
                != &selector.producer_signer_resolution_evidence_digest
            || receiver_id != &selector.receiver_id
        {
            saw_rejected = true;
            continue;
        }
        let Some(key) = validate_cached_historical(&entry, &selector) else {
            saw_rejected = true;
            continue;
        };
        let binding = signing_key_binding(&entry.evidence);
        if let Some(mls_binding) = &mls_binding {
            if did_from_method_for_actor(&selector.verification_method, &selector.agent_id)
                .is_none()
            {
                saw_rejected = true;
                continue;
            }
            let claim = arkret_sdk::mls::AgentMlsSignerClaim {
                group_id: mls_binding.group_id,
                epoch: mls_binding.epoch,
                group_state_ref: mls_binding.group_state_ref,
                signer_id: &selector.agent_id,
                signing_key: &key,
                agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
            };
            if arkret_sdk::mls::verify_ordinary_agent_mls_binding(mls_binding.view, &claim).is_err()
            {
                saw_rejected = true;
                continue;
            }
        }
        let material = PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        };
        if crate::identity::device_directory::verify_persistent_envelope_proofs(envelope, &material)
        {
            return CachedAgentEventVerdict::Verified;
        }
        saw_rejected = true;
    }
    if saw_rejected {
        CachedAgentEventVerdict::Rejected
    } else {
        CachedAgentEventVerdict::Unresolved
    }
}

/// Resolve the historical raw-key endpoint of an already accepted Agent Event.
///
/// This is used only to bind a transient message-stream preview to its durable
/// final. It repeats the historical evidence and producer-proof checks instead
/// of deriving an Agent key from the proof method name.
pub(crate) fn verified_cached_agent_event_endpoint(
    event: &arkret_sdk::Event,
    store: &LocalStateStore,
) -> Option<arkret_sdk::SignalSequenceEndpoint> {
    let envelope = serde_json::to_value(event).ok()?;
    let (event, agent_id, verification_method) = event_agent_identity(&envelope)?;
    let admission = origin_admission(&event)?;
    let signed_digest = arkret_sdk::signed_event_digest_claim(&event).ok()?;
    if signed_digest != event.event_id.identity_key().event_digest() {
        return None;
    }
    let mut digests = BTreeSet::new();
    for entry in store.cached_agent_signer_evidence(&agent_id, &verification_method) {
        let Some(receipt) = historical_receipt(&entry.evidence) else {
            continue;
        };
        let selector = EventAgentSelector {
            realm_id: event.realm_id.clone(),
            agent_actor_id: event.actor_id.clone(),
            agent_id: agent_id.clone(),
            verification_method: verification_method.clone(),
            event_id: event.event_id.clone(),
            producer_accepted_at: admission.accepted_at,
            producer_signer_resolution_evidence_ref: admission
                .producer_signer_resolution_evidence_ref
                .clone()?,
            producer_signer_resolution_evidence_digest: admission
                .producer_signer_resolution_evidence_digest
                .clone()?,
            receiver_id: receipt.receiver_id.clone(),
        };
        if !historical_receipt_matches_selector(receipt, &selector) {
            continue;
        }
        let CachedAgentSignerEvidenceContext::HistoricalEvent {
            realm_id,
            event_id,
            producer_accepted_at,
            producer_signer_resolution_evidence_ref,
            producer_signer_resolution_evidence_digest,
            receiver_id,
        } = &entry.verification_context
        else {
            continue;
        };
        if realm_id != &selector.realm_id
            || event_id != &selector.event_id
            || producer_accepted_at != &selector.producer_accepted_at
            || producer_signer_resolution_evidence_ref
                != &selector.producer_signer_resolution_evidence_ref
            || producer_signer_resolution_evidence_digest
                != &selector.producer_signer_resolution_evidence_digest
            || receiver_id != &selector.receiver_id
        {
            continue;
        }
        let Some(key) = validate_cached_historical(&entry, &selector) else {
            continue;
        };
        let material = PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        };
        if !crate::identity::device_directory::verify_persistent_envelope_proofs(
            &envelope, &material,
        ) {
            continue;
        }
        digests.insert(material.raw_ed25519_digest().ok()?);
    }
    let mut digests = digests.into_iter();
    let public_key_digest = digests.next()?;
    if digests.next().is_some() {
        return None;
    }
    Some(arkret_sdk::SignalSequenceEndpoint::AgentKey { public_key_digest })
}

async fn verify_for_cache(
    http: &arkret_sdk::http_client::Client,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
    evidence: AgentSignerEvidence,
    selector: &EventAgentSelector,
) -> Option<CachedAgentSignerEvidence> {
    let verification_context = CachedAgentSignerEvidenceContext::HistoricalEvent {
        realm_id: selector.realm_id.clone(),
        event_id: selector.event_id.clone(),
        producer_accepted_at: selector.producer_accepted_at,
        producer_signer_resolution_evidence_ref: selector
            .producer_signer_resolution_evidence_ref
            .clone(),
        producer_signer_resolution_evidence_digest: selector
            .producer_signer_resolution_evidence_digest
            .clone(),
        receiver_id: selector.receiver_id.clone(),
    };
    let entry =
        materialize_verified_cache_entry(http, anchor, evidence, verification_context).await?;
    validate_cached_historical(&entry, selector)
        .is_some()
        .then_some(entry)
}

async fn materialize_verified_cache_entry(
    http: &arkret_sdk::http_client::Client,
    anchor: &crate::identity::did_resolver::ResolverDidAnchor,
    evidence: AgentSignerEvidence,
    verification_context: CachedAgentSignerEvidenceContext,
) -> Option<CachedAgentSignerEvidence> {
    let admission = admission_evidence(&evidence);
    let snapshot = &admission.agent_authority_snapshot;
    let binding = &snapshot.core.signing_key_binding;
    let gate = &admission.controller_account_gate_attestation;
    let (outer_source_id, outer_verification_method) = match &evidence {
        AgentSignerEvidence::CurrentAdmission {
            outer_attestation, ..
        } => (
            &outer_attestation.source_id,
            &outer_attestation.verification_method,
        ),
        AgentSignerEvidence::HistoricalEvent {
            outer_attestation, ..
        } => (
            &outer_attestation.source_id,
            &outer_attestation.verification_method,
        ),
    };
    let mut verification_method_public_keys = BTreeMap::new();
    let controller_method = &binding.controller_proof.verification_method;
    verification_method_public_keys.insert(
        controller_method.as_str().to_owned(),
        resolve_method_key(http, anchor, controller_method).await?,
    );
    for (service_id, method) in [
        (
            &snapshot.lease.authority_id,
            &snapshot.lease.verification_method,
        ),
        (&gate.authority_id, &gate.verification_method),
        (outer_source_id, outer_verification_method),
    ] {
        if verification_method_public_keys.contains_key(method.as_str()) {
            continue;
        }
        let key = resolve_source_service_method_key(http, anchor, service_id, method).await?;
        verification_method_public_keys.insert(method.as_str().to_owned(), key);
    }
    if let Some(receipt) = historical_receipt(&evidence) {
        let method =
            arkret_sdk::signatures::agent_evidence::historical_receipt_verification_method(receipt)
                .ok()?;
        if !verification_method_public_keys.contains_key(method.as_str()) {
            let key =
                resolve_source_service_method_key(http, anchor, &receipt.receiver_id, &method)
                    .await?;
            verification_method_public_keys.insert(method.as_str().to_owned(), key);
        }
    }
    for seal in seal_lineage(&evidence) {
        for method in seal_signature_methods(seal)? {
            if verification_method_public_keys.contains_key(method.as_str()) {
                continue;
            }
            let key = resolve_method_key(http, anchor, &method).await?;
            verification_method_public_keys.insert(method.as_str().to_owned(), key);
        }
    }
    for proof in &snapshot
        .core
        .agent_lifecycle_witness
        .accepted_status_event
        .proofs
    {
        let method = match proof {
            arkret_sdk::EventProof::Producer(proof) => &proof.verification_method,
            arkret_sdk::EventProof::StationAdmission(proof) => &proof.verification_method,
        };
        if verification_method_public_keys.contains_key(method.as_str()) {
            continue;
        }
        let key = resolve_method_key(http, anchor, method).await?;
        verification_method_public_keys.insert(method.as_str().to_owned(), key);
    }
    let entry = CachedAgentSignerEvidence {
        evidence,
        verification_context,
        verification_method_public_keys,
        cached_at_unix_ms: crate::clock::now_unix_ms(),
    };
    Some(entry)
}

fn current_evidence_matches_context(
    evidence: &AgentSignerEvidence,
    context: &CachedAgentSignerEvidenceContext,
) -> bool {
    let (
        AgentSignerEvidence::CurrentAdmission {
            current_observation,
            ..
        },
        CachedAgentSignerEvidenceContext::CurrentSignal {
            operation_id,
            request_digest,
            verifier_id,
            audience,
            challenge,
        },
    ) = (evidence, context)
    else {
        return false;
    };
    current_observation.operation_id == *operation_id
        && current_observation.request_digest == *request_digest
        && current_observation.verifier_id == *verifier_id
        && current_observation.audience_id == *audience
        && current_observation.challenge == *challenge
}

fn verify_seal_signature(
    entry: &CachedAgentSignerEvidence,
    seal: &arkret_sdk::Seal,
) -> Result<(), AgentEvidenceRejectedReason> {
    let snapshot = authority_snapshot(&entry.evidence);
    let allowed = [
        snapshot.core.authority_id.as_str(),
        snapshot.core.signing_key_binding.controller_id.as_str(),
    ];
    let canonical = seal
        .canonical_bytes_for_id()
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let expected_digest = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&canonical))
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let signatures = match &seal.notary_signature {
        NotarySig::Single(signature) => vec![signature],
        NotarySig::Multi(multi) if !multi.signatures.is_empty() => {
            multi.signatures.iter().collect()
        }
        NotarySig::Multi(_) => {
            return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
        }
    };
    if signatures.into_iter().all(|signature| {
        let controller = signature
            .verification_method
            .split_once('#')
            .map_or(signature.verification_method.as_str(), |(did, _)| did);
        signature.payload_digest == expected_digest
            && allowed.contains(&controller)
            && entry
                .verification_method_public_keys
                .get(signature.verification_method.as_str())
                .is_some_and(|key| {
                    Ed25519DetachedJwsVerifier::new()
                        .verify_detached_jws(&signature.jws, &canonical, key)
                        .is_ok()
                })
    }) {
        Ok(())
    } else {
        Err(AgentEvidenceRejectedReason::SigningKeyMismatch)
    }
}

fn authorization_record_digests(evidence: &AgentSignerEvidence) -> Option<(Hash, Hash)> {
    let binding = signing_key_binding(evidence);
    authority_snapshot(evidence)
        .core
        .key_state_witness
        .cell_value
        .iter()
        .find_map(|entry| {
            if !agent_authorization_dot_matches_event(
                entry.tag.as_str(),
                binding.agent_key_authorize_event_id.as_str(),
            ) {
                return None;
            }
            let record = entry.value.as_object()?;
            let public_key_digest = Hash::new(record.get("public_key_digest")?.as_str()?).ok()?;
            let binding_digest =
                Hash::new(record.get("signing_key_binding_digest")?.as_str()?).ok()?;
            Some((public_key_digest, binding_digest))
        })
}

fn verify_lifecycle_reducer(
    entry: &CachedAgentSignerEvidence,
    witness: &arkret_sdk::AgentLifecycleWitness,
) -> Result<(), AgentEvidenceRejectedReason> {
    let snapshot = authority_snapshot(&entry.evidence);
    let event = &witness.accepted_status_event;
    if &witness.agent_id != event.actor_id.signing_principal_id()
        || event
            .executed_by
            .as_ref()
            .map(arkret_sdk::ActorId::signing_principal_id)
            != Some(&witness.controller_id)
        || event.realm_id != snapshot.core.principal_control_realm_id
        || arkret_sdk::signed_event_digest_claim(event)
            .ok()
            .is_none_or(|digest| {
                !witness.seal.delta.contains(&digest)
                    && !witness.seal.covered_event_digests.contains(&digest)
            })
        || event.payload.get("agent_id").and_then(Value::as_str) != Some(witness.agent_id.as_str())
        || event.payload.get("controller_id").and_then(Value::as_str)
            != Some(witness.controller_id.as_str())
    {
        return Err(AgentEvidenceRejectedReason::SigningKeyMismatch);
    }
    let provenance_matches = match (&witness.status, &witness.provenance) {
        (
            arkret_sdk::AgentLifecycleStatus::Active,
            arkret_sdk::AgentLifecycleProvenance::DelegatedPcrGenesis {
                realm_create_event_id,
                agent_provision_event_id,
            },
        ) => {
            let mut provision_refs = event
                .refs
                .iter()
                .filter(|event_ref| event_ref.role == "agent_provision");
            event.kind == arkret_sdk::EventKind::RealmCreate
                && event.event_id == *realm_create_event_id
                && provision_refs.next().is_some_and(|event_ref| {
                    event_ref.id == agent_provision_event_id.as_str() && event_ref.critical
                })
                && provision_refs.next().is_none()
        }
        (
            arkret_sdk::AgentLifecycleStatus::Active,
            arkret_sdk::AgentLifecycleProvenance::ResumeAccepted {
                resume_event_id,
                predecessor_pause_event_id,
            },
        ) => {
            event.kind == arkret_sdk::EventKind::SelfAgentResume
                && event.event_id == *resume_event_id
                && event.prev_refs.contains(predecessor_pause_event_id)
                && event.payload.get("transition").and_then(Value::as_str) == Some("resume")
                && event.payload.get("previous_status").and_then(Value::as_str) == Some("paused")
        }
        _ => false,
    };
    if !provenance_matches {
        return Err(AgentEvidenceRejectedReason::AuthorizationInactive);
    }
    let envelope =
        serde_json::to_value(event).map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let proofs = envelope
        .get("proofs")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    // The SDK owns the `encoding.md` §6 exclusion rule. This site used to apply
    // it by hand and dropped only `proofs`, `unsigned` and `actor_kind`: leaving
    // `event_id` in produced bytes the producer never signed, so every
    // well-formed evidence Event failed verification as
    // `SigningKeyMismatch`.
    let envelope = arkret_sdk::event_digest_preimage(&envelope)
        .map_err(|_| AgentEvidenceRejectedReason::SigningKeyMismatch)?;
    let verified = proofs.iter().any(|proof| {
        let Some(method) = proof.get("verification_method").and_then(Value::as_str) else {
            return false;
        };
        let Some(key) = entry.verification_method_public_keys.get(method) else {
            return false;
        };
        crate::identity::device_directory::verify_proof_value_for_signer(
            &envelope,
            proof,
            witness.controller_id.as_str(),
            witness.agent_id.as_str(),
            key,
        )
    });
    verified
        .then_some(())
        .ok_or(AgentEvidenceRejectedReason::SigningKeyMismatch)
}

fn verified_evidence_state(
    entry: &CachedAgentSignerEvidence,
    signer_actor_id: &arkret_sdk::ActorId,
) -> Option<(
    arkret_sdk::signatures::agent_evidence::VerifiedAgentEvidenceState,
    Hash,
    Hash,
)> {
    let binding = signing_key_binding(&entry.evidence);
    let (public_key_digest, binding_digest) = authorization_record_digests(&entry.evidence)?;
    let verify_seal = |seal: &arkret_sdk::Seal| verify_seal_signature(entry, seal);
    let verify_lifecycle =
        |witness: &arkret_sdk::AgentLifecycleWitness| verify_lifecycle_reducer(entry, witness);
    let context = AgentEvidenceStateVerificationContext {
        signer_id: &binding.agent_id,
        signer_actor_id,
        agent_key_id: &binding.agent_key_id,
        controller_id: &binding.controller_id,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        authorize_public_key_digest: &public_key_digest,
        authorize_signing_key_binding_digest: &binding_digest,
        verify_seal_signature: &verify_seal,
        verify_lifecycle_reducer: &verify_lifecycle,
    };
    let state = verify_agent_evidence_state(admission_evidence(&entry.evidence), &context).ok()?;
    Some((state, public_key_digest, binding_digest))
}

fn common_validation_context<'a>(
    entry: &'a CachedAgentSignerEvidence,
    state: &'a arkret_sdk::signatures::agent_evidence::VerifiedAgentEvidenceState,
    public_key_digest: &'a Hash,
    binding_digest: &'a Hash,
) -> Option<AgentEvidenceCommonContext<'a>> {
    let admission = admission_evidence(&entry.evidence);
    let snapshot = &admission.agent_authority_snapshot;
    let binding = &snapshot.core.signing_key_binding;
    let gate = &admission.controller_account_gate_attestation;
    Some(AgentEvidenceCommonContext {
        signer_id: &binding.agent_id,
        agent_key_id: &binding.agent_key_id,
        controller_id: &binding.controller_id,
        verification_method: &binding.verification_method,
        agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        authorize_public_key_digest: public_key_digest,
        authorize_signing_key_binding_digest: binding_digest,
        expected_authority_id: &snapshot.core.authority_id,
        expected_authority_verification_method: &snapshot.lease.verification_method,
        expected_account_authority_id: &gate.authority_id,
        expected_account_authority_verification_method: &gate.verification_method,
        controller_public_key: entry
            .verification_method_public_keys
            .get(binding.controller_proof.verification_method.as_str())?,
        authority_public_key: entry
            .verification_method_public_keys
            .get(snapshot.lease.verification_method.as_str())?,
        account_authority_public_key: entry
            .verification_method_public_keys
            .get(gate.verification_method.as_str())?,
        verified_state: state,
        require_transparency: false,
        transparency_verified: false,
        now: crate::clock::now_utc(),
    })
}

fn validate_current_entry(
    entry: &CachedAgentSignerEvidence,
    expected_agent_actor_id: &arkret_sdk::ActorId,
    expected_verification_method: &DidUrl,
) -> Option<[u8; 32]> {
    let CachedAgentSignerEvidenceContext::CurrentSignal {
        operation_id,
        request_digest,
        verifier_id,
        audience,
        challenge,
    } = &entry.verification_context
    else {
        return None;
    };
    if expected_agent_actor_id.as_account_id().is_none()
        || expected_agent_actor_id.signing_principal_id()
            != &signing_key_binding(&entry.evidence).agent_id
        || *expected_verification_method != signing_key_binding(&entry.evidence).verification_method
    {
        return None;
    }
    let (state, public_key_digest, binding_digest) =
        verified_evidence_state(entry, expected_agent_actor_id)?;
    let common = common_validation_context(entry, &state, &public_key_digest, &binding_digest)?;
    match validate_current_agent_signer_evidence(
        Some(&entry.evidence),
        &CurrentAgentSignerEvidenceValidationContext {
            common,
            operation_id,
            request_digest,
            verifier_id,
            audience,
            challenge,
        },
    ) {
        AgentSignerEvidenceVerdict::Verified(verified) => Some(*verified.key()),
        AgentSignerEvidenceVerdict::Unresolved(_) | AgentSignerEvidenceVerdict::Rejected(_) => None,
    }
}

fn validate_cached_historical(
    entry: &CachedAgentSignerEvidence,
    selector: &EventAgentSelector,
) -> Option<[u8; 32]> {
    let (state, public_key_digest, binding_digest) =
        verified_evidence_state(entry, &selector.agent_actor_id)?;
    let common = common_validation_context(entry, &state, &public_key_digest, &binding_digest)?;
    // The ordinary resolver only exposes the current DID/service document.
    // Until the client has ingested and validated the complete DID history,
    // it cannot honestly resolve a protected receipt kid at accepted_at.
    let resolve_receiver = |method: &DidUrl, _: chrono::DateTime<chrono::Utc>| {
        entry
            .verification_method_public_keys
            .get(method.as_str())
            .cloned()
    };
    match validate_historical_agent_signer_evidence(
        Some(&entry.evidence),
        &HistoricalAgentSignerEvidenceValidationContext {
            common,
            event_id: &selector.event_id,
            realm_id: &selector.realm_id,
            producer_accepted_at: selector.producer_accepted_at,
            producer_signer_resolution_evidence_ref: &selector
                .producer_signer_resolution_evidence_ref,
            producer_signer_resolution_evidence_digest: &selector
                .producer_signer_resolution_evidence_digest,
            receiver_id: &selector.receiver_id,
            resolve_receiver_historical_key: &resolve_receiver,
        },
    ) {
        AgentSignerEvidenceVerdict::Verified(verified) => Some(*verified.key()),
        AgentSignerEvidenceVerdict::Unresolved(_) | AgentSignerEvidenceVerdict::Rejected(_) => None,
    }
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
        NotarySig::Multi(_) => None,
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
    source_id: &DidCoreId,
    method: &DidUrl,
) -> Option<PublicKeyMaterial> {
    if method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .and_then(|controller| Did::new(controller.to_owned()).ok())
        .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
        .as_ref()
        != Some(source_id)
    {
        return None;
    }
    let source_did = Did::new(method.as_str().split_once('#')?.0.to_owned()).ok()?;
    if let Some(key) = resolve_method_key(http, anchor, method).await {
        return Some(key);
    }
    let description = http.describe().await.ok()?;
    if source_id != &description.service_id {
        return None;
    }
    let fetch_client = reqwest::Client::new();
    if !anchor
        .ensure_trusted_same_origin_service_document(&fetch_client, http.base_url(), &source_did)
        .await
    {
        return None;
    }
    let document = anchor.resolve_did_document(&source_did)?;
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

fn admission_evidence(evidence: &AgentSignerEvidence) -> &arkret_sdk::AgentAdmissionEvidence {
    match evidence {
        AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        }
        | AgentSignerEvidence::HistoricalEvent {
            admission_evidence, ..
        } => admission_evidence,
    }
}

fn authority_snapshot(evidence: &AgentSignerEvidence) -> &arkret_sdk::AgentAuthoritySnapshot {
    &admission_evidence(evidence).agent_authority_snapshot
}

fn signing_key_binding(evidence: &AgentSignerEvidence) -> &arkret_sdk::AgentSigningKeyBinding {
    &authority_snapshot(evidence).core.signing_key_binding
}

fn seal_lineage(evidence: &AgentSignerEvidence) -> &[arkret_sdk::Seal] {
    &authority_snapshot(evidence).core.seal_lineages
}

fn historical_receipt(
    evidence: &AgentSignerEvidence,
) -> Option<&arkret_sdk::AgentEventAdmissionReceipt> {
    match evidence {
        AgentSignerEvidence::HistoricalEvent {
            event_admission_receipt,
            ..
        } => Some(event_admission_receipt),
        AgentSignerEvidence::CurrentAdmission { .. } => None,
    }
}

fn historical_receipt_matches_selector(
    receipt: &arkret_sdk::AgentEventAdmissionReceipt,
    selector: &EventAgentSelector,
) -> bool {
    receipt.realm_id == selector.realm_id
        && receipt.agent_id == selector.agent_id
        && receipt.verification_method == selector.verification_method
        && receipt.event_id == selector.event_id
        && receipt.producer_accepted_at == selector.producer_accepted_at
        && receipt.producer_signer_resolution_evidence_ref
            == selector.producer_signer_resolution_evidence_ref
        && receipt.producer_signer_resolution_evidence_digest
            == selector.producer_signer_resolution_evidence_digest
        && receipt.receiver_id == selector.receiver_id
}

fn event_agent_identity(envelope: &Value) -> Option<(arkret_sdk::Event, DidCoreId, DidUrl)> {
    let event: arkret_sdk::Event = serde_json::from_value(envelope.clone()).ok()?;
    if event.actor_kind != Some(arkret_sdk::EnvelopeActorKind::Agent) || event.applet_id.is_some() {
        return None;
    }
    let agent_id = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .signing_principal_id()
        .clone();
    let verification_method = event
        .proofs
        .iter()
        .filter_map(arkret_sdk::EventProof::as_producer)
        .find(|proof| {
            proof
                .verification_method
                .as_str()
                .split_once('#')
                .is_some_and(|(controller, _)| controller == agent_id.as_str())
        })?
        .verification_method
        .clone();
    Some((event, agent_id, verification_method))
}

fn origin_admission(event: &arkret_sdk::Event) -> Option<&arkret_sdk::StationAdmissionProof> {
    event.proofs.iter().find_map(|proof| match proof {
        arkret_sdk::EventProof::StationAdmission(value) => Some(value),
        arkret_sdk::EventProof::Producer(_) => None,
    })
}

fn actor_id_from_full(did: &Did) -> Option<DidCoreId> {
    arkret_sdk::project_did_to_core_id(did).ok()
}

fn did_from_method_for_actor(method: &DidUrl, actor_id: &DidCoreId) -> Option<Did> {
    let did = Did::new(method.as_str().split_once('#')?.0.to_owned()).ok()?;
    (actor_id_from_full(&did).as_ref() == Some(actor_id)).then_some(did)
}

fn collect_selectors(
    value: &Value,
    receiver_id: &DidCoreId,
    depth: usize,
    out: &mut BTreeSet<EventAgentSelector>,
) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some(selector) = selector_from_object(object, receiver_id) {
                out.insert(selector);
            }
            for child in object.values() {
                collect_selectors(child, receiver_id, depth + 1, out);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_selectors(child, receiver_id, depth + 1, out);
            }
        }
        _ => {}
    }
}

fn selector_from_object(
    object: &serde_json::Map<String, Value>,
    receiver_id: &DidCoreId,
) -> Option<EventAgentSelector> {
    if object.get("applet_id").is_some() {
        return None;
    }
    if object.get("actor_kind").and_then(Value::as_str) != Some("agent") {
        return None;
    }
    let (event, agent_id, verification_method) =
        event_agent_identity(&Value::Object(object.clone()))?;
    let realm_id = event.realm_id.clone();
    if arkret_sdk::signed_event_digest_claim(&event).ok()?
        != event.event_id.identity_key().event_digest()
    {
        return None;
    }
    let admission = origin_admission(&event)?;
    Some(EventAgentSelector {
        realm_id,
        agent_actor_id: event.actor_id.clone(),
        agent_id,
        verification_method,
        event_id: event.event_id.clone(),
        producer_accepted_at: admission.accepted_at,
        producer_signer_resolution_evidence_ref: admission
            .producer_signer_resolution_evidence_ref
            .clone()?,
        producer_signer_resolution_evidence_digest: admission
            .producer_signer_resolution_evidence_digest
            .clone()?,
        receiver_id: receiver_id.clone(),
    })
}

impl Ord for EventAgentSelector {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.realm_id.as_str(),
            &self.agent_actor_id,
            self.agent_id.as_str(),
            self.verification_method.as_str(),
            self.event_id.as_str(),
            self.producer_accepted_at,
            self.producer_signer_resolution_evidence_ref.as_ref(),
            self.producer_signer_resolution_evidence_digest.as_str(),
            self.receiver_id.as_str(),
        )
            .cmp(&(
                other.realm_id.as_str(),
                &other.agent_actor_id,
                other.agent_id.as_str(),
                other.verification_method.as_str(),
                other.event_id.as_str(),
                other.producer_accepted_at,
                other.producer_signer_resolution_evidence_ref.as_ref(),
                other.producer_signer_resolution_evidence_digest.as_str(),
                other.receiver_id.as_str(),
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
