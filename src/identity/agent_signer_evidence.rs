use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::signatures::PublicKeyMaterial;
use arkret_sdk::{
    AgentSignerEvidence, AgentSignerEvidenceQueryRequestBody, AgentSignerEvidenceQuerySelector,
    Did, DidCoreId, DidUrl, RealmId,
};
use serde_json::Value;

use crate::state::{CachedAgentSignerEvidence, CachedAgentSignerEvidenceContext, LocalStateStore};

const MAX_SCAN_DEPTH: usize = 32;

#[derive(Clone)]
struct EventAgentSelector {
    accepted_event: arkret_sdk::Event,
    realm_id: RealmId,
    agent_actor_id: arkret_sdk::ActorId,
    agent_id: DidCoreId,
    verification_method: DidUrl,
    event_id: arkret_sdk::EventId,
    producer_accepted_at: chrono::DateTime<chrono::Utc>,
    producer_signer_resolution_evidence_ref: arkret_sdk::SignerEvidenceRef,
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
    state_store: &crate::runtime::input::StateStoreHandle,
) -> bool {
    let Some(receiver_id) = state_store
        .read(|store| store.active_authority())
        .map(|account| account.station_id)
    else {
        return false;
    };
    let mut selectors = BTreeSet::new();
    for projection in projections.values() {
        collect_selectors(projection, &receiver_id, 0, &mut selectors);
    }
    if selectors.is_empty() {
        return false;
    }

    let mut changed = false;
    let mut satisfied = BTreeSet::new();
    for selector in &selectors {
        let entries = state_store.read(|store| {
            store.cached_agent_signer_evidence(&selector.agent_id, &selector.verification_method)
        });
        for entry in entries {
            let Some(admission) = historical_admission(&entry.evidence) else {
                continue;
            };
            if !historical_admission_matches_selector(admission, selector) {
                continue;
            }
            if entry.verified_historical_key.is_some() {
                satisfied.insert(selector_cache_key(selector));
                break;
            }
            let root = entry.signer_evidence_root.clone();
            let Some(restored) = verify_for_cache(
                http,
                root,
                Some(entry.signer_evidence_dependencies),
                selector,
            )
            .await
            else {
                continue;
            };
            if state_store
                .write(|store| store.store_verified_agent_signer_evidence(restored))
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
                        } = &root
                        else {
                            continue;
                        };
                        let Some(receipt) = historical_admission(&evidence) else {
                            continue;
                        };
                        let Some(selector_index) = pending_selectors.iter().position(|selector| {
                            historical_admission_matches_selector(receipt, selector)
                        }) else {
                            continue;
                        };
                        let Some(entry) =
                            verify_for_cache(http, root, None, &pending_selectors[selector_index])
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
                // immutable signer dependencies are observable. Stop only after evidence is
                // fully verified and cached, not merely after a non-empty
                // query response.
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(500)).await;
            }
        }
    }
    changed
}

fn selector_cache_key(selector: &EventAgentSelector) -> (String, String, String) {
    (
        selector.agent_id.as_str().to_owned(),
        selector.verification_method.as_str().to_owned(),
        selector.event_id.as_str().to_owned(),
    )
}

/// Refresh only missing or expired authority; messages never bind this query.
pub(crate) async fn resolve_current_signal_sender_evidence(
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
    cached_entries: Vec<CachedAgentSignerEvidence>,
) -> Option<CachedAgentSignerEvidence> {
    resolve_current_signal_sender_evidence_with_clock(
        http,
        envelope,
        recipient_account_id,
        cached_entries,
        &garth::SystemClock,
    )
    .await
}

async fn resolve_current_signal_sender_evidence_with_clock(
    http: &arkret_sdk::http_client::Client,
    envelope: &arkret_wire::SignalEnvelope,
    recipient_account_id: arkret_sdk::AccountId,
    mut cached_entries: Vec<CachedAgentSignerEvidence>,
    clock: &impl garth::HostClock,
) -> Option<CachedAgentSignerEvidence> {
    if envelope.sender_device_id.is_some() {
        return None;
    }
    let now = clock.now();
    let mut states = BTreeMap::new();
    let mut dependencies = BTreeMap::new();
    for entry in &mut cached_entries {
        if entry.invalidated {
            continue;
        }
        let CachedAgentSignerEvidenceContext::CurrentRelation {
            agent_actor_id,
            realm_id,
            recipient_account_id: cached_recipient,
        } = &entry.verification_context
        else {
            continue;
        };
        if agent_actor_id != &envelope.sender_actor_id
            || realm_id != &envelope.realm_id
            || cached_recipient != &recipient_account_id
        {
            continue;
        }
        if entry.verified_current_key.is_none() {
            let arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
                agent_signer_evidence,
                ..
            } = &entry.signer_evidence_root
            else {
                continue;
            };
            entry.evidence = *agent_signer_evidence.clone();
            let root = &entry.signer_evidence_root;
            // Re-authenticate persisted immutable bytes at their signed observation.
            // The resulting token still retains the original deadline for permits(now).
            entry.verified_current_key = verify_current_root(
                root,
                &entry.signer_evidence_dependencies,
                agent_actor_id,
                &envelope.proof.verification_method,
                admission_evidence(&entry.evidence).valid_from(),
                None,
            )
            .await;
        }
        let Some(key) = entry.verified_current_key.as_ref() else {
            continue;
        };
        if key.key().permits(
            &envelope.sender_actor_id,
            &envelope.proof.verification_method,
            now,
        ) {
            return Some(entry.clone());
        }
        let state = authority_state_evidence(&entry.evidence);
        states.insert(state.state_digest.clone(), state.state.clone());
        for dependency in &entry.signer_evidence_dependencies {
            dependencies.insert(dependency.evidence_ref().ok()?, dependency.clone());
        }
    }
    let (request, outcome) = crate::identity::current_signer_evidence::query_for_signal(
        http,
        envelope,
        recipient_account_id.clone(),
        states.keys().cloned().take(64).collect(),
        dependencies.keys().cloned().take(64).collect(),
    )
    .await?;
    let dependencies = dependencies.into_values().collect::<Vec<_>>();
    let context = CachedAgentSignerEvidenceContext::CurrentRelation {
        agent_actor_id: envelope.sender_actor_id.clone(),
        realm_id: envelope.realm_id.clone(),
        recipient_account_id,
    };
    let mut verified = Vec::new();
    for item in outcome.response.evidences {
        if !request.queries.contains(&item.selector()) {
            return None;
        }
        let Ok((root, closure)) = item.hydrate_agent(&request, &states, &dependencies) else {
            continue;
        };
        let Some(key) = verify_current_root(
            &root,
            &closure,
            &envelope.sender_actor_id,
            &envelope.proof.verification_method,
            clock.now(),
            cached_entries
                .iter()
                .find_map(|entry| entry.verified_current_key.as_ref()),
        )
        .await
        else {
            continue;
        };
        let arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            ..
        } = &root
        else {
            continue;
        };
        verified.push(CachedAgentSignerEvidence {
            invalidated: false,
            evidence: *agent_signer_evidence.clone(),
            signer_evidence_root: root,
            signer_evidence_dependencies: closure,
            verified_current_key: Some(key),
            verification_context: context.clone(),
            verified_historical_key: None,
            cached_at_unix_ms: crate::clock::now_unix_ms(),
        });
    }
    let first = verified.pop()?;
    if verified
        .iter()
        .any(|entry| entry.verified_current_key != first.verified_current_key)
    {
        return None;
    }
    Some(first)
}

fn governance_dependencies(
    evidence: &[arkret_sdk::AuthenticatedSignerResolutionEvidence],
) -> Option<Vec<arkret_sdk::GovernanceDependency>> {
    evidence
        .iter()
        .map(|item| {
            Some(arkret_sdk::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
        selector: arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
            content_digest: item.canonical_sha256_digest().ok()?,
        },
        authenticated_signer_resolution_evidence: Box::new(item.clone()),
    })
        })
        .collect()
}

async fn verify_current_root(
    root: &arkret_sdk::AuthenticatedSignerResolutionEvidence,
    closure: &[arkret_sdk::AuthenticatedSignerResolutionEvidence],
    actor: &arkret_sdk::ActorId,
    method: &DidUrl,
    now: chrono::DateTime<chrono::Utc>,
    previous: Option<&arkret_sdk::VerifiedAgentCurrentContext>,
) -> Option<arkret_sdk::VerifiedAgentCurrentContext> {
    let dependencies = governance_dependencies(closure)?;
    let owned_root = std::sync::Arc::new(root.clone());
    let owned_dependencies = std::sync::Arc::new(dependencies.clone());
    arkret_sdk::verify_agent_current_context(
        actor,
        method,
        root,
        &dependencies,
        now,
        previous,
        move |request| {
            let root = owned_root.clone();
            let dependencies = owned_dependencies.clone();
            Box::pin(async move {
                arkret_sdk::verify_agent_portable_trust(request, &root, &dependencies)
            })
        },
    )
    .await
    .map_err(|error| tracing::warn!(%error, "Agent portable authority verification failed"))
    .ok()
}

/// Return a previously authenticated relationship token; each message still
/// passes actor/method, MLS scope/epoch, producer signature and replay checks.
pub(crate) fn cached_current_signal_sender_evidence(
    store: &LocalStateStore,
    envelope: &arkret_wire::SignalEnvelope,
) -> Option<(PublicKeyMaterial, arkret_sdk::EventId)> {
    if envelope.sender_device_id.is_some() {
        return None;
    }
    let mut verified = store.verified_agent_current_keys(
        &envelope.sender_actor_id,
        &envelope.realm_id,
        &envelope.proof.verification_method,
        crate::clock::now_utc(),
    );
    let (key, authorization) = verified.pop()?;
    if verified
        .iter()
        .any(|(other, auth)| *other != key || *auth != authorization)
    {
        return None;
    }
    Some((
        PublicKeyMaterial::Ed25519Raw {
            bytes: key.to_vec(),
        },
        authorization,
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
        let Some(receipt) = historical_admission(&entry.evidence) else {
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
            accepted_event: event.clone(),
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
            receiver_id: match receipt.receiver_id() {
                Ok(value) => value,
                Err(_) => continue,
            },
        };
        if !historical_admission_matches_selector(receipt, &selector) {
            saw_rejected = true;
            continue;
        }
        let CachedAgentSignerEvidenceContext::HistoricalEvent {
            realm_id,
            event_id,
            producer_accepted_at,
            producer_signer_resolution_evidence_ref,
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
        let Some(receipt) = historical_admission(&entry.evidence) else {
            continue;
        };
        let selector = EventAgentSelector {
            accepted_event: event.clone(),
            realm_id: event.realm_id.clone(),
            agent_actor_id: event.actor_id.clone(),
            agent_id: agent_id.clone(),
            verification_method: verification_method.clone(),
            event_id: event.event_id.clone(),
            producer_accepted_at: admission.accepted_at,
            producer_signer_resolution_evidence_ref: admission
                .producer_signer_resolution_evidence_ref
                .clone()?,
            receiver_id: match receipt.receiver_id() {
                Ok(value) => value,
                Err(_) => continue,
            },
        };
        if !historical_admission_matches_selector(receipt, &selector) {
            continue;
        }
        let CachedAgentSignerEvidenceContext::HistoricalEvent {
            realm_id,
            event_id,
            producer_accepted_at,
            producer_signer_resolution_evidence_ref,
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
    root: arkret_sdk::AuthenticatedSignerResolutionEvidence,
    cached_dependencies: Option<Vec<arkret_sdk::AuthenticatedSignerResolutionEvidence>>,
    selector: &EventAgentSelector,
) -> Option<CachedAgentSignerEvidence> {
    let closure = match cached_dependencies {
        Some(value) => value,
        None => fetch_signer_dependencies(http, &root, &selector.realm_id).await?,
    };
    let dependencies = governance_dependencies(&closure)?;
    let owned_root = std::sync::Arc::new(root.clone());
    let owned_dependencies = std::sync::Arc::new(dependencies.clone());
    let key = arkret_sdk::verify_agent_historical_event_key(
        &selector.accepted_event,
        &root,
        &dependencies,
        move |request| {
            let root = owned_root.clone();
            let dependencies = owned_dependencies.clone();
            Box::pin(async move {
                arkret_sdk::verify_agent_portable_trust(request, &root, &dependencies)
            })
        },
    )
    .await
    .map_err(|error| tracing::warn!(%error, "Agent historical closure verification failed"))
    .ok()?;
    let arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
        agent_signer_evidence,
        ..
    } = &root
    else {
        return None;
    };
    Some(CachedAgentSignerEvidence {
        invalidated: false,
        evidence: *agent_signer_evidence.clone(),
        signer_evidence_root: root,
        signer_evidence_dependencies: closure,
        verified_current_key: None,
        verified_historical_key: Some(key.ed25519_bytes().ok()?),
        verification_context: CachedAgentSignerEvidenceContext::HistoricalEvent {
            realm_id: selector.realm_id.clone(),
            event_id: selector.event_id.clone(),
            producer_accepted_at: selector.producer_accepted_at,
            producer_signer_resolution_evidence_ref: selector
                .producer_signer_resolution_evidence_ref
                .clone(),
            receiver_id: selector.receiver_id.clone(),
        },
        cached_at_unix_ms: crate::clock::now_unix_ms(),
    })
}

async fn fetch_signer_dependencies(
    http: &arkret_sdk::http_client::Client,
    root: &arkret_sdk::AuthenticatedSignerResolutionEvidence,
    realm_id: &RealmId,
) -> Option<Vec<arkret_sdk::AuthenticatedSignerResolutionEvidence>> {
    let mut collected = BTreeMap::new();
    let mut pending =
        arkret_sdk::governance_attester_evidence_selectors(std::iter::once(root)).ok()?;
    while !pending.is_empty() {
        if collected.len() + pending.len() > 64 {
            return None;
        }
        let request = arkret_sdk::SelfGovernanceDependencyResolveRequest {
            realm_id: realm_id.clone(),
            selectors: pending.clone(),
            byte_limit: arkret_sdk::MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES,
            history_traversal_access: None,
        };
        let response = http.governance_dependencies_resolve(&request).await.ok()?;
        response.validate_for_self_request(&request).ok()?;
        if response.items.len() != pending.len() {
            return None;
        }
        for item in response.items {
            if !pending.contains(item.selector()) {
                return None;
            }
            let arkret_sdk::GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } = item
            else {
                return None;
            };
            let digest = authenticated_signer_resolution_evidence
                .canonical_sha256_digest()
                .ok()?;
            collected.insert(digest, *authenticated_signer_resolution_evidence);
        }
        pending = arkret_sdk::governance_attester_evidence_selectors(collected.values()).ok()?;
        pending.retain(|selector| match selector {
            arkret_sdk::GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest,
            } => !collected.contains_key(content_digest),
            _ => true,
        });
    }
    Some(collected.into_values().collect())
}

fn validate_cached_historical(
    entry: &CachedAgentSignerEvidence,
    selector: &EventAgentSelector,
) -> Option<[u8; 32]> {
    let admission = historical_admission(&entry.evidence)?;
    if !historical_admission_matches_selector(admission, selector) {
        return None;
    }
    entry.verified_historical_key
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

fn authority_state_evidence(
    evidence: &AgentSignerEvidence,
) -> &arkret_sdk::AgentAuthorityStateEvidence {
    &admission_evidence(evidence).agent_authority_state_evidence
}

fn signing_key_binding(evidence: &AgentSignerEvidence) -> &arkret_sdk::AgentSigningKeyBinding {
    &authority_state_evidence(evidence).state.signing_key_binding
}

fn historical_admission(
    evidence: &AgentSignerEvidence,
) -> Option<&arkret_sdk::AgentEventAdmission> {
    match evidence {
        AgentSignerEvidence::HistoricalEvent {
            event_admission, ..
        } => Some(event_admission),
        AgentSignerEvidence::CurrentAdmission { .. } => None,
    }
}

fn historical_admission_matches_selector(
    admission: &arkret_sdk::AgentEventAdmission,
    selector: &EventAgentSelector,
) -> bool {
    admission.realm_id() == &selector.realm_id
        && admission.agent_id() == &selector.agent_id
        && admission.verification_method().ok() == Some(&selector.verification_method)
        && admission.event_id() == &selector.event_id
        && admission.producer_accepted_at().ok() == Some(selector.producer_accepted_at)
        && admission.producer_signer_resolution_evidence_ref().ok()
            == Some(&selector.producer_signer_resolution_evidence_ref)
        && admission.receiver_id().ok().as_ref() == Some(&selector.receiver_id)
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
                .and_then(|(controller, _)| Did::new(controller.to_owned()).ok())
                .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
                .is_some_and(|controller| controller == agent_id)
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
        accepted_event: event.clone(),
        realm_id,
        agent_actor_id: event.actor_id.clone(),
        agent_id,
        verification_method,
        event_id: event.event_id.clone(),
        producer_accepted_at: admission.accepted_at,
        producer_signer_resolution_evidence_ref: admission
            .producer_signer_resolution_evidence_ref
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

#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod cache_tests {
    use chrono::{DateTime, Utc};

    use super::*;

    #[derive(serde::Deserialize)]
    struct Fixture {
        actor: arkret_sdk::ActorId,
        verification_method: DidUrl,
        realm_id: RealmId,
        recipient_account_id: arkret_sdk::AccountId,
        valid_from: DateTime<Utc>,
        root: arkret_sdk::AuthenticatedSignerResolutionEvidence,
        dependencies: Vec<arkret_sdk::AuthenticatedSignerResolutionEvidence>,
    }

    #[derive(Clone)]
    struct FixedClock(DateTime<Utc>);

    impl garth::HostClock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    fn fixture() -> Fixture {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../arkret-rust-sdk/crates/sdk/tests/fixtures/agent-current-context.json");
        serde_json::from_slice(
            &std::fs::read(path).expect("public Agent context fixture must be generated first"),
        )
        .unwrap()
    }

    fn envelope(fixture: &Fixture) -> arkret_wire::SignalEnvelope {
        serde_json::from_value(serde_json::json!({
            "realm_id": fixture.realm_id,
            "scope_ref": {"kind":"realm", "realm_id":fixture.realm_id},
            "sender_actor_id": fixture.actor,
            "seal_ref": format!("ak:seal:sha256:{}", "a".repeat(64)),
            "signal_class": "session",
            "sent_at": arkret_sdk::canonical::format_timestamp_canonical(fixture.valid_from),
            "expires_at": arkret_sdk::canonical::format_timestamp_canonical(fixture.valid_from + chrono::Duration::seconds(10)),
            "encrypted_payload": {
                "scheme": arkret_wire::signal::SIGNAL_AEAD_SCHEME,
                "key_ref": {"algorithm":"MLS-EXPORTER-AEAD", "group_state_ref":"ak:event:AZVgkcivLIz2PjwUcjuT5bTb6295nnowDbSQak0QfNCa"},
                "purpose": arkret_wire::signal::SIGNAL_AEAD_PURPOSE,
                "aead_profile":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                "epoch":4, "nonce":"AAAAAAAAAAAAAAAA", "ciphertext":"AAAAAAAAAAAAAAAAAAAAAA",
                "aad_digest":format!("sha256:{}", "0".repeat(64))
            },
            "proof": {"kind":arkret_sdk::proof_kind::DETACHED_JWS,
                "verification_method":fixture.verification_method,
                "envelope_digest":format!("sha256:{}", "0".repeat(64)), "jws":""}
        })).unwrap()
    }

    async fn entry(fixture: &Fixture) -> CachedAgentSignerEvidence {
        let context = verify_current_root(
            &fixture.root,
            &fixture.dependencies,
            &fixture.actor,
            &fixture.verification_method,
            fixture.valid_from,
            None,
        )
        .await
        .expect("signed producer fixture must verify");
        let arkret_sdk::AuthenticatedSignerResolutionEvidence::Agent {
            agent_signer_evidence,
            ..
        } = &fixture.root
        else {
            panic!("Agent fixture")
        };
        CachedAgentSignerEvidence {
            evidence: *agent_signer_evidence.clone(),
            invalidated: false,
            signer_evidence_root: fixture.root.clone(),
            signer_evidence_dependencies: fixture.dependencies.clone(),
            verified_current_key: Some(context),
            verified_historical_key: None,
            verification_context: CachedAgentSignerEvidenceContext::CurrentRelation {
                agent_actor_id: fixture.actor.clone(),
                realm_id: fixture.realm_id.clone(),
                recipient_account_id: fixture.recipient_account_id.clone(),
            },
            cached_at_unix_ms: fixture.valid_from.timestamp_millis() as u64,
        }
    }

    pub(crate) async fn signed_fixture_entry() -> CachedAgentSignerEvidence {
        entry(&fixture()).await
    }

    #[tokio::test]
    async fn agent_cache_reuses_signed_context_across_messages_and_persisted_reconnect_without_query()
     {
        let fixture = fixture();
        let mut entry = entry(&fixture).await;
        let mut envelope = envelope(&fixture);
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let http = arkret_sdk::http_client::Client::builder(
            format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap(),
        )
        .allow_insecure_localhost()
        .build()
        .unwrap();
        let original_expiry = entry
            .verified_current_key
            .as_ref()
            .unwrap()
            .key()
            .expires_at();
        for message in 0..3 {
            envelope.sent_at = fixture.valid_from + chrono::Duration::milliseconds(message);
            entry = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                resolve_current_signal_sender_evidence_with_clock(
                    &http,
                    &envelope,
                    fixture.recipient_account_id.clone(),
                    vec![entry],
                    &FixedClock(envelope.sent_at),
                ),
            )
            .await
            .expect("cache hit must not wait for HTTP")
            .expect("valid current context");
        }
        let saved = serde_json::to_vec(&entry).unwrap();
        let restored: CachedAgentSignerEvidence = serde_json::from_slice(&saved).unwrap();
        assert!(restored.verified_current_key.is_none());
        let restored = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            resolve_current_signal_sender_evidence_with_clock(
                &http,
                &envelope,
                fixture.recipient_account_id.clone(),
                vec![restored],
                &FixedClock(envelope.sent_at),
            ),
        )
        .await
        .expect("reconnect must verify cached bytes without HTTP")
        .expect("restored current context");
        assert_eq!(
            restored
                .verified_current_key
                .as_ref()
                .unwrap()
                .key()
                .expires_at(),
            original_expiry
        );
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
}
