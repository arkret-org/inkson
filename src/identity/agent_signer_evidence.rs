//! Historical signing keys supplied by the authenticated Account Station.

use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::signatures::PublicKeyMaterial;
use arkret_sdk::{
    AgentSenderKind, Did, DidCoreId, DidUrl, HistoricalAgentSelector, HistoricalEventMode, RealmId,
    SignerKeyQueryResult, SignerKeyQuerySelector, SignerKeysQueryRequestBody,
};
use serde_json::Value;

use crate::state::{CachedHistoricalAgentSignerKey, LocalStateStore};

const MAX_SCAN_DEPTH: usize = 32;
const MAX_SCANNED_SELECTORS: usize = 4096;
const MAX_REQUEST_SELECTORS: usize = 64;

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

fn query_selector(selector: &EventAgentSelector) -> SignerKeyQuerySelector {
    SignerKeyQuerySelector::HistoricalAgent(HistoricalAgentSelector {
        verification_mode: HistoricalEventMode::HistoricalEvent,
        sender_kind: AgentSenderKind::Agent,
        actor: selector.agent_actor_id.clone(),
        verification_method: selector.verification_method.clone(),
        event_id: selector.event_id.clone(),
    })
}

fn historical_key(
    entry: &CachedHistoricalAgentSignerKey,
    selector: &EventAgentSelector,
    recipient: &arkret_sdk::AccountId,
) -> Option<[u8; 32]> {
    if entry.recipient_account_id != *recipient
        || entry.realm_id != selector.realm_id
        || entry.event_id != selector.event_id
        || entry.receiver_id != selector.receiver_id
        || entry.accepted_at != selector.producer_accepted_at
        || entry.producer_signer_evidence_ref != selector.producer_signer_resolution_evidence_ref
        || entry.key.actor != selector.agent_actor_id
        || entry.key.verification_method != selector.verification_method
    {
        return None;
    }
    entry.key.validate().ok()?;
    arkret_sdk::base64url_decode(entry.key.public_key_b64u.as_str().as_bytes())
        .ok()?
        .try_into()
        .ok()
}

fn verify_event_producer(selector: &EventAgentSelector, key: &[u8; 32]) -> bool {
    let event = &selector.accepted_event;
    let Ok(envelope) = serde_json::to_value(event) else {
        return false;
    };
    let Ok(preimage) = arkret_sdk::event_digest_preimage(&envelope) else {
        return false;
    };
    let Ok(suite) = event.event_id.event_digest().digest_suite() else {
        return false;
    };
    let material = PublicKeyMaterial::Ed25519Raw {
        bytes: key.to_vec(),
    };
    event.proofs.iter().filter_map(arkret_sdk::EventProof::as_producer).any(|proof| {
        if proof.verification_method != selector.verification_method { return false }
        let Ok(proof) = serde_json::to_value(proof) else { return false };
        crate::identity::device_directory::verify_proof_value_for_signer_result_with_digest_suite(
            &preimage, &proof, selector.agent_id.as_str(),
            event.actor_id.signing_principal_id().as_str(), &material, suite,
        ).is_ok()
    })
}

pub(crate) async fn prefetch_from_realm_projections(
    http: &arkret_sdk::http_client::Client,
    projections: &BTreeMap<String, Value>,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> bool {
    let Some(recipient) = state_store.read(|store| store.active_authority()) else {
        return false;
    };
    let generation = crate::identity::device_directory::cache_epoch();
    let mut selectors = BTreeSet::new();
    for projection in projections.values() {
        collect_selectors(projection, &recipient.station_id, 0, &mut selectors);
    }
    let mut by_realm = BTreeMap::<RealmId, Vec<EventAgentSelector>>::new();
    for selector in selectors
        .into_iter()
        .filter(|selector| {
            !state_store.read(|store| {
                store
                    .historical_agent_signer_keys(
                        &selector.agent_actor_id,
                        &selector.verification_method,
                    )
                    .iter()
                    .any(|entry| historical_key(entry, selector, &recipient).is_some())
            })
        })
        .take(MAX_REQUEST_SELECTORS)
    {
        by_realm
            .entry(selector.realm_id.clone())
            .or_default()
            .push(selector);
    }
    let mut changed = false;
    for (realm_id, pending) in by_realm {
        let request = SignerKeysQueryRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            realm_id,
            recipient_account_id: recipient.clone(),
            queries: pending.iter().map(query_selector).collect(),
        };
        let Ok(outcome) = http.signer_keys_query(&request).await else {
            continue;
        };
        if outcome.validate_for_request(&request).is_err() {
            continue;
        }
        for result in outcome.results {
            let SignerKeyQueryResult::HistoricalAgent(result) = result else {
                continue;
            };
            let arkret_sdk::HistoricalAgentSignerKeyResult {
                selector,
                key,
                accepted_at,
                signer_evidence_ref,
                ..
            } = result;
            let Some(selected) = pending.iter().find(|item| {
                query_selector(item) == SignerKeyQuerySelector::HistoricalAgent(selector.clone())
            }) else {
                continue;
            };
            let entry = CachedHistoricalAgentSignerKey {
                recipient_account_id: recipient.clone(),
                realm_id: selected.realm_id.clone(),
                event_id: selected.event_id.clone(),
                receiver_id: selected.receiver_id.clone(),
                accepted_at,
                producer_signer_evidence_ref: selected
                    .producer_signer_resolution_evidence_ref
                    .clone(),
                signer_evidence_ref,
                key,
                cached_at_unix_ms: crate::clock::now_unix_ms(),
            };
            let Some(key) = historical_key(&entry, selected, &recipient) else {
                continue;
            };
            if !verify_event_producer(selected, &key) {
                continue;
            }
            let stored = state_store.write(|store| {
                if generation != crate::identity::device_directory::cache_epoch()
                    || store.active_authority().as_ref() != Some(&recipient)
                {
                    return Err(
                        "historical signer response arrived after account changed".to_owned()
                    );
                }
                store.store_historical_agent_signer_key(entry)
            });
            changed |= stored.is_ok();
        }
    }
    changed
}

pub(crate) fn verify_cached_event(
    envelope: &Value,
    store: &LocalStateStore,
    mls_binding: Option<OrdinaryAgentMlsBinding<'_>>,
) -> CachedAgentEventVerdict {
    let Some((..)) = event_agent_identity(envelope) else {
        return CachedAgentEventVerdict::NotAgent;
    };
    let Some(recipient) = store.active_authority() else {
        return CachedAgentEventVerdict::Unresolved;
    };
    let Some(selector) = envelope
        .as_object()
        .and_then(|object| selector_from_object(object, &recipient.station_id))
    else {
        return CachedAgentEventVerdict::Rejected;
    };
    let mut matched = false;
    for entry in
        store.historical_agent_signer_keys(&selector.agent_actor_id, &selector.verification_method)
    {
        let Some(key) = historical_key(&entry, &selector, &recipient) else {
            continue;
        };
        matched = true;
        if let Some(binding) = &mls_binding {
            if did_from_method_for_actor(&selector.verification_method, &selector.agent_id)
                .is_none()
            {
                continue;
            }
            let claim = arkret_sdk::mls::AgentMlsSignerClaim {
                group_id: binding.group_id,
                epoch: binding.epoch,
                group_state_ref: binding.group_state_ref,
                signer_id: &selector.agent_id,
                signing_key: &key,
                agent_key_authorize_event_id: &entry.key.authorization_ref,
            };
            if arkret_sdk::mls::verify_ordinary_agent_mls_binding(binding.view, &claim).is_err() {
                continue;
            }
        }
        if verify_event_producer(&selector, &key) {
            return CachedAgentEventVerdict::Verified;
        }
    }
    if matched {
        CachedAgentEventVerdict::Rejected
    } else {
        CachedAgentEventVerdict::Unresolved
    }
}

pub(crate) fn verified_cached_agent_event_endpoint(
    event: &arkret_sdk::Event,
    store: &LocalStateStore,
) -> Option<arkret_sdk::SignalSequenceEndpoint> {
    let envelope = serde_json::to_value(event).ok()?;
    if verify_cached_event(&envelope, store, None) != CachedAgentEventVerdict::Verified {
        return None;
    }
    let recipient = store.active_authority()?;
    let selector = selector_from_object(envelope.as_object()?, &recipient.station_id)?;
    let mut digests = BTreeSet::new();
    for entry in
        store.historical_agent_signer_keys(&selector.agent_actor_id, &selector.verification_method)
    {
        if let Some(key) = historical_key(&entry, &selector, &recipient) {
            let material = PublicKeyMaterial::Ed25519Raw {
                bytes: key.to_vec(),
            };
            digests.insert(material.raw_ed25519_digest().ok()?);
        }
    }
    let mut digests = digests.into_iter();
    let public_key_digest = digests.next()?;
    if digests.next().is_some() {
        return None;
    }
    Some(arkret_sdk::SignalSequenceEndpoint::AgentKey { public_key_digest })
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
    if depth > MAX_SCAN_DEPTH || out.len() >= MAX_SCANNED_SELECTORS {
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
        agent_actor_id: event
            .executed_by
            .as_ref()
            .unwrap_or(&event.actor_id)
            .clone(),
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

#[cfg(test)]
mod historical_result_tests {
    use serde_json::json;

    use super::*;

    fn fixture() -> (EventAgentSelector, CachedHistoricalAgentSignerKey, [u8; 32]) {
        let intent: arkret_sdk::EventIntent = serde_json::from_value(json!({
            "kind":"ak.message.create",
            "scope_ref":{"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
            "actor_id":{"kind":"account","account_id":{"principal_id":"ak:did_core:web:agent.example","station_id":"ak:did_core:web:station.example"}},
            "created_at":"2026-05-19T00:00:00.000Z",
            "payload":{"strand_id":"ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9","track_name":"discussion","content":{"kind":"ak.content.text","body":"historical"}}
        })).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let mut event = crate::operation::author_intent_for_test(intent).into_event();
        event.actor_kind = Some(arkret_sdk::EnvelopeActorKind::Agent);
        let mut authored = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
        let signer = crate::event_signer::InksonEventSigner::from_dyn_signer(
            std::sync::Arc::new(
                arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner::new(
                    signing_key,
                    "did:web:agent.example#agent-key".to_owned(),
                ),
            ),
            "did:web:agent.example".to_owned(),
        );
        signer.sign_envelope(&mut authored).unwrap();
        let event = authored.into_event();
        let recipient = arkret_sdk::AccountId::new(
            DidCoreId::new("ak:did_core:web:reader.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let selector = EventAgentSelector {
            realm_id: event.realm_id.clone(),
            agent_actor_id: event.actor_id.clone(),
            agent_id: event.actor_id.signing_principal_id().clone(),
            verification_method: DidUrl::new("did:web:agent.example#agent-key").unwrap(),
            event_id: event.event_id.clone(),
            producer_accepted_at: "2026-05-19T00:00:00.000Z".parse().unwrap(),
            producer_signer_resolution_evidence_ref: arkret_sdk::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "a".repeat(64)
            ))
            .unwrap(),
            receiver_id: recipient.station_id.clone(),
            accepted_event: event,
        };
        let entry = CachedHistoricalAgentSignerKey {
            recipient_account_id: recipient,
            realm_id: selector.realm_id.clone(),
            event_id: selector.event_id.clone(),
            receiver_id: selector.receiver_id.clone(),
            accepted_at: selector.producer_accepted_at,
            producer_signer_evidence_ref: selector.producer_signer_resolution_evidence_ref.clone(),
            signer_evidence_ref: arkret_sdk::SignerEvidenceRef::new(format!(
                "ak:signer_evidence:sha256:{}",
                "b".repeat(64)
            ))
            .unwrap(),
            key: arkret_sdk::StationSigningKey {
                actor: selector.agent_actor_id.clone(),
                verification_method: selector.verification_method.clone(),
                public_key_b64u: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
                    &public_key,
                ))
                .unwrap(),
                authorization_ref: selector.event_id.clone(),
            },
            cached_at_unix_ms: 1,
        };
        (selector, entry, public_key)
    }

    #[test]
    fn historical_result_keeps_distinct_frozen_and_original_admission_refs() {
        let (selector, entry, key) = fixture();
        assert_ne!(
            entry.signer_evidence_ref,
            entry.producer_signer_evidence_ref
        );
        assert_eq!(
            historical_key(&entry, &selector, &entry.recipient_account_id),
            Some(key)
        );
        let value = serde_json::to_value(&entry).unwrap();
        assert!(value.get("signer_evidence_dependencies").is_none());
        let decoded: CachedHistoricalAgentSignerKey = serde_json::from_value(value).unwrap();
        assert_eq!(
            historical_key(&decoded, &selector, &entry.recipient_account_id),
            Some(key)
        );
    }

    #[test]
    fn historical_result_isolated_by_full_account_actor_and_admission() {
        let (selector, entry, _) = fixture();
        let mut recipient = entry.recipient_account_id.clone();
        recipient.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(historical_key(&entry, &selector, &recipient).is_none());
        let mut foreign = entry.clone();
        foreign.key.actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            selector.agent_id.clone(),
            recipient.station_id.clone(),
        ));
        assert!(historical_key(&foreign, &selector, &entry.recipient_account_id).is_none());
        foreign = entry.clone();
        foreign.accepted_at += chrono::Duration::seconds(1);
        assert!(historical_key(&foreign, &selector, &entry.recipient_account_id).is_none());
        foreign = entry.clone();
        foreign.receiver_id = recipient.station_id;
        assert!(historical_key(&foreign, &selector, &entry.recipient_account_id).is_none());
        foreign = entry.clone();
        foreign.producer_signer_evidence_ref = entry.signer_evidence_ref.clone();
        assert!(historical_key(&foreign, &selector, &entry.recipient_account_id).is_none());
    }

    #[test]
    fn station_result_does_not_bypass_the_real_event_signature() {
        let (mut selector, _, key) = fixture();
        assert!(verify_event_producer(&selector, &key));
        let wrong = ed25519_dalek::SigningKey::from_bytes(&[41; 32])
            .verifying_key()
            .to_bytes();
        assert!(!verify_event_producer(&selector, &wrong));
        selector.accepted_event.actor_seq += 1;
        assert!(!verify_event_producer(&selector, &key));
    }

    #[test]
    fn delegated_agent_signature_binds_record_actor_and_executing_account() {
        let (mut selector, _, key) = fixture();
        let mut event = selector.accepted_event.clone();
        event.executed_by = Some(event.actor_id.clone());
        event.actor_id = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        event.proofs.clear();
        let mut authored = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_sdk::DigestSuite::Sha256,
        )
        .unwrap();
        let signer = crate::event_signer::InksonEventSigner::from_dyn_signer(
            std::sync::Arc::new(
                arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner::new(
                    ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
                    "did:web:agent.example#agent-key".to_owned(),
                ),
            ),
            "did:web:agent.example".to_owned(),
        );
        signer.sign_envelope(&mut authored).unwrap();
        selector.accepted_event = authored.into_event();
        selector.event_id = selector.accepted_event.event_id.clone();
        let (_, principal, method) =
            event_agent_identity(&serde_json::to_value(&selector.accepted_event).unwrap()).unwrap();
        assert_eq!(principal, selector.agent_id);
        assert_eq!(method, selector.verification_method);
        assert!(verify_event_producer(&selector, &key));
        selector.accepted_event.executed_by =
            Some(arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                selector.agent_id.clone(),
                DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
            )));
        assert!(!verify_event_producer(&selector, &key));
    }
}
