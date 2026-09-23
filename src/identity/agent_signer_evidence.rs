//! Historical signing keys supplied by the authenticated Account Station.

use std::collections::{BTreeMap, BTreeSet};

use arkret_sdk::signatures::PublicKeyMaterial;
use arkret_sdk::{
    Did, DidCoreId, DidUrl, HistoricalSignerKeyQuerySender, RealmId, SignerKeyQueryResult,
    SignerKeyQuerySelector, SignerKeysQueryRequestBody,
};
use serde_json::Value;

use crate::state::{
    CachedHistoricalAgentSignerKey, HistoricalAgentEventCandidate, LocalStateStore,
};

#[derive(Clone)]
struct EventAgentSelector {
    accepted_event: arkret_sdk::Event,
    realm_id: RealmId,
    agent_actor_id: arkret_sdk::ActorId,
    agent_id: DidCoreId,
    verification_method: DidUrl,
    target_ref: arkret_wire::CommittedEventRef,
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

const MAX_REQUEST_SELECTORS: usize = 64;

fn query_selector(selector: &EventAgentSelector) -> SignerKeyQuerySelector {
    SignerKeyQuerySelector::HistoricalEvent {
        sender: HistoricalSignerKeyQuerySender::Agent {
            actor: selector.agent_actor_id.clone(),
            verification_method: selector.verification_method.clone(),
            committed_event_ref: selector.target_ref.clone(),
        },
    }
}

fn historical_key(
    entry: &CachedHistoricalAgentSignerKey,
    selector: &EventAgentSelector,
    recipient: &arkret_sdk::AccountId,
) -> Option<[u8; 32]> {
    if entry.recipient_account_id != *recipient
        || entry.realm_id != selector.realm_id
        || entry.target_ref != selector.target_ref
        || entry.receiver_id != selector.receiver_id
        || entry.actor != selector.agent_actor_id
        || entry.verification_method != selector.verification_method
        || entry.authorization_ref.stream_ref.realm_id() != &selector.realm_id
        || entry.authorization_ref.stream_position > entry.revision.stream_position
    {
        return None;
    }
    arkret_sdk::base64url_decode(entry.public_key_b64u.as_str().as_bytes())
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
    event.producer_proof.as_ref().is_some_and(|proof| {
        if proof.verification_method != selector.verification_method {
            return false;
        }
        let Ok(proof) = serde_json::to_value(proof) else {
            return false;
        };
        crate::identity::device_directory::verify_proof_value_for_signer_result_with_digest_suite(
            &preimage,
            &proof,
            selector.agent_id.as_str(),
            event.actor_id.signing_principal_id().as_str(),
            &material,
            suite,
        )
        .is_ok()
    })
}

/// Resolve only exact durable candidates. The query is deliberately rebuilt
/// from the committed coordinate stored at the verified carrier boundary; a
/// current projection or a bare Event id can never create transport work.
pub(crate) async fn prefetch_durable_historical_agent_keys(
    http: &arkret_sdk::http_client::Client,
    state_store: &crate::runtime::input::StateStoreHandle,
) -> bool {
    let Some(recipient) = state_store.read(|store| store.active_authority()) else {
        return false;
    };
    let generation = crate::identity::device_directory::cache_epoch();
    let mut pending_by_realm = BTreeMap::<RealmId, Vec<EventAgentSelector>>::new();
    let candidates = state_store.read(LocalStateStore::historical_agent_event_candidates);
    for candidate in candidates {
        if pending_by_realm.values().map(Vec::len).sum::<usize>() >= MAX_REQUEST_SELECTORS {
            break;
        }
        let Some(selector) =
            selector_from_candidate(&candidate, &candidate.accepted_event, &recipient.station_id)
        else {
            continue;
        };
        let already_resolved = state_store.read(|store| {
            store
                .historical_agent_signer_keys(
                    &selector.agent_actor_id,
                    &selector.verification_method,
                )
                .iter()
                .any(|entry| historical_key(entry, &selector, &recipient).is_some())
        });
        if !already_resolved {
            pending_by_realm
                .entry(selector.realm_id.clone())
                .or_default()
                .push(selector);
        }
    }

    let mut changed = false;
    for (realm_id, pending) in pending_by_realm {
        let request = SignerKeysQueryRequestBody {
            request_id: arkret_sdk::RequestId::new_v7_at(crate::clock::now_unix_ms()),
            realm_id,
            recipient_account_id: recipient.clone(),
            queries: pending.iter().map(query_selector).collect(),
        };
        let Ok(outcome) = http.signer_keys_query(&request).await else {
            continue;
        };
        for result in outcome.results {
            let SignerKeyQueryResult::HistoricalResolved {
                selector,
                key,
                accepted_at,
            } = result
            else {
                continue;
            };
            let Some(selected) = pending
                .iter()
                .find(|candidate| query_selector(candidate) == selector)
            else {
                continue;
            };
            let entry = CachedHistoricalAgentSignerKey {
                recipient_account_id: recipient.clone(),
                realm_id: selected.realm_id.clone(),
                target_ref: selected.target_ref.clone(),
                receiver_id: selected.receiver_id.clone(),
                accepted_at,
                actor: selected.agent_actor_id.clone(),
                verification_method: selected.verification_method.clone(),
                public_key_b64u: key.public_key_b64u,
                authorization_ref: key.authorization_ref,
                revision: key.revision,
                governance_generation: key.governance_generation,
                cached_at_unix_ms: crate::clock::now_unix_ms(),
            };
            let Some(public_key) = historical_key(&entry, selected, &recipient) else {
                continue;
            };
            if !verify_event_producer(selected, &public_key) {
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
            changed |= matches!(stored, Ok(true));
        }
    }
    changed
}

/// Index one row only after its carrier has crossed the account-subscribe or
/// per-stream scan verification boundary. The exact coordinate is copied from
/// the row; no projection field, cursor or arrival order participates.
pub(crate) fn index_verified_committed_event(
    store: &mut LocalStateStore,
    realm_id: &RealmId,
    view: &arkret_wire::CommittedEventView,
) -> Result<bool, String> {
    view.validate_shape().map_err(|error| error.to_string())?;
    let commit = view.commit();
    if &commit.realm_id != realm_id || commit.stream_ref.realm_id() != realm_id {
        return Err("historical Agent row belongs to another Realm".to_owned());
    }
    let Some(event) = view.reducer_input() else {
        return Ok(false);
    };
    let Some(recipient) = store.active_authority() else {
        return Ok(false);
    };
    let target_ref = arkret_wire::CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    };
    let Some(selector) =
        selector_from_committed_event(event.clone(), target_ref.clone(), &recipient.station_id)
    else {
        return Ok(false);
    };
    store.index_historical_agent_event_candidate(HistoricalAgentEventCandidate {
        recipient_account_id: recipient,
        realm_id: selector.realm_id,
        target_ref,
        accepted_event: selector.accepted_event,
        agent_actor_id: selector.agent_actor_id,
        agent_id: selector.agent_id,
        verification_method: selector.verification_method,
        receiver_id: selector.receiver_id,
        indexed_at_unix_ms: crate::clock::now_unix_ms(),
    })
}

pub(crate) fn index_verified_committed_events(
    store: &mut LocalStateStore,
    batch: &[garth::ClientEvent],
) -> Result<usize, String> {
    let mut changed = 0;
    for delta in batch.iter().filter_map(|event| match event {
        garth::ClientEvent::Committed(delta) => Some(delta),
        _ => None,
    }) {
        changed += usize::from(index_verified_committed_event(
            store,
            &delta.realm_id,
            &delta.view,
        )?);
    }
    Ok(changed)
}

pub(crate) fn verify_cached_event(
    envelope: &Value,
    store: &LocalStateStore,
    mls_binding: Option<OrdinaryAgentMlsBinding<'_>>,
) -> CachedAgentEventVerdict {
    let Some((event, ..)) = event_agent_identity(envelope) else {
        return CachedAgentEventVerdict::NotAgent;
    };
    let Some(recipient) = store.active_authority() else {
        return CachedAgentEventVerdict::Unresolved;
    };
    let candidates = store.historical_agent_event_candidates_for_event(&event.event_id);
    if candidates.is_empty() {
        return CachedAgentEventVerdict::Unresolved;
    }
    let mut matched = false;
    for candidate in candidates {
        let Some(selector) = selector_from_candidate(&candidate, &event, &recipient.station_id)
        else {
            continue;
        };
        for entry in store
            .historical_agent_signer_keys(&selector.agent_actor_id, &selector.verification_method)
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
                    signer_actor_id: &selector.agent_actor_id,
                    signing_key: &key,
                    agent_key_authorize_event_id: &entry.authorization_ref.event_id,
                };
                if arkret_sdk::mls::verify_ordinary_agent_mls_binding(binding.view, &claim).is_err()
                {
                    continue;
                }
            }
            if verify_event_producer(&selector, &key) {
                return CachedAgentEventVerdict::Verified;
            }
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
    let mut digests = BTreeSet::new();
    for candidate in store.historical_agent_event_candidates_for_event(&event.event_id) {
        let selector = selector_from_candidate(&candidate, event, &recipient.station_id)?;
        for entry in store
            .historical_agent_signer_keys(&selector.agent_actor_id, &selector.verification_method)
        {
            if let Some(key) = historical_key(&entry, &selector, &recipient) {
                let material = PublicKeyMaterial::Ed25519Raw {
                    bytes: key.to_vec(),
                };
                digests.insert(material.raw_ed25519_digest().ok()?);
            }
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
    let frozen_agent_evidence = event.producer_proof.is_some();
    if event.applet_id.is_some() || (event.executed_by.is_none() && !frozen_agent_evidence) {
        return None;
    }
    let agent_id = event
        .executed_by
        .as_ref()
        .unwrap_or(&event.actor_id)
        .signing_principal_id()
        .clone();
    let proof = event.producer_proof.as_ref()?;
    let verification_method = proof
        .verification_method
        .as_str()
        .split_once('#')
        .and_then(|(controller, _)| Did::new(controller.to_owned()).ok())
        .and_then(|did| arkret_sdk::project_did_to_core_id(&did).ok())
        .filter(|controller| controller == &agent_id)
        .map(|_| proof)
        .map(|proof| proof.verification_method.clone())?;
    Some((event, agent_id, verification_method))
}

fn actor_id_from_full(did: &Did) -> Option<DidCoreId> {
    arkret_sdk::project_did_to_core_id(did).ok()
}

fn did_from_method_for_actor(method: &DidUrl, actor_id: &DidCoreId) -> Option<Did> {
    let did = Did::new(method.as_str().split_once('#')?.0.to_owned()).ok()?;
    (actor_id_from_full(&did).as_ref() == Some(actor_id)).then_some(did)
}

fn selector_from_committed_event(
    event: arkret_sdk::Event,
    target_ref: arkret_wire::CommittedEventRef,
    receiver_id: &DidCoreId,
) -> Option<EventAgentSelector> {
    let (event, agent_id, verification_method) =
        event_agent_identity(&serde_json::to_value(event).ok()?)?;
    let realm_id = event.realm_id.clone();
    if target_ref.event_id != event.event_id || target_ref.stream_ref.realm_id() != &realm_id {
        return None;
    }
    let suite = event.event_id.event_digest().digest_suite().ok()?;
    event
        .validate_proof_bindings_with_digest_suite(suite)
        .ok()?;
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
        target_ref,
        receiver_id: receiver_id.clone(),
    })
}

fn selector_from_candidate(
    candidate: &HistoricalAgentEventCandidate,
    event: &arkret_sdk::Event,
    receiver_id: &DidCoreId,
) -> Option<EventAgentSelector> {
    if &candidate.accepted_event != event || &candidate.receiver_id != receiver_id {
        return None;
    }
    let selector =
        selector_from_committed_event(event.clone(), candidate.target_ref.clone(), receiver_id)?;
    (selector.realm_id == candidate.realm_id
        && selector.agent_actor_id == candidate.agent_actor_id
        && selector.agent_id == candidate.agent_id
        && selector.verification_method == candidate.verification_method)
        .then_some(selector)
}

#[cfg(test)]
mod historical_result_tests {
    use serde_json::json;

    use super::*;

    fn committed_ref(
        event_id: arkret_sdk::EventId,
        position: u64,
        seed: u8,
    ) -> arkret_wire::CommittedEventRef {
        arkret_wire::CommittedEventRef {
            event_id,
            commit_id: arkret_sdk::RealmCommitId::from_digest([seed; 32]),
            stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
                )
                .unwrap(),
            },
            stream_position: position,
        }
    }

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
        let event = crate::operation::author_intent_for_test(intent).into_event();
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
        let target_ref = committed_ref(event.event_id.clone(), 7, 7);
        let selector = EventAgentSelector {
            realm_id: event.realm_id.clone(),
            agent_actor_id: event.actor_id.clone(),
            agent_id: event.actor_id.signing_principal_id().clone(),
            verification_method: DidUrl::new("did:web:agent.example#agent-key").unwrap(),
            target_ref,
            receiver_id: recipient.station_id.clone(),
            accepted_event: event,
        };
        let entry = CachedHistoricalAgentSignerKey {
            recipient_account_id: recipient,
            realm_id: selector.realm_id.clone(),
            target_ref: selector.target_ref.clone(),
            receiver_id: selector.receiver_id.clone(),
            accepted_at: selector
                .accepted_event
                .producer_proof
                .as_ref()
                .unwrap()
                .created_at,
            actor: selector.agent_actor_id.clone(),
            verification_method: selector.verification_method.clone(),
            public_key_b64u: arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
                &public_key,
            ))
            .unwrap(),
            authorization_ref: committed_ref(
                arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]),
                3,
                9,
            ),
            revision: arkret_wire::CurrentRevision {
                commit_id: arkret_sdk::RealmCommitId::from_digest([10; 32]),
                stream_position: 11,
            },
            governance_generation: 2,
            cached_at_unix_ms: 1,
        };
        (selector, entry, public_key)
    }

    fn committed_view(selector: &EventAgentSelector) -> arkret_wire::CommittedEventView {
        arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
            event: selector.accepted_event.clone(),
            commit: arkret_wire::RealmCommit {
                commit_id: selector.target_ref.commit_id.clone(),
                realm_id: selector.realm_id.clone(),
                stream_ref: selector.target_ref.stream_ref.clone(),
                stream_position: selector.target_ref.stream_position,
                previous_commit_ref: Some(arkret_sdk::RealmCommitId::from_digest([6; 32])),
                event_ref: selector.target_ref.event_id.clone(),
                governance_generation: 2,
                authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [5; 32]),
                ),
                committed_at: selector
                    .accepted_event
                    .producer_proof
                    .as_ref()
                    .unwrap()
                    .created_at,
                signature: arkret_wire::DetachedObjectSignature {
                    context: arkret_wire::DetachedSignatureContext::RealmCommit,
                    signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                    verification_method: DidUrl::new("did:web:station.example#commit-key").unwrap(),
                    signed_digest: arkret_sdk::Hash::new(format!("sha256:{}", "c".repeat(64)))
                        .unwrap(),
                    created_at: selector
                        .accepted_event
                        .producer_proof
                        .as_ref()
                        .unwrap()
                        .created_at,
                    sig: arkret_sdk::Base64UrlString::new("AA").unwrap(),
                },
            },
        })
    }

    #[test]
    fn historical_result_keeps_original_admission_without_source_provenance() {
        let (selector, entry, key) = fixture();
        assert_ne!(
            entry.target_ref, entry.authorization_ref,
            "historical target and key authorization are independent coordinates"
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
        let mut independently_timed = entry.clone();
        independently_timed.accepted_at += chrono::Duration::seconds(1);
        assert_eq!(
            historical_key(&independently_timed, &selector, &entry.recipient_account_id),
            Some(key),
            "authorization acceptance time is not the producer proof timestamp"
        );
        assert_eq!(
            query_selector(&selector).committed_event_ref(),
            Some(&selector.target_ref)
        );
    }

    #[test]
    fn same_event_id_at_a_different_commit_coordinate_does_not_hit_the_cache() {
        let (mut selector, entry, _) = fixture();
        selector.target_ref.commit_id = arkret_sdk::RealmCommitId::from_digest([42; 32]);
        assert!(historical_key(&entry, &selector, &entry.recipient_account_id).is_none());

        selector = fixture().0;
        selector.target_ref.stream_position += 1;
        assert!(historical_key(&entry, &selector, &entry.recipient_account_id).is_none());
    }

    #[test]
    fn a_bare_event_from_a_current_projection_stays_unresolved() {
        let (selector, ..) = fixture();
        let mut store = crate::state::isolated_store_for_tests("historical-bare-projection");
        store.switch_test_account("did:web:reader.example");
        let envelope = serde_json::to_value(selector.accepted_event).unwrap();
        assert_eq!(
            verify_cached_event(&envelope, &store, None),
            CachedAgentEventVerdict::Unresolved
        );
    }

    #[test]
    fn verified_stream_row_builds_and_persists_the_exact_candidate() {
        let (selector, mut entry, _) = fixture();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("inkson-historical-coordinate-{stamp}.json"));
        let expected_recipient;
        {
            let mut store = LocalStateStore::with_path(path.clone());
            store.switch_test_account("did:web:reader.example");
            expected_recipient = store.active_authority().unwrap();
            entry.recipient_account_id = expected_recipient.clone();
            entry.receiver_id = expected_recipient.station_id.clone();
            assert!(
                index_verified_committed_event(
                    &mut store,
                    &selector.realm_id,
                    &committed_view(&selector),
                )
                .unwrap()
            );
            let candidates = store.historical_agent_event_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].target_ref, selector.target_ref);
            assert!(
                store
                    .store_historical_agent_signer_key(entry.clone())
                    .unwrap()
            );
        }
        let mut reopened = LocalStateStore::with_path(path.clone());
        reopened.switch_test_account("did:web:reader.example");
        assert_eq!(reopened.active_authority(), Some(expected_recipient));
        assert_eq!(
            reopened.historical_agent_event_candidates()[0].target_ref,
            selector.target_ref
        );
        assert_eq!(
            reopened.historical_agent_signer_keys(
                &selector.agent_actor_id,
                &selector.verification_method
            )[0]
            .authorization_ref,
            entry.authorization_ref
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mismatched_commit_event_reference_is_never_indexed() {
        let (selector, ..) = fixture();
        let mut view = committed_view(&selector);
        if let arkret_wire::CommittedEventView::Full(full) = &mut view {
            full.commit.event_ref =
                arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [44; 32]);
        }
        let mut store = crate::state::isolated_store_for_tests("historical-row-mismatch");
        store.switch_test_account("did:web:reader.example");
        assert!(index_verified_committed_event(&mut store, &selector.realm_id, &view).is_err());
        assert!(store.historical_agent_event_candidates().is_empty());
    }

    #[test]
    fn historical_result_isolated_by_full_account_actor_and_admission() {
        let (selector, entry, _) = fixture();
        let mut recipient = entry.recipient_account_id.clone();
        recipient.station_id = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert!(historical_key(&entry, &selector, &recipient).is_none());
        let mut foreign = entry.clone();
        foreign.actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            selector.agent_id.clone(),
            recipient.station_id.clone(),
        ));
        assert!(historical_key(&foreign, &selector, &entry.recipient_account_id).is_none());
        foreign = entry.clone();
        foreign.receiver_id = recipient.station_id;
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
        selector.accepted_event.created_at += chrono::Duration::seconds(1);
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
        event.producer_proof = None;
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
        selector.target_ref.event_id = selector.accepted_event.event_id.clone();
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
