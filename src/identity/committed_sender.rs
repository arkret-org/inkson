//! Committed sender admission over the host's accepted historical evidence.
//! Presentation and sync consumers use the same proof and MLS sender binding.

use serde_json::Value;

use crate::state::LocalStateStore;
use crate::state::projection::message_ops::{actor_principal_from_value, message_candidates};

/// Receiver-side proof verdict for a committed chat Event
/// (`server-trusted-results.md` §2, fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChatProofVerdict {
    /// Non-persistent system row with no attributed actor. Persistent actor
    /// messages without proofs are rejected before projection.
    Unattributed,
    /// Human-device producer proof is self-consistent, or an Agent producer
    /// verified against its historical signer evidence.
    Verified,
    /// Proof present but not self-consistent, or Agent evidence failed. The
    /// message MUST be dropped (fail-closed).
    Rejected,
    /// Proof is self-consistent but the producer is not a human device and its
    /// Agent signer evidence is not available yet. The message is shown
    /// flagged (`NeedsVerification`) rather than trusted.
    Unresolved,
}

/// Find the proof-bearing Event layer of a committed chat row and check its
/// `producer_proof` without resolving any signing key.
///
/// The row is a committed Event read from this account's own Station, whose
/// stream verification already bound it to the governance `RealmCommit`. The
/// governance Station judged the producer device authorization when it
/// admitted the Event, so the client only checks that the proof is
/// self-consistent (`server-trusted-results.md` §2, `federation.md` §3): the
/// digest covers the exact canonical Event bytes, the verification method
/// projects to the actual signer and a human device fragment is a complete
/// device id. A human-device producer is then [`ChatProofVerdict::Verified`];
/// other producers keep their own evidence rule and stay
/// [`ChatProofVerdict::Unresolved`] here.
pub(crate) fn verify_committed_chat_producer_proof(event: &Value) -> ChatProofVerdict {
    let candidates = message_candidates(event);
    let proof_bearing = candidates.iter().copied().find(|candidate| {
        candidate
            .get("producer_proof")
            .and_then(Value::as_object)
            .is_some()
            && candidate
                .get("actor_id")
                .and_then(actor_principal_from_value)
                .is_some_and(|actor| !actor.trim().is_empty())
    });
    let Some(envelope) = proof_bearing else {
        // An attributed row that ships no proof asserts a sender it cannot
        // back, so it never renders as trusted plaintext. Only a wholly
        // unattributed (system) row is Unattributed.
        let attributed = candidates.iter().copied().any(|candidate| {
            candidate
                .get("actor_id")
                .and_then(actor_principal_from_value)
                .is_some_and(|actor| !actor.trim().is_empty())
        });
        return if attributed {
            ChatProofVerdict::Rejected
        } else {
            ChatProofVerdict::Unattributed
        };
    };
    match committed_human_device_producer(envelope) {
        Ok(Some(_)) => ChatProofVerdict::Verified,
        Ok(None) => ChatProofVerdict::Unresolved,
        Err(()) => ChatProofVerdict::Rejected,
    }
}

/// The human-device producer of one exact committed Event, after the key-free
/// self-consistency check under the Realm's digest suite.
fn committed_human_device_producer(
    envelope: &Value,
) -> Result<Option<arkret_wire::HumanDeviceProducer>, ()> {
    let event = serde_json::from_value::<arkret_sdk::Event>(envelope.clone()).map_err(|_| ())?;
    let digest_suite = event.realm_id.digest_suite_code().digest_suite();
    event
        .verify_producer_proof_self_consistency(digest_suite)
        .map_err(|error| {
            tracing::warn!(event_id = %event.event_id, %error, "committed chat producer proof rejected");
        })
}

/// Realm-aware receiver proof gate. A cached retired minimal-metadata marker
/// is not a valid Realm profile and must not select its old pairwise trust
/// path or silently fall through to ordinary producer verification.
pub(crate) fn verify_chat_envelope_proof_for_realm(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> ChatProofVerdict {
    if let Some(store) = state_store
        && store.realm_projection_has_retired_minimal_metadata_marker(realm_id)
    {
        return ChatProofVerdict::Rejected;
    }
    let candidates = message_candidates(event);
    let proof_verdict = verify_committed_chat_producer_proof(event);
    if proof_verdict != ChatProofVerdict::Unresolved {
        return proof_verdict;
    }
    // Historical Agent evidence is indexed at the verified committed carrier
    // boundary. An unsigned projection marker is neither required nor trusted.
    if let Some(envelope) = candidates.iter().copied().find(|candidate| {
        candidate
            .get("producer_proof")
            .and_then(Value::as_object)
            .is_some()
            && candidate
                .get("actor_id")
                .and_then(actor_principal_from_value)
                .is_some()
    }) {
        let Some(store) = state_store else {
            return ChatProofVerdict::Unresolved;
        };
        let coordinates = encrypted_content_coordinates(realm_id, &candidates);
        let mls_view = if let Some((group_id, epoch, group_state_ref)) = &coordinates {
            let Some((authority, _, self_device)) = decrypt_identity else {
                return ChatProofVerdict::Unresolved;
            };
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            let Some(scope) = candidates
                .iter()
                .find_map(|candidate| {
                    candidate
                        .get("scope_ref")
                        .or_else(|| candidate.get("effective_scope"))
                })
                .and_then(|value| {
                    serde_json::from_value::<arkret_sdk::ScopeRef>(value.clone()).ok()
                })
                .filter(|scope| {
                    scope
                        .realm_id_opt()
                        .is_some_and(|realm| realm.as_str() == realm_id)
                })
            else {
                return ChatProofVerdict::Unresolved;
            };
            let Some(view) = crate::mls::runtime::ordinary_agent_mls_author_view_for_scope(
                store,
                secure_store.as_ref(),
                authority,
                self_device,
                &scope,
                group_id,
                *epoch,
                group_state_ref,
            ) else {
                return ChatProofVerdict::Unresolved;
            };
            Some(view)
        } else {
            None
        };
        let mls_binding = coordinates
            .as_ref()
            .and_then(|(group_id, epoch, group_state_ref)| {
                mls_view.as_ref().map(|view| {
                    crate::identity::agent_signer_evidence::OrdinaryAgentMlsBinding {
                        view,
                        group_id,
                        epoch: *epoch,
                        group_state_ref,
                    }
                })
            });
        return match crate::identity::agent_signer_evidence::verify_cached_event(
            envelope,
            store,
            mls_binding,
        ) {
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Verified => {
                ChatProofVerdict::Verified
            }
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Rejected => {
                ChatProofVerdict::Rejected
            }
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::Unresolved => {
                ChatProofVerdict::Unresolved
            }
            crate::identity::agent_signer_evidence::CachedAgentEventVerdict::NotAgent => {
                ChatProofVerdict::Unresolved
            }
        };
    }
    proof_verdict
}

pub(crate) fn verified_chat_sender_domain_for_realm(
    realm_id: &str,
    event: &Value,
    state_store: Option<&LocalStateStore>,
    decrypt_identity: Option<(&arkret_sdk::AccountId, &str, &arkret_sdk::DeviceId)>,
) -> Option<Vec<u8>> {
    if verify_chat_envelope_proof_for_realm(realm_id, event, state_store, decrypt_identity)
        != ChatProofVerdict::Verified
    {
        return None;
    }
    chat_sender_domain_from_verified_event(event)
}

pub(crate) fn chat_sender_domain_from_verified_event(event: &Value) -> Option<Vec<u8>> {
    // Standard content AAD uses the sender leaf's canonical ActorId
    // credential, preserving its Station. The device remains a proof selector
    // and must not replace the credential identity.
    let envelope = message_candidates(event).into_iter().find(|candidate| {
        candidate
            .get("producer_proof")
            .and_then(Value::as_object)
            .is_some()
    })?;
    let signed_event: arkret_sdk::Event = serde_json::from_value(envelope.clone()).ok()?;
    arkret_sdk::mls_basic_credential_identity(signed_event.actual_signer()).ok()
}

/// Reconstruct the encrypted-content group coordinates used by ordinary
/// Agent proof admission.
fn encrypted_content_coordinates(
    realm_id: &str,
    candidates: &[&Value],
) -> Option<(String, u64, String)> {
    let content = candidates.iter().find_map(|candidate| {
        candidate.get("encrypted_content").or_else(|| {
            candidate
                .get("content")
                .and_then(|content| content.get("encrypted_content"))
        })
    })?;
    let envelope = serde_json::from_value::<arkret_sdk::EncryptedEnvelope>(content.clone()).ok()?;
    let effective_scope = candidates
        .iter()
        .find_map(|candidate| {
            candidate
                .get("scope_ref")
                .or_else(|| candidate.get("effective_scope"))
        })
        .and_then(|value| serde_json::from_value::<arkret_sdk::ScopeRef>(value.clone()).ok())?;
    if effective_scope
        .realm_id_opt()
        .is_none_or(|realm| realm.as_str() != realm_id)
    {
        return None;
    }
    Some((
        effective_scope
            .canonical_mls_group_id()
            .ok()?
            .as_str()
            .to_owned(),
        envelope.encryption_context.epoch(),
        envelope
            .encryption_context
            .group_state_ref()
            .as_str()
            .to_owned(),
    ))
}
