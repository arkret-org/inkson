use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use arkret_sdk::contact_operations::*;
use serde_json::json;

use super::*;

fn local_signer() -> crate::event_signer::InksonEventSigner {
    crate::event_signer::build_ed25519_device_signer(
        [17; 32],
        "did:web:alice.example",
        "ak:device:01964137-0000-7000-8000-0000000000a1",
    )
}

pub(super) fn event(kind: &str) -> arkret_sdk::Event {
    let actor = crate::test_support::account_actor("did:web:alice.example");
    let peer = ContactPeer::Human {
        account_id: crate::test_support::authority("did:web:bob.example"),
    };
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id":"ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind":kind,"realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref":{"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
        "actor_id":actor,"created_at":"2026-09-12T12:00:00.000Z",
        "payload":{"peer":peer}
    })).unwrap();
    let mut event = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    local_signer()
        .sign_sdk_event_with_context(
            &mut event,
            crate::event_signer::ProducerProofContext::for_native_unit(
                arkret_sdk::DigestSuite::Sha256,
            ),
        )
        .unwrap();
    event.into_event()
}

fn direct_producer(
    event: &arkret_sdk::Event,
    signer: &crate::event_signer::InksonEventSigner,
) -> ContactProducerSigner {
    let (method, key) = local_contact_producer(event, signer).unwrap();
    ContactProducerSigner::direct(method, key).unwrap()
}

fn peer_request() -> (arkret_sdk::Event, ContactProducerSigner) {
    let signer = crate::event_signer::build_ed25519_device_signer(
        [18; 32],
        "did:web:bob.example",
        "ak:device:01964137-0000-7000-8000-0000000000b1",
    );
    let mut request = event(arkret_wire::event_kind_str::CONTACT_REQUESTED);
    request.actor_id = crate::test_support::account_actor("did:web:bob.example");
    request.payload.insert(
        "peer".into(),
        serde_json::to_value(ContactPeer::Human {
            account_id: crate::test_support::authority("did:web:alice.example"),
        })
        .unwrap(),
    );
    request.producer_proof = None;
    let mut authored = arkret_sdk::AuthoredEvent::finalize_with_digest_suite(
        request,
        arkret_sdk::DigestSuite::Sha256,
    )
    .unwrap();
    signer
        .sign_sdk_event_with_context(
            &mut authored,
            crate::event_signer::ProducerProofContext::for_native_unit(
                arkret_sdk::DigestSuite::Sha256,
            ),
        )
        .unwrap();
    let event = authored.into_event();
    let producer = direct_producer(&event, &signer);
    (event, producer)
}

pub(super) fn operation_id() -> ProtocolOperationId {
    ProtocolOperationId::new("ak:operation:contact.request.fixture").unwrap()
}

// Source signatures remain structural placeholders: these tests exercise an
// authenticated own-Station response, not remote Station/DID authentication.
fn signature() -> arkret_sdk::ProtocolSignature {
    serde_json::from_value(
        json!({"verification_method":"did:web:principal.example#key",
        "created_at":"2026-09-12T12:00:00.000Z","jws":"eyJhbGciOiJFZERTQSJ9..c2ln"}),
    )
    .unwrap()
}

fn accepted(event: &arkret_sdk::Event) -> ContactOperationOutcome {
    let peer: ContactPeer = serde_json::from_value(event.payload["peer"].clone()).unwrap();
    let holder = ContactPeer::Human {
        account_id: event.actor_id.as_account_id().unwrap().clone(),
    };
    let digest = arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
    let incoming = peer_request();
    let is_request = event.kind.as_str() == arkret_wire::event_kind_str::CONTACT_REQUESTED;
    let request = RequestAcceptanceReceipt {
        core: RequestAcceptanceReceiptCore {
            holder: if is_request {
                holder.clone()
            } else {
                peer.clone()
            },
            peer: if is_request {
                peer.clone()
            } else {
                holder.clone()
            },
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: if event.kind.as_str()
                == arkret_wire::event_kind_str::CONTACT_REQUESTED
            {
                event.event_id.clone()
            } else {
                incoming.0.event_id.clone()
            },
            producer_signer: if is_request {
                direct_producer(event, &local_signer())
            } else {
                incoming.1.clone()
            },
            source_checkpoint: digest.clone(),
            accepted_at: signature().created_at,
            issuer_id: event.actor_id.as_account_id().unwrap().station_id.clone(),
        },
        receipt_digest: digest.clone(),
        signature: signature(),
    };
    let lineage = ContactLineage {
        contact_round_id: digest.clone(),
        issuer: holder,
        peer: peer.clone(),
        version: 2,
        predecessor_event_ref: None,
        event_ref: event.event_id.clone(),
        producer_signer: direct_producer(event, &local_signer()),
        granted_to_peer_scopes: vec![ContactScope::DirectMessage],
        terminal: None,
        signature: signature(),
    };
    let current_proof = ContactCurrentProof {
        contact_round_id: digest.clone(),
        issuer_id: request.core.issuer_id.clone(),
        peer,
        terminal: false,
        head_event_ref: event.event_id.clone(),
        accepted_commit_event_ids: vec![event.event_id.clone()],
        complete_through: 2,
        fresh_until: signature().created_at,
        signature: signature(),
    };
    let operation_id = operation_id();
    let outcome = match event.kind.as_str() {
        arkret_wire::event_kind_str::CONTACT_REQUESTED => ContactAcceptedOutcome::Request {
            operation_id,
            request_acceptance_receipt: request,
        },
        arkret_wire::event_kind_str::CONTACT_ACCEPTED => ContactAcceptedOutcome::Response {
            operation_id,
            normal_response_acceptance_receipt: NormalResponseAcceptanceReceipt {
                contact_round_id: digest.clone(),
                request_receipt: request,
                response_event_ref: event.event_id.clone(),
                producer_signer: direct_producer(event, &local_signer()),
                outgoing_slot_absence_digest: digest,
                accepted_at: signature().created_at,
                issuer_id: current_proof.issuer_id.clone(),
                signature: signature(),
            },
            lineage,
            current_proof,
        },
        arkret_wire::event_kind_str::CONTACT_REJECTED => ContactAcceptedOutcome::Reject {
            operation_id,
            reject_acceptance_receipt: RejectAcceptanceReceipt {
                request_receipt: request,
                reject_event_ref: event.event_id.clone(),
                producer_signer: direct_producer(event, &local_signer()),
                accepted_at: signature().created_at,
                issuer_id: current_proof.issuer_id,
                signature: signature(),
            },
        },
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE => ContactAcceptedOutcome::ScopeUpdate {
            operation_id,
            lineage,
            current_proof,
        },
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE => ContactAcceptedOutcome::Tombstone {
            operation_id,
            lineage,
            current_proof,
        },
        _ => unreachable!(),
    };
    ContactOperationOutcome::Accepted { outcome }
}

fn problem(status: u16, code: &str) -> arkret_sdk::http_client::Error {
    arkret_sdk::http_client::Error::Api {
        status,
        error: Box::new(arkret_sdk::Problem::new(code, status, "fixture")),
    }
}

#[tokio::test]
async fn all_five_contacts_retry_only_the_exact_commit() {
    for kind in [
        arkret_wire::event_kind_str::CONTACT_REQUESTED,
        arkret_wire::event_kind_str::CONTACT_ACCEPTED,
        arkret_wire::event_kind_str::CONTACT_REJECTED,
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
    ] {
        let event = event(kind);
        let calls = RefCell::new(Vec::new());
        let responses = RefCell::new(VecDeque::from([
            Err(problem(503, "temporarily_unavailable")),
            Ok(accepted(&event)),
        ]));
        drive_contact_commit(
            || Ok(()),
            || {
                calls.borrow_mut().push("same_commit");
                std::future::ready(responses.borrow_mut().pop_front().unwrap())
            },
            |outcome| {
                validate_contact_commit_outcome(outcome, &event, &operation_id(), &local_signer())
            },
        )
        .await
        .unwrap();
        assert_eq!(*calls.borrow(), ["same_commit", "same_commit"]);
    }
}

#[tokio::test]
async fn terminal_success_failure_and_permission_denial_are_not_retried() {
    let event = event(arkret_wire::event_kind_str::CONTACT_REQUESTED);
    let failed = ContactOperationOutcome::Failed {
        outcome: ContactFailedOutcome {
            operation_id: operation_id(),
            result_kind: ContactResultKind::Request,
            reason: ContactOperationRejectReason::ContactTerminal,
        },
    };
    for response in [
        Ok(accepted(&event)),
        Ok(failed),
        Err(problem(403, "forbidden")),
        Err(problem(409, "failed_precondition")),
    ] {
        let response = RefCell::new(Some(response));
        let _ = drive_contact_commit(
            || Ok(()),
            || std::future::ready(response.borrow_mut().take().unwrap()),
            |outcome| {
                validate_contact_commit_outcome(outcome, &event, &operation_id(), &local_signer())
            },
        )
        .await;
    }
}

#[tokio::test]
async fn lost_commit_response_retries_original_and_session_switch_aborts() {
    let responses = RefCell::new(VecDeque::from([
        Err(arkret_sdk::http_client::Error::Http("lost response".into())),
        Err(problem(503, "temporarily_unavailable")),
    ]));
    let submits = Cell::new(0);
    assert!(
        drive_contact_commit(
            || Ok(()),
            || {
                submits.set(submits.get() + 1);
                std::future::ready(responses.borrow_mut().pop_front().unwrap())
            },
            |_| Ok(()),
        )
        .await
        .is_err()
    );
    assert_eq!(submits.get(), 2);
    let active = Cell::new(true);
    assert!(
        drive_contact_commit(
            || {
                anyhow::ensure!(active.get(), "session replaced");
                Ok(())
            },
            || {
                active.set(false);
                std::future::ready(Err(problem(503, "temporarily_unavailable")))
            },
            |_| Ok(())
        )
        .await
        .is_err()
    );
}

#[test]
fn exact_branch_operation_and_event_are_required_but_later_current_head_is_valid() {
    let event = event(arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE);
    let mut outcome = accepted(&event);
    let other = self::event(arkret_wire::event_kind_str::CONTACT_TOMBSTONE);
    if let ContactOperationOutcome::Accepted {
        outcome: ContactAcceptedOutcome::ScopeUpdate { current_proof, .. },
    } = &mut outcome
    {
        current_proof.head_event_ref = other.event_id.clone();
        current_proof.complete_through = 3;
    }
    validate_contact_commit_outcome(&outcome, &event, &operation_id(), &local_signer()).unwrap();
    assert!(
        validate_contact_commit_outcome(&outcome, &other, &operation_id(), &local_signer())
            .is_err()
    );
    assert!(
        validate_contact_commit_outcome(
            &outcome,
            &event,
            &ProtocolOperationId::new("ak:operation:other").unwrap(),
            &local_signer()
        )
        .is_err()
    );
    if let ContactOperationOutcome::Accepted {
        outcome: ContactAcceptedOutcome::ScopeUpdate { lineage, .. },
    } = &mut outcome
    {
        lineage.event_ref = other.event_id;
    }
    assert!(
        validate_contact_commit_outcome(&outcome, &event, &operation_id(), &local_signer())
            .is_err()
    );
}

#[test]
fn every_contact_result_binds_original_producer_method_and_local_key() {
    for kind in [
        arkret_wire::event_kind_str::CONTACT_REQUESTED,
        arkret_wire::event_kind_str::CONTACT_ACCEPTED,
        arkret_wire::event_kind_str::CONTACT_REJECTED,
        arkret_wire::event_kind_str::CONTACT_SCOPE_UPDATE,
        arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
    ] {
        let event = event(kind);
        let result = accepted(&event);
        validate_contact_commit_outcome(&result, &event, &operation_id(), &local_signer()).unwrap();
        let other_key = crate::event_signer::build_ed25519_device_signer(
            [18; 32],
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-0000000000a1",
        );
        assert!(
            validate_contact_commit_outcome(&result, &event, &operation_id(), &other_key).is_err()
        );
        for method_mutation in [false, true] {
            let count = if kind == arkret_wire::event_kind_str::CONTACT_ACCEPTED {
                2
            } else {
                1
            };
            for index in 0..count {
                let mut changed = result.clone();
                let ContactOperationOutcome::Accepted { outcome } = &mut changed else {
                    unreachable!()
                };
                let descriptor = match outcome {
                    ContactAcceptedOutcome::Request {
                        request_acceptance_receipt,
                        ..
                    } => &mut request_acceptance_receipt.core.producer_signer,
                    ContactAcceptedOutcome::Response {
                        normal_response_acceptance_receipt,
                        lineage,
                        ..
                    } => {
                        if index == 0 {
                            &mut normal_response_acceptance_receipt.producer_signer
                        } else {
                            &mut lineage.producer_signer
                        }
                    }
                    ContactAcceptedOutcome::Reject {
                        reject_acceptance_receipt,
                        ..
                    } => &mut reject_acceptance_receipt.producer_signer,
                    ContactAcceptedOutcome::ScopeUpdate { lineage, .. }
                    | ContactAcceptedOutcome::Tombstone { lineage, .. } => {
                        &mut lineage.producer_signer
                    }
                };
                *descriptor = ContactProducerSigner::direct(
                    if method_mutation {
                        arkret_sdk::DidUrl::new("did:web:alice.example#other-device").unwrap()
                    } else {
                        descriptor.verification_method().clone()
                    },
                    if method_mutation {
                        descriptor.public_key_b64u().clone()
                    } else {
                        arkret_sdk::Base64UrlString::new(other_key.public_key_base64url().unwrap())
                            .unwrap()
                    },
                )
                .unwrap();
                assert!(
                    validate_contact_commit_outcome(
                        &changed,
                        &event,
                        &operation_id(),
                        &local_signer()
                    )
                    .is_err(),
                    "{kind} descriptor {index} must bind the original producer"
                );
            }
        }
        let mut no_proof = event.clone();
        no_proof.producer_proof = None;
        assert!(
            validate_contact_commit_outcome(&result, &no_proof, &operation_id(), &local_signer())
                .is_err()
        );
    }
}

#[test]
fn nested_peer_request_keeps_its_own_producer_and_original_event_signature_is_real() {
    use arkret_sdk::signatures::proof::{
        Ed25519DetachedJwsVerifier, EventVerifier, PublicKeyMaterial,
    };
    use base64::Engine;

    let event = event(arkret_wire::event_kind_str::CONTACT_ACCEPTED);
    let descriptor = direct_producer(&event, &local_signer());
    let proof = event.producer_proof.as_ref().expect("producer proof");
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(proof.jws.split('.').nth(2).unwrap())
        .unwrap();
    Ed25519DetachedJwsVerifier::new()
        .verify(
            &proof.canonical_binding_bytes(&event.actor_id).unwrap(),
            &signature,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: descriptor.public_key_bytes().unwrap().to_vec(),
            },
        )
        .expect("the fixture original Event is signed by the bound local device");
    let mut result = accepted(&event);
    if let ContactOperationOutcome::Accepted {
        outcome:
            ContactAcceptedOutcome::Response {
                normal_response_acceptance_receipt,
                ..
            },
    } = &mut result
    {
        let producer = &mut normal_response_acceptance_receipt
            .request_receipt
            .core
            .producer_signer;
        *producer = ContactProducerSigner::direct(
            arkret_sdk::DidUrl::new("did:web:bob.example#peer-device").unwrap(),
            producer.public_key_b64u().clone(),
        )
        .unwrap();
    }
    validate_contact_commit_outcome(&result, &event, &operation_id(), &local_signer()).unwrap();
    if let ContactOperationOutcome::Accepted {
        outcome:
            ContactAcceptedOutcome::Response {
                normal_response_acceptance_receipt,
                ..
            },
    } = &mut result
    {
        normal_response_acceptance_receipt
            .request_receipt
            .core
            .request_event_ref = event.event_id.clone();
    }
    assert!(
        validate_contact_commit_outcome(&result, &event, &operation_id(), &local_signer()).is_err(),
        "any descriptor claiming the exact local Event must agree, even when nested"
    );
}

#[test]
fn session_fence_survives_device_refresh_but_rejects_session_account_or_signer_replacement() {
    let account = crate::test_support::authority("did:web:alice.example");
    let device =
        arkret_sdk::DeviceId::new("ak:device:01964137-0000-7000-8000-0000000000a1").unwrap();
    let _scope =
        crate::secure_key_store::DeviceSeedScopeTestGuard::replace(Some((&account, &device)));
    let signer = std::sync::Arc::new(crate::event_signer::build_ed25519_device_signer(
        [21; 32],
        "did:web:alice.example",
        device.as_str(),
    ));
    let _signer = crate::event_signer::ActiveSignerTestGuard::replace(Some(signer.clone()));
    let fence = AuthoringSessionFence::capture().unwrap();
    fence.check().unwrap();
    crate::identity::device_directory::fence_device_refresh();
    fence.check().unwrap();
    crate::identity::device_directory::reset_session_cache();
    assert!(
        fence.check().is_err(),
        "the same signer cannot cross a replaced session"
    );
    let fence = AuthoringSessionFence::capture().unwrap();
    fence.check().unwrap();
    fence.check_session_identity().unwrap();
    let other = crate::test_support::authority_at_station(
        "did:web:alice.example",
        "did:web:another.example",
    );
    crate::secure_key_store::set_active_device_seed_scope(Some((&other, &device)));
    assert!(fence.check().is_err());
    assert!(fence.check_session_identity().is_err());
    crate::secure_key_store::set_active_device_seed_scope(Some((&account, &device)));
    crate::event_signer::replace_active_signer(Some(std::sync::Arc::new(
        crate::event_signer::build_ed25519_device_signer(
            [22; 32],
            "did:web:alice.example",
            device.as_str(),
        ),
    )));
    assert!(fence.check().is_err());
    assert!(fence.check_session_identity().is_err());
}
