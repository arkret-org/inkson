use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use arkret_sdk::contact_operations::*;
use serde_json::json;

use super::*;

pub(super) fn event(kind: &str) -> arkret_sdk::Event {
    let actor = crate::test_support::account_actor("did:web:alice.example");
    let peer = ContactPeer::Human {
        account_id: crate::test_support::authority("did:web:bob.example"),
    };
    let event: arkret_sdk::Event = serde_json::from_value(json!({
        "event_id":"ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "kind":kind,"realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
        "scope_ref":{"kind":"realm","realm_id":"ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"},
        "actor_id":actor,"actor_seq":1,"created_at":"2026-09-12T12:00:00.000Z",
        "prev_refs":[],"payload":{"peer":peer},"proofs":[]
    })).unwrap();
    arkret_sdk::AuthoredEvent::finalize_with_digest_suite(event, arkret_sdk::DigestSuite::Sha256)
        .unwrap()
        .into_event()
}

pub(super) fn operation_id() -> ProtocolOperationId {
    ProtocolOperationId::new("ak:operation:contact.request.fixture").unwrap()
}

fn signature() -> arkret_sdk::ProtocolSignature {
    serde_json::from_value(
        json!({"verification_method":"did:web:principal.example#key",
        "created_at":"2026-09-12T12:00:00.000Z","jws":"AA"}),
    )
    .unwrap()
}

fn accepted(event: &arkret_sdk::Event) -> ContactOperationOutcome {
    let peer: ContactPeer = serde_json::from_value(event.payload["peer"].clone()).unwrap();
    let holder = ContactPeer::Human {
        account_id: event.actor_id.as_account_id().unwrap().clone(),
    };
    let digest = arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
    let request = RequestAcceptanceReceipt {
        core: RequestAcceptanceReceiptCore {
            holder: holder.clone(),
            peer: peer.clone(),
            slot_version: 1,
            slot_predecessor: None,
            previous_terminal_contact_round_id: None,
            request_event_ref: event.event_id.clone(),
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
        accepted_frontier: vec![event.event_id.clone()],
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
async fn all_five_contacts_confirm_pending_before_exact_retry() {
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
            || async {
                calls.borrow_mut().push("exact_seal");
                Ok(())
            },
            |outcome| validate_contact_commit_outcome(outcome, &event, &operation_id()),
        )
        .await
        .unwrap();
        assert_eq!(
            *calls.borrow(),
            ["same_commit", "exact_seal", "same_commit"]
        );
    }
}

#[tokio::test]
async fn terminal_success_failure_and_permission_denial_never_prepare_seal() {
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
        let confirms = Cell::new(0);
        let _ = drive_contact_commit(
            || Ok(()),
            || std::future::ready(response.borrow_mut().take().unwrap()),
            || async {
                confirms.set(confirms.get() + 1);
                Ok(())
            },
            |outcome| validate_contact_commit_outcome(outcome, &event, &operation_id()),
        )
        .await;
        assert_eq!(confirms.get(), 0);
    }
}

#[tokio::test]
async fn lost_commit_response_retries_original_before_seal_and_session_switch_aborts() {
    let event = event(arkret_wire::event_kind_str::CONTACT_REQUESTED);
    let responses = RefCell::new(VecDeque::from([
        Err(arkret_sdk::http_client::Error::Http("lost response".into())),
        Err(problem(503, "temporarily_unavailable")),
        Ok(accepted(&event)),
    ]));
    let submits = Cell::new(0);
    let confirms = Cell::new(0);
    drive_contact_commit(
        || Ok(()),
        || {
            submits.set(submits.get() + 1);
            std::future::ready(responses.borrow_mut().pop_front().unwrap())
        },
        || async {
            confirms.set(confirms.get() + 1);
            Ok(())
        },
        |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!((submits.get(), confirms.get()), (3, 1));
    let active = Cell::new(true);
    let confirms = Cell::new(0);
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
            || async {
                confirms.set(confirms.get() + 1);
                Ok(())
            },
            |_| Ok(())
        )
        .await
        .is_err()
    );
    assert_eq!(confirms.get(), 0);
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
    validate_contact_commit_outcome(&outcome, &event, &operation_id()).unwrap();
    assert!(validate_contact_commit_outcome(&outcome, &other, &operation_id()).is_err());
    assert!(
        validate_contact_commit_outcome(
            &outcome,
            &event,
            &ProtocolOperationId::new("ak:operation:other").unwrap()
        )
        .is_err()
    );
    if let ContactOperationOutcome::Accepted {
        outcome: ContactAcceptedOutcome::ScopeUpdate { lineage, .. },
    } = &mut outcome
    {
        lineage.event_ref = other.event_id;
    }
    assert!(validate_contact_commit_outcome(&outcome, &event, &operation_id()).is_err());
}

#[test]
fn session_fence_rejects_same_principal_account_switch_and_signer_replacement() {
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
    let fence = ContactSessionFence::capture().unwrap();
    fence.check().unwrap();
    let other = crate::test_support::authority_at_station(
        "did:web:alice.example",
        "did:web:another.example",
    );
    crate::secure_key_store::set_active_device_seed_scope(Some((&other, &device)));
    assert!(fence.check().is_err());
    crate::secure_key_store::set_active_device_seed_scope(Some((&account, &device)));
    crate::event_signer::replace_active_signer(Some(std::sync::Arc::new(
        crate::event_signer::build_ed25519_device_signer(
            [22; 32],
            "did:web:alice.example",
            device.as_str(),
        ),
    )));
    assert!(fence.check().is_err());
}
