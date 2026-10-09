use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use super::*;

fn attach_request() -> arkret_sdk::SidecarEnsureRequestBody {
    let realm = "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5";
    let sidecar = "ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV";
    let event = signed_chat_event_in_scope(
        "ak.sidecar.context.attach",
        json!({"kind":"sidecar","realm_id":realm,"sidecar_id":sidecar}),
        serde_json::to_value(local_fixture_actor("did:web:alice.example")).unwrap(),
        "2026-07-08T01:44:39.000Z",
        json!({
            "sidecar_id":sidecar,
            "source_context_ref":{"kind":"strand","strand_id":"ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"},
            "version":1
        }),
    );
    serde_json::from_value(json!({
        "phase":"attach",
        "operation_id":"ak:operation:01964137-0000-7000-8000-0000000000a1",
        "idempotency_key":"sidecar-frozen-fixture",
        "reservation_handle":"sidecar-frozen-reservation",
        "context_attach_event":event
    }))
    .unwrap()
}

fn accepted() -> arkret_sdk::SidecarEnsureOutcome {
    serde_json::from_value(json!({
        "status":"accepted",
        "operation_id":"ak:operation:01964137-0000-7000-8000-0000000000a1",
        "accepted_phase":"attach",
        "sidecar_id":"ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV",
        "source_context_ref":{"kind":"strand","strand_id":"ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"},
        "access_readiness":"opening",
        "pending_access_reconciliations":[]
    })).unwrap()
}

fn problem(status: u16, code: &str) -> arkret_sdk::http_client::Error {
    arkret_sdk::http_client::Error::Api {
        status,
        error: Box::new(arkret_sdk::Problem::new(code, status, "fixture")),
    }
}

#[test]
fn sidecar_operation_uses_canonical_id_and_restores_the_exact_reservation_binding() {
    let operation_id = new_native_sidecar_operation_id().unwrap();
    let canonical: arkret_sdk::OperationId = operation_id.as_str().parse().unwrap();
    assert_eq!(canonical.as_str(), operation_id.as_str());
    assert!(
        "ak:operation:sidecar.ensure.01964137-0000-7000-8000-0000000000a1"
            .parse::<arkret_sdk::OperationId>()
            .is_err()
    );

    let mut request = attach_request();
    let arkret_sdk::SidecarEnsureRequestBody::Attach(attach) = &mut request else {
        unreachable!()
    };
    attach.operation_id = operation_id.clone();
    let pending = PendingNativeSidecarCommit {
        operation_id: operation_id.clone(),
        sidecar_id: "ak:sidecar:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV"
            .parse()
            .unwrap(),
        source_context_ref: arkret_sdk::SidecarContextRef::Strand {
            strand_id: "ak:strand:ARbUzETAsZ3suuQ0GSmBWTsNjmUnTEEl_ZnDOUWRPm-N"
                .parse()
                .unwrap(),
        },
        expected_phase: arkret_sdk::SidecarEnsureAcceptedPhase::Attach,
        expires_at: crate::clock::now_utc() + chrono::Duration::minutes(5),
        request,
    };
    let bytes = serde_json::to_vec(&pending).unwrap();
    let restored: PendingNativeSidecarCommit = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
    assert_eq!(restored.request.operation_id(), &operation_id);
    let mut outcome = accepted();
    let arkret_sdk::SidecarEnsureOutcome::Accepted(result) = &mut outcome else {
        unreachable!()
    };
    result.operation_id = operation_id.clone();
    assert_eq!(
        accepted_native_sidecar_id(
            &outcome,
            &restored.operation_id,
            restored.expected_phase,
            &restored.sidecar_id,
            &restored.source_context_ref
        )
        .unwrap(),
        restored.sidecar_id
    );
    assert!(
        accepted_native_sidecar_id(
            &outcome,
            &new_native_sidecar_operation_id().unwrap(),
            restored.expected_phase,
            &restored.sidecar_id,
            &restored.source_context_ref
        )
        .is_err()
    );
}

#[tokio::test]
async fn sidecar_cut_conflict_and_lost_response_replay_the_original_proofs_and_keys() {
    let request = attach_request();
    let expected = serde_json::to_vec(&request).unwrap();
    let calls = RefCell::new(Vec::new());
    let responses = RefCell::new(VecDeque::from([
        Err(problem(503, "temporarily_unavailable")),
        Err(arkret_sdk::http_client::Error::Http(
            "lost accepted response".into(),
        )),
        Ok(accepted()),
    ]));
    let outcome = submit_frozen_sidecar_ensure(
        &request,
        crate::clock::now_utc() + chrono::Duration::minutes(5),
        || Ok(()),
        |request| {
            calls
                .borrow_mut()
                .push(serde_json::to_vec(request).unwrap());
            std::future::ready(responses.borrow_mut().pop_front().unwrap())
        },
    )
    .await
    .unwrap();
    assert_eq!(
        *calls.borrow(),
        vec![expected.clone(), expected.clone(), expected]
    );
    assert_eq!(outcome.operation_id(), request.operation_id());
}

#[tokio::test]
async fn sidecar_replay_stops_on_terminal_problems_and_after_its_bounded_attempts() {
    for (status, code, expected_calls) in [
        (403, "forbidden", 1),
        (409, "failed_precondition", 1),
        (503, "internal_error", 1),
        (503, "temporarily_unavailable", 3),
    ] {
        let request = attach_request();
        let calls = Cell::new(0);
        assert!(
            submit_frozen_sidecar_ensure(
                &request,
                crate::clock::now_utc() + chrono::Duration::minutes(5),
                || Ok(()),
                |_| {
                    calls.set(calls.get() + 1);
                    std::future::ready(Err(problem(status, code)))
                },
            )
            .await
            .is_err()
        );
        assert_eq!(calls.get(), expected_calls);
    }
}

#[tokio::test]
async fn sidecar_replay_stops_before_sending_after_session_replacement_or_expiry() {
    let request = attach_request();
    let active = Cell::new(true);
    let calls = Cell::new(0);
    assert!(
        submit_frozen_sidecar_ensure(
            &request,
            crate::clock::now_utc() + chrono::Duration::minutes(5),
            || {
                anyhow::ensure!(active.get(), "session replaced");
                Ok(())
            },
            |_| {
                calls.set(calls.get() + 1);
                active.set(false);
                std::future::ready(Err(problem(503, "temporarily_unavailable")))
            },
        )
        .await
        .is_err()
    );
    assert_eq!(calls.get(), 1);
    calls.set(0);
    assert!(
        submit_frozen_sidecar_ensure(
            &request,
            crate::clock::now_utc() - chrono::Duration::seconds(1),
            || Ok(()),
            |_| {
                calls.set(calls.get() + 1);
                std::future::ready(Ok(accepted()))
            },
        )
        .await
        .is_err()
    );
    assert_eq!(calls.get(), 0);
}
