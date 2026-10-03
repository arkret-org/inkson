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
        "operation_id":"ak:operation:sidecar.ensure.fixture",
        "idempotency_key":"sidecar-frozen-fixture",
        "reservation_handle":"sidecar-frozen-reservation",
        "context_attach_event":event
    }))
    .unwrap()
}

fn accepted() -> arkret_sdk::SidecarEnsureOutcome {
    serde_json::from_value(json!({
        "status":"accepted",
        "operation_id":"ak:operation:sidecar.ensure.fixture",
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
