use serde_json::json;

use crate::ephemeral::ensure_events_submit_accepted;

#[test]
fn events_batch_response_rejects_partial_acceptance() {
    let accepted: arkret_sdk::EventsSubmitOutcome = serde_json::from_value(json!({
        "status": "accepted",
        "delivery_state": "complete",
        "pending_delivery_count": 0,
        "rejected": []
    }))
    .unwrap();
    ensure_events_submit_accepted(&accepted).expect("fully accepted submit should pass");

    let partial: arkret_sdk::EventsSubmitOutcome = serde_json::from_value(json!({
        "status": "partial",
        "delivery_state": "complete",
        "pending_delivery_count": 0,
        "rejected": [
            {
                "id": "ak:event:AXcPfjVv4gB4YXMmxykws6YCG5IZrhBAAzc4-yYUDIY4",
                "reason_code": "capability_denied",
                "detail": "actor is not a member"
            }
        ]
    }))
    .unwrap();
    let err = ensure_events_submit_accepted(&partial).expect_err("partial submit must fail fast");
    assert!(err.to_string().contains("capability_denied"));
    assert!(err.to_string().contains("status=partial"));
}
