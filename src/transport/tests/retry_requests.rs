use serde_json::json;

use crate::ephemeral::ensure_events_submit_accepted;

#[test]
fn events_batch_response_rejects_partial_acceptance() {
    let accepted: arkret_sdk::EventsSubmitOutcome = serde_json::from_value(json!({
        "status": "accepted",
        "pending_delivery_count": 0,
        "rejections": []
    }))
    .unwrap();
    ensure_events_submit_accepted(&accepted).expect("fully accepted submit should pass");

    // `permission_denied` is a registered reason code: an unregistered token
    // would deserialize into `ReasonCode::Unknown` and the assertions below
    // would pass through that fallback instead of the registry.
    let partial: arkret_sdk::EventsSubmitOutcome = serde_json::from_value(json!({
        "status": "partial",
        "pending_delivery_count": 0,
        "rejections": [
            {
                "id": "ak:event:AXcPfjVv4gB4YXMmxykws6YCG5IZrhBAAzc4-yYUDIY4",
                "reason_code": "permission_denied",
                "detail": "actor is not a member"
            }
        ]
    }))
    .unwrap();
    assert_eq!(
        partial.rejections[0].reason_code,
        arkret_sdk::ReasonCode::PermissionDenied
    );
    let err = ensure_events_submit_accepted(&partial).expect_err("partial submit must fail fast");
    // The diagnostic quotes wire vocabulary, not Rust variant names, so a
    // pasted log line greps against the server's own response.
    assert!(err.to_string().contains("reason_code=permission_denied"));
    assert!(err.to_string().contains("status=partial"));
}
