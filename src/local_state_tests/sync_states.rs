//! Authority submit-result ingestion tests.

use super::*;

#[test]
fn submit_result_updates_submission_by_event_id() {
    let path = temp_state_path("move-event-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let local_id = "sha256:local-submit";
    let event_id = "ak:event:AXKJvMpMFIFTD9GYNEzOeImU-2ytvLCtsCq3Mrq9-Ci8";
    store.record_move_submission_with_event_id(
        local_id,
        Some(event_id.to_owned()),
        realm,
        "ak.strand.move",
        MoveSubmissionState::PendingCommit,
        None,
        None,
    );

    let updated = store.apply_move_submission_result(&crate::models::SubmitEventResult::rejected(
        event_id.to_owned(),
        "failed_precondition".to_owned(),
    ));

    assert!(updated);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].move_id, local_id);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::Rejected);
    assert_eq!(listed[0].reason.as_deref(), Some("failed_precondition"));
}

#[test]
fn submit_result_updates_submission_keyed_by_event_id() {
    let path = temp_state_path("move-event-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let event_id = "ak:event:AXYOPItXAzTTu_rqIAINR7C7AvNSR5bjjBslclmJ9ZVt";
    store.record_move_submission(
        event_id,
        realm,
        "ak.message.create",
        MoveSubmissionState::PendingCommit,
        None,
        None,
    );

    let updated = store.apply_move_submission_result(&crate::models::SubmitEventResult::rejected(
        event_id.to_owned(),
        "schema_violation".to_owned(),
    ));

    assert!(updated);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::Rejected);
    assert_eq!(listed[0].reason.as_deref(), Some("schema_violation"));
}
