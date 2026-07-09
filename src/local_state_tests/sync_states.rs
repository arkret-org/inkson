//! Sync event-state ingestion tests (server `event_states` → submission state).

use super::*;

#[test]
fn sync_event_states_update_submission_by_event_id() {
    let path = temp_state_path("move-event-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000001";
    let local_id = "sha256:local-submit";
    let event_id = "ak:event:0196419b-0000-7000-8000-0000000000aa";
    store.record_move_submission_with_event_id(
        local_id,
        Some(event_id.to_owned()),
        realm,
        "ak.strand.move",
        MoveSubmissionState::PendingSeal,
        None,
        Some("ak:seal:sha256:abc".to_owned()),
    );

    let updated = store.ingest_move_event_states(
        realm,
        &serde_json::json!({
            "event_states": [{
                "event_id": event_id,
                "event_state": "effective"
            }]
        }),
    );

    assert_eq!(updated, 1);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].move_id, local_id);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::Effective);
}

#[test]
fn sync_event_states_update_submission_keyed_by_event_id() {
    let path = temp_state_path("move-event-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000001";
    let event_id = "ak:event:0196419b-0000-7000-8000-0000000000bb";
    store.record_move_submission(
        event_id,
        realm,
        "mls_member_remove",
        MoveSubmissionState::PendingMlsBinding,
        None,
        None,
    );

    let updated = store.ingest_move_event_states(
        realm,
        &serde_json::json!({
            "event_states": [{
                "event_id": event_id,
                "event_state": "failed_bottom",
                "event_state_reason_code": "cell_in_bottom_state"
            }]
        }),
    );

    assert_eq!(updated, 1);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::FailedBottom);
    assert_eq!(listed[0].reason.as_deref(), Some("cell_in_bottom_state"));
}

#[test]
fn sync_event_states_update_submission_when_event_and_move_ids_are_present() {
    let path = temp_state_path("move-event-and-move-id-state");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:0196419b-0000-7000-8000-000000000001";
    let move_id = "sha256:local-submit-with-server-event";
    let event_id = "ak:event:0196419b-0000-7000-8000-0000000000cc";
    store.record_move_submission(
        move_id,
        realm,
        "ak.strand.move",
        MoveSubmissionState::PendingSeal,
        None,
        None,
    );

    let updated = store.ingest_move_event_states(
        realm,
        &serde_json::json!({
            "event_states": [{
                "event_id": event_id,
                "move_id": move_id,
                "event_state": "effective"
            }]
        }),
    );

    assert_eq!(updated, 1);
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].move_id, move_id);
    assert_eq!(listed[0].event_id.as_deref(), Some(event_id));
    assert_eq!(listed[0].state, MoveSubmissionState::Effective);
}
