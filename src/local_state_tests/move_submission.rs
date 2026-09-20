//! Move-submission state-machine and submission-record tests.

use super::*;

#[test]
fn move_submission_state_maps_only_station_queue_outcomes() {
    for status in [
        garth::SendQueueStatus::Queued,
        garth::SendQueueStatus::Forwarding,
    ] {
        assert_eq!(
            MoveSubmissionState::from_send_queue_status(status),
            MoveSubmissionState::PendingCommit
        );
    }
    assert_eq!(
        MoveSubmissionState::from_send_queue_status(garth::SendQueueStatus::Committed),
        MoveSubmissionState::Effective
    );
    for status in [
        garth::SendQueueStatus::Rejected,
        garth::SendQueueStatus::Failed,
        garth::SendQueueStatus::Cancelled,
    ] {
        assert_eq!(
            MoveSubmissionState::from_send_queue_status(status),
            MoveSubmissionState::Rejected
        );
    }
}

#[test]
fn move_submission_record_round_trips_through_store() {
    let path = temp_state_path("move-submission");
    let mut store = LocalStateStore::with_path(path.clone());
    let realm = "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-";
    let mid = "sha256:111";
    store.record_move_submission(
        mid,
        realm,
        "ak.consent.grant",
        MoveSubmissionState::PendingCommit,
        None,
        None,
    );
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].move_id, mid);
    assert_eq!(listed[0].state, MoveSubmissionState::PendingCommit);

    // A terminal local rejection survives a restart without becoming an
    // authority-committed success.
    {
        let record = store
            .cached
            .move_submissions
            .get_mut(mid)
            .expect("tracked move");
        record.state = MoveSubmissionState::Rejected;
        record.reason = Some("failed_precondition".to_owned());
    }
    let _ = store.flush();
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].state, MoveSubmissionState::Rejected);
    assert_eq!(listed[0].reason.as_deref(), Some("failed_precondition"));

    // Persistence: a fresh reader sees the same state.
    let reader = LocalStateStore::with_path(path);
    assert!(
        reader.move_submissions_for_realm(realm)[0]
            .state
            .is_failed()
    );

    // Drop it and the banner clears.
    let mut store = LocalStateStore::with_path(reader.path.clone());
    store.ensure_cached_loaded();
    store.cached.move_submissions.remove(mid);
    let _ = store.flush();
    assert!(store.move_submissions_for_realm(realm).is_empty());
}

#[test]
fn move_submission_pending_mls_binding_drives_toast() {
    let path = temp_state_path("move-mls-binding");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL";
    store.record_move_submission(
        "sha256:222",
        realm,
        "ak.message.create",
        MoveSubmissionState::PendingMlsBinding,
        Some("security_frontier missing".to_owned()),
        None,
    );
    assert!(store.realm_has_pending_mls_binding(realm));
    assert_eq!(store.resolve_member_remove_mls_bindings(realm), 0);
    let membership_event = "ak:event:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2";
    let binding_tracking_id = format!("mls-binding:{membership_event}");
    store.record_move_submission(
        binding_tracking_id.clone(),
        realm,
        "mls_member_remove",
        MoveSubmissionState::PendingMlsBinding,
        Some("epoch_update_required".to_owned()),
        None,
    );
    assert_eq!(store.resolve_member_remove_mls_bindings(realm), 1);
    assert!(store.realm_has_pending_mls_binding(realm));
    assert_eq!(
        store
            .move_submissions_for_realm(realm)
            .into_iter()
            .find(|record| record.move_id == binding_tracking_id)
            .map(|record| (record.state, record.reason)),
        Some((MoveSubmissionState::Effective, None))
    );
}

#[test]
fn add_binding_requires_explicit_mls_reconciliation_resolution() {
    let path = temp_state_path("move-mls-add-binding");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ak:realm:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K";
    store.record_move_submission(
        "ak:event:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K",
        realm,
        "mls_member_add",
        MoveSubmissionState::PendingMlsBinding,
        Some("epoch_update_required".to_owned()),
        None,
    );

    assert!(store.realm_has_pending_mls_binding(realm));
    assert_eq!(store.resolve_member_remove_mls_bindings(realm), 0);
    assert!(store.realm_has_pending_mls_binding(realm));
    assert_eq!(store.resolve_member_add_mls_bindings(realm), 1);
    assert!(!store.realm_has_pending_mls_binding(realm));
}

#[test]
fn pending_mls_binding_reason_preserves_add_and_remove_semantics() {
    let path = temp_state_path("move-mls-binding-reason");
    let mut store = LocalStateStore::with_path(path);
    let add_realm = "ak:realm:ARPLNzcjphDMDfIxAfob84mAe2e2BEgCqaFIxa-Shmpy";
    let remove_realm = "ak:realm:ASB4xvdOMgU12-O7GfgFFl2xisYB9bIZ_vTHzro0jXcG";
    let add_reason = "epoch_update_required: membership frontier changed; MLS Add commit required";
    let remove_reason =
        "epoch_update_required: membership frontier changed; MLS Remove commit required";

    store.record_move_submission(
        "ak:event:ARPLNzcjphDMDfIxAfob84mAe2e2BEgCqaFIxa-Shmpy",
        add_realm,
        "mls_member_add",
        MoveSubmissionState::PendingMlsBinding,
        Some(add_reason.to_owned()),
        None,
    );
    store.record_move_submission(
        "ak:event:ASB4xvdOMgU12-O7GfgFFl2xisYB9bIZ_vTHzro0jXcG",
        remove_realm,
        "mls_member_remove",
        MoveSubmissionState::PendingMlsBinding,
        Some(remove_reason.to_owned()),
        None,
    );

    assert_eq!(
        store.realm_pending_mls_binding_reason(add_realm).as_deref(),
        Some(add_reason)
    );
    assert_eq!(
        store
            .realm_pending_mls_binding_reason(remove_realm)
            .as_deref(),
        Some(remove_reason)
    );
}

#[test]
fn move_submission_state_label_and_badge_class_distinct_per_state() {
    for state in [
        MoveSubmissionState::PendingCommit,
        MoveSubmissionState::Effective,
        MoveSubmissionState::Rejected,
        MoveSubmissionState::PendingMlsBinding,
    ] {
        assert!(!state.slug().is_empty());
        assert!(!state.label_zh().is_empty());
        assert!(state.badge_class().starts_with("badge"));
    }
    assert!(!MoveSubmissionState::PendingCommit.is_failed());
    assert!(!MoveSubmissionState::Effective.is_failed());
    assert!(MoveSubmissionState::Rejected.is_failed());
}
