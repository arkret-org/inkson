//! Move-submission state-machine and submission-record tests.

use super::*;

#[test]
fn move_submission_state_maps_pending_seal_and_effective() {
    assert_eq!(
        MoveSubmissionState::from_submit_state("pending", None),
        MoveSubmissionState::PendingSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("pending_seal", None),
        MoveSubmissionState::PendingSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("accepted", None),
        MoveSubmissionState::PendingSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("effective", None),
        MoveSubmissionState::Effective
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("sealed", None),
        MoveSubmissionState::Effective
    );
}

#[test]
fn move_submission_state_maps_failure_reasons() {
    assert_eq!(
        MoveSubmissionState::from_submit_state(
            "rejected",
            Some("notary_paused: recovery notary not signed")
        ),
        MoveSubmissionState::NotaryPaused
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state(
            "rejected",
            Some("seal_signature_invalid for batch")
        ),
        MoveSubmissionState::RejectedSeal
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state(
            "rejected",
            Some("bottom: cell has concurrent candidates")
        ),
        MoveSubmissionState::FailedBottom
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("rejected", Some("covered_seals mismatch")),
        MoveSubmissionState::PendingMlsBinding
    );
    assert_eq!(
        MoveSubmissionState::from_submit_state("rejected", Some("if_state did not match")),
        MoveSubmissionState::FailedPrecondition
    );
}

#[test]
fn move_submission_record_round_trips_through_store() {
    let path = temp_state_path("move-submission");
    let mut store = LocalStateStore::with_path(path.clone());
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000001";
    let mid = "sha256:111";
    store.record_move_submission(
        mid,
        realm,
        "ck.consent.grant",
        MoveSubmissionState::PendingSeal,
        None,
        Some("ck:seal:sha256:abc".to_owned()),
    );
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].move_id, mid);
    assert_eq!(listed[0].state, MoveSubmissionState::PendingSeal);
    assert!(!store.realm_has_paused_notary(realm));

    // Update to NotaryPaused — Space should now flag the banner.
    assert!(store.update_move_submission_state(
        mid,
        MoveSubmissionState::NotaryPaused,
        Some("recovery notary not signed".to_owned()),
    ));
    assert!(store.realm_has_paused_notary(realm));
    let listed = store.move_submissions_for_realm(realm);
    assert_eq!(listed[0].state, MoveSubmissionState::NotaryPaused);
    assert_eq!(
        listed[0].reason.as_deref(),
        Some("recovery notary not signed")
    );

    // Persistence: a fresh reader sees the same state.
    let reader = LocalStateStore::with_path(path);
    assert!(reader.realm_has_paused_notary(realm));

    // Drop it and the banner clears.
    let mut store = LocalStateStore::with_path(reader.path.clone());
    store.drop_move_submission(mid);
    assert!(!store.realm_has_paused_notary(realm));
}

#[test]
fn move_submission_pending_mls_binding_drives_toast() {
    let path = temp_state_path("move-mls-binding");
    let mut store = LocalStateStore::with_path(path);
    let realm = "ck:realm:0196419b-0000-7000-8000-000000000002";
    store.record_move_submission(
        "sha256:222",
        realm,
        "ck.message.create",
        MoveSubmissionState::PendingMlsBinding,
        Some("covered_seals missing".to_owned()),
        None,
    );
    assert!(store.realm_has_pending_mls_binding(realm));
    assert!(!store.realm_has_paused_notary(realm));
}

#[test]
fn move_submission_state_label_and_badge_class_distinct_per_state() {
    for state in [
        MoveSubmissionState::PendingSeal,
        MoveSubmissionState::Effective,
        MoveSubmissionState::FailedPrecondition,
        MoveSubmissionState::FailedBottom,
        MoveSubmissionState::RejectedSeal,
        MoveSubmissionState::NotaryPaused,
        MoveSubmissionState::PendingMlsBinding,
    ] {
        assert!(!state.slug().is_empty());
        assert!(!state.label_zh().is_empty());
        assert!(state.badge_class().starts_with("badge"));
    }
    assert!(MoveSubmissionState::NotaryPaused.is_failed());
    assert!(!MoveSubmissionState::PendingSeal.is_failed());
    assert!(!MoveSubmissionState::Effective.is_failed());
}
