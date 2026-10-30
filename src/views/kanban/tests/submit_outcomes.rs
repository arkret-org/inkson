//! Actual submission-result consumption, durable recovery and card presentation.
#![cfg(not(target_arch = "wasm32"))]

use super::super::drag_drop_controller::{
    drop_unsubmitted_archive_operations, reconcile_kanban_operation_submission,
};
use super::*;
use crate::transport::auth::ApiCallError;

const REALM: &str = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
const EVENT: &str = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const LOCAL: &str = "01a01bdd-804b-7ad0-bee8-194898437ad7";

fn holder_record(state: &str) -> Value {
    holder_record_with_event(state, Some(json!(EVENT)))
}

fn holder_record_with_event(state: &str, event: Option<Value>) -> Value {
    let mut record = json!({
        "kind":"ak.strand.create", "operation_id":LOCAL,
        "local_target_ref":LOCAL, "write_state":state,
        "effect": {
            "strand_id":LOCAL, "board_space_id":"ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "list_space_id":"ak:space:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL", "title":"Offline card", "rank":"U"
        }
    });
    if let Some(event) = event {
        record["event_id"] = event;
    }
    record
}

fn queued_answer() -> Result<crate::models::EventSubmissionProgress, ApiCallError> {
    Err(ApiCallError::Failed(
        crate::event_submit::DurablyQueuedError {
            operation_id: EVENT.to_owned(),
            reason: Some("response was lost".to_owned()),
        }
        .into(),
    ))
}

fn assert_badge_state(state: CardState) {
    let mut dom =
        VirtualDom::new_with_props(|state: CardState| rsx! { WriteStateBadge { state } }, state);
    assert!(dom.rebuild_to_vec().edits.iter().any(|edit| matches!(edit,
        dioxus::core::Mutation::SetAttribute { name:"data-write-state", value:dioxus::core::AttributeValue::Text(value), .. }
        if value.as_str() == state.write_state().data_state()
    )));
}

#[test]
fn queued_submit_answer_preserves_exact_holder_event_and_card_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut store = LocalStateStore::with_path(&path);
    let initial = holder_record("queued");
    store.upsert_raw_operation(LOCAL, Some(REALM.to_owned()), initial.clone());
    reconcile_kanban_operation_submission(&mut store, LOCAL, &queued_answer());
    drop(store);
    let reopened = LocalStateStore::with_path(&path);
    let snapshot = reopened.load();
    let record = &snapshot.raw_operations[0];
    assert_eq!(
        record.payload, initial,
        "queued answer must not rewrite the enqueue owner's record"
    );
    assert_eq!(record.payload["event_id"], EVENT);
    assert!(raw_operation_accepted_create_target_id(&record.payload).is_none());
    let card = local_card_create_from_raw_operation(record).expect("queued card survives refresh");
    assert_eq!(card.card.title, "Offline card");
    assert!(!card.card.state.is_settled());
    assert_badge_state(card.card.state);
}

#[test]
fn explicit_refusal_drops_optimistic_card_but_a_queued_retry_remains_visible() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(dir.path().join("state.json"));
    store.upsert_raw_operation(LOCAL, Some(REALM.to_owned()), holder_record("queued"));
    let refusal = Err(ApiCallError::Failed(anyhow::anyhow!("capability_denied")));
    reconcile_kanban_operation_submission(&mut store, LOCAL, &refusal);
    let refused = store.load();
    assert!(local_card_create_from_raw_operation(&refused.raw_operations[0]).is_none());
    assert!(!raw_operation_card_state(&refused.raw_operations[0].payload).is_settled());
    assert_badge_state(raw_operation_card_state(&refused.raw_operations[0].payload));
    // The enqueue owner, rather than the view's error handler, stamps the
    // retry's exact Event identity before returning its queued answer.
    store.update_raw_operation_write_state(LOCAL, "queued", Some(EVENT.to_owned()), None);
    let retry = store.load().raw_operations[0].payload.clone();
    reconcile_kanban_operation_submission(&mut store, LOCAL, &queued_answer());
    assert_eq!(store.load().raw_operations[0].payload, retry);
    let card = local_card_create_from_raw_operation(&store.load().raw_operations[0]).unwrap();
    assert_eq!(card.card.state, CardState::Queued);
    assert_badge_state(card.card.state);
}

#[test]
fn late_queued_callback_cannot_erase_a_newer_accepted_result() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(dir.path().join("state.json"));
    let accepted = holder_record("accepted");
    store.upsert_raw_operation(LOCAL, Some(REALM.to_owned()), accepted.clone());
    reconcile_kanban_operation_submission(&mut store, LOCAL, &queued_answer());
    assert_eq!(store.load().raw_operations[0].payload, accepted);
}

#[test]
fn partial_archive_failure_preserves_submitted_outcomes_and_cancels_only_unsent_intents() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(dir.path().join("state.json"));
    let ids = ["accepted", "queued", "rejected", "unsubmitted"].map(str::to_owned);
    for (index, id) in ids.iter().enumerate() {
        let event = (id != "unsubmitted").then(|| {
            json!(arkret_sdk::EventId::from_digest(
                arkret_sdk::DigestSuite::Sha256,
                [index as u8 + 1; 32]
            ))
        });
        let mut payload =
            holder_record_with_event(if id == "unsubmitted" { "queued" } else { id }, event);
        payload["operation_id"] = json!(id);
        store.upsert_raw_operation(id, Some(REALM.to_owned()), payload);
    }
    let before = store.load();
    drop_unsubmitted_archive_operations(&mut store, &ids, "capability_denied");
    let after = store.load();
    for index in 0..3 {
        assert_eq!(
            after.raw_operations[index].payload,
            before.raw_operations[index].payload
        );
    }
    assert_eq!(after.raw_operations[3].payload["write_state"], "dropped");
    assert!(local_card_create_from_raw_operation(&after.raw_operations[3]).is_none());
}

fn verified_response() -> crate::models::EventSubmissionProgress {
    let realm: arkret_sdk::RealmId = REALM.parse().unwrap();
    let actor = crate::test_support::account_actor("ak:did_core:web:alice.example");
    let mut space = arkret_sdk::Space::create_object(realm.clone(), "board", "", actor);
    space.title = None;
    space.created_at = crate::test_support::committed_event::fixture_time(2);
    let accepted = crate::test_support::committed_event::verified_realm_item(
        realm,
        arkret_sdk::EventKind::SpaceCreate.as_str(),
        serde_json::to_value(arkret_sdk::SpaceCreatePayload::new(space)).unwrap(),
    );
    // This shared fixture verifies both real producer and Station signatures,
    // content identities and the fresh authority chain before returning.
    crate::models::EventSubmissionProgress::committed(
        accepted.event.event_id.to_string(),
        accepted.commit,
    )
}

#[test]
fn typed_submit_results_require_the_exact_verified_covering_commit_for_acceptance() {
    let response = verified_response();
    let dir = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(dir.path().join("state.json"));
    let mut initial = holder_record("queued");
    initial["event_id"] = json!(response.event_id);
    store.upsert_raw_operation(LOCAL, Some(REALM.to_owned()), initial.clone());
    for status in [
        garth::SendQueueStatus::Queued,
        garth::SendQueueStatus::Forwarding,
    ] {
        let mut pending = crate::models::EventSubmissionProgress::queued(response.event_id.clone());
        pending.status = status;
        reconcile_kanban_operation_submission(&mut store, LOCAL, &Ok(pending));
        assert_eq!(store.load().raw_operations[0].payload, initial);
        assert!(!raw_operation_card_state(&store.load().raw_operations[0].payload).is_settled());
    }
    reconcile_kanban_operation_submission(&mut store, LOCAL, &Ok(response));
    let accepted = store.load();
    assert_eq!(
        accepted.raw_operations[0].payload["write_state"],
        "accepted"
    );
    assert!(raw_operation_card_state(&accepted.raw_operations[0].payload).is_settled());
    assert_badge_state(raw_operation_card_state(
        &accepted.raw_operations[0].payload,
    ));
}

#[test]
fn contradictory_or_uncovered_typed_result_never_claims_acceptance() {
    let verified = verified_response();
    let dir = tempfile::tempdir().unwrap();
    let mut store = LocalStateStore::with_path(dir.path().join("state.json"));
    for scenario in [
        "missing_commit",
        "other_event",
        "queued_with_commit",
        "other_holder_event",
    ] {
        let mut response = verified.clone();
        let mut initial = holder_record("queued");
        initial["event_id"] = json!(response.event_id);
        match scenario {
            "missing_commit" => response.commit = None,
            "other_event" => response.event_id = EVENT.to_owned(),
            "queued_with_commit" => response.status = garth::SendQueueStatus::Queued,
            "other_holder_event" => initial["event_id"] = json!(EVENT),
            _ => unreachable!(),
        }
        let original_event = initial["event_id"].clone();
        store.upsert_raw_operation(LOCAL, Some(REALM.to_owned()), initial);
        reconcile_kanban_operation_submission(&mut store, LOCAL, &Ok(response));
        let failed = store.load();
        assert_eq!(
            failed.raw_operations[0].payload["write_state"], "failed",
            "{scenario}"
        );
        assert_eq!(
            failed.raw_operations[0].payload["event_id"], original_event,
            "{scenario}"
        );
        assert!(
            !raw_operation_card_state(&failed.raw_operations[0].payload).is_settled(),
            "{scenario}"
        );
        assert!(local_card_create_from_raw_operation(&failed.raw_operations[0]).is_none());
    }
    for (status, expected) in [
        (garth::SendQueueStatus::Rejected, "rejected"),
        (garth::SendQueueStatus::Failed, "failed"),
        (garth::SendQueueStatus::Cancelled, "cancelled"),
    ] {
        store.upsert_raw_operation(LOCAL, Some(REALM.to_owned()), holder_record("queued"));
        let mut result = crate::models::EventSubmissionProgress::rejected(
            EVENT.to_owned(),
            "capability_denied".to_owned(),
        );
        result.status = status;
        reconcile_kanban_operation_submission(&mut store, LOCAL, &Ok(result));
        assert_eq!(
            store.load().raw_operations[0].payload["write_state"],
            expected
        );
    }
}
