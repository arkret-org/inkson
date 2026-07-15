// `use super::*;` pulls the parent `kanban` module symbols into this
// `tests` module; the `pub(super)` re-export below republishes them so
// each `tests/<sub>.rs` doing `use super::*;` (whose `super` is THIS
// module) transitively sees the kanban symbols.
pub(super) use super::*;
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::move_builder::StrandPositionExpectation;
// Types the test bodies construct directly. The component-only `kanban/mod.rs`
// no longer brings them into scope after the structural split, so re-import
// them here for the `tests/<sub>.rs` files that reach them via `use super::*;`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::state::RawOperationRecord;

pub(super) const TEST_REALM_ID: &str = "ak:realm:0196419b-0000-7000-8000-000000000010";

// YOU-05-010: shared hermetic state-store fixture from `local_state`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::state::isolated_store_for_tests as temp_state_store;

mod activity_assignment;
mod calendar_event;
mod card_detail_routes;
mod due_calendar;
mod encrypted_scope;
mod lifecycle;
mod patch_synthesis;
mod projection_overlays;
mod roster;
mod strand_mls;

#[cfg(not(target_arch = "wasm32"))]
pub(super) trait TestEventPayloadView {
    fn kind_for_schema(&self) -> &str;
    fn payload_for_schema(&self) -> serde_json::Value;
}

#[cfg(not(target_arch = "wasm32"))]
impl TestEventPayloadView for arkret_sdk::Event {
    fn kind_for_schema(&self) -> &str {
        self.kind.as_str()
    }

    fn payload_for_schema(&self) -> serde_json::Value {
        serde_json::to_value(&self.payload).expect("event payload serializes")
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn assert_registered_payload_valid(event: &impl TestEventPayloadView) {
    let payload = event.payload_for_schema();
    arkret_sdk::schema::event_payload_validator_catalog()
        .unwrap()
        .validate_payload(event.kind_for_schema(), &payload)
        .unwrap_or_else(|err| {
            panic!(
                "{} payload violates registered schema: {err}\npayload: {}",
                event.kind_for_schema(),
                serde_json::to_string_pretty(&payload).unwrap()
            )
        });
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn sdk_event(event: crate::operation::Event) -> arkret_sdk::Event {
    event
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn sdk_event_local_target_ref(event: &arkret_sdk::Event) -> Option<&str> {
    event
        .unsigned
        .get("local_target_ref")
        .and_then(serde_json::Value::as_str)
}

pub(super) fn board_write_record(state: CardState, note: &str) -> BoardWriteRecord {
    BoardWriteRecord {
        state,
        move_id: "ak:operation:test".to_owned(),
        kind: "ak.strand.create".to_owned(),
        cell_id: "ak:cell:ak.component.test.board_write.v1:test".to_owned(),
        effect_summary: "{}".to_owned(),
        seal_ref: "ak:seal:test".to_owned(),
        hlc: "000000000000-0000-00000000".to_owned(),
        note: note.to_owned(),
        signed_move_json: None,
        rebase_attempts: 0,
    }
}

/// Helper for `relocate_card` tests — builds a KanbanCard with the
/// supplied id and rank, defaulting the rest of the demo fields.
pub(super) fn test_card(id: &str, rank: &str) -> KanbanCard {
    KanbanCard {
        id: id.to_owned(),
        rank: rank.to_owned(),
        title: "test".to_owned(),
        description: String::new(),
        body: String::new(),
        synthesis: String::new(),
        body_locked: false,
        synthesis_locked: false,
        created_by: String::new(),
        created_at: String::new(),
        updated_by: String::new(),
        updated_at: String::new(),
        labels: Vec::new(),
        assignee: String::new(),
        assigned_to_relations: Vec::new(),
        due: String::new(),
        calendar: CalendarCardFields::default(),
        primary_strand_id: String::new(),
        locked_strand: None,
        external_visibility: String::new(),
        history_visibility: String::new(),
        security_encrypted: None,
        state: CardState::Synced,
        lifecycle: StrandLifecycleState::Active,
    }
}
