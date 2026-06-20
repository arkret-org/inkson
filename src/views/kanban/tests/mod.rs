// `use super::*;` pulls the parent `kanban` module symbols into this
// `tests` module; the `pub(super)` re-export below republishes them so
// each `tests/<sub>.rs` doing `use super::*;` (whose `super` is THIS
// module) transitively sees the kanban symbols.
pub(super) use super::*;
// Types the test bodies construct directly. The component-only `kanban/mod.rs`
// no longer brings them into scope after the structural split, so re-import
// them here for the `tests/<sub>.rs` files that reach them via `use super::*;`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::local_state::RawOperationRecord;
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::move_builder::StrandPositionExpectation;

pub(super) const TEST_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-000000000010";

// YOU-05-010: shared hermetic state-store fixture from `local_state`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::local_state::isolated_store_for_tests as temp_state_store;

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
pub(super) fn assert_registered_payload_valid(event: &crate::operation::EventEnvelope) {
    cokret_sdk::schema::event_payload_validator_catalog()
        .validate_payload(&event.kind, &event.payload)
        .unwrap_or_else(|err| {
            panic!(
                "{} payload violates registered schema: {err}\npayload: {}",
                event.kind,
                serde_json::to_string_pretty(&event.payload).unwrap()
            )
        });
}

pub(super) fn board_write_record(state: CardState, note: &str) -> BoardWriteRecord {
    BoardWriteRecord {
        state,
        move_id: "ck:operation:test".to_owned(),
        kind: "ck.strand.create".to_owned(),
        cell_id: "ck:cell:test".to_owned(),
        effect_summary: "{}".to_owned(),
        seal_ref: "ck:seal:test".to_owned(),
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
