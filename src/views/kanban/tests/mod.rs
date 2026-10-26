// `use super::*;` pulls the parent `kanban` module symbols into this
// `tests` module; the `pub(super)` re-export below republishes them so
// each `tests/<sub>.rs` doing `use super::*;` (whose `super` is THIS
// module) transitively sees the kanban symbols.
pub(super) use super::*;
// Types the test bodies construct directly. The component-only `kanban/mod.rs`
// no longer brings them into scope after the structural split, so re-import
// them here for the `tests/<sub>.rs` files that reach them via `use super::*;`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::state::RawOperationRecord;
pub(super) use crate::test_support as fixture;

pub(super) const TEST_REALM_ID: &str = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";

// shared hermetic state-store fixture from `local_state`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::state::isolated_store_for_tests;

mod board_header;
mod calendar_event;
mod card_detail_routes;
mod due_calendar;
mod encrypted_scope;
mod lifecycle;
mod patch_synthesis;
mod projection_overlays;
mod roster;
mod strand_mls;
mod submit_outcomes;

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

/// A locally built write carries the payload the schema governs before it has an
/// identity, so the check does not need it authored.
#[cfg(not(target_arch = "wasm32"))]
impl TestEventPayloadView for crate::operation::LocalOperation {
    fn kind_for_schema(&self) -> &str {
        self.kind().as_str()
    }

    fn payload_for_schema(&self) -> serde_json::Value {
        serde_json::to_value(self.payload()).expect("event payload serializes")
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn assert_registered_payload_valid(event: &impl TestEventPayloadView) {
    let payload = event.payload_for_schema();
    arkret_schema_conformance::event_payload_validator_catalog()
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

/// Local Realm display and roster projection; it grants no authority.
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn creator_realm_projection(
    actor_id: &arkret_sdk::DidCoreId,
    encryption_profile: &str,
) -> serde_json::Value {
    serde_json::json!({
        "__kind": "realm",
        "content_scheme": encryption_profile,
        "member_roster_entries_limited": false,
        "member_roster_entries": [{ "actor_id": crate::mls_api_helpers::local_account_actor_id(actor_id.as_str()).unwrap(), "membership": "join" }],
        "summary": {
            "title": "Encrypted Realm",
            "encryption_profile": encryption_profile,
        },
    })
}

/// Canonical `encrypted_content` envelope fixture.
///
/// `StrandProjectionView.encrypted_content` carries the SDK
/// `EncryptedEnvelope`, so the fixtures build the whole
/// minimal `encrypted-envelope.schema.json` object instead of a three-key stand-in.
pub(super) fn test_encrypted_content_envelope(
    realm_id: &str,
    ciphertext: &str,
) -> arkret_sdk::EncryptedEnvelope {
    let scope = arkret_sdk::ScopeRef::Realm {
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned()).expect("fixture realm id"),
    };
    let group_state_ref =
        arkret_sdk::EventId::new("ak:event:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM")
            .expect("fixture group-state Event id");
    let header = arkret_sdk::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE,
        arkret_wire::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        "ak.strand.update",
        1,
        group_state_ref,
        "ak:device:fixture",
        arkret_sdk::EventContentRoutingContext::None,
    )
    .expect("fixture pre-encryption header");
    let payload_digest =
        arkret_sdk::EncryptedPayload::payload_digest_for_header(&header, ciphertext.to_owned())
            .expect("fixture payload digest");
    let payload = arkret_sdk::EncryptedPayload {
        scheme: arkret_wire::EncryptedPayloadScheme::MlsRfc9420,
        group_id: scope
            .canonical_mls_group_id()
            .expect("fixture MLS group id"),
        epoch: 1,
        content_type: KANBAN_STRAND_PATCH_VALUE_CONTENT_TYPE.to_owned(),
        ciphertext: ciphertext.to_owned(),
        pre_encryption_header: header,
        payload_digest,
    };
    arkret_sdk::mls::encrypted_envelope_from_payload(&payload)
        .expect("canonical encrypted_content envelope")
}

/// Helper for `relocate_card` tests — builds a KanbanCard with the
/// supplied id and rank, defaulting the rest of the demo fields.
pub(super) fn test_card(id: &str, rank: &str) -> KanbanCard {
    KanbanCard {
        id: id.to_owned(),
        rank: rank.to_owned(),
        title: "test".to_owned(),
        description: String::new(),
        description_body: String::new(),
        description_locked: false,
        synthesis: String::new(),
        synthesis_locked: false,
        created_by: String::new(),
        created_at: String::new(),
        updated_by: String::new(),
        updated_at: String::new(),
        labels: Vec::new(),
        assignee: String::new(),
        assigned_to_relations: Vec::new(),
        due: String::new(),
        calendar_rsvp: CalendarRsvpDisplay::default(),
        calendar_rsvp_cells: Vec::new(),
        authoring_basis: None,
        calendar_schedule_basis_refs: Vec::new(),
        calendar: CalendarCardFields::default(),
        primary_strand_id: String::new(),
        locked_strand: None,
        external_visibility: String::new(),
        history_access: String::new(),
        security_encrypted: None,
        state: CardState::Synced,
        lifecycle: StrandLifecycleState::Active,
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(super) fn assert_native_badge(state: CardState, expected: CardState) {
    let app = glory::ui::App::memory();
    let scope = app.scope();
    let directory = tempfile::Builder::new()
        .prefix("kanban-badge-")
        .tempdir_in("D:/BuildCache/inkson-glory/tmp")
        .unwrap();
    let config_store =
        crate::config::LocalConfigStore::with_path(directory.path().join("config.json"));
    let config = config_store.load();
    let boot = crate::presentation::BootState {
        config_store,
        config,
        state_store: SharedStateStore::new(LocalStateStore::with_path(
            directory.path().join("state.json"),
        )),
        initial_credential: String::new(),
        realm_tree_nodes: vec![],
    };
    let context = InksonContext::new(scope, boot, Route::Dashboard, |_| {
        Box::pin(async { crate::runtime::session::CurrentSessionRefresh::retry_later("unused") })
    });
    app.mount(crate::components::write_state_badge(
        scope,
        context,
        crate::components::WriteStateBadgeProps {
            state: state.write_state(),
            icon_only: None,
        },
    ))
    .unwrap();
    app.flush().unwrap();
    let expected = format!("write-state-{}", expected.write_state().data_state());
    let tree = app.tree();
    let mut pending = tree.roots().to_vec();
    let mut found = false;
    while let Some(id) = pending.pop() {
        let node = tree.node(id).unwrap();
        found |= node
            .descriptor
            .view()
            .classes
            .iter()
            .any(|class| class == &expected);
        pending.extend(&node.children);
    }
    assert!(
        found,
        "actual native badge must expose its precise holder state {expected}"
    );
}
