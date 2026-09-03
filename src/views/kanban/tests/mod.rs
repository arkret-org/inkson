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

pub(super) const TEST_REALM_ID: &str = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";

// shared hermetic state-store fixture from `local_state`.
#[cfg(not(target_arch = "wasm32"))]
pub(super) use crate::state::isolated_store_for_tests;

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

/// Realm-tree projection for an encrypted Realm whose creator is `actor_id`.
///
/// The creator fact is carried only by the projected `ak.realm.create` Event —
/// the sole registered writer of `ak.component.realm.authority_root.v1`. Post-P1
/// projections no longer mirror it into an `owner` / `created_by` field, and
/// `garth::realm_authority_root_controller_from_events` reads nothing
/// else, so a fixture that mirrors it would test a fallback the client does not
/// have.
#[cfg(not(target_arch = "wasm32"))]
pub(super) fn creator_realm_projection(
    _realm_id: &str,
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
        "state": {
            "events": [{
                "kind": "ak.realm.create",
                "actor_id": actor_id,
                "payload": {
                    "object": {
                        "encryption_profile": encryption_profile,
                    }
                }
            }]
        }
    })
}

#[test]
fn toast_editor_bootstrap_uses_asset_pipeline_urls() {
    let script = toast_editor_bootstrap_script("editor-host", "editor-fallback", "", true)
        .expect("bootstrap script");
    let config_json = script
        .split_once("const config = ")
        .and_then(|(_, suffix)| suffix.split_once(";\n"))
        .map(|(config, _)| config)
        .expect("embedded editor config");
    let config: serde_json::Value = serde_json::from_str(config_json).expect("editor config JSON");
    assert_eq!(config["scriptUrl"], TOAST_EDITOR_SCRIPT.to_string());
    assert_eq!(config["cssUrl"], TOAST_EDITOR_CSS.to_string());
    assert!(!script.contains("/assets/vendor/"));
    assert!(script.contains("existing.host === host"));
    assert!(script.contains("host.isConnected"));
    assert!(script.contains("fallback.isConnected"));
    assert!(script.contains("current.editor !== editor"));
    assert!(script.contains("registry.set(config.hostId, { editor, host, sync })"));
    assert!(script.contains("existing.editor.off(\"change\", existing.sync)"));
    assert!(
        script.find("const uploadImage").expect("upload callback")
            < script
                .find("editor = new window.toastui.Editor")
                .expect("editor construction")
    );
    assert!(!script.contains("existing.dispose()"));
}

#[test]
fn toast_editor_cleanup_revokes_callback_before_destroying_editor() {
    let script = toast_editor_cleanup_script("editor-host").expect("cleanup script");
    let delete = script.find("registry.delete").expect("registry deletion");
    let off = script.find("editor.off").expect("change callback removal");
    let destroy = script.find("editor.destroy").expect("editor destroy");

    assert!(delete < off);
    assert!(off < destroy);
    assert!(script.contains("existing.host !== host"));
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
        None,
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
        counter: None,
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
