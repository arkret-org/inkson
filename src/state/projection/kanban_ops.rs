//! Kanban realm-event → `RawOperationRecord` extraction (the sync engine's
//! kanban ingest funnel).
//!
//! Pure move from `views/kanban/model/{board_projection,
//! overlays}.rs`, zero behavior change): consumed by
//! `sync_engine::ingest_kanban_events` and the kanban view model.

use arkret_sdk::EventPayloadExt as _;
use serde::Serialize;

use crate::state::RawOperationRecord;

// Internal ingest-dispatch enum: each value is constructed from one Event and
// consumed immediately, so boxing the larger variant would only add an
// allocation per kanban Event without changing layout anywhere durable.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum LocalKanbanEvent {
    SpaceCreate(arkret_sdk::SpaceCreatePayload),
    SpaceUpdate(arkret_sdk::SpacePatchPayload),
    SpaceArchive(arkret_sdk::SpaceStateTransitionPayload),
    SpaceRestore(arkret_sdk::SpaceStateTransitionPayload),
    StrandCreate(arkret_sdk::StrandCreatePayload),
    StrandUpdate(arkret_sdk::StrandPatchPayload),
    StrandMove(arkret_sdk::StrandMovePayload),
    StrandReorder(arkret_sdk::StrandReorderPayload),
    StrandArchive(arkret_sdk::ObjectLifecyclePayload),
    StrandRestore(arkret_sdk::ObjectLifecyclePayload),
    RsvpSet(arkret_sdk::RsvpSetPayload),
    RelationCreate(arkret_sdk::RelationCreatePayload),
    RelationTombstone(arkret_sdk::RelationTombstonePayload),
}

impl LocalKanbanEvent {
    fn from_sdk_event(event: &arkret_sdk::Event) -> Option<Self> {
        Some(match &event.kind {
            arkret_sdk::EventKind::SpaceCreate => Self::SpaceCreate(
                event
                    .typed_payload::<arkret_wire::event_spec::SpaceCreate>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::SpaceUpdate => Self::SpaceUpdate(
                event
                    .typed_payload::<arkret_wire::event_spec::SpaceUpdate>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::SpaceArchive => Self::SpaceArchive(
                event
                    .typed_payload::<arkret_wire::event_spec::SpaceArchive>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::SpaceRestore => Self::SpaceRestore(
                event
                    .typed_payload::<arkret_wire::event_spec::SpaceRestore>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::StrandCreate => Self::StrandCreate(
                event
                    .typed_payload::<arkret_wire::event_spec::StrandCreate>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::StrandUpdate => Self::StrandUpdate(
                event
                    .typed_payload::<arkret_wire::event_spec::StrandUpdate>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::StrandMove => Self::StrandMove(
                event
                    .typed_payload::<arkret_wire::event_spec::StrandMove>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::StrandReorder => Self::StrandReorder(
                event
                    .typed_payload::<arkret_wire::event_spec::StrandReorder>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::StrandArchive => Self::StrandArchive(
                event
                    .typed_payload::<arkret_wire::event_spec::StrandArchive>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::StrandRestore => Self::StrandRestore(
                event
                    .typed_payload::<arkret_wire::event_spec::StrandRestore>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::RsvpSet => Self::RsvpSet(
                event
                    .typed_payload::<arkret_wire::event_spec::RsvpSet>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::RelationCreate => Self::RelationCreate(
                event
                    .typed_payload::<arkret_wire::event_spec::RelationCreate>()
                    .ok()?,
            ),
            arkret_sdk::EventKind::RelationTombstone => Self::RelationTombstone(
                event
                    .typed_payload::<arkret_wire::event_spec::RelationTombstone>()
                    .ok()?,
            ),
            _ => return None,
        })
    }

    fn record_value(&self, metadata: &LocalRecordMetadata) -> Option<serde_json::Value> {
        macro_rules! serialize_record {
            ($kind:ident, $payload:expr) => {
                serde_json::to_value(LocalKanbanRecord {
                    kind: arkret_sdk::EventKind::$kind,
                    operation_id: &metadata.operation_id,
                    actor_id: &metadata.actor_id,
                    created_at: &metadata.created_at,
                    write_state: "synced",
                    body: $payload,
                    local_target_ref: metadata.local_target_ref.as_deref(),
                })
                .ok()
            };
        }
        match self {
            Self::SpaceCreate(payload) => serialize_record!(SpaceCreate, payload),
            Self::SpaceUpdate(payload) => serialize_record!(SpaceUpdate, payload),
            Self::SpaceArchive(payload) => serialize_record!(SpaceArchive, payload),
            Self::SpaceRestore(payload) => serialize_record!(SpaceRestore, payload),
            Self::StrandCreate(payload) => serialize_record!(StrandCreate, payload),
            Self::StrandUpdate(payload) => serialize_record!(StrandUpdate, payload),
            Self::StrandMove(payload) => serialize_record!(StrandMove, payload),
            Self::StrandReorder(payload) => serialize_record!(StrandReorder, payload),
            Self::StrandArchive(payload) => serialize_record!(StrandArchive, payload),
            Self::StrandRestore(payload) => serialize_record!(StrandRestore, payload),
            Self::RsvpSet(payload) => serialize_record!(RsvpSet, payload),
            Self::RelationCreate(payload) => serialize_record!(RelationCreate, payload),
            Self::RelationTombstone(payload) => serialize_record!(RelationTombstone, payload),
        }
    }
}

#[derive(Serialize)]
struct LocalKanbanRecord<'a, T> {
    kind: arkret_sdk::EventKind,
    operation_id: &'a str,
    actor_id: &'a arkret_sdk::ActorId,
    created_at: &'a str,
    write_state: &'static str,
    body: &'a T,
    #[serde(skip_serializing_if = "Option::is_none")]
    local_target_ref: Option<&'a str>,
}

struct LocalRecordMetadata {
    operation_id: String,
    actor_id: arkret_sdk::ActorId,
    created_at: String,
    local_target_ref: Option<String>,
}

/// Normalize a batch of canonical realm events (from `backfill` /
/// `events/subscribe`) into [`RawOperationRecord`]s for EVERY kanban-relevant
/// kind — the single ingest funnel that replaces the old per-kind extractors.
pub(crate) fn kanban_operations_from_events(
    events: &[arkret_sdk::Event],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(kanban_operation_from_typed)
        .collect()
}

pub(crate) fn kanban_operations_from_client_events(
    events: &[garth::ClientEvent],
) -> Vec<RawOperationRecord> {
    events
        .iter()
        .filter_map(|event| match event {
            garth::ClientEvent::Message(message) => kanban_operation_from_typed(&message.event),
            garth::ClientEvent::Event(event) => kanban_operation_from_typed(event),
            _ => None,
        })
        .collect()
}

fn kanban_operation_from_typed(event: &arkret_sdk::Event) -> Option<RawOperationRecord> {
    let local_event = LocalKanbanEvent::from_sdk_event(event)?;
    let operation_id = event.event_id.as_str().to_owned();
    let local_target_ref =
        arkret_sdk::schema::derived_object_id_for_kind(event.kind.as_str(), &event.event_id);
    let metadata = LocalRecordMetadata {
        operation_id: operation_id.clone(),
        actor_id: event.actor_id.clone(),
        created_at: arkret_sdk::canonical::format_timestamp_canonical(event.created_at),
        local_target_ref,
    };
    let mut payload = local_event.record_value(&metadata)?;
    // Keep the signed envelope for authenticated decryption. Reduced patch
    // values alone cannot establish the sender, scope or ciphertext binding.
    if matches!(
        event.kind,
        arkret_sdk::EventKind::StrandUpdate | arkret_sdk::EventKind::RsvpSet
    ) {
        payload
            .as_object_mut()?
            .insert("event".to_owned(), serde_json::to_value(event).ok()?);
    }
    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: Some(event.realm_id.as_str().to_owned()),
        received_at: event.created_at,
        payload,
    })
}

#[cfg(test)]
pub(crate) fn strand_update_operation_from_event(
    event: &arkret_sdk::Event,
) -> Option<RawOperationRecord> {
    matches!(event.kind, arkret_sdk::EventKind::StrandUpdate)
        .then(|| kanban_operation_from_typed(event))?
}

#[cfg(test)]
pub(crate) fn sdk_events_from_values(values: &[serde_json::Value]) -> Vec<arkret_sdk::Event> {
    values
        .iter()
        .filter_map(|value| {
            let kind = value
                .get("kind")
                .or_else(|| value.get("event_kind"))
                .and_then(serde_json::Value::as_str)
                .map(arkret_sdk::EventKind::from)?;
            let payload = value.get("payload").or_else(|| value.get("body"))?.clone();
            let realm_id = value
                .get("realm_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| arkret_sdk::RealmId::new(value.to_owned()).ok())
                .unwrap_or_else(|| {
                    arkret_sdk::RealmId::new(
                        "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6",
                    )
                    .expect("fixture realm id")
                });
            let actor_id = value
                .get("actor_id")
                .and_then(|value| serde_json::from_value::<arkret_sdk::ActorId>(value.clone()).ok())
                .unwrap_or_else(|| {
                    arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                        arkret_sdk::DidCoreId::new("ak:did_core:webvh:z6mkfixture")
                            .expect("fixture actor principal"),
                        arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example")
                            .expect("fixture actor station"),
                    ))
                });
            let mut event = arkret_wire::test_support::raw_event(
                kind.as_str(),
                arkret_sdk::ScopeRef::Realm { realm_id },
                actor_id.signing_principal_id().clone(),
                actor_id.route_service_id().clone(),
                payload,
            )
            .ok()?;
            event.actor_id = actor_id;
            if let Some(event_id) = value
                .get("event_id")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| arkret_sdk::EventId::new(value.to_owned()).ok())
            {
                event.event_id = event_id;
            }
            if let Some(created_at) = value
                .get("created_at")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse().ok())
            {
                event.created_at = created_at;
            }
            Some(event)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rsvp_events_enter_the_kanban_projection_with_their_typed_schedule_basis() {
        let basis = arkret_sdk::Hash::new(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let basis_event_id = arkret_sdk::EventId::from_event_digest(&basis).unwrap();
        let event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::RsvpSet.as_str(),
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            },
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            serde_json::json!({
                "event_ref": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "occurrence": null,
                "entry": {
                    "schedule_basis_refs": [basis_event_id.to_string()],
                    "response": {"status": "accepted"}
                }
            }),
        )
        .unwrap();
        let records = kanban_operations_from_events(&[event]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload["kind"], "ak.rsvp.set");
        assert_eq!(
            records[0].payload["body"]["entry"]["schedule_basis_refs"][0],
            basis_event_id.to_string()
        );
    }

    #[test]
    fn client_event_path_projects_without_reparsing_the_envelope() {
        let mut event = arkret_wire::test_support::raw_event(
            arkret_sdk::EventKind::StrandUpdate.as_str(),
            arkret_sdk::ScopeRef::Realm {
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                )
                .unwrap(),
            },
            arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap(),
            json!({
                "target_ref": "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1",
                "patch": {"title": {"$op": "set", "value": "Updated"}}
            }),
        )
        .unwrap();
        event.event_id =
            arkret_sdk::EventId::new("ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z")
                .unwrap();

        let original = serde_json::to_value(&event).unwrap();
        let records =
            kanban_operations_from_client_events(&[garth::ClientEvent::Event(Box::new(event))]);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload["kind"], "ak.strand.update");
        assert_eq!(records[0].payload["event"], original);
        assert_eq!(
            records[0].payload["body"]["target_ref"],
            "ak:strand:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1"
        );
    }
}
