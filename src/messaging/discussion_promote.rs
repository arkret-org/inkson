//! G3.Y2 — "promote a Flow's discussion to its own child Space" state.
//!
//! Spec: `models/flow-and-message.md §5` (`discussion_space_ref`) +
//! `models/space-hierarchy.md §3-§4` (parent/child confirmed edge).
//!
//! The full promote flow needs three durable events:
//! 1. `cx.space.create` for the new child Space, with `parent_space_id` pointing back at the
//!    parent.
//! 2. `cx.space.child` on the parent + `cx.space.parent` on the child (the bidirectional
//!    confirmation edge).
//! 3. `cx.flow.update` on the original Flow, setting `discussion_space_ref = <new_space_id>`.
//!
//! The local 1.0 UI hides the promote modal unless the
//! `experimental-discussion-promote` feature is enabled. This module keeps
//! the wire builders covered by unit tests while the soland reducer is
//! completed.

use serde_json::{Value, json};

use crate::operation::{EventEnvelope, OperationBuilder, scope_id_as_realm_id, uuid_v7};

/// Whether the local UI should expose the discussion promote modal.
pub fn discussion_promote_enabled() -> bool {
    cfg!(feature = "experimental-discussion-promote")
}

/// Modal state for the "promote discussion" confirmation dialog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromoteDiscussionDraft {
    /// Message id (or Flow id, depending on entry point) being
    /// promoted. `None` means the modal is closed.
    pub source_id: Option<String>,
    /// User-visible title for the new child Space. Pre-filled from
    /// the source Flow's name on open.
    pub title: String,
}

impl PromoteDiscussionDraft {
    pub fn open(&mut self, source_id: String, default_title: String) {
        self.source_id = Some(source_id);
        self.title = default_title;
    }

    pub fn close(&mut self) {
        self.source_id = None;
        self.title.clear();
    }

    pub fn is_open(&self) -> bool {
        self.source_id.is_some()
    }

    pub fn is_submittable(&self) -> bool {
        self.source_id.is_some() && !self.title.trim().is_empty()
    }
}

/// Generated identifiers for the new child Space + the edge events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromoteIds {
    pub child_space_id: String,
    pub child_edge_event_id: String,
    pub parent_edge_event_id: String,
}

impl PromoteIds {
    pub fn fresh() -> Self {
        Self {
            child_space_id: format!("ck:space:{}", uuid_v7()),
            child_edge_event_id: format!("evt-child-{}", uuid_v7()),
            parent_edge_event_id: format!("evt-parent-{}", uuid_v7()),
        }
    }
}

/// Build the `cx.space.create` envelope for the new child Space.
pub fn build_child_space_create_op(
    parent_space_id: &str,
    actor: &str,
    ids: &PromoteIds,
    title: &str,
) -> EventEnvelope {
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    OperationBuilder::new(parent_space_id, actor, "cx.space.create")
        .target_ref(&ids.child_space_id)
        .body(json!({
            "object": {
                "id": ids.child_space_id,
                "schema": "cx.schema.space.v1",
                "realm_id": scope_id_as_realm_id(parent_space_id),
                "kind": "space",
                "title": title.trim(),
                "parent_space_id": parent_space_id,
                "created_by": actor,
                "created_at": created_at,
                "fields": {
                    "discoverability": "listed",
                    "join_rule": "invite"
                }
            }
        }))
        .build("yougen")
}

/// Build the parent-side `cx.space.child` confirmation edge.
pub fn build_child_edge_op(
    parent_space_id: &str,
    actor: &str,
    child_space_id: &str,
) -> EventEnvelope {
    OperationBuilder::new(parent_space_id, actor, "cx.space.child")
        .target_ref(child_space_id)
        .body(json!({
            "child_space_id": child_space_id,
        }))
        .build("yougen")
}

/// Build the child-side `cx.space.parent` confirmation edge.
pub fn build_parent_edge_op(
    child_space_id: &str,
    actor: &str,
    parent_space_id: &str,
) -> EventEnvelope {
    OperationBuilder::new(child_space_id, actor, "cx.space.parent")
        .target_ref(parent_space_id)
        .body(json!({
            "parent_space_id": parent_space_id,
        }))
        .build("yougen")
}

/// Build the `cx.flow.update` that points the source Flow's
/// `discussion_space_ref` at the new child Space.
pub fn build_flow_discussion_ref_op(
    parent_space_id: &str,
    actor: &str,
    flow_id: &str,
    child_space_id: &str,
) -> EventEnvelope {
    let mut patch = cokret_sdk::Patch::new();
    patch
        .insert_op(
            "discussion_space_ref",
            cokret_sdk::PatchOp::set(child_space_id),
        )
        .unwrap_or_else(|err| {
            panic!("invalid cx.patch.v1 discussion_space_ref patch: {err}");
        });
    let payload = cokret_sdk::ObjectPatchPayload::for_target(flow_id, patch)
        .and_then(|payload| payload.to_value())
        .unwrap_or_else(|err| {
            panic!("invalid cx.flow.update object_patch_payload: {err}");
        });

    OperationBuilder::new(parent_space_id, actor, "cx.flow.update")
        .target_ref(flow_id)
        .body(payload)
        .build("yougen")
}

/// Convenience helper that bundles all four envelopes into a single
/// list, in spec-required submit order.
pub fn build_promote_ops(
    parent_space_id: &str,
    actor: &str,
    source_flow_id: Option<&str>,
    ids: &PromoteIds,
    title: &str,
) -> Vec<EventEnvelope> {
    let mut ops = vec![
        build_child_space_create_op(parent_space_id, actor, ids, title),
        build_child_edge_op(parent_space_id, actor, &ids.child_space_id),
        build_parent_edge_op(&ids.child_space_id, actor, parent_space_id),
    ];
    if let Some(flow_id) = source_flow_id {
        ops.push(build_flow_discussion_ref_op(
            parent_space_id,
            actor,
            flow_id,
            &ids.child_space_id,
        ));
    }
    ops
}

/// Extract a stable child-space id for client-side optimistic UI
/// updates from a successful submit response. Returns `None` if the
/// response shape doesn't carry one.
pub fn child_space_id_from_response(value: &Value) -> Option<String> {
    value
        .get("space_id")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn draft_open_close_round_trip() {
        let mut draft = PromoteDiscussionDraft::default();
        assert!(!draft.is_open());
        draft.open("msg-1".into(), "Incident review".into());
        assert!(draft.is_open());
        assert_eq!(draft.title, "Incident review");
        draft.close();
        assert!(!draft.is_open());
        assert!(draft.title.is_empty());
    }

    #[test]
    fn draft_requires_non_blank_title_to_submit() {
        let mut draft = PromoteDiscussionDraft::default();
        draft.open("msg-1".into(), "  ".into());
        assert!(!draft.is_submittable());
        draft.title = "Hello".into();
        assert!(draft.is_submittable());
    }

    #[test]
    fn promote_ops_emits_four_events_when_flow_known() {
        let ids = PromoteIds::fresh();
        let ops = build_promote_ops(
            "ck:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            Some("ck:flow:0196419b-0000-7000-8000-000000000002"),
            &ids,
            "Child",
        );
        assert_eq!(ops.len(), 4);
        let kinds: Vec<&str> = ops.iter().map(|op| op.kind.as_str()).collect();
        assert_eq!(
            kinds,
            vec![
                "cx.space.create",
                "cx.space.child",
                "cx.space.parent",
                "cx.flow.update"
            ]
        );
    }

    #[test]
    fn flow_discussion_ref_update_matches_registered_payload_schema() {
        let event = build_flow_discussion_ref_op(
            "ck:space:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:flow:0196419b-0000-7000-8000-000000000002",
            "ck:space:0196419b-0000-7000-8000-000000000003",
        );
        assert_eq!(event.kind, "cx.flow.update");
        assert!(event.payload.get("discussion_space_ref").is_none());
        assert_eq!(
            event.payload["patch"]["discussion_space_ref"]["value"],
            "ck:space:0196419b-0000-7000-8000-000000000003"
        );
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&event.kind, &event.payload)
            .unwrap_or_else(|err| {
                panic!(
                    "discussion promote cx.flow.update payload violates spec: {err}\npayload: {}",
                    serde_json::to_string_pretty(&event.payload).unwrap()
                );
            });
    }

    #[test]
    fn promote_ops_skips_flow_update_without_flow_id() {
        let ids = PromoteIds::fresh();
        let ops = build_promote_ops(
            "ck:space:parent",
            "did:web:alice.example",
            None,
            &ids,
            "Child",
        );
        assert_eq!(ops.len(), 3);
    }
}
