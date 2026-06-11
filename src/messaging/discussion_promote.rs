//! G3.Y2 — "promote a Flow's discussion to a Circle-scoped Flow" state.
//!
//! Spec: `models/flow-and-message.md §5` (`scope_circle_id`) +
//! `models/circle.md §7.2` (wide seal Flow + narrow discussion Flow).
//!
//! This flow creates a Circle plus a private discussion Flow under the current
//! Realm. It MUST NOT create a Space hierarchy, and it MUST NOT write a Space
//! id into `scope_circle_id` (that field is for `ck:circle:*` ids only).
//!
//! The local 1.0 UI hides the promote modal unless the
//! `experimental-discussion-promote` feature is enabled. This module keeps
//! the wire builders covered by unit tests while the soland reducer is
//! completed.

use crate::operation::{EventEnvelope, ck_ops, uuid_v7};

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
    /// User-visible title for the new private discussion Flow. Pre-filled
    /// from the source Flow's name on open.
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

/// Generated identifiers for the new Circle-scoped discussion Flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromoteIds {
    pub circle_id: String,
    pub discussion_flow_id: String,
}

impl PromoteIds {
    pub fn fresh() -> Self {
        Self {
            circle_id: format!("ck:circle:{}", uuid_v7()),
            discussion_flow_id: format!("ck:flow:{}", uuid_v7()),
        }
    }
}

/// Build the `ck.circle.create` envelope for the private discussion scope.
pub fn build_discussion_circle_create_op(
    realm_id: &str,
    actor: &str,
    ids: &PromoteIds,
    title: &str,
) -> anyhow::Result<EventEnvelope> {
    Ok(ck_ops::discussion_circle_create(realm_id, actor, &ids.circle_id, title)?.build("yougen"))
}

/// Build the `ck.flow.create` envelope for the new private discussion Flow.
pub fn build_discussion_flow_create_op(
    realm_id: &str,
    actor: &str,
    ids: &PromoteIds,
    title: &str,
) -> anyhow::Result<EventEnvelope> {
    Ok(ck_ops::scoped_discussion_flow_create(
        realm_id,
        actor,
        &ids.discussion_flow_id,
        &ids.circle_id,
        title,
    )?
    .build("yougen"))
}

/// Build the `ck.relation.create` envelope that links the private Flow back
/// to the source public Flow/message.
pub fn build_confidential_discussion_relation_op(
    realm_id: &str,
    actor: &str,
    source_id: &str,
    ids: &PromoteIds,
) -> anyhow::Result<EventEnvelope> {
    Ok(ck_ops::confidential_discussion_relation_create(
        realm_id,
        actor,
        &ids.discussion_flow_id,
        source_id,
        &ids.circle_id,
    )?
    .build("yougen"))
}

/// Convenience helper that bundles the promote envelopes in submit order.
pub fn build_promote_ops(
    realm_id: &str,
    actor: &str,
    source_id: &str,
    ids: &PromoteIds,
    title: &str,
) -> anyhow::Result<Vec<EventEnvelope>> {
    Ok(vec![
        build_discussion_circle_create_op(realm_id, actor, ids, title)?,
        build_discussion_flow_create_op(realm_id, actor, ids, title)?,
        build_confidential_discussion_relation_op(realm_id, actor, source_id, ids)?,
    ])
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
    fn promote_ops_emit_circle_flow_and_private_relation() {
        let ids = PromoteIds::fresh();
        let ops = build_promote_ops(
            "ck:realm:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:flow:0196419b-0000-7000-8000-000000000003",
            &ids,
            "Private discussion",
        )
        .expect("promote ops build");
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].kind, "ck.circle.create");
        assert_eq!(ops[1].kind, "ck.flow.create");
        assert_eq!(ops[2].kind, "ck.relation.create");
        assert_eq!(
            ops[0].payload["object"]["realm_id"],
            "ck:realm:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(ops[1].payload["object"]["scope_circle_id"], ids.circle_id);
        assert_eq!(ops[2].payload["kind"], "confidential_discussion_of");
        // relation_create_payload is additionalProperties:false — the private
        // scope is carried by the Circle-scoped Flow (ops[1]), NOT by an
        // illegal `scope_circle_id` key on the relation payload.
        assert!(
            ops[2].payload.get("scope_circle_id").is_none(),
            "scope_circle_id is not a relation_create_payload field"
        );
        assert_eq!(ops[2].payload["from_ref"], ids.discussion_flow_id);
        assert_eq!(
            ops[2].payload["to_ref"],
            "ck:flow:0196419b-0000-7000-8000-000000000003"
        );
        for event in &ops {
            cokret_sdk::schema::event_payload_validator_catalog()
                .validate_payload(&event.kind, &event.payload)
                .unwrap_or_else(|err| {
                    panic!(
                        "discussion promote {} payload violates spec: {err}\npayload: {}",
                        event.kind,
                        serde_json::to_string_pretty(&event.payload).unwrap()
                    );
                });
        }
    }
}
