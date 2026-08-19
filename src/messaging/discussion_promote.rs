//! G3.Y2 — "promote a Strand's discussion to a Circle-scoped Strand" state.
//!
//! Spec: `models/strand-and-message.md §5` (`scope_circle_id`) +
//! `models/circle.md §7.2` (wide seal Strand + narrow discussion Strand).
//!
//! This strand creates a Circle plus a private discussion Strand under the current
//! Realm. It MUST NOT create a Space hierarchy, and it MUST NOT write a Space
//! id into `scope_circle_id` (that field is for `ak:circle:*` ids only).
//!
//! The local 1.0 UI hides the promote modal unless the
//! `experimental-discussion-promote` feature is enabled. This module keeps
//! the wire builders covered by unit tests while the soland reducer is
//! completed.

use crate::operation::ak_ops;

/// Whether the local UI should expose the discussion promote modal.
pub fn discussion_promote_enabled() -> bool {
    cfg!(feature = "experimental-discussion-promote")
}

/// Modal state for the experimental "create private Circle discussion" dialog.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PromoteDiscussionDraft {
    /// Message id (or Strand id, depending on entry point) being
    /// promoted. `None` means the modal is closed.
    pub source_id: Option<String>,
    /// User-visible title for the new private discussion Strand. Pre-filled
    /// from the source Strand's name on open.
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

/// Generated identifiers for the new Circle-scoped discussion Strand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromoteIds {
    pub circle_id: String,
    pub discussion_strand_id: String,
}

// `PromoteIds` is an *output* now, not an input: both ids are derived from the
// create Events that make them, so there is nothing to mint up front.

/// Build the `ak.circle.create` event for the private discussion scope.
pub fn build_discussion_circle_create_op(
    realm_id: &str,
    actor: &str,
    title: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    ak_ops::discussion_circle_create(realm_id, actor, title)?.build_sdk_event("inkson")
}

/// Build the `ak.strand.create` event for the new private discussion Strand.
pub fn build_discussion_strand_create_op(
    realm_id: &str,
    actor: &str,
    circle_id: &str,
    title: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    ak_ops::scoped_discussion_strand_create(realm_id, actor, circle_id, title)?
        .build_sdk_event("inkson")
}

/// Build the `ak.relation.create` event that links the private Strand back
/// to the source public Strand/message.
pub fn build_confidential_discussion_relation_op(
    realm_id: &str,
    actor: &str,
    source_id: &str,
    ids: &PromoteIds,
) -> anyhow::Result<crate::operation::LocalOperation> {
    ak_ops::confidential_discussion_relation_create(
        realm_id,
        actor,
        &ids.discussion_strand_id,
        source_id,
        &ids.circle_id,
    )?
    .build_sdk_event("inkson")
}

/// The object id an authored create Event derives, or an error naming the kind
/// that derives none.
pub fn derived_id(event: &arkret_sdk::AuthoredEvent) -> anyhow::Result<String> {
    arkret_sdk::schema::derived_object_id(event)
        .ok_or_else(|| anyhow::anyhow!("{} derives no object id", event.kind.as_str()))
}

/// Bundle the promote envelopes in submit order, together with the ids they
/// derive.
///
/// The order is forced by the identities: the Circle id falls out of the Circle
/// create, the Strand is scoped to that Circle and its id falls out of its own
/// create, and only then can the Relation name both. Nothing here is chosen.
pub fn build_promote_steps(
    realm_id: &str,
    actor: &str,
    source_id: &str,
    title: &str,
) -> anyhow::Result<Vec<crate::event_submit::EventUnitStep>> {
    let (realm_id, actor, source_id, title) = (
        realm_id.to_owned(),
        actor.to_owned(),
        source_id.to_owned(),
        title.to_owned(),
    );
    let circle_realm = realm_id.clone();
    let circle_actor = actor.clone();
    let circle_title = title.clone();
    let strand_realm = realm_id.clone();
    let strand_actor = actor.clone();
    let strand_title = title.clone();
    Ok(vec![
        Box::new(move |_| {
            Ok(vec![
                build_discussion_circle_create_op(&circle_realm, &circle_actor, &circle_title)?
                    .into_intent(),
            ])
        }),
        Box::new(move |authored| {
            let circle_id = derived_id(&authored[0])?;
            Ok(vec![
                build_discussion_strand_create_op(
                    &strand_realm,
                    &strand_actor,
                    &circle_id,
                    &strand_title,
                )?
                .into_intent(),
            ])
        }),
        Box::new(move |authored| {
            let ids = promote_ids(authored)?;
            Ok(vec![
                build_confidential_discussion_relation_op(&realm_id, &actor, &source_id, &ids)?
                    .into_intent(),
            ])
        }),
    ])
}

/// The Circle and Strand a promote unit created, read off the authored unit.
pub fn promote_ids(authored: &[arkret_sdk::AuthoredEvent]) -> anyhow::Result<PromoteIds> {
    let [circle, strand, ..] = authored else {
        anyhow::bail!("discussion promote unit is missing its create Events");
    };
    Ok(PromoteIds {
        circle_id: derived_id(circle)?,
        discussion_strand_id: derived_id(strand)?,
    })
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
    fn promote_ops_emit_circle_strand_and_private_relation() {
        let ops = crate::event_submit::author_event_unit_for_test(
            build_promote_steps(
                "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "did:web:alice.example",
                "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
                "Private discussion",
            )
            .expect("promote steps build"),
        )
        .expect("promote unit authors");
        let ids = promote_ids(&ops).expect("the unit reports the ids it created");
        // Both ids are derived from the creates that make them, so the bundle
        // and the ids it reports can never disagree.
        assert_eq!(
            ids.circle_id,
            arkret_sdk::CircleId::from_event_id(&ops[0].event_id).as_str()
        );
        assert_eq!(
            ids.discussion_strand_id,
            arkret_sdk::StrandId::from_event_id(&ops[1].event_id).as_str()
        );
        assert_eq!(ops.len(), 3);
        assert_eq!(ops[0].kind.as_str(), "ak.circle.create");
        assert_eq!(ops[1].kind.as_str(), "ak.strand.create");
        assert_eq!(ops[2].kind.as_str(), "ak.relation.create");
        assert_eq!(
            ops[0].payload["object"]["realm_id"],
            "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-"
        );
        assert_eq!(ops[1].payload["object"]["scope_circle_id"], ids.circle_id);
        // The relation travels on the object branch, the only one the
        // registered `ak.relation.create` contract can project into a cell.
        let relation = &ops[2].payload["relation"];
        assert_eq!(relation["relation_kind"], "confidential_discussion_of");
        // Relation scope belongs to the signed Event envelope, not the
        // closed RelationSnapshot payload.
        assert_eq!(
            ops[2].scope_ref.circle_id().map(|id| id.as_str()),
            Some(ids.circle_id.as_str())
        );
        assert!(
            !ops[2].payload.contains_key("scope_circle_id"),
            "the flat branch member must not appear beside the object branch"
        );
        assert_eq!(relation["from_ref"], ids.discussion_strand_id);
        assert_eq!(
            relation["to_ref"],
            "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2"
        );
        for event in &ops {
            arkret_sdk::schema::event_payload_validator_catalog()
                .unwrap()
                .validate_payload(
                    event.kind.as_str(),
                    &serde_json::to_value(&event.payload).unwrap(),
                )
                .unwrap_or_else(|err| {
                    panic!(
                        "discussion promote {} payload violates spec: {err}\npayload: {}",
                        event.kind.as_str(),
                        serde_json::to_string_pretty(&event.payload).unwrap()
                    );
                });
        }
    }
}
