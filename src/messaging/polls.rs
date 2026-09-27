//! G3.Y2 — poll composer + result tally state.
//!
//! Wire shape (spec: `models/content-types.md §4.9`, canonical schema
//! `content-block-poll.schema.json`, `additionalProperties: false`):
//! * `ak.message.create` with a `poll_block` content block `{kind: "ak.content.poll", body, poll:
//!   {kind: "disclosed", max_selections, answers: [{id, text}]}}` creates a poll.
//! * `ak.message.create` with a `poll_response_block` `{kind: "ak.content.poll.response", body,
//!   poll_response: {poll_ref: id:message, selections: [answer_id]}}` records a response.
//!
//! Closing a poll has NO carrier in spec v1 (the content-block schema's
//! `oneOf` registers only the two blocks above, and no `poll` Morph type or
//! close event kind is registered) — "closed" is therefore a local UI state
//! only and is never written to the wire.
//!
//! Polls are enabled in the local 1.0 UI because soland now projects the
//! content-type reducer state.

use serde::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;

use crate::operation::uuid_v7;
use crate::payload::strand_id_value;

/// Whether the local UI should expose poll composer / vote controls.
pub fn polls_enabled() -> bool {
    true
}

/// In-flight draft of a poll being composed by the user.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PollDraft {
    pub question: String,
    /// Always at least two entries — the composer prefills two empties
    /// and the "Add option" button pushes additional ones.
    pub options: Vec<String>,
    /// Maximum number of options a single voter may select. Defaults
    /// to 1 (single-choice).
    pub max_selections: u32,
}

impl PollDraft {
    pub fn new() -> Self {
        Self {
            question: String::new(),
            options: vec![String::new(), String::new()],
            max_selections: 1,
        }
    }

    pub fn add_option(&mut self) {
        self.options.push(String::new());
    }

    pub fn set_option(&mut self, index: usize, value: String) {
        if let Some(slot) = self.options.get_mut(index) {
            *slot = value;
        }
    }

    pub fn set_question(&mut self, value: String) {
        self.question = value;
    }

    /// `true` once the draft has a non-empty question and at least two
    /// non-blank options — the send button stays disabled below that.
    pub fn is_sendable(&self) -> bool {
        if self.question.trim().is_empty() {
            return false;
        }
        self.options
            .iter()
            .filter(|opt| !opt.trim().is_empty())
            .count()
            >= 2
    }

    pub fn clear(&mut self) {
        self.question.clear();
        self.options = vec![String::new(), String::new()];
        self.max_selections = 1;
    }
}

/// One option on a rendered poll card.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollOption {
    pub id: String,
    pub label: String,
}

/// Aggregate state of a poll as it renders in chat.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PollCard {
    pub poll_ref: Option<arkret_sdk::MessageId>,
    pub message_id: String,
    pub question: String,
    pub options: Vec<PollOption>,
    /// One Vec per option containing the complete ActorIds that currently vote for
    /// it. Same ordering as `options`.
    pub votes: Vec<Vec<arkret_sdk::ActorId>>,
    pub max_selections: u64,
    pub closed: bool,
    /// Exact accepted response identity per complete ActorId, never a local
    /// arrival-order winner. Unknown or incomplete verified input stays provisional.
    pub response_heads:
        std::collections::BTreeMap<arkret_sdk::ActorId, arkret_sdk::PollResponseHead>,
    pub provisional: bool,
    pub verified_scope: Option<arkret_sdk::ScopeRef>,
}

impl PollCard {
    pub fn from_draft(message_id: String, draft: &PollDraft) -> Self {
        let options: Vec<PollOption> = draft
            .options
            .iter()
            .filter(|opt| !opt.trim().is_empty())
            .enumerate()
            .map(|(idx, label)| PollOption {
                id: format!("opt-{idx}"),
                label: label.trim().to_owned(),
            })
            .collect();
        let votes = vec![Vec::<arkret_sdk::ActorId>::new(); options.len()];
        Self {
            poll_ref: None,
            message_id,
            question: draft.question.trim().to_owned(),
            options,
            votes,
            max_selections: u64::from(draft.max_selections.max(1)),
            closed: false,
            response_heads: Default::default(),
            provisional: true,
            verified_scope: None,
        }
    }

    /// Each complete ActorId contributes one vote, even for multiple selections.
    pub fn total_votes(&self) -> usize {
        self.votes
            .iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    pub fn votes_for(&self, option_index: usize) -> usize {
        self.votes.get(option_index).map(|v| v.len()).unwrap_or(0)
    }

    /// Returns `true` if `actor` has currently voted for *any* option
    /// in this poll.
    pub fn actor_has_voted(&self, actor: &arkret_sdk::ActorId) -> bool {
        self.votes
            .iter()
            .any(|opt_voters| opt_voters.iter().any(|did| did == actor))
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Build a view from the validated SDK definition and its accepted wire identity.
    /// The local render identity remains independent from the protocol message id.
    pub fn from_definition(
        message_id: String,
        poll_ref: &arkret_sdk::MessageId,
        definition: &arkret_models_collaboration::events_payloads::PollBlock,
    ) -> Self {
        let options: Vec<PollOption> = definition
            .poll
            .answers
            .iter()
            .map(|answer| PollOption {
                id: answer.id.clone(),
                label: answer.text.body.clone(),
            })
            .collect();
        Self {
            poll_ref: Some(poll_ref.clone()),
            message_id,
            question: definition.question_text().to_owned(),
            votes: vec![Vec::new(); options.len()],
            options,
            max_selections: definition.poll.max_selections,
            closed: false,
            response_heads: Default::default(),
            provisional: true,
            verified_scope: None,
        }
    }
}

/// Build the canonical `poll_block` message
/// (`content-block-poll.schema.json#/$defs/poll_block`) as a
/// `ak.message.create` event. The poll's wire identity is the full Event
/// identity retyped as `ak:message:<event-token>`; it is never duplicated in the create
/// payload.
pub fn build_poll_create_op(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    draft: &PollDraft,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let answers: Vec<arkret_models_collaboration::events_payloads::PollAnswer> = draft
        .options
        .iter()
        .filter(|opt| !opt.trim().is_empty())
        .enumerate()
        .map(
            |(idx, label)| arkret_models_collaboration::events_payloads::PollAnswer {
                id: format!("opt-{idx}"),
                text: arkret_sdk::ContentBlock::text(label.trim()),
            },
        )
        .collect();
    let block = arkret_models_collaboration::events_payloads::PollBlock {
        kind: arkret_models_collaboration::events_payloads::PollBlockKind::Poll,
        // `body` is the fallback text for clients without poll rendering;
        // `poll.question` is omitted so the question is read from `body`
        // (content-types.md §4.9).
        body: draft.question.trim().to_owned(),
        format: None,
        formatted_body: None,
        reply_context: None,
        poll: arkret_models_collaboration::events_payloads::PollBody {
            kind: arkret_models_collaboration::events_payloads::PollDisclosureKind::Disclosed,
            max_selections: u64::from(draft.max_selections.max(1)),
            question: None,
            answers,
        },
    };
    let payload = arkret_sdk::MessageCreatePayload::with_content(
        strand_id_value(strand_id)?,
        "discussion",
        arkret_sdk::ContentBlock::from_value(
            serde_json::to_value(&block)
                .map_err(|err| anyhow::anyhow!("poll create content serialize: {err}"))?,
        )?,
    );
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id, actor, payload,
    )
    .target_ref(strand_id)
    .build_sdk_event("inkson")
}

/// Derive the wire message id from a freshly built poll-create Event.
/// The Message id an accepted `ak.message.create` names.
///
/// `retype(event_id)`, so it only exists once the Event is accepted: this takes
/// the receipt's id rather than a draft.
pub fn poll_message_ref(kind: &arkret_sdk::EventKind, accepted_event_id: &str) -> Option<String> {
    if kind != &arkret_sdk::EventKind::MessageCreate {
        return None;
    }
    arkret_sdk::EventId::new(accepted_event_id.to_owned())
        .ok()
        .map(|event_id| {
            arkret_sdk::MessageId::from_event_id(&event_id)
                .as_str()
                .to_owned()
        })
}

/// Build the canonical `poll_response_block`
/// (`content-block-poll.schema.json#/$defs/poll_response_block`) as a
/// `ak.message.create` event on the poll's own Strand. `poll_ref` MUST be
/// the poll message's event-derived wire id (`ak:message:<event-token>`) — fail-closed
/// otherwise (a locally generated optimistic id never reaches the wire).
pub fn build_poll_vote_op(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    poll_ref: &str,
    selections: &[String],
) -> anyhow::Result<crate::operation::LocalOperation> {
    build_poll_vote_op_with_heads(realm_id, actor, strand_id, poll_ref, selections, Vec::new())
}

/// Author a replacement declaration only from accepted response Event refs
/// supplied by the caller's verified current poll projection.
pub fn build_poll_vote_op_with_heads(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    poll_ref: &str,
    selections: &[String],
    response_heads: Vec<arkret_sdk::PollResponseHead>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    if selections.is_empty() {
        anyhow::bail!("poll response requires at least one selection");
    }
    let poll_ref = arkret_sdk::MessageId::new(poll_ref.trim().to_owned())
        .map_err(|err| anyhow::anyhow!("invalid poll_ref {poll_ref:?}: {err:?}"))?;
    let block = arkret_models_collaboration::events_payloads::PollResponseBlock {
        kind: arkret_models_collaboration::events_payloads::PollResponseBlockKind::PollResponse,
        body: "poll response".to_owned(),
        format: None,
        formatted_body: None,
        reply_context: None,
        poll_response: arkret_models_collaboration::events_payloads::PollResponseBody {
            poll_ref,
            selections: selections.to_vec(),
        },
    };
    let payload = arkret_sdk::MessageCreatePayload::with_content(
        strand_id_value(strand_id)?,
        "discussion",
        arkret_sdk::ContentBlock::from_value(
            serde_json::to_value(&block)
                .map_err(|err| anyhow::anyhow!("poll vote content serialize: {err}"))?,
        )?,
    )
    .with_poll_response_heads(response_heads)?;
    crate::operation::TypedOperationBuilder::new::<arkret_sdk::event_spec::MessageCreate>(
        realm_id, actor, payload,
    )
    .target_ref(strand_id)
    .build_sdk_event("inkson")
}

/// Generate a fresh local poll id (`poll-<uuid>`), used only as the
/// optimistic local card/message identity before the create round-trip
/// stamps the wire `ak:message:` id. Never written to the wire.
pub fn new_poll_id() -> String {
    format!("poll-{}", uuid_v7())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_vote_authors_typed_response_heads_without_causal_refs() {
        let poll_event_ref = arkret_sdk::EventId::new(
            "ak:event:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu".to_owned(),
        )
        .unwrap();
        let response_event_ref = arkret_sdk::EventId::new(
            "ak:event:AfqXI4jyBJWA5HRhSr3SdFP5Qb_2V210Q00mFqUjA7_z".to_owned(),
        )
        .unwrap();
        let heads = vec![arkret_sdk::PollResponseHead {
            poll_event_ref: poll_event_ref.clone(),
            response_event_ref: response_event_ref.clone(),
        }];
        let operation = build_poll_vote_op_with_heads(
            "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
            "ak:did_core:web:alice.example",
            "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
            arkret_sdk::MessageId::from_event_id(&poll_event_ref).as_str(),
            &["opt-1".to_owned()],
            heads.clone(),
        )
        .unwrap();
        assert_eq!(
            operation.payload()["poll_response_heads"],
            serde_json::json!(heads)
        );
        crate::event_submit::queue_message_operation_for_test(&operation);
        assert!(!operation.payload().contains_key("causal_refs"));
        assert!(
            build_poll_vote_op_with_heads(
                "ak:realm:ATwcYH9whQqNBoigPl_CUBVI-Uq5clybecpwS8awgc1Q",
                "ak:did_core:web:alice.example",
                "ak:strand:AWXzIPVUImfYgHnXgbHa3_vgjelzSn9R639KPlpGif5c",
                arkret_sdk::MessageId::from_event_id(&poll_event_ref).as_str(),
                &["opt-1".to_owned()],
                vec![heads[0].clone(), heads[0].clone()],
            )
            .is_err()
        );
    }

    #[test]
    fn draft_starts_with_two_blank_options() {
        let draft = PollDraft::new();
        assert_eq!(draft.options.len(), 2);
        assert!(!draft.is_sendable());
    }

    #[test]
    fn draft_sendable_requires_question_and_two_options() {
        let mut draft = PollDraft::new();
        draft.set_question("pick one".into());
        assert!(!draft.is_sendable(), "needs two non-blank options");
        draft.set_option(0, "a".into());
        draft.set_option(1, "b".into());
        assert!(draft.is_sendable());
    }

    #[test]
    fn poll_card_from_draft_drops_blank_options() {
        let mut draft = PollDraft::new();
        draft.set_question("ship?".into());
        draft.set_option(0, "yes".into());
        draft.set_option(1, "no".into());
        draft.add_option();
        // intentionally leave the third option blank
        let card = PollCard::from_draft("msg-1".into(), &draft);
        assert_eq!(card.options.len(), 2);
        assert_eq!(card.options[0].label, "yes");
        assert_eq!(card.options[1].label, "no");
        assert_eq!(card.total_votes(), 0);
    }

    #[test]
    fn build_poll_create_op_emits_canonical_poll_block() {
        let mut draft = PollDraft::new();
        draft.set_question("ship?".into());
        draft.set_option(0, "yes".into());
        draft.set_option(1, "no".into());
        let op = build_poll_create_op(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            "did:web:alice.example",
            "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            &draft,
        )
        .expect("builds");
        crate::event_submit::queue_message_operation_for_test(&op);
        assert_eq!(op.kind().as_str(), "ak.message.create");
        assert!(!op.payload().contains_key("encrypted"));
        // Canonical poll_block: nested `poll` object, no flat fields.
        let block = op.payload().get("content").unwrap();
        assert_eq!(block["kind"], "ak.content.poll");
        assert_eq!(block["body"], "ship?");
        assert!(block.get("poll_id").is_none());
        assert!(block.get("options").is_none());
        assert!(block.get("question").is_none());
        assert_eq!(block["poll"]["kind"], "disclosed");
        assert_eq!(block["poll"]["max_selections"], 1);
        let answers = block["poll"]["answers"].as_array().unwrap();
        assert_eq!(answers.len(), 2);
        assert_eq!(answers[0]["id"], "opt-0");
        assert_eq!(answers[0]["text"]["kind"], "ak.content.text");
        assert_eq!(answers[0]["text"]["body"], "yes");
        // The wire message id is `retype(event_id)`: it exists once the poll
        // Event is authored, and it is what a later vote's `poll_ref` names.
        let authored = crate::operation::author_for_test(&op);
        let message_ref = poll_message_ref(op.kind(), authored.event_id.as_str()).unwrap();
        assert!(message_ref.starts_with("ak:message:"));
        arkret_schema_conformance::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(
                op.kind().as_str(),
                &serde_json::to_value(op.payload()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn build_poll_vote_op_emits_canonical_poll_response_block() {
        let op = build_poll_vote_op(
            "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
            "did:web:alice.example",
            "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
            "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu",
            &["opt-1".to_owned()],
        )
        .expect("builds");
        let block = op.payload().get("content").unwrap();
        assert_eq!(block["kind"], "ak.content.poll.response");
        assert!(block.get("poll_id").is_none());
        assert!(block.get("choice").is_none());
        assert_eq!(
            block["poll_response"]["poll_ref"],
            "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu"
        );
        assert_eq!(block["poll_response"]["selections"], json!(["opt-1"]));
        arkret_schema_conformance::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(
                op.kind().as_str(),
                &serde_json::to_value(op.payload()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn build_poll_vote_op_rejects_local_poll_ids() {
        // A locally generated optimistic id must never reach the wire as a
        // poll_ref (schema requires a full ak:message:<event-token> identity).
        assert!(
            build_poll_vote_op(
                "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h",
                "did:web:alice.example",
                "ak:strand:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934",
                &new_poll_id(),
                &["opt-0".to_owned()],
            )
            .is_err()
        );
    }

    #[test]
    fn poll_card_preserves_wire_identity_and_definition() {
        let content = json!({
            "kind": "ak.content.poll",
            "body": "ship?",
            "poll": {
                "kind": "disclosed",
                "max_selections": 2,
                "answers": [
                    {"id": "yes", "text": {"kind": "ak.content.text", "body": "Yes"}},
                    {"id": "no", "text": {"kind": "ak.content.text", "body": "No"}}
                ]
            }
        });
        let definition: arkret_models_collaboration::events_payloads::PollBlock =
            serde_json::from_value(content).unwrap();
        definition.validate().unwrap();
        let poll_ref = arkret_sdk::MessageId::new(
            "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu".to_owned(),
        )
        .unwrap();
        let card = PollCard::from_definition(
            "ak:event:A42FkwFdQPw7aC_yPcdlVU5ZjKLAnFCbmrXTVRJTNhRc".to_owned(),
            &poll_ref,
            &definition,
        );
        assert_eq!(
            card.poll_ref.as_ref().unwrap().as_str(),
            "ak:message:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu"
        );
        assert_eq!(
            card.message_id,
            "ak:event:A42FkwFdQPw7aC_yPcdlVU5ZjKLAnFCbmrXTVRJTNhRc"
        );
        assert_eq!(card.question, "ship?");
        assert_eq!(card.max_selections, 2);
        assert_eq!(card.options[0].id, "yes");
        assert_eq!(card.options[0].label, "Yes");
        assert!(!card.closed);
    }
}
