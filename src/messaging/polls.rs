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
use serde_json::{Value, json};

use crate::operation::{OperationBuilder, uuid_v7};
use crate::payload::{sdk_payload_value, strand_id_value};

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
    pub poll_id: String,
    pub message_id: String,
    pub question: String,
    pub options: Vec<PollOption>,
    /// One Vec per option containing the DIDs that currently vote for
    /// it. Same ordering as `options`.
    pub votes: Vec<Vec<String>>,
    pub max_selections: u32,
    pub closed: bool,
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
        let votes = vec![Vec::<String>::new(); options.len()];
        Self {
            poll_id: message_id.clone(),
            message_id,
            question: draft.question.trim().to_owned(),
            options,
            votes,
            max_selections: draft.max_selections.max(1),
            closed: false,
        }
    }

    /// Total non-deduplicated vote tally — used by `poll-total-votes`.
    pub fn total_votes(&self) -> usize {
        self.votes.iter().map(|v| v.len()).sum()
    }

    pub fn votes_for(&self, option_index: usize) -> usize {
        self.votes.get(option_index).map(|v| v.len()).unwrap_or(0)
    }

    /// Returns `true` if `actor` has currently voted for *any* option
    /// in this poll.
    pub fn actor_has_voted(&self, actor: &str) -> bool {
        self.votes
            .iter()
            .any(|opt_voters| opt_voters.iter().any(|did| did == actor))
    }

    /// Cast `actor`'s vote for `option_index`. For single-select polls
    /// (`max_selections == 1`) this removes any previous vote by the
    /// same actor on the same poll first (vote replacement). Returns
    /// `true` if the cast succeeded, `false` if the poll is closed or
    /// the index is out of bounds.
    pub fn vote(&mut self, actor: &str, option_index: usize) -> bool {
        if self.closed {
            return false;
        }
        if option_index >= self.options.len() {
            return false;
        }
        if self.max_selections == 1 {
            for opt in &mut self.votes {
                opt.retain(|did| did != actor);
            }
        }
        let voters = &mut self.votes[option_index];
        if !voters.iter().any(|did| did == actor) {
            voters.push(actor.to_owned());
        }
        true
    }

    pub fn vote_choices(&mut self, actor: &str, option_ids: &[String]) -> bool {
        if self.closed || option_ids.is_empty() {
            return false;
        }
        for voters in &mut self.votes {
            voters.retain(|did| did != actor);
        }
        let limit = self.max_selections.max(1) as usize;
        let mut changed = false;
        for option_id in option_ids.iter().take(limit) {
            if let Some(index) = self
                .options
                .iter()
                .position(|option| &option.id == option_id)
            {
                let voters = &mut self.votes[index];
                if !voters.iter().any(|did| did == actor) {
                    voters.push(actor.to_owned());
                    changed = true;
                }
            }
        }
        changed
    }

    pub fn close(&mut self) {
        self.closed = true;
    }

    /// Parse a canonical `poll_block`
    /// (`content-block-poll.schema.json#/$defs/poll_block`). `poll_ref` is
    /// the wire message id (`ak:message:<uuid7>`) carried by the enclosing
    /// `ak.message.create` — it becomes the card's `poll_id` (the identity
    /// `poll_response.poll_ref` points at); `message_id` stays the local
    /// render identity. Non-canonical shapes (missing `poll`, unknown
    /// `poll.kind`) fail closed to `None`.
    pub fn from_content(
        message_id: String,
        poll_ref: Option<&str>,
        content: &Value,
    ) -> Option<Self> {
        if content_kind(content) != Some("ak.content.poll") {
            return None;
        }
        let poll = content.get("poll")?;
        // `poll.kind` is a closed enum (const "disclosed" in v1); an unknown
        // tally-disclosure mode must not render as if it were disclosed.
        if poll.get("kind").and_then(Value::as_str) != Some("disclosed") {
            return None;
        }
        let question = poll
            .get("question")
            .and_then(|question| question.get("body"))
            .and_then(Value::as_str)
            .or_else(|| content.get("body").and_then(Value::as_str))?
            .trim()
            .to_owned();
        let options: Vec<PollOption> = poll
            .get("answers")
            .and_then(Value::as_array)?
            .iter()
            .filter_map(|answer| {
                let id = answer.get("id").and_then(Value::as_str)?.to_owned();
                let label = answer
                    .get("text")
                    .and_then(|text| text.get("body"))
                    .and_then(Value::as_str)?
                    .trim()
                    .to_owned();
                if id.is_empty() || label.is_empty() {
                    None
                } else {
                    Some(PollOption { id, label })
                }
            })
            .collect();
        if question.is_empty() || options.is_empty() {
            return None;
        }
        Some(Self {
            poll_id: poll_ref
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| message_id.clone()),
            message_id,
            question,
            votes: vec![Vec::new(); options.len()],
            options,
            max_selections: poll
                .get("max_selections")
                .and_then(Value::as_u64)
                .unwrap_or(1)
                .max(1) as u32,
            // Poll close has no spec v1 carrier — `closed` is local UI state.
            closed: false,
        })
    }
}

/// Parse a canonical `poll_response_block`
/// (`content-block-poll.schema.json#/$defs/poll_response_block`), returning
/// `(poll_ref, selections)`. An empty `selections` array is schema-legal but
/// tallies nothing, so it returns `None`.
pub fn poll_response_from_content(content: &Value) -> Option<(String, Vec<String>)> {
    if content_kind(content) != Some("ak.content.poll.response") {
        return None;
    }
    let response = content.get("poll_response")?;
    let poll_ref = response
        .get("poll_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?
        .to_owned();
    let selections = response
        .get("selections")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if selections.is_empty() {
        None
    } else {
        Some((poll_ref, selections))
    }
}

fn content_kind(content: &Value) -> Option<&str> {
    content.get("kind").and_then(Value::as_str)
}

/// Build the canonical `poll_block` message
/// (`content-block-poll.schema.json#/$defs/poll_block`) as a
/// `ak.message.create` event. The poll's wire identity is the stamped
/// `message_id` (`ak:message:<uuid7>` derived from the event id) — callers
/// read it back from `event.payload["message_id"]` to address later
/// `poll_response.poll_ref`s at this poll.
pub fn build_poll_create_op(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    draft: &PollDraft,
) -> anyhow::Result<arkret_sdk::Event> {
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
    let mut event = OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(strand_id)
    .body(sdk_payload_value(
        payload.to_value(),
        "poll ak.message.create payload serialize",
    )?)
    .build_sdk_event("inkson")?;
    let message_ref = event
        .event_id
        .as_str()
        .replacen("ak:event:", "ak:message:", 1);
    event
        .payload
        .insert("message_id".to_owned(), json!(message_ref));
    Ok(event)
}

/// Read the stamped wire message id (`ak:message:<uuid7>`) back from a
/// freshly built poll-create event — the identity later
/// `poll_response.poll_ref`s point at.
pub fn poll_message_ref(event: &arkret_sdk::Event) -> Option<String> {
    event
        .payload
        .get("message_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

/// Build the canonical `poll_response_block`
/// (`content-block-poll.schema.json#/$defs/poll_response_block`) as a
/// `ak.message.create` event on the poll's own Strand. `poll_ref` MUST be
/// the poll message's wire id (`ak:message:<uuid7>`) — fail-closed
/// otherwise (a locally generated optimistic id never reaches the wire).
pub fn build_poll_vote_op(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    poll_ref: &str,
    selections: &[String],
) -> anyhow::Result<arkret_sdk::Event> {
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
    );
    OperationBuilder::new(
        realm_id,
        actor,
        arkret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(strand_id)
    .body(sdk_payload_value(
        payload.to_value(),
        "poll vote ak.message.create payload serialize",
    )?)
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
    fn vote_replaces_prior_vote_for_single_select() {
        let mut draft = PollDraft::new();
        draft.set_question("q?".into());
        draft.set_option(0, "a".into());
        draft.set_option(1, "b".into());
        let mut card = PollCard::from_draft("msg-1".into(), &draft);
        assert!(card.vote("did:web:alice.example", 0));
        assert_eq!(card.votes_for(0), 1);
        assert!(card.vote("did:web:alice.example", 1));
        assert_eq!(card.votes_for(0), 0);
        assert_eq!(card.votes_for(1), 1);
    }

    #[test]
    fn vote_blocked_after_close() {
        let mut draft = PollDraft::new();
        draft.set_question("q?".into());
        draft.set_option(0, "a".into());
        draft.set_option(1, "b".into());
        let mut card = PollCard::from_draft("msg-1".into(), &draft);
        card.close();
        assert!(!card.vote("did:web:alice.example", 0));
    }

    #[test]
    fn build_poll_create_op_emits_canonical_poll_block() {
        let mut draft = PollDraft::new();
        draft.set_question("ship?".into());
        draft.set_option(0, "yes".into());
        draft.set_option(1, "no".into());
        let op = build_poll_create_op(
            "ak:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ak:strand:01904100-0000-7000-8000-000000000011",
            &draft,
        )
        .expect("builds");
        assert_eq!(op.kind.as_str(), "ak.message.create");
        assert!(op.payload.get("encrypted").is_none());
        // Canonical poll_block: nested `poll` object, no flat legacy fields.
        let block = op.payload.get("content").unwrap();
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
        // The stamped wire message id is readable back for poll_ref use.
        let message_ref = poll_message_ref(&op).unwrap();
        assert!(message_ref.starts_with("ak:message:"));
        arkret_sdk::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(
                op.kind.as_str(),
                &serde_json::to_value(&op.payload).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn build_poll_vote_op_emits_canonical_poll_response_block() {
        let op = build_poll_vote_op(
            "ak:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ak:strand:01904100-0000-7000-8000-000000000011",
            "ak:message:01904100-0000-7000-8000-000000000012",
            &["opt-1".to_owned()],
        )
        .expect("builds");
        let block = op.payload.get("content").unwrap();
        assert_eq!(block["kind"], "ak.content.poll.response");
        assert!(block.get("poll_id").is_none());
        assert!(block.get("choice").is_none());
        assert_eq!(
            block["poll_response"]["poll_ref"],
            "ak:message:01904100-0000-7000-8000-000000000012"
        );
        assert_eq!(block["poll_response"]["selections"], json!(["opt-1"]));
        arkret_sdk::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(
                op.kind.as_str(),
                &serde_json::to_value(&op.payload).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn build_poll_vote_op_rejects_local_poll_ids() {
        // A locally generated optimistic id must never reach the wire as a
        // poll_ref (schema requires ak:message:<uuid7>).
        assert!(
            build_poll_vote_op(
                "ak:realm:01904100-0000-7000-8000-000000000010",
                "did:web:alice.example",
                "ak:strand:01904100-0000-7000-8000-000000000011",
                &new_poll_id(),
                &["opt-0".to_owned()],
            )
            .is_err()
        );
    }

    #[test]
    fn poll_card_from_content_parses_canonical_poll_block() {
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
        let card = PollCard::from_content(
            "ak:event:1".to_owned(),
            Some("ak:message:01904100-0000-7000-8000-000000000012"),
            &content,
        )
        .unwrap();
        assert_eq!(
            card.poll_id,
            "ak:message:01904100-0000-7000-8000-000000000012"
        );
        assert_eq!(card.message_id, "ak:event:1");
        assert_eq!(card.question, "ship?");
        assert_eq!(card.max_selections, 2);
        assert_eq!(card.options[0].id, "yes");
        assert_eq!(card.options[0].label, "Yes");
        assert!(!card.closed);
    }

    #[test]
    fn poll_card_from_content_fails_closed_on_non_canonical_shapes() {
        // Legacy flat shape (pre-canonical) — no `poll` object.
        let flat = json!({
            "kind": "ak.content.poll",
            "poll_id": "poll-1",
            "question": "ship?",
            "options": [{"id": "yes", "label": "Yes"}, {"id": "no", "label": "No"}]
        });
        assert!(PollCard::from_content("ak:event:1".to_owned(), None, &flat).is_none());
        // Unknown tally-disclosure mode.
        let undisclosed = json!({
            "kind": "ak.content.poll",
            "body": "ship?",
            "poll": {
                "kind": "hidden",
                "max_selections": 1,
                "answers": [{"id": "yes", "text": {"kind": "ak.content.text", "body": "Yes"}}]
            }
        });
        assert!(PollCard::from_content("ak:event:1".to_owned(), None, &undisclosed).is_none());
    }

    #[test]
    fn poll_response_from_content_parses_canonical_block_only() {
        let canonical = json!({
            "kind": "ak.content.poll.response",
            "body": "poll response",
            "poll_response": {
                "poll_ref": "ak:message:01904100-0000-7000-8000-000000000012",
                "selections": ["opt-0", "opt-2"]
            }
        });
        let (poll_ref, selections) = poll_response_from_content(&canonical).unwrap();
        assert_eq!(poll_ref, "ak:message:01904100-0000-7000-8000-000000000012");
        assert_eq!(selections, vec!["opt-0".to_owned(), "opt-2".to_owned()]);
        // Legacy flat shape fails closed.
        let flat = json!({
            "kind": "ak.content.poll.response",
            "poll_id": "poll-1",
            "choice": "opt-0"
        });
        assert!(poll_response_from_content(&flat).is_none());
    }
}
