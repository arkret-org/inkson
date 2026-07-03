//! G3.Y2 — poll composer + result tally state.
//!
//! Wire shape (spec: `models/content-types.md §4.9`):
//! * `ck.message.create` with `content.kind = ck.content.poll` creates a poll.
//! * `ck.message.create` with `content.kind = ck.content.poll.response` records a response.
//! * `ck.message.create` with `content.kind = ck.content.poll.close` closes a poll.
//!
//! Polls are enabled in the local 1.0 UI because soland now projects the
//! content-type reducer state.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::operation::{OperationBuilder, uuid_v7};

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

    pub fn from_content(message_id: String, content: &Value) -> Option<Self> {
        if content_kind(content) != Some("ck.content.poll") {
            return None;
        }
        let poll_id = poll_id_from_content(content).unwrap_or_else(|| message_id.clone());
        let question = content
            .get("question")
            .and_then(Value::as_str)
            .or_else(|| content.get("body").and_then(Value::as_str))
            .or_else(|| {
                content
                    .get("poll")
                    .and_then(|poll| poll.get("question"))
                    .and_then(text_body)
            })?
            .trim()
            .to_owned();
        let options = poll_options_from_content(content);
        if question.is_empty() || options.len() < 2 {
            return None;
        }
        let mut card = Self {
            poll_id,
            message_id,
            question,
            votes: vec![Vec::new(); options.len()],
            options,
            max_selections: content
                .get("max_selections")
                .and_then(Value::as_u64)
                .or_else(|| {
                    content
                        .get("poll")
                        .and_then(|poll| poll.get("max_selections"))
                        .and_then(Value::as_u64)
                })
                .unwrap_or(1)
                .max(1) as u32,
            closed: content
                .get("closed")
                .and_then(Value::as_bool)
                .or_else(|| {
                    content
                        .get("poll")
                        .and_then(|poll| poll.get("closed"))
                        .and_then(Value::as_bool)
                })
                .unwrap_or(false),
        };
        if let Some(results) = content.get("results").and_then(Value::as_array) {
            for row in results {
                let Some(option_id) = row.get("id").and_then(Value::as_str) else {
                    continue;
                };
                let Some(index) = card
                    .options
                    .iter()
                    .position(|option| option.id == option_id)
                else {
                    continue;
                };
                if let Some(voters) = row.get("voters").and_then(Value::as_array) {
                    card.votes[index] = voters
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect();
                }
            }
        }
        Some(card)
    }
}

pub fn poll_response_from_content(content: &Value) -> Option<(String, Vec<String>)> {
    if content_kind(content) != Some("ck.content.poll.response") {
        return None;
    }
    let poll_id = poll_id_from_content(content)?;
    let choices = content
        .get("choices")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .or_else(|| {
            content
                .get("choice")
                .and_then(Value::as_str)
                .map(|choice| vec![choice.to_owned()])
        })
        .unwrap_or_default();
    if choices.is_empty() {
        None
    } else {
        Some((poll_id, choices))
    }
}

pub fn poll_close_id_from_content(content: &Value) -> Option<String> {
    if content_kind(content) == Some("ck.content.poll.close") {
        poll_id_from_content(content)
    } else {
        None
    }
}

fn content_kind(content: &Value) -> Option<&str> {
    content.get("kind").and_then(Value::as_str)
}

fn poll_id_from_content(content: &Value) -> Option<String> {
    content
        .get("poll_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("id"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(ToOwned::to_owned)
        })
}

fn text_body(value: &Value) -> Option<&str> {
    value.as_str().or_else(|| {
        value
            .get("body")
            .or_else(|| value.get("label"))
            .and_then(Value::as_str)
    })
}

fn poll_options_from_content(content: &Value) -> Vec<PollOption> {
    let options = content
        .get("options")
        .and_then(Value::as_array)
        .or_else(|| {
            content
                .get("poll")
                .and_then(|poll| poll.get("answers"))
                .and_then(Value::as_array)
        });
    options
        .map(|items| {
            items
                .iter()
                .enumerate()
                .filter_map(|(idx, item)| {
                    if let Some(label) = item.as_str().filter(|value| !value.trim().is_empty()) {
                        return Some(PollOption {
                            id: format!("opt-{idx}"),
                            label: label.trim().to_owned(),
                        });
                    }
                    let id = item
                        .get("id")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| format!("opt-{idx}"));
                    let label = item
                        .get("label")
                        .and_then(Value::as_str)
                        .or_else(|| item.get("text").and_then(text_body))?
                        .trim()
                        .to_owned();
                    if label.is_empty() {
                        None
                    } else {
                        Some(PollOption { id, label })
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

// YOU-02-001: these helpers return `Result` instead of panicking — the
// realm/strand ids they parse come from server-synced UI state, and a
// non-canonical id must not abort the client (wasm panic = blank page).
fn sdk_payload_value(result: cokret_sdk::Result<Value>, context: &str) -> anyhow::Result<Value> {
    result.map_err(|err| anyhow::anyhow!("{context}: {err}"))
}

fn strand_id_value(value: &str) -> anyhow::Result<cokret_sdk::StrandId> {
    cokret_sdk::StrandId::new(value.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid strand id {value:?}: {err:?}"))
}

/// Build the `ck.content.poll.create` event for the wire.
pub fn build_poll_create_op(
    realm_id: &str,
    actor: &str,
    strand_id: &str,
    poll_id: &str,
    draft: &PollDraft,
) -> anyhow::Result<cokret_sdk::Event> {
    let options: Vec<Value> = draft
        .options
        .iter()
        .filter(|opt| !opt.trim().is_empty())
        .enumerate()
        .map(|(idx, label)| json!({"id": format!("opt-{idx}"), "label": label.trim()}))
        .collect();
    let content = cokret_sdk::ContentBlock::new("ck.content.poll", draft.question.trim())
        .with_field("poll_id", json!(poll_id))
        .with_field("question", json!(draft.question.trim()))
        .with_field("options", Value::Array(options))
        .with_field("max_selections", json!(draft.max_selections.max(1)));
    let payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "poll create content serialize")?,
    )
    .with_message_id(poll_id);
    let mut event = OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(strand_id)
    .body(sdk_payload_value(
        payload.to_value(),
        "poll ck.message.create payload serialize",
    )?)
    .build_sdk_event("yougen")?;
    let message_ref = event
        .event_id
        .as_str()
        .replacen("ck:event:", "ck:message:", 1);
    event.content["message_id"] = json!(message_ref);
    event.content["content"]["message_id"] = json!(message_ref);
    Ok(event)
}

/// Build the `ck.content.poll.response` event for a single-select
/// vote. The multi-select variant is left for the soland-side reducer
/// work referenced above.
pub fn build_poll_vote_op(
    realm_id: &str,
    actor: &str,
    poll_id: &str,
    option_id: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    let strand_id = strand_id_from_realm_id(realm_id);
    let content = cokret_sdk::ContentBlock::new("ck.content.poll.response", "poll response")
        .with_field("poll_id", json!(poll_id))
        .with_field("choice", json!(option_id));
    let payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(&strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "poll vote content serialize")?,
    );
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(poll_id)
    .body(sdk_payload_value(
        payload.to_value(),
        "poll vote ck.message.create payload serialize",
    )?)
    .build_sdk_event("yougen")
}

/// Build the `ck.content.poll.close` event.
pub fn build_poll_close_op(
    realm_id: &str,
    actor: &str,
    poll_id: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    let strand_id = strand_id_from_realm_id(realm_id);
    let content = cokret_sdk::ContentBlock::new("ck.content.poll.close", "poll closed")
        .with_field("poll_id", json!(poll_id));
    let payload = cokret_sdk::MessageCreatePayload::with_content(
        strand_id_value(&strand_id)?,
        "discussion",
        sdk_payload_value(content.to_value(), "poll close content serialize")?,
    );
    OperationBuilder::new(
        realm_id,
        actor,
        cokret_sdk::events::kinds::EventKind::MessageCreate,
    )
    .target_ref(poll_id)
    .body(sdk_payload_value(
        payload.to_value(),
        "poll close ck.message.create payload serialize",
    )?)
    .build_sdk_event("yougen")
}

/// Generate a fresh poll id (`poll-<uuid>`).
pub fn new_poll_id() -> String {
    format!("poll-{}", uuid_v7())
}

fn strand_id_from_realm_id(realm_id: &str) -> String {
    let suffix = realm_id
        .trim()
        .strip_prefix("ck:realm:")
        .unwrap_or_else(|| realm_id.trim());
    format!("ck:strand:{suffix}")
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
    fn build_poll_create_op_includes_options() {
        let mut draft = PollDraft::new();
        draft.set_question("ship?".into());
        draft.set_option(0, "yes".into());
        draft.set_option(1, "no".into());
        let op = build_poll_create_op(
            "ck:realm:01904100-0000-7000-8000-000000000010",
            "did:web:alice.example",
            "ck:strand:01904100-0000-7000-8000-000000000011",
            "poll-x",
            &draft,
        )
        .expect("builds");
        assert_eq!(op.kind.as_str(), "ck.message.create");
        assert!(op.content.get("body").is_none());
        assert!(op.content.get("encrypted").is_none());
        assert!(op.content.get("poll_id").is_none());
        let options = op
            .content
            .get("content")
            .and_then(|content| content.get("options"))
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(options.len(), 2);
        cokret_sdk::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(op.kind.as_str(), &op.content)
            .unwrap();
    }

    #[test]
    fn poll_card_from_content_reads_results() {
        let content = json!({
            "kind": "ck.content.poll",
            "poll_id": "poll-1",
            "question": "ship?",
            "options": [
                {"id": "yes", "label": "Yes"},
                {"id": "no", "label": "No"}
            ],
            "results": [
                {"id": "yes", "voters": ["did:web:alice.example"]},
                {"id": "no", "voters": []}
            ]
        });
        let card = PollCard::from_content("ck:event:1".to_owned(), &content).unwrap();
        assert_eq!(card.poll_id, "poll-1");
        assert_eq!(card.votes_for(0), 1);
        assert_eq!(card.votes_for(1), 0);
    }
}
