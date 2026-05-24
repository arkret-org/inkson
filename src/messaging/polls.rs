//! G3.Y2 — poll composer + result tally state.
//!
//! Wire shape (spec: `models/content-types.md §4.9`):
//! * `cx.content.poll.create` — `{ poll_id, question, options: [{id, label}],
//!   max_selections, closes_at? }`
//! * `cx.content.poll.response` — `{ poll_id, choice }` (single-select) or
//!   `{ poll_id, choices: [id, ...] }` (multi-select)
//! * `cx.content.poll.close` — `{ poll_id }`
//!
//! The local 1.0 UI hides the composer unless the `experimental-polls`
//! feature is enabled. Builders remain compiled so the canonical wire
//! shape stays covered by unit tests while soland's reducer is completed.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::operation::{EventEnvelope, OperationBuilder, uuid_v7};

/// Whether the local UI should expose poll composer / vote controls.
pub fn polls_enabled() -> bool {
    cfg!(feature = "experimental-polls")
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

/// Aggregate state of a poll as it renders in the timeline.
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

    pub fn close(&mut self) {
        self.closed = true;
    }
}

/// Build the `cx.content.poll.create` envelope for the wire.
pub fn build_poll_create_op(
    space_id: &str,
    actor: &str,
    flow_id: &str,
    poll_id: &str,
    draft: &PollDraft,
) -> EventEnvelope {
    let options: Vec<Value> = draft
        .options
        .iter()
        .filter(|opt| !opt.trim().is_empty())
        .enumerate()
        .map(|(idx, label)| json!({"id": format!("opt-{idx}"), "label": label.trim()}))
        .collect();
    OperationBuilder::new(space_id, actor, "cx.content.poll.create")
        .target_ref(flow_id)
        .body(json!({
            "poll_id": poll_id,
            "flow_id": flow_id,
            "question": draft.question.trim(),
            "options": options,
            "max_selections": draft.max_selections.max(1),
        }))
        .build("yougen")
}

/// Build the `cx.content.poll.response` envelope for a single-select
/// vote. The multi-select variant is left for the soland-side reducer
/// work referenced above.
pub fn build_poll_vote_op(
    space_id: &str,
    actor: &str,
    poll_id: &str,
    option_id: &str,
) -> EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.content.poll.response")
        .target_ref(poll_id)
        .body(json!({
            "poll_id": poll_id,
            "choice": option_id,
        }))
        .build("yougen")
}

/// Build the `cx.content.poll.close` envelope.
pub fn build_poll_close_op(space_id: &str, actor: &str, poll_id: &str) -> EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.content.poll.close")
        .target_ref(poll_id)
        .body(json!({"poll_id": poll_id}))
        .build("yougen")
}

/// Generate a fresh poll id (`poll-<uuid>`).
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
    fn build_poll_create_op_includes_options() {
        let mut draft = PollDraft::new();
        draft.set_question("ship?".into());
        draft.set_option(0, "yes".into());
        draft.set_option(1, "no".into());
        let op = build_poll_create_op(
            "cx:space:1",
            "did:web:alice.example",
            "cx:flow:1",
            "poll-x",
            &draft,
        );
        assert_eq!(op.kind, "cx.content.poll.create");
        let options = op
            .payload
            .get("options")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(options.len(), 2);
    }
}
