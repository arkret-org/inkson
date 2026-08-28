//! G3.Y2 — @mention picker state.
//!
//! The chat composer hosts an @mention picker that surfaces the current
//! Space's participants as the user types `@`. We keep the picker state
//! in a small struct so the chat view can render `mention-picker` /
//! `mention-suggestion` / `mention-chip` testids off of a single
//! signal instead of juggling three.

use serde::{Deserialize, Serialize};

/// One row in the mention picker dropdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionCandidate {
    pub subject_id: String,
    pub display_name: String,
    #[serde(default)]
    pub insert_label: String,
    #[serde(default)]
    pub subtitle: String,
    #[serde(default)]
    pub is_agent: bool,
    #[serde(default)]
    pub controller_subject_id: String,
    #[serde(default)]
    pub controller_handle_at_time: String,
    #[serde(default)]
    pub agent_slug_at_time: String,
}

impl MentionCandidate {
    pub fn insert_label(&self) -> &str {
        if self.insert_label.trim().is_empty() {
            &self.display_name
        } else {
            &self.insert_label
        }
    }
}

/// Composer-side state for the @mention picker.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MentionPickerState {
    /// `true` when the picker dropdown is open.
    pub open: bool,
    /// Active filter, derived from the text after the most recent `@`.
    pub query: String,
    /// Byte range in the draft for the active `@...` token. The picker
    /// replaces this exact range so choosing a member after typing `@bo`
    /// updates the text at the cursor position instead of appending.
    pub active_range: Option<(usize, usize)>,
    /// Subject IDs already inserted into the current draft. The picker uses
    /// this to render `mention-chip` rows above the textarea and to
    /// avoid suggesting the same actor twice.
    pub inserted: Vec<MentionCandidate>,
}

impl MentionPickerState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(&mut self) {
        self.open = true;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
        self.active_range = None;
    }

    pub fn set_query(&mut self, query: String) {
        self.query = query;
    }

    pub fn set_active_token(&mut self, query: String, start: usize, end: usize) {
        self.open = true;
        self.query = query;
        self.active_range = Some((start, end));
    }

    /// Filter `candidates` down to those whose `display_name` or `subject_id`
    /// matches the current query (case-insensitive substring). The popover is
    /// scroll-bounded by CSS, so the model keeps every match available; this
    /// matters for controllers with more than a handful of personal agents.
    pub fn filter<'a>(&self, candidates: &'a [MentionCandidate]) -> Vec<&'a MentionCandidate> {
        let q = self.query.trim().to_ascii_lowercase();
        let inserted: std::collections::BTreeSet<&str> = self
            .inserted
            .iter()
            .map(|c| c.subject_id.as_str())
            .collect();
        candidates
            .iter()
            .filter(|c| !inserted.contains(c.subject_id.as_str()))
            .filter(|c| {
                if q.is_empty() {
                    true
                } else {
                    c.display_name.to_ascii_lowercase().contains(&q)
                        || c.insert_label.to_ascii_lowercase().contains(&q)
                        || c.subtitle.to_ascii_lowercase().contains(&q)
                        || c.subject_id.to_ascii_lowercase().contains(&q)
                }
            })
            .collect()
    }

    /// Add a candidate to the `inserted` list. Returns `true` if the
    /// candidate was new, `false` if it was already present.
    pub fn insert(&mut self, candidate: MentionCandidate) -> bool {
        if self
            .inserted
            .iter()
            .any(|existing| existing.subject_id == candidate.subject_id)
        {
            return false;
        }
        self.inserted.push(candidate);
        true
    }

    /// Drop the chip with the given subject ID, if present.
    pub fn remove(&mut self, subject_id: &str) {
        self.inserted.retain(|c| c.subject_id != subject_id);
    }

    /// Clear all picker state — typically called when the user has
    /// sent or discarded the draft.
    pub fn clear(&mut self) {
        self.inserted.clear();
        self.query.clear();
        self.open = false;
        self.active_range = None;
    }
}

pub fn active_mention_token_at_end(value: &str) -> Option<(String, usize, usize)> {
    let end = value.len();
    let token_start = value
        .char_indices()
        .rev()
        .find(|(_, ch)| ch.is_whitespace())
        .map(|(idx, ch)| idx + ch.len_utf8())
        .unwrap_or(0);
    let token = &value[token_start..end];
    let at_offset = token.rfind('@')?;
    let start = token_start + at_offset;
    if start > 0 {
        let before = value[..start].chars().next_back();
        if before.is_some_and(|ch| !ch.is_whitespace() && !matches!(ch, '(' | '[' | '{')) {
            return None;
        }
    }
    let query = &value[start + '@'.len_utf8()..end];
    if query.chars().any(|ch| ch.is_whitespace()) {
        return None;
    }
    Some((query.to_owned(), start, end))
}

/// Detect the reserved current-controller alias without mistaking an email,
/// a longer handle, or an agent selector (`@me/<slug>`) for the self mention.
pub fn contains_self_mention_token(value: &str) -> bool {
    value.match_indices("@me").any(|(start, token)| {
        let end = start + token.len();
        let before = value[..start].chars().next_back();
        let after = value[end..].chars().next();
        let left_boundary = before.is_none_or(|ch| {
            ch.is_whitespace() || matches!(ch, '(' | '[' | '{' | '<' | '"' | '\'')
        });
        let right_boundary = after.is_none_or(|ch| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    ')' | ']' | '}' | '>' | '"' | '\'' | ',' | '.' | ';' | '!' | '?'
                )
        });
        left_boundary && right_boundary
    })
}

pub fn replace_active_mention_token(
    value: &str,
    active_range: Option<(usize, usize)>,
    insert_label: &str,
) -> String {
    let mention = format!("@{}", insert_label.trim().trim_start_matches('@'));
    let Some((start, end)) = active_range else {
        let needs_space = value
            .chars()
            .next_back()
            .is_some_and(|ch| !ch.is_whitespace());
        return format!("{value}{}{mention} ", if needs_space { " " } else { "" });
    };
    if start > end
        || end > value.len()
        || !value.is_char_boundary(start)
        || !value.is_char_boundary(end)
    {
        let needs_space = value
            .chars()
            .next_back()
            .is_some_and(|ch| !ch.is_whitespace());
        return format!("{value}{}{mention} ", if needs_space { " " } else { "" });
    }
    let before = &value[..start];
    let after = &value[end..];
    let spacer = if after.chars().next().is_some_and(|ch| ch.is_whitespace()) {
        ""
    } else {
        " "
    };
    format!("{before}{mention}{spacer}{after}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> MentionCandidate {
        MentionCandidate {
            subject_id: "ak:did_core:web:alice.example".into(),
            display_name: "Alice".into(),
            insert_label: String::new(),
            subtitle: String::new(),
            is_agent: false,
            controller_subject_id: String::new(),
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        }
    }

    fn bob() -> MentionCandidate {
        MentionCandidate {
            subject_id: "ak:did_core:web:bob.example".into(),
            display_name: "Bob".into(),
            insert_label: String::new(),
            subtitle: String::new(),
            is_agent: false,
            controller_subject_id: String::new(),
            controller_handle_at_time: String::new(),
            agent_slug_at_time: String::new(),
        }
    }

    #[test]
    fn picker_filters_by_substring() {
        let mut state = MentionPickerState::new();
        state.set_query("ali".into());
        let candidates = vec![alice(), bob()];
        let filtered = state.filter(&candidates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].subject_id, "ak:did_core:web:alice.example");
    }

    #[test]
    fn picker_filters_agent_candidates_by_selector_label() {
        let mut state = MentionPickerState::new();
        state.set_query("summary".into());
        let candidates = vec![
            alice(),
            MentionCandidate {
                subject_id: "ak:did_core:web:agents.example:summary".into(),
                display_name: "Summary Assistant".into(),
                insert_label: "alice:example.com/summary".into(),
                subtitle: "agent of alice:example.com".into(),
                is_agent: true,
                controller_subject_id: "ak:did_core:web:example.com:users:alice".into(),
                controller_handle_at_time: "alice:example.com".into(),
                agent_slug_at_time: "summary".into(),
            },
        ];
        let filtered = state.filter(&candidates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].subject_id, "ak:did_core:web:agents.example:summary");
        assert_eq!(filtered[0].insert_label(), "alice:example.com/summary");
    }

    #[test]
    fn picker_hides_already_inserted_candidates() {
        let mut state = MentionPickerState::new();
        state.insert(alice());
        let candidates = vec![alice(), bob()];
        let filtered = state.filter(&candidates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].subject_id, "ak:did_core:web:bob.example");
    }

    #[test]
    fn picker_keeps_all_owned_agent_matches_available() {
        let candidates = (0..12)
            .map(|index| MentionCandidate {
                subject_id: format!("ak:did_core:web:agents.example:agent-{index}"),
                display_name: format!("agent-{index}"),
                insert_label: format!("me/agent-{index}"),
                subtitle: "Your agent".to_owned(),
                is_agent: true,
                controller_subject_id: "ak:did_core:web:alice.example".to_owned(),
                controller_handle_at_time: "alice:example.com".to_owned(),
                agent_slug_at_time: format!("agent-{index}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(MentionPickerState::new().filter(&candidates).len(), 12);
    }

    #[test]
    fn insert_is_idempotent() {
        let mut state = MentionPickerState::new();
        assert!(state.insert(alice()));
        assert!(!state.insert(alice()));
        assert_eq!(state.inserted.len(), 1);
    }

    #[test]
    fn clear_removes_all_picker_state() {
        let mut state = MentionPickerState::new();
        state.insert(alice());
        state.set_active_token("ali".to_owned(), 6, 10);

        state.clear();

        assert_eq!(state, MentionPickerState::new());
    }

    #[test]
    fn active_mention_token_tracks_query_at_current_input_end() {
        assert_eq!(
            active_mention_token_at_end("hello @bo"),
            Some(("bo".to_owned(), 6, 9))
        );
        assert_eq!(
            active_mention_token_at_end("hello (@ali"),
            Some(("ali".to_owned(), 7, 11))
        );
        assert!(active_mention_token_at_end("email@host").is_none());
        assert!(active_mention_token_at_end("hello @bob done").is_none());
    }

    #[test]
    fn self_alias_requires_an_exact_standalone_token() {
        assert!(contains_self_mention_token("ping @me"));
        assert!(contains_self_mention_token("ping (@me), please"));
        assert!(!contains_self_mention_token("mail@me"));
        assert!(!contains_self_mention_token("@media"));
        assert!(!contains_self_mention_token("@me:example.com"));
        assert!(!contains_self_mention_token("ask @me/summary"));
    }

    #[test]
    fn replace_active_mention_token_replaces_in_place() {
        assert_eq!(
            replace_active_mention_token("hello @bo", Some((6, 9)), "bob:local.host"),
            "hello @bob:local.host "
        );
        assert_eq!(
            replace_active_mention_token("@bo please", Some((0, 3)), "bob:local.host"),
            "@bob:local.host please"
        );
        assert_eq!(
            replace_active_mention_token("hello", None, "bob:local.host"),
            "hello @bob:local.host "
        );
    }
}
