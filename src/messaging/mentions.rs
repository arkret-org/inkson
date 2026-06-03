//! G3.Y2 — @mention picker state + sidecar hash helper.
//!
//! The chat composer hosts an @mention picker that surfaces the current
//! Space's participants as the user types `@`. We keep the picker state
//! in a small struct so the chat view can render `mention-picker` /
//! `mention-suggestion` / `mention-chip` testids off of a single
//! signal instead of juggling three.
//!
//! The sidecar-hash helper covers the E2EE notification routing path
//! described in `discovery/push-notifications.md §4.5` and the
//! `chat-advanced.md` spec — the server must be able to route a
//! notification to the mentioned actor without learning that actor's
//! DID in plaintext. We compute `SHA256(salt || did)` and surface it
//! as `content.mention_sidecar_hash` inside the outgoing
//! `ck.message.create` payload.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One row in the mention picker dropdown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionCandidate {
    pub did: String,
    pub display_name: String,
}

/// Composer-side state for the @mention picker.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MentionPickerState {
    /// `true` when the picker dropdown is open.
    pub open: bool,
    /// Active filter, derived from the text after the most recent `@`.
    pub query: String,
    /// DIDs already inserted into the current draft. The picker uses
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
    }

    pub fn set_query(&mut self, query: String) {
        self.query = query;
    }

    /// Filter `candidates` down to those whose `display_name` or `did`
    /// matches the current query (case-insensitive substring), capped
    /// at 8 rows to keep the picker compact.
    pub fn filter<'a>(&self, candidates: &'a [MentionCandidate]) -> Vec<&'a MentionCandidate> {
        let q = self.query.trim().to_ascii_lowercase();
        let inserted: std::collections::BTreeSet<&str> =
            self.inserted.iter().map(|c| c.did.as_str()).collect();
        candidates
            .iter()
            .filter(|c| !inserted.contains(c.did.as_str()))
            .filter(|c| {
                if q.is_empty() {
                    true
                } else {
                    c.display_name.to_ascii_lowercase().contains(&q)
                        || c.did.to_ascii_lowercase().contains(&q)
                }
            })
            .take(8)
            .collect()
    }

    /// Add a candidate to the `inserted` list. Returns `true` if the
    /// candidate was new, `false` if it was already present.
    pub fn insert(&mut self, candidate: MentionCandidate) -> bool {
        if self
            .inserted
            .iter()
            .any(|existing| existing.did == candidate.did)
        {
            return false;
        }
        self.inserted.push(candidate);
        true
    }

    /// Drop the chip with the given DID, if present.
    pub fn remove(&mut self, did: &str) {
        self.inserted.retain(|c| c.did != did);
    }

    /// Clear all picker state — typically called when the user has
    /// sent or discarded the draft.
    pub fn clear(&mut self) {
        self.inserted.clear();
        self.query.clear();
        self.open = false;
    }
}

/// E2EE-safe mention routing hash.
///
/// Per `discovery/push-notifications.md §4.5`, when the Space is
/// encrypted the client MUST NOT put `mentions: [did, ...]` on the
/// outer event in plaintext — the server only sees a list of opaque
/// hashes (`content.mention_sidecar_hash`) it can match against per-actor
/// inbox subscriptions without learning the mentioned DID.
///
/// `salt` is the per-Space mention salt issued by soland; until that
/// projection exists, callers pass the space_id as a stand-in (the
/// hash is still collision-resistant against random DIDs; the privacy
/// guarantee just degrades to "server already knew the space_id").
///
/// Returns lowercase hex.
pub fn mention_sidecar_hash(salt: &str, did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(b"|");
    hasher.update(did.as_bytes());
    let out = hasher.finalize();
    let mut hex = String::with_capacity(out.len() * 2);
    for byte in out {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

/// Build the full sidecar hash list for a `ck.message.create` payload.
/// The output is `["hash1", "hash2", ...]` matching the wire shape
/// expected by the notification routing layer.
pub fn mention_sidecar_hashes(salt: &str, mentioned_dids: &[String]) -> Vec<String> {
    mentioned_dids
        .iter()
        .map(|did| mention_sidecar_hash(salt, did))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alice() -> MentionCandidate {
        MentionCandidate {
            did: "did:web:alice.example".into(),
            display_name: "Alice".into(),
        }
    }

    fn bob() -> MentionCandidate {
        MentionCandidate {
            did: "did:web:bob.example".into(),
            display_name: "Bob".into(),
        }
    }

    #[test]
    fn picker_filters_by_substring() {
        let mut state = MentionPickerState::new();
        state.set_query("ali".into());
        let candidates = vec![alice(), bob()];
        let filtered = state.filter(&candidates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].did, "did:web:alice.example");
    }

    #[test]
    fn picker_hides_already_inserted_candidates() {
        let mut state = MentionPickerState::new();
        state.insert(alice());
        let candidates = vec![alice(), bob()];
        let filtered = state.filter(&candidates);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].did, "did:web:bob.example");
    }

    #[test]
    fn insert_is_idempotent() {
        let mut state = MentionPickerState::new();
        assert!(state.insert(alice()));
        assert!(!state.insert(alice()));
        assert_eq!(state.inserted.len(), 1);
    }

    #[test]
    fn sidecar_hash_is_deterministic_and_hex() {
        let hash_a = mention_sidecar_hash("salt", "did:web:alice.example");
        let hash_b = mention_sidecar_hash("salt", "did:web:alice.example");
        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a.len(), 64); // SHA-256 hex
        assert!(hash_a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sidecar_hash_changes_with_salt() {
        let a = mention_sidecar_hash("salt-1", "did:web:alice.example");
        let b = mention_sidecar_hash("salt-2", "did:web:alice.example");
        assert_ne!(a, b);
    }

    #[test]
    fn sidecar_hash_does_not_leak_did_substring() {
        // Even with a known salt, the hash output must not contain the
        // raw DID — that's the whole point of the sidecar.
        let did = "did:web:alice.example";
        let hash = mention_sidecar_hash("salt", did);
        assert!(!hash.contains("alice"));
    }
}
