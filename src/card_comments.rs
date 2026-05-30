//! F-CARD-COMMENT-1: typed model + payload builder for kanban-card
//! comment threads.
//!
//! Spec sources:
//! - `flow-and-message.md §4.3` — discussion tracks attached to a Flow surface as
//!   `cx.message.create` events keyed by `payload.thread_root = <card_flow_id>`.
//! - `space-and-place.md §4` — kanban cards ARE Flow objects, so reusing the message-create reducer
//!   is the natural binding.
//!
//! This module ships the typed representation + the payload builder
//! that constructs the canonical `cx.message.create` op. The UI
//! drawer + projection wiring are follow-ups; this revision is the
//! data-layer half that can be unit-tested in isolation.
//!
//! @-mention extraction is deliberately conservative — yougen
//! recognizes the `did:web:` / `did:key:` / `did:plc:` forms when
//! prefixed with `@`. Anything else falls through unchanged so a
//! literal email / handle text isn't mistakenly notified.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// F-CARD-COMMENT-1: a single comment row attached to a kanban
/// card. Mirrors the on-the-wire `cx.message.create` payload minus
/// the protocol-level envelope fields (`event_id`, `hlc`, etc.) —
/// callers turn this into a full envelope via the standard
/// `OperationBuilder` path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardComment {
    /// The card's own Flow id — used as `thread_root` so the
    /// projection groups the comment under this card.
    pub card_flow_id: String,
    /// Comment author DID.
    pub author_did: String,
    /// Raw body text (Markdown allowed; soland renders it).
    pub body: String,
    /// DIDs extracted from `@did:web:...` patterns in the body.
    /// `cx.message.create.payload.mentions[]` per spec §3 — yougen
    /// emits notifications only to these DIDs.
    pub mentions: Vec<String>,
}

impl CardComment {
    pub fn new(
        card_flow_id: impl Into<String>,
        author_did: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        let body_str = body.into();
        let mentions = extract_mentions(&body_str);
        Self {
            card_flow_id: card_flow_id.into(),
            author_did: author_did.into(),
            body: body_str,
            mentions,
        }
    }
}

/// F-CARD-COMMENT-1: build the `cx.message.create` payload that
/// the reducer accepts as a comment row on `card_flow_id`. Mirrors
/// the canonical envelope shape — caller wraps this in their
/// `OperationBuilder` to produce a signed Move.
///
/// `thread_root` is the load-bearing field: soland's reducer keys
/// the comment under it, so the kanban projection can later fetch
/// all comments for a given card via `index.query(thread_root)`.
pub fn build_card_comment_payload(comment: &CardComment) -> Value {
    json!({
        "thread_root": comment.card_flow_id,
        "author_did": comment.author_did,
        "body": comment.body,
        "mentions": comment.mentions,
    })
}

/// F-CARD-COMMENT-1: extract `@did:<method>:<id>` mentions from a
/// comment body.
///
/// The recognized forms:
/// - `@did:web:<host>(/path)?`
/// - `@did:key:<z...>`
/// - `@did:plc:<id>`
///
/// Each match is captured up to the first whitespace / punctuation
/// terminator. Duplicates are folded so a body that mentions Alice
/// twice doesn't notify her twice.
pub fn extract_mentions(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for token in body.split(|c: char| c.is_whitespace()) {
        let Some(after_at) = token.strip_prefix('@') else {
            continue;
        };
        if !after_at.starts_with("did:") {
            continue;
        }
        // Trim trailing punctuation the body might attach (comma,
        // period, semicolon, etc.) so `@did:web:alice,` and
        // `@did:web:alice.example.` both resolve to
        // `did:web:alice...`. We strip every trailing non-
        // alphanumeric / non-`-` / non-`_` / non-`/` char in turn;
        // `.` is deliberately strippable so end-of-sentence dots
        // don't poison the parsed DID. A `.` that lives mid-DID
        // (`did:web:bob.example`) is preserved because trim only
        // touches the tail.
        let did = after_at.trim_end_matches(|c: char| {
            !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '/' && c != ':'
        });
        if did.len() < "did:x:y".len() {
            continue;
        }
        // Method whitelist — same set the live form-validator
        // accepts (web / key / plc / webvh).
        let method_prefix = did.split(':').nth(1).unwrap_or("");
        if !matches!(method_prefix, "web" | "key" | "plc" | "webvh") {
            continue;
        }
        let did_owned = did.to_owned();
        if !out.contains(&did_owned) {
            out.push(did_owned);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_comment_extracts_mentions_eagerly() {
        let comment = CardComment::new(
            "cx:flow:card1",
            "did:web:alice.example",
            "ping @did:web:bob.example and @did:key:z6Mksample",
        );
        assert_eq!(
            comment.mentions,
            vec![
                "did:web:bob.example".to_owned(),
                "did:key:z6Mksample".to_owned(),
            ]
        );
    }

    #[test]
    fn build_payload_carries_thread_root_and_mentions() {
        let comment = CardComment::new(
            "cx:flow:card1",
            "did:web:alice.example",
            "hi @did:web:bob.example",
        );
        let payload = build_card_comment_payload(&comment);
        assert_eq!(payload["thread_root"], "cx:flow:card1");
        assert_eq!(payload["author_did"], "did:web:alice.example");
        assert_eq!(payload["body"], "hi @did:web:bob.example");
        assert_eq!(
            payload["mentions"],
            serde_json::json!(["did:web:bob.example"])
        );
    }

    #[test]
    fn extract_mentions_dedupes_repeated_dids() {
        let body = "@did:web:alice please @did:web:alice and @did:web:alice";
        let mentions = extract_mentions(body);
        assert_eq!(mentions, vec!["did:web:alice".to_owned()]);
    }

    #[test]
    fn extract_mentions_handles_trailing_punctuation() {
        let body = "Reviewers: @did:web:alice, @did:web:bob.example.";
        let mentions = extract_mentions(body);
        assert_eq!(
            mentions,
            vec!["did:web:alice".to_owned(), "did:web:bob.example".to_owned(),]
        );
    }

    #[test]
    fn extract_mentions_ignores_unknown_did_methods() {
        // bogus method shouldn't notify anyone — yougen only
        // recognizes web / key / plc / webvh per the reducer's
        // allow list.
        let body = "@did:bogus:alice ping";
        assert!(extract_mentions(body).is_empty());
    }

    #[test]
    fn extract_mentions_skips_bare_at_without_did_prefix() {
        let body = "@alice please look — yougen treats @ + handle as plain text.";
        assert!(extract_mentions(body).is_empty());
    }

    #[test]
    fn extract_mentions_handles_did_webvh() {
        let body = "@did:webvh:QmExampleScidValue123456:alice.example ping";
        assert_eq!(
            extract_mentions(body),
            vec!["did:webvh:QmExampleScidValue123456:alice.example".to_owned()]
        );
    }

    #[test]
    fn empty_body_has_no_mentions() {
        assert!(extract_mentions("").is_empty());
        assert!(extract_mentions("   ").is_empty());
    }

    #[test]
    fn comment_round_trips_through_serde() {
        let comment = CardComment::new(
            "cx:flow:card1",
            "did:web:alice.example",
            "@did:web:bob hello",
        );
        let bytes = serde_json::to_string(&comment).unwrap();
        let restored: CardComment = serde_json::from_str(&bytes).unwrap();
        assert_eq!(restored, comment);
    }
}
