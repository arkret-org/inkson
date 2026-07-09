//! F-CARD-COMMENT-1: typed model + payload builder for kanban-card
//! comment threads.
//!
//! Spec sources:
//! - `strand-and-message.md §4.3` / `§9` — a kanban card's discussion is a `discussion` track on
//!   the card's Strand; comments are `ck.message.create` events carrying the card's `strand_id` and
//!   `track_name = "discussion"`.
//! - `realm-and-space.md §4` — kanban cards ARE Strand objects, so reusing the message-create
//!   reducer is the natural binding.
//!
//! This module ships the typed representation + the payload builder
//! that constructs the canonical `ck.message.create` op via the SDK's
//! typed [`arkret_sdk::MessageCreatePayload`]. The UI drawer +
//! projection wiring are follow-ups; this revision is the data-layer
//! half that can be unit-tested in isolation.
//!
//! Schema notes (`event-payload.schema.json $defs.message_create_payload`,
//! `additionalProperties:false`):
//! - `strand_id` + `track_name` are required; the comment body rides in `content` (a
//!   `content_block`), never a top-level `body`.
//! - The author is NOT a payload field — the reducer derives `created_by` from the envelope
//!   `actor_id`, so we deliberately do not carry an `author_did` here.
//! - Threading uses `reply_to` (a `message_id`); the previous `thread_root` field was not part of
//!   this payload.
//!
//! @-mention extraction is deliberately conservative — inkson
//! recognizes the `did:web:` / `did:key:` / `did:plc:` / `did:webvh:` forms
//! when prefixed with `@`. Anything else falls through unchanged so a
//! literal email / handle text isn't mistakenly notified. Recognized DIDs
//! become structured [`crate::models::Mention`] nodes inside the content
//! block.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::models::Mention;

/// Discussion track name comments are attached to on the card's Strand.
const DISCUSSION_TRACK: &str = "discussion";

/// F-CARD-COMMENT-1: a single comment composed for a kanban card.
/// Carries only what the composer knows; the author is supplied by the
/// envelope `actor_id` at sign time and resolved by the reducer into
/// `created_by`, so it is intentionally absent here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CardComment {
    /// The card's own Strand id — becomes `payload.strand_id` so the
    /// discussion track on this card receives the comment.
    pub card_strand_id: String,
    /// Raw body text (Markdown allowed; soland renders it).
    pub body: String,
    /// DIDs extracted from `@did:...` patterns in the body. These are
    /// emitted as structured `Mention` nodes inside the content block.
    pub mentions: Vec<String>,
    /// Optional parent message id for threaded replies. Maps to
    /// `payload.reply_to`; `None` for a top-level comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_to: Option<String>,
}

impl CardComment {
    pub fn new(card_strand_id: impl Into<String>, body: impl Into<String>) -> Self {
        let body_str = body.into();
        let mentions = extract_mentions(&body_str);
        Self {
            card_strand_id: card_strand_id.into(),
            body: body_str,
            mentions,
            reply_to: None,
        }
    }

    /// Mark this comment as a threaded reply to `parent_message_id`.
    pub fn with_reply_to(mut self, parent_message_id: impl Into<String>) -> Self {
        self.reply_to = Some(parent_message_id.into());
        self
    }
}

/// F-CARD-COMMENT-1: build the `ck.message.create` payload for a card
/// comment, reusing the SDK's typed [`arkret_sdk::MessageCreatePayload`]
/// so the field set stays schema-compliant by construction.
///
/// The comment body rides in a `ck.content.text` content block; recognized
/// `@did:...` mentions are attached to the block as structured `Mention`
/// nodes (the block is `additionalProperties:true`). Threading is expressed
/// via `reply_to`. The author is omitted on purpose — the reducer derives it
/// from the envelope `actor_id`.
///
/// `strand_id` is the card's Strand id; card ids ultimately come from server
/// sync data, so a malformed id surfaces as a recoverable error instead of
/// a panic (YOU-02-001 — on wasm a panic kills the whole page).
pub fn build_card_comment_payload(comment: &CardComment) -> anyhow::Result<Value> {
    let mentions = comment
        .mentions
        .iter()
        .map(|did| {
            // YOU-05-006: `Mention` is now the SDK's strongly-typed model,
            // so the extracted string is validated into a `Did` here and a
            // malformed mention surfaces as a recoverable error.
            let subject_id = arkret_sdk::Did::new(did.clone())
                .map_err(|err| anyhow::anyhow!("invalid mention DID {did:?}: {err:?}"))?;
            serde_json::to_value(Mention::new(subject_id))
                .map_err(|err| anyhow::anyhow!("mention serialize: {err}"))
        })
        .collect::<anyhow::Result<Vec<Value>>>()?;

    let mut content = arkret_sdk::ContentBlock::new("ck.content.text", comment.body.clone())
        .with_field("format", json!("markdown"));
    if !mentions.is_empty() {
        content = content.with_field("mentions", Value::Array(mentions));
    }

    let strand_id = arkret_sdk::StrandId::new(comment.card_strand_id.clone()).map_err(|err| {
        anyhow::anyhow!(
            "invalid card strand id {:?}: {err:?}",
            comment.card_strand_id
        )
    })?;

    let mut payload = arkret_sdk::MessageCreatePayload::with_content(
        strand_id,
        DISCUSSION_TRACK,
        content
            .to_value()
            .map_err(|err| anyhow::anyhow!("content block serialize: {err}"))?,
    );
    if let Some(reply_to) = &comment.reply_to {
        payload = payload.with_reply_to(reply_to.clone());
    }

    payload
        .to_value()
        .map_err(|err| anyhow::anyhow!("card comment message_create payload serialize: {err}"))
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

    /// A syntactically valid Strand id for payloads that get schema-validated.
    const CARD_STRAND_ID: &str = "ak:strand:01904100-0000-7000-8000-000000000001";

    #[test]
    fn new_comment_extracts_mentions_eagerly() {
        let comment = CardComment::new(
            CARD_STRAND_ID,
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
    fn build_payload_uses_strand_track_and_content() {
        let comment = CardComment::new(CARD_STRAND_ID, "hi @did:web:bob.example");
        let payload = build_card_comment_payload(&comment).expect("builds");
        // Required schema fields.
        assert_eq!(payload["strand_id"], CARD_STRAND_ID);
        assert_eq!(payload["track_name"], "discussion");
        // Body rides in the content block, not a top-level `body`.
        assert!(payload.get("body").is_none());
        assert_eq!(payload["content"]["kind"], "ck.content.text");
        assert_eq!(payload["content"]["body"], "hi @did:web:bob.example");
        // Mentions are structured nodes inside the content block.
        assert_eq!(
            payload["content"]["mentions"][0]["subject_id"],
            "did:web:bob.example"
        );
        // Author is reducer-derived from the envelope, never in the payload.
        assert!(payload.get("author_did").is_none());
        assert!(payload.get("thread_root").is_none());
        assert!(payload.get("reply_to").is_none());
    }

    #[test]
    fn build_payload_threads_via_reply_to() {
        let comment = CardComment::new(CARD_STRAND_ID, "agreed")
            .with_reply_to("ak:message:01904100-0000-7000-8000-000000000002");
        let payload = build_card_comment_payload(&comment).expect("builds");
        assert_eq!(
            payload["reply_to"],
            "ak:message:01904100-0000-7000-8000-000000000002"
        );
    }

    #[test]
    fn build_payload_validates_against_message_create_schema() {
        let comment = CardComment::new(CARD_STRAND_ID, "ship it @did:web:bob.example");
        let payload = build_card_comment_payload(&comment).expect("builds");
        arkret_sdk::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload("ck.message.create", &payload)
            .expect("card comment payload must satisfy message_create_payload schema");
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
        // bogus method shouldn't notify anyone — inkson only
        // recognizes web / key / plc / webvh per the reducer's
        // allow list.
        let body = "@did:bogus:alice ping";
        assert!(extract_mentions(body).is_empty());
    }

    #[test]
    fn extract_mentions_skips_bare_at_without_did_prefix() {
        let body = "@alice please look — inkson treats @ + handle as plain text.";
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
        let comment = CardComment::new(CARD_STRAND_ID, "@did:web:bob hello");
        let bytes = serde_json::to_string(&comment).unwrap();
        let restored: CardComment = serde_json::from_str(&bytes).unwrap();
        assert_eq!(restored, comment);
    }
}
