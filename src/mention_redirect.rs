//! Round 4 (spec a77b995) — mention_redirect plaintext routing consumer.
//!
//! Wire shape: [`contrix_sdk::MentionRedirectRouting`] is the plaintext
//! routing fragment carried inside `MessagePayload` /
//! `SystemMessagePayload`. The single field is
//! `mention_redirect_target_actor_ids: Vec<Did>`. The receiver MUST:
//!
//! 1. Surface the routing to the UI (so the recipient understands the
//!    message was redirected to a specific actor set).
//! 2. Refuse to decrypt the message body at the push layer if the local
//!    actor is NOT in the list — this is the round-4 fail-closed
//!    behaviour for mention_redirect. The encrypted ciphertext is still
//!    persisted (in case the local actor later joins the redirect set
//!    via a `mention_redirect_revise` event) but the plaintext body is
//!    NOT computed.
//!
//! This module only owns the projection + the gating predicate; the
//! actual decrypt skip lives in [`crate::sync_engine`] / the message
//! renderer.

use serde::{Deserialize, Serialize};

/// Round 4 — local projection of [`contrix_sdk::MentionRedirectRouting`]
/// for the renderer. Wraps the wire shape one-for-one so the UI can
/// pass-through without re-discovering the field names.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMentionRedirect {
    /// `mention_redirect_target_actor_ids` per round-4 wire schema.
    /// Empty means "no redirect" (the normal case); non-empty means
    /// the message body is gated on the receiver's DID being in the
    /// list.
    #[serde(default)]
    pub mention_redirect_target_actor_ids: Vec<String>,
}

impl LocalMentionRedirect {
    /// Construct from the SDK's typed [`contrix_sdk::MentionRedirectRouting`].
    pub fn from_sdk(routing: &contrix_sdk::MentionRedirectRouting) -> Self {
        Self {
            mention_redirect_target_actor_ids: routing
                .mention_redirect_target_actor_ids
                .iter()
                .map(|d| d.as_str().to_owned())
                .collect(),
        }
    }

    /// Parse the `mention_redirect_target_actor_ids` array out of a
    /// raw JSON payload. Returns the default (empty) when absent so
    /// callers can chain it with `.is_active()`.
    pub fn from_payload(payload: &serde_json::Value) -> Self {
        let actors = payload
            .get("mention_redirect_target_actor_ids")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            mention_redirect_target_actor_ids: actors,
        }
    }

    /// True when the routing is active (non-empty list). The body is
    /// gated on this branch.
    pub fn is_active(&self) -> bool {
        !self.mention_redirect_target_actor_ids.is_empty()
    }

    /// Receiver-side gate: should `local_actor_did` decrypt the body?
    ///
    /// Round 4 rules:
    /// - Routing inactive (empty list) → `true` (normal message).
    /// - Routing active and `local_actor_did` is in the list → `true`.
    /// - Routing active and `local_actor_did` is NOT in the list →
    ///   `false`; the body MUST NOT be decrypted.
    pub fn should_decrypt_for(&self, local_actor_did: &str) -> bool {
        if !self.is_active() {
            return true;
        }
        self.mention_redirect_target_actor_ids
            .iter()
            .any(|did| did == local_actor_did)
    }

    /// Render the comma-separated DID list used by the UI banner. The
    /// i18n template `message.mention_redirect.banner` substitutes
    /// `{targets}` with this value.
    pub fn banner_targets(&self) -> String {
        self.mention_redirect_target_actor_ids.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inactive_routing_passes_decrypt_for_everyone() {
        let routing = LocalMentionRedirect::default();
        assert!(!routing.is_active());
        assert!(routing.should_decrypt_for("did:web:alice.example"));
        assert!(routing.should_decrypt_for("did:web:bob.example"));
    }

    #[test]
    fn active_routing_gates_on_actor_id() {
        let routing = LocalMentionRedirect {
            mention_redirect_target_actor_ids: vec![
                "did:web:alice.example".to_owned(),
                "did:web:carol.example".to_owned(),
            ],
        };
        assert!(routing.is_active());
        assert!(routing.should_decrypt_for("did:web:alice.example"));
        assert!(routing.should_decrypt_for("did:web:carol.example"));
        assert!(!routing.should_decrypt_for("did:web:bob.example"));
    }

    #[test]
    fn from_payload_extracts_target_actor_ids() {
        let payload = json!({
            "body_ciphertext": "...",
            "mention_redirect_target_actor_ids": [
                "did:web:alice.example",
                "did:web:bob.example"
            ]
        });
        let routing = LocalMentionRedirect::from_payload(&payload);
        assert_eq!(routing.mention_redirect_target_actor_ids.len(), 2);
        assert!(routing.is_active());
    }

    #[test]
    fn from_payload_returns_default_when_field_absent() {
        let payload = json!({"body_ciphertext": "..."});
        let routing = LocalMentionRedirect::from_payload(&payload);
        assert!(!routing.is_active());
    }

    #[test]
    fn banner_targets_renders_comma_separated() {
        let routing = LocalMentionRedirect {
            mention_redirect_target_actor_ids: vec![
                "did:web:alice".to_owned(),
                "did:web:bob".to_owned(),
            ],
        };
        assert_eq!(routing.banner_targets(), "did:web:alice, did:web:bob");
    }
}
