//! Round 4 (spec a77b995) — invite-claim strand helpers.
//!
//! The round-4 `ck.invite.claim` wire shape requires the claimant to
//! produce:
//!
//! 1. A `subject_proof` — a device-signed assertion that the device presenting the claim controls
//!    the principal DID accepting the invite. The signing input is the canonical JSON of
//!    `{invite_id, claimant_did, claimant_device_id, claimed_at}`.
//! 2. A `binding_proof` transcript — the canonical bytes of the OOB code material (offline_token or
//!    lookup_table_ref / pepper_id) that the auth server can hash and match against the original
//!    `ThirdPartyInvite` envelope.
//!
//! Plus five terminal states the receiver-side reducer surfaces to the
//! UI: `claimed`, `send_failed`, `revoked_by_capability_loss`,
//! `revoked_by_inviter_left`, `invalidated_by_rate_limit`. The
//! [`InviteTerminalState`] enum mirrors
//! [`cokret_sdk::ThirdPartyInviteTerminalState`] and carries the i18n
//! key + user-facing label so the UI can render any terminal state
//! consistently without re-discovering the labels.
//!
//! This module only owns the typed builders + the rendering helpers;
//! the network submit lives in [`crate::api::CokretApi`] and the
//! actual signing key plumbing lives in [`crate::event_signer`].

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Round 4 — terminal states for an invite, matching
/// [`cokret_sdk::ThirdPartyInviteTerminalState`] one-for-one.
///
/// The UI surfaces every variant via [`label`] / [`i18n_key`] so a
/// receiver-side reducer can advance the invite to any terminal state
/// without the client needing to handle each case bespoke.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteTerminalState {
    Claimed,
    SendFailed,
    RevokedByCapabilityLoss,
    RevokedByInviterLeft,
    InvalidatedByRateLimit,
}

impl InviteTerminalState {
    /// Map back to the SDK's canonical enum so callers can serialise
    /// directly to the wire without re-defining the JSON shape.
    pub fn as_sdk(self) -> cokret_sdk::ThirdPartyInviteTerminalState {
        use cokret_sdk::ThirdPartyInviteTerminalState as S;
        match self {
            Self::Claimed => S::Claimed,
            Self::SendFailed => S::SendFailed,
            Self::RevokedByCapabilityLoss => S::RevokedByCapabilityLoss,
            Self::RevokedByInviterLeft => S::RevokedByInviterLeft,
            Self::InvalidatedByRateLimit => S::InvalidatedByRateLimit,
        }
    }

    /// Lower-case wire string per round-4 schema enum.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Claimed => "claimed",
            Self::SendFailed => "send_failed",
            Self::RevokedByCapabilityLoss => "revoked_by_capability_loss",
            Self::RevokedByInviterLeft => "revoked_by_inviter_left",
            Self::InvalidatedByRateLimit => "invalidated_by_rate_limit",
        }
    }

    /// Stable i18n key under `crate::i18n` — UI renders translations,
    /// not the wire enum.
    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::Claimed => "invite.terminal.claimed",
            Self::SendFailed => "invite.terminal.send_failed",
            Self::RevokedByCapabilityLoss => "invite.terminal.revoked_by_capability_loss",
            Self::RevokedByInviterLeft => "invite.terminal.revoked_by_inviter_left",
            Self::InvalidatedByRateLimit => "invite.terminal.invalidated_by_rate_limit",
        }
    }

    /// Plain-English fallback. Production builds resolve the i18n key
    /// instead; this is for tests + tooling that don't load the
    /// translation table.
    pub fn label(self) -> &'static str {
        match self {
            Self::Claimed => "Claimed",
            Self::SendFailed => "Could not deliver invite",
            Self::RevokedByCapabilityLoss => "Revoked — inviter lost capability",
            Self::RevokedByInviterLeft => "Revoked — inviter left the space",
            Self::InvalidatedByRateLimit => "Invalidated — too many failed attempts",
        }
    }

    pub fn all() -> [InviteTerminalState; 5] {
        [
            Self::Claimed,
            Self::SendFailed,
            Self::RevokedByCapabilityLoss,
            Self::RevokedByInviterLeft,
            Self::InvalidatedByRateLimit,
        ]
    }

    /// Parse the wire enum string. Returns `None` if the string is not
    /// one of the five canonical values — receivers MUST treat unknown
    /// values as a `schema_violation`.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "claimed" => Some(Self::Claimed),
            "send_failed" => Some(Self::SendFailed),
            "revoked_by_capability_loss" => Some(Self::RevokedByCapabilityLoss),
            "revoked_by_inviter_left" => Some(Self::RevokedByInviterLeft),
            "invalidated_by_rate_limit" => Some(Self::InvalidatedByRateLimit),
            _ => None,
        }
    }
}

/// Round 4 — device-signed `subject_proof` carried inside
/// `ck.invite.claim`. The signature is detached EdDSA over the canonical
/// JSON of [`InviteSubjectProofBody`].
///
/// `verification_method` is the DID-URL pointing at the device verification method;
/// reducers verify the signature with that key before accepting the
/// claim. `alg` is the standard JWS / multibase tag (currently always
/// `EdDSA`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteSubjectProof {
    pub verification_method: String,
    pub alg: String,
    pub signature: String,
}

/// Canonical body the [`InviteSubjectProof`] signs over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteSubjectProofBody {
    pub invite_id: String,
    pub claimant_did: String,
    pub claimant_device_id: String,
    pub claimed_at: DateTime<Utc>,
}

impl InviteSubjectProofBody {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        cokret_sdk::canonical::canonical_json_bytes(&value)
            .map_err(|err| anyhow::anyhow!("invite subject_proof canonical_json failed: {err}"))
    }
}

/// Round 4 — `binding_proof` transcript carried alongside the
/// [`InviteSubjectProof`]. Holds the OOB code material (offline_token
/// commitment + salt, or lookup_table_ref + pepper_id) so the receiver
/// can replay the original `ThirdPartyInvite` validator.
///
/// The transcript is the canonical bytes of this struct; receivers
/// SHA-256 these bytes and match against the
/// `ThirdPartyInvite.binding_transcript_digest` field on the original
/// invite envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteBindingTranscript {
    pub invite_id: String,
    pub oob_code_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_salt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_table_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pepper_id: Option<String>,
    pub claimed_at: DateTime<Utc>,
}

impl InviteBindingTranscript {
    pub fn canonical_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        cokret_sdk::canonical::canonical_json_bytes(&value)
            .map_err(|err| anyhow::anyhow!("invite binding_proof canonical_json failed: {err}"))
    }
}

/// Round 4 — assemble a `ck.invite.claim` event body carrying the
/// device-signed [`InviteSubjectProof`] + the
/// [`InviteBindingTranscript`]. The device signing key MUST be the
/// keypair registered on the claimant's `ck.device.authorize` event.
///
/// Returns the raw JSON body for the caller to wrap in an
/// `OperationBuilder` / `EventEnvelope` and submit through
/// [`crate::api::CokretApi::submit_event_envelope`].
pub fn build_invite_claim_body(
    invite_id: &str,
    claimant_did: &str,
    claimant_device_id: &str,
    binding_transcript: &InviteBindingTranscript,
    device_signing_key: &SigningKey,
    device_kid: &str,
) -> anyhow::Result<Value> {
    let claimed_at = Utc::now();
    let proof_body = InviteSubjectProofBody {
        invite_id: invite_id.to_owned(),
        claimant_did: claimant_did.to_owned(),
        claimant_device_id: claimant_device_id.to_owned(),
        claimed_at,
    };
    let proof_bytes = proof_body.canonical_bytes()?;
    let sig = device_signing_key.sign(&proof_bytes);
    let subject_proof = InviteSubjectProof {
        verification_method: device_kid.to_owned(),
        alg: "EdDSA".to_owned(),
        signature: base64::engine::general_purpose::STANDARD_NO_PAD.encode(sig.to_bytes()),
    };
    Ok(json!({
        "invite_id": invite_id,
        "claimant_did": claimant_did,
        "claimant_device_id": claimant_device_id,
        "claimed_at": claimed_at,
        "subject_proof": subject_proof,
        "binding_proof": binding_transcript,
    }))
}

// Re-export so callers don't need to pull base64 in.
use base64::Engine as _;

#[cfg(test)]
mod tests {
    use ed25519_dalek::{SECRET_KEY_LENGTH, Verifier};

    use super::*;

    fn deterministic_signing_key(seed_byte: u8) -> SigningKey {
        let mut seed = [0u8; SECRET_KEY_LENGTH];
        seed.fill(seed_byte);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn terminal_states_round_trip_via_wire_string() {
        for state in InviteTerminalState::all() {
            let wire = state.as_wire();
            assert_eq!(InviteTerminalState::from_wire(wire), Some(state));
            assert!(!state.label().is_empty());
            assert!(state.i18n_key().starts_with("invite.terminal."));
        }
    }

    #[test]
    fn from_wire_rejects_non_canonical_strings() {
        assert!(InviteTerminalState::from_wire("pending").is_none());
        assert!(InviteTerminalState::from_wire("").is_none());
    }

    #[test]
    fn subject_proof_signature_verifies_against_device_key() {
        let signing_key = deterministic_signing_key(7);
        let verifying = signing_key.verifying_key();
        let body = InviteSubjectProofBody {
            invite_id: "ck:invite:0196419b-0000-7000-8000-000000000001".to_owned(),
            claimant_did: "did:web:alice.example".to_owned(),
            claimant_device_id: "ck:device:0196419b-0000-7000-8000-000000000002".to_owned(),
            claimed_at: Utc::now(),
        };
        let bytes = body.canonical_bytes().unwrap();
        let sig = signing_key.sign(&bytes);
        verifying.verify(&bytes, &sig).expect("self-verify");
    }

    #[test]
    fn build_invite_claim_body_round_trips_proof() {
        let signing_key = deterministic_signing_key(7);
        let transcript = InviteBindingTranscript {
            invite_id: "ck:invite:0196419b-0000-7000-8000-000000000001".to_owned(),
            oob_code_kind: "offline_token".to_owned(),
            token_commitment: Some("sha256:".to_owned() + &"a".repeat(64)),
            token_salt_id: Some("salt-1".to_owned()),
            lookup_table_ref: None,
            pepper_id: None,
            claimed_at: Utc::now(),
        };
        let body = build_invite_claim_body(
            "ck:invite:0196419b-0000-7000-8000-000000000001",
            "did:web:alice.example",
            "ck:device:0196419b-0000-7000-8000-000000000002",
            &transcript,
            &signing_key,
            "did:web:alice.example#device-0001",
        )
        .unwrap();
        assert_eq!(
            body["subject_proof"]["verification_method"],
            "did:web:alice.example#device-0001"
        );
        assert_eq!(body["subject_proof"]["alg"], "EdDSA");
        assert!(
            body["subject_proof"]["signature"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        );
        assert_eq!(body["binding_proof"]["oob_code_kind"], "offline_token");
    }
}
