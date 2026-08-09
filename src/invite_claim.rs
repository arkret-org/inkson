//! Invite-claim strand helpers.
//!
//! The `ak.invite.claim` wire shape carries a verification-service
//! `binding_proof` plus a subject-signed proof over the SDK-owned
//! `ak.invite.claim.subject_proof.v1` transcript.
//!
//! Plus five terminal states the receiver-side reducer surfaces to the
//! UI: `claimed`, `send_failed`, `revoked_by_capability_loss`,
//! `revoked_by_inviter_left`, `invalidated_by_rate_limit`. The
//! [`InviteTerminalState`] enum mirrors
//! [`arkret_sdk::ThirdPartyInviteTerminalState`] and carries the i18n
//! key + user-facing label so the UI can render any terminal state
//! consistently without re-discovering the labels.
//!
//! This module only owns the typed builders + the rendering helpers;
//! the network submit lives in [`crate::transport::TransportClient`] and the
//! actual signing key plumbing lives in [`crate::event_signer`].

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Round 4 — terminal states for an invite, matching
/// [`arkret_sdk::ThirdPartyInviteTerminalState`] one-for-one.
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
    pub fn as_sdk(self) -> arkret_sdk::ThirdPartyInviteTerminalState {
        use arkret_sdk::ThirdPartyInviteTerminalState as S;
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

/// Assemble a `ak.invite.claim` event body carrying the verification-service
/// `binding_proof` and subject-signed SDK [`arkret_sdk::InviteSubjectProof`].
///
/// Returns the SDK payload bound to `ak.invite.claim`; callers author it with
/// `TypedOperationBuilder::new::<event_spec::InviteClaim>`.
pub fn build_invite_claim_payload(
    invite_id: &str,
    realm_id: &str,
    subject_id: &str,
    token_commitment: &str,
    claim_nonce: &str,
    binding_proof: &Value,
    verification_service_id: &str,
    subject_signing_key: &SigningKey,
    subject_verification_method: &str,
) -> anyhow::Result<arkret_sdk::InviteClaimPayload> {
    let binding_proof_digest = arkret_sdk::canonical::canonical_sha256(binding_proof)?;
    let proof_body = arkret_sdk::InviteSubjectProofBody::from_wire_parts(
        subject_id,
        invite_id,
        realm_id,
        token_commitment,
        claim_nonce,
        verification_service_id,
        binding_proof_digest,
    )?;
    let proof_bytes = proof_body.canonical_bytes()?;
    let sig = subject_signing_key.sign(&proof_bytes);
    let subject_proof = arkret_sdk::InviteSubjectProof::new(
        arkret_sdk::DidUrl::new(subject_verification_method.to_owned())
            .map_err(|error| anyhow::anyhow!("invite subject verification method: {error}"))?,
        proof_body.transcript_digest()?,
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes()),
    );
    let payload = arkret_sdk::InviteClaimPayload {
        invite_id: arkret_sdk::InviteId::new(invite_id.to_owned())?,
        subject_id: arkret_sdk::Did::new(subject_id.to_owned())?,
        token_commitment: arkret_sdk::Hash::new(token_commitment.to_owned())?,
        claim_nonce: claim_nonce.to_owned(),
        binding_proof: serde_json::from_value(binding_proof.clone())?,
        subject_proof,
        extensions: Default::default(),
    };
    payload.validate()?;
    Ok(payload)
}

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
        let body = arkret_sdk::InviteSubjectProofBody::from_wire_parts(
            "did:web:alice.example",
            "ak:invite:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
            "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "nonce-claim-proof-1",
            "did:web:verify.example",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        let bytes = body.canonical_bytes().unwrap();
        let sig = signing_key.sign(&bytes);
        verifying.verify(&bytes, &sig).expect("self-verify");
    }

    #[test]
    fn build_invite_claim_payload_round_trips_proof() {
        let signing_key = deterministic_signing_key(7);
        let binding_proof = json!({
            "verification_service_id": "did:web:verify.example",
            "verification_method": "did:web:verify.example#invite-key",
            "subject_id": "did:web:alice.example",
            "realm_id": "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "audience": "arkret.invite.claim",
            "claim_nonce": "nonce-claim-proof-1",
            "expires_at": "2099-01-01T00:00:00.000Z",
            "signature": "binding-signature"
        });
        let body = build_invite_claim_payload(
            "ak:invite:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
            "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "did:web:alice.example",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "nonce-claim-proof-1",
            &binding_proof,
            "did:web:verify.example",
            &signing_key,
            "did:web:alice.example#device-0001",
        )
        .unwrap();
        let expected_binding_digest =
            arkret_sdk::canonical::canonical_sha256(&binding_proof).unwrap();
        let expected_transcript_digest = arkret_sdk::invite_subject_proof_transcript_digest(
            "did:web:alice.example",
            "ak:invite:AfUeGRE3CFApB-5spxARHjovex9S5j5RWL8mAUSkpOMS",
            "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "nonce-claim-proof-1",
            "did:web:verify.example",
            &expected_binding_digest,
        )
        .unwrap();
        assert_eq!(
            body.subject_proof.verification_method.as_str(),
            "did:web:alice.example#device-0001"
        );
        assert_eq!(body.subject_proof.signature_algorithm, "Ed25519");
        assert_eq!(
            body.subject_proof.transcript_digest,
            expected_transcript_digest
        );
        assert!(!body.subject_proof.signature.is_empty());
        assert_eq!(body.binding_proof.audience, "arkret.invite.claim");
    }
}
