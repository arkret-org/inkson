//! 6.3 — `principal_signing` recovery-proof transcript (client side).
//!
//! Builds the canonical `ak.identity.recovery_proof.v1` transcript a recovering
//! device signs, byte-for-byte identical to soland's reconstruction
//! (`soland/src/routing/identity/recovery.rs::recovery_proof_transcript` +
//! arkret-spec `recovery-session.schema.json` `$defs/principal_signing_transcript`).
//! Mismatch ⇒ the server rejects the proof, so this MUST stay in lockstep.
//!
//! The transcript binds every session-defining field, including the
//! root-anchored did:webvh generation reference.
//! Construction delegates to the SDK truth type rather than mirroring the wire
//! object locally.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

/// Build the canonical `principal_signing` proof transcript from a recovery
/// session JSON (the `ak.schema.recovery_session.v1` create/get response).
pub fn principal_signing_proof_transcript(session: &Value) -> anyhow::Result<Value> {
    let state: arkret_sdk::RecoverySessionState = serde_json::from_value(session.clone())?;
    let transcript = arkret_sdk::PrincipalSigningTranscript {
        schema: "ak.identity.recovery_proof.v1".to_owned(),
        kind: arkret_sdk::RecoveryProofKind::PrincipalSigning,
        principal_authority: state.principal_authority,
        requesting_device_id: state.requesting_device_id,
        trust_domain: state.trust_domain,
        policy_id: state.policy_id,
        policy_version: state.policy_version,
        recovery_session_id: state.recovery_session_id,
        identity_model: state.identity_model,
        model_generation_ref: state.current_device_generation_ref,
        publication_authority_context_digest: state.publication_authority_context_digest,
        challenge: state.challenge,
        expires_at: state.expires_at,
        // This is the session creation time, never a client-generated timestamp.
        created_at: state.created_at,
    };
    transcript.validate()?;
    Ok(serde_json::to_value(transcript)?)
}

/// Build the `principal_signing` proof body for `POST recovery-sessions/{id}/proofs`,
/// signed with the principal control key `signing_key`. The proof echoes the
/// session challenge and carries an Ed25519 signature over the canonical
/// transcript. Shape matches `recovery-session.schema.json $defs/principal_signing_proof`.
pub fn build_principal_signing_proof(
    session: &Value,
    verification_method: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<arkret_sdk::RecoverySessionProof> {
    let transcript = principal_signing_proof_transcript(session)?;
    let bytes = crate::canonical::canonical_json_bytes(&transcript)?;
    let signature = signing_key.sign(&bytes);
    let challenge = session
        .get("challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("recovery session missing `challenge`"))?;
    Ok(arkret_sdk::RecoverySessionProof::PrincipalSigning(
        arkret_sdk::RecoveryPrincipalSigningProof {
            kind: arkret_sdk::RecoveryPrincipalSigningProofKind::PrincipalSigning,
            challenge: arkret_sdk::Challenge::new(challenge).map_err(anyhow::Error::msg)?,
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned())
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: arkret_sdk::NonEmptyString::new("Ed25519")
                .map_err(anyhow::Error::msg)?,
            signature: arkret_sdk::Base64UrlString::new(B64.encode(signature.to_bytes()))
                .map_err(anyhow::Error::msg)?,
        },
    ))
}
