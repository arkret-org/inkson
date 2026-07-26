//! 6.3 — `principal_signing` recovery-proof transcript (client side).
//!
//! Builds the canonical `ak.identity.recovery_proof.v1` transcript a recovering
//! device signs, byte-for-byte identical to soland's reconstruction
//! (`soland/src/routing/identity/recovery.rs::recovery_proof_transcript` +
//! arkret-spec `recovery-session.schema.json` `$defs/principal_signing_transcript`).
//! Mismatch ⇒ the server rejects the proof, so this MUST stay in lockstep.
//!
//! The transcript binds every session-defining field, including the mutually
//! exclusive A/B authority model and its authoritative generation reference.
//! Construction delegates to the SDK truth type rather than mirroring the wire
//! object locally.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

/// Build the canonical `principal_signing` proof transcript from a recovery
/// session JSON (the `ak.schema.recovery_session.v1` create/get response).
pub fn principal_signing_proof_transcript(session: &Value) -> anyhow::Result<Value> {
    let state: arkret_sdk::RecoverySessionState = serde_json::from_value(session.clone())?;
    let model_generation_ref = match state.identity_model {
        arkret_sdk::RecoveryIdentityModel::CrossSigning => {
            let generation = state
                .ssk_generation
                .and_then(std::num::NonZeroU64::new)
                .ok_or_else(|| {
                    anyhow::anyhow!("cross-signing recovery session omits ssk_generation")
                })?;
            arkret_sdk::RecoveryModelGenerationRef::CrossSigning(generation)
        }
        arkret_sdk::RecoveryIdentityModel::EnrollmentAuthority => {
            let generation = state.current_device_generation_ref.ok_or_else(|| {
                anyhow::anyhow!(
                    "enrollment-authority recovery session omits current_device_generation_ref"
                )
            })?;
            arkret_sdk::RecoveryModelGenerationRef::EnrollmentAuthority(generation)
        }
    };
    let transcript = arkret_sdk::PrincipalSigningTranscript {
        schema: "ak.identity.recovery_proof.v1".to_owned(),
        kind: arkret_sdk::RecoveryProofKind::PrincipalSigning,
        principal_id: state.principal_id,
        requesting_device_id: state.requesting_device_id,
        trust_domain: state.trust_domain,
        policy_id: state.policy_id,
        policy_version: state.policy_version,
        recovery_session_id: state.recovery_session_id,
        identity_model: state.identity_model,
        model_generation_ref,
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
            challenge: challenge.to_owned(),
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned())
                .map_err(anyhow::Error::msg)?,
            alg: arkret_sdk::NonEmptyString::new("EdDSA").map_err(anyhow::Error::msg)?,
            signature: arkret_sdk::Base64UrlString::new(B64.encode(signature.to_bytes()))
                .map_err(anyhow::Error::msg)?,
        },
    ))
}

/// Same as [`build_principal_signing_proof`] but signs with the process-wide
/// active signer. Returns `Ok(None)` when no signer is installed. NOTE:
/// `principal_signing` proofs MUST be signed by a key the active recovery policy
/// authorizes as principal-grade control; the caller is responsible for ensuring
/// the active signer is that key.
pub fn build_principal_signing_proof_active(session: &Value) -> anyhow::Result<Option<Value>> {
    let Some(signer) = crate::event_signer::active_signer() else {
        return Ok(None);
    };
    let transcript = principal_signing_proof_transcript(session)?;
    let bytes = crate::canonical::canonical_json_bytes(&transcript)?;
    let signature = signer.sign_raw(&bytes)?;
    let challenge = session
        .get("challenge")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("recovery session missing `challenge`"))?;
    Ok(Some(json!({
        "kind": "principal_signing",
        "challenge": challenge,
        "verification_method": signer.verification_method(),
        "alg": signer.algorithm(),
        "signature": B64.encode(signature),
    })))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Verifier, VerifyingKey};

    use super::*;

    fn sample_session() -> Value {
        json!({
            "schema": "ak.schema.recovery_session.v1",
            "recovery_session_id": "ak:recovery_session:01964137-0000-7000-8000-0000000000aa",
            "principal_id": "did:key:z6MkPrincipalFixture",
            "requesting_device_id": "ak:device:01964137-0000-7000-8000-000000000099",
            "trust_domain": "ak:trust_domain:soland.local",
            "policy_id": "ak:policy:01964137-0000-7000-8000-0000000000bb",
            "policy_version": 1,
            "identity_model": "cross_signing",
            "ssk_generation": 1,
            "challenge": "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8",
            "state": "pending",
            "created_at": "2026-05-30T00:00:00.000Z",
            "updated_at": "2026-05-30T00:00:00.000Z",
            "expires_at": "2026-05-30T00:15:00.000Z",
        })
    }

    #[test]
    fn transcript_binds_every_session_field() {
        let t = principal_signing_proof_transcript(&sample_session()).unwrap();
        assert_eq!(t["type"], "ak.identity.recovery_proof.v1");
        assert_eq!(t["kind"], "principal_signing");
        for f in [
            "principal_id",
            "requesting_device_id",
            "trust_domain",
            "policy_id",
            "policy_version",
            "recovery_session_id",
            "identity_model",
            "model_generation_ref",
            "challenge",
            "created_at",
            "expires_at",
        ] {
            assert!(t.get(f).is_some(), "transcript missing {f}");
        }
        // created_at is the session value (not regenerated).
        assert_eq!(t["created_at"], "2026-05-30T00:00:00.000Z");
        assert_eq!(t["model_generation_ref"], 1);
        assert!(t.get("ssk_generation").is_none());
    }

    #[test]
    fn proof_signature_verifies_against_transcript() {
        let session = sample_session();
        let signing_key = SigningKey::from_bytes(&[51u8; 32]);
        let proof = serde_json::to_value(
            build_principal_signing_proof(
                &session,
                "did:key:z6MkPrincipalFixture#key",
                &signing_key,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(proof["kind"], "principal_signing");
        assert_eq!(proof["alg"], "EdDSA");
        assert_eq!(proof["challenge"], session["challenge"]);

        // Re-derive the transcript bytes and verify the embedded signature —
        // exactly what soland does server-side.
        let transcript = principal_signing_proof_transcript(&session).unwrap();
        let bytes = crate::canonical::canonical_json_bytes(&transcript).unwrap();
        let sig_raw = B64.decode(proof["signature"].as_str().unwrap()).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig_raw).unwrap();
        let vk: VerifyingKey = signing_key.verifying_key();
        vk.verify(&bytes, &signature)
            .expect("proof signature must verify against the canonical transcript");
    }

    #[test]
    fn missing_session_field_errors() {
        let mut session = sample_session();
        session.as_object_mut().unwrap().remove("identity_model");
        assert!(principal_signing_proof_transcript(&session).is_err());
    }
}
