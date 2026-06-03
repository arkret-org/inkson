//! 6.3 — `principal_signing` recovery-proof transcript (client side).
//!
//! Builds the canonical `cx.identity.recovery_proof.v1` transcript a recovering
//! device signs, byte-for-byte identical to soland's reconstruction
//! (`soland/src/routing/identity/recovery.rs::recovery_proof_transcript` +
//! contrix-spec `recovery-session.schema.json` `$defs/principal_signing_transcript`).
//! Mismatch ⇒ the server rejects the proof, so this MUST stay in lockstep.
//!
//! The transcript binds every session-defining field; the recovering client
//! reconstructs it from the create-session response (which carries them all):
//! `principal_id, requesting_device_id, trust_domain, policy_id, policy_version,
//! recovery_session_id, ssk_generation, challenge, created_at, expires_at`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

/// Build the canonical `principal_signing` proof transcript from a recovery
/// session JSON (the `cx.schema.recovery_session.v1` create/get response).
pub fn principal_signing_proof_transcript(session: &Value) -> anyhow::Result<Value> {
    let field = |name: &str| -> anyhow::Result<Value> {
        session
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("recovery session missing `{name}`"))
    };
    Ok(json!({
        "type": "cx.identity.recovery_proof.v1",
        "kind": "principal_signing",
        "principal_id": field("principal_id")?,
        "requesting_device_id": field("requesting_device_id")?,
        "trust_domain": field("trust_domain")?,
        "policy_id": field("policy_id")?,
        "policy_version": field("policy_version")?,
        "recovery_session_id": field("recovery_session_id")?,
        "ssk_generation": field("ssk_generation")?,
        "challenge": field("challenge")?,
        // created_at is the SESSION creation time (echoed from the response),
        // NOT a fresh client timestamp — must match the server's record.
        "created_at": field("created_at")?,
        "expires_at": field("expires_at")?,
    }))
}

/// Build the `principal_signing` proof body for `POST recovery-sessions/{id}/proofs`,
/// signed with the principal control key `signing_key`. The proof echoes the
/// session challenge and carries an Ed25519 signature over the canonical
/// transcript. Shape matches `recovery-session.schema.json $defs/principal_signing_proof`.
pub fn build_principal_signing_proof(
    session: &Value,
    verification_method: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<Value> {
    let transcript = principal_signing_proof_transcript(session)?;
    let bytes = crate::canonical::canonical_json_bytes(&transcript)?;
    let signature = signing_key.sign(&bytes);
    let challenge = session
        .get("challenge")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("recovery session missing `challenge`"))?;
    Ok(json!({
        "kind": "principal_signing",
        "challenge": challenge,
        "verification_method": verification_method,
        "alg": "EdDSA",
        "signature": B64.encode(signature.to_bytes()),
    }))
}

/// Same as [`build_principal_signing_proof`] but signs with the process-wide
/// active signer (device/HSM via `EventSigner::sign_raw`). Returns `Ok(None)`
/// when no signer is installed. NOTE: `principal_signing` proofs MUST be signed
/// by a key the active recovery policy authorizes as principal-grade control;
/// the caller is responsible for ensuring the active signer is that key.
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
    use super::*;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn sample_session() -> Value {
        json!({
            "schema": "cx.schema.recovery_session.v1",
            "recovery_session_id": "cx:recovery_session:01964137-0000-7000-8000-0000000000aa",
            "principal_id": "did:key:z6MkPrincipalFixture",
            "requesting_device_id": "cx:device:01964137-0000-7000-8000-000000000099",
            "trust_domain": "cx:trust_domain:soland.local",
            "policy_id": "cx:policy:01964137-0000-7000-8000-0000000000bb",
            "policy_version": 1,
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
        assert_eq!(t["type"], "cx.identity.recovery_proof.v1");
        assert_eq!(t["kind"], "principal_signing");
        for f in [
            "principal_id",
            "requesting_device_id",
            "trust_domain",
            "policy_id",
            "policy_version",
            "recovery_session_id",
            "ssk_generation",
            "challenge",
            "created_at",
            "expires_at",
        ] {
            assert!(t.get(f).is_some(), "transcript missing {f}");
        }
        // created_at is the session value (not regenerated).
        assert_eq!(t["created_at"], "2026-05-30T00:00:00.000Z");
    }

    #[test]
    fn proof_signature_verifies_against_transcript() {
        let session = sample_session();
        let signing_key = SigningKey::from_bytes(&[51u8; 32]);
        let proof =
            build_principal_signing_proof(&session, "did:key:z6MkPrincipalFixture#key", &signing_key)
                .unwrap();
        assert_eq!(proof["kind"], "principal_signing");
        assert_eq!(proof["alg"], "EdDSA");
        assert_eq!(proof["challenge"], session["challenge"]);

        // Re-derive the transcript bytes and verify the embedded signature —
        // exactly what soland does server-side.
        let transcript = principal_signing_proof_transcript(&session).unwrap();
        let bytes = crate::canonical::canonical_json_bytes(&transcript).unwrap();
        let sig_raw = B64
            .decode(proof["signature"].as_str().unwrap())
            .unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig_raw).unwrap();
        let vk: VerifyingKey = signing_key.verifying_key();
        vk.verify(&bytes, &signature)
            .expect("proof signature must verify against the canonical transcript");
    }

    #[test]
    fn missing_session_field_errors() {
        let mut session = sample_session();
        session.as_object_mut().unwrap().remove("ssk_generation");
        assert!(principal_signing_proof_transcript(&session).is_err());
    }
}
