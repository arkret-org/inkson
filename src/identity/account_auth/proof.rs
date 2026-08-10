use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

/// Convenience helper: build the full
/// [`arkret_sdk::SessionGrantIntrospectionProof`] (challenge + proof_jwt
/// bundle) ready to attach to a soland `session-grant/exchange` request.
/// The challenge is freshly minted from `current_time + grant_id`.
pub fn build_session_grant_introspection_proof_bundle(
    grant_id: &str,
    grant_jwt: &str,
    audience: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<arkret_sdk::SessionGrantIntrospectionProof> {
    let challenge = format!(
        "{ts}-{grant_id}",
        ts = chrono::Utc::now().timestamp_millis()
    );
    let proof_jwt = build_session_grant_introspection_proof(
        grant_id,
        grant_jwt,
        audience,
        &challenge,
        signing_key,
    )?;
    Ok(arkret_sdk::SessionGrantIntrospectionProof {
        challenge,
        proof_jwt,
    })
}

/// Decode the ephemeral private key returned with a coauth
/// `principal_session` grant. This key, not the long-lived local device key,
/// signs the one-use introspection proof soland forwards back to coauth.
pub fn session_grant_signing_key_from_pem(pem: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    use ed25519_dalek::pkcs8::DecodePrivateKey as _;

    ed25519_dalek::SigningKey::from_pkcs8_pem(pem.trim())
        .context("decode coauth session grant private key")
}

/// Build a session-grant introspection proof JWS. Signs the canonical
/// claims with the ephemeral session-grant private key whose public half
/// is stored by coauth as `session_public_key`.
///
/// The `challenge` is freshly constructed by the caller, typically
/// `format!("{ts}-{grant_id}")` where `ts` is the current Unix time.
/// The `expires_at` window is fixed at 60s - matches coauth's reference
/// implementation (`Duration::try_minutes(1)`).
///
/// Returns the JWS in compact serialization (`<header>.<payload>.<sig>`).
/// Embed the result in a [`SessionGrantIntrospectionProof`] and post it
/// to the soland endpoint that requires session-grant verification.
pub fn build_session_grant_introspection_proof(
    grant_id: &str,
    grant_jwt: &str,
    audience: &str,
    challenge: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<String> {
    if grant_id.trim().is_empty() {
        anyhow::bail!("grant_id is required");
    }
    if grant_jwt.trim().is_empty() {
        anyhow::bail!("grant_jwt is required");
    }
    if audience.trim().is_empty() {
        anyhow::bail!("audience is required");
    }
    let audience = arkret_sdk::ServiceId::new(audience.trim().to_owned())
        .map_err(|error| anyhow::anyhow!("audience must be a service core_id: {error}"))?;
    if challenge.trim().is_empty() {
        anyhow::bail!("challenge is required");
    }
    let now = chrono::Utc::now();
    let claims = arkret_sdk::SessionGrantIntrospectionProofClaims {
        kind: arkret_sdk::SESSION_GRANT_INTROSPECTION_PROOF_CLAIMS_KIND.to_owned(),
        grant_id: grant_id.to_owned(),
        grant_jwt_hash: session_grant_jwt_hash(grant_jwt),
        audience,
        challenge: challenge.to_owned(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    sign_compact_jws_ed25519(&claims, signing_key)
}

/// Hash the grant JWT bytes per coauth's `session_grant_jwt_hash`
/// (`"sha256:" + hex(sha256(grant_jwt))`). Public so callers can verify
/// their proof binding before sending.
pub fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    arkret_sdk::canonical::sha256_digest(grant_jwt.as_bytes())
}

/// Internal helper: serialize claims to canonical JSON, base64url-encode
/// header + payload, sign with Ed25519, return the compact JWS.
fn sign_compact_jws_ed25519<C: Serialize>(
    claims: &C,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<String> {
    use ed25519_dalek::Signer;
    // Compact JWS header (`alg=Ed25519`). The optional `typ=JWT` claim
    // tells generic JWT verifiers this is a JWT proof token; coauth's
    // verifier doesn't require it but adding it improves cross-provider
    // tooling round-trips.
    let header_json = br#"{"alg":"Ed25519","typ":"JWT"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_json = serde_json::to_vec(claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}
