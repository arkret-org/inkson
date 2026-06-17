use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Session-grant introspection proof claims. Mirrors
/// coauth's `SessionGrantIntrospectionProofClaims` (see
/// `coauth/crates/backend/src/handlers/cokret.rs:575`). soland forwards
/// the proof to coauth's private introspection endpoint when validating
/// a session-grant binding — the JWS MUST verify against
/// the session_public_key registered with the grant, and the
/// claims MUST match `grant_id` / `grant_jwt_hash` / `audience` /
/// `challenge` / `issued_at` / `expires_at` exactly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionGrantIntrospectionProofClaims {
    /// Always `"ck.session_grant.introspection_proof.v1"`.
    #[serde(rename = "type")]
    pub kind: String,
    pub grant_id: String,
    /// `"sha256:<hex>"` of the grant JWT bytes.
    pub grant_jwt_hash: String,
    /// MUST match `grant.audience` (typically the principal-server URL).
    pub audience: String,
    /// Random per-introspection challenge string supplied by the caller.
    pub challenge: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Convenience helper: build the full
/// [`crate::api::SessionGrantIntrospectionProof`] (challenge + proof_jwt
/// bundle) ready to attach to a soland `session-grant/exchange` request.
/// The challenge is freshly minted from `current_time + grant_id`.
pub fn build_session_grant_introspection_proof_bundle(
    grant_id: &str,
    grant_jwt: &str,
    audience: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<crate::api::SessionGrantIntrospectionProof> {
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
    Ok(crate::api::SessionGrantIntrospectionProof {
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
    if challenge.trim().is_empty() {
        anyhow::bail!("challenge is required");
    }
    let now = chrono::Utc::now();
    let claims = SessionGrantIntrospectionProofClaims {
        kind: "ck.session_grant.introspection_proof.v1".to_owned(),
        grant_id: grant_id.to_owned(),
        grant_jwt_hash: session_grant_jwt_hash(grant_jwt),
        audience: audience.to_owned(),
        challenge: challenge.to_owned(),
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(60),
    };
    sign_compact_jws_eddsa(&claims, signing_key)
}

/// Deterministic `sha256:<hex>` digest binding the OIDC code-exchange request
/// fields. The Account Authority does not consult this for the
/// `oidc_code_exchange` branch (it re-validates against the issuer), but the
/// SDK [`cokret_sdk::SessionGrantRequestProof`] requires a valid [`Hash`], so
/// we compute a real content digest of the binding fields rather than ship a
/// placeholder.
pub(crate) fn oidc_request_canonical_digest(
    issuer: &str,
    client_id: &str,
    authorization_code: &str,
    state: &str,
) -> anyhow::Result<cokret_sdk::Hash> {
    let canonical = format!("oidc_code_exchange|{issuer}|{client_id}|{authorization_code}|{state}");
    let digest = format!(
        "sha256:{}",
        crate::canonical::hex_encode(&Sha256::digest(canonical.as_bytes()))
    );
    cokret_sdk::Hash::new(digest)
        .map_err(|error| anyhow::anyhow!("invalid oidc request digest: {error}"))
}

/// Hash the grant JWT bytes per coauth's `session_grant_jwt_hash`
/// (`"sha256:" + hex(sha256(grant_jwt))`). Public so callers can verify
/// their proof binding before sending.
pub fn session_grant_jwt_hash(grant_jwt: &str) -> String {
    format!(
        "sha256:{}",
        crate::canonical::hex_encode(&Sha256::digest(grant_jwt.as_bytes()))
    )
}

/// Internal helper: serialize claims to canonical JSON, base64url-encode
/// header + payload, sign with Ed25519, return the compact JWS.
fn sign_compact_jws_eddsa<C: Serialize>(
    claims: &C,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<String> {
    use ed25519_dalek::Signer;
    // Compact JWS header (`alg=EdDSA`). The optional `typ=JWT` claim
    // tells generic JWT verifiers this is a JWT proof token; coauth's
    // verifier doesn't require it but adding it improves cross-provider
    // tooling round-trips.
    let header_json = br#"{"alg":"EdDSA","typ":"JWT"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json);
    let payload_json = serde_json::to_vec(claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes()).to_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature);
    Ok(format!("{header_b64}.{payload_b64}.{sig_b64}"))
}
