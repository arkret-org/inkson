//! F-DPOP-1: Proof-of-Possession JWS (DPoP-style) for session-grant
//! and key-package claim flows.
//!
//! Spec sources:
//! - `identity/session-grants.md` — every grant exchange MUST carry a proof binding the request to
//!   a client-held keypair so a stolen bearer token can't be replayed elsewhere.
//! - `crypto-media/key-packages.md §3` — `claim_keys` requests must present DPoP-style proofs to
//!   prevent token substitution attacks across recipients.
//!
//! RFC 9449 specifies DPoP in terms of EC-based keys (P-256). Yougen
//! already carries Ed25519 plumbing throughout its cross-signing and
//! recovery flows, so this module uses `EdDSA` JWS instead — the
//! [JWA registry] explicitly allows it as a JWS `alg` value, and
//! soland's verifier mirrors the choice. Switching the wire to EC
//! later is a Cargo.toml + closure swap; the public API here is
//! algorithm-agnostic.
//!
//! [JWA registry]: https://www.iana.org/assignments/jose
//!
//! The module is deliberately self-contained: no I/O, no SDK calls.
//! Higher layers (`coauth.rs`, `api.rs::claim_keys`) take the
//! returned proof string and attach it as the `DPoP:` request header.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use getrandom::fill;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// JOSE-style header carried in the proof's protected segment. We
/// keep it as a typed struct (instead of inline JSON) so a future
/// audit can confirm the field set at a glance.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DpopProtectedHeader {
    typ: String,
    alg: String,
    jwk: DpopJwk,
}

/// Public-key JWK embedded in the protected header. Matches RFC 7517
/// for `kty=OKP` / `crv=Ed25519` and RFC 8037 §2 for the binary
/// encoding of `x`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopJwk {
    pub kty: String,
    pub crv: String,
    /// Base64url-no-pad of the 32-byte Ed25519 public key.
    pub x: String,
}

impl DpopJwk {
    pub fn from_verifying_key(verifying_key: &VerifyingKey) -> Self {
        Self {
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
        }
    }
}

/// RFC 9449 §4 claims. Each proof binds to (HTTP method, HTTP target
/// URI, issue time, unique nonce). The receiver replays `jti`s into
/// a short-TTL cache so a captured proof can't be replayed on a
/// different request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DpopClaims {
    /// HTTP method, uppercase per RFC 9449 §4.1.
    pub htm: String,
    /// HTTP target URI without the query string.
    pub htu: String,
    /// Issued-at, Unix seconds.
    pub iat: i64,
    /// Unique per-proof nonce. Callers should generate a 128-bit
    /// random value and base64url-no-pad encode it.
    pub jti: String,
    /// Optional server-issued nonce (RFC 9449 §8). When the server
    /// challenges the client with `DPoP-Nonce: <value>` the next
    /// proof MUST echo it back so the server can rate-limit and
    /// detect replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Access-token hash (RFC 9449 §4.2). When a proof accompanies an
    /// access token, callers set this to
    /// `base64url-no-pad(sha256(access_token))` so the proof cannot be
    /// replayed with a different bearer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,
}

/// F-DPOP-1: build a serialised, attached JWS that yougen can stamp
/// into a `DPoP:` request header.
///
/// Format mirrors RFC 7515 compact serialization:
/// `base64url(header).base64url(payload).base64url(signature)`.
///
/// The header carries `typ=dpop+jwt`, `alg=EdDSA`, and the
/// caller's `jwk` (so the receiver can derive the thumbprint
/// without an out-of-band key directory). The payload is the
/// canonical [`DpopClaims`] JSON; the signature is Ed25519 over
/// `header.payload`.
pub fn build_dpop_proof_ed25519(
    signing_key: &SigningKey,
    claims: &DpopClaims,
) -> Result<String, DpopError> {
    if claims.htm.is_empty() {
        return Err(DpopError::EmptyClaim("htm"));
    }
    if claims.htu.is_empty() {
        return Err(DpopError::EmptyClaim("htu"));
    }
    if claims.jti.is_empty() {
        return Err(DpopError::EmptyClaim("jti"));
    }

    let header = DpopProtectedHeader {
        typ: "dpop+jwt".to_owned(),
        alg: "EdDSA".to_owned(),
        jwk: DpopJwk::from_verifying_key(&signing_key.verifying_key()),
    };
    let header_bytes =
        serde_json::to_vec(&header).map_err(|err| DpopError::Encode(err.to_string()))?;
    let payload_bytes =
        serde_json::to_vec(claims).map_err(|err| DpopError::Encode(err.to_string()))?;
    let header_b64 = URL_SAFE_NO_PAD.encode(header_bytes);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_bytes);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{signature_b64}"))
}

/// RFC 7638 JWK thumbprint for an Ed25519 `OKP` key. Encoded as
/// `base64url-no-pad(sha256(canonical_json))`.
///
/// The canonical form is the JWK with only the required members
/// (`crv`, `kty`, `x`), serialized in lex-min key order without
/// whitespace. Soland's `ck.session.grant` verifier rebuilds the
/// same string and compares — the value is what gets bound to the
/// access token (`jkt` claim) so a proof from a different
/// keypair is rejected.
pub fn jwk_thumbprint_ed25519(verifying_key: &VerifyingKey) -> String {
    let x = URL_SAFE_NO_PAD.encode(verifying_key.to_bytes());
    // Members are inlined in lex-min order — RFC 7638 mandates
    // exactly this serialization. Don't use `serde_json::json!`
    // because BTreeMap ordering depends on serde flags.
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    let digest = Sha256::digest(canonical.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Errors surfaced by [`build_dpop_proof_ed25519`].
#[derive(Debug, PartialEq, Eq)]
pub enum DpopError {
    /// A required claim (`htm` / `htu` / `jti`) was empty.
    EmptyClaim(&'static str),
    /// `serde_json` failed to encode the header or payload — should
    /// never happen for the typed structs above, but we surface it
    /// rather than panic just in case.
    Encode(String),
}

impl std::fmt::Display for DpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyClaim(name) => write!(f, "DPoP claim `{name}` must not be empty"),
            Self::Encode(msg) => write!(f, "DPoP encode failed: {msg}"),
        }
    }
}

impl std::error::Error for DpopError {}

/// Convenience constructor for [`DpopClaims`] that fills in a fresh
/// `iat` (current Unix seconds) and a 128-bit random `jti`.
///
/// Test code can build claims directly via the struct literal when
/// it wants to pin the timestamps; production callers should reach
/// for this builder so every proof gets its own nonce.
pub fn fresh_dpop_claims(
    htm: impl Into<String>,
    htu: impl Into<String>,
    nonce: Option<String>,
) -> DpopClaims {
    let mut bytes = [0u8; 16];
    // yougen routes randomness through `getrandom` everywhere else
    // (see `recovery_crypto`); stay consistent so audit logging
    // / RNG-feature flags don't have to special-case DPoP.
    fill(&mut bytes).expect("getrandom should not fail");
    DpopClaims {
        htm: htm.into(),
        htu: htu.into(),
        iat: chrono::Utc::now().timestamp(),
        jti: URL_SAFE_NO_PAD.encode(bytes),
        nonce,
        ath: None,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{SECRET_KEY_LENGTH, SigningKey};

    use super::*;

    fn signing_key_with_seed(seed: u8) -> SigningKey {
        let bytes: [u8; SECRET_KEY_LENGTH] = [seed; SECRET_KEY_LENGTH];
        SigningKey::from_bytes(&bytes)
    }

    fn fixed_claims() -> DpopClaims {
        DpopClaims {
            htm: "POST".to_owned(),
            htu: "https://soland.example/_cokret/gate/session_grants/exchange".to_owned(),
            iat: 1_716_000_000,
            jti: "fixed-nonce-1234".to_owned(),
            nonce: None,
            ath: None,
        }
    }

    #[test]
    fn proof_has_three_dot_separated_segments() {
        let key = signing_key_with_seed(0x42);
        let proof = build_dpop_proof_ed25519(&key, &fixed_claims()).expect("proof");
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3, "got {parts:?}");
        for p in &parts {
            assert!(!p.is_empty(), "segment empty in {proof}");
        }
    }

    #[test]
    fn proof_is_deterministic_for_fixed_inputs() {
        // Ed25519 is a deterministic signature scheme; identical
        // inputs MUST produce byte-identical proofs. Soland's
        // anti-replay cache relies on the `jti` to distinguish
        // proofs — if the underlying scheme were non-deterministic
        // we'd still get distinct signatures with the same `jti`,
        // which would mask a real replay.
        let key = signing_key_with_seed(0x42);
        let a = build_dpop_proof_ed25519(&key, &fixed_claims()).unwrap();
        let b = build_dpop_proof_ed25519(&key, &fixed_claims()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_jti_yields_distinct_signature() {
        let key = signing_key_with_seed(0x42);
        let mut c1 = fixed_claims();
        let mut c2 = fixed_claims();
        c2.jti = "fixed-nonce-5678".to_owned();
        let p1 = build_dpop_proof_ed25519(&key, &c1).unwrap();
        let p2 = build_dpop_proof_ed25519(&key, &c2).unwrap();
        assert_ne!(p1, p2);
        // Sanity: the only difference at the payload byte level is jti.
        c1.jti = c2.jti.clone();
        let p1_aligned = build_dpop_proof_ed25519(&key, &c1).unwrap();
        assert_eq!(p1_aligned, p2);
    }

    #[test]
    fn empty_required_claim_rejected() {
        let key = signing_key_with_seed(0x42);
        let mut claims = fixed_claims();
        claims.htm = String::new();
        assert_eq!(
            build_dpop_proof_ed25519(&key, &claims),
            Err(DpopError::EmptyClaim("htm"))
        );
        let mut claims = fixed_claims();
        claims.htu = String::new();
        assert_eq!(
            build_dpop_proof_ed25519(&key, &claims),
            Err(DpopError::EmptyClaim("htu"))
        );
        let mut claims = fixed_claims();
        claims.jti = String::new();
        assert_eq!(
            build_dpop_proof_ed25519(&key, &claims),
            Err(DpopError::EmptyClaim("jti"))
        );
    }

    #[test]
    fn signature_verifies_with_public_key_from_header() {
        use base64::Engine as _;
        use ed25519_dalek::{Signature, Verifier};
        let key = signing_key_with_seed(0xab);
        let proof = build_dpop_proof_ed25519(&key, &fixed_claims()).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let signature = Signature::from_slice(&sig_bytes).unwrap();
        key.verifying_key()
            .verify(signing_input.as_bytes(), &signature)
            .expect("signature must verify against the same key");
    }

    #[test]
    fn jwk_thumbprint_is_deterministic_for_a_given_key() {
        let key = signing_key_with_seed(0x42);
        let t1 = jwk_thumbprint_ed25519(&key.verifying_key());
        let t2 = jwk_thumbprint_ed25519(&key.verifying_key());
        assert_eq!(t1, t2);
        assert!(!t1.is_empty());
    }

    #[test]
    fn jwk_thumbprint_changes_across_different_keys() {
        let a = signing_key_with_seed(0x10);
        let b = signing_key_with_seed(0x20);
        assert_ne!(
            jwk_thumbprint_ed25519(&a.verifying_key()),
            jwk_thumbprint_ed25519(&b.verifying_key())
        );
    }

    #[test]
    fn jwk_in_header_round_trips_through_serde() {
        let key = signing_key_with_seed(0xab);
        let proof = build_dpop_proof_ed25519(&key, &fixed_claims()).unwrap();
        let header_b64 = proof.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        // Decode as a generic Value to avoid threading the lifetime
        // of the borrowed header bytes through DpopProtectedHeader.
        let header: serde_json::Value =
            serde_json::from_slice(&header_bytes).expect("header decodes");
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["jwk"]["kty"], "OKP");
        assert_eq!(header["jwk"]["crv"], "Ed25519");
        let jwk_x = header["jwk"]["x"].as_str().unwrap();
        let raw_x = URL_SAFE_NO_PAD.decode(jwk_x).unwrap();
        assert_eq!(raw_x, key.verifying_key().to_bytes());
    }

    #[test]
    fn fresh_dpop_claims_fills_iat_and_jti() {
        let claims = fresh_dpop_claims("POST", "https://soland.example/grants", None);
        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://soland.example/grants");
        assert!(claims.iat > 1_700_000_000);
        // jti should be base64url 22 chars (16 bytes encoded
        // without padding).
        assert_eq!(claims.jti.len(), 22);
        assert!(claims.ath.is_none());
    }

    #[test]
    fn optional_ath_serializes_when_present() {
        let key = signing_key_with_seed(0x42);
        let mut claims = fixed_claims();
        claims.ath = Some("token-hash".to_owned());
        let proof = build_dpop_proof_ed25519(&key, &claims).unwrap();
        let payload_b64 = proof.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["ath"], "token-hash");
    }
}
