use serde_json::Value;

mod build;
#[cfg(test)]
mod domain_sep;
mod signing;

pub use build::*;
#[cfg(test)]
pub use domain_sep::*;
pub use signing::*;

#[cfg(test)]
mod tests;

pub use arkret_sdk::BackupKind;

#[cfg(test)]
pub fn key_backup_hkdf_info(class: BackupKind, subdomain: &str) -> String {
    class.hkdf_info(subdomain)
}

/// Build the `principal_signing` branch of a §7.8.1 high-risk delete proof.
///
/// The proof covers the **one** canonical delete-intent transcript every branch
/// signs — the service-issued challenge plus the caller's `reason`, with an
/// absent reason encoded as JSON `null` rather than omitted. Signing anything
/// the caller assembled itself is exactly what §7.8.1 forbids, so the transcript
/// comes from the challenge object and nothing here re-derives it.
///
/// `principal_key` MUST be the principal control key `verification_method`
/// resolves to in the principal's DID document; a device key is rejected by the
/// receiver, which resolves the method through that document precisely to
/// exclude device and service keys.
///
/// # Errors
///
/// Returns an error when the transcript cannot be canonicalized, when
/// `verification_method` is not a DID URL, or when `created_at` falls outside
/// the challenge window — the same window the receiver enforces, checked here so
/// a clock-skewed client fails locally instead of burning a challenge.
pub fn key_backup_delete_principal_signing_proof(
    challenge: &arkret_sdk::KeysBackupsDeleteChallenge,
    reason: Option<&str>,
    verification_method: &str,
    principal_key: &ed25519_dalek::SigningKey,
    created_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<arkret_sdk::KeyBackupDeleteProof> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::Signer as _;

    if created_at < challenge.issued_at || created_at > challenge.expires_at {
        anyhow::bail!(
            "delete proof created_at {created_at} is outside the challenge window              {}..{}",
            challenge.issued_at,
            challenge.expires_at
        );
    }
    let transcript = challenge.delete_intent_transcript(reason);
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| anyhow::anyhow!("delete-intent transcript is not canonical: {error}"))?;
    let payload_digest = challenge
        .delete_intent_digest(reason)
        .map_err(|error| anyhow::anyhow!("delete-intent digest failed: {error}"))?;

    // Detached JWS over the canonical transcript bytes, alg-only protected
    // header — the shape `EventSigner::detached_jws_over` produces and the one
    // the receiver splits on `..`.
    let header = serde_json::to_vec(&serde_json::json!({ "alg": "Ed25519" }))
        .map_err(|error| anyhow::anyhow!("delete proof header encode: {error}"))?;
    let signature = principal_key.sign(&canonical).to_bytes();
    let jws = format!(
        "{}..{}",
        URL_SAFE_NO_PAD.encode(&header),
        URL_SAFE_NO_PAD.encode(signature)
    );

    Ok(arkret_sdk::KeyBackupDeleteProof::PrincipalSigning {
        proof: arkret_sdk::PayloadProof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_sdk::DidUrl::new(verification_method.to_owned()).map_err(
                |error| {
                    anyhow::anyhow!("delete proof verification method is not a DID URL: {error}")
                },
            )?,
            payload_digest,
            created_at,
            domain: None,
            // The audience is already bound inside the signed transcript, so
            // repeating it on the envelope would be a second, unchecked copy.
            audience: None,
            proof_purpose: None,
            jws,
        },
    })
}

pub(crate) fn required_str<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} is required"))
}

pub(crate) fn required_str_anyhow<'a>(value: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    required_str(value, key).map_err(|err| anyhow::anyhow!(err))
}
