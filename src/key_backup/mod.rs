use serde_json::Value;

mod build;
mod domain_sep;
mod signing;
mod validate;

pub use build::*;
pub use domain_sep::*;
pub use signing::*;
pub use validate::*;

#[cfg(test)]
mod tests;

const KEY_BACKUP_RAW_SIGNATURE_ALGORITHM: &str = "Ed25519";

pub use arkret_sdk::BackupKind;

/// Envelope fields the backup `auth_data.signature` MUST cover (key-management.md
/// §7.4.1 / §7.6 + the `ak.schema.key_backup.v1` `signed_fields.allOf`). Optional
/// fields (`supersedes`, `supersedes_digest`, `frontier_ref`) are only listed
/// when present on the envelope.
pub const KEY_BACKUP_SIGNED_FIELDS: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_kind",
    "backup_version",
    "series_id",
    "series_seq",
    "supersedes",
    "supersedes_digest",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
    "frontier_ref",
    // did_recovery backups MUST carry + sign this (key-backup.schema.json);
    // other classes MAY carry it as a hint. Listed here so the signer covers it
    // whenever present (the filter drops it when absent).
    "recovery_policy_ref",
];

/// The mandatory subset of [`KEY_BACKUP_SIGNED_FIELDS`] that MUST always be
/// covered (genesis envelopes omit `supersedes*`/`frontier_ref`).
const KEY_BACKUP_SIGNED_FIELDS_MANDATORY: &[&str] = &[
    "backup_id",
    "actor_id",
    "backup_kind",
    "backup_version",
    "series_id",
    "series_seq",
    "encryption",
    "domain_separation",
    "contents",
    "ciphertext_digest",
];

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

pub(crate) fn required_u64(value: &Value, key: &str) -> Result<u64, String> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{key} is required"))
}

pub(crate) fn is_protocol_device_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:device:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

pub(crate) fn is_protocol_backup_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:backup:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

pub(crate) fn is_protocol_backup_series_id(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak:backup_series:") else {
        return false;
    };
    rest.len() == 36
        && rest.chars().enumerate().all(|(idx, ch)| match idx {
            8 | 13 | 18 | 23 => ch == '-',
            14 => ch == '7',
            19 => matches!(ch, '8' | '9' | 'a' | 'b'),
            _ => ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
        })
}

pub(crate) fn is_base64url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

/// Protocol digest check: delegates to the single canonical validator
/// `arkret_sdk::Hash::new`, which accepts only the registered `sha256:` /
/// `blake3:` forms with lowercase-hex digests (digest-suite-registry). The
/// previous hand-rolled version additionally accepted `sha3_256:` / `sha512:`
/// and uppercase hex — both rejected by the protocol — so it has been removed
/// to avoid forking the digest grammar.
pub(crate) fn is_sha_digest(value: &str) -> bool {
    arkret_sdk::Hash::new(value).is_ok()
}
