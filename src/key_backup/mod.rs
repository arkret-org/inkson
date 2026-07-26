use serde_json::Value;

mod build;
mod domain_sep;
mod signing;
mod validate;

pub use build::*;
pub use domain_sep::*;
pub use signing::*;
pub use validate::*;

const KEY_BACKUP_SCHEMA: &str = "ak.schema.key_backup.v1";
const KEY_BACKUP_RAW_SIGNATURE_ALGORITHM: &str = "Ed25519";
pub const KEY_BACKUP_UNLOCK_PROOF_SCHEMA: &str = "ak.schema.key_backup_unlock_proof.v1";
pub const KEY_BACKUP_PLAINTEXT_SCHEMA: &str = "ak.schema.key_backup_plaintext.v1";
pub const KEY_BACKUP_ACTIVE_SERIES_SCHEMA: &str = "ak.schema.key_backup_active_series.v1";
pub const DEFAULT_SSK_GENERATION: u64 = 1;

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

pub fn key_backup_delete_ownership_proof(actor_id: &str, backup_id: &str) -> String {
    format!("dev-ssk-delete:v1:{actor_id}:{backup_id}")
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

#[cfg(test)]
mod tests;
