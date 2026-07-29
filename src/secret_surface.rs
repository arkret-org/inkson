//! Shared fail-closed checks for data that can leave a secret boundary.

use serde_json::Value;

const FORBIDDEN_SECRET_FIELD_NAMES: &[&str] = &[
    "account_mls_secret",
    "device_private_key",
    "device_seed",
    "hkdf_prk",
    "mls_secret",
    "mnemonic",
    "plaintext_keybag",
    "prk",
    "private_key",
    "recovery_key",
    "recovery_phrase",
    "recovery_secret",
    "root_private_key",
    "root_seed",
    "secret_b64u",
    "seed",
];

const PRIVATE_KEY_BLOCK_MARKERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SecretSurfaceViolation {
    ForbiddenField(String),
    PrivateKeyBlock(String),
    RecoveryMnemonic(String),
    TextAssignment(String),
}

impl SecretSurfaceViolation {
    pub(crate) fn path(&self) -> &str {
        match self {
            Self::ForbiddenField(path)
            | Self::PrivateKeyBlock(path)
            | Self::RecoveryMnemonic(path)
            | Self::TextAssignment(path) => path,
        }
    }
}

pub(crate) fn find_json_violation(path: &str, value: &Value) -> Option<SecretSurfaceViolation> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let next_path = format!("{path}.{key}");
                if is_forbidden_secret_field(key) {
                    return Some(SecretSurfaceViolation::ForbiddenField(next_path));
                }
                if let Some(violation) = find_json_violation(&next_path, value) {
                    return Some(violation);
                }
            }
            None
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(index, item)| find_json_violation(&format!("{path}[{index}]"), item)),
        Value::String(text) => find_text_violation(path, text),
        Value::Null | Value::Bool(_) | Value::Number(_) => None,
    }
}

pub(crate) fn find_text_violation(path: &str, text: &str) -> Option<SecretSurfaceViolation> {
    if PRIVATE_KEY_BLOCK_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
    {
        return Some(SecretSurfaceViolation::PrivateKeyBlock(path.to_owned()));
    }
    if contains_recovery_mnemonic(text) {
        return Some(SecretSurfaceViolation::RecoveryMnemonic(path.to_owned()));
    }
    if contains_secret_assignment(text) {
        return Some(SecretSurfaceViolation::TextAssignment(path.to_owned()));
    }
    None
}

pub(crate) fn sanitize_log_line(line: &str) -> &str {
    if find_text_violation("log", line).is_some() {
        "[redacted:secret-bearing-line]"
    } else {
        line
    }
}

fn is_forbidden_secret_field(name: &str) -> bool {
    FORBIDDEN_SECRET_FIELD_NAMES
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
}

fn contains_secret_assignment(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    FORBIDDEN_SECRET_FIELD_NAMES
        .iter()
        .any(|field| contains_field_assignment(&normalized, field))
}

fn contains_field_assignment(text: &str, field: &str) -> bool {
    let mut offset = 0;
    while let Some(relative) = text[offset..].find(field) {
        let start = offset + relative;
        let end = start + field.len();
        let before_is_boundary = start == 0
            || !text.as_bytes()[start - 1].is_ascii_alphanumeric()
                && text.as_bytes()[start - 1] != b'_';
        let after_is_boundary = end == text.len()
            || !text.as_bytes()[end].is_ascii_alphanumeric() && text.as_bytes()[end] != b'_';
        if before_is_boundary && after_is_boundary {
            let suffix = text[end..].trim_start();
            let suffix = suffix.strip_prefix('"').unwrap_or(suffix).trim_start();
            if suffix.starts_with('=') || suffix.starts_with(':') {
                return true;
            }
        }
        offset = end;
    }
    false
}

fn contains_recovery_mnemonic(text: &str) -> bool {
    let words = text
        .split(|character: char| !character.is_ascii_alphabetic())
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>();
    words.windows(24).any(|window| {
        crate::recovery_crypto::normalize_recovery_key_input(&window.join(" ")).is_some()
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn scans_store_log_telemetry_and_crash_shapes() {
        let mnemonic = crate::recovery_crypto::format_recovery_key(&[0_u8; 32]);
        let surfaces = [
            json!({"surface": "store", "private_key": "sentinel-private"}),
            json!({"surface": "log", "message": "seed=sentinel-seed"}),
            json!({"surface": "telemetry", "message": format!("words {mnemonic}")}),
            json!({
                "surface": "crash",
                "exception": {"value": "-----BEGIN PRIVATE KEY----- sentinel"}
            }),
        ];

        for surface in surfaces {
            assert!(
                find_json_violation("surface", &surface).is_some(),
                "{surface}"
            );
        }
    }

    #[test]
    fn permits_public_digests_ciphertext_and_opaque_references() {
        let public = json!({
            "prepared_plan_digest": format!("sha256:{}", "a".repeat(64)),
            "encrypted_backup_material": "ciphertext-only",
            "recovery_secret_ref": "ak:blob:public-ciphertext",
            "staged_secret_ref": "secure-store://security-transaction/opaque",
            "message": "recovery_key is required but was not supplied",
        });

        assert_eq!(find_json_violation("surface", &public), None);
    }

    #[test]
    fn log_sanitizer_never_returns_secret_bearing_input() {
        assert_eq!(
            sanitize_log_line("operation failed private_key=sentinel-private"),
            "[redacted:secret-bearing-line]"
        );
        assert_eq!(
            sanitize_log_line("operation failed safely"),
            "operation failed safely"
        );
    }
}
