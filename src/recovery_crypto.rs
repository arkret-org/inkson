//! Product-level recovery-key input and confirmation helpers.
//!
//! Key-backup KDF, nonce, commitment, and AEAD behavior is owned by
//! `arkret_crypto::backup`; this module intentionally contains no vault crypto.

use anyhow::{Result, anyhow};
pub use arkret_crypto::backup::{
    VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, VAULT_KDF_OUTPUT_LEN, VAULT_NONCE_LEN,
    VAULT_NONCE_SALT_LEN, VAULT_SALT_LEN, VaultKek, derive_vault_kek, derive_vault_kek_with_salt,
};
use sha2::{Digest, Sha256};

#[cfg(test)]
pub const IDENTITY_RECOVERY_ENTROPY_BYTES: usize = 32;

/// Generate a fresh 24-word BIP-39 identity recovery secret.
pub fn generate_recovery_key() -> Result<String> {
    arkret_crypto::identity_root::generate_bip39_identity_recovery_mnemonic()
        .map_err(|error| anyhow!("recovery key generation: {error}"))
}

#[cfg(test)]
pub fn format_recovery_key(bytes: &[u8]) -> String {
    arkret_crypto::identity_root::format_bip39_identity_recovery_mnemonic(bytes).unwrap_or_default()
}

pub fn normalize_recovery_key_input(input: &str) -> Option<String> {
    arkret_crypto::identity_root::normalize_bip39_identity_recovery_mnemonic(input).ok()
}

pub fn recovery_key_confirmation_matches(recovery_key: &str, confirmation: &str) -> bool {
    let Some(expected) = normalize_recovery_key_input(recovery_key) else {
        return false;
    };
    normalize_recovery_key_input(confirmation).as_deref() == Some(expected.as_str())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryKeyConfirmationDiff {
    Match,
    WordCount { entered: usize },
    MismatchAt { index: usize },
}

pub fn recovery_key_confirmation_diff(
    recovery_key: &str,
    confirmation: &str,
) -> RecoveryKeyConfirmationDiff {
    let expected = recovery_key
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let entered = confirmation
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    if entered.len() != expected.len() {
        return RecoveryKeyConfirmationDiff::WordCount {
            entered: entered.len(),
        };
    }
    expected
        .iter()
        .zip(&entered)
        .position(|(expected, entered)| expected != entered)
        .map_or(RecoveryKeyConfirmationDiff::Match, |index| {
            RecoveryKeyConfirmationDiff::MismatchAt { index: index + 1 }
        })
}

pub fn fingerprint_recovery_key(recovery_key: &str) -> String {
    let canonical = normalize_recovery_key_input(recovery_key).unwrap_or_else(|| {
        recovery_key
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase()
    });
    format!(
        "sha256:{}",
        crate::canonical::hex_encode(&Sha256::digest(canonical.as_bytes()))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sdk_kdf_is_deterministic_under_fixed_salt() {
        let salt = [42u8; VAULT_SALT_LEN];
        let first = derive_vault_kek_with_salt(b"correct horse battery staple", &salt).unwrap();
        let second = derive_vault_kek_with_salt(b"correct horse battery staple", &salt).unwrap();
        assert_eq!(first.key, second.key);
        assert_eq!(first.salt, second.salt);
    }

    #[test]
    fn recovery_key_round_trips_through_input_normalization() {
        let key = format_recovery_key(&[0u8; IDENTITY_RECOVERY_ENTROPY_BYTES]);
        let noisy = key
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>()
            .join("   ");
        assert_eq!(normalize_recovery_key_input(&noisy), Some(key));
    }

    #[test]
    fn confirmation_reports_first_mismatch() {
        let key = format_recovery_key(&[0u8; IDENTITY_RECOVERY_ENTROPY_BYTES]);
        let mut words = key.split_whitespace().collect::<Vec<_>>();
        words[6] = "zebra";
        assert_eq!(
            recovery_key_confirmation_diff(&key, &words.join(" ")),
            RecoveryKeyConfirmationDiff::MismatchAt { index: 7 }
        );
    }
}
