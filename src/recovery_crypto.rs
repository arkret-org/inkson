//! Product-level recovery-key input and confirmation helpers.
//!
//! Key-backup KDF, nonce, commitment, and AEAD behavior is owned by
//! `arkret_crypto::backup`; this module intentionally contains no vault crypto.

use anyhow::{Result, anyhow};
pub use arkret_crypto::backup::{
    RECOVERY_KEY_BYTES, VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, VAULT_KDF_OUTPUT_LEN,
    VAULT_NONCE_LEN, VAULT_NONCE_SALT_LEN, VAULT_SALT_LEN, VaultKek, derive_vault_kek,
    derive_vault_kek_with_salt,
};
use sha2::{Digest, Sha256};

/// Generate a fresh 24-word BIP-39 Recovery Key.
pub fn generate_recovery_key() -> Result<String> {
    let mut bytes = [0u8; RECOVERY_KEY_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| anyhow!("recovery key rng: {error}"))?;
    Ok(format_recovery_key(&bytes))
}

pub fn format_recovery_key(bytes: &[u8]) -> String {
    bip39::Mnemonic::from_entropy_in(bip39::Language::English, bytes)
        .map(|mnemonic| mnemonic.words().collect::<Vec<_>>().join(" "))
        .unwrap_or_default()
}

pub fn normalize_recovery_key_input(input: &str) -> Option<String> {
    let collapsed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.split_whitespace().count() != 24 {
        return None;
    }
    let candidate = collapsed.to_ascii_lowercase();
    let mnemonic = bip39::Mnemonic::parse_in(bip39::Language::English, &candidate).ok()?;
    Some(mnemonic.words().collect::<Vec<_>>().join(" "))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OobCodeKind {
    DirectHandle,
    Lookup,
}

pub const OOB_DIRECT_HANDLE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
pub const OOB_DIRECT_HANDLE_MIN_LEN: usize = 22;

pub fn classify_oob_code(input: &str) -> Option<OobCodeKind> {
    let normalized = input
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '-')
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    if normalized.len() >= OOB_DIRECT_HANDLE_MIN_LEN
        && normalized
            .bytes()
            .all(|byte| OOB_DIRECT_HANDLE_ALPHABET.contains(&byte))
    {
        return Some(OobCodeKind::DirectHandle);
    }
    (normalized.len() >= 4
        && normalized
            .chars()
            .all(|character| character.is_ascii_alphanumeric()))
    .then_some(OobCodeKind::Lookup)
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OobCodeAttemptTracker {
    pub wrong_attempts: u8,
}

impl OobCodeAttemptTracker {
    pub const MAX_ATTEMPTS: u8 = 3;

    pub fn note_wrong(&mut self) -> bool {
        self.wrong_attempts = self.wrong_attempts.saturating_add(1);
        self.is_locked_to_generic_error()
    }

    pub fn is_locked_to_generic_error(&self) -> bool {
        self.wrong_attempts >= Self::MAX_ATTEMPTS
    }

    pub fn reset(&mut self) {
        self.wrong_attempts = 0;
    }
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
        let key = format_recovery_key(&[0u8; RECOVERY_KEY_BYTES]);
        let noisy = key
            .split_whitespace()
            .map(str::to_ascii_uppercase)
            .collect::<Vec<_>>()
            .join("   ");
        assert_eq!(normalize_recovery_key_input(&noisy), Some(key));
    }

    #[test]
    fn confirmation_reports_first_mismatch() {
        let key = format_recovery_key(&[0u8; RECOVERY_KEY_BYTES]);
        let mut words = key.split_whitespace().collect::<Vec<_>>();
        words[6] = "zebra";
        assert_eq!(
            recovery_key_confirmation_diff(&key, &words.join(" ")),
            RecoveryKeyConfirmationDiff::MismatchAt { index: 7 }
        );
    }

    #[test]
    fn oob_tracker_locks_after_three_failures() {
        let mut tracker = OobCodeAttemptTracker::default();
        assert!(!tracker.note_wrong());
        assert!(!tracker.note_wrong());
        assert!(tracker.note_wrong());
        tracker.reset();
        assert!(!tracker.is_locked_to_generic_error());
    }
}
