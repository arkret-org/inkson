//! Private-data load/save and recovery-material predicates.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use dioxus::prelude::*;

use super::RECOVERY_STATE_KEY;
use super::types::RecoveryState;
use crate::local_state::LocalStateStore;
use crate::recovery_crypto::fingerprint_recovery_key;

pub(crate) fn load_state(
    state_store: &SyncSignal<LocalStateStore>,
    account_key: &str,
) -> RecoveryState {
    if account_key.is_empty() {
        return RecoveryState::default();
    }
    match state_store
        .read()
        .load_private_data(account_key, RECOVERY_STATE_KEY)
    {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        None => RecoveryState::default(),
    }
}

pub(crate) fn save_state(
    state_store: &mut SyncSignal<LocalStateStore>,
    account_key: &str,
    state: &RecoveryState,
) {
    if account_key.is_empty() {
        return;
    }
    if let Ok(payload) = serde_json::to_string(state) {
        state_store
            .write()
            .save_private_data(account_key, RECOVERY_STATE_KEY, payload);
    }
}

pub(crate) fn save_generated_recovery_key_metadata(
    state_store: &mut SyncSignal<LocalStateStore>,
    account_key: &str,
    recovery_key: &str,
) -> Option<(String, String)> {
    if account_key.trim().is_empty() || recovery_key.trim().is_empty() {
        return None;
    }
    let mut state = load_state(state_store, account_key);
    let fingerprint = fingerprint_recovery_key(recovery_key);
    let (_, recovery_public_key) =
        crate::hpke_backup::derive_recovery_keypair_from_recovery_key(recovery_key).ok()?;
    let rotated_at = chrono::Utc::now().to_rfc3339();
    state.recovery_key_fingerprint = fingerprint.clone();
    state.recovery_public_key_b64u = B64.encode(recovery_public_key);
    state.recovery_key_rotated_at = rotated_at.clone();
    state.passkey_wraps.clear();
    save_state(state_store, account_key, &state);
    Some((fingerprint, rotated_at))
}

pub(crate) fn recovery_state_has_user_material(state: &RecoveryState) -> bool {
    !state.recovery_key_fingerprint.trim().is_empty()
        || state
            .guardians
            .iter()
            .any(|guardian| !guardian.did.trim().is_empty() || !guardian.label.trim().is_empty())
}

pub(crate) fn recovery_options_configured(
    state_store: &LocalStateStore,
    account_key: &str,
) -> bool {
    if account_key.trim().is_empty() {
        return false;
    }
    state_store
        .load_private_data(account_key, RECOVERY_STATE_KEY)
        .and_then(|raw| serde_json::from_str::<RecoveryState>(&raw).ok())
        .map(|state| recovery_state_has_user_material(&state))
        .unwrap_or(false)
}

/// SHA-256 fingerprint of the locally configured Recovery Key (24 words), if
/// one was ever generated on this device. Used by recovery prompts and settings
/// affordances; never the plaintext.
pub(crate) fn local_recovery_key_fingerprint(
    state_store: &LocalStateStore,
    account_key: &str,
) -> Option<String> {
    if account_key.trim().is_empty() {
        return None;
    }
    state_store
        .load_private_data(account_key, RECOVERY_STATE_KEY)
        .and_then(|raw| serde_json::from_str::<RecoveryState>(&raw).ok())
        .map(|state| state.recovery_key_fingerprint)
        .filter(|fp| !fp.trim().is_empty())
}

/// Public HPKE key derived from the locally configured Recovery Key. This is
/// safe to keep because it can only seal new backups; opening them still
/// requires the offline 24-word Recovery Key.
pub(crate) fn local_recovery_public_key(
    state_store: &LocalStateStore,
    account_key: &str,
) -> Option<Vec<u8>> {
    if account_key.trim().is_empty() {
        return None;
    }
    state_store
        .load_private_data(account_key, RECOVERY_STATE_KEY)
        .and_then(|raw| serde_json::from_str::<RecoveryState>(&raw).ok())
        .map(|state| state.recovery_public_key_b64u)
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
        .and_then(|key| B64.decode(key.as_bytes()).ok())
        .filter(|key| !key.is_empty())
}

pub(crate) fn fmt_relative(iso: &str) -> String {
    if iso.is_empty() {
        return "never".to_owned();
    }
    let parsed = chrono::DateTime::parse_from_rfc3339(iso).ok();
    let Some(parsed) = parsed else {
        return iso.to_owned();
    };
    let now = chrono::Utc::now();
    let dur = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));
    let secs = dur.num_seconds().max(0);
    if secs < 60 {
        "just now".to_owned()
    } else if secs < 3_600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} hr ago", secs / 3_600)
    } else {
        format!("{} days ago", secs / 86_400)
    }
}
