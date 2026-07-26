//! Private-data load/save and recovery-material predicates.

use dioxus::prelude::*;

use super::RECOVERY_STATE_KEY;
use super::types::RecoveryState;
use crate::recovery_crypto::fingerprint_recovery_key;
use crate::state::LocalStateStore;

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
    let key_material = arkret_sdk::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_key,
        "",
        0,
    )
    .ok()?;
    let rotated_at = arkret_sdk::canonical::format_timestamp_canonical(chrono::Utc::now());
    state.recovery_key_fingerprint = fingerprint.clone();
    state.backup_hpke_public_key_multibase = key_material.backup_hpke_public_key_multikey.clone();
    state.recovery_key_rotated_at = rotated_at.clone();
    save_state(state_store, account_key, &state);
    Some((fingerprint, rotated_at))
}

pub(crate) fn recovery_state_has_user_material(state: &RecoveryState) -> bool {
    !state.recovery_key_fingerprint.trim().is_empty()
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
    local_recovery_public_key_result(state_store, account_key).ok()
}

pub(crate) fn local_recovery_public_key_result(
    state_store: &LocalStateStore,
    account_key: &str,
) -> anyhow::Result<Vec<u8>> {
    if account_key.trim().is_empty() {
        anyhow::bail!("active account key is empty");
    }
    let raw = state_store.load_private_data(account_key, RECOVERY_STATE_KEY);
    let raw = match raw {
        Some(raw) => raw,
        None if state_store
            .private_data_keys()
            .iter()
            .any(|key| key == RECOVERY_STATE_KEY) =>
        {
            anyhow::bail!("local recovery metadata cannot be decoded for the active account")
        }
        None => anyhow::bail!("local recovery metadata is unavailable"),
    };
    let state: RecoveryState = serde_json::from_str(&raw)
        .map_err(|error| anyhow::anyhow!("local recovery metadata is invalid: {error}"))?;
    decode_recovery_public_key_multibase(&state.backup_hpke_public_key_multibase)
}

pub(super) fn decode_recovery_public_key_multibase(key: &str) -> anyhow::Result<Vec<u8>> {
    let key = key.trim();
    if key.is_empty() {
        anyhow::bail!("local recovery metadata has no backup HPKE public key");
    }
    let encoded = arkret_sdk::decode_multibase_base58btc(key)
        .map_err(|error| anyhow::anyhow!("local backup HPKE public key is invalid: {error}"))?;
    let (codec, header_len) = arkret_sdk::decode_multicodec_varint(&encoded)
        .ok_or_else(|| anyhow::anyhow!("local backup HPKE public key has no multicodec"))?;
    if codec != 0xec || encoded.len().saturating_sub(header_len) != 32 {
        anyhow::bail!("local backup HPKE public key is not an X25519 public multikey");
    }
    Ok(encoded[header_len..].to_vec())
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
