//! Recovery surface — Recovery Key (24 words) + restore-from-backup, with
//! Social Recovery tucked behind an "Advanced" fold.
//!
//! - **Recovery Key (24 words)**: 256 bits of entropy, formatted as a 24-word BIP-39 mnemonic. This
//!   is the ONLY user-visible recovery credential — `normalize_recovery_key_input` (and therefore
//!   the `MlsUnlockPrompt` restore path) only accepts this 24-word format, so generating the key
//!   also wraps the account MLS secret behind it and uploads that backup (see
//!   `upload_recovery_key_account_backup`). The mnemonic plaintext only lives in memory between
//!   Generate and the user's Copy interaction; only a SHA-256 fingerprint plus rotation timestamp
//!   are persisted via `LocalStateStore::save_private_data` — the words themselves are never
//!   uploaded.
//! - **Restore from backup**: lists the server-side `ck.schema.key_backup.v1` ciphertext envelopes
//!   and decrypts them on-device with the 24-word Recovery Key. Envelopes sealed by the removed
//!   vault-passphrase flows are legacy garbage: they can still be listed and deleted, but no longer
//!   decrypted.
//! - **Social Recovery** (advanced, local bookkeeping only): guardian list + Shamir threshold +
//!   last-rehearsal timestamp persisted as JSON under the same private_data store.
//!
//! Everything writeable goes through `private_data`, which is itself
//! encrypted at rest under the account DID via `xor_encrypt` (and on
//! wasm32 mirrored to localStorage). The Recovery view never persists
//! the Recovery Key in plaintext.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::HelpTip;
use crate::local_state::LocalStateStore;
use crate::operation::uuid_v7;
use crate::recovery_crypto::{
    fingerprint_recovery_key, generate_passkey_wrap_salt, generate_recovery_key,
    normalize_recovery_key_input, open_recovery_key_with_passkey_prf,
    seal_recovery_key_with_passkey_prf,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{short_protocol_id, with_authed_api};

const RECOVERY_STATE_KEY: &str = "recovery.state.v1";

// SyncBadge / SyncBadgeState are shared in `crate::components::sync_badge`.
// The Recovery view renders the Recovery Key backup state through the shared
// component, overriding the "Local" label to "Not backed up yet" — the badge
// semantics stay global, only this view's copy changes. See C1.
use crate::components::SyncBadgeState as SyncBadge;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Guardian {
    label: String,
    did: String,
    note: String,
    #[serde(default)]
    confirmed: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct PasskeyRecoveryWrap {
    #[serde(default)]
    wrap_id: String,
    #[serde(default)]
    credential_id_b64: String,
    #[serde(default)]
    credential_label: String,
    #[serde(default)]
    rp_id: String,
    #[serde(default)]
    salt_b64: String,
    #[serde(default)]
    nonce_b64: String,
    #[serde(default)]
    ciphertext_b64: String,
    #[serde(default)]
    ciphertext_digest: String,
    #[serde(default)]
    recovery_key_fingerprint: String,
    #[serde(default)]
    created_at: String,
}

/// One row in the "List existing backups" table — server-side metadata
/// only. The server returns the full `ck.schema.key_backup.v1` envelope
/// (encryption block + ciphertext) and we decode just the fields the
/// restore UI actually needs: identification, KDF salt, AEAD nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BackupSummaryRow {
    backup_id: String,
    backup_class: String,
    recipient_method: String,
    backup_version: String,
    created_at: String,
    ciphertext_digest: String,
    salt_b64: String,
    nonce_b64: String,
    ciphertext_b64: String,
    /// Full server-returned envelope, retained so the recovery path can
    /// re-drive `restore_mls_history_backup_with_device_snapshot` and unwrap the
    /// account MLS secret (which both need the complete body, not just the
    /// summary fields). The list endpoint already returns full bodies.
    body: serde_json::Value,
}

fn parse_backup_summary(v: &serde_json::Value) -> Option<BackupSummaryRow> {
    let backup_id = v.get("backup_id")?.as_str()?.to_owned();
    let backup_class = v
        .get("backup_class")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let recipient_method = v
        .pointer("/encryption/recipient_method")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let backup_version = v
        .get("backup_version")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let created_at = v
        .get("created_at")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let ciphertext_digest = v
        .get("ciphertext_digest")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let salt_b64 = v
        .pointer("/encryption/kdf/salt")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let nonce_b64 = v
        .pointer("/encryption/aead/nonce")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    let ciphertext_b64 = v
        .get("ciphertext")
        .and_then(|c| c.as_str())
        .unwrap_or("")
        .to_owned();
    Some(BackupSummaryRow {
        backup_id,
        backup_class,
        recipient_method,
        backup_version,
        created_at,
        ciphertext_digest,
        salt_b64,
        nonce_b64,
        ciphertext_b64,
        body: v.clone(),
    })
}

/// Extract `BackupSummaryRow`s from the typed `list_key_backups`
/// response (`{"backups": [...]}`).
fn parse_backup_list(payload: &serde_json::Value) -> Vec<BackupSummaryRow> {
    payload
        .get("backups")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(parse_backup_summary).collect())
        .unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct BackupClassCounts {
    did_recovery: usize,
    secret_storage: usize,
    mls_history: usize,
    other: usize,
}

fn backup_class_counts(rows: &[BackupSummaryRow]) -> BackupClassCounts {
    let mut counts = BackupClassCounts::default();
    for row in rows {
        match row.backup_class.as_str() {
            "did_recovery" => counts.did_recovery += 1,
            "secret_storage" => counts.secret_storage += 1,
            "mls_history" => counts.mls_history += 1,
            _ => counts.other += 1,
        }
    }
    counts
}

fn backup_inventory_status(rows: &[BackupSummaryRow]) -> String {
    let counts = backup_class_counts(rows);
    if rows.is_empty() {
        return "Loaded 0 backups from the server. Recovery is incomplete: no did_recovery backup is available.".to_owned();
    }
    let mut message = format!(
        "Loaded {} backup(s): did_recovery {}, secret_storage {}, mls_history {}",
        rows.len(),
        counts.did_recovery,
        counts.secret_storage,
        counts.mls_history
    );
    if counts.other > 0 {
        message.push_str(&format!(", other {}", counts.other));
    }
    if counts.did_recovery == 0 {
        message.push_str(
            ". Recovery is incomplete for fresh devices until a did_recovery backup exists.",
        );
    }
    message
}

#[cfg(test)]
mod restore_parse_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_backup_summary_extracts_kdf_and_aead_fields() {
        let row = parse_backup_summary(&json!({
            "backup_id": "ck:backup:01964137-0000-7000-8000-000000000000",
            "backup_class": "secret_storage",
            "backup_version": "kb_1",
            "created_at": "2026-05-15T00:00:00Z",
            "ciphertext_digest": "sha256:abc",
            "encryption": {
                "recipient_method": "passphrase_kdf",
                "kdf": { "name": "argon2id", "salt": "U0FMVA" },
                "aead": { "name": "xchacha20_poly1305", "nonce": "Tk9OQ0U" }
            },
            "ciphertext": "Q1Q"
        }))
        .unwrap();
        assert_eq!(
            row.backup_id,
            "ck:backup:01964137-0000-7000-8000-000000000000"
        );
        assert_eq!(row.backup_class, "secret_storage");
        assert_eq!(row.recipient_method, "passphrase_kdf");
        assert_eq!(row.backup_version, "kb_1");
        assert_eq!(row.created_at, "2026-05-15T00:00:00Z");
        assert_eq!(row.salt_b64, "U0FMVA");
        assert_eq!(row.nonce_b64, "Tk9OQ0U");
        assert_eq!(row.ciphertext_b64, "Q1Q");
    }

    #[test]
    fn parse_backup_list_handles_envelope() {
        let enveloped = json!({"backups": [{"backup_id": "ck:backup:x"}]});
        assert_eq!(parse_backup_list(&enveloped).len(), 1);
        assert!(parse_backup_list(&json!([{"backup_id": "ck:backup:y"}])).is_empty());
    }

    #[test]
    fn parse_backup_summary_rejects_missing_id() {
        assert!(parse_backup_summary(&json!({})).is_none());
    }

    #[test]
    fn backup_inventory_status_marks_empty_server_as_incomplete() {
        assert!(backup_inventory_status(&[]).contains("Recovery is incomplete"));
    }

    #[test]
    fn backup_inventory_status_counts_classes() {
        let rows = parse_backup_list(&json!({
            "backups": [
                {
                    "backup_id": "ck:backup:a",
                    "backup_class": "did_recovery",
                    "encryption": {"recipient_method": "recovery_public_key"}
                },
                {
                    "backup_id": "ck:backup:b",
                    "backup_class": "secret_storage",
                    "encryption": {"recipient_method": "recovery_public_key"}
                },
                {
                    "backup_id": "ck:backup:c",
                    "backup_class": "mls_history",
                    "encryption": {"recipient_method": "secret_storage_key"}
                }
            ]
        }));
        let counts = backup_class_counts(&rows);
        assert_eq!(counts.did_recovery, 1);
        assert_eq!(counts.secret_storage, 1);
        assert_eq!(counts.mls_history, 1);
        assert!(!backup_inventory_status(&rows).contains("incomplete"));
    }

    #[test]
    fn recovery_state_without_user_material_is_not_configured() {
        assert!(!recovery_state_has_user_material(&RecoveryState::default()));
    }

    #[test]
    fn recovery_state_with_key_is_configured() {
        let mut keyed = RecoveryState::default();
        keyed.recovery_key_fingerprint = "sha256:abc".to_owned();
        assert!(recovery_state_has_user_material(&keyed));
    }

    #[test]
    fn recovery_state_with_only_passkey_wrapper_is_not_configured() {
        let mut state = RecoveryState::default();
        state.passkey_wraps.push(PasskeyRecoveryWrap {
            wrap_id: "ck:recovery-wrap:test".to_owned(),
            credential_id_b64: "Y3JlZA".to_owned(),
            recovery_key_fingerprint: "sha256:abc".to_owned(),
            ..PasskeyRecoveryWrap::default()
        });
        assert!(
            !recovery_state_has_user_material(&state),
            "passkey wrappers are convenience unlocks, not root recovery material"
        );
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RecoveryState {
    /// SHA-256 fingerprint of the current Recovery Key (never the plaintext).
    #[serde(default)]
    recovery_key_fingerprint: String,
    /// RFC-3339 UTC timestamp of the last Recovery Key rotation.
    #[serde(default)]
    recovery_key_rotated_at: String,
    /// 3 of 5, 2 of 3, etc. — encoded as `threshold / total`.
    #[serde(default = "default_threshold")]
    sss_threshold: u32,
    #[serde(default = "default_total")]
    sss_total: u32,
    #[serde(default)]
    guardians: Vec<Guardian>,
    /// Browser-local WebAuthn PRF wrappers for quick unlock of the current
    /// 24-word Recovery Key. These are convenience wrappers, not fresh-device
    /// recovery material.
    #[serde(default)]
    passkey_wraps: Vec<PasskeyRecoveryWrap>,
    /// RFC-3339 UTC of the last "Rehearse social recovery" click.
    #[serde(default)]
    last_rehearsed_at: String,
}

fn default_threshold() -> u32 {
    3
}
fn default_total() -> u32 {
    5
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            recovery_key_fingerprint: String::new(),
            recovery_key_rotated_at: String::new(),
            sss_threshold: default_threshold(),
            sss_total: default_total(),
            guardians: Vec::new(),
            passkey_wraps: Vec::new(),
            last_rehearsed_at: String::new(),
        }
    }
}

fn load_state(state_store: &Signal<LocalStateStore>, account_key: &str) -> RecoveryState {
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

fn save_state(state_store: &mut Signal<LocalStateStore>, account_key: &str, state: &RecoveryState) {
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
    state_store: &mut Signal<LocalStateStore>,
    account_key: &str,
    recovery_key: &str,
) -> Option<(String, String)> {
    if account_key.trim().is_empty() || recovery_key.trim().is_empty() {
        return None;
    }
    let mut state = load_state(state_store, account_key);
    let fingerprint = fingerprint_recovery_key(recovery_key);
    let rotated_at = chrono::Utc::now().to_rfc3339();
    state.recovery_key_fingerprint = fingerprint.clone();
    state.recovery_key_rotated_at = rotated_at.clone();
    state.passkey_wraps.clear();
    save_state(state_store, account_key, &state);
    Some((fingerprint, rotated_at))
}

fn recovery_state_has_user_material(state: &RecoveryState) -> bool {
    !state.recovery_key_fingerprint.trim().is_empty()
        || state
            .guardians
            .iter()
            .any(|guardian| !guardian.did.trim().is_empty() || !guardian.label.trim().is_empty())
}

fn passkey_wrap_aad(account_id: &str, wrap: &PasskeyRecoveryWrap) -> anyhow::Result<Vec<u8>> {
    crate::canonical::canonical_json_bytes(&serde_json::json!({
        "schema": "ck.local.recovery_passkey_wrap.v1",
        "account_id": account_id,
        "wrap_id": wrap.wrap_id,
        "credential_id": wrap.credential_id_b64,
        "rp_id": wrap.rp_id,
        "recovery_key_fingerprint": wrap.recovery_key_fingerprint,
        "created_at": wrap.created_at,
    }))
    .map_err(|err| anyhow::anyhow!("passkey wrap aad canonical json: {err}"))
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

fn fmt_relative(iso: &str) -> String {
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

/// Copy the 24-word Recovery Key to the clipboard so the user never has to
/// hand-select it (a partial selection silently drops words). Prefers the async
/// Clipboard API and falls back to `execCommand` on insecure contexts.
fn copy_recovery_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

/// RK-as-authority backup: wrap the local account MLS secret behind the just
/// generated 24-word Recovery Key and upload it, so the key the restore prompt
/// asks for is the same key that actually protects encrypted history. Mirrors
/// `MlsBackupPrompt`'s upload (account secret + best-effort sidecar). No-op with
/// an explanatory status when there is no account secret yet (encryption hasn't
/// been used, so there is nothing to back up — the backup runs on first use).
pub(crate) fn upload_recovery_key_account_backup(
    base_url: String,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
    recovery_key: String,
    mut status: Signal<String>,
) {
    let Some(recovery_secret) = crate::recovery_crypto::normalize_recovery_key_input(&recovery_key)
    else {
        return;
    };
    let base = base_url;
    let session = token();
    let actor = account_did();
    let device = device_id();
    if base.trim().is_empty() || session.trim().is_empty() || actor.trim().is_empty() {
        return;
    }
    // Only upload when encryption has produced an account secret. Otherwise there
    // is nothing to wrap yet; the secret is created on the first encrypted write
    // or an applied Welcome, and the backup-prompt path runs the upload then.
    let has_secret = {
        let secure = crate::secure_key_store::default_secure_key_store("yougen");
        matches!(
            crate::mls::runtime::load_account_mls_secret(secure.as_ref(), &actor),
            Ok(Some(_))
        )
    };
    if !has_secret {
        status.set(
            "Recovery Key saved. Your encrypted content will be backed up to it automatically the first time you use encryption.".to_owned(),
        );
        return;
    }
    let sidecar_json = if state_store.read().private_plaintext_is_empty() {
        None
    } else {
        Some(state_store.read().private_plaintext_snapshot_json())
    };
    status.set("Recovery Key generated — backing up your encrypted history to it…".to_owned());
    spawn(async move {
        let actor_for_sidecar = actor.clone();
        let device_for_sidecar = device.clone();
        let base_for_sidecar = base.clone();
        let session_for_sidecar = session.clone();
        let mut state_store = state_store;
        let result = with_authed_api(&base, session, |api| async move {
            let secure = crate::secure_key_store::default_secure_key_store("yougen");
            crate::mls::account_recovery::upload_mls_account_secret_backup_with_recovery_key(
                &api,
                secure.as_ref(),
                &actor,
                &device,
                &recovery_secret,
            )
            .await
        })
        .await;
        match result {
            Ok(backup_id) => {
                if let Ok(mut store) = state_store.try_write() {
                    crate::components::mark_mls_recovery_backup_configured(
                        &mut store,
                        &actor_for_sidecar,
                        &backup_id,
                    );
                }
                // Best-effort: also back up the encrypted local-plaintext sidecar
                // so a fresh device recovers the author's own content. A failure
                // here must not block the (successful) account-secret backup.
                if let Some(sidecar_json) = sidecar_json {
                    let actor = actor_for_sidecar;
                    let device = device_for_sidecar;
                    let _ =
                        with_authed_api(&base_for_sidecar, session_for_sidecar, |api| async move {
                            let secure =
                                crate::secure_key_store::default_secure_key_store("yougen");
                            crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                &api,
                                secure.as_ref(),
                                &actor,
                                &device,
                                &sidecar_json,
                            )
                            .await
                        })
                        .await;
                }
                if let Ok(mut slot) = status.try_write() {
                    *slot = "Recovery Key generated and your encrypted history is now backed up to it. Write the 24 words down — they are the only way to restore on a new device.".to_owned();
                }
            }
            Err(err) => {
                if let Ok(mut slot) = status.try_write() {
                    *slot = format!(
                        "Recovery Key saved, but backing up your encrypted history failed: {}",
                        err.display()
                    );
                }
            }
        }
    });
}

#[component]
pub fn RecoveryPanel(
    base_url: String,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
    account_did: Signal<String>,
    device_id: Signal<String>,
) -> Element {
    let actor_key = account_did();
    let initial = load_state(&state_store, &actor_key);

    // Recovery key state — plaintext only in memory after Generate.
    let mut live_recovery_key = use_signal(String::new);
    let mut recovery_key_fp = use_signal(|| initial.recovery_key_fingerprint.clone());
    let mut recovery_key_rotated_at = use_signal(|| initial.recovery_key_rotated_at.clone());
    let mut recovery_key_status = use_signal(String::new);
    let mut passkey_wraps = use_signal(|| initial.passkey_wraps.clone());
    let mut passkey_status = use_signal(String::new);
    let mut passkey_recovery_key_input = use_signal(String::new);

    // Social recovery state
    let mut threshold = use_signal(|| initial.sss_threshold);
    let mut total = use_signal(|| initial.sss_total);
    let mut guardians = use_signal(|| initial.guardians.clone());
    let mut new_guardian_label = use_signal(String::new);
    let mut new_guardian_did = use_signal(String::new);
    let mut new_guardian_note = use_signal(String::new);
    let mut last_rehearsed = use_signal(|| initial.last_rehearsed_at.clone());
    let mut social_status = use_signal(String::new);

    // Restore-from-backup state — drives the "List + decrypt + delete"
    // panel further down. The decrypted payload (recovery credentials)
    // lives only in `restore_plaintext` until the user clears it.
    let mut restore_status = use_signal(String::new);
    let mut restore_loading = use_signal(|| false);
    let mut restore_loaded_once = use_signal(|| false);
    let mut backup_rows = use_signal(Vec::<BackupSummaryRow>::new);
    let mut restore_pass = use_signal(String::new);
    let mut restore_target = use_signal(|| Option::<String>::None);
    let mut restore_plaintext = use_signal(String::new);

    // Server-side Recovery-Key backup marker (written by the upload paths via
    // `mark_mls_recovery_backup_configured`). Drives the section sync badge.
    let recovery_key_backed_up =
        crate::components::mls_recovery_backup_configured(&state_store.read(), &actor_key);

    {
        let actor_key = actor_key.clone();
        let state_store = state_store;
        use_effect(move || {
            let next = load_state(&state_store, &actor_key);
            if recovery_key_fp() != next.recovery_key_fingerprint {
                recovery_key_fp.set(next.recovery_key_fingerprint);
            }
            if recovery_key_rotated_at() != next.recovery_key_rotated_at {
                recovery_key_rotated_at.set(next.recovery_key_rotated_at);
            }
            if passkey_wraps() != next.passkey_wraps {
                passkey_wraps.set(next.passkey_wraps);
            }
        });
    }

    let snapshot_state = move || RecoveryState {
        recovery_key_fingerprint: recovery_key_fp(),
        recovery_key_rotated_at: recovery_key_rotated_at(),
        sss_threshold: threshold(),
        sss_total: total(),
        guardians: guardians(),
        passkey_wraps: passkey_wraps(),
        last_rehearsed_at: last_rehearsed(),
    };

    rsx! {
        div { class: "timeline recovery-panel", "data-testid": "recovery-panel", role: "region", "aria-label": "Recovery and key backup",
            div { class: "event",
                div { class: "event-head",
                    span { "Recovery options" }
                    span { "Recovery Key (24 words)" }
                    HelpTip { text: "The Recovery Key (24 words) is the only recovery credential. Cokret never stores it on the server; backups are encrypted on-device before upload. A recovery credential may unlock backup material; a fresh device is authorized only after the active recovery_policy accepts a bound recovery_session proof." }
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric",
                        strong { "Recovery Key (24 words)" }
                        span {
                            if recovery_key_fp().is_empty() { "not generated" } else { "fingerprint stored" }
                        }
                        div { class: "muted",
                            if recovery_key_fp().is_empty() {
                                "Generate one to enable cross-device recovery"
                            } else if recovery_key_rotated_at().is_empty() {
                                "Recovery Key imported on this device"
                            } else {
                                "Last rotated {fmt_relative(&recovery_key_rotated_at())}"
                            }
                        }
                    }
                    div { class: "metric",
                        strong { "What it protects" }
                        span { "Encrypted history" }
                        div { class: "muted", "account MLS secret + your own content sidecar, backed up automatically" }
                    }
                }
            }

            // Recovery key — the only user-visible recovery credential
            div { class: "event", "data-testid": "recovery-key-section",
                div { class: "event-head",
                    span { "Recovery Key (24 words)" }
                    span { "keep offline" }
                    crate::components::SyncBadge {
                        state: if recovery_key_backed_up { SyncBadge::Synced } else { SyncBadge::Local },
                        local_label: Some("Not backed up yet".to_owned()),
                        synced_label: Some("Backed up".to_owned()),
                        test_id: Some("recovery-key-sync-badge".to_owned()),
                    }
                    HelpTip { text: "This is your account's only recovery credential. Generating it wraps your account MLS secret behind these 24 words and uploads that encrypted backup; your own content sidecar is then backed up automatically after encrypted writes. The words themselves never leave this device (only a SHA-256 fingerprint is kept locally); Cokret cannot recover them for you, so write them down. Losing them means your encrypted history cannot be restored." }
                }

                // The key itself — promoted to a full-width hero so it reads as
                // the single most important value on the panel, not one metric
                // cell among equals.
                div { class: "recovery-key-hero",
                    if !live_recovery_key().is_empty() {
                        {
                            let words: Vec<String> = live_recovery_key()
                                .split_whitespace()
                                .map(|word| word.to_owned())
                                .collect();
                            // The `data-testid` element's text content must stay
                            // exactly the 24 whitespace-separated words (the index
                            // is a CSS counter, not text), so the e2e word-count
                            // assertion keeps holding.
                            rsx! {
                                ol { class: "recovery-key-grid", "data-testid": "recovery-key-current",
                                    for word in words {
                                        li { class: "rk-word", "{word}", " " }
                                    }
                                }
                            }
                        }
                    } else if !recovery_key_fp().is_empty() {
                        div { class: "recovery-key-masked", "data-testid": "recovery-key-current",
                            "•••• •••• •••• •••• •••• •••• •••• ••••"
                        }
                    } else {
                        div { class: "recovery-key-empty", "data-testid": "recovery-key-current",
                            strong { "Not generated yet" }
                            span { class: "muted", "Generate one to enable policy-approved backup unlock fallback." }
                        }
                    }
                }

                if !live_recovery_key().is_empty() {
                    div { class: "callout warn", "data-testid": "recovery-key-live-warning",
                        div { class: "body",
                            strong { "Write these 24 words down now." }
                            " Plaintext is only shown until you navigate away or generate a new one."
                        }
                    }
                } else if !recovery_key_fp().is_empty() {
                    div { class: "muted", "Plaintext is no longer in memory. Regenerate to view a new value." }
                }

                // Supporting metadata — deliberately quieter than the key above.
                div { class: "recovery-key-meta",
                    div {
                        span { class: "lbl", "Last rotated" }
                        span { class: "val", "data-testid": "recovery-key-rotated-at", "{fmt_relative(&recovery_key_rotated_at())}" }
                        span { class: "muted", "Rotate at least every 90 days" }
                    }
                    div {
                        span { class: "lbl", "Fingerprint" }
                        span { class: "val", "data-testid": "recovery-key-fp",
                            if recovery_key_fp().is_empty() { "—" } else {
                                {
                                    let fp = recovery_key_fp();
                                    let suffix = fp.split(':').nth(1).unwrap_or("");
                                    if suffix.len() >= 12 {
                                        format!("sha256:{}…", &suffix[..12])
                                    } else {
                                        fp
                                    }
                                }
                            }
                        }
                        span { class: "muted", "SHA-256, stored locally, never uploaded" }
                    }
                }

                if !recovery_key_status().is_empty() {
                    div { class: "muted", "data-testid": "recovery-key-status", "{recovery_key_status}" }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "recovery-key-regenerate",
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            let base_url = base_url.clone();
                            move |_| {
                                match generate_recovery_key() {
                                    Ok(key) => {
                                        let fp = fingerprint_recovery_key(&key);
                                        let now = chrono::Utc::now().to_rfc3339();
                                        live_recovery_key.set(key.clone());
                                        recovery_key_fp.set(fp);
                                        recovery_key_rotated_at.set(now);
                                        passkey_wraps.set(Vec::new());
                                        recovery_key_status.set(
                                            "New Recovery Key generated. Copy it now — it is only displayed once. Existing passkey quick-unlock wrappers were cleared.".to_owned()
                                        );
                                        passkey_status.set(String::new());
                                        let next = snapshot_state();
                                        save_state(&mut store, &actor_key, &next);
                                        // RK-as-authority: this 24-word key is the canonical
                                        // cross-device recovery credential (the restore prompt
                                        // only accepts a 24-word key), so wrap and upload the
                                        // account MLS secret backup with it now. Generating the
                                        // key is what makes a real cloud backup exist.
                                        upload_recovery_key_account_backup(
                                            base_url.clone(),
                                            token,
                                            account_did,
                                            device_id,
                                            state_store,
                                            key,
                                            recovery_key_status,
                                        );
                                    }
                                    Err(err) => {
                                        recovery_key_status.set(format!("Generate failed: {err}"));
                                    }
                                }
                            }
                        },
                        if recovery_key_fp().is_empty() { "Generate" } else { "Regenerate" }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-copy",
                        disabled: live_recovery_key().is_empty(),
                        title: "Copy the 24-word Recovery Key to the clipboard.",
                        onclick: move |_| {
                            copy_recovery_text_to_clipboard(&live_recovery_key());
                            recovery_key_status.set("Recovery Key copied to clipboard. Store it offline and clear it from the screen.".to_owned());
                        },
                        "Copy"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-clear-live",
                        disabled: live_recovery_key().is_empty(),
                        title: "Drop the plaintext from memory. The fingerprint stays in local state.",
                        onclick: move |_| {
                            live_recovery_key.set(String::new());
                            recovery_key_status.set("Plaintext cleared from memory.".to_owned());
                        },
                        "Clear from screen"
                    }
                }
            }

            // Passkey quick unlock — browser-local WebAuthn PRF wrapper
            div { class: "event", "data-testid": "passkey-recovery-section",
                div { class: "event-head",
                    span { "Passkey quick unlock" }
                    span { class: "muted", "browser-local WebAuthn PRF" }
                    HelpTip { text: "This wraps the 24-word Recovery Key with a WebAuthn PRF output for this browser/RP context. It is a convenience unlock layer, not a replacement for writing down the 24 words or for fresh-device recovery policy proof. The encrypted wrapper is stored locally; the server never receives the words." }
                }
                div { class: "metric-grid", "data-testid": "passkey-wrap-overview",
                    div { class: "metric",
                        strong { "Local wrappers" }
                        span { "data-testid": "passkey-wrap-count", "{passkey_wraps().len()} saved" }
                        div { class: "muted", "Stored in local recovery.state.v1 only" }
                    }
                    div { class: "metric",
                        strong { "Scope" }
                        span { "data-testid": "passkey-wrap-scope",
                            {
                                passkey_wraps()
                                    .last()
                                    .map(|wrap| wrap.rp_id.clone())
                                    .unwrap_or_else(|| crate::passkey_prf::default_rp_id().unwrap_or_else(|| "browser only".to_owned()))
                            }
                        }
                        div { class: "muted", "Bound to this origin / RP id" }
                    }
                    div { class: "metric",
                        strong { "Root method" }
                        span { "24-word Recovery Key" }
                        div { class: "muted", "Passkey unlock is additive; keep the words offline" }
                    }
                }
                if !passkey_status().is_empty() {
                    div { class: "muted", "data-testid": "passkey-wrap-status", "{passkey_status}" }
                }
                div { class: "workflow-form", "data-testid": "passkey-wrap-key-form",
                    Label { html_for: "passkey-wrap-recovery-key", "Recovery Key for passkey setup" }
                    Input {
                        id: "passkey-wrap-recovery-key",
                        "data-testid": "passkey-wrap-recovery-key",
                        r#type: "password",
                        autocomplete: "off",
                        value: "{passkey_recovery_key_input}",
                        placeholder: "Paste your existing 24-word Recovery Key",
                        oninput: move |event: FormEvent| passkey_recovery_key_input.set(event.value()),
                    }
                    div { class: "muted", "data-testid": "passkey-wrap-key-hint",
                        if !live_recovery_key().trim().is_empty() {
                            "Using the Recovery Key currently displayed above. You can also paste an existing 24-word key here after the words are cleared from screen."
                        } else if passkey_recovery_key_input().trim().is_empty() {
                            "Create passkey unlock becomes available after you generate a new Recovery Key or paste your existing 24 words here."
                        } else {
                            "Ready to create a browser-local passkey wrapper. The pasted words are cleared after setup succeeds."
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "passkey-wrap-create",
                        disabled: live_recovery_key().trim().is_empty() && passkey_recovery_key_input().trim().is_empty(),
                        title: if live_recovery_key().trim().is_empty() && passkey_recovery_key_input().trim().is_empty() {
                            "Generate a Recovery Key or paste your existing 24 words first."
                        } else {
                            "Create a browser-local passkey wrapper for the current 24-word Recovery Key."
                        },
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let raw_recovery_key = if live_recovery_key().trim().is_empty() {
                                    passkey_recovery_key_input()
                                } else {
                                    live_recovery_key()
                                };
                                let Some(recovery_key) = normalize_recovery_key_input(&raw_recovery_key) else {
                                    passkey_status.set(
                                        "Enter the full 24-word Recovery Key before creating passkey unlock.".to_owned(),
                                    );
                                    return;
                                };
                                let entered_fp = fingerprint_recovery_key(&recovery_key);
                                let existing_fp = recovery_key_fp();
                                if !existing_fp.trim().is_empty() && existing_fp != entered_fp {
                                    passkey_status.set(
                                        "Entered Recovery Key does not match the fingerprint stored for this account.".to_owned(),
                                    );
                                    return;
                                }
                                let effective_fp = if existing_fp.trim().is_empty() {
                                    entered_fp
                                } else {
                                    existing_fp
                                };
                                let actor = actor_key.clone();
                                let rp_id = crate::passkey_prf::default_rp_id()
                                    .unwrap_or_else(|| "origin-default".to_owned());
                                let label = format!("Cokret Recovery {}", short_protocol_id(&actor));
                                passkey_status.set("Waiting for passkey user verification…".to_owned());
                                spawn(async move {
                                    let salt = match generate_passkey_wrap_salt() {
                                        Ok(salt) => salt,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey wrapper salt failed: {err}"));
                                            return;
                                        }
                                    };
                                    let material = match crate::passkey_prf::create_recovery_passkey_prf(
                                        &label,
                                        &actor,
                                        &rp_id,
                                        &salt,
                                    )
                                    .await
                                    {
                                        Ok(material) => material,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey PRF unavailable: {err}"));
                                            return;
                                        }
                                    };
                                    let created_at = chrono::Utc::now().to_rfc3339();
                                    let mut wrap = PasskeyRecoveryWrap {
                                        wrap_id: format!("ck:recovery-wrap:{}", uuid_v7()),
                                        credential_id_b64: material.credential_id_b64.clone(),
                                        credential_label: label.clone(),
                                        rp_id: rp_id.clone(),
                                        recovery_key_fingerprint: effective_fp.clone(),
                                        created_at,
                                        ..PasskeyRecoveryWrap::default()
                                    };
                                    let aad = match passkey_wrap_aad(&actor, &wrap) {
                                        Ok(aad) => aad,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey wrapper AAD failed: {err}"));
                                            return;
                                        }
                                    };
                                    let sealed = match seal_recovery_key_with_passkey_prf(
                                        &recovery_key,
                                        &material.prf_output,
                                        &salt,
                                        &aad,
                                    ) {
                                        Ok(sealed) => sealed,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey wrapper encrypt failed: {err}"));
                                            return;
                                        }
                                    };
                                    wrap.salt_b64 = sealed.salt_b64;
                                    wrap.nonce_b64 = sealed.nonce_b64;
                                    wrap.ciphertext_b64 = sealed.ciphertext_b64;
                                    wrap.ciphertext_digest = sealed.ciphertext_digest;

                                    let mut next = passkey_wraps();
                                    next.retain(|existing| {
                                        existing.credential_id_b64 != wrap.credential_id_b64
                                            || existing.recovery_key_fingerprint != wrap.recovery_key_fingerprint
                                    });
                                    next.push(wrap);
                                    passkey_wraps.set(next);
                                    if recovery_key_fp().trim().is_empty() {
                                        recovery_key_fp.set(effective_fp);
                                    }
                                    passkey_recovery_key_input.set(String::new());
                                    save_state(&mut store, &actor, &snapshot_state());
                                    passkey_status.set(
                                        "Passkey quick unlock saved locally. Keep the 24 words offline for fresh-device recovery.".to_owned()
                                    );
                                });
                            }
                        },
                        "Create passkey unlock"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "passkey-wrap-unlock",
                        disabled: passkey_wraps().is_empty(),
                        title: "Use the latest local passkey wrapper to show the 24-word Recovery Key after user verification.",
                        onclick: {
                            let actor_key = actor_key.clone();
                            move |_| {
                                let actor = actor_key.clone();
                                let current_fp = recovery_key_fp();
                                let wrap = passkey_wraps()
                                    .into_iter()
                                    .rev()
                                    .find(|wrap| current_fp.is_empty() || wrap.recovery_key_fingerprint == current_fp);
                                let Some(wrap) = wrap else {
                                    passkey_status.set("No passkey wrapper matches the current Recovery Key fingerprint.".to_owned());
                                    return;
                                };
                                passkey_status.set("Waiting for passkey user verification…".to_owned());
                                spawn(async move {
                                    let material = match crate::passkey_prf::evaluate_recovery_passkey_prf(
                                        &wrap.credential_id_b64,
                                        &wrap.rp_id,
                                        &wrap.salt_b64,
                                    )
                                    .await
                                    {
                                        Ok(material) => material,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey PRF unlock failed: {err}"));
                                            return;
                                        }
                                    };
                                    let aad = match passkey_wrap_aad(&actor, &wrap) {
                                        Ok(aad) => aad,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey wrapper AAD failed: {err}"));
                                            return;
                                        }
                                    };
                                    let recovery_key = match open_recovery_key_with_passkey_prf(
                                        &material.prf_output,
                                        &wrap.salt_b64,
                                        &wrap.nonce_b64,
                                        &wrap.ciphertext_b64,
                                        &aad,
                                    ) {
                                        Ok(key) => key,
                                        Err(err) => {
                                            passkey_status.set(format!("Passkey wrapper decrypt failed: {err}"));
                                            return;
                                        }
                                    };
                                    if fingerprint_recovery_key(&recovery_key) != wrap.recovery_key_fingerprint {
                                        passkey_status.set("Passkey wrapper fingerprint mismatch.".to_owned());
                                        return;
                                    }
                                    live_recovery_key.set(recovery_key);
                                    recovery_key_status.set(
                                        "Recovery Key restored from local passkey quick unlock. Clear it from the screen when done.".to_owned()
                                    );
                                    passkey_status.set("Passkey quick unlock succeeded locally.".to_owned());
                                });
                            }
                        },
                        "Unlock with passkey"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "passkey-wrap-remove",
                        disabled: passkey_wraps().is_empty(),
                        title: "Remove local passkey quick-unlock wrappers. This does not delete server backups or the 24-word Recovery Key.",
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                passkey_wraps.set(Vec::new());
                                save_state(&mut store, &actor_key, &snapshot_state());
                                passkey_status.set("Removed local passkey quick-unlock wrappers.".to_owned());
                            }
                        },
                        "Remove local passkeys"
                    }
                }
            }

            // Social recovery — devices-and-auth §4.2. Advanced, collapsed by
            // default: the Recovery Key (24 words) is the primary credential;
            // guardian bookkeeping here is local-only.
            details { class: "event", "data-testid": "social-recovery-section",
                summary { class: "event-head",
                    span { "Advanced · Social Recovery (Shamir's Secret Sharing)" }
                    span { "{threshold} of {total} threshold" }
                    HelpTip { text: "The recovery secret is split into N shares; any T of them can reconstruct it. Guardians can be individuals, organizations' IT, family members, or trusted HSMs. Rotating the polynomial invalidates every prior share. Guardian tracking is local bookkeeping only; server-side outreach is a future feature." }
                }
                div { class: "workflow-form",
                    Label { html_for: "sss-threshold", "Threshold (T)" }
                    Input {
                        id: "sss-threshold",
                        "data-testid": "sss-threshold",
                        r#type: "number",
                        min: "2",
                        max: "10",
                        value: "{threshold}",
                        oninput: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |event: FormEvent| {
                                if let Ok(v) = event.value().parse::<u32>() {
                                    threshold.set(v.clamp(2, 10));
                                    save_state(&mut store, &actor_key, &snapshot_state());
                                }
                            }
                        },
                    }
                    Label { html_for: "sss-total", "Total shares (N)" }
                    Input {
                        id: "sss-total",
                        "data-testid": "sss-total",
                        r#type: "number",
                        min: "2",
                        max: "10",
                        value: "{total}",
                        oninput: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |event: FormEvent| {
                                if let Ok(v) = event.value().parse::<u32>() {
                                    total.set(v.clamp(2, 10));
                                    save_state(&mut store, &actor_key, &snapshot_state());
                                }
                            }
                        },
                    }
                }
                if guardians().is_empty() {
                    div { class: "muted", "data-testid": "no-guardians", "No guardians added yet. Add at least {threshold} to enable social recovery." }
                } else {
                    div { class: "metric-grid", "data-testid": "guardian-list",
                        for (idx , g) in guardians().iter().enumerate() {
                            div { class: "metric", "data-testid": "guardian-row",
                                strong { "{g.label}" }
                                {
                                    let guardian_did_label = short_protocol_id(&g.did);
                                    rsx! { span { class: "mono", title: "{g.did}", "{guardian_did_label}" } }
                                }
                                div { class: "muted",
                                    if g.note.is_empty() {
                                        if g.confirmed { "share confirmed" } else { "share pending" }
                                    } else {
                                        "{g.note}"
                                    }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "guardian-toggle-confirm",
                                        onclick: {
                                            let actor_key = actor_key.clone();
                                            let mut store = state_store;
                                            move |_| {
                                                let mut next = guardians();
                                                if let Some(slot) = next.get_mut(idx) {
                                                    slot.confirmed = !slot.confirmed;
                                                }
                                                guardians.set(next);
                                                save_state(&mut store, &actor_key, &snapshot_state());
                                            }
                                        },
                                        if g.confirmed { "Mark pending" } else { "Mark confirmed" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "guardian-remove",
                                        onclick: {
                                            let actor_key = actor_key.clone();
                                            let mut store = state_store;
                                            move |_| {
                                                let mut next = guardians();
                                                if idx < next.len() {
                                                    next.remove(idx);
                                                }
                                                guardians.set(next);
                                                save_state(&mut store, &actor_key, &snapshot_state());
                                            }
                                        },
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "workflow-form", "data-testid": "guardian-add-form",
                    Label { html_for: "guardian-label", "Guardian label" }
                    Input {
                        id: "guardian-label",
                        "data-testid": "guardian-label",
                        value: "{new_guardian_label}",
                        placeholder: "e.g. Mei / Backup HSM",
                        oninput: move |event: FormEvent| new_guardian_label.set(event.value()),
                    }
                    Label { html_for: "guardian-did", "Handle or DID" }
                    Input {
                        id: "guardian-did",
                        "data-testid": "guardian-did",
                        value: "{new_guardian_did}",
                        placeholder: "alice:example.com or did:web:...",
                        oninput: move |event: FormEvent| new_guardian_did.set(event.value()),
                    }
                    Label { html_for: "guardian-note", "Note (optional)" }
                    Input {
                        id: "guardian-note",
                        "data-testid": "guardian-note",
                        value: "{new_guardian_note}",
                        placeholder: "Person · Organization · Family · HSM",
                        oninput: move |event: FormEvent| new_guardian_note.set(event.value()),
                    }
                }
                if !social_status().is_empty() {
                    div { class: "muted", "data-testid": "social-status", "{social_status}" }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "social-add-guardian",
                        disabled: new_guardian_label().trim().is_empty() || new_guardian_did().trim().is_empty(),
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let raw_guardian = new_guardian_did();
                                let guardian_did =
                                    crate::identity_handle::principal_did_from_identifier(
                                        &raw_guardian,
                                    )
                                    .unwrap_or_else(|| raw_guardian.trim().to_owned());
                                let mut next = guardians();
                                next.push(Guardian {
                                    label: new_guardian_label().trim().to_owned(),
                                    did: guardian_did,
                                    note: new_guardian_note().trim().to_owned(),
                                    confirmed: false,
                                });
                                let added_label = new_guardian_label();
                                guardians.set(next);
                                new_guardian_label.set(String::new());
                                new_guardian_did.set(String::new());
                                new_guardian_note.set(String::new());
                                save_state(&mut store, &actor_key, &snapshot_state());
                                social_status.set(format!("Added guardian \"{added_label}\". Share confirmation is tracked locally."));
                            }
                        },
                        "+ Add guardian"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "social-recover-now",
                        disabled: guardians().len() < threshold() as usize,
                        title: if (guardians().len() as u32) < threshold() {
                            "Add enough guardians to meet the threshold before rehearsing."
                        } else {
                            "Records a Last rehearsed timestamp; integrate with guardian outreach when wired to the server."
                        },
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let now = chrono::Utc::now().to_rfc3339();
                                last_rehearsed.set(now);
                                save_state(&mut store, &actor_key, &snapshot_state());
                                social_status.set("Rehearsal logged. Outreach to guardians is a future server-side feature.".to_owned());
                            }
                        },
                        "Rehearse social recovery"
                    }
                }
            }

            // Restore from backup — devices-and-auth §4.1 + key-management.md §7.3
            //
            // Lists every backup the server still holds for this principal,
            // lets the user decrypt one locally with the 24-word Recovery
            // Key (XChaCha20-Poly1305 AEAD authenticates the tag before any
            // plaintext is returned), and offers a destructive Delete that
            // goes through the typed delete endpoint. Envelopes sealed by the
            // removed vault-passphrase flow are legacy garbage: listable and
            // deletable, but no longer decryptable.
            div { class: "event", "data-testid": "restore-section",
                div { class: "event-head",
                    span { "Restore from backup" }
                    span { class: "muted", "server-side ciphertext only" }
                    HelpTip { text: "List every encrypted backup the server still holds for your principal. Decryption happens on-device with your Recovery Key (24 words); the server never sees plaintext. Backups sealed by the removed vault-passphrase flow cannot be decrypted any more — treat them as leftovers to delete." }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "restore-list-button",
                        disabled: restore_loading(),
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                restore_status.set("Fetching backup list…".to_owned());
                                restore_loading.set(true);
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.list_key_backups().await
                                    })
                                    .await
                                    {
                                        Ok(payload) => {
                                            let rows = parse_backup_list(&payload);
                                            let status = backup_inventory_status(&rows);
                                            backup_rows.set(rows);
                                            restore_loaded_once.set(true);
                                            restore_status.set(status);
                                        }
                                        Err(err) => restore_status
                                            .set(format!("List: {}", err.display())),
                                    }
                                    restore_loading.set(false);
                                });
                            }
                        },
                        if restore_loading() { "Loading…" } else { "List my backups" }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "restore-clear-button",
                        disabled: backup_rows().is_empty() && restore_plaintext().is_empty(),
                        onclick: move |_| {
                            backup_rows.set(Vec::new());
                            restore_loaded_once.set(false);
                            restore_target.set(None);
                            restore_pass.set(String::new());
                            restore_plaintext.set(String::new());
                            restore_status.set("Cleared restore panel state.".to_owned());
                        },
                        "Clear"
                    }
                }
                if !restore_status().is_empty() {
                    div { class: "muted", "data-testid": "restore-status", "{restore_status}" }
                }
                if backup_rows().is_empty() {
                    div { class: "muted", "data-testid": "restore-empty",
                        if restore_loaded_once() {
                            "No server backups found. Recovery is incomplete until an active policy and did_recovery backup exist."
                        } else {
                            "No backups listed yet. Click \"List my backups\" to fetch from the server."
                        }
                    }
                } else {
                    div { class: "metric-grid", "data-testid": "restore-rows",
                        for row in backup_rows() {
                            div { class: "metric", "data-testid": "restore-row",
                                strong { "{row.backup_class}" }
                                {
                                    let backup_id_label = short_protocol_id(&row.backup_id);
                                    rsx! { div { class: "mono", title: "{row.backup_id}", "{backup_id_label}" } }
                                }
                                div { class: "muted",
                                    "version {row.backup_version} · created {fmt_relative(&row.created_at)}"
                                }
                                div { class: "muted", "method {row.recipient_method}" }
                                div { class: "muted", style: "word-break: break-all;",
                                    {
                                        let digest = row.ciphertext_digest.clone();
                                        let suffix = digest.split(':').nth(1).unwrap_or("");
                                        if suffix.len() > 16 {
                                            format!("digest sha256:{}…", &suffix[..16])
                                        } else {
                                            format!("digest {digest}")
                                        }
                                    }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "restore-select-button",
                                        onclick: {
                                            let bid = row.backup_id.clone();
                                            move |_| {
                                                restore_target.set(Some(bid.clone()));
                                                restore_plaintext.set(String::new());
                                                restore_status.set(format!(
                                                    "Selected {}. Enter your Recovery Key (24 words) below.",
                                                    short_protocol_id(&bid)
                                                ));
                                            }
                                        },
                                        if restore_target() == Some(row.backup_id.clone()) { "Selected" } else { "Decrypt" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "restore-delete-button",
                                        title: "Delete the server-side ciphertext. Local fingerprint metadata stays.",
                                        onclick: {
                                            let base = base_url.clone();
                                            let bid = row.backup_id.clone();
                                            let actor = account_did();
                                            move |_| {
                                                let base = base.clone();
                                                let api_token = token();
                                                let bid = bid.clone();
                                                let actor = actor.clone();
                                                restore_loading.set(true);
                                                restore_status.set(format!(
                                                    "Deleting {}…",
                                                    short_protocol_id(&bid)
                                                ));
                                                spawn(async move {
                                                    let bid_label = short_protocol_id(&bid);
                                                    let bid_clone = bid.clone();
                                                    let result = with_authed_api(&base, api_token, |api| async move {
                                                        api.delete_key_backup(&bid_clone, &actor).await
                                                    })
                                                    .await
                                                    .map_err(|err| anyhow::anyhow!("{}", err.display()));
                                                    match result {
                                                        Ok(_) => {
                                                            restore_status.set(format!("Deleted {bid_label}"));
                                                            let mut rows = backup_rows();
                                                            rows.retain(|r| r.backup_id != bid);
                                                            backup_rows.set(rows);
                                                            if restore_target() == Some(bid.clone()) {
                                                                restore_target.set(None);
                                                                restore_plaintext.set(String::new());
                                                            }
                                                        }
                                                        Err(err) => restore_status
                                                            .set(format!("Delete {bid_label} failed: {err}")),
                                                    }
                                                    restore_loading.set(false);
                                                });
                                            }
                                        },
                                        "Delete"
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(target_row) = restore_target()
                    .and_then(|id| backup_rows().into_iter().find(|r| r.backup_id == id))
                {
                    div { class: "workflow-form", "data-testid": "restore-decrypt-form",
                            {
                                let target_backup_id_label = short_protocol_id(&target_row.backup_id);
                                rsx! {
                                    div { class: "muted", title: "{target_row.backup_id}", "Decrypt {target_backup_id_label}" }
                                }
                            }
                            Label { html_for: "restore-recovery-key", "Recovery Key (24 words)" }
                            Input {
                                id: "restore-recovery-key",
                                "data-testid": "restore-recovery-key",
                                r#type: "password",
                                value: "{restore_pass}",
                                autocomplete: "off",
                                placeholder: "Enter the 24-word Recovery Key from your original device",
                                oninput: move |event: FormEvent| restore_pass.set(event.value()),
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "restore-decrypt-button",
                                    disabled: restore_pass().is_empty(),
                                    onclick: {
                                        let target_row = target_row.clone();
                                        let actor_key = actor_key.clone();
                                        let mut store = state_store;
                                        let base = base_url.clone();
                                        move |_| {
                                            // The 24-word Recovery Key is the only accepted
                                            // decryption credential; normalize before deriving.
                                            let Some(recovery_secret) =
                                                normalize_recovery_key_input(&restore_pass())
                                            else {
                                                restore_status.set(
                                                    "Enter the full 24-word Recovery Key (words separated by spaces).".to_owned(),
                                                );
                                                return;
                                            };
                                            let pass_bytes = recovery_secret.into_bytes();
                                            let metadata = target_row.body.clone();
                                            let bid = target_row.backup_id.clone();
                                            // Captured for the Option A account-MLS recovery below.
                                            let all_rows = backup_rows();
                                            let actor_key = actor_key.clone();
                                            let device = device_id();
                                            let base = base.clone();
                                            let api_token = token();
                                            restore_status.set("Stretching Recovery Key with Argon2id…".to_owned());
                                            restore_loading.set(true);
                                            spawn(async move {
                                                let bid_label = short_protocol_id(&bid);
                                                let fetch_actor = actor_key.clone();
                                                let fetch_device = device.clone();
                                                let fetch_metadata = metadata.clone();
                                                let body = match with_authed_api(&base, api_token, |api| async move {
                                                    crate::key_backup::fetch_key_backup_with_active_unlock_proof(
                                                        &api,
                                                        &fetch_metadata,
                                                        &fetch_actor,
                                                        &fetch_device,
                                                    )
                                                    .await
                                                })
                                                .await
                                                {
                                                    Ok(body) => body,
                                                    Err(err) => {
                                                        restore_status.set(format!(
                                                            "Fetch {bid_label} failed: {}",
                                                            err.display()
                                                        ));
                                                        restore_loading.set(false);
                                                        return;
                                                    }
                                                };
                                                // Spec §7.5: decrypt from the full envelope (verifies
                                                // key_commitment + recomputes the deterministic nonce +
                                                // binds the AEAD AAD), not from loose salt/nonce/ct.
                                                match crate::key_backup::open_passphrase_kdf_backup_body(&pass_bytes, &body) {
                                                    Ok(plain) => {
                                                        let text = String::from_utf8_lossy(&plain).into_owned();
                                                        restore_plaintext.set(text);
                                                        restore_status.set(format!("Decrypted {bid_label}. The plaintext below stays in memory only — clear it when done."));

                                                        // Option A — recover the ACCOUNT-scoped MLS
                                                        // snapshot secret so this fresh browser can
                                                        // decrypt realm/kanban history. The same
                                                        // normalized 24-word Recovery Key also
                                                        // unwraps the `mls_account_secret`
                                                        // backup; once stored, replay each
                                                        // `mls_history` backup so history is
                                                        // immediately decryptable.
                                                        let secure = crate::secure_key_store::default_secure_key_store("yougen");
                                                        let mls_secret_body = all_rows.iter().map(|r| &r.body).find(|b| {
                                                            crate::mls::account_recovery::is_mls_account_secret_backup(b)
                                                        });
                                                        if let Some(mls_secret_body) = mls_secret_body {
                                                            match crate::mls::account_recovery::decrypt_mls_account_secret_backup(
                                                                &pass_bytes,
                                                                mls_secret_body,
                                                            ) {
                                                                Ok(secret_bytes) => {
                                                                    let secret = String::from_utf8_lossy(&secret_bytes).into_owned();
                                                                    let secret_version = crate::mls::account_recovery::mls_account_secret_backup_version(
                                                                        mls_secret_body,
                                                                    );
                                                                    if let Err(err) = crate::mls::runtime::store_account_mls_secret_version(
                                                                        secure.as_ref(),
                                                                        &actor_key,
                                                                        secret_version,
                                                                        &secret,
                                                                    ) {
                                                                        restore_status.set(format!(
                                                                            "Decrypted {bid_label}; storing account MLS secret failed: {err}"
                                                                        ));
                                                                    } else {
                                                                        let mut restored = 0usize;
                                                                        let mut failed = 0usize;
                                                                        for r in all_rows.iter().filter(|r| r.backup_class == "mls_history") {
                                                                            let mut guard = store.write();
                                                                            let result = crate::mls::runtime::restore_mls_history_backup_with_device_snapshot(
                                                                                &mut guard,
                                                                                secure.as_ref(),
                                                                                &actor_key,
                                                                                &device,
                                                                                &r.body,
                                                                            );
                                                                            drop(guard);
                                                                            match result {
                                                                                Ok(_) => restored += 1,
                                                                                Err(_) => failed += 1,
                                                                            }
                                                                        }
                                                                        restore_status.set(format!(
                                                                            "Decrypted {bid_label}. Account MLS secret recovered; restored {restored} history backup(s), {failed} failed."
                                                                        ));
                                                                    }
                                                                }
                                                                Err(err) => restore_status.set(format!(
                                                                    "Decrypted {bid_label}; account MLS secret unwrap failed: {err}"
                                                                )),
                                                            }
                                                        }
                                                        restore_pass.set(String::new());
                                                    }
                                                    Err(err) => {
                                                        restore_plaintext.set(String::new());
                                                        restore_status.set(format!("Decrypt failed: {err}"));
                                                    }
                                                }
                                                restore_loading.set(false);
                                            });
                                        }
                                    },
                                    "Decrypt with Recovery Key"
                                }
                            }
                            if !restore_plaintext().is_empty() {
                                div { class: "event", "data-testid": "restore-plaintext-display",
                                    div { class: "event-head",
                                        span { "Decrypted payload" }
                                        span { class: "badge green", "in-memory" }
                                    }
                                    pre {
                                        class: "mono",
                                        "data-testid": "restore-plaintext",
                                        style: "white-space: pre-wrap; word-break: break-all;",
                                        "{restore_plaintext}"
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "restore-clear-plaintext-button",
                                            onclick: move |_| {
                                                restore_plaintext.set(String::new());
                                                restore_status.set("Cleared decrypted plaintext from memory.".to_owned());
                                            },
                                            "Clear plaintext"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

            // Recovery write path
            div { class: "event", "data-testid": "recovery-writeback-explainer",
                div { class: "event-head",
                    span { "What happens when recovery succeeds" }
                    span { "method-specific evidence" }
                    HelpTip { text: "A complete recovery session should make the new device generate its own key, bind proof to the active recovery_policy, record a recovery receipt, authorize the new device, and then unlock secret_storage / MLS history backups. This panel currently handles backup unlock; policy proof and device authorization are separate follow-up flows." }
                }
            }
        }
    }
}
