//! Recovery surface — Encrypted Cloud Vault + Recovery Key + Social
//! Recovery panels. Wires the three recovery layers from
//! `crypto-media/devices-and-auth.md` §4 to real state:
//!
//! - **Encrypted Cloud Vault**: the passphrase is stretched on-device with Argon2id
//!   (`recovery_crypto::derive_vault_kek`) and the resulting key encrypts a JSON payload with
//!   XChaCha20-Poly1305 before being POSTed to `PUT /_cokret/self/keys/backups/{backup_id}` via
//!   [`crate::api::CokretApi::put_key_backup`]. The server never sees the passphrase or the
//!   plaintext.
//! - **Recovery Key**: 256 bits of entropy, formatted as a 24-word BIP-39 mnemonic. The plaintext
//!   only lives in memory between Generate and the user's Copy / Print interaction; only a SHA-256
//!   fingerprint plus rotation timestamp are persisted via `LocalStateStore::save_private_data`.
//! - **Social Recovery**: guardian list + Shamir threshold + last-rehearsal timestamp persisted as
//!   JSON under the same private_data store.
//!
//! Everything writeable goes through `private_data`, which is itself
//! encrypted at rest under the account DID via `xor_encrypt` (and on
//! wasm32 mirrored to localStorage). The Recovery view never persists
//! the passphrase or the Recovery Key in plaintext.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::HelpTip;
use crate::key_backup::build_recovery_vault_backup_body;
use crate::local_state::LocalStateStore;
use crate::operation::uuid_v7;
use crate::recovery_crypto::{
    RECOVERY_PASSPHRASE_MIN_STRENGTH, derive_vault_kek, estimate_passphrase_strength,
    fingerprint_recovery_key, generate_passkey_wrap_salt, generate_recovery_key,
    open_recovery_key_with_passkey_prf, recovery_passphrase_strength_error,
    seal_recovery_key_with_passkey_prf,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::{short_protocol_id, with_authed_api};

const RECOVERY_STATE_KEY: &str = "recovery.state.v1";

// SyncBadge / SyncBadgeState are now shared in `crate::components::sync_badge`.
// The Recovery view uses the bare enum for signal state and renders via
// the shared component, overriding the "Pending" label to "Uploading…" to
// keep the existing copy. See C1 — unified sync badge.
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
    fn recovery_state_without_user_material_is_not_configured() {
        assert!(!recovery_state_has_user_material(&RecoveryState::default()));
    }

    #[test]
    fn recovery_state_with_key_or_vault_is_configured() {
        let mut keyed = RecoveryState::default();
        keyed.recovery_key_fingerprint = "sha256:abc".to_owned();
        assert!(recovery_state_has_user_material(&keyed));

        let mut vaulted = RecoveryState::default();
        vaulted.vault_backup_id = "ck:backup:abc".to_owned();
        assert!(recovery_state_has_user_material(&vaulted));
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
    /// Latest Encrypted Cloud Vault backup id, once `put_key_backup` has
    /// accepted at least one upload. Empty until first upload.
    #[serde(default)]
    vault_backup_id: String,
    /// RFC-3339 UTC timestamp of the last successful vault upload.
    #[serde(default)]
    vault_uploaded_at: String,
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
            vault_backup_id: String::new(),
            vault_uploaded_at: String::new(),
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

fn recovery_state_has_user_material(state: &RecoveryState) -> bool {
    !state.vault_backup_id.trim().is_empty()
        || !state.recovery_key_fingerprint.trim().is_empty()
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

fn passphrase_strength_label(score: u8) -> &'static str {
    match score {
        0 => "—",
        1 => "Weak",
        2 => "Fair",
        3 => "Good",
        4 => "Strong",
        _ => "Very strong",
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

    // Vault section state
    let mut passphrase = use_signal(String::new);
    let mut confirm_pass = use_signal(String::new);
    let mut vault_status = use_signal(String::new);
    let mut vault_sync = use_signal(|| {
        if initial.vault_uploaded_at.is_empty() {
            SyncBadge::Local
        } else {
            SyncBadge::Synced
        }
    });
    let mut vault_backup_id = use_signal(|| initial.vault_backup_id.clone());
    let mut vault_uploaded_at = use_signal(|| initial.vault_uploaded_at.clone());

    // Recovery key state — plaintext only in memory after Generate.
    let mut live_recovery_key = use_signal(String::new);
    let mut recovery_key_fp = use_signal(|| initial.recovery_key_fingerprint.clone());
    let mut recovery_key_rotated_at = use_signal(|| initial.recovery_key_rotated_at.clone());
    let mut recovery_key_status = use_signal(String::new);
    let mut passkey_wraps = use_signal(|| initial.passkey_wraps.clone());
    let mut passkey_status = use_signal(String::new);

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
    let mut backup_rows = use_signal(Vec::<BackupSummaryRow>::new);
    let mut restore_pass = use_signal(String::new);
    let mut restore_target = use_signal(|| Option::<String>::None);
    let mut restore_plaintext = use_signal(String::new);

    let strength = estimate_passphrase_strength(&passphrase());
    let min_strength = RECOVERY_PASSPHRASE_MIN_STRENGTH;

    let snapshot_state = move || RecoveryState {
        vault_backup_id: vault_backup_id(),
        vault_uploaded_at: vault_uploaded_at(),
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
                    span { "Encrypted Vault · Social Recovery · Recovery Key" }
                    HelpTip { text: "Cokret never stores your passphrase on the server. Backups are encrypted on-device before upload. A recovery option may unlock backup material; a fresh device is authorized only after the active recovery_policy accepts a bound recovery_session proof." }
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric",
                        strong { {crate::i18n::tr("recovery.primary")} }
                        span { "Encrypted Cloud Vault" }
                        div { class: "muted", "Argon2id + xchacha20poly1305" }
                    }
                    div { class: "metric",
                        strong { "Backup" }
                        span { "SSS {threshold} of {total}" }
                        div { class: "muted", "{guardians().len()} guardian(s) recorded" }
                    }
                    div { class: "metric",
                        strong { "Recovery Key" }
                        span {
                            if recovery_key_fp().is_empty() { "not generated" } else { "fingerprint stored" }
                        }
                        div { class: "muted",
                            if recovery_key_rotated_at().is_empty() { "Generate one to enable single-key recovery" } else { "Last rotated {fmt_relative(&recovery_key_rotated_at())}" }
                        }
                    }
                    div { class: "metric",
                        strong { "Last rehearsal" }
                        span { "{fmt_relative(&last_rehearsed())}" }
                        div { class: "muted", "Rehearse at least every 30 days" }
                    }
                }
            }

            // Encrypted Cloud Vault — devices-and-auth §4.1
            div { class: "event", "data-testid": "vault-section",
                div { class: "event-head",
                    span { "Encrypted Cloud Vault" }
                    crate::components::SyncBadge {
                        state: vault_sync(),
                        pending_label: Some("Uploading…".to_owned()),
                        test_id: Some("vault-sync-badge".to_owned()),
                    }
                    HelpTip { text: "Your passphrase unlocks encrypted backup material. It is stretched on-device with Argon2id (m=64MiB, t=3, p=4) and encrypts the recovery payload plus account MLS history secret; it is not by itself DID ownership proof." }
                }
                div { class: "workflow-form",
                    Label { html_for: "vault-passphrase", "Vault passphrase" }
                    Input {
                        id: "vault-passphrase",
                        "data-testid": "vault-passphrase",
                        r#type: "password",
                        value: "{passphrase}",
                        placeholder: "24+ characters or several random words",
                        autocomplete: "new-password",
                        oninput: move |event: FormEvent| passphrase.set(event.value()),
                    }
                    Label { html_for: "vault-passphrase-confirm", "Confirm passphrase" }
                    Input {
                        id: "vault-passphrase-confirm",
                        "data-testid": "vault-passphrase-confirm",
                        r#type: "password",
                        value: "{confirm_pass}",
                        autocomplete: "new-password",
                        oninput: move |event: FormEvent| confirm_pass.set(event.value()),
                    }
                    div { class: "muted", "data-testid": "vault-passphrase-strength",
                        "Strength: {passphrase_strength_label(strength)} ({strength}/5). Minimum: Good ({min_strength}/5)."
                    }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Latest upload" }
                        span {
                            "data-testid": "vault-uploaded-at",
                            "{fmt_relative(&vault_uploaded_at())}"
                        }
                        div { class: "muted",
                            if vault_backup_id().is_empty() { "No backup uploaded yet" } else { "backup_id: {vault_backup_id()}" }
                        }
                    }
                    div { class: "metric",
                        strong { "Storage" }
                        span { "Ciphertext only" }
                        div { class: "muted", "The server cannot decrypt your backup" }
                    }
                }
                if !vault_status().is_empty() {
                    div { class: "muted", "data-testid": "vault-status", "{vault_status}" }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "vault-rekey",
                        disabled: recovery_passphrase_strength_error(&passphrase()).is_some()
                            || passphrase() != confirm_pass()
                            || passphrase().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            let mut store = state_store;
                            let actor_key = actor_key.clone();
                            move |_| {
                                let pass = passphrase();
                                let confirm = confirm_pass();
                                if pass.is_empty() || pass != confirm {
                                    vault_status.set("Passphrase and confirmation must match.".to_owned());
                                    return;
                                }
                                if let Some(reason) = recovery_passphrase_strength_error(&pass) {
                                    vault_status.set(reason.to_owned());
                                    return;
                                }
                                vault_sync.set(SyncBadge::Pending);
                                vault_status.set("Stretching passphrase with Argon2id…".to_owned());

                                let base = base.clone();
                                let api_token = token();
                                let actor = actor_key.clone();
                                let device = device_id();
                                let next_backup_id = if vault_backup_id().is_empty() {
                                    format!("ck:backup:{}", uuid_v7())
                                } else {
                                    vault_backup_id()
                                };
                                let payload_plaintext = serde_json::json!({
                                    "schema_version": 1,
                                    "actor_id": actor,
                                    "device_id": device,
                                    "recovery_key_fingerprint": recovery_key_fp(),
                                    "minted_at": chrono::Utc::now().to_rfc3339(),
                                })
                                .to_string();
                                let pass_bytes = pass.into_bytes();
                                let backup_id_for_async = next_backup_id.clone();
                                let actor_for_async = actor.clone();
                                let actor_key_for_async = actor_key.clone();
                                let device_for_async = device.clone();

                                spawn(async move {
                                    let kek = match derive_vault_kek(&pass_bytes) {
                                        Ok(k) => k,
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("Argon2id failed: {err}"));
                                            return;
                                        }
                                    };
                                    let body = match build_recovery_vault_backup_body(
                                        &backup_id_for_async,
                                        &actor_for_async,
                                        &device_for_async,
                                        &kek,
                                        payload_plaintext.as_bytes(),
                                    ) {
                                        Ok(b) => b,
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("AEAD encrypt failed: {err}"));
                                            return;
                                        }
                                    };
                                    let backup_id_clone = backup_id_for_async.clone();
                                    // Cloned up-front because the primary upload moves `api_token`.
                                    let mls_base = base.clone();
                                    let mls_api_token = api_token.clone();
                                    // X5.3 — clones for the private-plaintext sidecar upload
                                    // (the account-secret upload below moves `mls_base`/`mls_api_token`).
                                    let sidecar_base = base.clone();
                                    let sidecar_api_token = api_token.clone();
                                    let sidecar_actor = actor_for_async.clone();
                                    let sidecar_device = device_for_async.clone();
                                    // Snapshot the sidecar before any await so we don't hold the
                                    // store borrow across the network round-trips.
                                    let sidecar_json = if store.read().private_plaintext_is_empty() {
                                        None
                                    } else {
                                        Some(store.read().private_plaintext_snapshot_json())
                                    };
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.put_key_backup(&backup_id_clone, body).await
                                    })
                                    .await
                                    {
                                        Ok(_) => {
                                            let now = chrono::Utc::now().to_rfc3339();
                                            vault_backup_id.set(backup_id_for_async.clone());
                                            vault_uploaded_at.set(now.clone());
                                            vault_sync.set(SyncBadge::Synced);
                                            vault_status.set(format!(
                                                "Uploaded backup {backup_id_for_async}"
                                            ));
                                            passphrase.set(String::new());
                                            confirm_pass.set(String::new());
                                            let mut next = snapshot_state();
                                            next.vault_backup_id = backup_id_for_async;
                                            next.vault_uploaded_at = now;
                                            save_state(&mut store, &actor_key_for_async, &next);

                                            // Option A — also wrap the ACCOUNT-scoped MLS snapshot
                                            // secret behind the same passphrase so a brand-new
                                            // browser of this account can decrypt realm/kanban
                                            // history after recovery. Reuses the already-derived KEK
                                            // (no second Argon2id pass). Best-effort: a failure here
                                            // must not undo the primary vault upload above.
                                            let secure = crate::secure_key_store::default_secure_key_store("yougen");
                                            match crate::mls::runtime::load_or_create_account_mls_secret(
                                                secure.as_ref(),
                                                &actor_for_async,
                                                &device_for_async,
                                            ) {
                                                Ok(account_secret) => {
                                                    let mls_backup_id =
                                                        format!("ck:backup:{}", uuid_v7());
                                                    match crate::mls::account_recovery::build_mls_account_secret_backup_body_with_kek(
                                                        &mls_backup_id,
                                                        &actor_for_async,
                                                        &device_for_async,
                                                        &kek,
                                                        &account_secret,
                                                    ) {
                                                        Ok(mls_body) => {
                                                            let mls_id = mls_backup_id.clone();
                                                            let mls_outcome = with_authed_api(
                                                                &mls_base,
                                                                mls_api_token,
                                                                |api| async move {
                                                                    api.put_key_backup(&mls_id, mls_body).await
                                                                },
                                                            )
                                                            .await;
                                                            if let Err(err) = mls_outcome {
                                                                vault_status.set(format!(
                                                                    "Vault uploaded; account MLS recovery key upload failed: {}",
                                                                    err.display()
                                                                ));
                                                            } else if let Some(sidecar_json) = sidecar_json {
                                                                // X5.3 — account secret backup is up;
                                                                // now back up the encrypted local-plaintext
                                                                // sidecar (KEK derived from the account
                                                                // secret inside the helper) so a fresh
                                                                // browser recovers the author's own content.
                                                                // Best-effort: failure must not undo the
                                                                // vault/account-secret uploads above.
                                                                let sidecar_outcome = with_authed_api(
                                                                    &sidecar_base,
                                                                    sidecar_api_token,
                                                                    |api| async move {
                                                                        let secure = crate::secure_key_store::default_secure_key_store("yougen");
                                                                        crate::mls::account_recovery::upload_mls_private_plaintext_backup(
                                                                            &api,
                                                                            secure.as_ref(),
                                                                            &sidecar_actor,
                                                                            &sidecar_device,
                                                                            &sidecar_json,
                                                                        )
                                                                        .await
                                                                    },
                                                                )
                                                                .await;
                                                                if let Err(err) = sidecar_outcome {
                                                                    vault_status.set(format!(
                                                                        "Vault + account MLS recovery key uploaded; private plaintext backup failed: {}",
                                                                        err.display()
                                                                    ));
                                                                }
                                                            }
                                                        }
                                                        Err(err) => vault_status.set(format!(
                                                            "Vault uploaded; failed to wrap account MLS secret: {err}"
                                                        )),
                                                    }
                                                }
                                                Err(err) => vault_status.set(format!(
                                                    "Vault uploaded; account MLS secret unavailable: {err}"
                                                )),
                                            }
                                        }
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("Upload failed: {}", err.display()));
                                        }
                                    }
                                });
                            }
                        },
                        {crate::i18n::tr("recovery.vault_encrypt_button")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "vault-rotate-passphrase",
                        disabled: vault_backup_id().is_empty(),
                        title: crate::i18n::tr("recovery.vault_rotate_hint"),
                        onclick: move |_| {
                            vault_status.set(crate::i18n::tr("recovery.vault_rotate_prompt"));
                        },
                        {crate::i18n::tr("recovery.vault_rotate_button")}
                    }
                }
            }

            // Recovery key — fallback path
            div { class: "event", "data-testid": "recovery-key-section",
                div { class: "event-head",
                    span { "Recovery Key" }
                    span { "high-entropy string · keep offline" }
                    HelpTip { text: "A fallback for when every device is lost and no guardian is reachable. Cokret never stores this on the server — only a SHA-256 fingerprint stays in local state for verification. Generate one and write it down or print it." }
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
                            move |_| {
                                match generate_recovery_key() {
                                    Ok(key) => {
                                        let fp = fingerprint_recovery_key(&key);
                                        let now = chrono::Utc::now().to_rfc3339();
                                        live_recovery_key.set(key);
                                        recovery_key_fp.set(fp);
                                        recovery_key_rotated_at.set(now);
                                        passkey_wraps.set(Vec::new());
                                        recovery_key_status.set(
                                            "New Recovery Key generated. Copy it now — it is only displayed once. Existing passkey quick-unlock wrappers were cleared.".to_owned()
                                        );
                                        passkey_status.set(String::new());
                                        let next = snapshot_state();
                                        save_state(&mut store, &actor_key, &next);
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
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "passkey-wrap-create",
                        disabled: live_recovery_key().trim().is_empty(),
                        title: if live_recovery_key().trim().is_empty() {
                            "Generate or unlock the 24-word Recovery Key first."
                        } else {
                            "Create a browser-local passkey wrapper for the current 24-word Recovery Key."
                        },
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let recovery_key = live_recovery_key();
                                if recovery_key.trim().is_empty() {
                                    passkey_status.set("Generate or unlock the 24-word Recovery Key first.".to_owned());
                                    return;
                                }
                                let actor = actor_key.clone();
                                let rp_id = crate::passkey_prf::default_rp_id()
                                    .unwrap_or_else(|| "origin-default".to_owned());
                                let label = format!("Cokret Recovery {}", short_protocol_id(&actor));
                                let fp = recovery_key_fp();
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
                                        recovery_key_fingerprint: fp.clone(),
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

            // Social recovery — devices-and-auth §4.2
            div { class: "event", "data-testid": "social-recovery-section",
                div { class: "event-head",
                    span { "Social Recovery · Shamir's Secret Sharing" }
                    span { "{threshold} of {total} threshold" }
                    HelpTip { text: "The recovery secret is split into N shares; any T of them can reconstruct it. Guardians can be individuals, organizations' IT, family members, or trusted HSMs. Rotating the polynomial invalidates every prior share." }
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
            // lets the user decrypt one locally with the original
            // passphrase (XChaCha20-Poly1305 AEAD authenticates the tag
            // before any plaintext is returned), and offers a destructive
            // Delete that goes through the typed delete endpoint.
            div { class: "event", "data-testid": "restore-section",
                div { class: "event-head",
                    span { "Restore from backup" }
                    span { class: "muted", "Encrypted Cloud Vault · server-side ciphertext only" }
                    HelpTip { text: "List every encrypted vault the server still holds for your principal. Decryption happens on-device with your passphrase; the server never sees plaintext. Use this on a new device, or to verify that the latest upload is still readable." }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "restore-list-button",
                        disabled: restore_loading(),
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                restore_status.set("Fetching vault list…".to_owned());
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
                                            let len = rows.len();
                                            backup_rows.set(rows);
                                            restore_status.set(format!(
                                                "Loaded {len} backup(s) from the server"
                                            ));
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
                    div { class: "muted", "data-testid": "restore-empty", "No backups listed yet. Click \"List my backups\" to fetch from the server." }
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
                                                    "Selected {}. Enter your vault passphrase below.",
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
                            Label { html_for: "restore-passphrase", "Vault passphrase" }
                            Input {
                                id: "restore-passphrase",
                                "data-testid": "restore-passphrase",
                                r#type: "password",
                                value: "{restore_pass}",
                                autocomplete: "current-password",
                                placeholder: "Enter the passphrase you used when this vault was uploaded",
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
                                            let pass_bytes = restore_pass().into_bytes();
                                            let metadata = target_row.body.clone();
                                            let bid = target_row.backup_id.clone();
                                            // Captured for the Option A account-MLS recovery below.
                                            let all_rows = backup_rows();
                                            let actor_key = actor_key.clone();
                                            let device = device_id();
                                            let base = base.clone();
                                            let api_token = token();
                                            restore_status.set("Stretching passphrase with Argon2id…".to_owned());
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
                                                        // passphrase that just opened the recovery
                                                        // vault also unwraps the `mls_account_secret`
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
                                    "Decrypt with passphrase"
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
