//! Recovery surface — Encrypted Cloud Vault + Recovery Key + Social
//! Recovery panels. Wires the three recovery layers from
//! `crypto-media/devices-and-auth.md` §4 to real state:
//!
//! - **Encrypted Cloud Vault**: the passphrase is stretched on-device with Argon2id
//!   (`recovery_crypto::derive_vault_kek`) and the resulting key encrypts a JSON payload with
//!   XChaCha20-Poly1305 before being POSTed to `PUT /api/v1/keys/backups/{backup_id}` via
//!   [`crate::api::ContrixApi::put_key_backup`]. The server never sees the passphrase or the
//!   plaintext.
//! - **Recovery Key**: 256 bits of entropy, formatted as Crockford-base32 groups. The plaintext
//!   only lives in memory between Generate and the user's Copy / Print interaction; only a SHA-256
//!   fingerprint plus rotation timestamp are persisted via `LocalStateStore::save_private_data`.
//! - **Social Recovery**: guardian list + Shamir threshold + last-rehearsal timestamp persisted as
//!   JSON under the same private_data store.
//!
//! Everything writeable goes through `private_data`, which is itself
//! encrypted at rest under the account DID via `xor_encrypt` (and on
//! wasm32 mirrored to localStorage). The Recovery view never persists
//! the passphrase or the Recovery Key in cleartext.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::HelpTip;
use crate::key_backup::build_recovery_vault_backup_body;
use crate::local_state::LocalStateStore;
use crate::operation::uuid_v7;
use crate::recovery_crypto::{
    VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, decrypt_vault, derive_vault_kek,
    encrypt_vault, estimate_passphrase_strength, fingerprint_recovery_key, generate_recovery_key,
};
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

/// One row in the "List existing backups" table — server-side metadata
/// only. The server returns the full `cx.schema.key_backup.v1` envelope
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
            "backup_id": "cx:backup:01964137-0000-7000-8000-000000000000",
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
            "cx:backup:01964137-0000-7000-8000-000000000000"
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
        let enveloped = json!({"backups": [{"backup_id": "cx:backup:x"}]});
        assert_eq!(parse_backup_list(&enveloped).len(), 1);
        assert!(parse_backup_list(&json!([{"backup_id": "cx:backup:y"}])).is_empty());
    }

    #[test]
    fn parse_backup_summary_rejects_missing_id() {
        assert!(parse_backup_summary(&json!({})).is_none());
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

    let snapshot_state = move || RecoveryState {
        vault_backup_id: vault_backup_id(),
        vault_uploaded_at: vault_uploaded_at(),
        recovery_key_fingerprint: recovery_key_fp(),
        recovery_key_rotated_at: recovery_key_rotated_at(),
        sss_threshold: threshold(),
        sss_total: total(),
        guardians: guardians(),
        last_rehearsed_at: last_rehearsed(),
    };

    rsx! {
        div { class: "timeline", "data-testid": "recovery-panel", role: "region", "aria-label": "Recovery and key backup",
            // R3 spec sync (b47ff6ec) — Recovery Policy / Receipt stub.
            //
            // Spec landed two new normative JSON schemas:
            //   - `recovery-policy.schema.json` — policy_id, principal_id,
            //     policy_version, proof_kinds[] (device_quorum |
            //     recovery_unlock | trusted_recovery_service |
            //     principal_signing).
            //   - `recovery-receipt.schema.json` — receipt_id, principal_id,
            //     recovery_session_id, proof_summary[], completion_timestamp.
            //
            // Soland exposes list / inspect endpoints (`/api/v1/recovery/policies`
            // and `/api/v1/recovery/receipts`). Wiring lands in R3.1; this
            // stub keeps the panel + testids stable so the QA harness can
            // assert presence today and verify content once the live fetch
            // is wired.
            //
            // TODO(R3.1): replace placeholder rows with a real
            // `ContrixApi::recovery_policy_get` / `recovery_receipt_list`
            // fetch and decode against the schemas above.
            div { class: "event", "data-testid": "recovery-policy-panel",
                div { class: "event-head",
                    span { "Recovery policy" }
                    span { class: "badge", "spec b47ff6ec" }
                    HelpTip { text: "The recovery policy declares which proof kinds (device_quorum, recovery_unlock, trusted_recovery_service, principal_signing) and what threshold must be met before a recovery_session can complete. Receipts carry the proof_summary for audit." }
                }
                div { class: "muted",
                    "TODO(R3.1): wire to /api/v1/recovery/policies + /api/v1/recovery/receipts. "
                    "The panel surface and testids below stay stable so QA can assert on them today."
                }
                div { class: "metric-grid", "data-testid": "recovery-policy-overview",
                    div { class: "metric",
                        strong { "policy_id" }
                        span { "data-testid": "recovery-policy-id", "—" }
                        div { class: "muted", "Stable id; rotates on policy_version bump" }
                    }
                    div { class: "metric",
                        strong { "policy_version" }
                        span { "data-testid": "recovery-policy-version", "—" }
                        div { class: "muted", "Monotonic; server rejects mismatch with recovery_policy_mismatch" }
                    }
                    div { class: "metric",
                        strong { "proof_kinds" }
                        span { "data-testid": "recovery-policy-proof-kinds", "device_quorum · recovery_unlock · trusted_recovery_service · principal_signing" }
                        div { class: "muted", "Subset chosen by the policy author" }
                    }
                    div { class: "metric",
                        strong { "threshold" }
                        span { "data-testid": "recovery-policy-threshold", "—" }
                        div { class: "muted", "Minimum proof count required to issue a receipt" }
                    }
                }
                div { class: "event-head",
                    span { "Receipt history" }
                    span { class: "muted", "data-testid": "recovery-receipt-count", "0 receipts" }
                }
                div {
                    class: "muted",
                    "data-testid": "recovery-receipt-empty",
                    "No recovery receipts on record. When a recovery_session completes, soland writes a receipt with proof_summary[]; this panel will surface the summary + completion_timestamp."
                }
                div {
                    class: "muted",
                    "data-testid": "recovery-error-hints",
                    "Server-side errors surfaced here: "
                    span { class: "badge red", "recovery_witness_revoke_lagging" }
                    " "
                    span { class: "badge red", "recovery_policy_mismatch" }
                    " "
                    span { class: "badge red", "challenge_proof_invalid" }
                }
            }
            div { class: "event",
                div { class: "event-head",
                    span { "Recovery options" }
                    span { "Encrypted Vault · Social Recovery · Recovery Key" }
                    HelpTip { text: "Contrix never stores your passphrase on the server. Backups are encrypted on-device before upload. Any one recovery path is enough to re-authorize a new device on your account." }
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
                    HelpTip { text: "Your passphrase is stretched on-device with Argon2id (m=64MiB, t=3, p=4) and encrypts the recovery payload plus account MLS history secret with XChaCha20-Poly1305 before upload. Anyone who learns it can unlock encrypted history backups; revoking a device does not erase an MLS history secret already stored on that device." }
                }
                div { class: "workflow-form",
                    label { r#for: "vault-passphrase", "Vault passphrase" }
                    input {
                        id: "vault-passphrase",
                        "data-testid": "vault-passphrase",
                        r#type: "password",
                        value: "{passphrase}",
                        placeholder: "Choose a strong passphrase (16+ chars recommended)",
                        autocomplete: "new-password",
                        oninput: move |evt| passphrase.set(evt.value()),
                    }
                    label { r#for: "vault-passphrase-confirm", "Confirm passphrase" }
                    input {
                        id: "vault-passphrase-confirm",
                        "data-testid": "vault-passphrase-confirm",
                        r#type: "password",
                        value: "{confirm_pass}",
                        autocomplete: "new-password",
                        oninput: move |evt| confirm_pass.set(evt.value()),
                    }
                    div { class: "muted", "data-testid": "vault-passphrase-strength",
                        "Strength: {passphrase_strength_label(strength)} ({strength}/5)"
                    }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Key derivation" }
                        span { "Argon2id (m=64MiB, t=3, p=4)" }
                        div { class: "muted", "OWASP-recommended parameters" }
                    }
                    div { class: "metric",
                        strong { "Encryption" }
                        span { "xchacha20poly1305" }
                        div { class: "muted", "192-bit nonce, AEAD authenticated" }
                    }
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
                        span { "PUT /api/v1/keys/backups" }
                        div { class: "muted", "Ciphertext only; the server cannot decrypt" }
                    }
                }
                if !vault_status().is_empty() {
                    div { class: "muted", "data-testid": "vault-status", "{vault_status}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "vault-rekey",
                        disabled: strength < 2 || passphrase() != confirm_pass() || passphrase().is_empty(),
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
                                vault_sync.set(SyncBadge::Pending);
                                vault_status.set("Stretching passphrase with Argon2id…".to_owned());

                                let base = base.clone();
                                let api_token = token();
                                let actor = actor_key.clone();
                                let device = device_id();
                                let next_backup_id = if vault_backup_id().is_empty() {
                                    format!("cx:backup:{}", uuid_v7())
                                } else {
                                    vault_backup_id()
                                };
                                let payload_plaintext = serde_json::json!({
                                    "schema_version": 1,
                                    "actor_did": actor,
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
                                    let ct = match encrypt_vault(&kek, payload_plaintext.as_bytes()) {
                                        Ok(c) => c,
                                        Err(err) => {
                                            vault_sync.set(SyncBadge::Failed);
                                            vault_status.set(format!("AEAD encrypt failed: {err}"));
                                            return;
                                        }
                                    };
                                    let body = build_recovery_vault_backup_body(
                                        &backup_id_for_async,
                                        &actor_for_async,
                                        &device_for_async,
                                        &ct.ciphertext_b64,
                                        &ct.digest_sha256,
                                        &ct.salt_b64,
                                        &ct.nonce_b64,
                                        VAULT_ARGON2_M_KIB,
                                        VAULT_ARGON2_T,
                                        VAULT_ARGON2_P,
                                    );
                                    let backup_id_clone = backup_id_for_async.clone();
                                    // Cloned up-front because the primary upload moves `api_token`.
                                    let mls_base = base.clone();
                                    let mls_api_token = api_token.clone();
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
                                                "Uploaded backup {backup_id_for_async} ({} bytes ciphertext)",
                                                ct.ciphertext.len()
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
                                                        format!("cx:backup:{}", uuid_v7());
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
                    button {
                        class: "secondary",
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
                }
                div { class: "muted",
                    "A fallback for when every device is lost and no guardian is reachable. Contrix never stores this on the server — only a SHA-256 fingerprint stays in local state for verification. Generate one and write it down or print it."
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Current Recovery Key" }
                        span { "data-testid": "recovery-key-current",
                            if !live_recovery_key().is_empty() {
                                "{live_recovery_key()}"
                            } else if !recovery_key_fp().is_empty() {
                                "·······-·······-·······-·······-·······-·······"
                            } else {
                                "not generated"
                            }
                        }
                        div { class: "muted",
                            if !live_recovery_key().is_empty() {
                                "Plaintext is only shown until you navigate away or generate a new one."
                            } else if !recovery_key_fp().is_empty() {
                                "Plaintext is no longer in memory. Regenerate to view a new value."
                            } else {
                                "Generate one to enable single-key fallback recovery"
                            }
                        }
                    }
                    div { class: "metric",
                        strong { "Last rotated" }
                        span { "data-testid": "recovery-key-rotated-at", "{fmt_relative(&recovery_key_rotated_at())}" }
                        div { class: "muted", "Recommended: rotate at least every 90 days" }
                    }
                    div { class: "metric",
                        strong { "Fingerprint" }
                        span { "data-testid": "recovery-key-fp",
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
                        div { class: "muted", "SHA-256 of the Recovery Key (locally stored, never uploaded)" }
                    }
                }
                if !recovery_key_status().is_empty() {
                    div { class: "muted", "data-testid": "recovery-key-status", "{recovery_key_status}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
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
                                        recovery_key_status.set(
                                            "New Recovery Key generated. Copy it now — it is only displayed once.".to_owned()
                                        );
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
                    button {
                        class: "secondary",
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

            // Social recovery — devices-and-auth §4.2
            div { class: "event", "data-testid": "social-recovery-section",
                div { class: "event-head",
                    span { "Social Recovery · Shamir's Secret Sharing" }
                    span { "{threshold} of {total} threshold" }
                    HelpTip { text: "The recovery secret is split into N shares; any T of them can reconstruct it. Guardians can be individuals, organizations' IT, family members, or trusted HSMs. Rotating the polynomial invalidates every prior share." }
                }
                div { class: "workflow-form",
                    label { r#for: "sss-threshold", "Threshold (T)" }
                    input {
                        id: "sss-threshold",
                        "data-testid": "sss-threshold",
                        r#type: "number",
                        min: "2",
                        max: "10",
                        value: "{threshold}",
                        oninput: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |evt: Event<FormData>| {
                                if let Ok(v) = evt.value().parse::<u32>() {
                                    threshold.set(v.clamp(2, 10));
                                    save_state(&mut store, &actor_key, &snapshot_state());
                                }
                            }
                        },
                    }
                    label { r#for: "sss-total", "Total shares (N)" }
                    input {
                        id: "sss-total",
                        "data-testid": "sss-total",
                        r#type: "number",
                        min: "2",
                        max: "10",
                        value: "{total}",
                        oninput: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |evt: Event<FormData>| {
                                if let Ok(v) = evt.value().parse::<u32>() {
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
                                    button {
                                        class: "secondary",
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
                                    button {
                                        class: "secondary",
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
                    label { r#for: "guardian-label", "Guardian label" }
                    input {
                        id: "guardian-label",
                        "data-testid": "guardian-label",
                        value: "{new_guardian_label}",
                        placeholder: "e.g. Mei / Backup HSM",
                        oninput: move |evt| new_guardian_label.set(evt.value()),
                    }
                    label { r#for: "guardian-did", "Handle or DID" }
                    input {
                        id: "guardian-did",
                        "data-testid": "guardian-did",
                        value: "{new_guardian_did}",
                        placeholder: "alice:example.com or did:web:...",
                        oninput: move |evt| new_guardian_did.set(evt.value()),
                    }
                    label { r#for: "guardian-note", "Note (optional)" }
                    input {
                        id: "guardian-note",
                        "data-testid": "guardian-note",
                        value: "{new_guardian_note}",
                        placeholder: "Person · Organization · Family · HSM",
                        oninput: move |evt| new_guardian_note.set(evt.value()),
                    }
                }
                if !social_status().is_empty() {
                    div { class: "muted", "data-testid": "social-status", "{social_status}" }
                }
                div { class: "actions",
                    button {
                        class: "primary",
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
                    button {
                        class: "secondary",
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
                    button {
                        class: "primary",
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
                    button {
                        class: "secondary",
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
                                    button {
                                        class: "secondary",
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
                                    button {
                                        class: "secondary",
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
                            label { r#for: "restore-passphrase", "Vault passphrase" }
                            input {
                                id: "restore-passphrase",
                                "data-testid": "restore-passphrase",
                                r#type: "password",
                                value: "{restore_pass}",
                                autocomplete: "current-password",
                                placeholder: "Enter the passphrase you used when this vault was uploaded",
                                oninput: move |evt| restore_pass.set(evt.value()),
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "restore-decrypt-button",
                                    disabled: restore_pass().is_empty() || target_row.salt_b64.is_empty() || target_row.nonce_b64.is_empty() || target_row.ciphertext_b64.is_empty(),
                                    onclick: {
                                        let target_row = target_row.clone();
                                        let actor_key = actor_key.clone();
                                        let mut store = state_store;
                                        move |_| {
                                            let pass_bytes = restore_pass().into_bytes();
                                            let salt = target_row.salt_b64.clone();
                                            let nonce = target_row.nonce_b64.clone();
                                            let ct = target_row.ciphertext_b64.clone();
                                            let bid = target_row.backup_id.clone();
                                            // Captured for the Option A account-MLS recovery below.
                                            let all_rows = backup_rows();
                                            let actor_key = actor_key.clone();
                                            let device = device_id();
                                            restore_status.set("Stretching passphrase with Argon2id…".to_owned());
                                            restore_loading.set(true);
                                            spawn(async move {
                                                let bid_label = short_protocol_id(&bid);
                                                match decrypt_vault(&pass_bytes, &salt, &nonce, &ct) {
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
                                                                    if let Err(err) = crate::mls::runtime::store_account_mls_secret(
                                                                        secure.as_ref(),
                                                                        &actor_key,
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
                                        button {
                                            class: "secondary",
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
                }
                div { class: "muted",
                    "The new device generates its own key, the recovery is recorded against your account, your DID/key log is updated with method-specific evidence, the new device is re-authorized, and your encrypted Spaces roll their epoch to include it. Existing devices are notified."
                }
            }
        }
    }
}
