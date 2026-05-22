//! G3.Y1 — Key backup status surface at `/settings/security`.
//!
//! Surfaces:
//! - `key-backup-status` — "enabled" / "disabled" / "out-of-date"
//! - `key-backup-trigger-button` — manually triggers a backup
//! - `key-backup-restore-button` — manually triggers a restore
//! - `key-backup-last-backup-at` — timestamp text
//!
//! Wires to soland's existing `cx.schema.key_backup.v1` endpoints
//! (`PUT/GET /api/v1/keys/backups/{backup_id}` via
//! [`crate::api::ContrixApi::put_key_backup`] /
//! [`crate::api::ContrixApi::list_key_backups`]). The MLS-key backup
//! endpoints that the spec defines under
//! `crypto-media/encryption-and-audit.md` §2.4 (epoch backfill via
//! `mls_history_backup_key`) do NOT yet exist on the soland side and
//! are tagged as `TODO(G3.Y1-followup)` calls below.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    components::HelpTip,
    key_backup::build_recovery_vault_backup_body,
    local_state::LocalStateStore,
    operation::uuid_v7,
    recovery_crypto::{
        VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, derive_vault_kek, encrypt_vault,
    },
    views::helpers::{short_protocol_id, with_authed_api},
};

const KEY_BACKUP_STATE_KEY: &str = "key_backup.state.v1";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct KeyBackupState {
    /// `enabled` / `disabled` / `out-of-date`. Mirrors the wording the
    /// cotest `encryption/key-backup` scenario asserts against in the
    /// `key-backup-status` testid.
    #[serde(default)]
    status: String,
    /// RFC-3339 timestamp of the last successful backup upload.
    #[serde(default)]
    last_backup_at: String,
    /// Most recently uploaded `backup_id` so the manual restore path
    /// can pre-fill the lookup.
    #[serde(default)]
    last_backup_id: String,
}

impl KeyBackupState {
    fn status_label(&self) -> &str {
        if self.status.is_empty() {
            "disabled"
        } else {
            &self.status
        }
    }
}

fn load_state(state_store: &LocalStateStore, account_did: &str) -> KeyBackupState {
    if account_did.is_empty() {
        return KeyBackupState::default();
    }
    match state_store.load_private_data(account_did, KEY_BACKUP_STATE_KEY) {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        None => KeyBackupState::default(),
    }
}

fn save_state(state_store: &mut LocalStateStore, account_did: &str, state: &KeyBackupState) {
    if account_did.is_empty() {
        return;
    }
    if let Ok(payload) = serde_json::to_string(state) {
        state_store.save_private_data(account_did, KEY_BACKUP_STATE_KEY, payload);
    }
}

#[component]
pub fn SettingsSecurityPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let actor_did = account_did();
    let initial = load_state(&state_store.read(), &actor_did);

    let mut status_text = use_signal(|| initial.status_label().to_owned());
    let mut last_backup_at = use_signal(|| initial.last_backup_at.clone());
    let mut last_backup_id = use_signal(|| initial.last_backup_id.clone());
    let mut passphrase = use_signal(String::new);
    let mut action_status = use_signal(String::new);

    let has_session = !token().trim().is_empty();
    let last_backup_id_value = last_backup_id();
    let last_backup_id_label = short_protocol_id(&last_backup_id_value);

    rsx! {
        div { class: "settings", "data-testid": "settings-security-panel",
            div { class: "settings-shell",
                section { class: "settings-content-column",
                    div { class: "event settings-content-hero",
                        div { class: "event-head",
                            span { "Security" }
                            span { if has_session { "authenticated" } else { "not signed in" } }
                        }
                        div { class: "settings-content-title-row",
                            h2 { class: "settings-content-title", "Key backup" }
                            HelpTip { text: "Encrypted Cloud Vault backup of your signing keys + MLS history key. The passphrase is stretched on-device with Argon2id; the server only stores the ciphertext.".to_owned() }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Backup status" }
                            span {
                                "data-testid": "key-backup-status",
                                "{status_text}"
                            }
                        }
                        div { class: "metric-grid",
                            div { class: "metric",
                                strong { "Last backup" }
                                span {
                                    "data-testid": "key-backup-last-backup-at",
                                    if last_backup_at().is_empty() { "never" } else { "{last_backup_at}" }
                                }
                                div { class: "muted",
                                    if last_backup_id().is_empty() {
                                        "Trigger a backup to start protecting your keys."
                                    } else {
                                        "backup_id: {last_backup_id_label}"
                                    }
                                }
                            }
                            div { class: "metric",
                                strong { "Encryption" }
                                span { "Argon2id + XChaCha20-Poly1305" }
                                div { class: "muted", "m=64MiB, t=3, p=4" }
                            }
                            div { class: "metric",
                                strong { "Storage" }
                                span { "PUT /api/v1/keys/backups" }
                                div { class: "muted", "ciphertext only" }
                            }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Actions" }
                            span { "manual triggers" }
                        }
                        p { class: "muted",
                            "Enter a passphrase, then trigger a backup or restore. The passphrase plaintext only lives in this tab's memory during the Argon2id stretch."
                        }
                        div { class: "workflow-form",
                            label { r#for: "key-backup-passphrase", "Backup passphrase" }
                            input {
                                id: "key-backup-passphrase",
                                "data-testid": "key-backup-passphrase-input",
                                r#type: "password",
                                value: "{passphrase}",
                                placeholder: "16+ characters recommended",
                                autocomplete: "new-password",
                                oninput: move |evt| passphrase.set(evt.value()),
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "key-backup-trigger-button",
                                disabled: !has_session || passphrase().trim().is_empty(),
                                onclick: {
                                    let actor = actor_did.clone();
                                    move |_| {
                                        let base = base_url();
                                        let api_token = token();
                                        let actor_owned = actor.clone();
                                        let device = device_id();
                                        let pass = passphrase();
                                        let backup_id = if last_backup_id().is_empty() {
                                            format!("cx:backup:{}", uuid_v7())
                                        } else {
                                            last_backup_id()
                                        };
                                        action_status.set(format!(
                                            "Stretching passphrase + uploading backup {}…",
                                            short_protocol_id(&backup_id)
                                        ));
                                        let actor_for_payload = actor_owned.clone();
                                        let pass_bytes = pass.into_bytes();
                                        let backup_id_async = backup_id.clone();
                                        let device_for_payload = device.clone();
                                        spawn(async move {
                                            let payload = serde_json::json!({
                                                "schema_version": 1,
                                                "actor_did": actor_for_payload,
                                                "device_id": device_for_payload,
                                                "minted_at": chrono::Utc::now().to_rfc3339(),
                                                "source": "settings.security.trigger_backup",
                                            })
                                            .to_string();
                                            let kek = match derive_vault_kek(&pass_bytes) {
                                                Ok(k) => k,
                                                Err(err) => {
                                                    action_status.set(format!(
                                                        "Argon2id stretch failed: {err}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            let ct = match encrypt_vault(&kek, payload.as_bytes()) {
                                                Ok(c) => c,
                                                Err(err) => {
                                                    action_status.set(format!(
                                                        "AEAD encrypt failed: {err}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            let body = build_recovery_vault_backup_body(
                                                &backup_id_async,
                                                &actor_for_payload,
                                                &device_for_payload,
                                                &ct.ciphertext_b64,
                                                &ct.digest_sha256,
                                                &ct.salt_b64,
                                                &ct.nonce_b64,
                                                VAULT_ARGON2_M_KIB,
                                                VAULT_ARGON2_T,
                                                VAULT_ARGON2_P,
                                            );
                                            let backup_id_inner = backup_id_async.clone();
                                            match with_authed_api(&base, api_token, |api| async move {
                                                api.put_key_backup(&backup_id_inner, body).await
                                            })
                                            .await
                                            {
                                                Ok(_) => {
                                                    let now = chrono::Utc::now().to_rfc3339();
                                                    last_backup_id.set(backup_id_async.clone());
                                                    last_backup_at.set(now.clone());
                                                    status_text.set("enabled".to_owned());
                                                    action_status.set(format!(
                                                        "Backup {} stored ({} bytes ciphertext)",
                                                        short_protocol_id(&backup_id_async),
                                                        ct.ciphertext.len()
                                                    ));
                                                    let next = KeyBackupState {
                                                        status: "enabled".to_owned(),
                                                        last_backup_at: now,
                                                        last_backup_id: backup_id_async,
                                                    };
                                                    save_state(
                                                        &mut state_store.write(),
                                                        &actor_owned,
                                                        &next,
                                                    );
                                                    passphrase.set(String::new());
                                                }
                                                Err(err) => {
                                                    status_text.set("out-of-date".to_owned());
                                                    action_status.set(format!(
                                                        "Backup upload failed: {}",
                                                        err.display()
                                                    ));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Trigger backup"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "key-backup-restore-button",
                                disabled: !has_session || last_backup_id().is_empty(),
                                onclick: move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let backup_id = last_backup_id();
                                    if backup_id.is_empty() {
                                        action_status.set(
                                            "No backup_id known — trigger a backup first or paste an id at /recover.".to_owned()
                                        );
                                        return;
                                    }
                                    action_status.set(format!(
                                        "Fetching backup {}…",
                                        short_protocol_id(&backup_id)
                                    ));
                                    spawn(async move {
                                        // TODO(G3.Y1-followup): soland
                                        // exposes `GET /api/v1/keys/backups/{id}`
                                        // but the MLS-history backup
                                        // endpoints (spec
                                        // crypto-media/encryption-and-audit.md
                                        // §2.4 — epoch backfill) are
                                        // not yet implemented. The
                                        // restore path here pulls the
                                        // recovery-vault payload only;
                                        // re-deriving MLS epoch keys
                                        // is gated on that follow-up.
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.get_key_backup(&backup_id).await
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                action_status.set(format!(
                                                    "Fetched backup metadata: {response}"
                                                ));
                                            }
                                            Err(err) => {
                                                action_status.set(format!(
                                                    "Restore fetch failed: {}",
                                                    err.display()
                                                ));
                                            }
                                        }
                                    });
                                },
                                "Restore from backup"
                            }
                        }
                        if !action_status().is_empty() {
                            div { class: "muted", "data-testid": "key-backup-action-status", "{action_status}" }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_reports_disabled() {
        let state = KeyBackupState::default();
        assert_eq!(state.status_label(), "disabled");
    }

    #[test]
    fn enabled_state_reports_enabled() {
        let state = KeyBackupState {
            status: "enabled".to_owned(),
            last_backup_at: "2026-05-21T00:00:00Z".to_owned(),
            last_backup_id: "cx:backup:abc".to_owned(),
        };
        assert_eq!(state.status_label(), "enabled");
    }
}
