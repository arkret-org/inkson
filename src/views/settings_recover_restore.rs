//! G3.Y1 — Fresh-device restore at `/recover`.
//!
//! Surfaces:
//! - `recovery-restore-panel` — wrapper
//! - `recovery-restore-passphrase-input` — paste/type the passphrase
//! - `recovery-restore-backup-id-input` — optional manual backup_id
//!   override; defaults to whichever id soland's
//!   `GET /api/v1/keys/backups` returns at the top of the list
//! - `recovery-restore-button` — derives the recovery key, fetches +
//!   decrypts the backup envelope
//! - `recovery-restore-status` — feedback
//!
//! This panel does NOT push `cx.device.authorized` on its own —
//! that's the domain of the device-pairing flow (`settings_devices.rs`)
//! and the SDK's cross-signing executor. We only re-hydrate the
//! private payload so the caller can re-establish identity locally.
//!
//! Coauth endpoints that the e2e harness exercises but that don't
//! yet exist:
//!
//! - `POST /api/v1/auth/passkey/begin` —
//!   TODO(G3.Y1-followup): coauth needs an unauthenticated entry
//!   point that lets a brand-new device claim the recovered identity
//!   without first holding a bearer token. Until then this view only
//!   exercises the on-device passphrase → KEK → decrypt path; the
//!   server round-trip happens via the existing
//!   `/api/v1/keys/backups/{backup_id}` endpoint with a temporary
//!   placeholder token in tests.

use dioxus::prelude::*;
use serde_json::Value;

use crate::{components::HelpTip, recovery_crypto::decrypt_vault, views::helpers::with_authed_api};

#[component]
pub fn RecoverPanel(base_url: Signal<String>, token: Signal<String>) -> Element {
    let mut passphrase = use_signal(String::new);
    let mut backup_id = use_signal(String::new);
    let mut restore_status = use_signal(String::new);
    let mut decrypted_payload = use_signal(String::new);

    let has_session = !token().trim().is_empty();

    rsx! {
        div { class: "settings", "data-testid": "recovery-restore-panel",
            div { class: "settings-shell",
                section { class: "settings-content-column",
                    div { class: "event settings-content-hero",
                        div { class: "event-head",
                            span { "Recover" }
                            span { if has_session { "authenticated" } else { "no session" } }
                        }
                        div { class: "settings-content-title-row",
                            h2 { class: "settings-content-title", "Restore from backup" }
                            HelpTip { text: "Enter the recovery passphrase you wrote down on the original device. The KEK is derived locally with Argon2id; the server never sees the passphrase.".to_owned() }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Inputs" }
                            span { "passphrase + backup id" }
                        }
                        div { class: "workflow-form",
                            label { r#for: "recovery-restore-passphrase-input", "Recovery passphrase" }
                            input {
                                id: "recovery-restore-passphrase-input",
                                "data-testid": "recovery-restore-passphrase-input",
                                r#type: "password",
                                value: "{passphrase}",
                                placeholder: "12-word passphrase or vault passphrase",
                                autocomplete: "current-password",
                                oninput: move |evt| passphrase.set(evt.value()),
                            }
                            label { r#for: "recovery-restore-backup-id-input", "Backup id (optional)" }
                            input {
                                id: "recovery-restore-backup-id-input",
                                "data-testid": "recovery-restore-backup-id-input",
                                r#type: "text",
                                value: "{backup_id}",
                                placeholder: "cx:backup:01964137-… (leave blank to use the latest)",
                                oninput: move |evt| backup_id.set(evt.value()),
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "recovery-restore-button",
                                disabled: passphrase().trim().is_empty(),
                                onclick: move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let pass = passphrase();
                                    let bid_input = backup_id();
                                    restore_status.set(
                                        "Looking up backup envelope from soland…".to_owned(),
                                    );
                                    decrypted_payload.set(String::new());
                                    spawn(async move {
                                        let backup_value = if bid_input.trim().is_empty() {
                                            // Fall back to the latest entry in
                                            // the list. Failure here is fatal —
                                            // we can't decrypt without an
                                            // envelope.
                                            match with_authed_api(
                                                &base,
                                                api_token.clone(),
                                                |api| async move { api.list_key_backups().await },
                                            )
                                            .await
                                            {
                                                Ok(value) => match latest_backup(&value) {
                                                    Some(v) => v,
                                                    None => {
                                                        restore_status.set(
                                                            "No backups available. Trigger one from /settings/security first or paste a backup_id.".to_owned(),
                                                        );
                                                        return;
                                                    }
                                                },
                                                Err(err) => {
                                                    restore_status.set(format!(
                                                        "Backup list failed: {}",
                                                        err.display()
                                                    ));
                                                    return;
                                                }
                                            }
                                        } else {
                                            let bid_clone = bid_input.clone();
                                            match with_authed_api(
                                                &base,
                                                api_token.clone(),
                                                move |api| async move {
                                                    api.get_key_backup(&bid_clone).await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(v) => v,
                                                Err(err) => {
                                                    restore_status.set(format!(
                                                        "Backup fetch failed: {}",
                                                        err.display()
                                                    ));
                                                    return;
                                                }
                                            }
                                        };

                                        let Some(salt) = backup_value
                                            .pointer("/encryption/kdf/salt")
                                            .and_then(|v| v.as_str())
                                        else {
                                            restore_status.set(
                                                "Backup envelope missing /encryption/kdf/salt — refusing to decrypt.".to_owned(),
                                            );
                                            return;
                                        };
                                        let Some(nonce) = backup_value
                                            .pointer("/encryption/aead/nonce")
                                            .and_then(|v| v.as_str())
                                        else {
                                            restore_status.set(
                                                "Backup envelope missing /encryption/aead/nonce — refusing to decrypt.".to_owned(),
                                            );
                                            return;
                                        };
                                        let Some(ciphertext) = backup_value
                                            .get("ciphertext")
                                            .and_then(|v| v.as_str())
                                        else {
                                            restore_status.set(
                                                "Backup envelope missing top-level ciphertext.".to_owned(),
                                            );
                                            return;
                                        };
                                        // TODO(G3.Y1-followup): verify
                                        // the envelope's `key_commitment`
                                        // (spec key-management.md §7.2)
                                        // BEFORE calling decrypt_vault
                                        // so a wrong passphrase fails
                                        // locally with no oracle leak.
                                        match decrypt_vault(
                                            pass.as_bytes(),
                                            salt,
                                            nonce,
                                            ciphertext,
                                        ) {
                                            Ok(plain) => {
                                                let recovered = String::from_utf8_lossy(&plain)
                                                    .into_owned();
                                                decrypted_payload.set(recovered);
                                                restore_status.set(
                                                    "Decrypt succeeded. Recovery payload recovered to local memory only.".to_owned(),
                                                );
                                            }
                                            Err(err) => {
                                                restore_status.set(format!(
                                                    "Decrypt failed: {err}"
                                                ));
                                            }
                                        }
                                    });
                                },
                                "Restore"
                            }
                        }
                    }

                    div { class: "event",
                        div { class: "event-head",
                            span { "Status" }
                            span { "data-testid": "recovery-restore-status", "{restore_status}" }
                        }
                        if !decrypted_payload().is_empty() {
                            div { class: "muted", "data-testid": "recovery-restore-payload-preview",
                                "Recovered payload size: {decrypted_payload().len()} bytes (held in tab memory only)"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Pick the most recent backup entry from a `list_key_backups`
/// response. Falls back to the first record when `created_at` is
/// missing so the function never silently drops data. Returns `None`
/// when no backups are present.
fn latest_backup(value: &Value) -> Option<Value> {
    let arr = value.get("backups").and_then(Value::as_array)?;
    if arr.is_empty() {
        return None;
    }
    let mut best: Option<&Value> = None;
    let mut best_key = String::new();
    for entry in arr {
        let created = entry
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if best.is_none() || created > best_key {
            best = Some(entry);
            best_key = created;
        }
    }
    best.cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn latest_backup_picks_newest_created_at() {
        let payload = json!({
            "backups": [
                {"backup_id": "a", "created_at": "2026-05-01T00:00:00Z"},
                {"backup_id": "b", "created_at": "2026-05-15T00:00:00Z"},
                {"backup_id": "c", "created_at": "2026-04-30T00:00:00Z"}
            ]
        });
        let picked = latest_backup(&payload).expect("picks");
        assert_eq!(picked["backup_id"], "b");
    }

    #[test]
    fn latest_backup_returns_none_for_empty_list() {
        assert!(latest_backup(&json!({"backups": []})).is_none());
        assert!(latest_backup(&json!({})).is_none());
    }
}
