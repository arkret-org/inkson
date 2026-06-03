//! G3.Y1 — Fresh-device restore at `/recover`.
//!
//! Surfaces:
//! - `recovery-restore-panel` — wrapper
//! - `recovery-restore-passphrase-input` — paste/type the passphrase
//! - `recovery-restore-backup-id-input` — optional manual backup_id override; defaults to whichever
//!   id soland's `GET /api/v1/keys/backups` returns at the top of the list
//! - `recovery-restore-button` — derives the recovery key, fetches + decrypts the backup envelope
//! - `recovery-restore-status` — feedback
//!
//! This panel does NOT push `cx.device.authorize` on its own —
//! that's the domain of the device-pairing flow (`settings_devices.rs`)
//! and the SDK's cross-signing executor. We only re-hydrate the
//! private payload so the caller can re-establish identity locally.
//!
//! Coauth endpoints that the e2e harness exercises but that don't
//! yet exist:
//!
//! - `POST /api/v1/auth/passkey/begin` — TODO(G3.Y1-followup): coauth needs an unauthenticated
//!   entry point that lets a brand-new device claim the recovered identity without first holding a
//!   bearer token. Until then this view only exercises the on-device passphrase → KEK → decrypt
//!   path; the server round-trip happens via the existing `/api/v1/keys/backups/{backup_id}`
//!   endpoint with a temporary placeholder token in tests.

use dioxus::prelude::*;
use serde_json::Value;

use crate::components::HelpTip;
use crate::local_state::LocalStateStore;
use crate::views::helpers::with_authed_api;

#[component]
pub fn RecoverPanel(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: String,
    device_id: String,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
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
                                placeholder: "ck:backup:01964137-… (leave blank to use the latest)",
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

                                        // Spec §7.5: decrypt from the full envelope. `open_*`
                                        // verifies `key_commitment` (wrong-passphrase fail-fast,
                                        // no oracle leak), recomputes the deterministic nonce, and
                                        // binds the AEAD AAD, returning a clear error for any
                                        // missing/mismatched field.
                                        match crate::key_backup::open_passphrase_kdf_backup_body(
                                            pass.as_bytes(),
                                            &backup_value,
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
                                "Restore recovery vault"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "recovery-restore-mls-history-button",
                                disabled: !has_session || account_did.trim().is_empty() || device_id.trim().is_empty(),
                                onclick: move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let actor = account_did.clone();
                                    let device = device_id.clone();
                                    let mut state_store = state_store;
                                    restore_status.set(
                                        "Looking up latest MLS history backup from soland…".to_owned(),
                                    );
                                    decrypted_payload.set(String::new());
                                    spawn(async move {
                                        if api_token.trim().is_empty() {
                                            restore_status.set(
                                                "Sign in before restoring MLS history.".to_owned(),
                                            );
                                            return;
                                        }
                                        let list_value = match with_authed_api(
                                            &base,
                                            api_token.clone(),
                                            |api| async move {
                                                api.list_key_backups_by_series(
                                                    None,
                                                    Some("mls_history"),
                                                )
                                                .await
                                            },
                                        )
                                        .await
                                        {
                                            Ok(value) => value,
                                            Err(err) => {
                                                restore_status.set(format!(
                                                    "MLS history backup list failed: {}",
                                                    err.display()
                                                ));
                                                return;
                                            }
                                        };
                                        let Some(candidate) = latest_mls_history_backup(&list_value) else {
                                            restore_status.set(
                                                "No MLS history backup is available for this account/device.".to_owned(),
                                            );
                                            return;
                                        };
                                        let backup_value = if candidate
                                            .get("ciphertext")
                                            .and_then(Value::as_str)
                                            .is_some()
                                        {
                                            candidate
                                        } else {
                                            let Some(bid) = candidate
                                                .get("backup_id")
                                                .and_then(Value::as_str)
                                                .map(ToOwned::to_owned)
                                            else {
                                                restore_status.set(
                                                    "MLS history backup row missing backup_id.".to_owned(),
                                                );
                                                return;
                                            };
                                            match with_authed_api(
                                                &base,
                                                api_token.clone(),
                                                move |api| async move {
                                                    api.get_key_backup(&bid).await
                                                },
                                            )
                                            .await
                                            {
                                                Ok(value) => value,
                                                Err(err) => {
                                                    restore_status.set(format!(
                                                        "MLS history backup fetch failed: {}",
                                                        err.display()
                                                    ));
                                                    return;
                                                }
                                            }
                                        };
                                        let secure_store =
                                            crate::secure_key_store::default_secure_key_store(
                                                "yougen",
                                            );
                                        match crate::mls::runtime::restore_mls_history_backup_with_device_snapshot(
                                            &mut state_store.write(),
                                            secure_store.as_ref(),
                                            &actor,
                                            &device,
                                            &backup_value,
                                        ) {
                                            Ok(summary) => {
                                                let backup_label = summary
                                                    .backup_id
                                                    .as_deref()
                                                    .unwrap_or("(unknown backup)");
                                                restore_status.set(format!(
                                                    "MLS history restored from {backup_label}; space {} epoch {} (floor {}).",
                                                    crate::views::helpers::short_protocol_id(
                                                        &summary.space_id
                                                    ),
                                                    summary.envelope_epoch,
                                                    summary.epoch_floor
                                                ));
                                            }
                                            Err(err) => {
                                                restore_status.set(format!(
                                                    "MLS history restore failed: {}",
                                                    err.user_message()
                                                ));
                                            }
                                        }
                                    });
                                },
                                "Restore MLS history"
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
        if entry.get("backup_class").and_then(Value::as_str) == Some("mls_history") {
            continue;
        }
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

fn latest_mls_history_backup(value: &Value) -> Option<Value> {
    let arr = value.get("backups").and_then(Value::as_array)?;
    let mut best: Option<&Value> = None;
    let mut best_epoch = 0u64;
    let mut best_created = String::new();
    for entry in arr {
        if entry.get("backup_class").and_then(Value::as_str) != Some("mls_history") {
            continue;
        }
        let epoch = mls_history_backup_epoch(entry);
        let created = entry
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if best.is_none() || epoch > best_epoch || (epoch == best_epoch && created > best_created) {
            best = Some(entry);
            best_epoch = epoch;
            best_created = created;
        }
    }
    best.cloned()
}

fn mls_history_backup_epoch(value: &Value) -> u64 {
    value
        .pointer("/envelope_meta/epoch")
        .and_then(Value::as_u64)
        .or_else(|| {
            value
                .get("contents")
                .and_then(Value::as_array)
                .and_then(|items| {
                    items
                        .iter()
                        .find(|item| {
                            item.get("item_type").and_then(Value::as_str) == Some("mls_group_state")
                        })
                        .and_then(|item| item.get("epoch").and_then(Value::as_u64))
                })
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

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

    #[test]
    fn latest_backup_ignores_mls_history_for_passphrase_restore() {
        let payload = json!({
            "backups": [
                {
                    "backup_id": "mls",
                    "backup_class": "mls_history",
                    "created_at": "2026-05-20T00:00:00Z"
                },
                {
                    "backup_id": "vault",
                    "backup_class": "secret_storage",
                    "created_at": "2026-05-01T00:00:00Z"
                }
            ]
        });
        let picked = latest_backup(&payload).expect("picks recovery vault");
        assert_eq!(picked["backup_id"], "vault");
    }

    #[test]
    fn latest_mls_history_backup_prefers_highest_epoch() {
        let payload = json!({
            "backups": [
                {
                    "backup_id": "older-created",
                    "backup_class": "mls_history",
                    "created_at": "2026-05-30T00:00:00Z",
                    "envelope_meta": {"epoch": 2}
                },
                {
                    "backup_id": "newer-epoch",
                    "backup_class": "mls_history",
                    "created_at": "2026-05-20T00:00:00Z",
                    "contents": [{"item_type": "mls_group_state", "epoch": 5}]
                },
                {
                    "backup_id": "vault",
                    "backup_class": "secret_storage",
                    "created_at": "2026-05-31T00:00:00Z"
                }
            ]
        });
        let picked = latest_mls_history_backup(&payload).expect("picks MLS backup");
        assert_eq!(picked["backup_id"], "newer-epoch");
    }
}
