//! G3.Y1 — Key backup status surface at `/settings/security`.
//!
//! Pure STATUS panel: it computes the real backup state from the server
//! (`list_key_backups` → is there an `mls_account_secret` backup?) instead of
//! keeping a local mirror, and it offers no manual trigger. The only write
//! path for key backups is the Recovery Key (24 words) flow on
//! `/settings/recovery` (plus the automatic backups after encrypted writes:
//! the private-plaintext sidecar AND the §7.10 continuous `mls_history`
//! uploads after each accepted `ck.mls.commit`); when nothing is configured
//! the single action here is a link to that page.
//!
//! Spec alignment (the old G3.Y1-followup note here was wrong and is
//! resolved): `crypto-media/encryption-and-audit.md` §2.4 deliberately does
//! NOT define a dedicated MLS-key backup endpoint. Epoch backfill is a CLIENT
//! replay of the Realm's `ck.mls.commit` history (key-management.md §7.3
//! step 6); the key material itself travels on the generic key-backup surface
//! as `backup_class="mls_history"` envelopes
//! (`PUT/GET /_cokret/self/keys/backups/{backup_id}`), implemented in
//! `crate::mls::account_recovery` and the `MlsUnlockPrompt` restore flow. The
//! remaining gap was CLIENT continuity — now closed by
//! `crate::components::mls_history_backup` (key-management.md §7.10 automatic
//! continuous backup) — not a missing soland endpoint.
//!
//! Surfaces:
//! - `key-backup-status` — "enabled" / "disabled" / "loading" / "error"
//! - `key-backup-last-backup-at` — created_at of the account-secret backup
//! - `key-backup-recovery-key-fp` — local Recovery Key fingerprint (never the words)
//! - `key-backup-setup-link` — link to `/settings/recovery` when disabled
//! - `key-backup-history-pending` — Realms whose newest MLS epoch material still awaits its
//!   continuous `mls_history` upload ("0" when drained)
//! - `key-backup-history-last-uploaded-at` — last successful continuous upload
//! - `key-backup-history-error` — last continuous-upload failure (only rendered after a failure)

use dioxus::prelude::*;
use dioxus_router::Link;
use serde_json::Value;

use crate::components::HelpTip;
use crate::local_state::LocalStateStore;
use crate::routes::Route;
use crate::views::helpers::with_authed_api;

/// Resolved server-side backup status.
#[derive(Clone, Debug, PartialEq, Eq)]
enum KeyBackupStatus {
    Loading,
    /// Server holds an `mls_account_secret` backup; `created_at` of that
    /// backup (RFC-3339) when present.
    Enabled {
        last_backup_at: String,
    },
    Disabled,
    /// Could not reach the server; carries the display error.
    Error(String),
}

impl KeyBackupStatus {
    /// Stable text for the `key-backup-status` testid.
    fn label(&self) -> &str {
        match self {
            Self::Loading => "loading",
            Self::Enabled { .. } => "enabled",
            Self::Disabled => "disabled",
            Self::Error(_) => "error",
        }
    }
}

/// Pure resolver: pick the account-secret backup out of a `list_key_backups`
/// payload and map it to a status. Unit-testable without a live session.
fn resolve_key_backup_status(list_payload: &Value) -> KeyBackupStatus {
    match crate::mls::account_recovery::select_mls_account_secret_backup(list_payload) {
        Some(body) => KeyBackupStatus::Enabled {
            last_backup_at: body
                .get("created_at")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        },
        None => KeyBackupStatus::Disabled,
    }
}

#[component]
pub fn SettingsSecurityPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut status = use_signal(|| KeyBackupStatus::Loading);
    let mut history_status = use_signal(crate::components::mls_history_backup_status);

    // Lightweight poll of the continuous mls_history backup job state (a
    // plain static job table — no server round-trip). Keeps the panel live
    // while mounted without introducing a second persisted status store.
    use_future(move || async move {
        loop {
            let current = crate::components::mls_history_backup_status();
            if *history_status.peek() != current {
                history_status.set(current);
            }
            crate::api::sleep_for(std::time::Duration::from_millis(1500)).await;
        }
    });

    let has_session = !token().trim().is_empty();
    let recovery_key_fp =
        crate::views::recovery::local_recovery_key_fingerprint(&state_store.read(), &account_did());

    // On mount (and whenever session/server change): compute the REAL backup
    // state from the server list. No local double bookkeeping.
    use_resource(move || async move {
        let base = base_url();
        let session = token();
        if base.trim().is_empty() || session.trim().is_empty() {
            status.set(KeyBackupStatus::Disabled);
            return;
        }
        match with_authed_api(
            &base,
            session,
            |api| async move { api.list_key_backups().await },
        )
        .await
        {
            Ok(payload) => status.set(resolve_key_backup_status(&payload)),
            Err(err) => status.set(KeyBackupStatus::Error(err.display())),
        }
    });

    let current = status();
    let history_now = history_status();
    let last_backup_at = match &current {
        KeyBackupStatus::Enabled { last_backup_at } if !last_backup_at.is_empty() => {
            last_backup_at.clone()
        }
        _ => "never".to_owned(),
    };
    let fp_short = recovery_key_fp
        .as_deref()
        .map(|fp| {
            let suffix = fp.split(':').nth(1).unwrap_or("");
            if suffix.len() >= 12 {
                format!("sha256:{}…", &suffix[..12])
            } else {
                fp.to_owned()
            }
        })
        .unwrap_or_else(|| "—".to_owned());

    rsx! {
        div { class: "settings-content-stack", "data-testid": "settings-security-panel",
            div { class: "event settings-control-panel",
                div { class: "event-head",
                    span { "Key backup" }
                    span { if has_session { "authenticated" } else { "not signed in" } }
                    HelpTip { text: "Status of your encrypted-history backup. Your account MLS secret (and your own content sidecar) is backed up automatically once a Recovery Key (24 words) exists; the ciphertext lives on the server, the 24 words never do.".to_owned() }
                }
            }

            div { class: "event",
                div { class: "event-head",
                    span { "Backup status" }
                    span {
                        "data-testid": "key-backup-status",
                        "{current.label()}"
                    }
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Last backup" }
                        span {
                            "data-testid": "key-backup-last-backup-at",
                            "{last_backup_at}"
                        }
                        div { class: "muted",
                            match &current {
                                KeyBackupStatus::Enabled { .. } => "account MLS secret backed up server-side",
                                KeyBackupStatus::Disabled => "No backup yet — generate a Recovery Key to enable it.",
                                KeyBackupStatus::Loading => "checking the server…",
                                KeyBackupStatus::Error(_) => "could not reach the server",
                            }
                        }
                    }
                    div { class: "metric",
                        strong { "Recovery Key (24 words)" }
                        span { "data-testid": "key-backup-recovery-key-fp", "{fp_short}" }
                        div { class: "muted",
                            if recovery_key_fp.is_some() {
                                "fingerprint stored locally — the words stay offline"
                            } else {
                                "not generated on this device"
                            }
                        }
                    }
                    div { class: "metric",
                        strong { "Storage" }
                        span { "PUT /_cokret/self/keys/backups" }
                        div { class: "muted", "ciphertext only" }
                    }
                    div { class: "metric",
                        strong { "Continuous history backup" }
                        span {
                            "data-testid": "key-backup-history-pending",
                            "{history_now.pending_realms}"
                        }
                        div { class: "muted",
                            if history_now.in_flight {
                                "uploading epoch material…"
                            } else if history_now.pending_realms > 0 {
                                "Realm(s) with epoch material waiting to upload"
                            } else {
                                "all MLS epoch material backed up"
                            }
                        }
                        div { class: "muted",
                            "last upload: "
                            span {
                                "data-testid": "key-backup-history-last-uploaded-at",
                                {history_now.last_uploaded_at.clone().unwrap_or_else(|| "never".to_owned())}
                            }
                        }
                    }
                }
                if let KeyBackupStatus::Error(err) = &current {
                    div { class: "muted", "data-testid": "key-backup-error", "{err}" }
                }
                if let Some(history_err) = history_now.last_error.clone() {
                    div { class: "muted", "data-testid": "key-backup-history-error",
                        "last history-backup failure"
                        if let Some(at) = history_now.last_error_at.clone() {
                            " ({at})"
                        }
                        ": {history_err}"
                    }
                }
                if matches!(current, KeyBackupStatus::Disabled) {
                    div { class: "actions",
                        Link {
                            class: "primary",
                            "data-testid": "key-backup-setup-link",
                            to: Route::SettingsRecovery,
                            "Generate a Recovery Key (24 words)"
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn empty_list_resolves_disabled() {
        let status = resolve_key_backup_status(&json!({ "backups": [] }));
        assert_eq!(status.label(), "disabled");
    }

    #[test]
    fn account_secret_backup_resolves_enabled_with_timestamp() {
        let status = resolve_key_backup_status(&json!({
            "backups": [{
                "backup_id": "ck:backup:01964137-0000-7000-8000-000000000000",
                "backup_class": "secret_storage",
                "created_at": "2026-06-01T00:00:00Z",
                "encryption": { "recipient_method": "passphrase_kdf" },
                "contents": [{
                    "item_type": "mls_account_secret",
                    "secret_id": "yougen_mls_account_secret"
                }]
            }]
        }));
        match status {
            KeyBackupStatus::Enabled { last_backup_at } => {
                assert_eq!(last_backup_at, "2026-06-01T00:00:00Z");
            }
            other => panic!("expected enabled, got {other:?}"),
        }
    }
}
