//! The `RecoveryPanel` Dioxus component.

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;

use super::backup_summary::{
    BackupInventoryStatus, backup_inventory_status, fmt_backup_timestamp, parse_backup_list,
    sorted_backups_latest_first,
};
use super::helpers::copy_recovery_text_to_clipboard;
use super::state::{fmt_relative, load_state, save_generated_recovery_key_metadata};
use super::types::BackupSummaryRow;
use super::upload::{RecoveryKeyBackupOutcome, upload_recovery_key_account_backup};
use crate::components::HelpTip;
// SyncBadge / SyncBadgeState are shared in `crate::components::sync_badge`.
// The Recovery view renders the Recovery Key backup state through the shared
// component, overriding the "Local" label via `recovery.panel.badge_*` — the
// badge semantics stay global, only this view's copy changes. See C1.
use crate::components::SyncBadgeState as SyncBadge;
use crate::i18n::{substitute_args, tr, tr_args};
use crate::recovery_crypto::{
    RecoveryKeyConfirmationDiff, generate_recovery_key, recovery_key_confirmation_diff,
};
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;

const RESTORE_BACKUP_TIME_LIMIT: usize = 5;

/// Custody-first recovery-material phases. The plaintext exists only in
/// memory while the user transcribes it and while the confirmed material is
/// being published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollPhase {
    /// No enrollment in flight.
    Idle,
    /// Words are on screen and must be re-entered before any server write.
    CustodyConfirmation,
    /// Custody is confirmed; policy and first backup are being published.
    Publishing,
}

#[component]
pub fn RecoveryPanel(
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let state_store = crate::app::SessionContext::get().state_store;
    let actor_key = account_did();
    let initial = load_state(&state_store, &actor_key);

    // Recovery key state — plaintext only in memory after Generate.
    let mut live_recovery_key = use_signal(String::new);
    let mut recovery_key_fp = use_signal(|| initial.recovery_key_fingerprint.clone());
    let mut backup_hpke_public_key_multibase =
        use_signal(|| initial.backup_hpke_public_key_multibase.clone());
    let mut recovery_key_rotated_at = use_signal(|| initial.recovery_key_rotated_at.clone());
    let mut recovery_key_status = use_signal(String::new);
    let mut recovery_key_confirm_input = use_signal(String::new);
    let mut enroll_phase = use_signal(|| EnrollPhase::Idle);
    let mut confirm_attempts = use_signal(|| 0u32);
    let mut copied_feedback = use_signal(|| false);
    let mut device_unauthorized = use_signal(|| false);
    let navigator = use_navigator();

    // Backup history state — the panel shows server-side ciphertext inventory
    // only by time, without exposing raw backup IDs or destructive row actions.
    let mut restore_status = use_signal(String::new);
    let mut restore_loading = use_signal(|| false);
    let mut restore_loaded_once = use_signal(|| false);
    let mut backup_rows = use_signal(Vec::<BackupSummaryRow>::new);

    // Server-side Recovery-Key backup marker (written by the upload paths via
    // `mark_mls_recovery_backup_configured`). Drives the section sync badge.
    let recovery_key_backed_up =
        crate::components::mls_recovery_backup_configured(&state_store.read(), &actor_key);
    let recovery_material_established = !recovery_key_fp().is_empty() || recovery_key_backed_up;

    {
        let actor_key = actor_key.clone();
        use_effect(move || {
            let next = load_state(&state_store, &actor_key);
            if recovery_key_fp() != next.recovery_key_fingerprint {
                recovery_key_fp.set(next.recovery_key_fingerprint);
            }
            if backup_hpke_public_key_multibase() != next.backup_hpke_public_key_multibase {
                backup_hpke_public_key_multibase.set(next.backup_hpke_public_key_multibase);
            }
            if recovery_key_rotated_at() != next.recovery_key_rotated_at {
                recovery_key_rotated_at.set(next.recovery_key_rotated_at);
            }
        });
    }

    rsx! {
        div { class: "timeline recovery-panel", "data-testid": "recovery-panel", role: "region", "aria-label": tr("recovery.panel.aria_label"),
            div { class: "event",
                div { class: "event-head",
                    span { {tr("recovery.panel.options")} }
                    span { {tr("recovery.recovery_key_section")} }
                    HelpTip { text: tr("recovery.panel.overview_help") }
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric", "data-testid": "recovery-status-card",
                        strong { {tr("recovery.recovery_key_section")} }
                        span {
                            {
                                match enroll_phase() {
                                    EnrollPhase::Publishing => tr("recovery.panel.status.publishing"),
                                    EnrollPhase::CustodyConfirmation => tr("recovery.panel.status.write_down"),
                                    EnrollPhase::Idle => {
                                        if !recovery_key_fp().is_empty() {
                                            tr("recovery.panel.status.accepted")
                                        } else if recovery_key_backed_up {
                                            tr("recovery.panel.status.unconfirmed")
                                        } else {
                                            tr("recovery.panel.status.not_set")
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "muted",
                            {
                                match enroll_phase() {
                                    EnrollPhase::Publishing => tr("recovery.panel.detail.publishing"),
                                    EnrollPhase::CustodyConfirmation => tr("recovery.panel.detail.custody"),
                                    EnrollPhase::Idle => {
                                        if !recovery_key_fp().is_empty() {
                                            if recovery_key_rotated_at().is_empty() {
                                                tr("recovery.panel.detail.confirmed")
                                            } else {
                                                tr_args(
                                                    "recovery.panel.detail.accepted_at",
                                                    &[("when", fmt_relative(&recovery_key_rotated_at()))],
                                                )
                                            }
                                        } else if recovery_key_backed_up {
                                            tr("recovery.panel.detail.material_elsewhere")
                                        } else {
                                            tr("recovery.panel.detail.generate_cta")
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "metric",
                        strong { {tr("recovery.panel.protects_title")} }
                        span { {tr("recovery.panel.protects_value")} }
                        div { class: "muted", {tr("recovery.panel.protects_hint")} }
                    }
                }
            }

            // Recovery key — the only user-visible recovery credential
            div { class: "event", "data-testid": "recovery-key-section",
                div { class: "event-head",
                    span { {tr("recovery.recovery_key_section")} }
                    span { {tr("recovery.panel.keep_offline")} }
                    crate::components::SyncBadge {
                        state: if recovery_key_backed_up { SyncBadge::Synced } else { SyncBadge::Local },
                        local_label: Some(tr("recovery.panel.badge_not_backed_up")),
                        synced_label: Some(tr("recovery.panel.badge_backed_up")),
                        test_id: Some("recovery-key-sync-badge".to_owned()),
                    }
                    HelpTip { text: tr("recovery.panel.key_help") }
                }

                // The key itself — promoted to a full-width hero so it reads as
                // the single most important value on the panel, not one metric
                // cell among equals.
                div { class: "recovery-key-hero",
                    if enroll_phase() == EnrollPhase::Publishing {
                        div { class: "recovery-key-empty", "data-testid": "recovery-key-pending",
                            strong { {tr("recovery.panel.publishing_title")} }
                            span { class: "muted",
                                {tr("recovery.panel.publishing_hint")}
                            }
                        }
                    } else if !live_recovery_key().is_empty() {
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
                            strong { {tr("recovery.panel.not_generated")} }
                            span { class: "muted", {tr("recovery.panel.not_generated_hint")} }
                        }
                    }
                }

                if !live_recovery_key().is_empty() {
                    div { class: "callout warn", "data-testid": "recovery-key-live-warning",
                        div { class: "body",
                            strong { {tr("recovery.panel.write_down_title")} }
                            " "
                            {tr("recovery.panel.write_down_body")}
                        }
                    }
                    div { class: "workflow-form", "data-testid": "recovery-key-confirm-form",
                        Label { html_for: "recovery-key-confirm-input", {tr("recovery.panel.confirm_label")} }
                        Textarea {
                            id: "recovery-key-confirm-input",
                            "data-testid": "recovery-key-confirm-input",
                            rows: "3",
                            value: "{recovery_key_confirm_input}",
                            placeholder: tr("recovery.panel.confirm_placeholder"),
                            oninput: move |event: FormEvent| recovery_key_confirm_input.set(event.value()),
                        }
                        div { class: "muted", "data-testid": "recovery-key-confirm-hint",
                            {tr("recovery.panel.confirm_hint")}
                        }
                    }
                } else if !recovery_key_fp().is_empty() {
                    div { class: "muted", {tr("recovery.panel.plaintext_cleared")} }
                }

                if recovery_material_established && enroll_phase() == EnrollPhase::Idle {
                    div { class: "callout warn", "data-testid": "recovery-key-rotation-guard",
                        div { class: "body",
                            strong { {tr("recovery.panel.rotation_guard_title")} }
                            " "
                            {tr("recovery.panel.rotation_guard_body")}
                        }
                    }
                }

                // Supporting metadata — deliberately quieter than the key above.
                div { class: "recovery-key-meta",
                    div {
                        span { class: "lbl", {tr("recovery.panel.last_accepted")} }
                        span { class: "val", "data-testid": "recovery-key-rotated-at", "{fmt_relative(&recovery_key_rotated_at())}" }
                        span { class: "muted", {tr("recovery.panel.rotate_hint")} }
                    }
                    div {
                        span { class: "lbl", {tr("recovery.panel.fingerprint")} }
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
                        span { class: "muted", {tr("recovery.panel.fingerprint_hint")} }
                    }
                }

                if !recovery_key_status().is_empty() {
                    div { class: "muted", "data-testid": "recovery-key-status", "{recovery_key_status}" }
                }
                if device_unauthorized() {
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-goto-devices",
                            title: tr("recovery.panel.goto_devices_title"),
                            onclick: move |_| {
                                navigator.push(crate::routes::Route::SettingsDevices);
                            },
                            {tr("recovery.panel.goto_devices")}
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: if enroll_phase() == EnrollPhase::CustodyConfirmation {
                            ButtonVariant::Secondary
                        } else {
                            ButtonVariant::Primary
                        },
                        "data-testid": "recovery-key-regenerate",
                        disabled: enroll_phase() == EnrollPhase::Publishing || (recovery_material_established && enroll_phase() == EnrollPhase::Idle),
                        title: if enroll_phase() == EnrollPhase::CustodyConfirmation {
                            tr("recovery.panel.regenerate_title_fresh")
                        } else if recovery_material_established {
                            tr("recovery.panel.regenerate_title_guard")
                        } else {
                            tr("recovery.panel.regenerate_title_default")
                        },
                        onclick: move |_| {
                            if enroll_phase() == EnrollPhase::Publishing
                                || (recovery_material_established
                                    && enroll_phase() == EnrollPhase::Idle)
                            {
                                return;
                            }
                            match generate_recovery_key() {
                                Ok(key) => {
                                    live_recovery_key.set(key);
                                    recovery_key_confirm_input.set(String::new());
                                    confirm_attempts.set(0);
                                    copied_feedback.set(false);
                                    device_unauthorized.set(false);
                                    enroll_phase.set(EnrollPhase::CustodyConfirmation);
                                    recovery_key_status.set(tr("recovery.panel.generated_status"));
                                }
                                Err(err) => {
                                    recovery_key_status.set(substitute_args(
                                        tr("recovery.panel.generate_failed"),
                                        &[("error", err.to_string())],
                                    ));
                                }
                            }
                        },
                        if enroll_phase() == EnrollPhase::Publishing {
                            {tr("recovery.panel.publishing_button")}
                        } else if enroll_phase() == EnrollPhase::CustodyConfirmation {
                            {tr("recovery.panel.start_over")}
                        } else if recovery_key_fp().is_empty() {
                            {tr("recovery.panel.generate")}
                        } else {
                            {tr("recovery.panel.handoff_required")}
                        }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-copy",
                        disabled: live_recovery_key().is_empty(),
                        title: tr("recovery.panel.copy_title"),
                        onclick: move |_| {
                            copy_recovery_text_to_clipboard(&live_recovery_key());
                            // In-place feedback instead of a status-line string;
                            // reverts after a moment so repeat copies read clearly.
                            copied_feedback.set(true);
                            spawn(async move {
                                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(
                                    2_000,
                                ))
                                .await;
                                copied_feedback.set(false);
                            });
                        },
                        if copied_feedback() {
                            {tr("recovery.panel.copied")}
                        } else {
                            {tr("recovery.panel.copy")}
                        }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-confirm-retry",
                        disabled: live_recovery_key().is_empty() || recovery_key_confirm_input().is_empty(),
                        title: tr("recovery.panel.retry_title"),
                        onclick: move |_| {
                            recovery_key_confirm_input.set(String::new());
                        },
                        {tr("recovery.panel.retry")}
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-clear-live",
                        disabled: live_recovery_key().is_empty(),
                        title: tr("recovery.panel.clear_live_title"),
                        onclick: {
                            let base_url = base_url.clone();
                            let actor_key = actor_key.clone();
                            let store = state_store;
                            move |_| {
                                let current_key = live_recovery_key();
                                // The on_outcome handler runs inside the upload
                                // task's spawn, where tr() has no Dioxus context
                                // (see `upload_recovery_key_account_backup`) —
                                // resolve the status strings here and move them
                                // across the boundary.
                                let status_custody_confirmed = tr("recovery.panel.custody_confirmed");
                                let status_metadata_save_failed =
                                    tr("recovery.panel.metadata_save_failed");
                                let status_accepted_done = tr("recovery.panel.accepted_done");
                                match recovery_key_confirmation_diff(
                                    &current_key,
                                    &recovery_key_confirm_input(),
                                ) {
                                    RecoveryKeyConfirmationDiff::Match => {
                                        enroll_phase.set(EnrollPhase::Publishing);
                                        recovery_key_status.set(status_custody_confirmed.clone());
                                        let accepted_key = current_key.clone();
                                        let accepted_actor = actor_key.clone();
                                        let on_outcome = EventHandler::new(
                                            move |outcome: RecoveryKeyBackupOutcome| match outcome {
                                                RecoveryKeyBackupOutcome::Established => {
                                                    let mut accepted_store = store;
                                                    let Some((fingerprint, rotated_at)) =
                                                        save_generated_recovery_key_metadata(
                                                            &mut accepted_store,
                                                            &accepted_actor,
                                                            &accepted_key,
                                                        )
                                                    else {
                                                        enroll_phase.set(
                                                            EnrollPhase::CustodyConfirmation,
                                                        );
                                                        recovery_key_status.set(
                                                            status_metadata_save_failed.clone(),
                                                        );
                                                        return;
                                                    };
                                                    recovery_key_fp.set(fingerprint);
                                                    recovery_key_rotated_at.set(rotated_at);
                                                    live_recovery_key.set(String::new());
                                                    recovery_key_confirm_input.set(String::new());
                                                    confirm_attempts.set(0);
                                                    enroll_phase.set(EnrollPhase::Idle);
                                                    recovery_key_status.set(
                                                        status_accepted_done.clone(),
                                                    );
                                                }
                                                RecoveryKeyBackupOutcome::DeviceUnauthorized => {
                                                    enroll_phase.set(
                                                        EnrollPhase::CustodyConfirmation,
                                                    );
                                                    device_unauthorized.set(true);
                                                }
                                                RecoveryKeyBackupOutcome::Transient => {
                                                    enroll_phase.set(
                                                        EnrollPhase::CustodyConfirmation,
                                                    );
                                                }
                                            },
                                        );
                                        upload_recovery_key_account_backup(
                                            base_url.clone(),
                                            token,
                                            account_did,
                                            device_id,
                                            state_store,
                                            current_key,
                                            recovery_key_status,
                                            None,
                                            Some(on_outcome),
                                        );
                                    }
                                    RecoveryKeyConfirmationDiff::WordCount { entered } => {
                                        let attempts = confirm_attempts() + 1;
                                        confirm_attempts.set(attempts);
                                        let extra = if attempts >= 3 {
                                            tr("recovery.panel.retry_extra")
                                        } else {
                                            String::new()
                                        };
                                        recovery_key_status.set(substitute_args(
                                            tr("recovery.panel.word_count"),
                                            &[
                                                ("entered", entered.to_string()),
                                                ("extra", extra),
                                            ],
                                        ));
                                    }
                                    RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                        let attempts = confirm_attempts() + 1;
                                        confirm_attempts.set(attempts);
                                        let extra = if attempts >= 3 {
                                            tr("recovery.panel.retry_extra")
                                        } else {
                                            String::new()
                                        };
                                        recovery_key_status.set(substitute_args(
                                            tr("recovery.panel.word_mismatch"),
                                            &[("index", index.to_string()), ("extra", extra)],
                                        ));
                                    }
                                }
                            }
                        },
                        {tr("recovery.panel.confirm_publish")}
                    }
                }
            }

            // Backup history — key-management.md §7.3 + device-lifecycle.md §6
            //
            // Lists only backup creation times. Detailed envelope identifiers,
            // per-backup decrypt controls, and destructive delete controls stay
            // out of this user-facing panel.
            details { class: "event", "data-testid": "restore-section",
                summary { class: "event-head",
                    span { {tr("recovery.panel.history_title")} }
                    span { class: "muted", {tr("recovery.panel.history_subtitle")} }
                    HelpTip { text: tr("recovery.panel.history_help") }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "restore-list-button",
                        disabled: restore_loading(),
                        onclick: {
                            let base = base_url.clone();
                            // Written from inside the spawned task below, where
                            // tr() has no Dioxus context — resolve the status
                            // templates here and move them across the boundary.
                            let status_inventory_empty = tr("recovery.panel.inventory_empty");
                            let status_inventory_loaded_tpl =
                                tr("recovery.panel.inventory_loaded");
                            let status_fetch_failed_tpl = tr("recovery.panel.fetch_failed");
                            move |_| {
                                restore_status.set(tr("recovery.panel.fetching"));
                                restore_loading.set(true);
                                let base = base.clone();
                                let api_token = token();
                                let status_inventory_empty = status_inventory_empty.clone();
                                let status_inventory_loaded_tpl =
                                    status_inventory_loaded_tpl.clone();
                                let status_fetch_failed_tpl = status_fetch_failed_tpl.clone();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.list_key_backups().await
                                    })
                                    .await
                                    {
                                        Ok(payload) => {
                                            let payload =
                                                serde_json::to_value(&payload).unwrap_or_default();
                                            let rows = parse_backup_list(&payload);
                                            let status = match backup_inventory_status(&rows) {
                                                BackupInventoryStatus::Empty => {
                                                    status_inventory_empty.clone()
                                                }
                                                BackupInventoryStatus::Loaded { count, latest } => {
                                                    substitute_args(
                                                        status_inventory_loaded_tpl.clone(),
                                                        &[
                                                            ("count", count.to_string()),
                                                            ("latest", latest),
                                                        ],
                                                    )
                                                }
                                            };
                                            backup_rows.set(rows);
                                            restore_loaded_once.set(true);
                                            restore_status.set(status);
                                        }
                                        Err(err) => restore_status.set(substitute_args(
                                            status_fetch_failed_tpl.clone(),
                                            &[("error", err.display().to_string())],
                                        )),
                                    }
                                    restore_loading.set(false);
                                });
                            }
                        },
                        if restore_loading() {
                            {tr("recovery.panel.loading")}
                        } else {
                            {tr("recovery.panel.refresh")}
                        }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "restore-clear-button",
                        title: tr("recovery.panel.clear_title"),
                        disabled: backup_rows().is_empty(),
                        onclick: move |_| {
                            backup_rows.set(Vec::new());
                            restore_loaded_once.set(false);
                            restore_status.set(tr("recovery.panel.cleared"));
                        },
                        {tr("recovery.panel.clear")}
                    }
                }
                if !restore_status().is_empty() {
                    div { class: "muted", "data-testid": "restore-status", "{restore_status}" }
                }
                if backup_rows().is_empty() {
                    div { class: "muted", "data-testid": "restore-empty",
                        if restore_loaded_once() {
                            {tr("recovery.panel.no_backups")}
                        } else {
                            {tr("recovery.panel.not_loaded")}
                        }
                    }
                } else {
                    {
                        let rows = sorted_backups_latest_first(&backup_rows());
                        let total_backups = rows.len();
                        let latest = rows.first().cloned();
                        let latest_id = latest
                            .as_ref()
                            .map(|row| row.backup_id.clone())
                            .unwrap_or_default();
                        let latest_created_at = latest
                            .as_ref()
                            .map(|row| row.created_at.clone())
                            .unwrap_or_default();
                        let latest_relative = fmt_relative(&latest_created_at);
                        let latest_timestamp = fmt_backup_timestamp(&latest_created_at);
                        let visible_rows: Vec<BackupSummaryRow> = rows
                            .iter()
                            .take(RESTORE_BACKUP_TIME_LIMIT)
                            .cloned()
                            .collect();
                        let older_count = total_backups.saturating_sub(visible_rows.len());

                        rsx! {
                            div { class: "restore-backup-overview", "data-testid": "restore-summary",
                                div { class: "restore-latest-backup", "data-testid": "restore-latest-backup",
                                    span { class: "lbl", {tr("recovery.panel.last_backup")} }
                                    strong { "data-testid": "restore-latest-backup-relative", "{latest_relative}" }
                                    span { class: "muted", "data-testid": "restore-latest-backup-time", "{latest_timestamp}" }
                                }
                                div { class: "restore-backup-count", "data-testid": "restore-backup-count",
                                    span { class: "lbl", {tr("recovery.panel.backups_found")} }
                                    strong { "{total_backups}" }
                                    span { class: "muted", {tr("recovery.panel.snapshots")} }
                                }
                            }
                            div { class: "restore-time-list", "data-testid": "restore-backup-times",
                                div { class: "restore-time-list-head",
                                    span { {tr("recovery.panel.backup_times")} }
                                    span { class: "muted",
                                        {tr_args("recovery.panel.total", &[("total", total_backups.to_string())])}
                                    }
                                }
                                ul { class: "restore-time-items",
                                    for row in visible_rows {
                                        {
                                            let is_latest = row.backup_id == latest_id;
                                            let relative = fmt_relative(&row.created_at);
                                            let timestamp = fmt_backup_timestamp(&row.created_at);
                                            rsx! {
                                                li {
                                                    class: if is_latest { "restore-time-item latest" } else { "restore-time-item" },
                                                    "data-testid": "restore-backup-time",
                                                    span { class: "restore-time-dot" }
                                                    div { class: "restore-time-copy",
                                                        span { class: "restore-time-primary", "{relative}" }
                                                        span { class: "restore-time-secondary", "{timestamp}" }
                                                    }
                                                    if is_latest {
                                                        span { class: "badge green restore-time-badge", {tr("recovery.panel.latest")} }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if older_count > 0 {
                                    div { class: "restore-time-more muted", "data-testid": "restore-backup-older-count",
                                        {tr_args("recovery.panel.older_hidden", &[("count", older_count.to_string())])}
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Recovery write path
            details { class: "event", "data-testid": "recovery-writeback-explainer",
                summary { class: "event-head",
                    span { {tr("recovery.panel.writeback_title")} }
                    span { {tr("recovery.panel.writeback_subtitle")} }
                }
                div { class: "muted",
                    {tr("recovery.panel.writeback_body")}
                }
            }
        }
    }
}
