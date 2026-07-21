//! The `RecoveryPanel` Dioxus component.

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;

use super::backup_summary::{
    backup_inventory_status, fmt_backup_timestamp, parse_backup_list, sorted_backups_latest_first,
};
use super::helpers::copy_recovery_text_to_clipboard;
use super::state::{fmt_relative, load_state, save_generated_recovery_key_metadata, save_state};
use super::types::{BackupSummaryRow, Guardian, RecoveryState};
use super::upload::{RecoveryKeyBackupOutcome, upload_recovery_key_account_backup};
use crate::components::HelpTip;
// SyncBadge / SyncBadgeState are shared in `crate::components::sync_badge`.
// The Recovery view renders the Recovery Key backup state through the shared
// component, overriding the "Local" label to "Not backed up yet" — the badge
// semantics stay global, only this view's copy changes. See C1.
use crate::components::SyncBadgeState as SyncBadge;
use crate::recovery_crypto::{
    RecoveryKeyConfirmationDiff, generate_recovery_key, recovery_key_confirmation_diff,
};
use crate::transport::auth::with_authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::textarea::Textarea;
use crate::views::helpers::display_name_for_did;

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

    // Social recovery state
    let mut threshold = use_signal(|| initial.sss_threshold);
    let mut total = use_signal(|| initial.sss_total);
    let mut guardians = use_signal(|| initial.guardians.clone());
    let mut new_guardian_label = use_signal(String::new);
    let mut new_guardian_did = use_signal(String::new);
    let mut new_guardian_note = use_signal(String::new);
    let mut last_rehearsed = use_signal(|| initial.last_rehearsed_at.clone());
    let mut social_status = use_signal(String::new);

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

    let snapshot_state = move || RecoveryState {
        recovery_key_fingerprint: recovery_key_fp(),
        backup_hpke_public_key_multibase: backup_hpke_public_key_multibase(),
        recovery_key_rotated_at: recovery_key_rotated_at(),
        sss_threshold: threshold(),
        sss_total: total(),
        guardians: guardians(),
        last_rehearsed_at: last_rehearsed(),
    };

    rsx! {
        div { class: "timeline recovery-panel", "data-testid": "recovery-panel", role: "region", "aria-label": "Recovery and key backup",
            div { class: "event",
                div { class: "event-head",
                    span { "Recovery options" }
                    span { "Recovery Key (24 words)" }
                    HelpTip { text: "The Recovery Key (24 words) is the only recovery credential. Arkret never stores it on the server; backups are encrypted on-device before upload. A recovery credential may unlock backup material; a fresh device is authorized only after the active recovery_policy accepts a bound recovery_session proof." }
                }
                div { class: "metric-grid", "data-testid": "recovery-overview",
                    div { class: "metric", "data-testid": "recovery-status-card",
                        strong { "Recovery Key (24 words)" }
                        span {
                            {
                                match enroll_phase() {
                                    EnrollPhase::Publishing => "publishing confirmed recovery material…",
                                    EnrollPhase::CustodyConfirmation => "write the words down now",
                                    EnrollPhase::Idle => {
                                        if !recovery_key_fp().is_empty() {
                                            "recovery material accepted ✓"
                                        } else if recovery_key_backed_up {
                                            "backup on server — unconfirmed here"
                                        } else {
                                            "not set ⚠"
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "muted",
                            {
                                match enroll_phase() {
                                    EnrollPhase::Publishing => "Cold custody is confirmed; the policy and first encrypted backup are being accepted.".to_owned(),
                                    EnrollPhase::CustodyConfirmation => "Write the words down, then re-enter them before anything is published.".to_owned(),
                                    EnrollPhase::Idle => {
                                        if !recovery_key_fp().is_empty() {
                                            if recovery_key_rotated_at().is_empty() {
                                                "Recovery Key confirmed on this device".to_owned()
                                            } else {
                                                format!("Accepted {}", fmt_relative(&recovery_key_rotated_at()))
                                            }
                                        } else if recovery_key_backed_up {
                                            "Accepted recovery material exists, but this device does not retain its plaintext.".to_owned()
                                        } else {
                                            "Generate one to enable cross-device recovery".to_owned()
                                        }
                                    }
                                }
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
                    HelpTip { text: "This is your account's only recovery credential. Generating it wraps your account MLS secret behind these 24 words and uploads that encrypted backup; your own content sidecar is then backed up automatically after encrypted writes. The words themselves never leave this device (only a SHA-256 fingerprint is kept locally); Arkret cannot recover them for you, so write them down. Losing them means your encrypted history cannot be restored." }
                }

                // The key itself — promoted to a full-width hero so it reads as
                // the single most important value on the panel, not one metric
                // cell among equals.
                div { class: "recovery-key-hero",
                    if enroll_phase() == EnrollPhase::Publishing {
                        div { class: "recovery-key-empty", "data-testid": "recovery-key-pending",
                            strong { "Publishing the recovery policy and encrypted backup…" }
                            span { class: "muted",
                                "The confirmed words stay only in memory until this write succeeds or you retry."
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
                            strong { "Not generated yet" }
                            span { class: "muted", "Generate one to enable policy-approved backup unlock fallback." }
                        }
                    }
                }

                if !live_recovery_key().is_empty() {
                    div { class: "callout warn", "data-testid": "recovery-key-live-warning",
                        div { class: "body",
                            strong { "Write these 24 words down now." }
                            " Re-enter the saved words below before clearing them from this screen."
                        }
                    }
                    div { class: "workflow-form", "data-testid": "recovery-key-confirm-form",
                        Label { html_for: "recovery-key-confirm-input", "Re-enter the saved Recovery Key" }
                        Textarea {
                            id: "recovery-key-confirm-input",
                            "data-testid": "recovery-key-confirm-input",
                            rows: "3",
                            value: "{recovery_key_confirm_input}",
                            placeholder: "Type or paste the 24 words you saved",
                            oninput: move |event: FormEvent| recovery_key_confirm_input.set(event.value()),
                        }
                        div { class: "muted", "data-testid": "recovery-key-confirm-hint",
                            "The words must match before the plaintext is cleared. If a word is wrong, the check tells you which position to fix — no need to regenerate."
                        }
                    }
                } else if !recovery_key_fp().is_empty() {
                    div { class: "muted", "Plaintext is no longer in memory. Recovery-key replacement requires the staged handoff workflow." }
                }

                if recovery_material_established && enroll_phase() == EnrollPhase::Idle {
                    div { class: "callout warn", "data-testid": "recovery-key-rotation-guard",
                        div { class: "body",
                            strong { "Direct replacement is disabled." }
                            " A new Recovery Key must be activated through the durable two-entry handoff, then all protected backup series must be rewrapped before the old key is revoked."
                        }
                    }
                }

                // Supporting metadata — deliberately quieter than the key above.
                div { class: "recovery-key-meta",
                    div {
                        span { class: "lbl", "Last accepted" }
                        span { class: "val", "data-testid": "recovery-key-rotated-at", "{fmt_relative(&recovery_key_rotated_at())}" }
                        span { class: "muted", "Rotate only through the staged handoff workflow" }
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
                if device_unauthorized() {
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "recovery-key-goto-devices",
                            title: "Authorize this device from one you already use, then come back and generate the key.",
                            onclick: move |_| {
                                navigator.push(crate::routes::Route::SettingsDevices);
                            },
                            "Open device settings"
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
                            "Discard the displayed words and prepare a fresh recovery secret."
                        } else if recovery_material_established {
                            "Direct replacement is unsafe; use staged handoff."
                        } else {
                            "Generate the words locally; nothing is published until you re-enter them."
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
                                    recovery_key_status.set(
                                        "Write the words down offline and re-enter them. No recovery material has been published yet."
                                            .to_owned(),
                                    );
                                }
                                Err(err) => {
                                    recovery_key_status.set(format!("Generate failed: {err}"));
                                }
                            }
                        },
                        if enroll_phase() == EnrollPhase::Publishing {
                            "Publishing…"
                        } else if enroll_phase() == EnrollPhase::CustodyConfirmation {
                            "Start over with a new key"
                        } else if recovery_key_fp().is_empty() {
                            "Generate"
                        } else {
                            "Staged handoff required"
                        }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-copy",
                        disabled: live_recovery_key().is_empty(),
                        title: "Copy the 24-word Recovery Key to the clipboard.",
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
                        if copied_feedback() { "✓ Copied!" } else { "Copy" }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-confirm-retry",
                        disabled: live_recovery_key().is_empty() || recovery_key_confirm_input().is_empty(),
                        title: "Clear the entry and type the saved words again.",
                        onclick: move |_| {
                            recovery_key_confirm_input.set(String::new());
                        },
                        "Clear and retry"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "recovery-key-clear-live",
                        disabled: live_recovery_key().is_empty(),
                        title: "Confirm the offline copy before publishing recovery material.",
                        onclick: {
                            let base_url = base_url.clone();
                            let actor_key = actor_key.clone();
                            let store = state_store;
                            move |_| {
                                let current_key = live_recovery_key();
                                match recovery_key_confirmation_diff(
                                    &current_key,
                                    &recovery_key_confirm_input(),
                                ) {
                                    RecoveryKeyConfirmationDiff::Match => {
                                        enroll_phase.set(EnrollPhase::Publishing);
                                        recovery_key_status.set(
                                            "Cold custody confirmed. Publishing the recovery policy and first encrypted backup…"
                                                .to_owned(),
                                        );
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
                                                            "Recovery material was accepted, but public local metadata could not be saved."
                                                                .to_owned(),
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
                                                        "Recovery material accepted; plaintext cleared from memory. Keep the offline copy in cold custody."
                                                            .to_owned(),
                                                    );
                                                }
                                                RecoveryKeyBackupOutcome::DeviceNotAuthorized => {
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
                                            " If your saved copy keeps failing, start over with a new key."
                                        } else {
                                            ""
                                        };
                                        recovery_key_status.set(format!(
                                            "You entered {entered} of 24 words. Complete the phrase, then confirm again.{extra}"
                                        ));
                                    }
                                    RecoveryKeyConfirmationDiff::MismatchAt { index } => {
                                        let attempts = confirm_attempts() + 1;
                                        confirm_attempts.set(attempts);
                                        let extra = if attempts >= 3 {
                                            " If your saved copy keeps failing, start over with a new key."
                                        } else {
                                            ""
                                        };
                                        recovery_key_status.set(format!(
                                            "Word {index} does not match the displayed key. Fix it and confirm again.{extra}"
                                        ));
                                    }
                                }
                            }
                        },
                        "Confirm custody and publish"
                    }
                }
            }

            // Social recovery — key-management.md §7.4. Advanced, collapsed by
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
                div { class: "muted", "data-testid": "sss-progress",
                    {
                        let have = guardians().len() as u32;
                        let need = threshold();
                        if have >= need {
                            format!("{have} guardian(s) added — the {need}-guardian threshold is met.")
                        } else {
                            format!("{have} of {need} guardians added — add {} more to enable social recovery.", need - have)
                        }
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
                                    let guardian_did_label =
                                        display_name_for_did(&state_store.read(), &g.did);
                                    rsx! { span { title: "{g.did}", "{guardian_did_label}" } }
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
                                    crate::identity::handle::principal_did_from_identifier(
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
                        title: {
                            let have = guardians().len() as u32;
                            let need = threshold();
                            if have < need {
                                format!("Add {} more guardian(s) to meet the {need}-guardian threshold before rehearsing.", need - have)
                            } else {
                                "Records a Last rehearsed timestamp; integrate with guardian outreach when wired to the server.".to_owned()
                            }
                        },
                        onclick: {
                            let actor_key = actor_key.clone();
                            let mut store = state_store;
                            move |_| {
                                let now = arkret_sdk::canonical::format_timestamp_canonical(
                                    chrono::Utc::now(),
                                );
                                last_rehearsed.set(now);
                                save_state(&mut store, &actor_key, &snapshot_state());
                                social_status.set("Rehearsal logged. Outreach to guardians is a future server-side feature.".to_owned());
                            }
                        },
                        "Rehearse social recovery"
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
                    span { "Advanced · Backup history" }
                    span { class: "muted", "server-side ciphertext only" }
                    HelpTip { text: "Shows when encrypted backups were created on the server. Backup contents stay encrypted and are not shown here." }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "restore-list-button",
                        disabled: restore_loading(),
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                restore_status.set("Fetching backup times…".to_owned());
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
                                            let payload =
                                                serde_json::to_value(&payload).unwrap_or_default();
                                            let rows = parse_backup_list(&payload);
                                            let status = backup_inventory_status(&rows);
                                            backup_rows.set(rows);
                                            restore_loaded_once.set(true);
                                            restore_status.set(status);
                                        }
                                        Err(err) => restore_status
                                            .set(format!("Backup times: {}", err.display())),
                                    }
                                    restore_loading.set(false);
                                });
                            }
                        },
                        if restore_loading() { "Loading…" } else { "Refresh backup times" }
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "restore-clear-button",
                        title: "Only clears this local panel. It does not delete server backups.",
                        disabled: backup_rows().is_empty(),
                        onclick: move |_| {
                            backup_rows.set(Vec::new());
                            restore_loaded_once.set(false);
                            restore_status.set("Cleared local backup history state. Server backups were not deleted.".to_owned());
                        },
                        "Clear panel"
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
                            "No backup times loaded yet."
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
                                    span { class: "lbl", "Last backup" }
                                    strong { "data-testid": "restore-latest-backup-relative", "{latest_relative}" }
                                    span { class: "muted", "data-testid": "restore-latest-backup-time", "{latest_timestamp}" }
                                }
                                div { class: "restore-backup-count", "data-testid": "restore-backup-count",
                                    span { class: "lbl", "Backups found" }
                                    strong { "{total_backups}" }
                                    span { class: "muted", "encrypted snapshots" }
                                }
                            }
                            div { class: "restore-time-list", "data-testid": "restore-backup-times",
                                div { class: "restore-time-list-head",
                                    span { "Backup times" }
                                    span { class: "muted", "{total_backups} total" }
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
                                                        span { class: "badge green restore-time-badge", "latest" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                if older_count > 0 {
                                    div { class: "restore-time-more muted", "data-testid": "restore-backup-older-count",
                                        "{older_count} older backup time(s) hidden"
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
                    span { "Advanced · What happens when recovery succeeds" }
                    span { "method-specific evidence" }
                }
                div { class: "muted",
                    "A complete recovery session makes the new device generate its own key, bind proof to the active recovery_policy, record a recovery receipt, authorize the new device, and then unlock secret_storage / MLS history backups. Backup history stays visible above; policy proof and device authorization are separate follow-up strands."
                }
            }
        }
    }
}
