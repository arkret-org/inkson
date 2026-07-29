//! The `RecoveryPanel` Dioxus component.

use dioxus::prelude::*;
use dioxus_router::hooks::use_navigator;

use super::backup_summary::{
    backup_inventory_status, fmt_backup_timestamp, parse_backup_list, sorted_backups_latest_first,
};
use super::helpers::copy_recovery_text_to_clipboard;
use super::state::{fmt_relative, load_state, save_generated_recovery_key_metadata};
use super::types::BackupSummaryRow;
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
    let mut fresh_recovery_words =
        use_signal(crate::fresh_device_recovery::RecoveryWordsInput::default);
    let mut fresh_recovery_status = use_signal(String::new);
    let mut fresh_recovery_running = use_signal(|| false);
    let mut fresh_recovery_checkpoint = use_signal(|| None);

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
    {
        let actor_key = actor_key.clone();
        use_effect(move || {
            let Ok(principal_id) = arkret_sdk::Did::new(actor_key.clone()) else {
                return;
            };
            let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
            match crate::security_transaction::load_fresh_device_recovery_checkpoint(
                secure_store.as_ref(),
                &principal_id,
            ) {
                Ok(checkpoint) => fresh_recovery_checkpoint.set(checkpoint),
                Err(error) => fresh_recovery_status.set(format!(
                    "Could not load the durable recovery checkpoint: {error}"
                )),
            }
        });
    }

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

            div { class: "event", "data-testid": "fresh-device-recovery-section",
                div { class: "event-head",
                    span { "Recover this device" }
                    span { "24-word proof" }
                    HelpTip { text: "This verifies the Recovery Key against the active policy and opens the durable recovery strand. Proof verification alone never marks the device ready; authorization, terminal receipt, holder-bound grant refresh, and encrypted-history restore must all finish." }
                }
                Label { html_for: "fresh-device-recovery-words", "Existing Recovery Key" }
                Textarea {
                    id: "fresh-device-recovery-words",
                    "data-testid": "fresh-device-recovery-words",
                    rows: "3",
                    value: "{fresh_recovery_words().as_str()}",
                    autocomplete: "off",
                    placeholder: "Enter the 24 words kept offline",
                    oninput: move |event: FormEvent| {
                        fresh_recovery_words.write().replace(event.value());
                    },
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "fresh-device-recovery-start",
                        disabled: fresh_recovery_running() || fresh_recovery_words().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let Some(words) = fresh_recovery_words().normalized() else {
                                    fresh_recovery_status.set(
                                        "Enter exactly 24 valid Recovery Key words.".to_owned(),
                                    );
                                    return;
                                };
                                fresh_recovery_words.write().clear();
                                fresh_recovery_running.set(true);
                                fresh_recovery_status.set(
                                    "Verifying the recovery proof against the active policy…"
                                        .to_owned(),
                                );
                                let base = base.clone();
                                let api_token = token();
                                let principal_id = account_did();
                                let requesting_device_id = device_id();
                                spawn(async move {
                                    let result = with_authed_api(
                                        &base,
                                        api_token,
                                        |api| async move {
                                            let policy = crate::recovery_strand::fetch_active_recovery_policy(&api)
                                                .await?
                                                .ok_or_else(|| anyhow::anyhow!("no active recovery policy"))?;
                                            let body = crate::recovery_strand::create_session_body(
                                                &principal_id,
                                                &requesting_device_id,
                                                policy.trust_domain.as_str(),
                                                Some((policy.policy_id.as_str(), policy.version)),
                                            )?;
                                            let session = api.create_recovery_session(&body).await?;
                                            let outcome = crate::recovery_strand::submit_recovery_unlock_proof(
                                                &api,
                                                &session,
                                                &policy,
                                                words.as_str(),
                                            )
                                            .await?;
                                            let authoritative = api
                                                .get_recovery_session(
                                                    session.recovery_session_id.as_str(),
                                                )
                                                .await?;
                                            let transaction = if outcome.state
                                                == arkret_sdk::SessionState::Verified
                                                && authoritative.identity_model
                                                    == arkret_sdk::RecoveryIdentityModel::CrossSigning
                                            {
                                                let secure_store =
                                                    crate::secure_key_store::default_secure_key_store(
                                                        "inkson",
                                                    );
                                                let prepared = crate::fresh_device_recovery::
                                                    prepare_cross_signing_recovery_from_words(
                                                        &api,
                                                        secure_store.as_ref(),
                                                        &authoritative,
                                                        words.as_str(),
                                                    )
                                                    .await?;
                                                let transaction_id =
                                                    prepared.request.transaction_id.clone();
                                                let transaction_store = crate::security_transaction::
                                                    InksonSecurityTransactionStore::new(
                                                        secure_store.clone(),
                                                    );
                                                let staged_ref = transaction_store
                                                    .stage_secret(
                                                        &transaction_id,
                                                        prepared.staged_secret,
                                                    )
                                                    .await?;
                                                let engine = crate::security_transaction::
                                                    security_transaction_engine(
                                                        api.sdk_http_client()?,
                                                        secure_store,
                                                    );
                                                Some(
                                                    crate::fresh_device_recovery::
                                                        FreshDeviceRecovery::new(engine)
                                                        .create_or_resume(
                                                            prepared.request,
                                                            Some(staged_ref),
                                                        )
                                                        .await?,
                                                )
                                            } else {
                                                None
                                            };
                                            anyhow::Ok((authoritative, outcome, transaction))
                                        },
                                    )
                                    .await;
                                    match result {
                                        Ok((session, outcome, transaction))
                                            if outcome.state
                                                == arkret_sdk::SessionState::Verified =>
                                        {
                                            let checkpoint = crate::security_transaction::FreshDeviceRecoveryCheckpoint::from_verified_session(&session)
                                                .and_then(|mut checkpoint| {
                                                    if let Some(transaction) = &transaction {
                                                        checkpoint.observe_transaction(transaction)?;
                                                    }
                                                    Ok(checkpoint)
                                                });
                                            match checkpoint {
                                                Ok(checkpoint) => {
                                                    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                                                    match crate::security_transaction::save_fresh_device_recovery_checkpoint(
                                                        secure_store.as_ref(),
                                                        &checkpoint,
                                                    )
                                                    .await
                                                    {
                                                        Ok(()) => {
                                                            fresh_recovery_checkpoint.set(Some(checkpoint));
                                                            let progress = transaction
                                                                .as_ref()
                                                                .map(|transaction| format!(
                                                                    " Bound transaction {} is server-authoritative at {:?}.",
                                                                    transaction.transaction_id,
                                                                    transaction.state
                                                                ))
                                                                .unwrap_or_else(|| {
                                                                    " Enrollment-authority transaction preparation is still required."
                                                                        .to_owned()
                                                                });
                                                            fresh_recovery_status.set(format!(
                                                                "Recovery session {} is verified and durably checkpointed ({:?}).{} This device is not ready yet.",
                                                                session.recovery_session_id,
                                                                session.identity_model,
                                                                progress
                                                            ));
                                                        }
                                                        Err(error) => fresh_recovery_status.set(format!(
                                                            "Recovery proof verified, but the durable public checkpoint failed: {error}. No transaction was started."
                                                        )),
                                                    }
                                                }
                                                Err(error) => fresh_recovery_status.set(format!(
                                                    "Recovery proof verified, but the authoritative session could not be checkpointed: {error}. No transaction was started."
                                                )),
                                            }
                                        }
                                        Ok((_session, outcome, _transaction)) => {
                                            fresh_recovery_status.set(format!(
                                                "Recovery proof was not verified (state: {:?}); no device-ready state was granted.",
                                                outcome.state
                                            ));
                                        }
                                        Err(error) => {
                                            fresh_recovery_status.set(format!(
                                                "Recovery proof failed safely: {}",
                                                error.display()
                                            ));
                                        }
                                    }
                                    fresh_recovery_running.set(false);
                                });
                            }
                        },
                        if fresh_recovery_running() { "Verifying…" } else { "Start durable recovery" }
                    }
                    if fresh_recovery_checkpoint()
                        .as_ref()
                        .and_then(|checkpoint| checkpoint.transaction_id.as_ref())
                        .is_some()
                    {
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "fresh-device-recovery-resume",
                            disabled: fresh_recovery_running(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let Some(mut checkpoint) = fresh_recovery_checkpoint() else {
                                        return;
                                    };
                                    let Some(transaction_id) = checkpoint.transaction_id.clone() else {
                                        return;
                                    };
                                    fresh_recovery_running.set(true);
                                    fresh_recovery_status.set(
                                        "Reading authoritative transaction progress…".to_owned(),
                                    );
                                    let base = base.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        let result = with_authed_api(&base, api_token, |api| async move {
                                            let secure_store =
                                                crate::secure_key_store::default_secure_key_store("inkson");
                                            let engine = crate::security_transaction::security_transaction_engine(
                                                api.sdk_http_client()?,
                                                secure_store.clone(),
                                            );
                                            let recovery = crate::fresh_device_recovery::FreshDeviceRecovery::new(engine);
                                            let transaction = match recovery
                                                .retry_byte_identical_pending(&transaction_id)
                                                .await?
                                            {
                                                Some(transaction) => transaction,
                                                None => recovery.refresh(&transaction_id).await?,
                                            };
                                            checkpoint.observe_transaction(&transaction)?;
                                            crate::security_transaction::save_fresh_device_recovery_checkpoint(
                                                secure_store.as_ref(),
                                                &checkpoint,
                                            )
                                            .await?;
                                            anyhow::Ok((checkpoint, transaction))
                                        })
                                        .await;
                                        match result {
                                            Ok((checkpoint, transaction)) => {
                                                fresh_recovery_checkpoint.set(Some(checkpoint));
                                                fresh_recovery_status.set(format!(
                                                    "Server state: {:?}; next required step: {:?}. This device is not ready until terminal attestation, grant promotion, durable device/control projection, and restore report all pass.",
                                                    transaction.state,
                                                    transaction.next_required_step
                                                ));
                                            }
                                            Err(error) => fresh_recovery_status.set(format!(
                                                "Recovery resume failed safely: {}",
                                                error.display()
                                            )),
                                        }
                                        fresh_recovery_running.set(false);
                                    });
                                }
                            },
                            "Resume durable recovery"
                        }
                    }
                }
                if !fresh_recovery_status().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "fresh-device-recovery-status",
                        "{fresh_recovery_status}"
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
