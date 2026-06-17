//! The `RecoveryPanel` Dioxus component.

use dioxus::prelude::*;

use super::backup_summary::{
    backup_inventory_status, fmt_backup_timestamp, parse_backup_list, sorted_backups_latest_first,
};
use super::helpers::{copy_recovery_text_to_clipboard, passkey_wrap_aad};
use super::state::{fmt_relative, load_state, save_state};
use super::types::{BackupSummaryRow, Guardian, PasskeyRecoveryWrap, RecoveryState};
use super::upload::upload_recovery_key_account_backup;
use crate::components::HelpTip;
// SyncBadge / SyncBadgeState are shared in `crate::components::sync_badge`.
// The Recovery view renders the Recovery Key backup state through the shared
// component, overriding the "Local" label to "Not backed up yet" — the badge
// semantics stay global, only this view's copy changes. See C1.
use crate::components::SyncBadgeState as SyncBadge;
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

const RESTORE_BACKUP_TIME_LIMIT: usize = 5;

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
                                        let _ = &mut store;
                                        let _ = &actor_key;
                                        let _ = snapshot_state;
                                        // Reveal the words in-context (a deliberate settings
                                        // action), but do NOT persist a recovery fingerprint
                                        // upfront. `upload_recovery_key_account_backup` is
                                        // fail-closed: it persists local recovery metadata ONLY
                                        // after the server accepts the backup (i.e. this device
                                        // passed the verified-device gate). A device the server
                                        // rejects with `device_not_authorized` therefore never
                                        // leaves a divergent Recovery Key root behind, and the
                                        // status line routes the user to authorize / restore.
                                        live_recovery_key.set(key.clone());
                                        passkey_status.set(String::new());
                                        recovery_key_status.set(
                                            "Recovery Key generated. Setting it up on the server — copy the words now; they are only displayed once.".to_owned()
                                        );
                                        upload_recovery_key_account_backup(
                                            base_url.clone(),
                                            token,
                                            account_did,
                                            device_id,
                                            state_store,
                                            key,
                                            recovery_key_status,
                                            None,
                                            None,
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

            // Backup history — devices-and-auth §4.1 + key-management.md §7.3
            //
            // Lists only backup creation times. Detailed envelope identifiers,
            // per-backup decrypt controls, and destructive delete controls stay
            // out of this user-facing panel.
            div { class: "event", "data-testid": "restore-section",
                div { class: "event-head",
                    span { "Backup history" }
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
            div { class: "event", "data-testid": "recovery-writeback-explainer",
                div { class: "event-head",
                    span { "What happens when recovery succeeds" }
                    span { "method-specific evidence" }
                    HelpTip { text: "A complete recovery session should make the new device generate its own key, bind proof to the active recovery_policy, record a recovery receipt, authorize the new device, and then unlock secret_storage / MLS history backups. This panel now keeps backup history visible while policy proof and device authorization remain separate follow-up strands." }
                }
            }
        }
    }
}
