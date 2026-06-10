//! U4 — "谁可以邀请我" 接收策略设置 (`/settings/invite-policy`).
//!
//! Edits the actor `invite_receive_policy` (spec `invite-addressing.md` §5,
//! authoritative `cokret_sdk::InviteReceivePolicy`):
//! - `allowed_introduction_kinds` — which introduction-evidence kinds are accepted at all
//!   (consent_grant / locator_ref / shared_realm / same_principal_server / explicit_address).
//! - `explicit_address_behavior` — drop / quarantine / notify for raw-address invites.
//! - `disclosure.high_trust` — whether contacts learn the invite outcome.
//! - `blocked_subjects` — list of subjects barred from inviting, with removal.
//!
//! YOU-01-006: the form edits a `cokret_sdk::InviteReceivePolicy` held whole in
//! a signal. On GET we keep the *entire* server policy (including the
//! `trusted_*` / `blocked_principal_services` lists this form does not surface);
//! on SET we stamp the required `schema` constant and `subject_id = account_did`
//! and post the same object back, so server-stored lists survive the round-trip
//! and the body satisfies the soland handler (which deserialises the SDK type
//! with `deny_unknown_fields` and enforces `subject_id == session actor`).
//!
//! The soland self-plane endpoint (`/_cokret/self/invite-receive-policy`)
//! degrades gracefully — on a 404/501/405 GET it seeds the form with defaults,
//! and a failed save is surfaced inline without losing the user's edits.
//!
//! Surfaces (testids for cotest):
//! - `invite-policy-panel`
//! - `invite-policy-kind-{kind}` (checkboxes)
//! - `invite-policy-explicit-behavior` (select)
//! - `invite-policy-disclosure-high-trust` (switch)
//! - `invite-policy-blocked-row[data-subject]`, `invite-policy-unblock-{subject}`
//! - `invite-policy-save-button`, `invite-policy-status`

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use crate::i18n::tr;
use crate::models::{
    DisclosureLevel, INVITE_RECEIVE_POLICY_SCHEMA, InviteDisclosurePolicy, InviteReceiveAction,
    InviteReceivePolicy, default_invite_receive_policy,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::switch::Switch;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Introduction-evidence kinds offered in the UI, paired with the i18n key for
/// their natural-language label (looked up via the active locale).
const INTRODUCTION_KINDS: &[(&str, &str)] = &[
    ("consent_grant", "invite_policy.kind.consent_grant"),
    ("locator_ref", "invite_policy.kind.locator_ref"),
    ("shared_realm", "invite_policy.kind.shared_realm"),
    (
        "same_principal_server",
        "invite_policy.kind.same_principal_server",
    ),
    ("explicit_address", "invite_policy.kind.explicit_address"),
];

/// Map the `explicit_address_behavior` enum to/from the Select's string value.
fn explicit_behavior_to_str(action: &InviteReceiveAction) -> &'static str {
    match action {
        InviteReceiveAction::Drop => "drop",
        InviteReceiveAction::Quarantine => "quarantine",
        InviteReceiveAction::Notify => "notify",
    }
}

fn explicit_behavior_from_str(value: &str) -> Option<InviteReceiveAction> {
    match value {
        "drop" => Some(InviteReceiveAction::Drop),
        "quarantine" => Some(InviteReceiveAction::Quarantine),
        "notify" => Some(InviteReceiveAction::Notify),
        _ => None,
    }
}

/// Whether the high-trust disclosure tier is set to `outcome` (let contacts
/// learn the invite result). Absent disclosure / absent tier defaults to the
/// recommended `outcome`.
fn high_trust_is_outcome(policy: &InviteReceivePolicy) -> bool {
    policy
        .disclosure
        .as_ref()
        .and_then(|d| d.high_trust.as_ref())
        .map(|level| matches!(level, DisclosureLevel::Outcome))
        .unwrap_or(true)
}

#[component]
pub fn InvitePolicySettingsCard(
    base_url: Signal<String>,
    token: Signal<String>,
    account_did: Signal<String>,
) -> Element {
    let mut policy = use_signal(|| default_invite_receive_policy(&account_did()));
    let mut loaded = use_signal(|| false);
    let mut loading = use_signal(|| true);
    let mut status = use_signal(String::new);
    let mut saving = use_signal(|| false);

    // Hydrate from the server once. 404/501/405 → keep defaults (the endpoint
    // isn't wired on this deployment yet); any other error surfaces inline but
    // still lets the user edit + save against the real endpoint.
    {
        use_effect(move || {
            if loaded() {
                return;
            }
            loaded.set(true);
            let base = base_url();
            let api_token = token();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move {
                    api.get_invite_receive_policy().await
                })
                .await
                {
                    Ok(server_policy) => {
                        policy.set(server_policy);
                    }
                    Err(err) => {
                        // Graceful-degrade message; defaults stay in the form.
                        status.set(
                            tr("invite_policy.load_failed").replace("{error}", &err.display()),
                        );
                    }
                }
                loading.set(false);
            });
        });
    }

    let current = policy.read().clone();
    let explicit_behavior_selected = use_memo(move || {
        Some(explicit_behavior_to_str(&policy.read().explicit_address_behavior).to_owned())
    });
    let high_trust_outcome = high_trust_is_outcome(&current);

    rsx! {
        div { class: "event", "data-testid": "invite-policy-panel",
            div { class: "event-head",
                span { {tr("invite_policy.title")} }
                if loading() { span { {tr("invite_policy.loading")} } }
            }
            div { class: "muted", {tr("invite_policy.intro")} }

            // ── allowed_introduction_kinds ───────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", {tr("invite_policy.kinds_title")} }
                div { class: "settings-list",
                    for (kind, label_key) in INTRODUCTION_KINDS.iter().copied() {
                        {
                            let checked = current.allowed_introduction_kinds.iter().any(|k| k == kind);
                            rsx! {
                                label { class: "metric invite-policy-kind-row",
                                    Checkbox {
                                        "data-testid": "invite-policy-kind-{kind}",
                                        checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |state: CheckboxState| {
                                            let enabled = bool::from(state);
                                            let mut next = policy.read().clone();
                                            next.allowed_introduction_kinds.retain(|k| k != kind);
                                            if enabled {
                                                next.allowed_introduction_kinds.push(kind.to_owned());
                                            }
                                            policy.set(next);
                                        },
                                    }
                                    span { " {tr(label_key)}" }
                                }
                            }
                        }
                    }
                }
            }

            // ── explicit_address_behavior ────────────────────────────────
            div { class: "settings-subsection",
                Label { html_for: "invite-policy-explicit-behavior", {tr("invite_policy.explicit_label")} }
                Select::<String> {
                    id: "invite-policy-explicit-behavior",
                    "data-testid": "invite-policy-explicit-behavior",
                    value: Some(explicit_behavior_selected.into()),
                    on_value_change: move |v: Option<String>| {
                        if let Some(action) = v.as_deref().and_then(explicit_behavior_from_str) {
                            let mut next = policy.read().clone();
                            next.explicit_address_behavior = action;
                            policy.set(next);
                        }
                    },
                    SelectOption::<String> { index: 0usize, value: "drop".to_string(), text_value: "drop", {tr("invite_policy.explicit.drop")} }
                    SelectOption::<String> { index: 1usize, value: "quarantine".to_string(), text_value: "quarantine", {tr("invite_policy.explicit.quarantine")} }
                    SelectOption::<String> { index: 2usize, value: "notify".to_string(), text_value: "notify", {tr("invite_policy.explicit.notify")} }
                }
                div { class: "muted",
                    {tr("invite_policy.unknown_prefix")}
                    if matches!(current.unknown_invites, crate::models::UnknownInviteAction::Drop) { {tr("invite_policy.unknown_drop")} } else { {tr("invite_policy.unknown_quarantine")} }
                    {tr("invite_policy.unknown_suffix")}
                }
            }

            // ── disclosure ───────────────────────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", {tr("invite_policy.disclosure_title")} }
                label { class: "metric",
                    Switch {
                        "data-testid": "invite-policy-disclosure-high-trust",
                        checked: high_trust_outcome,
                        on_checked_change: move |checked: bool| {
                            let mut next = policy.read().clone();
                            let mut disclosure = next.disclosure.unwrap_or(InviteDisclosurePolicy {
                                high_trust: None,
                                low_trust: None,
                            });
                            disclosure.high_trust = Some(if checked {
                                DisclosureLevel::Outcome
                            } else {
                                DisclosureLevel::Opaque
                            });
                            next.disclosure = Some(disclosure);
                            policy.set(next);
                        },
                    }
                    span { " {tr(\"invite_policy.disclosure_toggle\")}" }
                }
                div { class: "muted", {tr("invite_policy.disclosure_hint")} }
            }

            // ── blocked_subjects ─────────────────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", {tr("invite_policy.blocked_title")} }
                if current.blocked_subjects.is_empty() {
                    div { class: "muted", "data-testid": "invite-policy-blocked-empty", {tr("invite_policy.blocked_empty")} }
                } else {
                    div { class: "settings-list",
                        for subject in current.blocked_subjects.iter().map(|d| d.as_str().to_owned()) {
                            div {
                                class: "metric invite-policy-blocked-row",
                                "data-testid": "invite-policy-blocked-row",
                                "data-subject": "{subject}",
                                span { class: "mono", title: "{subject}", "{short_protocol_id(&subject)}" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "invite-policy-unblock-{subject}",
                                    onclick: {
                                        let subject = subject.clone();
                                        move |_| {
                                            let mut next = policy.read().clone();
                                            next.blocked_subjects.retain(|s| s.as_str() != subject);
                                            policy.set(next);
                                            status.set(tr("invite_policy.unblocked_hint"));
                                        }
                                    },
                                    {tr("invite_policy.unblock")}
                                }
                            }
                        }
                    }
                }
            }

            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "invite-policy-save-button",
                    disabled: saving(),
                    onclick: move |_| {
                        let base = base_url();
                        let api_token = token();
                        let subject = account_did();
                        // Stamp the spec-required `schema` + `subject_id` before
                        // SET; the SDK type carries the server's `trusted_*`
                        // lists from the GET hydrate, so they round-trip intact.
                        let mut to_save = policy.read().clone();
                        to_save.schema = INVITE_RECEIVE_POLICY_SCHEMA.to_owned();
                        match cokret_sdk::Did::new(subject.clone()) {
                            Ok(did) => to_save.subject_id = did,
                            Err(_) => {
                                status.set(
                                    tr("invite_policy.save_failed")
                                        .replace("{error}", "missing or invalid account DID"),
                                );
                                return;
                            }
                        }
                        saving.set(true);
                        status.set(tr("invite_policy.saving"));
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.set_invite_receive_policy(&to_save).await
                            })
                            .await
                            {
                                Ok(server_policy) => {
                                    policy.set(server_policy);
                                    status.set(tr("invite_policy.saved"));
                                }
                                Err(err) => status.set(
                                    tr("invite_policy.save_failed").replace("{error}", &err.display()),
                                ),
                            }
                            saving.set(false);
                        });
                    },
                    if saving() { {tr("invite_policy.save_busy")} } else { {tr("invite_policy.save")} }
                }
            }

            if !status.read().is_empty() {
                div { class: "muted", "data-testid": "invite-policy-status", "{status}" }
            }
        }
    }
}
