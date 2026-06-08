//! U4 — "谁可以邀请我" 接收策略设置 (`/settings/invite-policy`).
//!
//! Edits the actor `invite_receive_policy` (spec `invite_receive_policy`):
//! - `allowed_introduction_kinds` — which introduction-evidence kinds are
//!   accepted at all (consent_grant / locator_ref / shared_realm /
//!   same_principal_server / explicit_address).
//! - `explicit_address_behavior` — drop / quarantine / notify for raw-address
//!   invites.
//! - `disclosure.high_trust` — whether contacts learn the invite outcome.
//! - `blocked_subjects` — list of subjects barred from inviting, with removal.
//!
//! The soland self-plane endpoint (`/_cokret/self/invite-receive-policy`) is
//! still being wired; the panel connects to the real endpoint and degrades
//! gracefully — on a 404/501/405 GET it seeds the form with defaults, and a
//! failed save is surfaced inline without losing the user's edits.
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
use crate::models::InviteReceivePolicy;
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
    ("same_principal_server", "invite_policy.kind.same_principal_server"),
    ("explicit_address", "invite_policy.kind.explicit_address"),
];

#[component]
pub fn InvitePolicySettingsCard(
    base_url: Signal<String>,
    token: Signal<String>,
) -> Element {
    let mut policy = use_signal(InviteReceivePolicy::default);
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
                    Ok(outcome) => {
                        policy.set(outcome.policy);
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
    let explicit_behavior_selected = use_memo(move || Some(policy.read().explicit_address_behavior.clone()));
    let high_trust_outcome = current.disclosure.high_trust == "outcome";

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
                        if let Some(v) = v {
                            let mut next = policy.read().clone();
                            next.explicit_address_behavior = v;
                            policy.set(next);
                        }
                    },
                    SelectOption::<String> { index: 0usize, value: "drop".to_string(), text_value: "drop", {tr("invite_policy.explicit.drop")} }
                    SelectOption::<String> { index: 1usize, value: "quarantine".to_string(), text_value: "quarantine", {tr("invite_policy.explicit.quarantine")} }
                    SelectOption::<String> { index: 2usize, value: "notify".to_string(), text_value: "notify", {tr("invite_policy.explicit.notify")} }
                }
                div { class: "muted",
                    {tr("invite_policy.unknown_prefix")}
                    if current.unknown_invites == "drop" { {tr("invite_policy.unknown_drop")} } else { {tr("invite_policy.unknown_quarantine")} }
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
                            next.disclosure.high_trust = if checked { "outcome".to_owned() } else { "opaque".to_owned() };
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
                        for subject in current.blocked_subjects.iter().cloned() {
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
                                            next.blocked_subjects.retain(|s| s != &subject);
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
                        let to_save = policy.read().clone();
                        saving.set(true);
                        status.set(tr("invite_policy.saving"));
                        spawn(async move {
                            match with_authed_api(&base, api_token, |api| async move {
                                api.set_invite_receive_policy(&to_save).await
                            })
                            .await
                            {
                                Ok(outcome) => {
                                    policy.set(outcome.policy);
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
