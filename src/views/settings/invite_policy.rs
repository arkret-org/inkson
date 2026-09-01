//! U4 - "who can invite me" receive-policy settings (`/settings/invite-policy`).
//!
//! Edits the actor `invite_receive_policy` (spec `invite-addressing.md` §5,
//! authoritative `arkret_sdk::InviteReceivePolicy`):
//! - `holder_allowed_introduction_kinds` — which introduction-evidence kinds are accepted at all
//!   (consent_grant / locator_ref / shared_realm / same_station / explicit_address).
//! - `explicit_address_behavior` — drop / quarantine / notify for raw-address invites.
//! - `disclosure.high_trust` — whether contacts learn the invite outcome.
//! - `denied_actor_ids` — exact actors barred from inviting, with removal.
//!
//! YOU-01-006: the form edits a `arkret_sdk::InviteReceivePolicy` held whole in
//! a signal. On GET we keep the *entire* server policy (including the
//! `trusted_*` / `denied_source_ids` lists this form does not surface);
//! on SET we stamp the required schema constant and exact active account_id
//! and post the same object back, so server-stored lists survive the round-trip
//! and the body satisfies the soland handler (which deserialises the SDK type
//! with deny_unknown_fields and enforces account_id == session account).
//!
//! The soland self-plane endpoint (`/_arkret/self/invite-receive-policy`)
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

use arkret_wire::SchemaId;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use crate::i18n::tr;
use crate::models::{DisclosureLevel, DisclosurePolicy, InviteReceiveAction, InviteReceivePolicy};
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::switch::Switch;
use crate::views::helpers::short_protocol_id;

/// Introduction-evidence kinds offered in the UI, paired with the i18n key for
/// their natural-language label (looked up via the active locale).
const INTRODUCTION_KINDS: &[(&str, &str)] = &[
    ("consent_grant", "invite_policy.kind.consent_grant"),
    ("locator_ref", "invite_policy.kind.locator_ref"),
    ("shared_realm", "invite_policy.kind.shared_realm"),
    ("handle_claim", "invite_policy.kind.handle_claim"),
    ("same_station", "invite_policy.kind.same_station"),
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

fn discovery_trust_is_outcome(policy: &InviteReceivePolicy) -> bool {
    policy
        .disclosure
        .as_ref()
        .and_then(|d| d.discovery_trust.as_ref())
        .map(|level| matches!(level, DisclosureLevel::Outcome))
        .unwrap_or(false)
}

fn list_to_text(list: &[String]) -> String {
    list.join(", ")
}

fn parse_list(value: &str) -> Vec<String> {
    let mut list = Vec::new();
    for item in value
        .split([',', '\n', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let item = item.to_ascii_lowercase();
        if !list.iter().any(|existing| existing == &item) {
            list.push(item);
        }
    }
    list
}

fn constraints_lines(constraints: &arkret_wire::ReceivePolicyConstraints) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(kinds) = constraints.deployment_allowed_introduction_kinds.as_ref() {
        lines.push(format!("permitted: {}", kinds.join(", ")));
    }
    if !constraints.deployment_denied_introduction_kinds.is_empty() {
        lines.push(format!(
            "forbidden: {}",
            constraints.deployment_denied_introduction_kinds.join(", ")
        ));
    }
    if let Some(action) = constraints.handle_claim_max_behavior.as_ref() {
        lines.push(format!("handle cap: {}", explicit_behavior_to_str(action)));
    }
    if let Some(action) = constraints.explicit_address_max_behavior.as_ref() {
        lines.push(format!(
            "explicit cap: {}",
            explicit_behavior_to_str(action)
        ));
    }
    if let Some(domains) = constraints.allowed_handle_domains.as_ref() {
        lines.push(format!("handle domains: {}", domains.join(", ")));
    }
    if let Some(services) = constraints.trusted_directory_ids.as_ref() {
        lines.push(format!(
            "directory services: {}",
            services
                .iter()
                .map(|did| did.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines
}

#[component]
pub fn InvitePolicySettingsCard(token: Signal<String>) -> Element {
    let Some(account) = crate::app::SessionContext::get().active_account() else {
        return rsx! { div { class: "error", "No active account" } };
    };
    let account_id = account.authority;
    let subject_key = account_id.to_string();
    rsx! {
        InvitePolicySettingsCardBody {
            key: "{subject_key}",
            token,
            account_id,
        }
    }
}

#[component]
fn InvitePolicySettingsCardBody(
    token: Signal<String>,
    account_id: arkret_sdk::AccountId,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let active_account = crate::app::SessionContext::get().active_account;
    let base_url = use_signal(move || {
        active_account()
            .map(|account| account.server_url.to_string())
            .unwrap_or_default()
    });
    let initial_subject_id = account_id.clone();
    let mut policy = use_signal(move || InviteReceivePolicy::spec_default(initial_subject_id));
    let mut loaded = use_signal(|| false);
    let mut loading = use_signal(|| true);
    let mut status = use_signal(String::new);
    let mut saving = use_signal(|| false);
    let mut constraints = use_signal(|| None::<arkret_wire::ReceivePolicyConstraints>);

    // Hydrate from the server once. 404/501/405 → keep defaults (the endpoint
    // isn't wired on this deployment yet); any other error surfaces inline but
    // still lets the user edit + save against the real endpoint.
    {
        let load_account_id = account_id.clone();
        use_effect(move || {
            if loaded() {
                return;
            }
            loaded.set(true);
            let base = base_url();
            let api_token = token();
            let load_account_id = load_account_id.clone();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move {
                    let constraints = api
                        .describe()
                        .await
                        .ok()
                        .and_then(|description| description.receive_policy_constraints);
                    let policy = crate::transport::account::get_invite_receive_policy(
                        &api.sdk_http_client()?,
                        &load_account_id,
                    )
                    .await?;
                    Ok((policy, constraints))
                })
                .await
                {
                    Ok((server_policy, server_constraints)) => {
                        policy.set(server_policy);
                        constraints.set(server_constraints);
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
    let handle_behavior_selected = use_memo(move || {
        let action = policy
            .read()
            .handle_claim_behavior
            .clone()
            .unwrap_or(InviteReceiveAction::Quarantine);
        Some(explicit_behavior_to_str(&action).to_owned())
    });
    let high_trust_outcome = high_trust_is_outcome(&current);
    let discovery_trust_outcome = discovery_trust_is_outcome(&current);
    let allowed_handle_domains = list_to_text(&current.allowed_handle_domains);
    let denied_handle_domains = list_to_text(&current.denied_handle_domains);

    rsx! {
        div { class: "event", "data-testid": "invite-policy-panel",
            div { class: "event-head",
                span { {tr("invite_policy.title")} }
                if loading() { span { {tr("invite_policy.loading")} } }
            }
            div { class: "muted", {tr("invite_policy.intro")} }

            // ── holder_allowed_introduction_kinds ──────────────────────────────────────
            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", {tr("invite_policy.kinds_title")} }
                div { class: "settings-list",
                    for (kind, label_key) in INTRODUCTION_KINDS.iter().copied() {
                        {
                            let checked = current.holder_allowed_introduction_kinds.iter().any(|k| k == kind);
                            rsx! {
                                label { class: "metric invite-policy-kind-row",
                                    Checkbox {
                                        "data-testid": "invite-policy-kind-{kind}",
                                        checked: if checked { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |state: CheckboxState| {
                                            let enabled = bool::from(state);
                                            let mut next = policy.read().clone();
                                            next.holder_allowed_introduction_kinds.retain(|k| k != kind);
                                            if enabled {
                                                next.holder_allowed_introduction_kinds.push(kind.to_owned());
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
                Label { html_for: "invite-policy-handle-behavior", {tr("invite_policy.handle_label")} }
                Select::<String> {
                    id: "invite-policy-handle-behavior",
                    "data-testid": "invite-policy-handle-behavior",
                    value: Some(handle_behavior_selected.into()),
                    on_value_change: move |v: Option<String>| {
                        if let Some(action) = v.as_deref().and_then(explicit_behavior_from_str) {
                            let mut next = policy.read().clone();
                            next.handle_claim_behavior = Some(action);
                            policy.set(next);
                        }
                    },
                    SelectOption::<String> { index: 0usize, value: "drop".to_string(), text_value: "drop", {tr("invite_policy.explicit.drop")} }
                    SelectOption::<String> { index: 1usize, value: "quarantine".to_string(), text_value: "quarantine", {tr("invite_policy.explicit.quarantine")} }
                    SelectOption::<String> { index: 2usize, value: "notify".to_string(), text_value: "notify", {tr("invite_policy.explicit.notify")} }
                }
                div { class: "settings-grid compact",
                    label { class: "field",
                        span { {tr("invite_policy.handle_allowed_domains")} }
                        input {
                            "data-testid": "invite-policy-handle-allowed-domains",
                            value: "{allowed_handle_domains}",
                            placeholder: "example.com, team.example",
                            oninput: move |event: FormEvent| {
                                let mut next = policy.read().clone();
                                next.allowed_handle_domains = parse_list(&event.value());
                                policy.set(next);
                            },
                        }
                    }
                    label { class: "field",
                        span { {tr("invite_policy.handle_blocked_domains")} }
                        input {
                            "data-testid": "invite-policy-handle-blocked-domains",
                            value: "{denied_handle_domains}",
                            placeholder: "spam.example",
                            oninput: move |event: FormEvent| {
                                let mut next = policy.read().clone();
                                next.denied_handle_domains = parse_list(&event.value());
                                policy.set(next);
                            },
                        }
                    }
                }
                div { class: "muted", {tr("invite_policy.handle_hint")} }
            }

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
                            let mut disclosure = next.disclosure.unwrap_or(DisclosurePolicy {
                                high_trust: None,
                                discovery_trust: None,
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
                label { class: "metric",
                    Switch {
                        "data-testid": "invite-policy-disclosure-discovery-trust",
                        checked: discovery_trust_outcome,
                        on_checked_change: move |checked: bool| {
                            let mut next = policy.read().clone();
                            let mut disclosure = next.disclosure.unwrap_or(DisclosurePolicy {
                                high_trust: None,
                                discovery_trust: None,
                                low_trust: None,
                            });
                            disclosure.discovery_trust = Some(if checked {
                                DisclosureLevel::Outcome
                            } else {
                                DisclosureLevel::Opaque
                            });
                            next.disclosure = Some(disclosure);
                            policy.set(next);
                        },
                    }
                    span { " {tr(\"invite_policy.discovery_disclosure_toggle\")}" }
                }
                div { class: "muted", {tr("invite_policy.disclosure_hint")} }
            }

            // ── denied_actor_ids ───────────────────────────────────────────
            if let Some(server_constraints) = constraints.read().as_ref() {
                div { class: "settings-subsection", "data-testid": "invite-policy-caps",
                    strong { class: "settings-subsection-title", {tr("invite_policy.server_caps_title")} }
                    {
                        let lines = constraints_lines(server_constraints);
                        rsx! {
                            if lines.is_empty() {
                                div { class: "muted", {tr("invite_policy.server_caps_empty")} }
                            } else {
                                div { class: "settings-list",
                                    for line in lines {
                                        div { class: "muted mono", "{line}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div { class: "settings-subsection",
                strong { class: "settings-subsection-title", {tr("invite_policy.blocked_title")} }
                if current.denied_actor_ids.is_empty() {
                    div { class: "muted", "data-testid": "invite-policy-blocked-empty", {tr("invite_policy.blocked_empty")} }
                } else {
                    div { class: "settings-list",
                        for (subject, subject_actor) in current.denied_actor_ids.iter().filter_map(|actor| {
                            serde_json::to_string(actor).ok().map(|encoded| (encoded, actor.clone()))
                        }) {
                            div {
                                class: "metric invite-policy-blocked-row",
                                "data-testid": "invite-policy-blocked-row",
                                "data-subject": "{subject}",
                                span { class: "mono", title: "{subject}", "{short_protocol_id(&subject)}" }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "invite-policy-unblock-{subject}",
                                    onclick: {
                                        move |_| {
                                            let mut next = policy.read().clone();
                                            next.denied_actor_ids.retain(|actor| actor != &subject_actor);
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
                        // Stamp the spec-required schema and exact account before
                        // SET; the SDK type carries the server's `trusted_*`
                        // lists from the GET hydrate, so they round-trip intact.
                        let mut to_save = policy.read().clone();
                        to_save.schema = SchemaId::INVITE_RECEIVE_POLICY_V1.to_owned();
                        to_save.account_id = account_id.clone();
                        saving.set(true);
                        status.set(tr("invite_policy.saving"));
                        spawn(async move {
                            match with_authed_sdk_client(&base, api_token, |http| async move {
                                crate::transport::account::set_invite_receive_policy(&http, &to_save).await
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
