//! G3.Y3 — Personal blocklist settings page (`/settings/blocked-users`).
//!
//! Actor-private list of blocked DIDs. Spec
//! `governance/content-moderation.md` §4 — personal blocklist is a
//! client-side filter; spec `discovery/client-preferences.md` §2
//! defines the `ck.account.blocklist` account_data shape.
//!
//! Surfaces:
//! - `blocked-users-panel` wrapper
//! - `blocked-users-list` list wrapper
//! - `blocked-user-row[data-actor-did, data-blocked-at]` per entry
//! - `block-target-input`, `block-user-button`, `unblock-button`
//! - `write-status`
//!
//! The `block-actor-button` testid exposed elsewhere (directory rows,
//! space member rows) is owned by the respective view modules — this
//! file only owns the settings surface.

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use crate::components::{EmptyState, EmptyStateKind};
use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::views::helpers::short_protocol_id;

/// `reason_code` options offered for a personal block. Mirrors the report
/// reason enum in `governance/content-moderation.md` §3.2 (`spam`,
/// `harassment`, `hate_speech`, `nsfw`, `illegal`, `misinformation`, `other`).
const BLOCK_REASON_CODES: &[&str] = &[
    "spam",
    "harassment",
    "hate_speech",
    "nsfw",
    "illegal",
    "misinformation",
    "other",
];

/// Human label for a `target.kind` value.
fn target_kind_label(kind: &str) -> &'static str {
    match kind {
        "service" => "Principal server / service",
        "domain" => "Domain",
        "organization" => "Organization",
        _ => "Actor (user / agent)",
    }
}

/// Placeholder hint for the identifier input, by target kind. Actor uses the
/// v1-core default principal method `did:webvh`, not `did:web`.
fn target_kind_placeholder(kind: &str) -> &'static str {
    match kind {
        "service" => "did:web:server.acme.example",
        "domain" => "example.com",
        "organization" => "did:web:acme.example",
        _ => "did:webvh:<scid>:alice.example",
    }
}

/// Resolve a UI expiry choice to an absolute RFC 3339 timestamp. `never`
/// (and any unknown value) maps to `None` — a permanent block.
fn expiry_choice_to_rfc3339(choice: &str) -> Option<String> {
    let duration = match choice {
        "1d" => chrono::Duration::days(1),
        "7d" => chrono::Duration::days(7),
        "30d" => chrono::Duration::days(30),
        _ => return None,
    };
    Some((chrono::Utc::now() + duration).to_rfc3339())
}

#[component]
pub fn BlocklistSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let _ = account_did;

    let initial = state_store.read().client_blocklist();
    let mut entries = use_signal(|| initial);
    let mut target_kind = use_signal(|| "actor".to_owned());
    let kind_selected = use_memo(move || Some(target_kind()));
    let mut add_input = use_signal(String::new);
    let mut reason_code = use_signal(String::new);
    let reason_selected = use_memo(move || Some(reason_code()));
    let mut expiry_choice = use_signal(|| "never".to_owned());
    let expiry_selected = use_memo(move || Some(expiry_choice()));
    let mut applies_to = use_signal(|| {
        crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO
            .iter()
            .map(|surface| (*surface).to_owned())
            .collect::<Vec<String>>()
    });
    let mut status = use_signal(String::new);

    // Live validation: the identifier must parse as a DID for DID-shaped kinds
    // (actor / service / organization) or as a domain for `domain`. At least
    // one surface must be selected.
    let kind_now = target_kind();
    let is_did_kind = crate::account_data::blocklist_kind_is_did(&kind_now);
    let raw_input = add_input();
    let input_trimmed = raw_input.trim();
    let input_empty = input_trimmed.is_empty();
    let input_valid = !input_empty
        && if is_did_kind {
            crate::views::settings::is_likely_valid_did(input_trimmed)
        } else {
            crate::views::settings::is_likely_valid_domain(input_trimmed)
        };
    let applies_empty = applies_to.read().is_empty();
    let can_block = input_valid && !applies_empty;
    let input_class = if input_empty {
        "blocklist-did"
    } else if input_valid {
        "blocklist-did blocklist-did-valid"
    } else {
        "blocklist-did blocklist-did-invalid"
    };
    let invalid_hint = if is_did_kind {
        "Enter a valid DID (e.g. did:webvh:<scid>:alice.example)."
    } else {
        "Enter a valid domain (e.g. example.com)."
    };
    let target_input_label = if is_did_kind {
        "Target DID"
    } else {
        "Target domain"
    };

    rsx! {
        div { class: "event", "data-testid": "blocked-users-panel",
            div { class: "event-head",
                span { "Personal blocklist" }
            }
            div { class: "muted",
                "Blocked targets are hidden from your messages and notifications on your devices. "
                "Blocks are a local filter — they are not broadcast and do not change what other members see."
            }

            div { class: "settings-list", "data-testid": "blocked-users-list",
                if entries.read().is_empty() {
                    EmptyState {
                        title: "Blocklist empty".to_owned(),
                        kind: EmptyStateKind::Empty,
                        message: Some("You haven't blocked anything yet.".to_owned()),
                        test_id: None,
                    }
                } else {
                    for entry in entries.read().iter().cloned() {
                        {
                            let blocked_at = entry.blocked_at.clone().unwrap_or_default();
                            let kind = entry.kind.clone();
                            let kind_label = target_kind_label(&kind);
                            let applies_summary = if entry.applies_to.is_empty() {
                                "all surfaces".to_owned()
                            } else {
                                entry.applies_to.join(", ")
                            };
                            let expires_at = entry.expires_at.clone();
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "blocked-user-row",
                                    "data-actor-did": "{entry.did}",
                                    "data-target-kind": "{kind}",
                                    "data-blocked-at": "{blocked_at}",
                                    div { class: "event-head",
                                        span { class: "badge", "{kind_label}" }
                                        span { class: "mono", title: "{entry.did}", "{entry.did}" }
                                        if !blocked_at.is_empty() {
                                            span { class: "muted", "{blocked_at}" }
                                        }
                                    }
                                    div { class: "muted", "Applies to: {applies_summary}" }
                                    if let Some(expires) = &expires_at {
                                        div { class: "muted", "Expires: {expires}" }
                                    }
                                    if let Some(reason) = &entry.reason {
                                        div { class: "muted", "Reason: {reason}" }
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "unblock-button",
                                            "data-actor-did": "{entry.did}",
                                            onclick: {
                                                let target_value = entry.did.clone();
                                                let target_kind = entry.kind.clone();
                                                let base = base_url;
                                                move |_| {
                                                    let changed = state_store
                                                        .write()
                                                        .unblock_target(&target_kind, &target_value);
                                                    let next = state_store.read().client_blocklist();
                                                    entries.set(next.clone());
                                                    if changed {
                                                        status.set(format!(
                                                            "Unblocked {}",
                                                            short_protocol_id(&target_value)
                                                        ));
                                                        crate::views::settings::push_blocklist_account_data(
                                                            base(),
                                                            token(),
                                                            next,
                                                        );
                                                    }
                                                }
                                            },
                                            "Unblock"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div { class: "event",
                div { class: "field",
                    Label { html_for: "block-target-kind", "Target type" }
                    Select::<String> {
                        "data-testid": "block-target-kind",
                        value: Some(kind_selected.into()),
                        on_value_change: move |v: Option<String>| {
                            if let Some(v) = v {
                                target_kind.set(v);
                            }
                        },
                        SelectOption::<String> { index: 0usize, value: "actor".to_string(), text_value: "Actor", {target_kind_label("actor")} }
                        SelectOption::<String> { index: 1usize, value: "service".to_string(), text_value: "Service", {target_kind_label("service")} }
                        SelectOption::<String> { index: 2usize, value: "domain".to_string(), text_value: "Domain", {target_kind_label("domain")} }
                        SelectOption::<String> { index: 3usize, value: "organization".to_string(), text_value: "Organization", {target_kind_label("organization")} }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-target-input-input", "{target_input_label}" }
                    Input {
                        id: "block-target-input-input",
                        class: "{input_class}",
                        "data-testid": "block-target-input",
                        value: "{add_input}",
                        placeholder: target_kind_placeholder(&kind_now),
                        "aria-invalid": if !input_empty && !input_valid { "true" } else { "false" },
                        oninput: move |event: FormEvent| add_input.set(event.value()),
                    }
                    if !input_empty && !input_valid {
                        div {
                            class: "settings-inline-hint settings-inline-hint-invalid",
                            "data-testid": "block-target-invalid",
                            "{invalid_hint}"
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-applies-to", "Applies to" }
                    div { class: "blocklist-applies-grid", "data-testid": "block-applies-to",
                        for surface in crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO.iter().copied() {
                            label { class: "metric",
                                Checkbox {
                                    "data-testid": "block-applies-{surface}",
                                    checked: if applies_to.read().iter().any(|s| s == surface) {
                                        CheckboxState::Checked
                                    } else {
                                        CheckboxState::Unchecked
                                    },
                                    on_checked_change: move |state: CheckboxState| {
                                        let mut next = applies_to();
                                        if bool::from(state) {
                                            if !next.iter().any(|s| s == surface) {
                                                next.push(surface.to_owned());
                                            }
                                        } else {
                                            next.retain(|s| s != surface);
                                        }
                                        applies_to.set(next);
                                    },
                                }
                                span { "{surface}" }
                            }
                        }
                    }
                    if applies_empty {
                        div {
                            class: "settings-inline-hint settings-inline-hint-invalid",
                            "data-testid": "block-applies-empty",
                            "Select at least one surface to block."
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-reason", "Reason (optional)" }
                    Select::<String> {
                        "data-testid": "block-reason",
                        value: Some(reason_selected.into()),
                        on_value_change: move |v: Option<String>| {
                            reason_code.set(v.unwrap_or_default());
                        },
                        SelectOption::<String> { index: 0usize, value: String::new(), text_value: "No reason", "No reason" }
                        for (idx , code) in BLOCK_REASON_CODES.iter().copied().enumerate() {
                            SelectOption::<String> {
                                index: idx + 1,
                                value: code.to_string(),
                                text_value: "{code}",
                                "{code}"
                            }
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-expiry", "Expires" }
                    Select::<String> {
                        "data-testid": "block-expiry",
                        value: Some(expiry_selected.into()),
                        on_value_change: move |v: Option<String>| {
                            if let Some(v) = v {
                                expiry_choice.set(v);
                            }
                        },
                        SelectOption::<String> { index: 0usize, value: "never".to_string(), text_value: "Never", "Never (permanent)" }
                        SelectOption::<String> { index: 1usize, value: "1d".to_string(), text_value: "24 hours", "24 hours" }
                        SelectOption::<String> { index: 2usize, value: "7d".to_string(), text_value: "7 days", "7 days" }
                        SelectOption::<String> { index: 3usize, value: "30d".to_string(), text_value: "30 days", "30 days" }
                    }
                }

                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "block-user-button",
                        disabled: !can_block,
                        onclick: {
                            let base = base_url;
                            move |_| {
                                let kind = target_kind();
                                let target = add_input().trim().to_owned();
                                if target.is_empty() || applies_to.read().is_empty() {
                                    return;
                                }
                                let reason = {
                                    let code = reason_code();
                                    let code = code.trim().to_owned();
                                    if code.is_empty() { None } else { Some(code) }
                                };
                                let applies = applies_to();
                                let expires = expiry_choice_to_rfc3339(&expiry_choice());
                                let changed = state_store
                                    .write()
                                    .block_target(&kind, &target, reason, applies, expires);
                                let next = state_store.read().client_blocklist();
                                entries.set(next.clone());
                                if changed {
                                    status.set(format!(
                                        "blocklist updated; added {}",
                                        short_protocol_id(&target)
                                    ));
                                    add_input.set(String::new());
                                    crate::views::settings::push_blocklist_account_data(
                                        base(),
                                        token(),
                                        next,
                                    );
                                } else {
                                    status.set(format!(
                                        "{} is already blocked",
                                        short_protocol_id(&target)
                                    ));
                                }
                            }
                        },
                        "Block target"
                    }
                }
                if !status.read().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "write-status",
                        "{status}"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_uses_client_blocklist_state_store_methods() {
        let mut store = LocalStateStore::default();
        assert!(store.client_blocklist().is_empty());

        assert!(store.block_user("did:web:bob.example", None));
        assert!(!store.block_user("did:web:bob.example", None));

        let entries = store.client_blocklist();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].did, "did:web:bob.example");
        assert!(entries[0].blocked_at.is_some());

        assert!(store.unblock_user("did:web:bob.example"));
        assert!(!store.unblock_user("did:web:bob.example"));
        assert!(store.client_blocklist().is_empty());
    }
}
