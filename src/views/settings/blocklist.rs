//! G3.Y3 — Personal blocklist settings page (`/settings/blocked-users`).
//!
//! Actor-private list of blocked stable identity ids. Spec
//! `governance/content-moderation.md` §4 — personal blocklist is a
//! client-side filter; spec `discovery/client-preferences.md` §2
//! defines the `ak.account.blocklist` account_data shape.
//!
//! Surfaces:
//! - `blocked-users-panel` wrapper
//! - `blocked-users-list` list wrapper
//! - `blocked-user-row[data-actor-id, data-blocked-at]` per entry
//! - `block-target-input`, `block-user-button`, `unblock-button`
//! - `write-status`
//!
//! The `block-actor-button` testid exposed elsewhere (directory rows,
//! space member rows) is owned by the respective view modules — this
//! file only owns the settings surface.

use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;

use crate::components::{EmptyState, EmptyStateKind};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::views::helpers::{actor_display_label, short_protocol_id};

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
fn target_kind_label(kind: crate::account_data::BlocklistUiTargetKind) -> &'static str {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Service => "Station / service",
        crate::account_data::BlocklistUiTargetKind::Domain => "Domain",
        crate::account_data::BlocklistUiTargetKind::Organization => "Organization",
        crate::account_data::BlocklistUiTargetKind::Actor => "Actor (user / agent)",
    }
}

/// Placeholder hint for the stable identifier input, by target kind.
fn target_kind_placeholder(kind: crate::account_data::BlocklistUiTargetKind) -> &'static str {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Service => {
            "ak:did_core:web:server.acme.example"
        }
        crate::account_data::BlocklistUiTargetKind::Domain => "example.com",
        crate::account_data::BlocklistUiTargetKind::Organization => "ak:did_core:web:acme.example",
        crate::account_data::BlocklistUiTargetKind::Actor => {
            "ak:did_core:webvh:<scid>:alice.example"
        }
    }
}

/// Resolve a UI expiry choice to an absolute RFC 3339 timestamp. `never`
/// (and any unknown value) maps to `None` — a permanent block.
fn expiry_choice_to_rfc3339(choice: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    let duration = match choice {
        "1d" => chrono::Duration::days(1),
        "7d" => chrono::Duration::days(7),
        "30d" => chrono::Duration::days(30),
        _ => return None,
    };
    Some(chrono::Utc::now() + duration)
}

fn is_valid_identity_id(input: &str) -> bool {
    arkret_sdk::DidCoreId::new(input.trim().to_owned()).is_ok()
}

#[component]
pub fn BlocklistSettingsCard(principal_id: Signal<String>, token: Signal<String>) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let active_account = crate::app::SessionContext::get().active_account;
    let base_url = use_signal(move || {
        active_account()
            .map(|account| account.server_url.to_string())
            .unwrap_or_default()
    });
    let mut state_store = crate::app::SessionContext::get().state_store;

    let initial = state_store.read().client_blocklist();
    let mut entries = use_signal(|| initial);
    let mut target_kind = use_signal(|| crate::account_data::BlocklistUiTargetKind::Actor);
    let kind_selected = use_memo(move || Some(target_kind().ui_value().to_owned()));
    let mut add_input = use_signal(String::new);
    let mut reason_code = use_signal(String::new);
    let reason_selected = use_memo(move || Some(reason_code()));
    let mut expiry_choice = use_signal(|| "never".to_owned());
    let expiry_selected = use_memo(move || Some(expiry_choice()));
    let mut applies_to = use_signal(|| crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO.to_vec());
    let mut status = use_signal(String::new);

    // Live validation: identity kinds (actor / service / organization) require
    // a stable DidCoreId; `domain` requires a domain. At least one surface must
    // be selected.
    let kind_now = target_kind();
    let is_identity_kind = kind_now.is_identity();
    let raw_input = add_input();
    let input_trimmed = raw_input.trim();
    let input_empty = input_trimmed.is_empty();
    let input_valid = !input_empty
        && if is_identity_kind {
            is_valid_identity_id(input_trimmed)
        } else {
            crate::views::settings::is_likely_valid_domain(input_trimmed)
        };
    let applies_empty = applies_to.read().is_empty();
    let has_session = !token().trim().is_empty();
    let can_block = input_valid && !applies_empty && has_session;
    let input_class = if input_empty {
        "blocklist-id"
    } else if input_valid {
        "blocklist-id blocklist-id-valid"
    } else {
        "blocklist-id blocklist-id-invalid"
    };
    let invalid_hint = if is_identity_kind {
        "Enter a valid stable identity id (e.g. ak:did_core:webvh:<scid>)."
    } else {
        "Enter a valid domain (e.g. example.com)."
    };
    let target_input_label = if is_identity_kind {
        "Target stable id"
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
                            let blocked_at = entry.created_at;
                            let kind = crate::account_data::blocklist_target_kind_label(&entry.target);
                            let kind_label = match kind {
                                "service" => target_kind_label(crate::account_data::BlocklistUiTargetKind::Service),
                                "domain" => target_kind_label(crate::account_data::BlocklistUiTargetKind::Domain),
                                "organization" => target_kind_label(crate::account_data::BlocklistUiTargetKind::Organization),
                                _ => target_kind_label(crate::account_data::BlocklistUiTargetKind::Actor),
                            };
                            let entry_value = crate::account_data::blocklist_target_value(&entry.target);
                            let entry_label = if crate::account_data::target_is_actor(&entry.target) {
                                actor_display_label(&state_store.read(), entry_value)
                            } else {
                                short_protocol_id(entry_value)
                            };
                            let applies_summary = entry.applies_to.iter()
                                .map(|surface| crate::account_data::blocklist_surface_label(*surface))
                                .collect::<Vec<_>>()
                                .join(", ");
                            let expires_at = entry.expires_at;
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "blocked-user-row",
                                    "data-actor-id": "{entry_value}",
                                    "data-target-kind": "{kind}",
                                    "data-blocked-at": "{blocked_at}",
                                    div { class: "event-head",
                                        span { class: "badge", "{kind_label}" }
                                        span { title: "{entry_value}", "{entry_label}" }
                                        span { class: "muted", "{blocked_at}" }
                                    }
                                    div { class: "muted", "Applies to: {applies_summary}" }
                                    if let Some(expires) = &expires_at {
                                        div { class: "muted", "Expires: {expires}" }
                                    }
                                    if let Some(reason) = &entry.reason_code {
                                        div { class: "muted", "Reason: {reason}" }
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "unblock-button",
                                            "data-actor-id": "{entry_value}",
                                            disabled: !has_session,
                                            onclick: {
                                                let target = entry.target.clone();
                                                let target_value = entry_value.to_owned();
                                                let base = base_url;
                                                move |_| {
                                                    let changed = state_store
                                                        .write()
                                                        .unblock_target(&target);
                                                    let next = state_store.read().client_blocklist();
                                                    entries.set(next.clone());
                                                    if changed {
                                                        let target_label = if crate::account_data::target_is_actor(&target) {
                                                            actor_display_label(
                                                                &state_store.read(),
                                                                &target_value,
                                                            )
                                                        } else {
                                                            short_protocol_id(&target_value)
                                                        };
                                                        status.set(format!(
                                                            "Unblocked {}",
                                                            target_label
                                                        ));
                                                        crate::views::settings::push_blocklist_account_data(
                                                            base(),
                                                            token(),
                                                            principal_id(),
                                                            state_store,
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
                            if let Some(kind) = v.as_deref().and_then(
                                crate::account_data::BlocklistUiTargetKind::from_ui_value,
                            ) {
                                target_kind.set(kind);
                            }
                        },
                        for (index, kind) in crate::account_data::BlocklistUiTargetKind::ALL.iter().copied().enumerate() {
                            SelectOption::<String> {
                                index,
                                value: kind.ui_value().to_owned(),
                                text_value: kind.ui_value(),
                                {target_kind_label(kind)}
                            }
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-target-input-input", "{target_input_label}" }
                    Input {
                        id: "block-target-input-input",
                        class: "{input_class}",
                        "data-testid": "block-target-input",
                        value: "{add_input}",
        placeholder: target_kind_placeholder(kind_now),
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
                            div { class: "metric",
                                Checkbox {
                                    "data-testid": "block-applies-{crate::account_data::blocklist_surface_label(surface)}",
                                    checked: if applies_to.read().contains(&surface) {
                                        CheckboxState::Checked
                                    } else {
                                        CheckboxState::Unchecked
                                    },
                                    on_checked_change: move |state: CheckboxState| {
                                        let mut next = applies_to();
                                        if bool::from(state) {
                                            if !next.contains(&surface) {
                                                next.push(surface);
                                            }
                                        } else {
                                            next.retain(|candidate| *candidate != surface);
                                        }
                                        applies_to.set(next);
                                    },
                                }
                                span { {crate::account_data::blocklist_surface_label(surface)} }
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
                                    .block_target(kind, &target, reason, applies, expires);
                                let next = state_store.read().client_blocklist();
                                entries.set(next.clone());
                                if changed {
                                    let target_label = if kind == crate::account_data::BlocklistUiTargetKind::Actor {
                                        actor_display_label(&state_store.read(), &target)
                                    } else {
                                        short_protocol_id(&target)
                                    };
                                    status.set(format!(
                                        "blocklist updated; added {}",
                                        target_label
                                    ));
                                    add_input.set(String::new());
                                    crate::views::settings::push_blocklist_account_data(
                                        base(),
                                        token(),
                                        principal_id(),
                                        state_store,
                                        next,
                                    );
                                } else {
                                    let target_label = if kind == crate::account_data::BlocklistUiTargetKind::Actor {
                                        actor_display_label(&state_store.read(), &target)
                                    } else {
                                        short_protocol_id(&target)
                                    };
                                    status.set(format!(
                                        "{} is already blocked",
                                        target_label
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
    use super::is_valid_identity_id;

    #[test]
    fn actor_block_target_requires_canonical_identity_id() {
        assert!(is_valid_identity_id("ak:did_core:webvh:z6mkfixtureactor"));
        assert!(!is_valid_identity_id(
            "did:webvh:z6mkfixtureactor:actor.example"
        ));
    }

    #[test]
    fn blocklist_uses_client_blocklist_state_store_methods() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist");
        assert!(store.client_blocklist().is_empty());

        assert!(store.block_user("ak:did_core:web:bob.example", None));
        assert!(!store.block_user("ak:did_core:web:bob.example", None));

        let entries = store.client_blocklist();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            crate::account_data::blocklist_target_value(&entries[0].target),
            "ak:did_core:web:bob.example"
        );
        assert!(crate::account_data::target_is_actor(&entries[0].target));
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from(["ak:did_core:web:bob.example".to_owned()])
        );

        let remote = entries.clone();
        store.set_client_blocklist(4, remote.clone());
        store.set_client_blocklist(3, Vec::new());
        store.set_client_blocklist(4, Vec::new());
        assert_eq!(store.client_blocklist_revision(), 4);
        assert_eq!(store.client_blocklist(), remote);

        store.complete_personal_block_saga("ak:did_core:web:bob.example");
        assert!(store.pending_personal_block_sagas().is_empty());

        assert!(store.unblock_user("ak:did_core:web:bob.example"));
        assert!(!store.unblock_user("ak:did_core:web:bob.example"));
        assert!(store.client_blocklist().is_empty());
    }
}
