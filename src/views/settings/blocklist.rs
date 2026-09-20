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

/// Translation key for a `target.kind` value.
fn target_kind_label_key(kind: crate::account_data::BlocklistUiTargetKind) -> &'static str {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Domain => {
            "settings.privacy.blocklist.kind.domain"
        }
        crate::account_data::BlocklistUiTargetKind::Actor => {
            "settings.privacy.blocklist.kind.actor"
        }
    }
}

fn surface_label_key(
    surface: arkret_models_collaboration::objects::productivity::AccountBlocklistSurface,
) -> &'static str {
    use arkret_models_collaboration::objects::productivity::AccountBlocklistSurface;
    match surface {
        AccountBlocklistSurface::Messages => "settings.privacy.blocklist.surface.messages",
        AccountBlocklistSurface::Mentions => "settings.privacy.blocklist.surface.mentions",
        AccountBlocklistSurface::Dm => "settings.privacy.blocklist.surface.dm",
        AccountBlocklistSurface::Calls => "settings.privacy.blocklist.surface.calls",
        AccountBlocklistSurface::Contacts => "settings.privacy.blocklist.surface.contacts",
        AccountBlocklistSurface::Applets => "settings.privacy.blocklist.surface.applets",
        AccountBlocklistSurface::Presence => "settings.privacy.blocklist.surface.presence",
        AccountBlocklistSurface::Notifications => {
            "settings.privacy.blocklist.surface.notifications"
        }
        AccountBlocklistSurface::Directory => "settings.privacy.blocklist.surface.directory",
    }
}

/// Placeholder hint for the stable identifier input, by target kind.
fn target_kind_placeholder(kind: crate::account_data::BlocklistUiTargetKind) -> &'static str {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Domain => "example.com",
        crate::account_data::BlocklistUiTargetKind::Actor => {
            r#"{"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:station.example"}}"#
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

fn is_valid_identity_id(kind: crate::account_data::BlocklistUiTargetKind, input: &str) -> bool {
    match kind {
        crate::account_data::BlocklistUiTargetKind::Actor => {
            serde_json::from_str::<arkret_sdk::ActorId>(input).is_ok()
        }
        crate::account_data::BlocklistUiTargetKind::Domain => !input.trim().is_empty(),
    }
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

    // Actor targets require an explicit full ActorId. Do not infer a Station for
    // a bare principal or expand an organization/service affiliation into senders.
    let kind_now = target_kind();
    let raw_input = add_input();
    let input_trimmed = raw_input.trim();
    let input_empty = input_trimmed.is_empty();
    let input_valid = !input_empty
        && if kind_now == crate::account_data::BlocklistUiTargetKind::Actor {
            is_valid_identity_id(kind_now, input_trimmed)
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
    let invalid_hint_key = if kind_now == crate::account_data::BlocklistUiTargetKind::Actor {
        "settings.privacy.blocklist.invalid.actor"
    } else {
        "settings.privacy.blocklist.invalid.domain"
    };
    let target_input_label_key = if kind_now == crate::account_data::BlocklistUiTargetKind::Actor {
        "settings.privacy.blocklist.target.actor"
    } else {
        "settings.privacy.blocklist.target.domain"
    };
    rsx! {
        div { class: "event", "data-testid": "blocked-users-panel",
            div { class: "event-head",
                span { {crate::i18n::tr("settings.privacy.blocklist.title")} }
            }
            div { class: "muted",
                {crate::i18n::tr("settings.privacy.blocklist.description")}
            }

            div { class: "settings-list", "data-testid": "blocked-users-list",
                if entries.read().is_empty() {
                    EmptyState {
                        title: crate::i18n::tr("settings.privacy.blocklist.empty_title"),
                        kind: EmptyStateKind::Empty,
                        message: Some(crate::i18n::tr("settings.privacy.blocklist.empty_body")),
                        test_id: None,
                    }
                } else {
                    for entry in entries.read().iter().cloned() {
                        {
                            let blocked_at = entry.created_at;
                            let kind = crate::account_data::blocklist_target_kind_label(&entry.target);
                            let kind_label = if kind == "domain" {
                                crate::i18n::tr(target_kind_label_key(crate::account_data::BlocklistUiTargetKind::Domain))
                            } else {
                                crate::i18n::tr(target_kind_label_key(crate::account_data::BlocklistUiTargetKind::Actor))
                            };
                            let entry_value = crate::account_data::blocklist_target_value(&entry.target);
                            let entry_label = if crate::account_data::target_is_actor(&entry.target) {
                                actor_display_label(&state_store.read(), &entry_value)
                            } else {
                                short_protocol_id(&entry_value)
                            };
                            let applies_summary = entry.applies_to.iter()
                                .map(|surface| crate::i18n::tr(surface_label_key(*surface)))
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
                                    div { class: "muted", {crate::i18n::tr_args(
                                        "settings.privacy.blocklist.applies_summary",
                                        &[("surfaces", applies_summary)],
                                    )} }
                                    if let Some(expires) = &expires_at {
                                        div { class: "muted", {crate::i18n::tr_args(
                                            "settings.privacy.blocklist.expires_summary",
                                            &[("expires", expires.to_string())],
                                        )} }
                                    }
                                    if let Some(reason) = &entry.reason_code {
                                        div { class: "muted", {crate::i18n::tr_args(
                                            "settings.privacy.blocklist.reason_summary",
                                            &[("reason", crate::i18n::tr(&format!("moderation.report.reason.{reason}")))],
                                        )} }
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
                                                        status.set(crate::i18n::substitute_args(
                                                            crate::i18n::tr("settings.privacy.blocklist.status.unblocked"),
                                                            &[("target", target_label)],
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
                                            {crate::i18n::tr("settings.privacy.blocklist.unblock")}
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
                    Label { html_for: "block-target-kind", {crate::i18n::tr("settings.privacy.blocklist.target_type")} }
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
                                text_value: crate::i18n::tr(target_kind_label_key(kind)),
                                {crate::i18n::tr(target_kind_label_key(kind))}
                            }
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-target-input-input", {crate::i18n::tr(target_input_label_key)} }
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
                            {crate::i18n::tr(invalid_hint_key)}
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-applies-to", {crate::i18n::tr("settings.privacy.blocklist.applies_to")} }
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
                                span { {crate::i18n::tr(surface_label_key(surface))} }
                            }
                        }
                    }
                    if applies_empty {
                        div {
                            class: "settings-inline-hint settings-inline-hint-invalid",
                            "data-testid": "block-applies-empty",
                            {crate::i18n::tr("settings.privacy.blocklist.applies_required")}
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-reason", {crate::i18n::tr("settings.privacy.blocklist.reason_optional")} }
                    Select::<String> {
                        "data-testid": "block-reason",
                        value: Some(reason_selected.into()),
                        on_value_change: move |v: Option<String>| {
                            reason_code.set(v.unwrap_or_default());
                        },
                        SelectOption::<String> {
                            index: 0usize,
                            value: String::new(),
                            text_value: crate::i18n::tr("settings.privacy.blocklist.no_reason"),
                            {crate::i18n::tr("settings.privacy.blocklist.no_reason")}
                        }
                        for (idx , code) in BLOCK_REASON_CODES.iter().copied().enumerate() {
                            SelectOption::<String> {
                                index: idx + 1,
                                value: code.to_string(),
                                text_value: crate::i18n::tr(&format!("moderation.report.reason.{code}")),
                                {crate::i18n::tr(&format!("moderation.report.reason.{code}"))}
                            }
                        }
                    }
                }

                div { class: "field",
                    Label { html_for: "block-expiry", {crate::i18n::tr("settings.privacy.blocklist.expires")} }
                    Select::<String> {
                        "data-testid": "block-expiry",
                        value: Some(expiry_selected.into()),
                        on_value_change: move |v: Option<String>| {
                            if let Some(v) = v {
                                expiry_choice.set(v);
                            }
                        },
                        SelectOption::<String> { index: 0usize, value: "never".to_string(), text_value: crate::i18n::tr("settings.privacy.blocklist.expiry.never"), {crate::i18n::tr("settings.privacy.blocklist.expiry.never")} }
                        SelectOption::<String> { index: 1usize, value: "1d".to_string(), text_value: crate::i18n::tr("settings.privacy.blocklist.expiry.1d"), {crate::i18n::tr("settings.privacy.blocklist.expiry.1d")} }
                        SelectOption::<String> { index: 2usize, value: "7d".to_string(), text_value: crate::i18n::tr("settings.privacy.blocklist.expiry.7d"), {crate::i18n::tr("settings.privacy.blocklist.expiry.7d")} }
                        SelectOption::<String> { index: 3usize, value: "30d".to_string(), text_value: crate::i18n::tr("settings.privacy.blocklist.expiry.30d"), {crate::i18n::tr("settings.privacy.blocklist.expiry.30d")} }
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
                                    status.set(crate::i18n::substitute_args(
                                        crate::i18n::tr("settings.privacy.blocklist.status.added"),
                                        &[("target", target_label)],
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
                                    status.set(crate::i18n::substitute_args(
                                        crate::i18n::tr("settings.privacy.blocklist.status.duplicate"),
                                        &[("target", target_label)],
                                    ));
                                }
                            }
                        },
                        {crate::i18n::tr("settings.privacy.blocklist.block")}
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
    fn actor_block_target_requires_full_actor_id() {
        use crate::account_data::BlocklistUiTargetKind as Kind;
        let actor = account_actor("ak:did_core:web:station.example");
        assert!(is_valid_identity_id(Kind::Actor, &actor));
        assert!(!is_valid_identity_id(
            Kind::Actor,
            "ak:did_core:web:bob.example"
        ));
        assert!(!is_valid_identity_id(
            Kind::Actor,
            r#"{"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example"}}"#
        ));
        let service = arkret_sdk::ActorId::service(
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
        .to_string();
        assert!(is_valid_identity_id(Kind::Actor, &service));
    }

    fn account_actor(station: &str) -> String {
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            arkret_sdk::DidCoreId::new(station).unwrap(),
        ))
        .to_string()
    }

    #[test]
    fn blocklist_uses_client_blocklist_state_store_methods() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist");
        assert!(store.client_blocklist().is_empty());

        let actor = account_actor("ak:did_core:web:station.example");
        assert!(!store.block_user("ak:did_core:web:bob.example", None));
        assert!(store.block_user(&actor, None));
        assert!(!store.block_user(&actor, None));

        let entries = store.client_blocklist();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            crate::account_data::blocklist_target_value(&entries[0].target),
            actor
        );
        assert!(crate::account_data::target_is_actor(&entries[0].target));
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from([actor.clone()])
        );
        assert!(store.personal_blocklist_write_pending());
        assert!(store.committed_personal_block_sagas().is_empty());

        let remote = entries.clone();
        store.set_client_blocklist(4, remote.clone());
        store.set_client_blocklist(3, Vec::new());
        store.set_client_blocklist(4, Vec::new());
        assert_eq!(store.client_blocklist_revision(), 4);
        assert_eq!(store.client_blocklist(), remote);
        assert!(!store.personal_blocklist_write_pending());
        assert_eq!(
            store.committed_personal_block_sagas(),
            std::collections::BTreeSet::from([actor.clone()])
        );

        store.complete_personal_block_saga(&actor);
        assert!(store.pending_personal_block_sagas().is_empty());

        assert!(store.unblock_user(&actor));
        assert!(!store.unblock_user(&actor));
        assert!(store.client_blocklist().is_empty());
    }

    #[test]
    fn block_sagas_preserve_distinct_stations_and_canonicalize_input() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-stations");
        let first = account_actor("ak:did_core:web:station-a.example");
        let second = account_actor("ak:did_core:web:station-b.example");
        let pretty = serde_json::to_string_pretty(
            &serde_json::from_str::<arkret_sdk::ActorId>(&first).unwrap(),
        )
        .unwrap();
        assert!(store.block_user(&pretty, None));
        assert!(!store.block_user(&first, None));
        assert!(store.block_target(
            crate::account_data::BlocklistUiTargetKind::Actor,
            &second,
            None,
            Vec::new(),
            None
        ));
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from([first.clone(), second.clone()])
        );
        assert!(store.unblock_user(&first));
        assert_eq!(store.client_blocklist().len(), 1);
        assert_eq!(
            crate::account_data::blocklist_target_value(&store.client_blocklist()[0].target),
            second
        );
    }

    #[test]
    fn non_dm_block_does_not_stage_contact_tombstone() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-non-dm");
        let actor = account_actor("ak:did_core:web:station.example");
        assert!(store.block_target(
            crate::account_data::BlocklistUiTargetKind::Actor,
            &actor,
            None,
            vec![arkret_models_collaboration::objects::productivity::AccountBlocklistSurface::Messages],
            None,
        ));
        assert!(store.pending_personal_block_sagas().is_empty());
    }

    #[test]
    fn actor_projection_cache_is_bounded_and_revision_invalidated() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-cache");
        let mut actors = Vec::new();
        let mut entries = Vec::new();
        for index in 0..300 {
            let actor = account_actor(&format!("ak:did_core:web:station-{index}.example"));
            entries.push(
                crate::account_data::new_blocklist_entry(
                    crate::account_data::BlocklistUiTargetKind::Actor,
                    &actor,
                    None,
                    crate::account_data::DEFAULT_BLOCKLIST_APPLIES_TO.to_vec(),
                    None,
                    chrono::Utc::now(),
                )
                .unwrap(),
            );
            actors.push(actor);
        }
        store.set_client_blocklist(7, entries);
        for actor in &actors {
            assert_eq!(store.client_blocklist_for_actor(actor).len(), 1);
        }
        assert_eq!(store.blocklist_projection_cache_len(), 256);

        store.set_client_blocklist(8, Vec::new());
        assert_eq!(store.blocklist_projection_cache_len(), 0);
        assert!(store.client_blocklist_for_actor(&actors[0]).is_empty());
        assert_eq!(store.blocklist_projection_cache_len(), 1);
    }

    #[test]
    fn tombstone_failure_resumes_without_rewriting_blocklist_revision() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-resume");
        let actor = account_actor("ak:did_core:web:station.example");
        assert!(store.block_user(&actor, None));
        let accepted_entries = store.client_blocklist();

        // Simulate Account Data acceptance followed by a Contact transport
        // failure: the accepted leg is durable and the write leg is no longer
        // pending, so the retry resumes at tombstone instead of minting v2.
        store.set_client_blocklist(1, accepted_entries);
        assert_eq!(store.client_blocklist_revision(), 1);
        assert!(!store.personal_blocklist_write_pending());
        assert_eq!(
            store.committed_personal_block_sagas(),
            std::collections::BTreeSet::from([actor.clone()])
        );
        assert_eq!(
            store.pending_personal_block_sagas(),
            std::collections::BTreeSet::from([actor])
        );
    }

    #[test]
    fn unblock_rebuilds_view_from_retained_history_without_restoring_contact() {
        let mut store = crate::state::isolated_store_for_tests("settings-blocklist-unblock");
        let blocked = account_actor("ak:did_core:web:blocked.example");
        let visible = account_actor("ak:did_core:web:visible.example");
        let retained_history = vec![blocked.clone(), visible.clone()];
        assert!(store.block_user(&blocked, None));
        let accepted_entries = store.client_blocklist();
        store.set_client_blocklist(1, accepted_entries);
        store.complete_personal_block_saga(&blocked);

        let projected = retained_history
            .iter()
            .filter(|actor| {
                !crate::account_data::is_blocked(&store.client_blocklist_for_actor(actor), actor)
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(projected, vec![visible.clone()]);

        assert!(store.unblock_user(&blocked));
        assert!(store.personal_blocklist_write_pending());
        assert!(store.pending_personal_block_sagas().is_empty());
        let rebuilt = retained_history
            .iter()
            .filter(|actor| {
                !crate::account_data::is_blocked(&store.client_blocklist_for_actor(actor), actor)
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(rebuilt, retained_history);
    }
}
