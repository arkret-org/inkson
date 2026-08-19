//! Realm bootstrap wizard (`ak.realm.create`) section component.

use dioxus::prelude::*;
use dioxus_router::Link;

use super::data::{
    ANCHOR_PROFILE_OPTIONS, CONTENT_SCHEME_OPTIONS, DISCOVERABILITY_OPTIONS,
    ENCRYPTION_PROFILE_OPTIONS, FEDERATION_POLICY_OPTIONS, HASH_PROFILE_OPTIONS,
    HISTORY_VISIBILITY_OPTIONS, JOIN_RULE_OPTIONS, SECURITY_CLASS_OPTIONS, option_hint,
};
use super::helpers::{
    content_scheme_constraint_hint, history_visibility_admits_prejoin, normalize_content_scheme,
    parse_seed_members, plaintext_services_for_policy, policy_combination_hint,
};
use super::model::{NEW_REALM_STEPS, NewRealmStep};
use crate::api_error::is_auth_expired_error;
use crate::config::LocalConfigStore;
use crate::i18n::{tr, tr_args};
use crate::routes::Route;
use crate::transport::auth::authed_api_ready;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// Bootstrap-progress templates resolved *before* the create task is
/// spawned.
///
/// `tr()` reads the i18n signal out of Dioxus context, which is not
/// available inside a spawned task — the same constraint that makes
/// `components::feedback` carry keys + args across the boundary instead of
/// resolved text. Here the messages are consumed by `realm_state` rather
/// than the toast host, so the component resolves the templates on render
/// and moves this struct into the task, then fills `{placeholder}`s with
/// [`crate::i18n::substitute_args`] — the one substitution implementation.
#[derive(Clone)]
struct BootstrapProgressStrings {
    accepted: String,
    created: String,
    seeded_owner_only: String,
    seeded_members: String,
    canonical_policy: String,
    plaintext_services: String,
    mls_ready_backup: String,
    mls_ready_local: String,
    mls_admission_failed: String,
    mls_welcome_queued: String,
    floor_required: String,
    signer_not_ready: String,
    create_failed: String,
    created_then_failed: String,
    invalid_server_url: String,
    session_expired: String,
}

impl BootstrapProgressStrings {
    fn resolve() -> Self {
        Self {
            accepted: tr("setup.progress.accepted"),
            created: tr("setup.progress.created"),
            seeded_owner_only: tr("setup.progress.seeded_owner_only"),
            seeded_members: tr("setup.progress.seeded_members"),
            canonical_policy: tr("setup.progress.canonical_policy"),
            plaintext_services: tr("setup.progress.plaintext_services"),
            mls_ready_backup: tr("setup.progress.mls_ready_backup"),
            mls_ready_local: tr("setup.progress.mls_ready_local"),
            mls_admission_failed: tr("setup.progress.mls_admission_failed"),
            mls_welcome_queued: tr("setup.progress.mls_welcome_queued"),
            floor_required: tr("setup.progress.floor_required"),
            signer_not_ready: tr("setup.error.signer_not_ready"),
            create_failed: tr("setup.error.create_failed"),
            created_then_failed: tr("setup.error.created_then_failed"),
            invalid_server_url: tr("setup.error.invalid_server_url"),
            session_expired: tr("setup.error.session_expired"),
        }
    }

    fn fill(template: &str, args: &[(&'static str, String)]) -> String {
        crate::i18n::substitute_args(template.to_owned(), args)
    }
}

/// Realm authoring becomes available once the session credential and secure
/// store have finished hydrating. The async authenticated-client provider used
/// by the submit path owns grant rotation, so UI readiness must not depend on a
/// synchronous snapshot of the persisted grant: that snapshot can briefly be
/// expired while the provider is rotating it in the background.
fn realm_create_available(
    has_session: bool,
    basics_ready: bool,
    boundary_ready: bool,
    secure_store_ready: bool,
    create_busy: bool,
    has_created_realm: bool,
) -> bool {
    has_session
        && basics_ready
        && boundary_ready
        && secure_store_ready
        && !create_busy
        && !has_created_realm
}

#[component]
pub(super) fn RealmsSection(
    plaintext_service_id: String,
    secure_store_ready: bool,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    mut selected_realm_id: Signal<String>,
    // State signals are owned by the parent `SetupPanel` so the wizard's
    // in-progress draft survives switching between setup sections (the
    // sections are conditionally rendered, so locally-owned hooks would reset
    // on every section change).
    mut create_step: Signal<NewRealmStep>,
    mut seed_members: Signal<String>,
    mut realm_title: Signal<String>,
    mut realm_summary: Signal<String>,
    mut realm_alias: Signal<String>,
    mut realm_discoverability: Signal<String>,
    mut realm_policy_join_rule: Signal<String>,
    mut realm_policy_history_visibility: Signal<String>,
    mut realm_encryption_profile: Signal<String>,
    mut realm_content_scheme: Signal<String>,
    mut realm_security_class: Signal<String>,
    mut realm_federation_policy: Signal<String>,
    mut realm_notary_profile: Signal<String>,
    mut realm_digest_algorithm: Signal<String>,
    mut realm_state: Signal<String>,
    mut realm_create_busy: Signal<bool>,
    mut created_realm_id: Signal<String>,
    mut pending_recovery_gate: Signal<bool>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let has_session = !token().trim().is_empty();

    let realm_discoverability_selected = use_memo(move || Some(realm_discoverability()));
    let realm_policy_join_rule_selected = use_memo(move || Some(realm_policy_join_rule()));
    let realm_policy_history_visibility_selected =
        use_memo(move || Some(realm_policy_history_visibility()));
    let realm_encryption_profile_selected = use_memo(move || Some(realm_encryption_profile()));
    let realm_content_scheme_selected = use_memo(move || Some(realm_content_scheme()));
    let realm_security_class_selected = use_memo(move || Some(realm_security_class()));
    let realm_federation_policy_selected = use_memo(move || Some(realm_federation_policy()));
    let realm_notary_profile_selected = use_memo(move || Some(realm_notary_profile()));
    let realm_digest_algorithm_selected = use_memo(move || Some(realm_digest_algorithm()));

    let active_create_step = create_step();
    let title_value = realm_title();
    let summary_value = realm_summary();
    let alias_value = realm_alias();
    let discoverability_value = realm_discoverability();
    let join_rule_value = realm_policy_join_rule();
    let history_visibility_value = realm_policy_history_visibility();
    let encryption_profile_value = realm_encryption_profile();
    let content_scheme_value = realm_content_scheme();
    let encryption_is_e2ee =
        crate::security_state::encryption_profile_is_encrypted(&encryption_profile_value);
    let history_requires_exporter_aead =
        encryption_is_e2ee && history_visibility_admits_prejoin(&history_visibility_value);
    let content_scheme_warning = content_scheme_constraint_hint(
        encryption_is_e2ee,
        &history_visibility_value,
        &content_scheme_value,
    );
    let security_class_value = realm_security_class();
    let federation_policy_value = realm_federation_policy();
    let notary_profile_value = realm_notary_profile();
    let digest_algorithm_value = realm_digest_algorithm();
    let federation_policy_open_forbidden = security_class_value == "high_assurance";

    let seed_members_value = seed_members();
    let realm_state_value = realm_state();
    let realm_create_busy_value = realm_create_busy();
    let created_realm_id_value = created_realm_id();
    let parsed_seed_members = parse_seed_members(&seed_members_value);
    let seed_member_count = parsed_seed_members.len();
    let has_created_realm = !created_realm_id_value.trim().is_empty();
    let created_realm_id_label = short_protocol_id(&created_realm_id_value);
    let current_visibility_hint = policy_combination_hint(
        &discoverability_value,
        &join_rule_value,
        &history_visibility_value,
    );
    let current_policy_error = matches!(current_visibility_hint, Some(("error", _, _)));
    let basics_ready = !title_value.trim().is_empty();
    let boundary_ready = !current_policy_error && content_scheme_warning.is_none();
    let create_blocker = if has_created_realm {
        Some(tr("setup.blocker.already_created"))
    } else if !has_session {
        Some(tr("setup.blocker.sign_in"))
    } else if !secure_store_ready {
        Some(tr("setup.blocker.secure_store"))
    } else if realm_create_busy_value {
        Some(tr("setup.blocker.creating"))
    } else {
        None
    };
    let draft_state_label = tr("setup.state.draft");
    let progress_strings = BootstrapProgressStrings::resolve();
    let can_advance_step = match active_create_step {
        NewRealmStep::Basics => basics_ready,
        NewRealmStep::Boundary => boundary_ready,
        NewRealmStep::Seed => basics_ready && boundary_ready,
        NewRealmStep::Done => has_created_realm,
    };
    let can_create_realm = realm_create_available(
        has_session,
        basics_ready,
        boundary_ready,
        secure_store_ready,
        realm_create_busy_value,
        has_created_realm,
    );

    rsx! {
        if pending_recovery_gate() {
            crate::ui::dialog::Dialog {
                open: true,
                on_open_change: move |open: bool| {
                    if !open {
                        pending_recovery_gate.set(false);
                    }
                },
                "data-testid": "encrypted-realm-recovery-gate",
                "aria-label": tr("setup.recovery_gate.aria"),
                div { class: "modal event",
                    div { class: "modal-head event-head",
                        h3 { {tr("setup.recovery_gate.title")} }
                        span { class: "muted", {tr("setup.recovery_gate.badge")} }
                    }
                    div { class: "modal-body",
                        div { class: "muted",
                            {tr("setup.recovery_gate.body")}
                        }
                    }
                    div { class: "modal-foot actions",
                        Link {
                            class: "primary",
                            "data-testid": "encrypted-realm-recovery-gate-setup",
                            to: Route::SettingsRecovery,
                            onclick: move |_| pending_recovery_gate.set(false),
                            {tr("setup.action.setup_recovery_key")}
                        }
                    }
                }
            }
        }
        div { class: "setup-shell new-realm-shell", "data-testid": "realm-lifecycle-strand",
            div { class: "setup-column",
                div { class: "event new-realm-hero", "data-testid": "realm-setup-guide",
                    div { class: "event-head",
                        span { {tr("setup.new_realm")} }
                    }
                    h2 { class: "settings-content-title", {tr("setup.realm_title_heading")} }
                    div { class: "muted",
                        {tr("setup.realm_intro")}
                    }
                }

                div { class: "event new-realm-stepper",
                    div { class: "event-head",
                        span { {tr("setup.create_steps")} }
                        span {
                            {tr_args(
                                "setup.step_progress",
                                &[
                                    ("current", active_create_step.number().to_owned()),
                                    ("total", NEW_REALM_STEPS.len().to_string()),
                                ],
                            )}
                        }
                    }
                    div { class: "setup-step-list",
                        for step in NEW_REALM_STEPS {
                            Button {
                                variant: if active_create_step == step { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                disabled: step == NewRealmStep::Done && !has_created_realm,
                                onclick: move |_| create_step.set(step),
                                span { class: "setup-step-index", "{step.number()}" }
                                span { class: "setup-step-label",
                                    strong { {tr(step.label_key())} }
                                    small { {tr(step.subtitle_key())} }
                                }
                            }
                        }
                    }

                if active_create_step == NewRealmStep::Basics {
                    div { class: "setup-step-panel",
                        div { class: "event-head",
                            span { {tr("setup.step.basics.label")} }
                            span { {tr("setup.basics.hint")} }
                        }
                        div { class: "workflow-form setup-form-grid",
                            div { class: "setup-field",
                                Label { html_for: "realm-title-input-input", {tr("setup.field.realm_title")} }
                                Input {
                                    id: "realm-title-input-input",
                                    "data-testid": "realm-title-input",
                                    value: "{title_value}",
                                    placeholder: tr("setup.field.realm_title_placeholder"),
                                    oninput: move |event: FormEvent| realm_title.set(event.value())
                                }
                            }
                            div { class: "setup-field setup-field-span-2",
                                Label { html_for: "realm-summary-input-input", {tr("setup.field.summary")} }
                                Textarea {
                                    id: "realm-summary-input-input",
                                    "data-testid": "realm-summary-input",
                                    value: "{summary_value}",
                                    rows: "3",
                                    placeholder: tr("setup.field.realm_summary_placeholder"),
                                    oninput: move |event: FormEvent| realm_summary.set(event.value())
                                }
                            }
                            div { class: "setup-field",
                                Label {
                                    html_for: "realm-alias-input-input",
                                    {tr("setup.field.realm_alias")}
                                }
                                Input {
                                    id: "realm-alias-input-input",
                                    "data-testid": "realm-alias-input",
                                    value: "{alias_value}",
                                    placeholder: tr("setup.field.realm_alias_placeholder"),
                                    oninput: move |event: FormEvent| realm_alias.set(event.value())
                                }
                            }
                        }
                        div { class: "actions setup-nav-actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "new-realm-next-button",
                                disabled: !can_advance_step,
                                onclick: move |_| create_step.set(active_create_step.next()),
                                {tr("setup.action.next_boundary")}
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Boundary {
                    div { class: "setup-step-panel",
                        div { class: "event-head",
                            span { {tr("setup.step.boundary.label")} }
                            span { {tr("setup.boundary.hint")} }
                        }
                        div { class: "setup-axis-grid",
                            div { class: "metric directory-axis-card",
                                strong { {tr("setup.axis.discoverability")} }
                                div { class: "workflow-form setup-field",
                                    label { {tr("setup.axis.discoverability.question")} }
                                    Select::<String> {
                                        "data-testid": "realm-discoverability-input",
                                        value: Some(realm_discoverability_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                realm_discoverability.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in DISCOVERABILITY_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: tr(label),
                                                {tr(label)}
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        {option_hint(&DISCOVERABILITY_OPTIONS, &discoverability_value, "setup.axis.discoverability.unset")}
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card",
                                strong { {tr("setup.axis.join_rule")} }
                                div { class: "workflow-form setup-field",
                                    label { {tr("setup.axis.join_rule.question")} }
                                    Select::<String> {
                                        "data-testid": "realm-policy-join-rule-input",
                                        value: Some(realm_policy_join_rule_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                realm_policy_join_rule.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in JOIN_RULE_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: tr(label),
                                                {tr(label)}
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        {option_hint(&JOIN_RULE_OPTIONS, &join_rule_value, "setup.axis.join_rule.unset")}
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card",
                                strong { {tr("setup.axis.history_visibility")} }
                                div { class: "workflow-form setup-field",
                                    label { {tr("setup.axis.history_visibility.question")} }
                                    Select::<String> {
                                        "data-testid": "realm-policy-history-visibility-input",
                                        value: Some(realm_policy_history_visibility_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                if history_visibility_admits_prejoin(&v)
                                                    && crate::security_state::encryption_profile_is_encrypted(
                                                        &realm_encryption_profile(),
                                                    )
                                                {
                                                    realm_content_scheme.set(
                                                        "mls_exporter_aead_v1".to_owned(),
                                                    );
                                                }
                                                realm_policy_history_visibility.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in HISTORY_VISIBILITY_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: tr(label),
                                                {tr(label)}
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        {option_hint(&HISTORY_VISIBILITY_OPTIONS, &history_visibility_value, "setup.axis.history_visibility.unset")}
                                    }
                                }
                            }
                            // These create-locked Realm fields are shown here so the user
                            // makes the permanent choice intentionally.
                            div { class: "metric directory-axis-card",
                                strong { {tr("setup.axis.encryption")} }
                                div { class: "workflow-form setup-field",
                                    label { {tr("setup.axis.encryption.question")} }
                                    Select::<String> {
                                        "data-testid": "realm-encryption-profile-input",
                                        value: Some(realm_encryption_profile_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                let encrypted =
                                                    crate::security_state::encryption_profile_is_encrypted(&v);
                                                if encrypted
                                                    && history_visibility_admits_prejoin(
                                                        &realm_policy_history_visibility(),
                                                    )
                                                {
                                                    realm_content_scheme.set(
                                                        "mls_exporter_aead_v1".to_owned(),
                                                    );
                                                }
                                                realm_encryption_profile.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in ENCRYPTION_PROFILE_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: tr(label),
                                                {tr(label)}
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        {option_hint(&ENCRYPTION_PROFILE_OPTIONS, &encryption_profile_value, "setup.axis.encryption.unset")}
                                    }
                                    div { class: "muted",
                                        {tr("setup.axis.encryption.locked")}
                                    }
                                }
                            }
                            // encryption-and-audit.md §2.10 — `content_scheme`
                            // capability axis. Only meaningful for E2EE realms;
                            // orthogonal to History visibility (the runtime
                            // delivery toggle). Default exporter-AEAD.
                            if encryption_is_e2ee {
                                div { class: "metric directory-axis-card",
                                    strong { {tr("setup.axis.content_scheme")} }
                                    div { class: "workflow-form setup-field",
                                        label { {tr("setup.axis.content_scheme.question")} }
                                        Select::<String> {
                                            "data-testid": "realm-content-scheme-input",
                                            value: Some(realm_content_scheme_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    if v == "mls_rfc9420"
                                                        && history_visibility_admits_prejoin(
                                                            &realm_policy_history_visibility(),
                                                        )
                                                    {
                                                        realm_policy_history_visibility
                                                            .set("joined".to_owned());
                                                    }
                                                    realm_content_scheme.set(v);
                                                }
                                            },
                                            for (i, (option_value, label, _)) in CONTENT_SCHEME_OPTIONS.iter().enumerate() {
                                                SelectOption::<String> {
                                                    index: i,
                                                    value: option_value.to_string(),
                                                    text_value: tr(label),
                                                    disabled: history_requires_exporter_aead
                                                        && *option_value == "mls_rfc9420",
                                                    {tr(label)}
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            {option_hint(&CONTENT_SCHEME_OPTIONS, &content_scheme_value, "setup.axis.content_scheme.unset")}
                                        }
                                        if history_requires_exporter_aead {
                                            div { class: "muted",
                                                {tr("setup.axis.content_scheme.prejoin_forced")}
                                            }
                                        }
                                        if let Some(hint) = content_scheme_warning {
                                            div { class: "inline-warn",
                                                span { class: "body", "{hint}" }
                                            }
                                        }
                                        div { class: "muted",
                                            {tr("setup.axis.content_scheme.capability_only")}
                                        }
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card",
                                strong { {tr("setup.axis.security_class")} }
                                div { class: "workflow-form setup-field",
                                    label { {tr("setup.axis.security_class.question")} }
                                    Select::<String> {
                                        "data-testid": "realm-security-class-input",
                                        value: Some(realm_security_class_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                realm_security_class.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in SECURITY_CLASS_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: tr(label),
                                                {tr(label)}
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        {option_hint(&SECURITY_CLASS_OPTIONS, &security_class_value, "setup.axis.security_class.unset")}
                                    }
                                }
                            }
                        }

                        // Spec realm-and-space.md §2.3 advanced
                        // fields — collapsed by default. All
                        // three are create-locked. Defaults
                        // (restricted / single_did / sha256)
                        // suit the dev + small-deployment cases;
                        // production operators tweak as needed.
                        details { class: "setup-advanced",
                            "data-testid": "realm-advanced-config",
                            summary { class: "setup-advanced-summary",
                                {tr("setup.boundary.advanced_summary")}
                            }
                            div { class: "setup-axis-grid setup-advanced-grid",
                                div { class: "metric directory-axis-card",
                                    strong { {tr("setup.axis.federation_policy")} }
                                    div { class: "workflow-form setup-field",
                                        label { {tr("setup.axis.federation_policy.question")} }
                                        Select::<String> {
                                            "data-testid": "realm-federation-policy-input",
                                            value: Some(realm_federation_policy_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    realm_federation_policy.set(v);
                                                }
                                            },
                                            for (i, (option_value, label, _)) in FEDERATION_POLICY_OPTIONS.iter().enumerate() {
                                                SelectOption::<String> {
                                                    index: i,
                                                    value: option_value.to_string(),
                                                    text_value: tr(label),
                                                    disabled: federation_policy_open_forbidden && *option_value == "open",
                                                    {tr(label)}
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            {option_hint(&FEDERATION_POLICY_OPTIONS, &federation_policy_value, "setup.axis.federation_policy.unset")}
                                        }
                                        if federation_policy_open_forbidden {
                                            div { class: "muted",
                                                {tr("setup.axis.federation_policy.high_assurance")}
                                            }
                                        }
                                    }
                                }
                                div { class: "metric directory-axis-card",
                                    strong { {tr("setup.axis.seal_profile")} }
                                    div { class: "workflow-form setup-field",
                                        label { {tr("setup.axis.seal_profile.question")} }
                                        Select::<String> {
                                            "data-testid": "realm-seal-profile-input",
                                            value: Some(realm_notary_profile_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    realm_notary_profile.set(v);
                                                }
                                            },
                                            for (i, (option_value, label, _)) in ANCHOR_PROFILE_OPTIONS.iter().enumerate() {
                                                SelectOption::<String> {
                                                    index: i,
                                                    value: option_value.to_string(),
                                                    text_value: tr(label),
                                                    {tr(label)}
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            {option_hint(&ANCHOR_PROFILE_OPTIONS, &notary_profile_value, "setup.axis.seal_profile.unset")}
                                        }
                                    }
                                }
                                div { class: "metric directory-axis-card",
                                    strong { {tr("setup.axis.hash_profile")} }
                                    div { class: "workflow-form setup-field",
                                        label { {tr("setup.axis.hash_profile.question")} }
                                        Select::<String> {
                                            "data-testid": "realm-hash-profile-input",
                                            value: Some(realm_digest_algorithm_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    realm_digest_algorithm.set(v);
                                                }
                                            },
                                            for (i, (option_value, label, _)) in HASH_PROFILE_OPTIONS.iter().enumerate() {
                                                SelectOption::<String> {
                                                    index: i,
                                                    value: option_value.to_string(),
                                                    text_value: tr(label),
                                                    {tr(label)}
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            {option_hint(&HASH_PROFILE_OPTIONS, &digest_algorithm_value, "setup.axis.hash_profile.unset")}
                                        }
                                    }
                                }
                            }
                        }

                        if let Some((tone, heading_key, body_key)) = current_visibility_hint {
                            div { class: if tone == "error" { "inline-error" } else { "inline-warn" },
                                span { class: "body",
                                    strong { {tr(heading_key)} }
                                    " "
                                    {tr(body_key)}
                                }
                            }
                        }

                        div { class: "actions setup-nav-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "new-realm-back-button",
                                onclick: move |_| create_step.set(active_create_step.previous()),
                                {tr("setup.action.back")}
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "new-realm-next-button",
                                disabled: !can_advance_step,
                                onclick: move |_| create_step.set(active_create_step.next()),
                                {tr("setup.action.next_seed")}
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Seed {
                    div { class: "setup-step-panel",
                        div { class: "event-head",
                            span { {tr("setup.seed.heading")} }
                            span { {tr("setup.seed.hint")} }
                        }
                        div { class: "workflow-form setup-form-grid",
                            div { class: "setup-field setup-field-span-2",
                                Label { html_for: "seed-members-input-input", {tr("setup.field.seed_members")} }
                                Textarea {
                                    id: "seed-members-input-input",
                                    "data-testid": "seed-members-input",
                                    value: "{seed_members_value}",
                                    rows: "4",
                                    placeholder: "did:webvh:<scid>:alice.example\ndid:webvh:<scid>:bob.example",
                                    oninput: move |event: FormEvent| seed_members.set(event.value())
                                }
                                div { class: "muted", {tr("setup.field.seed_members_help")} }
                            }
                            div { class: "setup-field setup-field-span-2",
                                label { {tr("setup.seed.preview")} }
                                if seed_member_count == 0 {
                                    div { class: "muted", {tr("setup.seed.preview_empty")} }
                                } else {
                                    div { class: "setup-chip-wrap",
                                        for member in parsed_seed_members.iter().take(8) {
                                            {
                                                let member_label =
                                                    actor_display_label(&state_store.read(), member);
                                                rsx! {
                                                    span { class: "badge blue", title: "{member}", "{member_label}" }
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "muted",
                                    {tr_args(
                                        "setup.seed.preview_count",
                                        &[("count", seed_member_count.to_string())],
                                    )}
                                }
                            }
                        }
                        if let Some(blocker) = create_blocker {
                            div { class: "inline-warn", "data-testid": "realm-create-blocker",
                                span { class: "body", "{blocker}" }
                            }
                        }
                        if realm_state_value != draft_state_label {
                            div { class: "setup-summary-list", "data-testid": "realm-create-status",
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { {tr("setup.state.bootstrap")} }
                                    span { class: "muted", "{realm_state_value}" }
                                }
                            }
                        }
                        div { class: "actions setup-nav-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "new-realm-back-button",
                                onclick: move |_| create_step.set(active_create_step.previous()),
                                {tr("setup.action.back")}
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "create-realm-button",
                                disabled: !can_create_realm,
                                onclick: {
                                    let base = base_url.clone();
                                    let strings = progress_strings.clone();
                                    move |_| {
                                        let strings = strings.clone();
                                        let history_visibility = realm_policy_history_visibility();
                                        let encryption_profile = realm_encryption_profile();
                                        let content_scheme = normalize_content_scheme(
                                            crate::security_state::encryption_profile_is_encrypted(
                                                &encryption_profile,
                                            ),
                                            &history_visibility,
                                            &realm_content_scheme(),
                                        );
                                        if let Err(error) =
                                            crate::event_builders::validate_realm_history_content_scheme_for_profile(
                                                &encryption_profile,
                                                &history_visibility,
                                                Some(content_scheme.as_str()),
                                            )
                                        {
                                            let message = error.to_string();
                                            realm_state.set(message.clone());
                                            crate::components::feedback::toast_error(
                                                "feedback.realm_create_failed",
                                                vec![],
                                                Some(message),
                                            );
                                            return;
                                        }
                                        // `recovery_material_pending` is a normative hard gate:
                                        // encrypted Realm creation requires a configured recovery path.
                                        if crate::security_state::encryption_profile_is_encrypted(
                                            &encryption_profile,
                                        )
                                        {
                                            let actor_now = account_did();
                                            let recovery_ready = {
                                                let store = state_store.read();
                                                crate::views::recovery::recovery_options_configured(
                                                    &store, &actor_now,
                                                ) || crate::components::mls_recovery_backup_configured(
                                                    &store, &actor_now,
                                                )
                                            };
                                            if !recovery_ready {
                                                pending_recovery_gate.set(true);
                                                return;
                                            }
                                        }
                                        realm_create_busy.set(true);
                                        realm_state.set(tr("setup.blocker.creating"));
                                        let api_token = token();
                                        let base = base.clone();
                                        let backup_trigger_signal =
                                            crate::components::try_needs_mls_backup_signal();
                                        let title = realm_title();
                                        let summary = realm_summary();
                                        let alias = realm_alias();
                                        let discoverability = realm_discoverability();
                                        let join_rule = realm_policy_join_rule();
                                        let security_class = realm_security_class();
                                        let federation_policy = realm_federation_policy();
                                        let notary_profile = realm_notary_profile();
                                        let digest_algorithm = realm_digest_algorithm();
                                        let seed_text = seed_members();
                                        let actor = account_did();
                                        let device = device_id();
                                        let configured_plaintext_service_id =
                                            plaintext_service_id.clone();
                                        spawn(async move {
                                            if crate::event_signer::active_signer().is_none() {
                                                match crate::event_signer::bootstrap_default_signer("inkson") {
                                                    Ok(_) => {}
                                                    Err(error) => {
                                                        let message = BootstrapProgressStrings::fill(
                                                            &strings.signer_not_ready,
                                                            &[("error", error.to_string())],
                                                        );
                                                        realm_create_busy.set(false);
                                                        realm_state.set(message.clone());
                                                        crate::components::feedback::toast_error(
                                                            "feedback.realm_create_failed",
                                                            vec![],
                                                            Some(message),
                                                        );
                                                        return;
                                                    }
                                                }
                                            }
                                            let invitees = parse_seed_members(&seed_text);
                                            match authed_api_ready(&base, api_token.clone()).await {
                                                Ok(api) => {
                                                    let mut plaintext_services = plaintext_services_for_policy(
                                                        &configured_plaintext_service_id,
                                                    );
                                                    if let Ok(description) = api.describe().await {
                                                        let service_id = description.service_id.as_str().trim();
                                                        if !service_id.is_empty()
                                                            && !plaintext_services
                                                                .iter()
                                                                .any(|existing| existing == service_id)
                                                        {
                                                            plaintext_services.push(service_id.to_owned());
                                                        }
                                                    }
                                                    // Spec realm.schema.json requires
                                                    // trust_domain on the create event.
                                                    // sync_engine caches the server's
                                                    // advertised value in
                                                    // state_store.server_trust_domain
                                                    // after describe; if it isn't set
                                                    // yet we ask the API to fall back
                                                    // to the describe response.
                                                    let cached_trust_domain = state_store
                                                        .read()
                                                        .load()
                                                        .server_trust_domain
                                                        .clone();
                                                    let trust_domain = match cached_trust_domain {
                                                        Some(value) if !value.trim().is_empty() => value,
                                                        _ => match api.describe().await {
                                                            Ok(desc) => desc.trust_domain.as_str().to_owned(),
                                                            Err(_) => String::new(),
                                                        },
                                                    };
                                                    let submitter = match api.event_submitter() {
                                                        Ok(submitter) => submitter,
                                                        Err(error) => {
                                                            let message = BootstrapProgressStrings::fill(
                                                                &strings.create_failed,
                                                                &[("error", error.to_string())],
                                                            );
                                                            realm_create_busy.set(false);
                                                            realm_state.set(message.clone());
                                                            crate::components::feedback::toast_error(
                                                                "feedback.realm_create_failed",
                                                                vec![],
                                                                Some(message),
                                                            );
                                                            return;
                                                        }
                                                    };
                                                    match crate::transport::realm_write::create_realm(
                                                        &submitter,
                                                        &actor,
                                                        &title,
                                                        Some(&summary),
                                                        &discoverability,
                                                        &join_rule,
                                                        &history_visibility,
                                                        &encryption_profile,
                                                        &security_class,
                                                        &federation_policy,
                                                        &notary_profile,
                                                        &digest_algorithm,
                                                        &trust_domain,
                                                        invitees.clone(),
                                                        plaintext_services.clone(),
                                                        (!alias.trim().is_empty()).then(|| alias.trim()),
                                                        Some(content_scheme.as_str()),
                                                    ).await {
                                                    Ok(realm) => {
                                                        // R15: ak.realm.create now returns
                                                        // RealmCreateResult with the new
                                                        // `ak:realm:*` id under `realm_id`.
                                                        let realm_id = realm.realm_id.clone();
                                                        selected_realm_id.set(realm_id.clone());
                                                        created_realm_id.set(realm_id.clone());
                                                        // Optimistic sidebar update goes
                                                        // through the canonical store —
                                                        // the Realm tree Signal is derived
                                                        // from `state_store.realm_tree_projections`
                                                        // by RouterView's derive effect, so
                                                        // the `save_realm_tree_projection`
                                                        // below is the single write the
                                                        // sidebar picks up.
                                                        let mut projection_members = Vec::new();
                                                        if !actor.trim().is_empty() {
                                                            projection_members.push(actor.clone());
                                                        }
                                                        for invitee in &invitees {
                                                            if !projection_members.iter().any(|member| member == invitee) {
                                                                projection_members.push(invitee.clone());
                                                            }
                                                        }
                                                        let projection_admins = if actor.trim().is_empty() {
                                                            Vec::new()
                                                        } else {
                                                            vec![actor.clone()]
                                                        };
                                                        // Single-source the "which profile
                                                        // recommends which floor" rule.
                                                        let projection_floor =
                                                            crate::event_builders::encryption_profile_uses_recommended_floor(
                                                                &encryption_profile,
                                                            )
                                                            .then(|| {
                                                                crate::realm_defaults::RECOMMENDED_REALM_ENCRYPTION_FLOOR
                                                                    .to_owned()
                                                            });
                                                        let projection_body =
                                                            crate::realm_tree::OptimisticRealmTreeProjection::realm(
                                                                crate::realm_tree::RealmProjectionInput {
                                                                    owner: actor.clone(),
                                                                    admins: projection_admins,
                                                                    members: projection_members,
                                                                    title: title.clone(),
                                                                    summary: summary.clone(),
                                                                    discoverability: discoverability.clone(),
                                                                    encryption_profile: encryption_profile.clone(),
                                                                    content_scheme: content_scheme.clone(),
                                                                    history_visibility: history_visibility.clone(),
                                                                    plaintext_visible_services: plaintext_services.clone(),
                                                                    collaboration_role: None,
                                                                    encryption_floor: projection_floor,
                                                                },
                                                            )
                                                            .into_value();
                                                        state_store.write().save_realm_tree_projection(
                                                            realm_id.clone(),
                                                            projection_body,
                                                        );
                                                        // The canonical Realm transaction is
                                                        // complete at this point. Transition the
                                                        // wizard immediately; MLS initialization
                                                        // and backup below are post-create setup
                                                        // and must not leave a successfully created
                                                        // Realm looking like a retryable Seed draft.
                                                        realm_state.set(BootstrapProgressStrings::fill(
                                                            &strings.accepted,
                                                            &[("id", realm_id.clone())],
                                                        ));
                                                        create_step.set(NewRealmStep::Done);

                                                        let mut initial_mls_backup_id = None;
                                                        if crate::security_state::encryption_profile_is_encrypted(
                                                            &encryption_profile,
                                                        ) {
                                                            // Acquiring the accepted Seal view, verifying + pinning the
                                                            // governance proof, creating the epoch-0 group and landing
                                                            // `ak.mls.genesis` all live in the shared creator bootstrap so
                                                            // an interrupted attempt (unmount / network / closed tab) is
                                                            // replayed by the per-Realm bootstrap effect instead of leaving
                                                            // the Realm permanently unable to perform encrypted writes.
                                                            let bootstrap =
                                                                match crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
                                                                    &api,
                                                                    state_store,
                                                                    &realm_id,
                                                                    &actor,
                                                                    &device,
                                                                )
                                                                .await
                                                                {
                                                                    Ok(outcome) => outcome,
                                                                    Err(err) => {
                                                                        let message = BootstrapProgressStrings::fill(
                                                                            &strings.created_then_failed,
                                                                            &[
                                                                                ("id", realm_id.clone()),
                                                                                ("error", err.to_string()),
                                                                            ],
                                                                        );
                                                                        realm_create_busy.set(false);
                                                                        realm_state.set(message.clone());
                                                                        crate::components::feedback::toast_error(
                                                                            "feedback.realm_create_failed",
                                                                            vec![],
                                                                            Some(message),
                                                                        );
                                                                        return;
                                                                    }
                                                                };
                                                            if let Some(snapshot) = bootstrap.fresh_snapshot {
                                                                // §7.10: a brand-new Realm has no prior series, so
                                                                // this resolves to a genesis envelope — and it seeds
                                                                // the series-tail cache so post-commit continuous
                                                                // uploads chain successors without an extra read.
                                                                match crate::components::upload_mls_history_backup_now(
                                                                    &api,
                                                                    &base,
                                                                    &actor,
                                                                    &device,
                                                                    &realm_id,
                                                                    &snapshot,
                                                                )
                                                                .await
                                                                {
                                                                    Ok(backup_id) => {
                                                                        initial_mls_backup_id = Some(backup_id);
                                                                    }
                                                                    Err(err) => {
                                                                        tracing::warn!(
                                                                            error = %err,
                                                                            realm = %realm_id,
                                                                            "initial MLS history backup upload failed"
                                                                        );
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        let mut seeded_mls_ok = 0_usize;
                                                        let mut seeded_mls_err = String::new();
                                                        if crate::security_state::encryption_profile_is_encrypted(
                                                            &encryption_profile,
                                                        ) && !invitees.is_empty() {
                                                            match crate::views::realm_admin::submit_mls_admission_for_invitees(
                                                                &api,
                                                                state_store,
                                                                realm_id.clone(),
                                                                actor.clone(),
                                                                device.clone(),
                                                                invitees.clone(),
                                                            )
                                                            .await
                                                            {
                                                                Ok(count) => seeded_mls_ok = count,
                                                                Err(err) => seeded_mls_err = err.to_string(),
                                                            }
                                                        }

                                                        let fill = BootstrapProgressStrings::fill;
                                                        let mut steps = vec![fill(
                                                            &strings.created,
                                                            &[("id", realm_id.clone())],
                                                        )];
                                                        if invitees.is_empty() {
                                                            steps.push(strings.seeded_owner_only.clone());
                                                        } else {
                                                            steps.push(fill(
                                                                &strings.seeded_members,
                                                                &[("count", invitees.len().to_string())],
                                                            ));
                                                        }
                                                        steps.push(fill(
                                                            &strings.canonical_policy,
                                                            &[
                                                                ("discoverability", discoverability.clone()),
                                                                ("join_rule", join_rule.clone()),
                                                                (
                                                                    "history_visibility",
                                                                    history_visibility.clone(),
                                                                ),
                                                            ],
                                                        ));
                                                        if !plaintext_services.is_empty() {
                                                            steps.push(fill(
                                                                &strings.plaintext_services,
                                                                &[(
                                                                    "count",
                                                                    plaintext_services.len().to_string(),
                                                                )],
                                                            ));
                                                        }
                                                        if let Some(backup_id) = initial_mls_backup_id {
                                                            steps.push(fill(
                                                                &strings.mls_ready_backup,
                                                                &[(
                                                                    "id",
                                                                    short_protocol_id(&backup_id),
                                                                )],
                                                            ));
                                                        } else if crate::security_state::encryption_profile_is_encrypted(
                                                            &encryption_profile,
                                                        ) {
                                                            steps.push(strings.mls_ready_local.clone());
                                                        }
                                                        if !seeded_mls_err.is_empty() {
                                                            steps.push(fill(
                                                                &strings.mls_admission_failed,
                                                                &[("error", seeded_mls_err.clone())],
                                                            ));
                                                        } else if seeded_mls_ok > 0 {
                                                            steps.push(fill(
                                                                &strings.mls_welcome_queued,
                                                                &[("count", seeded_mls_ok.to_string())],
                                                            ));
                                                        }
                                                        if crate::event_builders::encryption_profile_uses_recommended_floor(
                                                            &encryption_profile,
                                                        ) {
                                                            steps.push(strings.floor_required.clone());
                                                        }

                                                        let message = steps.join(" · ");
                                                        realm_create_busy.set(false);
                                                        realm_state.set(message);
                                                        if crate::security_state::encryption_profile_is_encrypted(
                                                            &encryption_profile,
                                                        ) && let Some(signal) = backup_trigger_signal {
                                                            // Realm bootstrap creates the account MLS secret
                                                            // before the first encrypted message/card write,
                                                            // so attempt the recovery-public-key backup here
                                                            // instead of waiting for a later write hook.
                                                            crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                                                base.clone(),
                                                                api_token.clone(),
                                                                actor.clone(),
                                                                device.clone(),
                                                                state_store,
                                                                signal,
                                                            )
                                                            .await;
                                                        }
                                                    }
                                                    Err(error) => {
                                                        let message = if is_auth_expired_error(&error) {
                                                            strings.session_expired.clone()
                                                        } else {
                                                            BootstrapProgressStrings::fill(
                                                                &strings.create_failed,
                                                                &[("error", error.to_string())],
                                                            )
                                                        };
                                                        realm_create_busy.set(false);
                                                        realm_state.set(message.clone());
                                                        crate::components::feedback::toast_error(
                                                            "feedback.realm_create_failed",
                                                            vec![],
                                                            Some(message),
                                                        );
                                                    }
                                                }
                                                }
                                                Err(error) => {
                                                    let error_text = error.to_string();
                                                    let message = if crate::api_error::is_authenticated_session_unavailable_error(&error) {
                                                        strings.session_expired.clone()
                                                    } else {
                                                        BootstrapProgressStrings::fill(
                                                            &strings.invalid_server_url,
                                                            &[("error", error_text)],
                                                        )
                                                    };
                                                    realm_create_busy.set(false);
                                                    realm_state.set(message.clone());
                                                    crate::components::feedback::toast_error(
                                                        "feedback.realm_create_failed",
                                                        vec![],
                                                        Some(message),
                                                    );
                                                }
                                            }
                                        });
                                    }
                                },
                                {tr("setup.action.create_realm")}
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Done {
                    div { class: "setup-step-panel", "data-testid": "realm-setup-done",
                        div { class: "event-head",
                            span { {tr("setup.step.done.label")} }
                            span { {tr("setup.done.hint")} }
                        }
                        if has_created_realm {
                            div { class: "setup-summary-list",
                                div { class: "setup-summary-row",
                                    strong { {tr("setup.done.created_realm")} }
                                    span { class: "mono", title: "{created_realm_id_value}", "data-testid": "selected-realm-id", "{created_realm_id_label}" }
                                }
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { {tr("setup.state.bootstrap")} }
                                    span { class: "muted", "{realm_state_value}" }
                                }
                            }
                            div { class: "actions setup-nav-actions",
                                if realm_create_busy_value {
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        disabled: true,
                                        {tr("setup.action.finishing")}
                                    }
                                } else {
                                    Link {
                                        class: "primary",
                                        to: Route::Realm { realm_id: created_realm_id_value.clone() },
                                        {tr("setup.action.open_realm")}
                                    }
                                }
                            }
                        } else {
                            div { class: "muted", {tr("setup.done.empty")} }
                        }
                    }
                }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::realm_create_available;

    #[test]
    fn realm_create_does_not_wait_for_background_grant_rotation() {
        assert!(realm_create_available(true, true, true, true, false, false));
    }

    #[test]
    fn realm_create_still_waits_for_local_prerequisites() {
        assert!(!realm_create_available(
            false, true, true, true, false, false
        ));
        assert!(!realm_create_available(
            true, false, true, true, false, false
        ));
        assert!(!realm_create_available(
            true, true, false, true, false, false
        ));
        assert!(!realm_create_available(
            true, true, true, false, false, false
        ));
        assert!(!realm_create_available(true, true, true, true, true, false));
        assert!(!realm_create_available(true, true, true, true, false, true));
    }
}
