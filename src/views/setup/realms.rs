//! Realm bootstrap wizard (`ak.realm.create`) section component.

use dioxus::prelude::*;
use dioxus_router::Link;

use super::data::{
    CONTENT_SCHEME_OPTIONS, DISCOVERABILITY_OPTIONS, ENCRYPTION_PROFILE_OPTIONS,
    FEDERATION_POLICY_OPTIONS, HASH_PROFILE_OPTIONS, HISTORY_ACCESS_OPTIONS, JOIN_RULE_OPTIONS,
    SECURITY_CLASS_OPTIONS, option_hint,
};
use super::helpers::{
    content_scheme_constraint_hint, encryption_selection_is_e2ee, history_access_admits_prejoin,
    normalize_content_scheme, plaintext_services_for_policy, policy_combination_hint,
};
use super::model::{NEW_REALM_STEPS, NewRealmStep};
use crate::api_error::is_auth_expired_error;
use crate::components::HelpTip;
use crate::i18n::{tr, tr_args};
use crate::routes::Route;
use crate::transport::auth::authed_api_ready;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::short_protocol_id;

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
    canonical_policy: String,
    plaintext_services: String,
    mls_ready_local: String,
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
            canonical_policy: tr("setup.progress.canonical_policy"),
            plaintext_services: tr("setup.progress.plaintext_services"),
            mls_ready_local: tr("setup.progress.mls_ready_local"),
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

/// Recovery readiness has three states because `None` means the authoritative
/// server check has not completed (or could not complete), not that Recovery
/// is absent. Treating it as `false` makes a transient request race look like a
/// request to configure a second Recovery Key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EncryptedRealmRecoveryGateState {
    Ready,
    Checking,
    Missing,
}

async fn create_initial_default_discussion(
    api: &crate::transport::TransportClient,
    realm_id: &str,
    actor: &str,
) -> anyhow::Result<String> {
    let founding_realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let submitter = api.event_submitter()?.for_founding_realm(founding_realm);
    let create =
        crate::operation::ak_ops::initial_default_discussion_strand_create(realm_id, actor)?
            .build_sdk_event("inkson")?;
    let accepted = submitter.submit_sdk_event(&create).await?;
    let event_id = arkret_sdk::EventId::new(accepted.event_id).map_err(|error| {
        anyhow::anyhow!(tr_args(
            "setup.error.invalid_default_strand_id",
            &[("error", error.to_string())],
        ))
    })?;
    let strand_id = arkret_sdk::StrandId::from_event_id(&event_id).into_string();
    let set_default =
        crate::operation::ak_ops::realm_set_default_strand(realm_id, actor, &strand_id)?
            .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&set_default).await?;
    Ok(strand_id)
}

/// Accepted server policy is the account-level authority for Recovery setup.
/// Local metadata and the MLS backup marker remain useful offline fallbacks,
/// but a missing local cache must not contradict an already accepted policy.
fn encrypted_realm_recovery_gate_state(
    account_recovery_configured: Option<bool>,
    local_recovery_configured: bool,
    mls_recovery_backup_configured: bool,
) -> EncryptedRealmRecoveryGateState {
    if matches!(account_recovery_configured, Some(true))
        || local_recovery_configured
        || mls_recovery_backup_configured
    {
        EncryptedRealmRecoveryGateState::Ready
    } else if matches!(account_recovery_configured, Some(false)) {
        EncryptedRealmRecoveryGateState::Missing
    } else {
        EncryptedRealmRecoveryGateState::Checking
    }
}

#[component]
pub(super) fn RealmsSection(
    plaintext_service_id: String,
    secure_store_ready: bool,
    token: Signal<String>,
    account_recovery_configured: Signal<Option<bool>>,
    mut selected_realm_id: Signal<String>,
    // State signals are owned by the parent `SetupPanel` so the wizard's
    // in-progress draft survives switching between setup sections (the
    // sections are conditionally rendered, so locally-owned hooks would reset
    // on every section change).
    mut create_step: Signal<NewRealmStep>,
    mut realm_title: Signal<String>,
    mut realm_summary: Signal<String>,
    mut realm_alias: Signal<String>,
    mut realm_discoverability: Signal<String>,
    mut realm_policy_join_rule: Signal<String>,
    mut realm_policy_history_access: Signal<String>,
    mut realm_encryption_profile: Signal<String>,
    mut realm_content_scheme: Signal<String>,
    mut realm_security_class: Signal<String>,
    mut realm_federation_policy: Signal<String>,
    mut realm_digest_algorithm: Signal<String>,
    mut realm_state: Signal<String>,
    mut realm_create_busy: Signal<bool>,
    mut created_realm_id: Signal<String>,
    mut pending_recovery_gate: Signal<bool>,
) -> Element {
    let active_account = crate::app::SessionContext::get().active_account;
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let has_session = !token().trim().is_empty();

    let realm_discoverability_selected = use_memo(move || Some(realm_discoverability()));
    let realm_policy_join_rule_selected = use_memo(move || Some(realm_policy_join_rule()));
    let realm_policy_history_access_selected =
        use_memo(move || Some(realm_policy_history_access()));
    let realm_encryption_profile_selected = use_memo(move || Some(realm_encryption_profile()));
    let realm_content_scheme_selected = use_memo(move || Some(realm_content_scheme()));
    let realm_security_class_selected = use_memo(move || Some(realm_security_class()));
    let realm_federation_policy_selected = use_memo(move || Some(realm_federation_policy()));
    let realm_digest_algorithm_selected = use_memo(move || Some(realm_digest_algorithm()));

    let active_create_step = create_step();
    let title_value = realm_title();
    let summary_value = realm_summary();
    let alias_value = realm_alias();
    let discoverability_value = realm_discoverability();
    let join_rule_value = realm_policy_join_rule();
    let history_access_value = realm_policy_history_access();
    let encryption_profile_value = realm_encryption_profile();
    let content_scheme_value = realm_content_scheme();
    let encryption_is_e2ee = encryption_selection_is_e2ee(&encryption_profile_value);
    let history_requires_exporter_aead =
        encryption_is_e2ee && history_access_admits_prejoin(&history_access_value);
    let content_scheme_warning = content_scheme_constraint_hint(
        encryption_is_e2ee,
        &history_access_value,
        &content_scheme_value,
    );
    let security_class_value = realm_security_class();
    let federation_policy_value = realm_federation_policy();
    let digest_algorithm_value = realm_digest_algorithm();
    let federation_policy_open_forbidden = security_class_value == "high_assurance";

    let discoverability_help = [
        tr("setup.axis.discoverability.question"),
        option_hint(
            &DISCOVERABILITY_OPTIONS,
            &discoverability_value,
            "setup.axis.discoverability.unset",
        ),
    ]
    .join(" ");
    let join_rule_help = [
        tr("setup.axis.join_rule.question"),
        option_hint(
            &JOIN_RULE_OPTIONS,
            &join_rule_value,
            "setup.axis.join_rule.unset",
        ),
    ]
    .join(" ");
    let history_access_help = [
        tr("setup.axis.history_access.question"),
        option_hint(
            &HISTORY_ACCESS_OPTIONS,
            &history_access_value,
            "setup.axis.history_access.unset",
        ),
    ]
    .join(" ");
    let encryption_help = [
        tr("setup.axis.encryption.question"),
        option_hint(
            &ENCRYPTION_PROFILE_OPTIONS,
            &encryption_profile_value,
            "setup.axis.encryption.unset",
        ),
        tr("setup.axis.encryption.locked"),
    ]
    .join(" ");
    let mut content_scheme_help_parts = vec![
        tr("setup.axis.content_scheme.question"),
        option_hint(
            &CONTENT_SCHEME_OPTIONS,
            &content_scheme_value,
            "setup.axis.content_scheme.unset",
        ),
        tr("setup.axis.content_scheme.capability_only"),
    ];
    if history_requires_exporter_aead {
        content_scheme_help_parts.push(tr("setup.axis.content_scheme.prejoin_forced"));
    }
    let content_scheme_help = content_scheme_help_parts.join(" ");
    let security_class_help = [
        tr("setup.axis.security_class.question"),
        option_hint(
            &SECURITY_CLASS_OPTIONS,
            &security_class_value,
            "setup.axis.security_class.unset",
        ),
    ]
    .join(" ");
    let mut federation_policy_help_parts = vec![
        tr("setup.axis.federation_policy.question"),
        option_hint(
            &FEDERATION_POLICY_OPTIONS,
            &federation_policy_value,
            "setup.axis.federation_policy.unset",
        ),
    ];
    if federation_policy_open_forbidden {
        federation_policy_help_parts.push(tr("setup.axis.federation_policy.high_assurance"));
    }
    let federation_policy_help = federation_policy_help_parts.join(" ");
    let hash_profile_help = [
        tr("setup.axis.hash_profile.question"),
        option_hint(
            &HASH_PROFILE_OPTIONS,
            &digest_algorithm_value,
            "setup.axis.hash_profile.unset",
        ),
    ]
    .join(" ");

    let realm_state_value = realm_state();
    let realm_create_busy_value = realm_create_busy();
    let created_realm_id_value = created_realm_id();
    let has_created_realm = !created_realm_id_value.trim().is_empty();
    let created_realm_id_label = short_protocol_id(&created_realm_id_value);
    let current_visibility_hint = policy_combination_hint(
        &discoverability_value,
        &join_rule_value,
        &history_access_value,
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
        NewRealmStep::Create => basics_ready && boundary_ready,
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

    // The authoritative recovery check is asynchronous. If the gate was
    // opened from an earlier negative result, close it as soon as either the
    // server policy or a local fallback proves Recovery is configured.
    use_effect(move || {
        let gate_state =
            active_account().map_or(EncryptedRealmRecoveryGateState::Checking, |_account| {
                let store = state_store.read();
                encrypted_realm_recovery_gate_state(
                    account_recovery_configured(),
                    crate::views::recovery::recovery_options_configured(&store),
                    crate::components::mls_recovery_backup_configured(&store),
                )
            });
        if gate_state == EncryptedRealmRecoveryGateState::Ready && pending_recovery_gate() {
            pending_recovery_gate.set(false);
        }
    });

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
                        div { class: "workflow-form setup-form-grid",
                            div { class: "setup-field",
                                Label {
                                    html_for: "realm-title-input-input",
                                    {tr("setup.field.realm_title")}
                                    span { class: "required-indicator", "aria-hidden": "true", " *" }
                                }
                                Input {
                                    id: "realm-title-input-input",
                                    "data-testid": "realm-title-input",
                                    required: true,
                                    "aria-required": "true",
                                    value: "{title_value}",
                                    placeholder: tr("setup.field.realm_title_placeholder"),
                                    oninput: move |event: FormEvent| realm_title.set(event.value())
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
                            div { class: "setup-field setup-field-span-2",
                                Label { html_for: "realm-summary-input-input", {tr("setup.field.summary")} }
                                Textarea {
                                    id: "realm-summary-input-input",
                                    "data-testid": "realm-summary-input",
                                    value: "{summary_value}",
                                    rows: "2",
                                    placeholder: tr("setup.field.realm_summary_placeholder"),
                                    oninput: move |event: FormEvent| realm_summary.set(event.value())
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
                        div { class: "setup-axis-grid",
                            div { class: "metric directory-axis-card setup-axis-card",
                                div { class: "setup-axis-card-heading",
                                    strong { {tr("setup.axis.discoverability")} }
                                    HelpTip { text: discoverability_help }
                                }
                                div { class: "workflow-form setup-field",
                                    Select::<String> {
                                        "data-testid": "realm-discoverability-input",
                                        "aria-label": tr("setup.axis.discoverability"),
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
                                }
                            }
                            div { class: "metric directory-axis-card setup-axis-card",
                                div { class: "setup-axis-card-heading",
                                    strong { {tr("setup.axis.join_rule")} }
                                    HelpTip { text: join_rule_help }
                                }
                                div { class: "workflow-form setup-field",
                                    Select::<String> {
                                        "data-testid": "realm-policy-join-rule-input",
                                        "aria-label": tr("setup.axis.join_rule"),
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
                                }
                            }
                            div { class: "metric directory-axis-card setup-axis-card",
                                div { class: "setup-axis-card-heading",
                                    strong { {tr("setup.axis.history_access")} }
                                    HelpTip { text: history_access_help }
                                }
                                div { class: "workflow-form setup-field",
                                    Select::<String> {
                                        "data-testid": "realm-policy-history-access-input",
                                        "aria-label": tr("setup.axis.history_access"),
                                        value: Some(realm_policy_history_access_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                if history_access_admits_prejoin(&v)
                                                    && encryption_selection_is_e2ee(
                                                        &realm_encryption_profile(),
                                                    )
                                                {
                                                    realm_content_scheme.set(
                                                        "mls_exporter_aead_v1".to_owned(),
                                                    );
                                                }
                                                realm_policy_history_access.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in HISTORY_ACCESS_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: tr(label),
                                                {tr(label)}
                                            }
                                        }
                                    }
                                }
                            }
                            // These create-locked Realm fields are shown here so the user
                            // makes the permanent choice intentionally.
                            div { class: "metric directory-axis-card setup-axis-card",
                                div { class: "setup-axis-card-heading",
                                    strong { {tr("setup.axis.encryption")} }
                                    HelpTip { text: encryption_help }
                                }
                                div { class: "workflow-form setup-field",
                                    Select::<String> {
                                        "data-testid": "realm-encryption-profile-input",
                                        "aria-label": tr("setup.axis.encryption"),
                                        value: Some(realm_encryption_profile_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                let encrypted =
                                                    encryption_selection_is_e2ee(&v);
                                                if encrypted
                                                    && history_access_admits_prejoin(
                                                        &realm_policy_history_access(),
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
                                }
                            }
                            // encryption-and-audit.md §2.10 — `content_scheme`
                            // capability axis. Only meaningful for E2EE realms;
                            // orthogonal to history access (the runtime
                            // delivery toggle). Default exporter-AEAD.
                            if encryption_is_e2ee {
                                div { class: "metric directory-axis-card setup-axis-card",
                                    div { class: "setup-axis-card-heading",
                                        strong { {tr("setup.axis.content_scheme")} }
                                        HelpTip { text: content_scheme_help }
                                    }
                                    div { class: "workflow-form setup-field",
                                        Select::<String> {
                                            "data-testid": "realm-content-scheme-input",
                                            "aria-label": tr("setup.axis.content_scheme"),
                                            value: Some(realm_content_scheme_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    if v == "mls_rfc9420"
                                                        && history_access_admits_prejoin(
                                                            &realm_policy_history_access(),
                                                        )
                                                    {
                                                        realm_policy_history_access
                                                            .set("since_join".to_owned());
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
                                        if let Some(hint) = content_scheme_warning {
                                            div { class: "inline-warn",
                                                span { class: "body", "{hint}" }
                                            }
                                        }
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card setup-axis-card",
                                div { class: "setup-axis-card-heading",
                                    strong { {tr("setup.axis.security_class")} }
                                    HelpTip { text: security_class_help }
                                }
                                div { class: "workflow-form setup-field",
                                    Select::<String> {
                                        "data-testid": "realm-security-class-input",
                                        "aria-label": tr("setup.axis.security_class"),
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
                                }
                            }
                        }

                        // Spec realm-and-space.md §2.3 advanced
                        // fields — collapsed by default. All
                        // two are create-locked. Defaults
                        // (restricted / sha256) suit the dev +
                        // small-deployment cases; production operators
                        // tweak as needed. The notary signer is derived from
                        // verified Station evidence, not selected by
                        // an unbacked profile string.
                        details { class: "setup-advanced",
                            "data-testid": "realm-advanced-config",
                            summary { class: "setup-advanced-summary",
                                {tr("setup.boundary.advanced_summary")}
                            }
                            div { class: "setup-axis-grid setup-advanced-grid",
                                div { class: "metric directory-axis-card setup-axis-card",
                                    div { class: "setup-axis-card-heading",
                                        strong { {tr("setup.axis.federation_policy")} }
                                        HelpTip { text: federation_policy_help }
                                    }
                                    div { class: "workflow-form setup-field",
                                        Select::<String> {
                                            "data-testid": "realm-federation-policy-input",
                                            "aria-label": tr("setup.axis.federation_policy"),
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
                                    }
                                }
                                div { class: "metric directory-axis-card setup-axis-card",
                                    div { class: "setup-axis-card-heading",
                                        strong { {tr("setup.axis.hash_profile")} }
                                        HelpTip { text: hash_profile_help }
                                    }
                                    div { class: "workflow-form setup-field",
                                        Select::<String> {
                                            "data-testid": "realm-hash-profile-input",
                                            "aria-label": tr("setup.axis.hash_profile"),
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
                                {tr("setup.action.next_create")}
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Create {
                    div { class: "setup-step-panel",
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
                                        let history_access = realm_policy_history_access();
                                        let encryption_profile = realm_encryption_profile();
                                        let content_scheme = normalize_content_scheme(
                                            encryption_selection_is_e2ee(
                                                &encryption_profile,
                                            ),
                                            &history_access,
                                            &realm_content_scheme(),
                                        );
                                        if let Err(error) =
                                            crate::event_builders::validate_realm_history_content_scheme_for_profile(
                                                &encryption_profile,
                                                &history_access,
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
                                        if encryption_selection_is_e2ee(
                                            &encryption_profile,
                                        )
                                        {
                                            let recovery_gate_state = active_account().map_or(
                                                EncryptedRealmRecoveryGateState::Checking,
                                                |_account| {
                                                    let store = state_store.read();
                                                    encrypted_realm_recovery_gate_state(
                                                        account_recovery_configured(),
                                                        crate::views::recovery::recovery_options_configured(
                                                            &store,
                                                        ),
                                                        crate::components::mls_recovery_backup_configured(
                                                            &store,
                                                        ),
                                                    )
                                                },
                                            );
                                            match recovery_gate_state {
                                                EncryptedRealmRecoveryGateState::Ready => {}
                                                EncryptedRealmRecoveryGateState::Missing => {
                                                    pending_recovery_gate.set(true);
                                                    return;
                                                }
                                                EncryptedRealmRecoveryGateState::Checking => {
                                                    let message = tr("setup.recovery_gate.checking");
                                                    realm_state.set(message);
                                                    crate::components::feedback::toast_info(
                                                        "setup.recovery_gate.checking",
                                                        vec![],
                                                    );
                                                    return;
                                                }
                                            }
                                        }
                                        realm_create_busy.set(true);
                                        realm_state.set(tr("setup.blocker.creating"));
                                        let Some(account) = active_account() else {
                                            realm_create_busy.set(false);
                                            realm_state.set(tr("setup.blocker.account_context_unavailable"));
                                            return;
                                        };
                                        let authority = account.authority.clone();
                                        let account_device_id = account.device_id.clone();
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
                                        let digest_algorithm = realm_digest_algorithm();
                                        let actor = active_account()
                                            .map(|account| account.principal_id().to_string())
                                            .unwrap_or_default();
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
                                                        &history_access,
                                                        &encryption_profile,
                                                        &security_class,
                                                        &federation_policy,
                                                        &digest_algorithm,
                                                        &trust_domain,
                                                        plaintext_services.clone(),
                                                        (!alias.trim().is_empty()).then(|| alias.trim()),
                                                        Some(content_scheme.as_str()),
                                                    ).await {
                                                    Ok(realm) => {
                                                        // R15: ak.realm.create now returns
                                                        // RealmCreateResult with the new
                                                        // `ak:realm:*` id under `realm_id`.
                                                        let realm_id = realm.realm_id.clone();
                                                        if realm.first_commit.realm_id.as_str() != realm_id
                                                            || realm.first_commit.stream_position != 0
                                                        {
                                                            let error = format!(
                                                                "Realm founding returned a non-genesis RealmCommit {}",
                                                                realm.first_commit.commit_id
                                                            );
                                                            let message = BootstrapProgressStrings::fill(
                                                                &strings.created_then_failed,
                                                                &[("id", realm_id.clone()), ("error", error)],
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
                                                        tracing::debug!(
                                                            realm_id = %realm_id,
                                                            commit_id = %realm.first_commit.commit_id,
                                                            phase = "realm_founding",
                                                            state = "committed",
                                                            "Realm setup phase completed"
                                                        );
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
                                                        let projection_admins = if actor.trim().is_empty() {
                                                            Vec::new()
                                                        } else {
                                                            vec![actor.clone()]
                                                        };
                                                        let projection_body =
                                                            crate::realm_tree::OptimisticRealmTreeProjection::realm(
                                                                crate::realm_tree::RealmProjectionInput {
                                                                    owner: actor.clone(),
                                                                    admins: projection_admins,
                                                                    members: projection_members,
                                                                    title: title.clone(),
                                                                    summary: summary.clone(),
                                                                    discoverability: discoverability.clone(),
                                                                    history_access: history_access.clone(),
                                                                    plaintext_visible_services: plaintext_services.clone(),
                                                                    collaboration_role: None,
                                                                },
                                                            )
                                                            .into_value();
                                                        state_store.write().save_realm_tree_projection(
                                                            realm_id.clone(),
                                                            projection_body,
                                                        );
                                                        // The first authority-signed RealmCommit is the sole
                                                        // completion boundary. Keep the committed Realm
                                                        // reachable even when later product initialization
                                                        // (default discussion / MLS artifacts) needs recovery.
                                                        create_step.set(NewRealmStep::Done);
                                                        if let Err(err) = create_initial_default_discussion(
                                                            &api,
                                                            &realm_id,
                                                            &actor,
                                                        )
                                                        .await
                                                        {
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
                                                        // The accepted Realm remains on Done throughout
                                                        // post-create setup; keep its progress visible while
                                                        // MLS initialization and backup finish below.
                                                        realm_state.set(BootstrapProgressStrings::fill(
                                                            &strings.accepted,
                                                            &[("id", realm_id.clone())],
                                                        ));

                                                        if encryption_selection_is_e2ee(
                                                            &encryption_profile,
                                                        ) {
                                                            tracing::debug!(
                                                                realm_id = %realm_id,
                                                                phase = "mls_genesis",
                                                                state = "pending",
                                                                "Realm setup phase started"
                                                            );
                                                            // Acquiring the accepted Seal view, verifying + pinning the
                                                            // governance proof, creating the epoch-0 group and landing
                                                            // `ak.mls.genesis` all live in the shared creator bootstrap so
                                                            // an interrupted attempt (unmount / network / closed tab) is
                                                            // replayed by the per-Realm bootstrap effect instead of leaving
                                                            // the Realm permanently unable to perform encrypted writes.
                                                            match crate::mls::creator_bootstrap::ensure_creator_realm_mls_genesis(
                                                                     &api,
                                                                     &crate::app::runtime_adapter::state_store_handle(state_store),
                                                                     &realm_id,
                                                                     &authority,
                                                                     &account_device_id,
                                                                )
                                                                .await
                                                                {
                                                                    Ok(()) => {
                                                                        tracing::debug!(
                                                                            realm_id = %realm_id,
                                                                            phase = "mls_genesis",
                                                                            state = "accepted",
                                                                            "Realm setup phase completed"
                                                                        );
                                                                    }
                                                                    Err(err) => {
                                                                        tracing::warn!(
                                                                            realm_id = %realm_id,
                                                                            phase = "mls_genesis",
                                                                            state = "failed",
                                                                            error = %err,
                                                                            "Realm setup phase failed"
                                                                        );
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
                                                                }
                                                        }

                                                        let fill = BootstrapProgressStrings::fill;
                                                        let mut steps = vec![fill(
                                                            &strings.created,
                                                            &[("id", realm_id.clone())],
                                                        )];
                                                        steps.push(fill(
                                                            &strings.canonical_policy,
                                                            &[
                                                                ("discoverability", discoverability.clone()),
                                                                ("join_rule", join_rule.clone()),
                                                                (
                                                                    "history_access",
                                                                    history_access.clone(),
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
                                                        if encryption_selection_is_e2ee(
                                                            &encryption_profile,
                                                        ) {
                                                            steps.push(strings.mls_ready_local.clone());
                                                        }
                                                        if crate::event_builders::encryption_profile_uses_recommended_floor(
                                                            &encryption_profile,
                                                        ) {
                                                            steps.push(strings.floor_required.clone());
                                                        }

                                                        let message = steps.join(" · ");
                                                        realm_create_busy.set(false);
                                                        realm_state.set(message);
                                                        if encryption_selection_is_e2ee(
                                                            &encryption_profile,
                                                        ) && let Some(signal) = backup_trigger_signal {
                                                            // Realm bootstrap creates the account MLS secret
                                                            // before the first encrypted message/card write,
                                                            // so attempt the recovery-public-key backup here
                                                            // instead of waiting for a later write hook.
                                                            crate::components::maybe_auto_backup_mls_after_encrypted_write(
                                                                 base.clone(),
                                                                 api_token.clone(),
                                                                 authority.clone(),
                                                                 actor.clone(),
                                                                 account_device_id.to_string(),
                                                                crate::app::runtime_adapter::state_store_handle(
                                                                    state_store,
                                                                ),
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
    use super::{
        EncryptedRealmRecoveryGateState, encrypted_realm_recovery_gate_state,
        realm_create_available,
    };

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

    #[test]
    fn encrypted_realm_accepts_server_recovery_policy_without_local_cache() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(Some(true), false, false),
            EncryptedRealmRecoveryGateState::Ready
        );
    }

    #[test]
    fn encrypted_realm_waits_while_server_state_is_unknown() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(None, false, false),
            EncryptedRealmRecoveryGateState::Checking
        );
    }

    #[test]
    fn encrypted_realm_prompts_only_after_server_confirms_recovery_is_missing() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(Some(false), false, false),
            EncryptedRealmRecoveryGateState::Missing
        );
    }

    #[test]
    fn encrypted_realm_keeps_local_recovery_fallbacks() {
        assert_eq!(
            encrypted_realm_recovery_gate_state(None, true, false),
            EncryptedRealmRecoveryGateState::Ready
        );
        assert_eq!(
            encrypted_realm_recovery_gate_state(None, false, true),
            EncryptedRealmRecoveryGateState::Ready
        );
    }
}
