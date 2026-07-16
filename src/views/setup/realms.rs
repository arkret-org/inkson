//! Realm bootstrap wizard (`ak.realm.create`) section component.

use dioxus::prelude::*;
use dioxus_router::Link;

use super::data::{
    ANCHOR_PROFILE_OPTIONS, CONTENT_SCHEME_OPTIONS, DISCOVERABILITY_OPTIONS,
    ENCRYPTION_PROFILE_OPTIONS, FEDERATION_POLICY_OPTIONS, HASH_PROFILE_OPTIONS,
    HISTORY_VISIBILITY_OPTIONS, JOIN_RULE_OPTIONS, SECURITY_CLASS_OPTIONS,
};
use super::helpers::{
    content_scheme_constraint_hint, history_visibility_admits_prejoin, normalize_content_scheme,
    parse_seed_members, plaintext_services_for_policy, policy_combination_hint,
};
use super::model::{NEW_REALM_STEPS, NewRealmStep};
use crate::api_error::is_auth_expired_error;
use crate::config::LocalConfigStore;
use crate::routes::Route;
use crate::transport::auth::authed_api;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::{display_name_for_did, short_protocol_id};

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
    mut recovery_gate_acknowledged: Signal<bool>,
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
    let create_blocker = if !has_session {
        Some("Sign in before creating a Realm.")
    } else if !secure_store_ready {
        Some("Device signing storage is still starting. Try again in a moment.")
    } else if realm_create_busy_value {
        Some("Creating Realm...")
    } else {
        None
    };
    let can_advance_step = match active_create_step {
        NewRealmStep::Basics => basics_ready,
        NewRealmStep::Boundary => boundary_ready,
        NewRealmStep::Seed => basics_ready && boundary_ready,
        NewRealmStep::Done => has_created_realm,
    };
    let can_create_realm = has_session
        && basics_ready
        && boundary_ready
        && secure_store_ready
        && !realm_create_busy_value;

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
                "aria-label": "Set up recovery before creating an encrypted Realm",
                div { class: "modal event",
                    div { class: "modal-head event-head",
                        h3 { "Set up recovery first" }
                        span { class: "muted", "encrypted Realm" }
                    }
                    div { class: "modal-body",
                        div { class: "muted",
                            "This Realm is end-to-end encrypted. If you lose this device and have no Recovery Key or backup configured, its contents are permanently unrecoverable. Set up your 24-word Recovery Key and back up your keys before creating it."
                        }
                        div { class: "muted",
                            "data-testid": "encrypted-realm-recovery-gate-override-hint",
                            "If you continue without recovery, press Create realm again to proceed at your own risk."
                        }
                    }
                    div { class: "modal-foot actions",
                        Link {
                            class: "primary",
                            "data-testid": "encrypted-realm-recovery-gate-setup",
                            to: Route::SettingsRecovery,
                            onclick: move |_| pending_recovery_gate.set(false),
                            "Set up Recovery Key"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "encrypted-realm-recovery-gate-override",
                            onclick: move |_| {
                                // personal_node override: accept single-point-of-failure
                                // risk for this session and let the next Create proceed.
                                recovery_gate_acknowledged.set(true);
                                pending_recovery_gate.set(false);
                            },
                            "Continue without recovery"
                        }
                    }
                }
            }
        }
        div { class: "setup-shell new-realm-shell", "data-testid": "realm-lifecycle-strand",
            div { class: "setup-column",
                div { class: "event new-realm-hero", "data-testid": "realm-setup-guide",
                    div { class: "event-head",
                        span { "New Realm" }
                    }
                    h2 { class: "settings-content-title", "Create a Realm" }
                    div { class: "muted",
                        "A Realm is the security / sync / E2EE boundary. The recommended mode is MLS with metadata_encryption_floor=e2ee_required and content_encryption_floor=e2ee_required."
                    }
                }

                div { class: "event new-realm-stepper",
                    div { class: "event-head",
                        span { "Create steps" }
                        span { "{active_create_step.number()} / 4" }
                    }
                    div { class: "setup-step-list",
                        for step in NEW_REALM_STEPS {
                            Button {
                                variant: if active_create_step == step { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                disabled: step == NewRealmStep::Done && !has_created_realm,
                                onclick: move |_| create_step.set(step),
                                span { class: "setup-step-index", "{step.number()}" }
                                span { class: "setup-step-label",
                                    strong { "{step.label()}" }
                                    small { "{step.subtitle()}" }
                                }
                            }
                        }
                    }

                if active_create_step == NewRealmStep::Basics {
                    div { class: "setup-step-panel",
                        div { class: "event-head",
                            span { "Basics" }
                            span { "required title" }
                        }
                        div { class: "workflow-form setup-form-grid",
                            div { class: "setup-field",
                                Label { html_for: "realm-title-input-input", "Realm title" }
                                Input {
                                    id: "realm-title-input-input",
                                    "data-testid": "realm-title-input",
                                    value: "{title_value}",
                                    placeholder: "Engineering, Research, Design system...",
                                    oninput: move |event: FormEvent| realm_title.set(event.value())
                                }
                            }
                            div { class: "setup-field setup-field-span-2",
                                Label { html_for: "realm-summary-input-input", "Summary" }
                                Textarea {
                                    id: "realm-summary-input-input",
                                    "data-testid": "realm-summary-input",
                                    value: "{summary_value}",
                                    rows: "3",
                                    placeholder: "What this Realm is for.",
                                    oninput: move |event: FormEvent| realm_summary.set(event.value())
                                }
                            }
                            div { class: "setup-field",
                                Label { html_for: "realm-alias-input-input", "Realm alias (optional)" }
                                Input {
                                    id: "realm-alias-input-input",
                                    "data-testid": "realm-alias-input",
                                    value: "{alias_value}",
                                    placeholder: "engineering",
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
                                "Next: Boundary"
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Boundary {
                    div { class: "setup-step-panel",
                        div { class: "event-head",
                            span { "Boundary" }
                            span { "three independent axes" }
                        }
                        div { class: "setup-axis-grid",
                            div { class: "metric directory-axis-card",
                                strong { "Discoverability" }
                                div { class: "workflow-form setup-field",
                                    label { "Who can discover that this Realm exists?" }
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
                                                text_value: "{label}",
                                                "{label}"
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        "{DISCOVERABILITY_OPTIONS.iter().find(|(value, _, _)| *value == discoverability_value).map(|(_, _, hint)| *hint).unwrap_or(\"Discovery posture is not set.\")}"
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card",
                                strong { "Join rule" }
                                div { class: "workflow-form setup-field",
                                    label { "How does a principal become a member?" }
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
                                                text_value: "{label}",
                                                "{label}"
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        "{JOIN_RULE_OPTIONS.iter().find(|(value, _, _)| *value == join_rule_value).map(|(_, _, hint)| *hint).unwrap_or(\"Join path is not set.\")}"
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card",
                                strong { "History visibility" }
                                div { class: "workflow-form setup-field",
                                    label { "What history can new members read?" }
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
                                                        "mls-exporter-aead-v1".to_owned(),
                                                    );
                                                }
                                                realm_policy_history_visibility.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in HISTORY_VISIBILITY_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: "{label}",
                                                "{label}"
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        "{HISTORY_VISIBILITY_OPTIONS.iter().find(|(value, _, _)| *value == history_visibility_value).map(|(_, _, hint)| *hint).unwrap_or(\"History scope is not set.\")}"
                                    }
                                }
                            }
                            // These create-locked Realm fields are shown here so the user
                            // makes the permanent choice intentionally.
                            div { class: "metric directory-axis-card",
                                strong { "Encryption" }
                                div { class: "workflow-form setup-field",
                                    label { "Protection" }
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
                                                        "mls-exporter-aead-v1".to_owned(),
                                                    );
                                                }
                                                realm_encryption_profile.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in ENCRYPTION_PROFILE_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: "{label}",
                                                "{label}"
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        "{ENCRYPTION_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == encryption_profile_value).map(|(_, _, hint)| *hint).unwrap_or(\"Encryption profile is not set.\")}"
                                    }
                                    div { class: "muted",
                                        "Locked after creation."
                                    }
                                }
                            }
                            // encryption-and-audit.md §2.10 — `content_scheme`
                            // capability axis. Only meaningful for E2EE realms;
                            // orthogonal to History visibility (the runtime
                            // delivery toggle). Default exporter-AEAD.
                            if encryption_is_e2ee {
                                div { class: "metric directory-axis-card",
                                    strong { "Content scheme" }
                                    div { class: "workflow-form setup-field",
                                        label { "Which MLS content scheme should this Realm use?" }
                                        Select::<String> {
                                            "data-testid": "realm-content-scheme-input",
                                            value: Some(realm_content_scheme_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    if v == "mls-rfc9420"
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
                                                    text_value: "{label}",
                                                    disabled: history_requires_exporter_aead
                                                        && *option_value == "mls-rfc9420",
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{CONTENT_SCHEME_OPTIONS.iter().find(|(value, _, _)| *value == content_scheme_value).map(|(_, _, hint)| *hint).unwrap_or(\"Content scheme is not set.\")}"
                                        }
                                        if history_requires_exporter_aead {
                                            div { class: "muted",
                                                "Pre-join history uses content_scheme=mls-exporter-aead-v1."
                                            }
                                        }
                                        if let Some(hint) = content_scheme_warning {
                                            div { class: "inline-warn",
                                                span { class: "body", "{hint}" }
                                            }
                                        }
                                        div { class: "muted",
                                            "Capability only — actual delivery still follows History visibility."
                                        }
                                    }
                                }
                            }
                            div { class: "metric directory-axis-card",
                                strong { "Security class" }
                                div { class: "workflow-form setup-field",
                                    label { "Posture for federation and audit defaults." }
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
                                                text_value: "{label}",
                                                "{label}"
                                            }
                                        }
                                    }
                                    div { class: "muted",
                                        "{SECURITY_CLASS_OPTIONS.iter().find(|(value, _, _)| *value == security_class_value).map(|(_, _, hint)| *hint).unwrap_or(\"Security class is not set.\")}"
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
                                "Advanced (federation policy / seal profile / hash profile)"
                            }
                            div { class: "setup-axis-grid setup-advanced-grid",
                                div { class: "metric directory-axis-card",
                                    strong { "Federation policy" }
                                    div { class: "workflow-form setup-field",
                                        label { "How does this Realm interoperate with other deployments?" }
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
                                                    text_value: "{label}",
                                                    disabled: federation_policy_open_forbidden && *option_value == "open",
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{FEDERATION_POLICY_OPTIONS.iter().find(|(value, _, _)| *value == federation_policy_value).map(|(_, _, hint)| *hint).unwrap_or(\"Federation policy is not set.\")}"
                                        }
                                        if federation_policy_open_forbidden {
                                            div { class: "muted",
                                                "High assurance allows only restricted, closed, or quarantine federation."
                                            }
                                        }
                                    }
                                }
                                div { class: "metric directory-axis-card",
                                    strong { "Seal profile" }
                                    div { class: "workflow-form setup-field",
                                        label { "Who signs durable seals for this Realm?" }
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
                                                    text_value: "{label}",
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{ANCHOR_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == notary_profile_value).map(|(_, _, hint)| *hint).unwrap_or(\"Seal profile is not set.\")}"
                                        }
                                    }
                                }
                                div { class: "metric directory-axis-card",
                                    strong { "Hash profile" }
                                    div { class: "workflow-form setup-field",
                                        label { "Digest algorithm for canonical hashing." }
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
                                                    text_value: "{label}",
                                                    "{label}"
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "{HASH_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == digest_algorithm_value).map(|(_, _, hint)| *hint).unwrap_or(\"Hash profile is not set.\")}"
                                        }
                                    }
                                }
                            }
                        }

                        if let Some((tone, heading, body)) = current_visibility_hint {
                            div { class: if tone == "error" { "inline-error" } else { "inline-warn" },
                                span { class: "body",
                                    strong { "{heading}" }
                                    " {body}"
                                }
                            }
                        }

                        div { class: "actions setup-nav-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "new-realm-back-button",
                                onclick: move |_| create_step.set(active_create_step.previous()),
                                "Back"
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "new-realm-next-button",
                                disabled: !can_advance_step,
                                onclick: move |_| create_step.set(active_create_step.next()),
                                "Next: Seed"
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Seed {
                    div { class: "setup-step-panel",
                        div { class: "event-head",
                            span { "Seed members" }
                            span { "optional" }
                        }
                        div { class: "workflow-form setup-form-grid",
                            div { class: "setup-field setup-field-span-2",
                                Label { html_for: "seed-members-input-input", "Initial members" }
                                Textarea {
                                    id: "seed-members-input-input",
                                    "data-testid": "seed-members-input",
                                    value: "{seed_members_value}",
                                    rows: "4",
                                    placeholder: "did:webvh:<scid>:alice.example\ndid:webvh:<scid>:bob.example",
                                    oninput: move |event: FormEvent| seed_members.set(event.value())
                                }
                                div { class: "muted", "One DID per line, or comma-separated. Handle invites require directory resolution." }
                            }
                            div { class: "setup-field setup-field-span-2",
                                label { "Seed preview" }
                                if seed_member_count == 0 {
                                    div { class: "muted", "No extra seed members." }
                                } else {
                                    div { class: "setup-chip-wrap",
                                        for member in parsed_seed_members.iter().take(8) {
                                            {
                                                let member_label =
                                                    display_name_for_did(&state_store.read(), member);
                                                rsx! {
                                                    span { class: "badge blue", title: "{member}", "{member_label}" }
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "muted", "{seed_member_count} principal(s) will be included in the bootstrap request." }
                            }
                        }
                        if let Some(blocker) = create_blocker {
                            div { class: "inline-warn", "data-testid": "realm-create-blocker",
                                span { class: "body", "{blocker}" }
                            }
                        }
                        if realm_state_value != "Draft not created yet" {
                            div { class: "setup-summary-list", "data-testid": "realm-create-status",
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { "Bootstrap state" }
                                    span { class: "muted", "{realm_state_value}" }
                                }
                            }
                        }
                        div { class: "actions setup-nav-actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "new-realm-back-button",
                                onclick: move |_| create_step.set(active_create_step.previous()),
                                "Back"
                            }
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "create-realm-button",
                                disabled: !can_create_realm,
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
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
                                        // S6 soft-gate: block encrypted-Realm creation when
                                        // no recovery path is configured, unless the user has
                                        // explicitly overridden via the gate dialog.
                                        if crate::security_state::encryption_profile_is_encrypted(
                                            &encryption_profile,
                                        ) && !recovery_gate_acknowledged()
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
                                        realm_state.set("Creating Realm...".to_owned());
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
                                                        let message = format!(
                                                            "event signer is not ready; cannot sign ak.realm.create: {error}"
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
                                            match authed_api(&base, api_token.clone()) {
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
                                                            let message = format!("create failed: {error}");
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
                                                                    plaintext_visible_services: plaintext_services.clone(),
                                                                    encryption_floor: projection_floor,
                                                                },
                                                            )
                                                            .into_value();
                                                        state_store.write().save_realm_tree_projection(
                                                            realm_id.clone(),
                                                            projection_body,
                                                        );

                                                        let mut initial_mls_backup_id = None;
                                                        if crate::security_state::encryption_profile_is_encrypted(
                                                            &encryption_profile,
                                                        ) {
                                                            let secure = crate::secure_key_store::default_secure_key_store("inkson");
                                                            let seal_view = match wait_for_realm_seal_view(
                                                                &submitter,
                                                                &realm_id,
                                                            )
                                                            .await
                                                            {
                                                                Ok(view) => view,
                                                                Err(err) => {
                                                                    let message = format!(
                                                                        "created {}; refreshing the accepted Seal view before MLS setup failed: {err}",
                                                                        realm_id
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
                                                            state_store.write().set_realm_seal_view(
                                                                realm_id.clone(),
                                                                crate::state::LocalSealView {
                                                                    frontier: vec![seal_view.seal_id.to_string()],
                                                                    state_root: Some(seal_view.state_root.to_string()),
                                                                    ..Default::default()
                                                                },
                                                            );
                                                            let genesis_proof_request = match crate::mls::governance_proof::proof_request(
                                                                &realm_id,
                                                                None,
                                                                arkret_sdk::base64url_encode(realm_id.as_bytes()),
                                                                0,
                                                                0,
                                                            ) {
                                                                Ok(request) => request,
                                                                Err(err) => {
                                                                    let message = format!(
                                                                        "created {}; preparing the MLS governance proof request failed: {err}",
                                                                        realm_id
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
                                                            if let Err(err) = crate::mls::governance_proof::fetch_verify_and_cache_proof(
                                                                &api,
                                                                state_store,
                                                                &genesis_proof_request,
                                                            )
                                                            .await
                                                            {
                                                                let message = format!(
                                                                    "created {}; verifying the accepted governance proof before MLS setup failed: {err}",
                                                                    realm_id
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
                                                            let (snapshot, creator_genesis_summary) = {
                                                                let mut store = state_store.write();
                                                                match crate::mls::runtime::ensure_creator_mls_snapshot(
                                                                    &mut store,
                                                                    secure.as_ref(),
                                                                    &realm_id,
                                                                    &actor,
                                                                    &device,
                                                                ) {
                                                                    Ok(summary) => {
                                                                        (store.mls_snapshot_for(&realm_id), summary)
                                                                    }
                                                                    Err(err) => {
                                                                        let message = format!(
                                                                            "created {}; MLS initial group setup failed: {}",
                                                                            realm_id,
                                                                            err.user_message()
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
                                                            };
                                                            // Emit the one-time ak.mls.genesis for the
                                                            // freshly-created creator group at epoch 0,
                                                            // BEFORE any ak.mls.commit can bump the epoch.
                                                            // A duplicate (mls_genesis_already_exists) is
                                                            // treated as success. Failure is non-fatal:
                                                            // soland lazily defaults a never-seen group to
                                                            // epoch 0, so commits still work; we just leave
                                                            // the genesis_emitted flag unset to retry later
                                                            // via the kanban encrypted-write path.
                                                            let genesis_event = creator_genesis_summary
                                                                .as_ref()
                                                                .and_then(|genesis_summary| {
                                                                    let mut store = state_store.write();
                                                                    if store.mls_genesis_emitted_for(&realm_id) {
                                                                        return None;
                                                                    }
                                                                    match crate::mls::group_events::build_creator_mls_genesis_event(
                                                                        &mut store,
                                                                        &realm_id,
                                                                        &actor,
                                                                        &device,
                                                                        Some(genesis_summary),
                                                                    ) {
                                                                        Ok(event) => event,
                                                                        Err(err) => {
                                                                            tracing::warn!(
                                                                                error = %err,
                                                                                realm = %realm_id,
                                                                                "building ak.mls.genesis event failed",
                                                                            );
                                                                            None
                                                                        }
                                                                    }
                                                                });
                                                            if let Some(genesis_event) = genesis_event {
                                                                match match api.event_submitter() {
                                                                    Ok(sub) => sub.submit_sdk_event(&genesis_event).await,
                                                                    Err(err) => Err(err),
                                                                } {
                                                                    Ok(_) => {
                                                                        state_store.write().mark_mls_genesis_emitted_with_event(
                                                                            realm_id.clone(),
                                                                            &genesis_event.event_id,
                                                                        );
                                                                    }
                                                                    Err(err) => {
                                                                        let text = err.to_string();
                                                                        if text.contains("mls_genesis_already_exists") {
                                                                            state_store.write().mark_mls_genesis_emitted(realm_id.clone());
                                                                        } else {
                                                                            tracing::warn!(
                                                                                error = %text,
                                                                                realm = %realm_id,
                                                                                "ak.mls.genesis submit failed; soland will default epoch 0 and the kanban write path will retry",
                                                                            );
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                            if let Some(snapshot) = snapshot {
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

                                                        let mut steps = vec![format!("created {}", realm_id)];
                                                        if invitees.is_empty() {
                                                            steps.push("seeded owner only".to_owned());
                                                        } else {
                                                            steps.push(format!("seeded {} member(s)", invitees.len()));
                                                        }
                                                        steps.push(format!(
                                                            "canonical policy {} / {} / {}",
                                                            discoverability,
                                                            join_rule,
                                                            history_visibility
                                                        ));
                                                        if !plaintext_services.is_empty() {
                                                            steps.push(format!(
                                                                "plaintext services {}",
                                                                plaintext_services.len()
                                                            ));
                                                        }
                                                        if let Some(backup_id) = initial_mls_backup_id {
                                                            steps.push(format!(
                                                                "MLS ready; history backup {}",
                                                                short_protocol_id(&backup_id)
                                                            ));
                                                        } else if crate::security_state::encryption_profile_is_encrypted(
                                                            &encryption_profile,
                                                        ) {
                                                            steps.push("MLS ready locally".to_owned());
                                                        }
                                                        if !seeded_mls_err.is_empty() {
                                                            steps.push(format!(
                                                                "MLS admission failed: {seeded_mls_err}"
                                                            ));
                                                        } else if seeded_mls_ok > 0 {
                                                            steps.push(format!(
                                                                "MLS Welcome queued for {seeded_mls_ok}"
                                                            ));
                                                        }
                                                        if crate::event_builders::encryption_profile_uses_recommended_floor(
                                                            &encryption_profile,
                                                        ) {
                                                            steps.push("metadata/content floor e2ee_required".to_owned());
                                                        }

                                                        let message = steps.join(" · ");
                                                        realm_create_busy.set(false);
                                                        realm_state.set(message);
                                                        create_step.set(NewRealmStep::Done);
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
                                                            "Session expired. Refresh or sign in again before creating a Realm.".to_owned()
                                                        } else {
                                                            format!("create failed: {error}")
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
                                                    let message = format!("invalid server URL: {error}");
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
                                "Create Realm"
                            }
                        }
                    }
                }

                if active_create_step == NewRealmStep::Done {
                    div { class: "setup-step-panel", "data-testid": "realm-setup-done",
                        div { class: "event-head",
                            span { "Done" }
                            span { "next context" }
                        }
                        if has_created_realm {
                            div { class: "setup-summary-list",
                                div { class: "setup-summary-row",
                                    strong { "Created Realm" }
                                    span { class: "mono", title: "{created_realm_id_value}", "data-testid": "selected-realm-id", "{created_realm_id_label}" }
                                }
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { "Bootstrap state" }
                                    span { class: "muted", "{realm_state_value}" }
                                }
                            }
                            div { class: "actions setup-nav-actions",
                                Link {
                                    class: "primary",
                                    to: Route::Realm { realm_id: created_realm_id_value.clone() },
                                    "Open Realm"
                                }
                            }
                        } else {
                            div { class: "muted", "Create a Realm before opening the next context." }
                        }
                    }
                }
                }
            }
        }
    }
}

async fn wait_for_realm_seal_view(
    submitter: &crate::event_submit::EventSubmitter,
    realm_id: &str,
) -> anyhow::Result<arkret_sdk::RealmSealFrontierView> {
    const ATTEMPTS: usize = 20;
    const DELAY: std::time::Duration = std::time::Duration::from_millis(250);

    for attempt in 0..ATTEMPTS {
        match submitter.events_frontier_realm_seal_view(realm_id).await {
            Ok(view) => return Ok(view),
            Err(error)
                if attempt + 1 < ATTEMPTS
                    && (error.to_string().contains("404")
                        || error.to_string().contains("no accepted Seal")) =>
            {
                crate::runtime_helpers::sleep_for(DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("realm Seal retry loop returns on its final attempt")
}
