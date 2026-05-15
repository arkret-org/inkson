//! Onboarding stepper — claude-design `desktop/onboarding.html`.
//!
//! Account creation and account recovery are owned by coauth's OIDC pages.
//! `/onboarding` is a signed-in identity setup surface that breaks the local
//! DID/device/recovery decisions into four small steps.
//!
//! Spec sources:
//! - `identity/identity-did.md` §3 — v1 core default principal DID method is
//!   `did:web`.
//! - `identity/identity-handles.md` — handles are only human-readable entry
//!   points.
//! - `crypto-media/device-lifecycle.md` §1-§3 — login factor → cx.session.grant;
//!   device authorization → cx.device.authorized; device verification →
//!   cx.key.verification.*.
//! - `crypto-media/device-lifecycle.md` §10-§13 — encrypted cloud vault / SSS /
//!   recovery key.
//!
//! Steps:
//!   1. Choose a DID method (v1 core: did:web; high-trust: did:webvh; other
//!      methods are v1.1+ extensions).
//!   2. Bind a handle.
//!   3. Generate the local device key + cx.device.authorized.
//!   4. Configure a recovery policy (vault passphrase / SSS guardian /
//!      recovery key).

use dioxus::prelude::*;
use dioxus_router::Link;

use crate::{
    api::ContrixApi,
    local_state::LocalStateStore,
    routes::Route,
    views::helpers::{authed_api, handle_from_did},
};

/// Storage key for the onboarding-step-4 recovery choice (`vault` / `social` / `key`).
const ONBOARDING_RECOVERY_CHOICE_KEY: &str = "onboarding.recovery_choice";

/// Render a `did:key:zXXXX...XX` shorthand for display. Keeps the
/// `ed25519/` prefix style so the metric tile remains compact.
fn shorten_device_key(did_key: &str) -> String {
    if let Some(rest) = did_key.strip_prefix("did:key:") {
        if rest.len() > 10 {
            format!("ed25519/{}…{}", &rest[..6], &rest[rest.len() - 4..])
        } else {
            format!("ed25519/{rest}")
        }
    } else if did_key.is_empty() {
        "(not generated yet)".to_owned()
    } else {
        did_key.to_owned()
    }
}

#[cfg(test)]
mod display_tests {
    use super::shorten_device_key;

    #[test]
    fn shortens_long_did_key() {
        let s = shorten_device_key("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH");
        assert!(s.starts_with("ed25519/"));
        assert!(s.contains("…"));
        assert!(s.len() < "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH".len());
    }

    #[test]
    fn falls_back_for_empty() {
        assert_eq!(shorten_device_key(""), "(not generated yet)");
    }

    #[test]
    fn passes_through_non_did_key() {
        assert_eq!(shorten_device_key("custom-id-42"), "custom-id-42");
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OnboardingStep {
    DidMethod,
    Handle,
    Device,
    Recovery,
}

impl OnboardingStep {
    fn index(self) -> usize {
        match self {
            Self::DidMethod => 1,
            Self::Handle => 2,
            Self::Device => 3,
            Self::Recovery => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::DidMethod => "DID method",
            Self::Handle => "Handle",
            Self::Device => "Device key",
            Self::Recovery => "Recovery",
        }
    }
}

#[component]
pub fn OnboardingPanel(
    base_url: String,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut step = use_signal(|| OnboardingStep::DidMethod);
    let mut did_method = use_signal(|| "did:web".to_owned());
    let mut handle_local = use_signal(|| "alice".to_owned());
    let mut handle_domain = use_signal(|| "users.contrix.social".to_owned());

    let initial_choice = state_store
        .read()
        .load_private_data(&account_did(), ONBOARDING_RECOVERY_CHOICE_KEY)
        .unwrap_or_default();
    let mut recovery_choice = use_signal(|| initial_choice);

    let device_key_display = state_store
        .read()
        .local_identity_record()
        .map(|record| shorten_device_key(&record.did_key))
        .unwrap_or_else(|| shorten_device_key(""));
    let mut register_did = use_signal(|| account_did());
    let mut register_handle = use_signal(|| handle_from_did(&account_did()));
    let mut register_display_name = use_signal(|| "yougen".to_owned());
    let mut register_device_id = use_signal(|| device_id());
    let mut account_state = use_signal(|| "No bootstrap action yet".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "onboarding-panel", role: "region", "aria-label": "Onboarding stepper",
            // Header / progress
            div { class: "event", "data-testid": "onboarding-header",
                div { class: "event-head",
                    span { "Onboarding" }
                    span { "step {step().index()} / 4 · {step().label()}" }
                }
                div { class: "muted",
                    "Establish a recoverable identity. Account registration and account recovery happen in the coauth sign-in flow; these four steps configure the on-device identity surface."
                }
                div { class: "actions", "data-testid": "onboarding-progress", role: "tablist",
                    for s in [OnboardingStep::DidMethod, OnboardingStep::Handle, OnboardingStep::Device, OnboardingStep::Recovery] {
                        button {
                            class: if step() == s { "primary" } else { "secondary" },
                            role: "tab",
                            "aria-selected": if step() == s { "true" } else { "false" },
                            onclick: move |_| step.set(s),
                            "{s.index()}. {s.label()}"
                        }
                    }
                }
            }

            div { class: "event", "data-testid": "account-flow",
                div { class: "event-head",
                    span { "Identity bootstrap" }
                    span { "account / session checks" }
                }
                div { class: "muted",
                    "Account bootstrap moved out of Workspace Setup. Routine sign-in still belongs to Login; this card exists so onboarding keeps the identity-side setup and verification actions together."
                }
                div { class: "muted", "{account_state}" }
                div { class: "workflow-form",
                    input {
                        "data-testid": "account-register-did-input",
                        value: "{register_did}",
                        oninput: move |event| {
                            let value = event.value();
                            register_handle.set(handle_from_did(&value));
                            register_did.set(value);
                        }
                    }
                    input {
                        "data-testid": "account-register-handle-input",
                        value: "{register_handle}",
                        oninput: move |event| register_handle.set(event.value())
                    }
                    input {
                        "data-testid": "account-register-display-name-input",
                        value: "{register_display_name}",
                        oninput: move |event| register_display_name.set(event.value())
                    }
                    input {
                        "data-testid": "account-register-device-id-input",
                        value: "{register_device_id}",
                        oninput: move |event| register_device_id.set(event.value())
                    }
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "register-account-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let actor = register_did();
                                let handle = register_handle();
                                let display = register_display_name();
                                let device = register_device_id();
                                spawn(async move {
                                    match ContrixApi::new(&base) {
                                        Ok(api) => match api.register_account(
                                            &actor,
                                            &handle,
                                            Some(&display),
                                            Some(&device),
                                        ).await {
                                            Ok(account) => account_state.set(format!("registered {}", account.handle)),
                                            Err(error) => account_state.set(format!("register failed: {error}")),
                                        },
                                        Err(error) => account_state.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Register"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "account-me-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.account_me().await {
                                            Ok(account) => account_state.set(format!("me {}", account.did)),
                                            Err(error) => account_state.set(format!("me failed: {error}")),
                                        },
                                        Err(error) => account_state.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        },
                        "Me"
                    }
                    button {
                        class: "secondary",
                        onclick: move |_| step.set(OnboardingStep::Handle),
                        "Continue Onboarding"
                    }
                    Link { class: "secondary", to: Route::Login, "Open Login" }
                    Link { class: "secondary", to: Route::Settings, "Open Settings" }
                }
            }

            // Step 1: DID method
            if step() == OnboardingStep::DidMethod {
                div { class: "event", "data-testid": "onboarding-step-did",
                    div { class: "event-head",
                        span { "Step 1 · DID method" }
                        span { "identity-did.md §3" }
                    }
                    div { class: "muted",
                        "v1 core defaults to did:web for the principal identifier. did:webvh raises trust with an audit-log chain; did:plc / did:key / did:pkh / KERI / TSP are v1.1+ interop extensions."
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "did:web" }
                            span { class: if did_method() == "did:web" { "badge accent" } else { "badge" }, "v1 core default" }
                            div { class: "muted", "HTTPS + domain; the Auth Server can host on a subdomain" }
                        }
                        div { class: "metric",
                            strong { "did:webvh" }
                            span { class: if did_method() == "did:webvh" { "badge accent" } else { "badge" }, "high-trust" }
                            div { class: "muted", "did:web + did.jsonl history + SCID + witness" }
                        }
                        div { class: "metric",
                            strong { "did:plc" }
                            span { class: "badge amber", "v1.1+ extension" }
                            div { class: "muted", "AT Protocol interop only" }
                        }
                        div { class: "metric",
                            strong { "did:key / did:pkh / did:keri" }
                            span { class: "badge muted", "Limited / extension" }
                            div { class: "muted", "Ephemeral / wallet / KERI interop" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if did_method() == "did:web" { "primary" } else { "secondary" },
                            "data-testid": "did-method-web",
                            onclick: move |_| did_method.set("did:web".to_owned()),
                            "Use did:web (default)"
                        }
                        button {
                            class: if did_method() == "did:webvh" { "primary" } else { "secondary" },
                            "data-testid": "did-method-webvh",
                            onclick: move |_| did_method.set("did:webvh".to_owned()),
                            "Use did:webvh (high-trust)"
                        }
                        button { class: "secondary", "data-testid": "next-handle", onclick: move |_| step.set(OnboardingStep::Handle), "Next →" }
                    }
                }
            }

            // Step 2: Handle binding
            if step() == OnboardingStep::Handle {
                div { class: "event", "data-testid": "onboarding-step-handle",
                    div { class: "event-head",
                        span { "Step 2 · Handle binding" }
                        span { "identity-handles.md" }
                    }
                    div { class: "muted",
                        "Handles are a human-readable entry point, not a permission key. Once bound, they can be reverse-resolved back to your DID."
                    }
                    div { class: "workflow-form",
                        label { "Local part" }
                        input {
                            "data-testid": "handle-local-input",
                            value: "{handle_local}",
                            oninput: move |evt| handle_local.set(evt.value()),
                        }
                        label { "Domain" }
                        input {
                            "data-testid": "handle-domain-input",
                            value: "{handle_domain}",
                            oninput: move |evt| handle_domain.set(evt.value()),
                        }
                    }
                    div { class: "muted",
                        "= @{handle_local}@{handle_domain} → {did_method}:{handle_domain}:{handle_local}"
                    }
                    div { class: "muted",
                        "Reverse resolution evidence is preserved as a content-addressed proof in the public directory."
                    }
                    div { class: "actions",
                        button { class: "secondary", onclick: move |_| step.set(OnboardingStep::DidMethod), "← Back" }
                        button { class: "secondary", "data-testid": "next-device", onclick: move |_| step.set(OnboardingStep::Device), "Next →" }
                    }
                }
            }

            // Step 3: Device key + authorization
            if step() == OnboardingStep::Device {
                div { class: "event", "data-testid": "onboarding-step-device",
                    div { class: "event-head",
                        span { "Step 3 · Device key" }
                        span { "device-lifecycle §1-§3" }
                    }
                    div { class: "muted",
                        "This device generates its own signing key locally (ed25519). The private key never leaves the device. Authorizing the device into your long-term set is a separate step; signing in alone only gives this device a short-lived session."
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Device key" }
                            span { "data-testid": "onboarding-device-key", "{device_key_display}" }
                            div { class: "muted", "Generated locally; private key never uploaded" }
                        }
                        div { class: "metric",
                            strong { "Device id" }
                            span { class: "mono", "data-testid": "onboarding-device-id", "{device_id()}" }
                            div { class: "muted", "Stable identifier for this device" }
                        }
                        div { class: "metric",
                            strong { "Device authorization" }
                            span { "Required to stay long-term" }
                            div { class: "muted", "Adds this device's public key to your authorized set" }
                        }
                        div { class: "metric",
                            strong { "Verification" }
                            span { "Optional SAS / QR" }
                            div { class: "muted", "Your existing devices cross-sign the new one" }
                        }
                    }
                    div { class: "actions",
                        button { class: "secondary", onclick: move |_| step.set(OnboardingStep::Handle), "← Back" }
                        button { class: "secondary", "data-testid": "next-recovery", onclick: move |_| step.set(OnboardingStep::Recovery), "Next →" }
                    }
                }
            }

            // Step 4: Recovery configuration
            if step() == OnboardingStep::Recovery {
                div { class: "event", "data-testid": "onboarding-step-recovery",
                    div { class: "event-head",
                        span { "Step 4 · Recovery" }
                        span { "device-lifecycle §10-§13" }
                    }
                    div { class: "muted",
                        "Three independent layers, all stackable. Recovering through any one of them re-authorizes a fresh device on your account."
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Encrypted Cloud Vault" }
                            span { class: if recovery_choice() == "vault" { "badge accent" } else { "badge" }, "Argon2id + xchacha20poly1305" }
                            div { class: "muted", "Strong passphrase stretched on-device, then encrypted master key + recovery key are uploaded" }
                        }
                        div { class: "metric",
                            strong { "Social Recovery (SSS)" }
                            span { class: if recovery_choice() == "social" { "badge accent" } else { "badge" }, "3 / 5 threshold" }
                            div { class: "muted", "Shamir's Secret Sharing splits the secret across trusted guardians" }
                        }
                        div { class: "metric",
                            strong { "Recovery Key" }
                            span { class: if recovery_choice() == "key" { "badge accent" } else { "badge" }, "high-entropy" }
                            div { class: "muted", "Keep offline on physical media; the server never stores it" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if recovery_choice() == "vault" { "primary" } else { "secondary" },
                            "data-testid": "recovery-vault",
                            onclick: move |_| recovery_choice.set("vault".to_owned()),
                            "Vault"
                        }
                        button {
                            class: if recovery_choice() == "social" { "primary" } else { "secondary" },
                            "data-testid": "recovery-social",
                            onclick: move |_| recovery_choice.set("social".to_owned()),
                            "Social Recovery"
                        }
                        button {
                            class: if recovery_choice() == "key" { "primary" } else { "secondary" },
                            "data-testid": "recovery-key",
                            onclick: move |_| recovery_choice.set("key".to_owned()),
                            "Recovery Key"
                        }
                    }
                    div { class: "actions",
                        button { class: "secondary", onclick: move |_| step.set(OnboardingStep::Device), "← Back" }
                        {
                            let choice = recovery_choice();
                            let choice_empty = choice.trim().is_empty();
                            rsx! {
                                Link {
                                    class: if choice_empty { "secondary" } else { "primary" },
                                    "data-testid": "onboarding-finish",
                                    to: Route::Dashboard,
                                    onclick: {
                                        let actor = account_did();
                                        let choice = choice.clone();
                                        move |_| {
                                            if !choice.trim().is_empty() {
                                                state_store.write().save_private_data(
                                                    &actor,
                                                    ONBOARDING_RECOVERY_CHOICE_KEY,
                                                    choice.clone(),
                                                );
                                            }
                                        }
                                    },
                                    if choice_empty { "Select a recovery option to finish" } else { "Finish onboarding →" }
                                }
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
    use super::*;

    #[test]
    fn onboarding_step_indices_are_unique_and_one_based() {
        let steps = [
            OnboardingStep::DidMethod,
            OnboardingStep::Handle,
            OnboardingStep::Device,
            OnboardingStep::Recovery,
        ];
        let indices: Vec<usize> = steps.iter().copied().map(OnboardingStep::index).collect();
        assert_eq!(
            indices,
            vec![1, 2, 3, 4],
            "indices must be 1..=4 in declared order"
        );
    }

    #[test]
    fn onboarding_step_labels_are_unique() {
        let labels = [
            OnboardingStep::DidMethod.label(),
            OnboardingStep::Handle.label(),
            OnboardingStep::Device.label(),
            OnboardingStep::Recovery.label(),
        ];
        let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for l in labels {
            assert!(seen.insert(l), "duplicate onboarding label `{l}`");
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn onboarding_step_labels_are_human_readable() {
        for step in [
            OnboardingStep::DidMethod,
            OnboardingStep::Handle,
            OnboardingStep::Device,
            OnboardingStep::Recovery,
        ] {
            let label = step.label();
            assert!(!label.is_empty(), "label cannot be empty");
            assert!(
                !label.starts_with("cx."),
                "labels are human strings, not event kinds: got `{label}`"
            );
        }
    }
}
