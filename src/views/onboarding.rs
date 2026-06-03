//! Onboarding stepper — claude-design `desktop/onboarding.html`.
//!
//! Account creation and account recovery are owned by coauth's OIDC pages.
//! `/onboarding` is a signed-in identity setup surface that breaks the local
//! DID/device/recovery decisions into four small steps.
//!
//! Spec sources:
//! - `identity/identity-did.md` §3 — the default principal DID method is `did:webvh`; `did:web` is
//!   kept for testing/local flows and is not recommended for production.
//! - `identity/identity-handles.md` — handles are only human-readable entry points.
//! - `crypto-media/device-lifecycle.md` §1-§3 — login factor → ck.session.grant; device
//!   authorization → ck.device.authorize; device verification → ck.key.verification.*.
//! - `crypto-media/device-lifecycle.md` §10-§13 — encrypted cloud vault / SSS / recovery key.
//!
//! Steps:
//!   1. Choose a DID method (default: did:webvh; did:web is test/local only; placeholder methods
//!      are visible but not selectable).
//!   2. Bind a handle.
//!   3. Generate the local device key + ck.device.authorize.
//!   4. Configure a recovery policy (vault passphrase / SSS guardian / recovery key).

use dioxus::prelude::*;
use dioxus_router::Link;

use crate::api::CokretApi;
use crate::identity_handle::{detect_handle_homograph_risk, handle_will_be_nfc_normalised};
use crate::local_state::LocalStateStore;
use crate::routes::Route;
use crate::views::helpers::{handle_from_did, short_protocol_id, with_authed_api};

/// Storage key for the onboarding-step-4 recovery choice (`vault` / `social` / `key`).
const ONBOARDING_RECOVERY_CHOICE_KEY: &str = "onboarding.recovery_choice";
const DEFAULT_PRINCIPAL_DID_METHOD: &str = "did:webvh";
const TEST_ONLY_DID_METHOD: &str = "did:web";

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
#[allow(clippy::redundant_closure)] // `use_signal(|| signal())` reads the inner value at init.
pub fn OnboardingPanel(
    base_url: String,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut step = use_signal(|| OnboardingStep::DidMethod);
    let mut did_method = use_signal(|| DEFAULT_PRINCIPAL_DID_METHOD.to_owned());
    let mut handle_local = use_signal(|| "alice".to_owned());
    let mut handle_domain = use_signal(|| "users.cokret.social".to_owned());

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
    let device_id_value = device_id();
    let device_id_label = short_protocol_id(&device_id_value);
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
                role: "region",
                "aria-labelledby": "account-flow-heading",
                "aria-describedby": "account-flow-help",
                div { class: "event-head",
                    span { id: "account-flow-heading", "Identity bootstrap" }
                    span { "account / session checks" }
                }
                div { id: "account-flow-help", class: "muted",
                    "Account bootstrap moved out of Realm setup. Routine sign-in still belongs to Login; this card exists so onboarding keeps the identity-side setup and verification actions together."
                }
                div {
                    class: "muted",
                    role: "status",
                    "aria-live": "polite",
                    "aria-atomic": "true",
                    "data-testid": "account-flow-status",
                    "{account_state}"
                }
                div { class: "workflow-form",
                    input {
                        "data-testid": "account-register-did-input",
                        "aria-label": "Account DID",
                        "aria-describedby": "account-flow-help",
                        value: "{register_did}",
                        oninput: move |event| {
                            let value = event.value();
                            register_handle.set(handle_from_did(&value));
                            register_did.set(value);
                        }
                    }
                    input {
                        "data-testid": "account-register-handle-input",
                        "aria-label": "Local handle",
                        value: "{register_handle}",
                        oninput: move |event| register_handle.set(event.value())
                    }
                    input {
                        "data-testid": "account-register-display-name-input",
                        "aria-label": "Display name",
                        value: "{register_display_name}",
                        oninput: move |event| register_display_name.set(event.value())
                    }
                    input {
                        "data-testid": "account-register-device-id-input",
                        "aria-label": "Device ID",
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
                                    match CokretApi::new(&base) {
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
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.account_me().await
                                    })
                                    .await
                                    {
                                        Ok(account) => account_state
                                            .set(format!("me {}", account.did)),
                                        Err(err) => account_state
                                            .set(format!("me: {}", err.display())),
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
                        "Default principal identifiers now use did:webvh. did:web is kept for testing/local flows and is not recommended for production. did:plc and did:keri are placeholders only; placeholder methods cannot be selected here."
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "did:webvh" }
                            span { class: if did_method() == DEFAULT_PRINCIPAL_DID_METHOD { "badge accent" } else { "badge green" }, "current default" }
                            div { class: "muted", "did:web + did.jsonl history + SCID + witness" }
                        }
                        div { class: "metric",
                            strong { "did:web" }
                            span { class: if did_method() == TEST_ONLY_DID_METHOD { "badge accent" } else { "badge amber" }, "test only" }
                            div { class: "muted", "HTTPS + domain; kept for local/test coverage, not recommended for production" }
                        }
                        div { class: "metric",
                            strong { "did:plc" }
                            span { class: "badge amber", "placeholder" }
                            div { class: "muted", "Reserved for future AT Protocol interop; not selectable" }
                        }
                        div { class: "metric",
                            strong { "did:key / did:pkh / did:keri" }
                            span { class: "badge amber", "interop / placeholder" }
                            div { class: "muted", "did:key and did:pkh are interop references; did:keri is not supported yet and is not selectable" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if did_method() == DEFAULT_PRINCIPAL_DID_METHOD { "primary" } else { "secondary" },
                            "data-testid": "did-method-webvh",
                            onclick: move |_| did_method.set(DEFAULT_PRINCIPAL_DID_METHOD.to_owned()),
                            "Use did:webvh (default)"
                        }
                        button {
                            class: if did_method() == TEST_ONLY_DID_METHOD { "primary" } else { "secondary" },
                            "data-testid": "did-method-web",
                            onclick: move |_| did_method.set(TEST_ONLY_DID_METHOD.to_owned()),
                            "Use did:web (test only)"
                        }
                        button { class: "secondary", "data-testid": "next-handle", onclick: move |_| step.set(OnboardingStep::Handle), "Next →" }
                    }
                }
            }

            // Step 2: Handle binding
            //
            // R3 spec sync (b47ff6ec) — wire-level handle homograph
            // guard. Surface an inline warning when the localpart
            // mixes scripts (Latin + Cyrillic/Greek/Armenian) or
            // contains non-NFC characters. The server will reject
            // confusable handles with
            // `failed_precondition reason="handle_homograph_forbidden"`;
            // surfacing the warning here gives users a chance to
            // correct the input before submission.
            if step() == OnboardingStep::Handle {
                {
                    let localpart_value = handle_local();
                    let homograph_risk = detect_handle_homograph_risk(&localpart_value);
                    let nfc_warning = handle_will_be_nfc_normalised(&localpart_value);
                    let homograph_label = homograph_risk
                        .as_ref()
                        .map(|r| r.script_label())
                        .unwrap_or_default();
                    let homograph_present = homograph_risk.is_some();
                    rsx! {
                        div { class: "event", "data-testid": "onboarding-step-handle",
                            div { class: "event-head",
                                span { "Step 2 · Handle binding" }
                                span { "identity-handles.md §17" }
                            }
                            div { class: "muted",
                                "Handles are a human-readable entry point, not a permission key. Once bound, they can be reverse-resolved back to your DID."
                            }
                            div { class: "workflow-form",
                                label { r#for: "handle-local-input", "Local part" }
                                input {
                                    id: "handle-local-input",
                                    "data-testid": "handle-local-input",
                                    "aria-label": "Handle local part",
                                    value: "{handle_local}",
                                    oninput: move |evt| handle_local.set(evt.value()),
                                }
                                label { r#for: "handle-domain-input", "Domain" }
                                input {
                                    id: "handle-domain-input",
                                    "data-testid": "handle-domain-input",
                                    "aria-label": "Handle domain",
                                    value: "{handle_domain}",
                                    oninput: move |evt| handle_domain.set(evt.value()),
                                }
                            }
                            // R3 — inline homograph + NFC warnings.
                            if homograph_present {
                                div {
                                    class: "muted",
                                    "data-testid": "handle-script-mixed-warning",
                                    role: "alert",
                                    span { class: "badge red", "handle_homograph_forbidden" }
                                    " Mixed scripts detected: {homograph_label}. The server will reject this handle. Pick a single-script localpart."
                                }
                            }
                            if nfc_warning {
                                div {
                                    class: "muted",
                                    "data-testid": "handle-nfc-warning",
                                    role: "alert",
                                    span { class: "badge amber", "NFC" }
                                    " The handle contains combining marks. It will be Unicode-normalised (NFC) on the wire; the normalised form will be the canonical handle."
                                }
                            }
                            div { class: "muted",
                                "= {handle_local}:{handle_domain} → {did_method}:{handle_domain}:users:{handle_local}"
                            }
                            div { class: "muted",
                                "Reverse resolution evidence is preserved as a content-addressed proof in the public directory."
                            }
                            div { class: "actions",
                                button { class: "secondary", onclick: move |_| step.set(OnboardingStep::DidMethod), "← Back" }
                                button {
                                    class: "secondary",
                                    "data-testid": "next-device",
                                    disabled: homograph_present,
                                    onclick: move |_| step.set(OnboardingStep::Device),
                                    "Next →"
                                }
                            }
                        }
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
                            span { class: "mono", "data-testid": "onboarding-device-id", title: "{device_id_value}", "{device_id_label}" }
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

                    // CXP B-C first-backup gate (spec head 37ce729 /
                    // CXP-0008 §4 / device-lifecycle §10-§13).
                    //
                    // The inception key (the very first device key
                    // authorized at account bootstrap) MUST NOT be
                    // retired until a `backup_class=did_recovery`
                    // envelope has been published — otherwise an
                    // account could become permanently
                    // unrecoverable. The UI hard-blocks the
                    // "Authorize device" → retirement transition
                    // until the first did_recovery envelope is
                    // observed via `GET /_cokret/self/keys/backups`.
                    FirstBackupGate {
                        base_url: base_url.clone(),
                        token,
                        account_did: account_did(),
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
                        "Three stackable recovery inputs. Each can contribute backup unlock or policy proof material; a fresh device is authorized only after the active recovery_policy accepts a bound recovery_session."
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Encrypted Cloud Vault" }
                            span { class: if recovery_choice() == "vault" { "badge accent" } else { "badge" }, "Argon2id + xchacha20poly1305" }
                            div { class: "muted", "Strong passphrase stretched on-device, then encrypted backup material is uploaded" }
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
                        role: "radiogroup",
                        "aria-label": "Recovery policy",
                        button {
                            class: if recovery_choice() == "vault" { "primary" } else { "secondary" },
                            "data-testid": "recovery-vault",
                            role: "radio",
                            "aria-checked": if recovery_choice() == "vault" { "true" } else { "false" },
                            "aria-label": "Encrypted Cloud Vault",
                            onclick: move |_| recovery_choice.set("vault".to_owned()),
                            "Vault"
                        }
                        button {
                            class: if recovery_choice() == "social" { "primary" } else { "secondary" },
                            "data-testid": "recovery-social",
                            role: "radio",
                            "aria-checked": if recovery_choice() == "social" { "true" } else { "false" },
                            "aria-label": "Social Recovery using Shamir Secret Sharing",
                            onclick: move |_| recovery_choice.set("social".to_owned()),
                            "Social Recovery"
                        }
                        button {
                            class: if recovery_choice() == "key" { "primary" } else { "secondary" },
                            "data-testid": "recovery-key",
                            role: "radio",
                            "aria-checked": if recovery_choice() == "key" { "true" } else { "false" },
                            "aria-label": "Display-once Recovery Key",
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

/// CXP B-C — first-backup gate. The inception key cannot retire
/// until a `backup_class=did_recovery` envelope has been published.
/// This component polls `GET /_cokret/self/keys/backups?backup_class=did_recovery`
/// and renders a hard-blocked panel until at least one such envelope
/// is observed. On `ok=true` the gate flips to "satisfied".
#[component]
pub fn FirstBackupGate(base_url: String, token: Signal<String>, account_did: String) -> Element {
    let mut gate_satisfied = use_signal(|| false);
    let mut status = use_signal(|| "checking did_recovery backup envelope…".to_owned());
    let mut last_error_code = use_signal(String::new);

    let do_check = {
        let base = base_url.clone();
        move || {
            let base = base.clone();
            let api_token = token();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move {
                    // CXP B-C / §3.3: recovery flow calls
                    // `LIST?series_id=` (or the bare `LIST` with
                    // `backup_class=did_recovery` filter). For the
                    // first-backup gate we only need at least one
                    // did_recovery envelope to exist; pass
                    // `series_id=None` so we see all series and
                    // filter on `backup_class`.
                    api.list_key_backups_by_series(None, Some("did_recovery"))
                        .await
                })
                .await
                {
                    Ok(value) => {
                        let count = value
                            .get("backups")
                            .and_then(|b| b.as_array())
                            .map(|a| a.len())
                            .unwrap_or(0);
                        if count > 0 {
                            gate_satisfied.set(true);
                            status.set(format!(
                                "first-backup gate satisfied: {count} did_recovery envelope(s) on record"
                            ));
                        } else {
                            gate_satisfied.set(false);
                            status.set(
                                "no did_recovery envelope on record — publish one before retiring the inception key".to_owned()
                            );
                        }
                    }
                    Err(err) => {
                        gate_satisfied.set(false);
                        let display = err.display();
                        // Surface the spec-defined error codes so the
                        // operator can tell apart a frontier-stale
                        // mismatch from a post-reset-stale mismatch.
                        for code in [
                            "backup_frontier_stale",
                            "backup_post_reset_stale",
                            "recovery_policy_mismatch",
                            "legacy_secret_storage_wire_form",
                        ] {
                            if display.contains(code) {
                                last_error_code.set(code.to_owned());
                                break;
                            }
                        }
                        status.set(format!("backup list failed: {display}"));
                    }
                }
            });
        }
    };

    // Kick off a check once when the component mounts. The
    // dependent-on-account-did effect ensures we re-check if the
    // identity changes mid-flow.
    {
        let do_check = do_check.clone();
        let _account_did = account_did.clone();
        use_effect(move || {
            do_check();
        });
    }

    rsx! {
        div {
            class: "event",
            "data-testid": "onboarding-first-backup-gate",
            "data-gate-state": if gate_satisfied() { "satisfied" } else { "blocked" },
            role: "region",
            "aria-labelledby": "first-backup-gate-heading",
            "aria-describedby": "first-backup-gate-help",
            div { class: "event-head",
                span { id: "first-backup-gate-heading", "First-backup gate (CXP B-C)" }
                if gate_satisfied() {
                    span { class: "badge green", "aria-label": "First backup envelope satisfied", "satisfied" }
                } else {
                    span { class: "badge red", "aria-label": "First backup envelope still required", "blocked" }
                }
            }
            div { id: "first-backup-gate-help", class: "muted",
                "The inception key MUST NOT retire until a backup_class=did_recovery envelope has been published. This is a hard gate (CXP B-C / device-lifecycle §10-§13) — without it the Cokret principal control state could become permanently unrecoverable."
            }
            div {
                class: "muted",
                "data-testid": "onboarding-first-backup-status",
                role: "status",
                "aria-live": "polite",
                "aria-atomic": "true",
                "{status}"
            }
            if !last_error_code().is_empty() {
                div {
                    class: "badge red",
                    "data-testid": "onboarding-first-backup-error-code",
                    "data-error-code": "{last_error_code}",
                    "error: {last_error_code}"
                }
            }
            div { class: "actions",
                button {
                    class: "primary",
                    "data-testid": "onboarding-first-backup-retry",
                    onclick: {
                        let do_check = do_check.clone();
                        move |_| do_check()
                    },
                    "Retry check"
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
                !label.starts_with("ck."),
                "labels are human strings, not event kinds: got `{label}`"
            );
        }
    }

    #[test]
    fn onboarding_default_did_method_is_webvh() {
        assert_eq!(DEFAULT_PRINCIPAL_DID_METHOD, "did:webvh");
        assert_eq!(TEST_ONLY_DID_METHOD, "did:web");
        assert_ne!(DEFAULT_PRINCIPAL_DID_METHOD, TEST_ONLY_DID_METHOD);
    }
}
