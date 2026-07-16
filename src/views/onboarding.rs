//! Onboarding stepper — claude-design `desktop/onboarding.html`.
//!
//! Account creation and account recovery are owned by coauth's OIDC pages.
//! `/onboarding` is a signed-in identity setup surface that breaks the local
//! DID/device/recovery decisions into four small steps.
//!
//! Spec sources:
//! - `identity/identity-did.md` §3 — the default principal DID method is `did:webvh`; `did:web` is
//!   kept for testing/local strands and is not recommended for production.
//! - `identity/identity-handles.md` — handles are only human-readable entry points.
//! - `crypto-media/device-lifecycle.md` §1-§3 — login factor → ak.session.grant; device
//!   authorization → ak.device.authorize; device verification → ak.key.verification.*.
//! - `crypto-media/device-lifecycle.md` §10-§13 — recovery key (24 words) / SSS.
//!
//! Steps:
//!   1. Generate the recovery secret and complete cold-custody confirmation.
//!   2. Prepare and publish the public DID inception draft.
//!   3. Atomically submit the root-signed PCR create and authority-signed first device authorize.
//!   4. Accept recovery policy + first backup before any ordinary durable write.

use dioxus::prelude::*;
use dioxus_router::Link;

use crate::identity::handle::{detect_handle_homograph_risk, handle_will_be_nfc_normalised};
use crate::recovery_strand::{
    FirstBackupGateBlockReason, FirstBackupGateStatus, first_backup_gate_status_from_payloads,
};
use crate::routes::Route;
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::short_protocol_id;

/// Storage key for the onboarding-step-4 recovery choice (`vault` / `social` / `key`).
const ONBOARDING_RECOVERY_CHOICE_KEY: &str = "onboarding.recovery_choice";
const DEFAULT_PRINCIPAL_DID_METHOD: &str = "did:webvh";
const TEST_ONLY_DID_METHOD: &str = "did:web";
const PCR_ENCRYPTION_PROFILE: &str = "mls_rfc9420";
const PCR_ENCRYPTION_FLOOR: &str = "e2ee_required";

fn recovery_setup_label(choice: &str) -> &'static str {
    match choice.trim() {
        "" => "Select a recovery option to continue",
        "key" => "Open Recovery Key setup ->",
        "social" => "Open Social Recovery setup ->",
        _ => "Open Recovery setup ->",
    }
}

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
            Self::Recovery => 1,
            Self::DidMethod => 2,
            Self::Device => 3,
            Self::Handle => 4,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Recovery => "Cold custody",
            Self::DidMethod => "Identity draft",
            Self::Device => "Atomic bootstrap",
            Self::Handle => "Recovery material",
        }
    }
}

#[component]
#[allow(clippy::redundant_closure)] // `use_signal(|| signal())` reads the inner value at init.
pub fn OnboardingPanel(
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let mut step = use_signal(|| OnboardingStep::Recovery);
    let mut did_method = use_signal(|| DEFAULT_PRINCIPAL_DID_METHOD.to_owned());
    let mut handle_local = use_signal(|| "alice".to_owned());
    let mut handle_domain = use_signal(|| "users.arkret.social".to_owned());

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
    let mut account_state = use_signal(|| "Verified identity binding not loaded".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "onboarding-panel", role: "region", "aria-label": "Onboarding stepper",
            // Header / progress
            div { class: "event", "data-testid": "onboarding-header",
                div { class: "event-head",
                    span { "Onboarding" }
                    span { "step {step().index()} / 4 · {step().label()}" }
                }
                div { class: "muted",
                    "Establish a recoverable identity. Account registration and account recovery happen in the coauth sign-in strand; these four steps configure the on-device identity surface."
                }
                div { class: "actions", "data-testid": "onboarding-progress", role: "tablist",
                    for s in [OnboardingStep::Recovery, OnboardingStep::DidMethod, OnboardingStep::Device, OnboardingStep::Handle] {
                        Button {
                            variant: if step() == s { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            role: "tab",
                            "aria-selected": if step() == s { "true" } else { "false" },
                            onclick: move |_| step.set(s),
                            "{s.index()}. {s.label()}"
                        }
                    }
                }
            }

            PendingPrincipalBootstrap { token, account_did, device_id }
            PendingAccountIdentityCreation {
                token,
                account_did,
                device_id,
                config_store,
            }

            div { class: "event", "data-testid": "account-strand",
                role: "region",
                "aria-labelledby": "account-strand-heading",
                "aria-describedby": "account-strand-help",
                div { class: "event-head",
                    span { id: "account-strand-heading", "Identity bootstrap" }
                    span { "account / session checks" }
                }
                div { id: "account-strand-help", class: "muted",
                    "This signed-in surface only displays the Account Authority's verified principal binding. A user-supplied DID cannot be registered here. A new principal is bound only after its custody-confirmed entry 0 and atomic PCR bootstrap have been accepted."
                }
                div {
                    class: "muted",
                    role: "status",
                    "aria-live": "polite",
                    "aria-atomic": "true",
                    "data-testid": "account-strand-status",
                    "{account_state}"
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "account-me-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let api_token = token();
                                let base = base.clone();
                                spawn(async move {
                                    match with_authed_sdk_client(&base, api_token, |http| async move {
                                        crate::transport::account::account_me(&http).await
                                    })
                                    .await
                                    {
                                        Ok(account) => account_state
                                            .set(format!("verified principal {}", account.did)),
                                        Err(err) => account_state
                                            .set(format!("me: {}", err.display())),
                                    }
                                });
                            }
                        },
                        "Me"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        onclick: move |_| step.set(OnboardingStep::Recovery),
                        "Continue Onboarding"
                    }
                    Link { class: "secondary", to: Route::Login, "Open Login" }
                    Link { class: "secondary", to: Route::Settings, "Open Settings" }
                }
            }

            // Step 2: public identity draft
            if step() == OnboardingStep::DidMethod {
                div { class: "event", "data-testid": "onboarding-step-did",
                    div { class: "event-head",
                        span { "Step 2 · Public identity draft" }
                        span { "identity-did.md §3" }
                    }
                    div { class: "muted",
                        "The client derives root_0 and the root_1 pre-rotation commitment from the already-confirmed Recovery Key, then persists only this public draft and its canonical idempotency keys. Root seed material is never written to ordinary client state."
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
                        Button {
                            variant: if did_method() == DEFAULT_PRINCIPAL_DID_METHOD { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "did-method-webvh",
                            onclick: move |_| did_method.set(DEFAULT_PRINCIPAL_DID_METHOD.to_owned()),
                            "Use did:webvh (default)"
                        }
                        Button {
                            variant: if did_method() == TEST_ONLY_DID_METHOD { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "did-method-web",
                            onclick: move |_| did_method.set(TEST_ONLY_DID_METHOD.to_owned()),
                            "Use did:web (test only)"
                        }
                        Button { variant: ButtonVariant::Secondary, onclick: move |_| step.set(OnboardingStep::Recovery), "← Back" }
                        Button { variant: ButtonVariant::Secondary, "data-testid": "next-device", onclick: move |_| step.set(OnboardingStep::Device), "Next →" }
                    }
                }
            }

            // Step 4: accepted recovery material and optional handle binding
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
                                span { "Step 4 · Recovery material ready" }
                                span { "identity-handles.md §17" }
                            }
                            div { class: "muted",
                                "Ordinary durable writes stay blocked until an accepted recovery policy and matching did_recovery envelope make recovery_material_pending=false. A handle may be bound only after that gate; it is a human-readable entry point, never a permission key."
                            }
                            div { class: "workflow-form",
                                Label { html_for: "handle-local-input", "Local part" }
                                Input {
                                    id: "handle-local-input",
                                    "data-testid": "handle-local-input",
                                    "aria-label": "Handle local part",
                                    value: "{handle_local}",
                                    oninput: move |event: FormEvent| handle_local.set(event.value()),
                                }
                                Label { html_for: "handle-domain-input", "Domain" }
                                Input {
                                    id: "handle-domain-input",
                                    "data-testid": "handle-domain-input",
                                    "aria-label": "Handle domain",
                                    value: "{handle_domain}",
                                    oninput: move |event: FormEvent| handle_domain.set(event.value()),
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
                                Button { variant: ButtonVariant::Secondary, onclick: move |_| step.set(OnboardingStep::Device), "← Back" }
                            }
                        }
                    }
                }
            }

            // Step 3: Device key + authorization
            if step() == OnboardingStep::Device {
                div { class: "event", "data-testid": "onboarding-step-device",
                    div { class: "event-head",
                        span { "Step 3 · Atomic PCR bootstrap" }
                        span { "device-lifecycle §1-§3" }
                    }
                    div { class: "muted",
                        "Self PCR bootstrap is one atomic two-Event batch: the cold identity root signs only ak.realm.create with its critical did_inception ref, and the delegated enrollment authority signs ak.device.authorize. A managed Agent remains on its controller-delegated path and never carries did_inception."
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
                            strong { "Principal Control Realm" }
                            span { class: "badge accent", "MLS-backed" }
                            div { class: "muted", "Your account control stream uses encryption_profile={PCR_ENCRYPTION_PROFILE} with metadata/content floors {PCR_ENCRYPTION_FLOOR}" }
                        }
                        div { class: "metric",
                            strong { "Verification" }
                            span { "Optional SAS / QR" }
                            div { class: "muted", "Your existing devices cross-sign the new one" }
                        }
                    }

                    // The bootstrap batch is the only durable-write exception.
                    // Every later persistent Event remains blocked while
                    // recovery_material_pending is true.
                    FirstBackupGate {
                        token,
                        account_did: account_did(),
                    }

                    div { class: "actions",
                        Button { variant: ButtonVariant::Secondary, onclick: move |_| step.set(OnboardingStep::DidMethod), "← Back" }
                        Button { variant: ButtonVariant::Secondary, "data-testid": "next-recovery", onclick: move |_| step.set(OnboardingStep::Handle), "Next →" }
                    }
                }
            }

            // Step 1: recovery-secret custody confirmation
            if step() == OnboardingStep::Recovery {
                div { class: "event", "data-testid": "onboarding-step-recovery",
                    div { class: "event-head",
                        span { "Step 1 · Cold custody" }
                        span { "device-lifecycle §10-§13" }
                    }
                    div { class: "muted",
                        "Generate the 24-word Recovery Key before entry 0 exists. Confirm custody by re-entering the randomly selected word positions or by an accepted hardware/guardian acknowledgement. Only then may the same public inception draft be published. The Recovery Key, root seed, recovery-proof seed and HPKE private key never enter logs, wire payloads or ordinary local state."
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Recovery Key (24 words)" }
                            span { class: if recovery_choice() == "key" { "badge accent" } else { "badge" }, "high-entropy" }
                            div { class: "muted", "Keep offline on physical media; the server never stores it" }
                        }
                        div { class: "metric",
                            strong { "Social Recovery (SSS)" }
                            span { class: if recovery_choice() == "social" { "badge accent" } else { "badge" }, "3 / 5 threshold" }
                            div { class: "muted", "Shamir's Secret Sharing splits the secret across trusted guardians" }
                        }
                    }
                    div { class: "actions",
                        role: "radiogroup",
                        "aria-label": "Recovery policy",
                        Button {
                            variant: if recovery_choice() == "key" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "recovery-key",
                            role: "radio",
                            "aria-checked": if recovery_choice() == "key" { "true" } else { "false" },
                            "aria-label": "Display-once Recovery Key (24 words)",
                            onclick: move |_| recovery_choice.set("key".to_owned()),
                            "Recovery Key (24 words)"
                        }
                        Button {
                            variant: if recovery_choice() == "social" { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "recovery-social",
                            role: "radio",
                            "aria-checked": if recovery_choice() == "social" { "true" } else { "false" },
                            "aria-label": "Social Recovery using Shamir Secret Sharing",
                            onclick: move |_| recovery_choice.set("social".to_owned()),
                            "Social Recovery"
                        }
                    }
                    div { class: "actions",
                        {
                            let choice = recovery_choice();
                            let choice_empty = choice.trim().is_empty();
                            let finish_label = recovery_setup_label(&choice);
                            if choice_empty {
                                rsx! {
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "onboarding-finish",
                                        disabled: true,
                                        "{finish_label}"
                                    }
                                }
                            } else {
                                rsx! {
                                    Link {
                                        class: "primary",
                                        "data-testid": "onboarding-finish",
                                        to: Route::SettingsRecovery,
                                        onclick: {
                                            let actor = account_did();
                                            let choice = choice.clone();
                                            move |_| {
                                                state_store.write().save_private_data(
                                                    &actor,
                                                    ONBOARDING_RECOVERY_CHOICE_KEY,
                                                    choice.clone(),
                                                );
                                            }
                                        },
                                        "{finish_label}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn random_custody_word_indices(word_count: usize) -> anyhow::Result<Vec<usize>> {
    if word_count < 3 {
        anyhow::bail!("recovery phrase is too short for custody confirmation");
    }
    let mut indices = Vec::with_capacity(3);
    while indices.len() < 3 {
        let mut random = [0_u8; 2];
        getrandom::fill(&mut random)?;
        let candidate = usize::from(u16::from_le_bytes(random)) % word_count;
        if !indices.contains(&candidate) {
            indices.push(candidate);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

#[component]
fn PendingAccountIdentityCreation(
    mut token: Signal<String>,
    mut account_did: Signal<String>,
    mut device_id: Signal<String>,
    config_store: Signal<crate::config::LocalConfigStore>,
) -> Element {
    let mut state_store = crate::app::SessionContext::get().state_store;
    let handoff = state_store.read().pending_account_handoff();
    let mut recovery_key = use_signal(String::new);
    let mut word_indices = use_signal(Vec::<usize>::new);
    let mut confirmations = use_signal(|| vec![String::new(), String::new(), String::new()]);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| {
        "Generate the Recovery Key locally. The server receives only the signed public inception operation."
            .to_owned()
    });

    let Some(handoff) = handoff else {
        return rsx! {};
    };
    if let Some(retry_after_ms) = handoff.retry_after_ms {
        return rsx! {
            div { class: "event", "data-testid": "identity-creation-busy",
                div { class: "event-head", span { "Identity creation is active elsewhere" } }
                div { class: "muted",
                    "Another holder owns the current lease. Retry after approximately {retry_after_ms} ms; this client will not mint a second identity."
                }
                Link { class: "secondary", to: Route::Login, "Authenticate again after the lease expires" }
            }
        };
    }
    let expired = handoff.expires_at <= chrono::Utc::now()
        || handoff
            .lease_expires_at
            .is_some_and(|expires_at| expires_at <= chrono::Utc::now());
    let indices = word_indices();

    rsx! {
        div { class: "event", "data-testid": "account-handoff-onboarding",
            div { class: "event-head",
                span { "Account handoff · identity creation" }
                span { class: "badge accent", "lease fence {handoff.lease_fence.unwrap_or_default()}" }
            }
            div { class: "muted",
                "Hosting: {handoff.principal_server_url}. Enrollment authority: {handoff.enrollment_authority_did}. Trust domain: {handoff.trust_domain}."
            }
            if expired {
                div { class: "auth-status", role: "alert",
                    "The handoff or lease expired. Authenticate again; Inkson will resume only the same reserved public operation."
                }
                Link { class: "primary", to: Route::Login, "Authenticate again" }
            } else if recovery_key().is_empty() {
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "onboarding-generate-recovery-key",
                    disabled: busy(),
                    onclick: move |_| {
                        match crate::recovery_crypto::generate_recovery_key().and_then(|key| {
                            let count = key.split_whitespace().count();
                            let selected = random_custody_word_indices(count)?;
                            Ok((key, selected))
                        }) {
                            Ok((key, selected)) => {
                                recovery_key.set(key);
                                word_indices.set(selected);
                                confirmations.set(vec![String::new(), String::new(), String::new()]);
                                status.set("Write all 24 words down offline, then confirm the three randomly selected positions.".to_owned());
                            }
                            Err(error) => status.set(format!("Could not generate Recovery Key: {error}")),
                        }
                    },
                    "Generate Recovery Key"
                }
            } else {
                Label { html_for: "onboarding-recovery-key-display", "Recovery Key — shown once" }
                textarea {
                    id: "onboarding-recovery-key-display",
                    class: "form-input",
                    "data-testid": "onboarding-recovery-key-display",
                    readonly: true,
                    rows: "5",
                    value: "{recovery_key}",
                }
                for (slot, index) in indices.iter().copied().enumerate() {
                    Label { html_for: "custody-word-{slot}", "Word #{index + 1}" }
                    Input {
                        id: "custody-word-{slot}",
                        "data-testid": "custody-word-confirmation",
                        autocomplete: "off",
                        value: "{confirmations()[slot]}",
                        disabled: busy(),
                        oninput: move |event: FormEvent| {
                            let mut values = confirmations();
                            values[slot] = event.value();
                            confirmations.set(values);
                        },
                    }
                }
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "onboarding-bind-identity",
                    disabled: busy(),
                    onclick: move |_| {
                        let words: Vec<String> = recovery_key()
                            .split_whitespace()
                            .map(|word| word.to_ascii_lowercase())
                            .collect();
                        let answers = confirmations();
                        if indices.len() != 3
                            || indices.iter().enumerate().any(|(slot, index)| {
                                answers[slot].trim().to_ascii_lowercase() != words[*index]
                            })
                        {
                            status.set("One or more selected words do not match. Nothing has been published.".to_owned());
                            return;
                        }
                        let handoff = handoff.clone();
                        let supplied_key = recovery_key();
                        let device = handoff.device_id.clone();
                        busy.set(true);
                        status.set("Reserving the public operation, proving root control, and binding the account…".to_owned());
                        spawn(async move {
                            let result = async {
                                let checkpoint = crate::identity::principal_registration::prepare_registration_checkpoint(
                                    &handoff,
                                    &device,
                                    &supplied_key,
                                )?;
                                let barrier = {
                                    let mut store = state_store.write();
                                    store.set_pending_principal_registration(Some(checkpoint.clone()))?;
                                    store.begin_durable_flush()?
                                };
                                barrier.wait().await?;
                                let dpop = {
                                    let mut store = state_store.write();
                                    crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
                                };
                                let completion = crate::identity::principal_registration::complete_account_handoff_binding(
                                    &handoff,
                                    &checkpoint,
                                    &supplied_key,
                                    &dpop,
                                )
                                .await?;
                                let actor = completion.session_grant.principal_id.to_string();
                                let grant_jwt = completion.session_grant.grant_jwt.clone();
                                let persisted_grant = crate::state::PersistedSessionGrant {
                                    grant_jwt: grant_jwt.clone(),
                                    session_private_key_pem: completion.session_private_key_pem,
                                    grant_id: completion.session_grant.grant_id.to_string(),
                                    audience: completion.session_grant.audience.to_string(),
                                    principal_id: actor.clone(),
                                    device_id: device.clone(),
                                    principal_server_url: handoff.principal_server_url.clone(),
                                    grant_expires_at: Some(completion.session_grant.expires_at),
                                    stored_at: chrono::Utc::now(),
                                };
                                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                                crate::secure_key_store::adopt_device_seed_scope_on_login(
                                    secure_store.as_ref(),
                                    &actor,
                                )?;
                                let mut accepted = checkpoint;
                                accepted.binding_receipt = Some(serde_json::to_value(
                                    completion.binding_receipt,
                                )?);
                                accepted.stage = crate::state::PendingPrincipalRegistrationStage::BindingRegistered;
                                {
                                    let mut store = state_store.write();
                                    store.adopt_pending_login(&actor);
                                    crate::views::login::persist_completed_login_dpop_key(
                                        &mut store,
                                        secure_store.as_ref(),
                                        &actor,
                                        &device,
                                        &completion.dpop_device_key,
                                    )
                                    .map_err(anyhow::Error::msg)?;
                                    store.set_pending_principal_registration(Some(accepted))?;
                                    store.set_pending_account_handoff(None)?;
                                    store.set_session_grant(Some(persisted_grant));
                                    store.register_known_account(&actor);
                                }
                                crate::identity::account_auth::clear_account_handoff_grant()?;
                                crate::views::helpers::persist_config(
                                    config_store,
                                    handoff.principal_server_url,
                                    actor.clone(),
                                    device.clone(),
                                    grant_jwt.clone(),
                                );
                                Ok::<_, anyhow::Error>((actor, device, grant_jwt))
                            }
                            .await;
                            match result {
                                Ok((actor, device, grant)) => {
                                    account_did.set(actor);
                                    device_id.set(device);
                                    token.set(grant);
                                    recovery_key.set(String::new());
                                    confirmations.set(vec![String::new(), String::new(), String::new()]);
                                    status.set("Identity entry 0 is bound. Continue the first-device PCR bootstrap below.".to_owned());
                                }
                                Err(error) => status.set(format!("Identity binding did not complete: {error}")),
                            }
                            busy.set(false);
                        });
                    },
                    "Confirm custody and bind identity"
                }
            }
            div { class: "muted", role: "status", "aria-live": "polite", "data-testid": "account-handoff-status", "{status}" }
        }
    }
}

#[component]
fn PendingPrincipalBootstrap(
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
) -> Element {
    let base_url = crate::app::SessionContext::base_url_string();
    let mut state_store = crate::app::SessionContext::get().state_store;
    let checkpoint = state_store.read().pending_principal_registration();
    let mut recovery_key = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(|| {
        "Re-enter the same 24-word Recovery Key to sign the PCR root anchor and finish the recovery-material gate."
            .to_owned()
    });

    let Some(registration) = checkpoint else {
        return rsx! {};
    };
    let did_label = short_protocol_id(&registration.did);
    let stage_label = format!("{:?}", registration.stage);

    rsx! {
        div {
            class: "event",
            "data-testid": "pending-principal-bootstrap",
            role: "region",
            "aria-label": "Finish identity bootstrap",
            div { class: "event-head",
                span { "Finish identity bootstrap" }
                span { class: "badge accent", "{stage_label}" }
            }
            div { class: "muted",
                "Entry 0 is bound to {did_label}. The cold root will sign only the closed ak.realm.create anchor; the Account Authority signs the first device authorization. Both are submitted atomically."
            }
            Label { html_for: "bootstrap-recovery-key", "Recovery Key (24 words)" }
            textarea {
                id: "bootstrap-recovery-key",
                class: "form-input",
                "data-testid": "bootstrap-recovery-key",
                rows: "5",
                autocomplete: "off",
                value: "{recovery_key}",
                disabled: busy(),
                oninput: move |event| recovery_key.set(event.value()),
            }
            div {
                class: "muted",
                "data-testid": "bootstrap-status",
                role: "status",
                "aria-live": "polite",
                "{status}"
            }
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "bootstrap-submit",
                    disabled: busy() || recovery_key().trim().is_empty(),
                    onclick: move |_| {
                        let registration = registration.clone();
                        let supplied_key = recovery_key();
                        let base = base_url.clone();
                        let session = token();
                        let actor = account_did();
                        let device = device_id();
                        if actor != registration.did || device != registration.device_id {
                            status.set(
                                "The signed-in principal/device does not match the saved bootstrap draft. Sign out and continue the matching registration."
                                    .to_owned(),
                            );
                            return;
                        }
                        busy.set(true);
                        status.set("Validating the cold root and submitting the atomic bootstrap unit…".to_owned());
                        spawn(async move {
                            let result = async {
                                crate::identity::principal_registration::validate_checkpoint_recovery_key(
                                    &registration,
                                    &supplied_key,
                                )?;

                                if registration.stage
                                    == crate::state::PendingPrincipalRegistrationStage::BindingRegistered
                                {
                                    let signer = crate::event_signer::active_signer()
                                        .ok_or_else(|| anyhow::anyhow!("device signer is unavailable"))?;
                                    let signer = crate::event_signer::bind_active_signer_device_id(&device)?
                                        .unwrap_or(signer);
                                    let device_public_key = signer
                                        .public_key_multibase()
                                        .ok_or_else(|| anyhow::anyhow!("device signer has no Ed25519 public key"))?;
                                    let hpke_key = {
                                        let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                                        let (_, public_key) = crate::mls::runtime::load_or_create_device_hpke_keypair(
                                            secure_store.as_ref(),
                                            &actor,
                                            &device,
                                        )?;
                                        crate::identity::did_key::encode_x25519_multibase(&public_key)
                                    };
                                    let dpop = {
                                        let mut store = state_store.write();
                                        crate::identity::account_auth::grant_dpop::ensure_device_key(&mut store)?
                                    };
                                    let account_base = crate::identity::session_refresh::sdk_base_url_from_gate_account_base(
                                        &registration.gate_account_base,
                                    )?;
                                    let account_client = arkret_sdk::http_client::ClientBuilder::new(account_base)
                                        .allow_insecure_localhost()
                                        .auth(arkret_sdk::http_client::Auth::Dpop(
                                            dpop.sdk_dpop_auth_for_access_token(session.clone()),
                                        ))
                                        .build()?;
                                    let bootstrap_registration = registration.clone();
                                    let bootstrap_key = supplied_key.clone();
                                    crate::transport::auth::with_authed_sdk_client(
                                        &base,
                                        session.clone(),
                                        |principal_client| async move {
                                            crate::identity::principal_registration::bootstrap_principal(
                                                &bootstrap_registration,
                                                &bootstrap_key,
                                                device_public_key,
                                                hpke_key,
                                                signer.as_ref(),
                                                &account_client,
                                                &principal_client,
                                            )
                                            .await
                                        },
                                    )
                                    .await
                                    .map_err(|error| anyhow::anyhow!(error.display()))?;
                                    let mut accepted = registration.clone();
                                    accepted.stage = crate::state::PendingPrincipalRegistrationStage::BootstrapAccepted;
                                    let barrier = {
                                        let mut store = state_store.write();
                                        store.set_pending_principal_registration(Some(accepted))?;
                                        store.begin_durable_flush()?
                                    };
                                    barrier.wait().await?;
                                }

                                let recovery_actor = actor.clone();
                                let recovery_device = device.clone();
                                let recovery_key_value = supplied_key.clone();
                                let backup_id = crate::transport::auth::with_authed_api(
                                    &base,
                                    session,
                                    |api| async move {
                                        crate::recovery_strand::ensure_recovery_policy_and_did_recovery_backup(
                                            &api,
                                            &recovery_actor,
                                            &recovery_device,
                                            &recovery_key_value,
                                        )
                                        .await
                                    },
                                )
                                .await
                                .map_err(|error| anyhow::anyhow!(error.display()))?;
                                crate::views::recovery::save_generated_recovery_key_metadata(
                                    &mut state_store,
                                    &actor,
                                    &supplied_key,
                                )
                                .ok_or_else(|| anyhow::anyhow!("save public recovery metadata failed"))?;
                                let barrier = {
                                    let mut store = state_store.write();
                                    store.set_pending_principal_registration(None)?;
                                    store.begin_durable_flush()?
                                };
                                barrier.wait().await?;
                                Ok::<_, anyhow::Error>(backup_id)
                            }
                            .await;
                            match result {
                                Ok(backup_id) => {
                                    recovery_key.set(String::new());
                                    status.set(format!(
                                        "Identity bootstrap and recovery-material gate complete ({backup_id})."
                                    ));
                                }
                                Err(error) => status.set(format!(
                                    "Bootstrap remains resumable and no alternate identity was created: {error}"
                                )),
                            }
                            busy.set(false);
                        });
                    },
                    "Finish bootstrap and recovery"
                }
            }
        }
    }
}

/// Recovery-material gate. Ordinary post-bootstrap durable writes remain
/// blocked until an accepted `backup_class=did_recovery` first envelope
/// matches the active recovery policy. This component reads the active policy,
/// lists did_recovery backups, and renders a blocked panel until the list
/// contains a matching `recovery_public_key` backup.
#[component]
pub fn FirstBackupGate(token: Signal<String>, account_did: String) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
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
                    // The first-backup-gate reducer reads both payloads leniently
                    // via `Value` accessors; serialize the typed SDK outcomes back
                    // to their wire JSON.
                    let policy = serde_json::to_value(&api.get_recovery_policy().await?)?;
                    let backups = serde_json::to_value(
                        &api.list_key_backups_by_series(None, Some("did_recovery"))
                            .await?,
                    )?;
                    Ok::<(serde_json::Value, serde_json::Value), anyhow::Error>((policy, backups))
                })
                .await
                {
                    Ok((policy, backups)) => {
                        last_error_code.set(String::new());
                        match first_backup_gate_status_from_payloads(&policy, &backups) {
                            FirstBackupGateStatus::Satisfied { backup_id } => {
                                gate_satisfied.set(true);
                                status.set(format!(
                                    "first-backup gate satisfied: accepted did_recovery backup {} matches the active recovery_policy_ref",
                                    short_protocol_id(&backup_id)
                                ));
                            }
                            FirstBackupGateStatus::Blocked(
                                FirstBackupGateBlockReason::NoActiveRecoveryPolicy,
                            ) => {
                                gate_satisfied.set(false);
                                status.set(
                                    "recovery_material_pending: no active accepted recovery_policy"
                                        .to_owned(),
                                );
                            }
                            FirstBackupGateStatus::Blocked(
                                FirstBackupGateBlockReason::NoMatchingDidRecoveryBackup {
                                    policy_id,
                                    policy_version,
                                },
                            ) => {
                                gate_satisfied.set(false);
                                status.set(format!(
                                    "no accepted did_recovery backup matches active recovery_policy_ref {}@{} with recipient_method=recovery_public_key",
                                    short_protocol_id(&policy_id),
                                    policy_version
                                ));
                            }
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
    // identity changes mid-strand.
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
                span { id: "first-backup-gate-heading", "Recovery-material gate" }
                if gate_satisfied() {
                    span { class: "badge green", "aria-label": "First backup envelope satisfied", "satisfied" }
                } else {
                    span { class: "badge red", "aria-label": "First backup envelope still required", "blocked" }
                }
            }
            div { id: "first-backup-gate-help", class: "muted",
                "While recovery_material_pending is true, the atomic PCR bootstrap is the only permitted durable write. Normal Events, MLS application writes, and second-device enrollment remain blocked until the accepted policy and matching did_recovery envelope are both visible."
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
                Button {
                    variant: ButtonVariant::Primary,
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
            OnboardingStep::Recovery,
            OnboardingStep::DidMethod,
            OnboardingStep::Device,
            OnboardingStep::Handle,
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
                !label.starts_with("ak."),
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

    #[test]
    fn onboarding_recovery_finish_opens_setup_strand() {
        assert_eq!(
            recovery_setup_label(""),
            "Select a recovery option to continue"
        );
        assert_eq!(recovery_setup_label("key"), "Open Recovery Key setup ->");
        assert_eq!(
            recovery_setup_label("social"),
            "Open Social Recovery setup ->"
        );
        assert_eq!(PCR_ENCRYPTION_PROFILE, "mls_rfc9420");
        assert_eq!(PCR_ENCRYPTION_FLOOR, "e2ee_required");
    }

    #[test]
    fn account_first_custody_samples_three_distinct_word_positions() {
        let positions = random_custody_word_indices(24).unwrap();
        assert_eq!(positions.len(), 3);
        assert!(positions.windows(2).all(|window| window[0] < window[1]));
        assert!(positions.iter().all(|position| *position < 24));
    }
}
