use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dioxus::prelude::*;
use serde_json::json;

use crate::api::ContrixApi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DidMethod {
    DidPlc,
    DidWeb,
    DidWebvh,
    DidKey,
}

impl DidMethod {
    fn label(self) -> &'static str {
        match self {
            Self::DidPlc => "did:plc",
            Self::DidWeb => "did:web",
            Self::DidWebvh => "did:webvh",
            Self::DidKey => "did:key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegistrationPath {
    CreateNewDid,
    BindExistingDid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RegisterStep {
    ChooseDid,
    HandleInput,
    DisplayName,
    DidProof,
    Recovery,
    DeviceBootstrap,
    Complete,
}

#[component]
pub fn RegisterPanel(base_url: String, on_register: EventHandler<()>) -> Element {
    let mut step = use_signal(|| RegisterStep::ChooseDid);
    let mut registration_path = use_signal(|| RegistrationPath::CreateNewDid);
    let mut did_method = use_signal(|| DidMethod::DidPlc);
    let mut generated_did = use_signal(String::new);
    let mut existing_did = use_signal(String::new);
    let mut existing_did_status = use_signal(String::new);
    let mut handle = use_signal(String::new);
    let mut handle_available = use_signal(|| Option::<bool>::None);
    let mut display_name = use_signal(|| "yougen user".to_owned());
    let mut device_label = use_signal(|| "yougen device".to_owned());
    let mut recovery_method = use_signal(|| "passphrase".to_owned());
    let mut register_status = use_signal(|| String::new());
    let mut proof_challenge = use_signal(|| String::new());
    let mut proof_audience = use_signal(String::new);
    let mut proof_origin = use_signal(String::new);
    let mut proof_expires_at = use_signal(String::new);
    let mut proof_nonce = use_signal(String::new);
    let mut proof_verification_method = use_signal(|| "authentication".to_owned());

    rsx! {
        div { class: "timeline", "data-testid": "register-panel",
            // Step indicator
            div { class: "event",
                div { class: "event-head",
                    span { "Registration" }
                    span { match step() {
                        RegisterStep::ChooseDid => "Step 1/6: DID path",
                        RegisterStep::HandleInput => "Step 2/6: Handle",
                        RegisterStep::DisplayName => "Step 3/6: Display Name",
                        RegisterStep::DidProof => "Step 4/6: DID Proof",
                        RegisterStep::Recovery => "Step 5/6: Recovery",
                        RegisterStep::DeviceBootstrap => "Step 6/6: Device",
                        RegisterStep::Complete => "Complete",
                    }}
                }
            }

            // Step 1: DID path and generation/binding
            if step() == RegisterStep::ChooseDid {
                div { class: "event", "data-testid": "did-generation",
                    div { class: "event-head", span { "DID" } span { "create or bind" } }
                    div { class: "muted",
                        "Create a portable account identifier or bind one you already control. New production accounts default to did:plc; did:web and did:webvh are available for domain-backed identities. did:key is temporary/test-only."
                    }
                    div { class: "metric-grid", "data-testid": "did-method-policy",
                        div { class: "metric",
                            strong { "Default" }
                            span { "did:plc" }
                            div { class: "muted", "ordinary user principal" }
                        }
                        div { class: "metric",
                            strong { "Domain" }
                            span { "did:web / did:webvh" }
                            div { class: "muted", "domain-backed user, org, or service" }
                        }
                        div { class: "metric",
                            strong { "Temporary" }
                            span { "did:key" }
                            div { class: "muted", "test, bootstrap, device, or invite only" }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: if registration_path() == RegistrationPath::CreateNewDid { "primary" } else { "secondary" },
                            "data-testid": "register-path-create",
                            onclick: move |_| registration_path.set(RegistrationPath::CreateNewDid),
                            "Create new DID"
                        }
                        button {
                            class: if registration_path() == RegistrationPath::BindExistingDid { "primary" } else { "secondary" },
                            "data-testid": "register-path-bind",
                            onclick: move |_| registration_path.set(RegistrationPath::BindExistingDid),
                            "Bind existing DID"
                        }
                    }
                    if registration_path() == RegistrationPath::CreateNewDid {
                        div { class: "actions",
                            button {
                                class: if did_method() == DidMethod::DidPlc { "primary" } else { "secondary" },
                                "data-testid": "did-plc",
                                onclick: move |_| did_method.set(DidMethod::DidPlc),
                                "did:plc"
                            }
                            button {
                                class: if did_method() == DidMethod::DidWeb { "primary" } else { "secondary" },
                                "data-testid": "did-web",
                                onclick: move |_| did_method.set(DidMethod::DidWeb),
                                "did:web"
                            }
                            button {
                                class: if did_method() == DidMethod::DidWebvh { "primary" } else { "secondary" },
                                "data-testid": "did-webvh",
                                onclick: move |_| did_method.set(DidMethod::DidWebvh),
                                "did:webvh"
                            }
                            button {
                                class: if did_method() == DidMethod::DidKey { "primary" } else { "secondary" },
                                "data-testid": "did-key",
                                onclick: move |_| did_method.set(DidMethod::DidKey),
                                "did:key test"
                            }
                        }
                        if did_method() == DidMethod::DidKey {
                            div { class: "event error-banner", "data-testid": "did-key-principal-warning",
                                div { class: "event-head", span { "Temporary DID" } span { "not a long-lived principal" } }
                                div { class: "muted", "did:key is only valid here for temporary, test, bootstrap, device, or invite flows. Production user principals should use did:plc, did:web, or did:webvh." }
                            }
                        }
                        {let did_desc = match did_method() {
                            DidMethod::DidPlc => "did:plc - default portable DID for new accounts",
                            DidMethod::DidWeb => "did:web - domain-backed DID for operators who control DNS/HTTPS",
                            DidMethod::DidWebvh => "did:webvh - domain-backed DID with verifiable history",
                            DidMethod::DidKey => "did:key - temporary/test-only; avoid for durable accounts",
                        };
                        rsx! { div { class: "muted", "Selected: {did_desc}" } }}
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "generate-did-button",
                                onclick: move |_| {
                                    let did = generate_did(did_method());
                                    generated_did.set(did);
                                    step.set(RegisterStep::HandleInput);
                                },
                                "Generate DID"
                            }
                        }
                    } else {
                        div { class: "workflow-form",
                            label { "Existing DID" }
                            input {
                                "data-testid": "bind-existing-did-input",
                                value: "{existing_did}",
                                placeholder: "did:plc:..., did:web:..., did:webvh:..., or did:key:...",
                                oninput: move |evt| {
                                    existing_did.set(evt.value());
                                    existing_did_status.set(String::new());
                                },
                            }
                            div { class: "muted",
                                "Binding keeps the identifier you already control and asks for a scoped proof before account registration."
                            }
                            if !existing_did_status().is_empty() {
                                div { class: "muted", "data-testid": "bind-existing-did-status", "{existing_did_status}" }
                            }
                            div { class: "actions",
                                button {
                                    class: "primary",
                                    "data-testid": "bind-existing-did-button",
                                    onclick: move |_| {
                                        let did = existing_did().trim().to_owned();
                                        if did.trim().is_empty() {
                                            existing_did_status.set("Enter the DID you want to bind.".to_owned());
                                        } else if !is_supported_existing_did(&did) {
                                            existing_did_status.set(
                                                "Supported DID methods are did:plc, did:web, did:webvh, and temporary did:key.".to_owned(),
                                            );
                                        } else {
                                            generated_did.set(did);
                                            step.set(RegisterStep::HandleInput);
                                        }
                                    },
                                    "Use Existing DID"
                                }
                            }
                        }
                    }
                    if !generated_did().is_empty() {
                        div { class: "muted", "DID: {generated_did}" }
                    }
                }
            }

            // Step 2: Handle input
            if step() == RegisterStep::HandleInput {
                div { class: "event", "data-testid": "handle-input",
                    div { class: "event-head", span { "Handle" } span { "username" } }
                    div { class: "workflow-form",
                        input {
                            "data-testid": "register-handle-input",
                            value: "{handle}",
                            placeholder: "alice.example",
                            oninput: move |evt| {
                                handle.set(evt.value());
                                handle_available.set(None);
                            },
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "check-handle-button",
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let h = handle();
                                        spawn(async move {
                                            match ContrixApi::new(&base) {
                                                Ok(api) => match api.resolve_handle(&h).await {
                                                    Ok(_) => handle_available.set(Some(false)),
                                                    Err(_) => handle_available.set(Some(true)),
                                                },
                                                Err(_) => handle_available.set(None),
                                            }
                                        });
                                    }
                                },
                                "Check Availability"
                            }
                        }
                        if let Some(available) = handle_available() {
                            div { class: "muted", "data-testid": "handle-status",
                                if available { "Handle is available" } else { "Handle is taken" }
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "next-to-displayname",
                                onclick: move |_| step.set(RegisterStep::DisplayName),
                                "Next"
                            }
                            button {
                                class: "secondary",
                                onclick: move |_| step.set(RegisterStep::ChooseDid),
                                "Back"
                            }
                        }
                    }
                }
            }

            // Step 3: Display name
            if step() == RegisterStep::DisplayName {
                div { class: "event", "data-testid": "display-name-input",
                    div { class: "event-head", span { "Profile" } span { "display name" } }
                    div { class: "workflow-form",
                        label { "Display Name" }
                        input {
                            "data-testid": "register-display-name",
                            value: "{display_name}",
                            oninput: move |evt| display_name.set(evt.value()),
                        }
                        label { "Device Label" }
                        input {
                            "data-testid": "register-device-label",
                            value: "{device_label}",
                            oninput: move |evt| device_label.set(evt.value()),
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                onclick: move |_| step.set(RegisterStep::DidProof),
                                "Next"
                            }
                            button {
                                class: "secondary",
                                onclick: move |_| step.set(RegisterStep::HandleInput),
                                "Back"
                            }
                        }
                    }
                }
            }

            // Step 4: DID proof challenge
            if step() == RegisterStep::DidProof {
                div { class: "event", "data-testid": "did-proof",
                    div { class: "event-head", span { "DID Proof" } span { "challenge" } }
                    div { class: "muted",
                        "Prove control of the DID by signing a short-lived challenge scoped to this server audience and browser origin. The backend operation is still submitted through the existing placeholder API."
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "generate-proof-button",
                            onclick: {
                                let proof_base_url = base_url.clone();
                                move |_| {
                                    let now = chrono::Utc::now();
                                    proof_challenge.set(format!("challenge-{}", now.timestamp()));
                                    proof_audience.set(proof_base_url.clone());
                                    proof_origin.set("yougen://registration".to_owned());
                                    proof_expires_at.set((now + chrono::Duration::minutes(10)).to_rfc3339());
                                    proof_nonce.set(format!("nonce-{}", crate::operation::uuid_v8()));
                                }
                            },
                            "Generate Challenge"
                        }
                    }
                    if !proof_challenge().is_empty() {
                        div { class: "workflow-form",
                            div { class: "muted", "data-testid": "proof-challenge", "Challenge: {proof_challenge}" }
                            div { class: "muted", "Audience: {proof_audience}" }
                            div { class: "muted", "Origin: {proof_origin}" }
                            div { class: "muted", "Expires: {proof_expires_at}" }
                            div { class: "muted", "Nonce: {proof_nonce}" }
                            label { "Verification Method" }
                            input {
                                "data-testid": "proof-verification-method",
                                value: "{proof_verification_method}",
                                placeholder: "authentication",
                                oninput: move |evt| proof_verification_method.set(evt.value()),
                            }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                onclick: move |_| step.set(RegisterStep::Recovery),
                                "Sign & Continue"
                            }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            onclick: move |_| step.set(RegisterStep::DisplayName),
                            "Back"
                        }
                    }
                }
            }

            // Step 5: Recovery policy
            if step() == RegisterStep::Recovery {
                div { class: "event", "data-testid": "recovery-policy",
                    div { class: "event-head", span { "Recovery" } span { "policy selection" } }
                    div { class: "actions",
                        button {
                            class: if recovery_method() == "passphrase" { "primary" } else { "secondary" },
                            onclick: move |_| recovery_method.set("passphrase".to_owned()),
                            "Passphrase"
                        }
                        button {
                            class: if recovery_method() == "security_key" { "primary" } else { "secondary" },
                            onclick: move |_| recovery_method.set("security_key".to_owned()),
                            "Security Key"
                        }
                    }
                    div { class: "muted", "Selected: {recovery_method}" }
                    div { class: "actions",
                        button {
                            class: "primary",
                            onclick: move |_| step.set(RegisterStep::DeviceBootstrap),
                            "Next"
                        }
                        button {
                            class: "secondary",
                            onclick: move |_| step.set(RegisterStep::DidProof),
                            "Back"
                        }
                    }
                }
            }

            // Step 6: Device bootstrap
            if step() == RegisterStep::DeviceBootstrap {
                div { class: "event", "data-testid": "device-bootstrap",
                    div { class: "event-head", span { "Device Bootstrap" } span { "register account" } }
                    div { class: "muted",
                        "DID: {generated_did}\nHandle: {handle}\nDisplay: {display_name}\nDevice: {device_label}"
                    }
                    {let path_label = match registration_path() {
                        RegistrationPath::CreateNewDid => "create new DID",
                        RegistrationPath::BindExistingDid => "bind existing DID",
                    };
                    rsx! { div { class: "muted", "Registration path: {path_label}" } }}
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "complete-registration-button",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let base = base.clone();
                                    let did = generated_did();
                                    let h = handle();
                                    let name = display_name();
                                    let device = device_label();
                                    let recovery = recovery_method();
                                    let proof = proof_challenge();
                                    let audience = proof_audience();
                                    let origin = proof_origin();
                                    let expires_at = proof_expires_at();
                                    let nonce = proof_nonce();
                                    let verification_method = proof_verification_method();
                                    let did_method_name = match registration_path() {
                                        RegistrationPath::CreateNewDid => did_method().label().to_owned(),
                                        RegistrationPath::BindExistingDid => supported_existing_did_method(&did)
                                            .unwrap_or(did_method().label())
                                            .to_owned(),
                                    };
                                    let operation_type = match registration_path() {
                                        RegistrationPath::CreateNewDid => "cx.did.create",
                                        RegistrationPath::BindExistingDid => "cx.did.bind",
                                    };
                                    spawn(async move {
                                        match ContrixApi::new(&base) {
                                            Ok(api) => {
                                                let did_operation = json!({
                                                    "type": operation_type,
                                                    "did_method": did_method_name,
                                                    "handle": h.clone(),
                                                    "display_name": name.clone(),
                                                    "device_label": device.clone(),
                                                    "recovery_method": recovery,
                                                    "proof": {
                                                        "kind": "development_placeholder",
                                                        "challenge": proof,
                                                        "audience": audience,
                                                        "origin": origin,
                                                        "expires_at": expires_at,
                                                        "nonce": nonce,
                                                        "verification_method": verification_method,
                                                    },
                                                    "submitted_at": chrono::Utc::now().to_rfc3339(),
                                                });

                                                match api.submit_did_operation(&did, did_operation).await {
                                                    Ok(operation) => match api.register_account(
                                                        &did,
                                                        &h,
                                                        Some(&name),
                                                        Some(&device),
                                                    ).await {
                                                        Ok(account) => {
                                                            register_status.set(format!(
                                                                "Registered: {} via {} ({})",
                                                                account.did, operation.operation_id, operation.status
                                                            ));
                                                            step.set(RegisterStep::Complete);
                                                        }
                                                        Err(e) => register_status.set(format!("Registration failed: {e}")),
                                                    },
                                                    Err(error) => register_status.set(format!(
                                                        "DID operation submit failed: {error}"
                                                    )),
                                                }
                                            }
                                            Err(e) => register_status.set(format!("Invalid URL: {e}")),
                                        }
                                    });
                                }
                            },
                            "Complete Registration"
                        }
                        button {
                            class: "secondary",
                            onclick: move |_| step.set(RegisterStep::Recovery),
                            "Back"
                        }
                    }
                    if !register_status().is_empty() {
                        div { class: "muted", "data-testid": "register-status", "{register_status}" }
                    }
                }
            }

            // Complete
            if step() == RegisterStep::Complete {
                div { class: "event", "data-testid": "registration-complete",
                    div { class: "event-head", span { "Complete" } span { "success" } }
                    div { class: "space-title", "Account registered successfully!" }
                    div { class: "muted", "DID: {generated_did}" }
                    div { class: "muted", "Handle: {handle}" }
                    if !register_status().is_empty() {
                        div { class: "muted", "data-testid": "register-summary-status", "{register_status}" }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "continue-to-login",
                            onclick: move |_| on_register.call(()),
                            "Continue to Login"
                        }
                    }
                }
            }
        }
    }
}

fn generate_did(method: DidMethod) -> String {
    let timestamp = (chrono::Utc::now().timestamp_millis() as u64) & 0x0fff_ffff_ffff;
    let mut seed = [0u8; 16];
    let _ = getrandom::fill(&mut seed);
    let random_hex = seed
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    match method {
        DidMethod::DidPlc => format!("did:plc:{}", &random_hex[..24]),
        DidMethod::DidWeb => format!("did:web:user-{:011x}.example", timestamp),
        DidMethod::DidWebvh => format!("did:webvh:user-{:011x}.example", timestamp),
        DidMethod::DidKey => format!("did:key:z{}", URL_SAFE_NO_PAD.encode(seed)),
    }
}

fn is_supported_existing_did(did: &str) -> bool {
    supported_existing_did_method(did).is_some()
}

fn supported_existing_did_method(did: &str) -> Option<&'static str> {
    let did = did.trim();
    if did.starts_with("did:plc:") {
        Some("did:plc")
    } else if did.starts_with("did:webvh:") {
        Some("did:webvh")
    } else if did.starts_with("did:web:") {
        Some("did:web")
    } else if did.starts_with("did:key:") {
        Some("did:key")
    } else {
        None
    }
}
