use dioxus::prelude::*;

use crate::api::ContrixApi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DidMethod {
    DidUuid,
    DidWeb,
    DidKey,
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
pub fn RegisterPanel(
    base_url: String,
    on_register: EventHandler<()>,
) -> Element {
    let mut step = use_signal(|| RegisterStep::ChooseDid);
    let mut did_method = use_signal(|| DidMethod::DidUuid);
    let mut generated_did = use_signal(String::new);
    let mut handle = use_signal(String::new);
    let mut handle_available = use_signal(|| Option::<bool>::None);
    let mut display_name = use_signal(|| "clientx user".to_owned());
    let mut device_label = use_signal(|| "clientx device".to_owned());
    let mut recovery_method = use_signal(|| "passphrase".to_owned());
    let mut register_status = use_signal(|| String::new());
    let mut proof_challenge = use_signal(|| String::new());

    rsx! {
        div { class: "timeline", "data-testid": "register-panel",
            // Step indicator
            div { class: "event",
                div { class: "event-head",
                    span { "Registration" }
                    span { match step() {
                        RegisterStep::ChooseDid => "Step 1/6: Choose DID",
                        RegisterStep::HandleInput => "Step 2/6: Handle",
                        RegisterStep::DisplayName => "Step 3/6: Display Name",
                        RegisterStep::DidProof => "Step 4/6: DID Proof",
                        RegisterStep::Recovery => "Step 5/6: Recovery",
                        RegisterStep::DeviceBootstrap => "Step 6/6: Device",
                        RegisterStep::Complete => "Complete",
                    }}
                }
            }

            // Step 1: DID generation
            if step() == RegisterStep::ChooseDid {
                div { class: "event", "data-testid": "did-generation",
                    div { class: "event-head", span { "DID Generation" } span { "select method" } }
                    div { class: "actions",
                        button {
                            class: if did_method() == DidMethod::DidUuid { "primary" } else { "secondary" },
                            "data-testid": "did-uuid",
                            onclick: move |_| did_method.set(DidMethod::DidUuid),
                            "did:uuid"
                        }
                        button {
                            class: if did_method() == DidMethod::DidWeb { "primary" } else { "secondary" },
                            "data-testid": "did-web",
                            onclick: move |_| did_method.set(DidMethod::DidWeb),
                            "did:web"
                        }
                        button {
                            class: if did_method() == DidMethod::DidKey { "primary" } else { "secondary" },
                            "data-testid": "did-key",
                            onclick: move |_| did_method.set(DidMethod::DidKey),
                            "did:key"
                        }
                    }
                    {let did_desc = match did_method() {
                        DidMethod::DidUuid => "did:uuid - UUID-based identifier",
                        DidMethod::DidWeb => "did:web - Web-based identifier",
                        DidMethod::DidKey => "did:key - Cryptographic key identifier",
                    };
                    rsx! { div { class: "muted", "Selected: {did_desc}" } }}
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "generate-did-button",
                            onclick: move |_| {
                                let uuid = format!("{:032x}", 0u128); // placeholder UUID
                                let did = match did_method() {
                                    DidMethod::DidUuid => format!("did:uuid:{uuid}"),
                                    DidMethod::DidWeb => format!("did:web:{}", &uuid[..16]),
                                    DidMethod::DidKey => format!("did:key:z{}", &uuid[..32]),
                                };
                                generated_did.set(did);
                                step.set(RegisterStep::HandleInput);
                            },
                            "Generate DID"
                        }
                    }
                    if !generated_did().is_empty() {
                        div { class: "muted", "Generated: {generated_did}" }
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
                    div { class: "muted", "Prove ownership of your DID. A challenge will be generated." }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "generate-proof-button",
                            onclick: move |_| {
                                proof_challenge.set(format!("challenge-{}", chrono::Utc::now().timestamp()));
                            },
                            "Generate Challenge"
                        }
                    }
                    if !proof_challenge().is_empty() {
                        div { class: "muted", "data-testid": "proof-challenge", "Challenge: {proof_challenge}" }
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
                        button {
                            class: if recovery_method() == "social_recovery" { "primary" } else { "secondary" },
                            onclick: move |_| recovery_method.set("social_recovery".to_owned()),
                            "Social Recovery"
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
                                    spawn(async move {
                                        match ContrixApi::new(&base) {
                                            Ok(api) => match api.register_account(
                                                &did,
                                                &h,
                                                Some(&name),
                                                Some(&device),
                                            ).await {
                                                Ok(account) => {
                                                    register_status.set(format!("Registered: {}", account.did));
                                                    step.set(RegisterStep::Complete);
                                                }
                                                Err(e) => register_status.set(format!("Registration failed: {e}")),
                                            },
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
