use dioxus::prelude::*;

use crate::{
    models::ContactResponse,
    views::helpers::{short_protocol_id, with_authed_api},
};

#[component]
pub fn ContactNewPanel(base_url: String, token: Signal<String>) -> Element {
    let mut target = use_signal(String::new);
    let mut scope = use_signal(|| "message".to_owned());
    let mut status = use_signal(|| "ready".to_owned());

    rsx! {
        div { class: "settings", "data-testid": "contact-request-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { "New contact" }
                            span { "consent gate" }
                        }
                        label { "DID" }
                        input {
                            "data-testid": "contact-target-input",
                            value: "{target}",
                            placeholder: "did:web:alice.example",
                            oninput: move |evt| target.set(evt.value()),
                        }
                        label { "Scope" }
                        select {
                            "data-testid": "contact-scope-select",
                            value: "{scope}",
                            onchange: move |evt| scope.set(evt.value()),
                            option { value: "invite", "invite" }
                            option { value: "message", "message" }
                            option { value: "call", "call" }
                        }
                        div { class: "actions",
                            button {
                                class: "primary",
                                "data-testid": "send-contact-request-button",
                                disabled: target.read().trim().is_empty(),
                                onclick: {
                                    let base = base_url.clone();
                                    move |_| {
                                        let api_token = token();
                                        let base = base.clone();
                                        let target_did = target().trim().to_owned();
                                        let requested_scope = scope();
                                        spawn(async move {
                                            match with_authed_api(&base, api_token, |api| async move {
                                                api.request_contact_scoped(&target_did, &requested_scope).await
                                            })
                                            .await
                                            {
                                                Ok(contact) => status.set(format!(
                                                    "{} {} {}",
                                                    contact.status, contact.scope, contact.target
                                                )),
                                                Err(err) => status.set(format!("error {}", err.display())),
                                            }
                                        });
                                    }
                                },
                                "Send"
                            }
                        }
                        div {
                            class: "muted",
                            "data-testid": "contact-request-status",
                            "{status}"
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn ContactsPanel(base_url: String, token: Signal<String>) -> Element {
    let mut contacts = use_signal(Vec::<ContactResponse>::new);
    let mut status = use_signal(|| "loading".to_owned());
    let mut loaded = use_signal(|| false);

    {
        let base = base_url.clone();
        use_effect(move || {
            if loaded() {
                return;
            }
            loaded.set(true);
            let api_token = token();
            let base = base.clone();
            spawn(async move {
                match with_authed_api(&base, api_token, |api| async move { api.contacts().await }).await {
                    Ok(response) => {
                        let count = response.contacts.len();
                        contacts.set(response.contacts);
                        status.set(format!("contacts {count}"));
                    }
                    Err(err) => status.set(format!("error {}", err.display())),
                }
            });
        });
    }

    rsx! {
        div { class: "settings", "data-testid": "contacts-panel",
            div { class: "settings-shell",
                section { class: "settings-content-stack",
                    div { class: "event",
                        div { class: "event-head",
                            span { "Contacts" }
                            span { "{status}" }
                        }
                        if contacts.read().is_empty() {
                            div { class: "muted", "No contacts" }
                        } else {
                            ul { class: "settings-list",
                                for contact in contacts.read().iter().cloned() {
                                    li {
                                        class: "event",
                                        "data-testid": "contact-row",
                                        "data-requester": "{contact.requester}",
                                        "data-target": "{contact.target}",
                                        "data-status": "{contact.status}",
                                        div { class: "event-head",
                                            span { "{contact.status}" }
                                            span { class: "mono", title: "{contact.target}", "{short_protocol_id(&contact.target)}" }
                                        }
                                        div { class: "muted",
                                            "{contact.requester} -> {contact.target}"
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
}
