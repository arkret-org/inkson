// TRUST-CACHE: contact card / contact list per CKP B-E §1 — these
// surfaces MAY consult the locally cached `binding_state` (verified
// badge, mention autocomplete fields). On cache miss or any
// identity-handles.md §6.1.2 trigger the UI MUST downgrade to an
// "unverified" badge. For authority surfaces (wallet disclosure /
// accept invite / audit-trail review) callers MUST first-party verify
// the DID Document via `crate::did_resolver::build_default_resolver`
// instead of relying on the cached binding state surfaced here.

use dioxus::prelude::*;

use crate::models::ContactListRow;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::views::helpers::{short_protocol_id, with_authed_api};

#[component]
pub fn ContactNewPanel(base_url: String, token: Signal<String>) -> Element {
    let mut target = use_signal(String::new);
    let mut scope = use_signal(|| "direct_message".to_owned());
    let scope_selected = use_memo(move || Some(scope()));
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
                        Label { html_for: "contact-target-input-input", "DID" }
                        Input {
                            id: "contact-target-input-input",
                            "data-testid": "contact-target-input",
                            value: "{target}",
                            placeholder: "did:web:alice.example",
                            oninput: move |event: FormEvent| target.set(event.value()),
                        }
                        Label { html_for: "contact-scope-select-input", "Scope" }
                        Select::<String> {
                            id: "contact-scope-select-input",
                            "data-testid": "contact-scope-select",
                            value: Some(scope_selected.into()),
                            on_value_change: move |v: Option<String>| { if let Some(v) = v { scope.set(v); } },
                            SelectOption::<String> { index: 0usize, value: "invite".to_string(), text_value: "invite", "invite" }
                            SelectOption::<String> { index: 1usize, value: "direct_message".to_string(), text_value: "direct_message", "direct_message" }
                            SelectOption::<String> { index: 2usize, value: "voice_call".to_string(), text_value: "voice_call", "voice_call" }
                            SelectOption::<String> { index: 3usize, value: "video_call".to_string(), text_value: "video_call", "video_call" }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
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
    let mut contacts = use_signal(Vec::<ContactListRow>::new);
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
                match with_authed_api(&base, api_token, |api| async move { api.contacts().await })
                    .await
                {
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
                                for contact in contacts.read().iter() {
                                    li {
                                        class: "event",
                                        "data-testid": "contact-row",
                                        "data-peer": "{contact.peer}",
                                        "data-state": "{contact.state}",
                                        div { class: "event-head",
                                            span { "{contact.state}" }
                                            span { class: "mono", title: "{contact.peer}", "{short_protocol_id(&contact.peer)}" }
                                        }
                                        div { class: "muted",
                                            "scopes: {contact.bidirectional_scopes.join(\", \")}"
                                        }
                                        if let Some(summary) = &contact.direct_conversation {
                                            div { class: "muted mono",
                                                "dm {short_protocol_id(&summary.realm_id)} / {short_protocol_id(&summary.main_flow_id)}"
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
}
