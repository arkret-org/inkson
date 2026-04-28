use dioxus::prelude::*;
use serde_json::json;

use crate::{
    crypto::compose_local_encrypted_message, local_state::LocalStateStore,
    views::helpers::authed_api,
};

const EMOJI_GRID: &[&str] = &[
    "\u{1f44d}",
    "\u{2764}\u{fe0f}",
    "\u{1f602}",
    "\u{1f62e}",
    "\u{1f622}",
    "\u{1f389}",
    "\u{1f525}",
    "\u{1f44e}",
    "\u{1f64f}",
    "\u{1f440}",
    "\u{1f4af}",
    "\u{1f680}",
];

/// Event model for timeline display.
#[derive(Clone, Debug, PartialEq)]
pub struct TimelineEvent {
    pub id: String,
    pub sender: String,
    pub sender_display: String,
    pub body: String,
    pub timestamp: String,
    pub reply_to: Option<String>,
    pub reactions: Vec<(String, Vec<String>)>,
    pub redacted: bool,
    pub edited: bool,
    pub thread_id: Option<String>,
    pub blob_ref: Option<String>,
}

impl Default for TimelineEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            sender: "chask".to_owned(),
            sender_display: "local".to_owned(),
            body: String::new(),
            timestamp: String::new(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            thread_id: None,
            blob_ref: None,
        }
    }
}

#[component]
pub fn TimelinePanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_space: String,
    timeline: Signal<Vec<String>>,
    draft: Signal<String>,
    state_store: Signal<LocalStateStore>,
    crypto_state: Signal<String>,
    base_url_sig: Signal<String>,
) -> Element {
    let mut show_reaction_picker = use_signal(|| Option::<usize>::None);
    let mut editing_index = use_signal(|| Option::<usize>::None);
    let mut edit_draft = use_signal(String::new);
    let mut redact_confirm = use_signal(|| Option::<usize>::None);
    let mut reply_to_index = use_signal(|| Option::<usize>::None);
    let mut thread_open = use_signal(|| Option::<usize>::None);
    let mut encrypt_toggle = use_signal(|| false);
    let _typing_indicator = use_signal(|| String::new());
    let read_receipts = use_signal(Vec::<String>::new);
    let mut blob_status = use_signal(|| String::new());
    let mut search_query = use_signal(String::new);

    // Clone String params so they can be used in multiple closures
    let _base_url_c = base_url.clone();
    let account_did_c = account_did.clone();
    let device_id_c = device_id.clone();
    let selected_space_c = selected_space.clone();

    let events_data: Vec<(usize, TimelineEvent)> = timeline()
        .iter()
        .enumerate()
        .map(|(i, body)| {
            (
                i,
                TimelineEvent {
                    id: format!("local-event-{i}"),
                    sender: "chask".to_owned(),
                    sender_display: "local".to_owned(),
                    body: body.clone(),
                    timestamp: "now".to_owned(),
                    reply_to: None,
                    reactions: Vec::new(),
                    redacted: false,
                    edited: false,
                    thread_id: None,
                    blob_ref: None,
                },
            )
        })
        .collect();

    rsx! {
        div { class: "timeline", "data-testid": "timeline",
            // Message search bar
            div { class: "composer", style: "margin-bottom: 8px;",
                input {
                    r#type: "text",
                    "data-testid": "timeline-search",
                    placeholder: "Search messages...",
                    value: "{search_query}",
                    oninput: move |evt| search_query.set(evt.value()),
                }
            }

            for (idx, event) in events_data.into_iter() {
                // Filter by search query
                if search_query().is_empty() || event.body.to_lowercase().contains(&search_query().to_lowercase()) {
                div {
                    class: "event",
                    "data-testid": "timeline-event",
                    key: "{event.id}",

                    div { class: "event-head",
                        span { "{event.sender_display}" }
                        span { "{event.timestamp}" }
                    }

                    if let Some(reply_id) = &event.reply_to {
                        div { class: "muted", "data-testid": "reply-indicator",
                            "\u{21a9}\u{fe0f} Reply to {reply_id}"
                        }
                    }

                    if event.redacted {
                        div { class: "muted", "[Message redacted]" }
                    } else {
                        div { "data-testid": "event-body", "{event.body}" }

                        if event.edited {
                            span { class: "muted", " (edited)" }
                        }

                        if let Some(blob_ref) = &event.blob_ref {
                            div { class: "muted", "data-testid": "blob-attachment",
                                // Image preview for image blobs
                                if blob_ref.ends_with(".png") || blob_ref.ends_with(".jpg") || blob_ref.ends_with(".jpeg") || blob_ref.ends_with(".gif") || blob_ref.ends_with(".webp") {
                                    img {
                                        src: "{base_url}/api/v1/blob/get?blob_ref={blob_ref}",
                                        alt: "Attached image",
                                        style: "max-width: 300px; max-height: 200px; border-radius: 4px; margin: 4px 0;",
                                        loading: "lazy",
                                    }
                                }
                                a {
                                    href: "{base_url}/api/v1/blob/get?blob_ref={blob_ref}",
                                    target: "_blank",
                                    "\u{1f4ce} Blob: {blob_ref}"
                                }
                            }
                        }

                        // Reactions display
                        if !event.reactions.is_empty() {
                            div { class: "actions",
                                for (emoji, senders) in &event.reactions {
                                    button {
                                        class: "secondary",
                                        "data-testid": "reaction-badge",
                                        "{emoji} {senders.len()}"
                                    }
                                }
                            }
                        }

                        // Action buttons
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "reply-button",
                                onclick: move |_| reply_to_index.set(Some(idx)),
                                "Reply"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "react-button",
                                onclick: move |_| {
                                    let current = show_reaction_picker();
                                    show_reaction_picker.set(if current == Some(idx) { None } else { Some(idx) });
                                },
                                "React"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "edit-button",
                                onclick: move |_| {
                                    editing_index.set(Some(idx));
                                    edit_draft.set(event.body.clone());
                                },
                                "Edit"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "redact-button",
                                onclick: move |_| redact_confirm.set(Some(idx)),
                                "Redact"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "thread-button",
                                onclick: move |_| {
                                    let current = thread_open();
                                    thread_open.set(if current == Some(idx) { None } else { Some(idx) });
                                },
                                "Thread"
                            }
                        }

                        // Reaction picker
                        if show_reaction_picker() == Some(idx) {
                            div { class: "actions", "data-testid": "reaction-picker",
                                for emoji in EMOJI_GRID {
                                    button {
                                        class: "secondary",
                                        key: "{emoji}",
                                        onclick: {
                                            let base = base_url.clone();
                                            let eid = event.id.clone();
                                            let emoji = emoji.to_string();
                                            move |_| {
                                                let base = base.clone();
                                                let eid = eid.clone();
                                                let emoji = emoji.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    if let Ok(api) = authed_api(&base, api_token) {
                                                        let _ = api.add_reaction(&eid, &emoji).await;
                                                    }
                                                });
                                                show_reaction_picker.set(None);
                                            }
                                        },
                                        "{emoji}"
                                    }
                                }
                            }
                        }

                        // Edit input
                        if editing_index() == Some(idx) {
                            div { class: "composer", "data-testid": "edit-composer",
                                textarea {
                                    value: "{edit_draft}",
                                    oninput: move |evt| edit_draft.set(evt.value()),
                                }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "save-edit-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let eid = event.id.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let eid = eid.clone();
                                                let content = edit_draft();
                                                let api_token = token();
                                                spawn(async move {
                                                    if let Ok(api) = authed_api(&base, api_token) {
                                                        let _ = api.edit_message(&eid, json!({"msgtype": "m.text", "body": content})).await;
                                                    }
                                                });
                                                editing_index.set(None);
                                            }
                                        },
                                        "Save"
                                    }
                                    button {
                                        class: "secondary",
                                        onclick: move |_| editing_index.set(None),
                                        "Cancel"
                                    }
                                }
                            }
                        }

                        // Redact confirm dialog
                        if redact_confirm() == Some(idx) {
                            div { class: "event", "data-testid": "redact-confirm",
                                div { class: "space-title", "Redact this message?" }
                                div { class: "actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "confirm-redact-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let eid = event.id.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let eid = eid.clone();
                                                let api_token = token();
                                                spawn(async move {
                                                    if let Ok(api) = authed_api(&base, api_token) {
                                                        let _ = api.redact_message(&eid, None).await;
                                                    }
                                                });
                                                redact_confirm.set(None);
                                            }
                                        },
                                        "Confirm Redact"
                                    }
                                    button {
                                        class: "secondary",
                                        onclick: move |_| redact_confirm.set(None),
                                        "Cancel"
                                    }
                                }
                            }
                        }

                        // Thread selector
                        if thread_open() == Some(idx) {
                            div { class: "event", "data-testid": "thread-panel",
                                div { class: "event-head",
                                    span { "Thread" }
                                    span { "{event.id}" }
                                }
                                div { class: "muted", "Thread messages would appear here." }
                                div { class: "actions",
                                    button {
                                        class: "secondary",
                                        onclick: move |_| thread_open.set(None),
                                        "Close Thread"
                                    }
                                }
                            }
                        }
                    }
                }
                } // end search filter
            }

            if timeline().is_empty() {
                div { class: "event",
                    div { class: "event-head", span { "serverx" } span { "empty" } }
                    div { "No timeline events yet. Compose a dev-mode message." }
                }
            }
        }

        // Composer section
        div { class: "composer", "data-testid": "composer",
            if let Some(reply_idx) = reply_to_index() {
                div { class: "muted", "data-testid": "reply-to-banner",
                    "Replying to local-event-{reply_idx}"
                    button {
                        class: "secondary",
                        onclick: move |_| reply_to_index.set(None),
                        "Cancel Reply"
                    }
                }
            }

            textarea {
                "data-testid": "composer-input",
                value: "{draft}",
                placeholder: if encrypt_toggle() { "Write an encrypted message" } else { "Write a plaintext dev-mode message" },
                oninput: {
                    let sc = selected_space_c.clone();
                    move |event| {
                    let value = event.value();
                    draft.set(value.clone());
                    state_store.write().save_draft(sc.clone(), value);
                    // Send typing indicator
                    let base = base_url_sig();
                    let api_token = token();
                    let space = sc.clone();
                    spawn(async move {
                        if let Ok(api) = authed_api(&base, api_token) {
                            let _ = api.send_typing(&space, true).await;
                        }
                    });
                }},
            }

            div { class: "actions",
                // Encrypt toggle
                label {
                    input {
                        r#type: "checkbox",
                        "data-testid": "encrypt-local-button",
                        checked: encrypt_toggle(),
                        onchange: move |evt| encrypt_toggle.set(evt.value() == "true"),
                    }
                    " Encrypt Local"
                }

                // File attachment button
                button {
                    class: "secondary",
                    "data-testid": "attach-blob-button",
                    onclick: move |_| {
                        let base = base_url_sig();
                        let api_token = token();
                        spawn(async move {
                            if let Ok(api) = authed_api(&base, api_token) {
                                match api.upload_blob(b"chask attached bytes").await {
                                    Ok(blob) => blob_status.set(format!("attached {}", blob.blob_ref)),
                                    Err(e) => blob_status.set(format!("attach failed: {e}")),
                                }
                            }
                        });
                    },
                    "Attach Blob"
                }

                button {
                    class: "primary",
                    "data-testid": "send-button",
                    onclick: {
                        let sc = selected_space_c.clone();
                        let ac = account_did_c.clone();
                        let dc = device_id_c.clone();
                        move |_| {
                        let body = draft().trim().to_owned();
                        if body.is_empty() {
                            return;
                        }

                        let space_for_encrypt = sc.clone();
                        let space_for_plain = sc.clone();
                        let space_for_draft = sc.clone();
                        if encrypt_toggle() {
                            match compose_local_encrypted_message(
                                &ac,
                                &dc,
                                &space_for_encrypt,
                                "cx:message:local-compose",
                                &body,
                            ) {
                                Ok(message) => {
                                    timeline.write().push(format!(
                                        "encrypted {} epoch {} digest {}",
                                        message.payload.scheme.as_str(),
                                        message.payload.epoch,
                                        message.payload.payload_digest
                                    ));
                                    crypto_state.set(format!(
                                        "encrypted local payload for {}",
                                        message.payload.group_id
                                    ));
                                    state_store.write().save_draft(space_for_encrypt, "");
                                    draft.set(String::new());
                                }
                                Err(error) => crypto_state.set(format!("encrypt failed: {error}")),
                            }
                        } else {
                            let base = base_url_sig();
                            let space = space_for_plain;
                            let api_token = token();
                            let reply = reply_to_index();
                            let body_clone = body.clone();
                            spawn(async move {
                                if let Ok(api) = authed_api(&base, api_token) {
                                    let thread_id = reply.map(|r| format!("local-event-{r}"));
                                    let _ = api.send_message(
                                        &space,
                                        thread_id.as_deref(),
                                        json!({"msgtype": "m.text", "body": body_clone}),
                                        false,
                                    ).await;
                                }
                            });
                            timeline.write().push(body);
                            state_store.write().save_draft(space_for_draft, "");
                            draft.set(String::new());
                            reply_to_index.set(None);
                        }
                    }},
                    "Send"
                }

                button {
                    class: "secondary",
                    "data-testid": "report-queue-button",
                    onclick: {
                        let sc = selected_space_c.clone();
                        let ac = account_did_c.clone();
                        let dc = device_id_c.clone();
                        move |_| {
                        let base = base_url_sig();
                        let actor = ac.clone();
                        let dev = dc.clone();
                        let api_token = token();
                        let space = sc.clone();
                        spawn(async move {
                            if let Ok(api) = authed_api(&base, api_token) {
                                let _ = api.report_moderation(&space, "local:event", "spam", &actor).await;
                                let _ = api.send_to_device(&actor, &dev).await;
                            }
                        });
                    }},
                    "Report / Queue"
                }
            }

            if !blob_status().is_empty() {
                div { class: "muted", "data-testid": "blob-status", "{blob_status}" }
            }

            if !read_receipts().is_empty() {
                div { class: "muted", "data-testid": "read-receipts",
                    "Read by: {read_receipts:?}"
                }
            }
        }
    }
}
