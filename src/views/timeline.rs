use chrono::Utc;
use dioxus::prelude::*;
use serde_json::json;

use crate::{
    conformance::PlaintextBoundary,
    crypto::compose_local_encrypted_message,
    local_state::{LocalStateStore, ReadMarkerRecord},
    media::{hash_matches, media_type_preview_policy, sha256_hex},
    operation::uuid_v8,
    views::helpers::authed_api_with_sync,
};

const ATTACHMENT_BYTES: &[u8] = b"yougen encrypted bytes";

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

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TimelineRevision {
    pub body: String,
    pub timestamp: String,
    pub operation_id: Option<String>,
    pub commit_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct BlobAttachment {
    blob_ref: String,
    size: usize,
    media_type: String,
    sha256: String,
    thumbnail_ref: Option<String>,
}

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
    pub operation_id: Option<String>,
    pub commit_id: Option<String>,
    pub redaction_id: Option<String>,
    pub tombstone_reason: Option<String>,
    pub revisions: Vec<TimelineRevision>,
    pub pending: bool,
}

impl Default for TimelineEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            sender: "yougen".to_owned(),
            sender_display: "local".to_owned(),
            body: String::new(),
            timestamp: String::new(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            thread_id: None,
            blob_ref: None,
            operation_id: None,
            commit_id: None,
            redaction_id: None,
            tombstone_reason: None,
            revisions: Vec::new(),
            pending: false,
        }
    }
}

impl TimelineEvent {
    pub fn system_notice(
        id: impl Into<String>,
        sender_display: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            sender: "did:web:serverx.local".to_owned(),
            sender_display: sender_display.into(),
            body: body.into(),
            timestamp: timestamp_now(),
            ..Self::default()
        }
    }

    pub fn pending_message(
        id: impl Into<String>,
        sender: impl Into<String>,
        sender_display: impl Into<String>,
        body: impl Into<String>,
        reply_to: Option<String>,
        thread_id: Option<String>,
    ) -> Self {
        Self {
            id: id.into(),
            sender: sender.into(),
            sender_display: sender_display.into(),
            body: body.into(),
            timestamp: timestamp_now(),
            reply_to,
            thread_id,
            pending: true,
            ..Self::default()
        }
    }

    pub fn apply_send_ack(&mut self, event_id: String, operation_id: String, commit_id: String) {
        self.id = event_id;
        self.operation_id = Some(operation_id);
        self.commit_id = Some(commit_id);
        self.pending = false;
    }

    pub fn apply_revision(
        &mut self,
        new_body: String,
        operation_id: Option<String>,
        commit_id: Option<String>,
    ) {
        self.revisions.push(TimelineRevision {
            body: self.body.clone(),
            timestamp: self.timestamp.clone(),
            operation_id: self.operation_id.clone(),
            commit_id: self.commit_id.clone(),
        });
        self.body = new_body;
        self.timestamp = timestamp_now();
        self.operation_id = operation_id;
        self.commit_id = commit_id;
        self.redacted = false;
        self.redaction_id = None;
        self.tombstone_reason = None;
        self.edited = true;
        self.pending = false;
    }

    pub fn apply_redaction(&mut self, redaction_id: String, reason: Option<String>) {
        self.redacted = true;
        self.operation_id = None;
        self.commit_id = None;
        self.redaction_id = Some(redaction_id);
        self.tombstone_reason = reason;
        self.timestamp = timestamp_now();
        self.pending = false;
    }

    pub fn fact_summary(&self) -> Option<String> {
        match (
            self.operation_id.as_deref(),
            self.commit_id.as_deref(),
            self.redaction_id.as_deref(),
        ) {
            (_, _, Some(redaction_id)) => Some(format!("tombstone {redaction_id}")),
            (Some(operation_id), Some(commit_id), _) => {
                Some(format!("fact {operation_id} / commit {commit_id}"))
            }
            (Some(operation_id), None, _) => Some(format!("fact {operation_id}")),
            _ => None,
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
    timeline: Signal<Vec<TimelineEvent>>,
    draft: Signal<String>,
    state_store: Signal<LocalStateStore>,
    crypto_state: Signal<String>,
    sync_cursor: Signal<String>,
    repo_state: Signal<String>,
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
    let mut read_receipts = use_signal(Vec::<String>::new);
    let mut receipt_status = use_signal(|| "Read receipt: none".to_owned());
    let mut blob_status = use_signal(|| String::new());
    let mut attached_blob = use_signal(|| Option::<BlobAttachment>::None);
    let mut write_status = use_signal(|| String::new());
    let mut search_query = use_signal(String::new);
    let mut private_plaintext = use_signal(|| false);
    let mut plaintext_ack = use_signal(|| false);

    let account_did_c = account_did.clone();
    let device_id_c = device_id.clone();
    let selected_space_c = selected_space.clone();
    let account_did_key = account_did.clone();
    let device_id_key = device_id.clone();
    let selected_space_key = selected_space.clone();
    let latest_read_marker = state_store.read().latest_read_marker(&selected_space);
    let latest_read_marker_event_id = latest_read_marker
        .as_ref()
        .map(|marker| marker.body.event_id.clone());
    let read_marker_status = latest_read_marker
        .as_ref()
        .map(read_marker_status_label)
        .unwrap_or_else(|| "Read marker: none".to_owned());

    let events_data: Vec<(usize, TimelineEvent)> = timeline()
        .iter()
        .enumerate()
        .map(|(i, event)| (i, event.clone()))
        .collect();
    let plaintext_service = plaintext_visible_service(&base_url);
    let plaintext_boundary = PlaintextBoundary {
        allowed_services: vec![plaintext_service.clone()],
        is_e2ee: encrypt_toggle(),
    };
    let plaintext_can_leave = plaintext_boundary.can_send_plaintext(&plaintext_service);
    let plaintext_blocked = private_plaintext() && !encrypt_toggle() && !plaintext_ack();

    rsx! {
        div {
            class: "timeline",
            "data-testid": "timeline",
            role: "feed",
            "aria-label": "Timeline events",
            "aria-live": "polite",
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
                if search_query().is_empty()
                    || event.body.to_lowercase().contains(&search_query().to_lowercase())
                    || event.revisions.iter().any(|revision| {
                        revision
                            .body
                            .to_lowercase()
                            .contains(&search_query().to_lowercase())
                    })
                {
                    div {
                        class: "event",
                        "data-testid": "timeline-event",
                        role: "article",
                        "aria-label": "Timeline event from {event.sender_display}",
                        key: "{event.id}",

                        div { class: "event-head",
                            span { "{event.sender_display}" }
                            span {
                                "{event.timestamp}"
                                if event.pending {
                                    " (pending)"
                                }
                            }
                        }

                        if latest_read_marker_event_id.as_deref() == Some(event.id.as_str()) {
                            div { class: "muted", "data-testid": "read-marker-badge",
                                "Read marker here"
                            }
                        }

                        if let Some(reply_id) = &event.reply_to {
                            div { class: "muted", "data-testid": "reply-indicator",
                                "\u{21a9}\u{fe0f} Reply to {reply_id}"
                            }
                        }

                        if event.redacted {
                            div { class: "muted", "data-testid": "redacted-tombstone", "[Message redacted]" }
                            if let Some(reason) = &event.tombstone_reason {
                                div { class: "muted", "Tombstone reason: {reason}" }
                            }
                        } else {
                            div { "data-testid": "event-body", "{event.body}" }
                            if event.edited {
                                span { class: "muted", " (edited)" }
                            }

                            if let Some(blob_ref) = &event.blob_ref {
                                div { class: "muted", "data-testid": "blob-attachment",
                                    div { "Blob: {blob_ref}" }
                                    div {
                                        "Downloaded through the authenticated blob API; bearer tokens are not embedded in media URLs."
                                    }
                                }
                            }

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
                                    onclick: {
                                        let body = event.body.clone();
                                        move |_| {
                                            editing_index.set(Some(idx));
                                            edit_draft.set(body.clone());
                                        }
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
                                button {
                                    class: "secondary",
                                    "data-testid": "mark-read-button",
                                    disabled: event.pending || selected_space.trim().is_empty(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let event_id = event.id.clone();
                                        let space = selected_space.clone();
                                        let topic_id = event.thread_id.clone();
                                        let actor = account_did.clone();
                                        let device = device_id.clone();
                                        move |_| {
                                            if event_id.trim().is_empty() || space.trim().is_empty() {
                                                write_status.set("mark read skipped: missing event or space".to_owned());
                                                return;
                                            }

                                            let marker = state_store.write().save_read_marker(
                                                actor.clone(),
                                                device.clone(),
                                                space.clone(),
                                                topic_id.clone(),
                                                event_id.clone(),
                                            );
                                            write_status.set(format!("read marker saved {}", marker.body.event_id));
                                            receipt_status.set(format!("Read receipt: sending {}", marker.body.event_id));

                                            let base = base.clone();
                                            let api_token = token();
                                            let wait_for = active_sync_token(sync_cursor());
                                            let receipt_space = marker.body.space_id.clone();
                                            let receipt_event_id = marker.body.event_id.clone();
                                            let actor_for_status = marker.actor.clone();
                                            spawn(async move {
                                                match authed_api_with_sync(&base, api_token, wait_for) {
                                                    Ok(api) => match api
                                                        .send_receipt(
                                                            &receipt_space,
                                                            &receipt_event_id,
                                                            "cx.receipt.read",
                                                        )
                                                        .await
                                                    {
                                                        Ok(receipt) if receipt.ok => {
                                                            read_receipts.write().push(format!(
                                                                "{actor_for_status} -> {receipt_event_id}"
                                                            ));
                                                            receipt_status.set(format!(
                                                                "Read receipt: sent cx.receipt.read for {receipt_event_id}"
                                                            ));
                                                        }
                                                        Ok(_) => receipt_status.set(format!(
                                                            "Read receipt: server returned not ok for {receipt_event_id}"
                                                        )),
                                                        Err(error) => receipt_status.set(format!(
                                                            "Read receipt failed: {error}"
                                                        )),
                                                    },
                                                    Err(error) => receipt_status.set(format!(
                                                        "Read receipt failed: {error}"
                                                    )),
                                                }
                                            });
                                        }
                                    },
                                    "Mark Read"
                                }
                            }

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
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    spawn(async move {
                                                        if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
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
                                                let space = selected_space.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let space = space.clone();
                                                    let content = edit_draft().trim().to_owned();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    if content.is_empty() {
                                                        write_status.set("edit skipped: body is empty".to_owned());
                                                        editing_index.set(None);
                                                        return;
                                                    }
                                                    // Optimistic: apply revision immediately
                                                    let _original_body = timeline.write().iter_mut()
                                                        .find(|c| c.id == eid)
                                                        .map(|found| {
                                                            let orig = found.body.clone();
                                                            found.revisions.push(TimelineRevision {
                                                                body: found.body.clone(),
                                                                timestamp: found.timestamp.clone(),
                                                                operation_id: found.operation_id.clone(),
                                                                commit_id: found.commit_id.clone(),
                                                            });
                                                            found.body = content.clone();
                                                            found.timestamp = timestamp_now();
                                                            found.edited = true;
                                                            found.pending = true;
                                                            orig
                                                        });
                                                    editing_index.set(None);

                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => match api
                                                                .edit_message(&eid, json!({"msgtype": "m.text", "body": content.clone()}))
                                                                .await
                                                            {
                                                                Ok(updated) => {
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        found.operation_id = Some(updated.operation_id.clone());
                                                                        found.commit_id = Some(updated.commit_id.clone());
                                                                        found.pending = false;
                                                                    }
                                                                    state_store.write().append_raw_operation(
                                                                        updated.operation_id.clone(),
                                                                        Some(space),
                                                                        json!({
                                                                            "event_id": updated.event_id,
                                                                            "commit_id": updated.commit_id,
                                                                            "kind": "cx.message.revise",
                                                                        }),
                                                                    );
                                                                    repo_state.set(updated.commit_id.clone());
                                                                    write_status.set(format!("revised {}", updated.operation_id));
                                                                }
                                                                Err(error) => {
                                                                    // Rollback optimistic edit
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        if let Some(rev) = found.revisions.pop() {
                                                                            found.body = rev.body;
                                                                            found.timestamp = rev.timestamp;
                                                                            found.operation_id = rev.operation_id;
                                                                            found.commit_id = rev.commit_id;
                                                                        }
                                                                        found.edited = !found.revisions.is_empty();
                                                                        found.pending = false;
                                                                    }
                                                                    write_status.set(format!("edit failed: {error}"));
                                                                }
                                                            },
                                                            Err(error) => write_status.set(format!("invalid server URL: {error}")),
                                                        }
                                                    });
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
                                                let space = selected_space.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let space = space.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    let reason = Some("user requested tombstone".to_owned());
                                                    // Optimistic: apply redaction immediately
                                                    let original = timeline.write().iter_mut()
                                                        .find(|c| c.id == eid)
                                                        .map(|found| {
                                                            let orig = found.clone();
                                                            found.redacted = true;
                                                            found.body = String::new();
                                                            found.operation_id = None;
                                                            found.commit_id = None;
                                                            found.redaction_id = None;
                                                            found.tombstone_reason = reason.clone();
                                                            found.timestamp = timestamp_now();
                                                            found.pending = true;
                                                            orig
                                                        });
                                                    redact_confirm.set(None);

                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => match api.redact_message(&eid, reason.as_deref()).await {
                                                                Ok(redacted) => {
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        found.apply_redaction(redacted.redaction_id.clone(), reason.clone());
                                                                    }
                                                                    state_store.write().append_raw_operation(
                                                                        redacted.redaction_id.clone(),
                                                                        Some(space),
                                                                        json!({
                                                                            "event_id": redacted.event_id,
                                                                            "kind": "cx.message.redact",
                                                                            "reason": reason,
                                                                        }),
                                                                    );
                                                                    write_status.set(format!("tombstoned {}", redacted.redaction_id));
                                                                }
                                                                Err(error) => {
                                                                    // Rollback optimistic redaction
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        if let Some(original) = original {
                                                                            *found = original;
                                                                        }
                                                                    }
                                                                    write_status.set(format!("redact failed: {error}"));
                                                                }
                                                            },
                                                            Err(error) => write_status.set(format!("invalid server URL: {error}")),
                                                        }
                                                    });
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

                        if let Some(fact) = event.fact_summary() {
                            div { class: "muted", "data-testid": "event-fact", "{fact}" }
                        }

                        if !event.revisions.is_empty() {
                            div { class: "section", "data-testid": "revision-chain",
                                div { class: "muted", "Revision chain ({event.revisions.len()})" }
                                for revision in &event.revisions {
                                    div { class: "muted", "data-testid": "revision-entry",
                                        "{revision.timestamp}: {revision.body}"
                                        if let Some(operation_id) = &revision.operation_id {
                                            " [{operation_id}]"
                                        }
                                        if let Some(commit_id) = &revision.commit_id {
                                            " / {commit_id}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if timeline().is_empty() {
                div { class: "event",
                    div { class: "event-head", span { "serverx" } span { "empty" } }
                    div { "No timeline events yet. Compose a dev-mode message." }
                }
            }
        }

        div { class: "composer", "data-testid": "composer",
            div {
                class: "event",
                "data-testid": "plaintext-boundary-panel",
                role: "note",
                "aria-label": "Plaintext boundary",
                div { class: "event-head",
                    span { "Plaintext boundary" }
                    span {
                        "data-testid": "plaintext-boundary-state",
                        if encrypt_toggle() { "encrypted local" } else if plaintext_blocked { "private plaintext blocked" } else if plaintext_can_leave { "plaintext visible" } else { "blocked" }
                    }
                }
                div { class: "muted", "data-testid": "plaintext-visible-services",
                    "Visible service: {plaintext_service}"
                }
                div { class: "muted", "data-testid": "plaintext-preview-disclosure",
                    "Plaintext messages may be visible to the configured server and may feed server-side search, previews, moderation, and notification snippets."
                }
                label {
                    input {
                        r#type: "checkbox",
                        "data-testid": "private-plaintext-toggle",
                        checked: private_plaintext(),
                        onchange: move |evt| {
                            private_plaintext.set(evt.value() == "true");
                            plaintext_ack.set(false);
                        },
                    }
                    " Mark draft as private"
                }
                if private_plaintext() && !encrypt_toggle() {
                    div {
                        class: "muted",
                        "data-testid": "plaintext-boundary-warning",
                        "Private plaintext is not E2EE. Enable Encrypt Local or acknowledge that this server may see the body."
                    }
                    if !plaintext_ack() {
                        button {
                            class: "secondary",
                            "data-testid": "plaintext-boundary-ack",
                            onclick: move |_| plaintext_ack.set(true),
                            "Acknowledge plaintext exposure"
                        }
                    }
                }
            }
            if let Some(reply_idx) = reply_to_index() {
                div { class: "muted", "data-testid": "reply-to-banner",
                    "Replying to {reply_target_label(&timeline(), reply_idx)}"
                    button {
                        class: "secondary",
                        onclick: move |_| reply_to_index.set(None),
                        "Cancel Reply"
                    }
                }
            }

            textarea {
                "data-testid": "composer-input",
                "aria-label": "Message composer",
                value: "{draft}",
                placeholder: if encrypt_toggle() { "Write an encrypted message (Ctrl+Enter to send)" } else { "Write a plaintext dev-mode message (Ctrl+Enter to send)" },
                oninput: {
                    let sc = selected_space_c.clone();
                    move |event| {
                        let value = event.value();
                        draft.set(value.clone());
                        state_store.write().save_draft(sc.clone(), value);
                        let base = base_url_sig();
                        let api_token = token();
                        let space = sc.clone();
                        let wait_for = active_sync_token(sync_cursor());
                        spawn(async move {
                            if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                let _ = api.send_typing(&space, true).await;
                            }
                        });
                    }
                },
                onkeydown: move |event| {
                    if event.key().to_string() == "Enter" && event.modifiers().ctrl() {
                        let body = draft().trim().to_owned();
                        if body.is_empty() {
                            return;
                        }
                        if private_plaintext() && !encrypt_toggle() && !plaintext_ack() {
                            write_status.set("plaintext blocked: acknowledge boundary or enable encryption".to_owned());
                            return;
                        }
                        let reply_target = reply_to_index()
                            .and_then(|idx| timeline().get(idx).map(|event| event.id.clone()));
                        let thread_id = reply_target.clone();
                        let space_for_encrypt = selected_space_key.clone();
                        let space_for_plain = selected_space_key.clone();
                        let space_for_draft = selected_space_key.clone();
                        if encrypt_toggle() {
                            match compose_local_encrypted_message(
                                &account_did_key,
                                &device_id_key,
                                &space_for_encrypt,
                                "cx:message:local-compose",
                                &body,
                            ) {
                                Ok(message) => {
                                    timeline.write().push(TimelineEvent::system_notice(
                                        format!("local-encrypted-{}", uuid_v8()),
                                        "local",
                                        format!(
                                            "encrypted {} epoch {} digest {}",
                                            message.payload.scheme.as_str(),
                                            message.payload.epoch,
                                            message.payload.payload_digest
                                        ),
                                    ));
                                }
                                Err(error) => {
                                    timeline.write().push(TimelineEvent::system_notice(
                                        format!("encrypt-error-{}", uuid_v8()),
                                        "local",
                                        format!("encryption failed: {error}"),
                                    ));
                                }
                            }
                        } else {
                            let event_id = format!("ev:local:{}", uuid_v8());
                            timeline.write().push(TimelineEvent {
                                id: event_id.clone(),
                                sender: account_did_key.clone(),
                                sender_display: "you".to_owned(),
                                body: body.clone(),
                                timestamp: Utc::now().to_rfc3339(),
                                reply_to: reply_target,
                                reactions: Vec::new(),
                                redacted: false,
                                edited: false,
                                thread_id: thread_id.clone(),
                                blob_ref: None,
                                operation_id: None,
                                commit_id: None,
                                redaction_id: None,
                                tombstone_reason: None,
                                revisions: Vec::new(),
                                pending: true,
                            });
                            let base = base_url_sig();
                            let api_token = token();
                            let space = space_for_plain.clone();
                            let wait_for = active_sync_token(sync_cursor());
                            spawn(async move {
                                if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                    let content = json!({"body": body, "format": "plain"});
                                    match api.send_message(&space, thread_id.as_deref(), content, false).await {
                                        Ok(resp) => {
                                            if let Some(event) = timeline.write().iter_mut().find(|e| e.id == event_id) {
                                                event.apply_send_ack(resp.event_id.clone(), resp.operation_id.clone(), resp.commit_id.clone());
                                            }
                                        }
                                        Err(error) => {
                                            timeline.write().retain(|e| e.id != event_id);
                                            write_status.set(format!("send failed: {error}"));
                                        }
                                    }
                                }
                            });
                        }
                        draft.set(String::new());
                        state_store.write().save_draft(space_for_draft, String::new());
                        reply_to_index.set(None);
                        plaintext_ack.set(false);
                    }
                },
            }

            div { class: "actions",
                label {
                    input {
                        r#type: "checkbox",
                        "data-testid": "encrypt-local-button",
                        checked: encrypt_toggle(),
                        onchange: move |evt| encrypt_toggle.set(evt.value() == "true"),
                    }
                    " Encrypt Local"
                }

                button {
                    class: "secondary",
                    "data-testid": "attach-blob-button",
                    onclick: move |_| {
                        let base = base_url_sig();
                        let api_token = token();
                        let wait_for = active_sync_token(sync_cursor());
                        spawn(async move {
                            if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                match api.upload_blob(ATTACHMENT_BYTES).await {
                                    Ok(blob) => {
                                        let local_hash = sha256_hex(ATTACHMENT_BYTES);
                                        let hash_state = if blob.sha256.trim_start_matches("sha256:") == local_hash {
                                            "upload hash ok"
                                        } else {
                                            "upload hash mismatch"
                                        };
                                        let policy = media_type_preview_policy(&blob.media_type);
                                        attached_blob.set(Some(BlobAttachment {
                                            blob_ref: blob.blob_ref.clone(),
                                            size: blob.size,
                                            media_type: blob.media_type.clone(),
                                            sha256: blob.sha256.clone(),
                                            thumbnail_ref: blob.thumbnail_ref.clone(),
                                        }));
                                        blob_status.set(format!(
                                            "attached {} ({hash_state}; {}; no token in media URL)",
                                            blob.blob_ref,
                                            policy.label()
                                        ));
                                    }
                                    Err(error) => blob_status.set(format!("attach failed: {error}")),
                                }
                            }
                        });
                    },
                    "Attach Blob"
                }

                if let Some(blob) = attached_blob() {
                    div { class: "event", "data-testid": "blob-policy-panel",
                        div { class: "event-head",
                            span { "Blob" }
                            span { "{blob.media_type}" }
                        }
                        div { class: "muted", "Ref: {blob.blob_ref}" }
                        div { class: "muted", "SHA-256: {blob.sha256}" }
                        div { class: "muted", "Size: {blob.size} bytes" }
                        div { class: "muted", "Policy: {media_type_preview_policy(&blob.media_type).label()}" }
                        div { class: "muted", "Download path uses Authorization header; bearer token is never placed in the blob URL." }
                        if let Some(thumbnail_ref) = &blob.thumbnail_ref {
                            div { class: "muted", "Thumbnail: {thumbnail_ref}" }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "verify-blob-download",
                                onclick: {
                                    let blob_ref = blob.blob_ref.clone();
                                    let expected_sha256 = blob.sha256.clone();
                                    move |_| {
                                        let base = base_url_sig();
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        let blob_ref = blob_ref.clone();
                                        let expected_sha256 = expected_sha256.clone();
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api.get_blob_bytes(&blob_ref).await {
                                                    Ok(bytes) if hash_matches(&expected_sha256, &bytes) => {
                                                        blob_status.set(format!(
                                                            "download verified sha256 {} ({} bytes)",
                                                            expected_sha256,
                                                            bytes.len()
                                                        ));
                                                    }
                                                    Ok(bytes) => {
                                                        blob_status.set(format!(
                                                            "download hash mismatch expected {} got {}",
                                                            expected_sha256,
                                                            sha256_hex(&bytes)
                                                        ));
                                                    }
                                                    Err(error) => blob_status.set(format!("download failed: {error}")),
                                                },
                                                Err(error) => blob_status.set(format!("invalid server URL: {error}")),
                                            }
                                        });
                                    }
                                },
                                "Verify Download"
                            }
                        }
                    }
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
                            if private_plaintext() && !encrypt_toggle() && !plaintext_ack() {
                                write_status.set("plaintext blocked: acknowledge boundary or enable encryption".to_owned());
                                return;
                            }

                            let reply_target = reply_to_index()
                                .and_then(|idx| timeline().get(idx).map(|event| event.id.clone()));
                            let thread_id = reply_target.clone();
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
                                        timeline.write().push(TimelineEvent::system_notice(
                                            format!("local-encrypted-{}", uuid_v8()),
                                            "local",
                                            format!(
                                                "encrypted {} epoch {} digest {}",
                                                message.payload.scheme.as_str(),
                                                message.payload.epoch,
                                                message.payload.payload_digest
                                            ),
                                        ));
                                        crypto_state.set(format!(
                                            "encrypted local payload for {}",
                                            message.payload.group_id
                                        ));
                                        write_status.set("queued local encrypted fact".to_owned());
                                        state_store.write().save_draft(space_for_encrypt, "");
                                        draft.set(String::new());
                                        reply_to_index.set(None);
                                        plaintext_ack.set(false);
                                    }
                                    Err(error) => crypto_state.set(format!("encrypt failed: {error}")),
                                }
                            } else {
                                let local_event_id = format!("local-event-{}", uuid_v8());
                                timeline.write().push(TimelineEvent::pending_message(
                                    local_event_id.clone(),
                                    ac.clone(),
                                    "local",
                                    body.clone(),
                                    reply_target.clone(),
                                    thread_id.clone(),
                                ));
                                state_store.write().save_draft(space_for_draft, "");
                                draft.set(String::new());
                                reply_to_index.set(None);
                                plaintext_ack.set(false);

                                let base = base_url_sig();
                                let space = space_for_plain;
                                let api_token = token();
                                let wait_for = active_sync_token(sync_cursor());
                                let body_clone = body.clone();
                                spawn(async move {
                                    match authed_api_with_sync(&base, api_token, wait_for) {
                                        Ok(api) => match api
                                            .send_message(
                                                &space,
                                                thread_id.as_deref(),
                                                json!({"msgtype": "m.text", "body": body_clone.clone()}),
                                                false,
                                            )
                                            .await
                                        {
                                            Ok(sent) => {
                                                if let Some(found) = timeline
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_event_id)
                                                {
                                                    found.apply_send_ack(
                                                        sent.event_id.clone(),
                                                        sent.operation_id.clone(),
                                                        sent.commit_id.clone(),
                                                    );
                                                }
                                                sync_cursor.set(sent.sync_token.clone());
                                                repo_state.set(
                                                    sent.head_commit
                                                        .clone()
                                                        .unwrap_or(sent.commit_id.clone()),
                                                );
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(sent.sync_token.clone());
                                                    store.append_raw_operation(
                                                        sent.operation_id.clone(),
                                                        Some(space),
                                                        json!({
                                                            "event_id": sent.event_id,
                                                            "commit_id": sent.commit_id,
                                                            "head_commit": sent.head_commit,
                                                            "kind": "cx.message.create",
                                                        }),
                                                    );
                                                }
                                                write_status.set(format!("persisted {}", sent.operation_id));
                                            }
                                            Err(error) => {
                                                if let Some(found) = timeline
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_event_id)
                                                {
                                                    found.pending = false;
                                                }
                                                write_status.set(format!("send failed: {error}"));
                                            }
                                        },
                                        Err(error) => write_status.set(format!("invalid server URL: {error}")),
                                    }
                                });
                            }
                        }
                    },
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
                            let wait_for = active_sync_token(sync_cursor());
                            spawn(async move {
                                if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                    let _ = api.report_moderation(&space, "local:event", "spam", &actor).await;
                                    let _ = api.send_to_device(&actor, &dev).await;
                                }
                            });
                        }
                    },
                    "Report / Queue"
                }
            }

            if !write_status().is_empty() {
                div { class: "muted", "data-testid": "write-status", "{write_status}" }
            }

            if !blob_status().is_empty() {
                div { class: "muted", "data-testid": "blob-status", "{blob_status}" }
            }

            div { class: "muted", "data-testid": "read-marker-status", "{read_marker_status}" }
            div { class: "muted", "data-testid": "read-receipt-status", "{receipt_status}" }

            if !read_receipts().is_empty() {
                div { class: "muted", "data-testid": "read-receipts",
                    "Read by: {read_receipts:?}"
                }
            }
        }
    }
}

fn active_sync_token(sync_cursor: String) -> Option<String> {
    (!sync_cursor.trim().is_empty() && sync_cursor != "-").then_some(sync_cursor)
}

fn reply_target_label(events: &[TimelineEvent], reply_idx: usize) -> String {
    events
        .get(reply_idx)
        .map(|event| event.id.clone())
        .unwrap_or_else(|| format!("local-event-{reply_idx}"))
}

fn timestamp_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M").to_string()
}

fn read_marker_status_label(marker: &ReadMarkerRecord) -> String {
    let scope = marker
        .body
        .topic_id
        .as_deref()
        .map(|topic_id| format!("thread {topic_id}"))
        .unwrap_or_else(|| "space timeline".to_owned());
    format!(
        "Read marker: {} ({scope}) at {}",
        marker.body.event_id,
        marker.updated_at.format("%Y-%m-%d %H:%M")
    )
}

fn plaintext_visible_service(base_url: &str) -> String {
    base_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .filter(|host| !host.is_empty())
        .map(|host| format!("configured server {host}"))
        .unwrap_or_else(|| "configured server".to_owned())
}
