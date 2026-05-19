use chrono::Utc;
// A6.2: HasFileData trait surfaces `event.files()` on DragData /
// FormData events; not re-exported via the prelude root.
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::{
    conformance::PlaintextBoundary,
    crypto::compose_local_encrypted_message,
    local_state::{LocalStateStore, ReadMarkerRecord},
    media::{hash_matches, media_type_preview_policy, sha256_hex},
    operation::{EventEnvelope, OperationBuilder, uuid_v7},
    views::helpers::{
        active_sync_token, authed_api_with_sync, with_authed_api, with_authed_api_with_sync,
    },
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
    pub event_id: Option<String>,
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
    pub space_id: Option<String>,
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
    pub event_id: Option<String>,
    pub redaction_id: Option<String>,
    pub tombstone_reason: Option<String>,
    pub revisions: Vec<TimelineRevision>,
    pub pending: bool,
    /// When present, this message carries an `encrypted_payload`
    /// object that the local MLS group may be able to decrypt.
    /// Timeline's audit-accessed emitter watches this field
    /// — on successful decrypt, fires a single `cx.audit.accessed` for
    /// `id` per session (de-duplicated by `audit_accessed_emitted`).
    pub encrypted_payload: Option<serde_json::Value>,
}

impl Default for TimelineEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            space_id: None,
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
            event_id: None,
            redaction_id: None,
            tombstone_reason: None,
            revisions: Vec::new(),
            pending: false,
            encrypted_payload: None,
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
            sender: "did:web:server.local".to_owned(),
            sender_display: sender_display.into(),
            body: body.into(),
            timestamp: timestamp_now(),
            ..Self::default()
        }
    }

    pub fn pending_message(
        space_id: impl Into<String>,
        id: impl Into<String>,
        sender: impl Into<String>,
        sender_display: impl Into<String>,
        body: impl Into<String>,
        reply_to: Option<String>,
        thread_id: Option<String>,
    ) -> Self {
        Self {
            space_id: Some(space_id.into()),
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

    pub fn apply_send_ack(&mut self, event_id: String, operation_id: String) {
        self.id = event_id;
        self.operation_id = Some(operation_id);
        self.event_id = None;
        self.pending = false;
    }

    pub fn apply_revision(
        &mut self,
        new_body: String,
        operation_id: Option<String>,
        event_id: Option<String>,
    ) {
        self.revisions.push(TimelineRevision {
            body: self.body.clone(),
            timestamp: self.timestamp.clone(),
            operation_id: self.operation_id.clone(),
            event_id: self.event_id.clone(),
        });
        self.body = new_body;
        self.timestamp = timestamp_now();
        self.operation_id = operation_id;
        self.event_id = event_id;
        self.redacted = false;
        self.redaction_id = None;
        self.tombstone_reason = None;
        self.edited = true;
        self.pending = false;
    }

    pub fn apply_redaction(&mut self, redaction_id: String, reason: Option<String>) {
        self.redacted = true;
        self.operation_id = None;
        self.event_id = None;
        self.redaction_id = Some(redaction_id);
        self.tombstone_reason = reason;
        self.timestamp = timestamp_now();
        self.pending = false;
    }

    pub fn fact_summary(&self) -> Option<String> {
        match (
            self.operation_id.as_deref(),
            self.event_id.as_deref(),
            self.redaction_id.as_deref(),
        ) {
            (_, _, Some(redaction_id)) => Some(format!("tombstone {redaction_id}")),
            (Some(operation_id), Some(event_id), _) => {
                Some(format!("fact {operation_id} / event {event_id}"))
            }
            (Some(operation_id), None, _) => Some(format!("fact {operation_id}")),
            _ => None,
        }
    }
}

fn text_content(body: &str) -> serde_json::Value {
    json!({
        "blocks": [{"kind": "text", "text": body}],
        "body": body,
    })
}

pub(crate) fn message_create_operation(
    space_id: &str,
    actor: &str,
    thread_id: Option<&str>,
    body: &str,
) -> EventEnvelope {
    let mut payload = json!({
        "body": body,
        "content": text_content(body),
        "encrypted": false,
    });
    if let Some(thread_id) = thread_id {
        payload["thread_id"] = json!(thread_id);
    }
    OperationBuilder::new(space_id, actor, "cx.message.create")
        .body(payload)
        .build("yougen")
}

fn message_revise_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.message.revise")
        .target_ref(event_id)
        .body(json!({
            "body": body,
            "content": text_content(body),
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn message_redact_operation(
    space_id: &str,
    actor: &str,
    event_id: &str,
    reason: Option<&str>,
) -> EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn reaction_add_operation(space_id: &str, actor: &str, event_id: &str, key: &str) -> EventEnvelope {
    OperationBuilder::new(space_id, actor, "cx.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "actor": actor,
            "event_id": event_id,
            "key": key,
        }))
        .build("yougen")
}

#[component]
pub fn TimelinePanel(
    base_url: String,
    account_did: String,
    device_id: String,
    token: Signal<String>,
    selected_space: String,
    selected_space_scope: Vec<String>,
    timeline: Signal<Vec<TimelineEvent>>,
    draft: Signal<String>,
    state_store: Signal<LocalStateStore>,
    crypto_state: Signal<String>,
    sync_cursor: Signal<String>,
    frontier_state: Signal<String>,
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
    let mut initial_sync_requested = use_signal(|| false);
    // A6.2 composer drag-drop attachment state. `compose_dragover`
    // toggles the `is-dragover` outline as the user holds a file
    // over the composer; `compose_upload_status` shows an inline
    // progress / error string for the most recent drop.
    let mut compose_dragover = use_signal(|| false);
    let mut compose_upload_status = use_signal(|| String::new());
    // A5 — personal blocklist. Renderers hide bodies from blocked
    // senders behind a "Show anyway" placeholder; `blocked_show_anyway`
    // tracks per-event opt-ins so once the user clicks reveal, the row
    // stays expanded for the lifetime of the render.
    let mut blocked_show_anyway = use_signal(std::collections::BTreeSet::<String>::new);
    let blocked_did_set: std::collections::BTreeSet<String> = state_store
        .read()
        .client_blocklist()
        .into_iter()
        .map(|entry| entry.did)
        .collect();
    // A2 / AW-3.10: shared owned-agent list so the timeline composer
    // can mount [`PrivateComposeBanner`] + apply the
    // `private-compose-mode` class when the active draft mentions one
    // of the controller's agents.
    let owned_agents_ctx = use_context::<crate::views::agent_workspace::OwnedAgentsContext>();

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

    let timeline_snapshot = timeline();
    let events_data: Vec<(usize, TimelineEvent)> = timeline_snapshot
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            selected_space_scope.is_empty()
                || event
                    .space_id
                    .as_deref()
                    .map(|space_id| selected_space_scope.iter().any(|id| id == space_id))
                    .unwrap_or(true)
        })
        .map(|(i, event)| (i, event.clone()))
        .collect();
    let events_for_reply_lookup = timeline_snapshot.clone();
    let events_for_composer_lookup = timeline_snapshot;
    let plaintext_service = plaintext_visible_service(&base_url);
    let plaintext_boundary = PlaintextBoundary {
        allowed_services: vec![plaintext_service.clone()],
        is_e2ee: encrypt_toggle(),
    };
    let plaintext_can_leave = plaintext_boundary.can_send_plaintext(&plaintext_service);
    let plaintext_blocked = private_plaintext() && !encrypt_toggle() && !plaintext_ack();

    if timeline().is_empty() && !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        let base = base_url_sig();
        let api_token = token();
        let wait_for = active_sync_token(sync_cursor());
        spawn(async move {
            if let Ok(sync) =
                with_authed_api_with_sync(&base, api_token, wait_for, |api| async move {
                    api.sync(None).await
                })
                .await
            {
                let events = timeline_events_from_sync_spaces(&sync.spaces);
                if !events.is_empty() {
                    timeline.set(events);
                }
                sync_cursor.set(sync.cursor);
            }
        });
    }

    // Attested-audit emitter. Spec
    // `crypto-media/encryption-and-audit.md §11` says
    // `cx.audit.accessed` MUST be fired by readers on every successful
    // MLS decrypt. User-initiated Mark Read is approximately correct
    // but doesn't distinguish decrypt-success from "user clicked the
    // button". This
    // future scans the current `timeline()` snapshot for events
    // carrying `encrypted_payload`, attempts a local MLS decrypt via
    // the persisted snapshot for the Space, and on each new success
    // emits a single `cx.audit.accessed` (dedup keyed by event_id).
    // Non-attested servers ignore the event; attested ones use it.
    let audit_accessed_emitted = use_signal(std::collections::HashSet::<String>::new);
    let mls_passphrase_store = use_context::<Signal<crate::mls_passphrase::MlsPassphraseStore>>();
    {
        let base_a = base_url.clone();
        let token_a = token;
        let space_a = selected_space.clone();
        let actor_a = account_did.clone();
        let device_a = device_id.clone();
        let mut emitted_sig = audit_accessed_emitted;
        use_future(move || {
            let base = base_a.clone();
            let space = space_a.clone();
            let actor = actor_a.clone();
            let device = device_a.clone();
            async move {
                let snapshot = timeline();
                // Identify candidates first so the closure doesn't have
                // to re-read the signal under await.
                let candidates: Vec<(String, serde_json::Value)> = snapshot
                    .iter()
                    .filter_map(|event| {
                        let id = event.id.clone();
                        let payload = event.encrypted_payload.clone()?;
                        if emitted_sig.read().contains(&id) {
                            None
                        } else {
                            Some((id, payload))
                        }
                    })
                    .collect();
                if candidates.is_empty() {
                    return;
                }
                let passphrase = mls_passphrase_store
                    .read()
                    .get(&space)
                    .map(str::to_owned)
                    .unwrap_or_default();
                let api_token = token_a();
                for (event_id, payload_value) in candidates {
                    let Some(plaintext) =
                        try_local_mls_decrypt(state_store, &space, &passphrase, &payload_value)
                    else {
                        continue;
                    };
                    let _ = plaintext;
                    emitted_sig.write().insert(event_id.clone());
                    let base = base.clone();
                    let api_token = api_token.clone();
                    let space = space.clone();
                    let actor = actor.clone();
                    let device = device.clone();
                    spawn(async move {
                        let _ = with_authed_api(&base, api_token, |api| async move {
                            let op = crate::audit::build_audit_accessed(
                                &space, &actor, &event_id, &device,
                            )
                            .build("yougen");
                            api.submit_event_envelope(&op).await
                        })
                        .await;
                    });
                }
            }
        });
    }

    // A2 / AW-3.10: precompute private-compose state outside rsx so
    // the let bindings live in Rust statement scope (rsx parses node
    // contexts as nodes, not statements). When the active timeline
    // draft mentions one of the controller's owned agents we apply
    // the `private-compose-mode` class so the textarea border +
    // background flip to the private routing palette, and mount the
    // [`PrivateComposeBanner`] underneath.
    let private_compose_owned_agents = owned_agents_ctx.read().clone();
    let private_compose_mentions = crate::views::helpers::parse_structured_mentions(&draft());
    let private_compose_target_did = private_compose_mentions
        .iter()
        .map(|m| m.target.clone())
        .find(|target| {
            crate::views::agent_workspace::is_controller_owned_agent(
                target,
                &private_compose_owned_agents,
            )
        });
    let private_compose_active = private_compose_target_did.is_some();
    let composer_class = if private_compose_active {
        "composer private-compose-mode"
    } else {
        "composer"
    };

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
                        id: "{event.id}",
                        "data-testid": "timeline-event",
                        "data-event-id": "{event.id}",
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
                            if let Some((quoted_name, quoted_body)) = timeline_reply_quote_preview(
                                &events_for_reply_lookup,
                                reply_id,
                            ) {
                                div { class: "chat-reply-quote", "data-testid": "reply-indicator",
                                    span { class: "chat-reply-quote-name", "{quoted_name}" }
                                    div { class: "chat-reply-quote-body", "{quoted_body}" }
                                }
                            } else {
                                div { class: "chat-reply-quote chat-reply-quote-missing", "data-testid": "reply-indicator",
                                    "\u{21a9}\u{fe0f} Reply to a message"
                                }
                            }
                        }

                        if event.redacted {
                            div { class: "muted", "data-testid": "redacted-tombstone", "[Message redacted]" }
                            if let Some(reason) = &event.tombstone_reason {
                                div { class: "muted", "Tombstone reason: {reason}" }
                            }
                        } else if blocked_did_set.contains(&event.sender)
                            && !blocked_show_anyway.read().contains(&event.id)
                        {
                            // A5 — sender is on the actor-private
                            // blocklist. Render a placeholder + a
                            // reveal button rather than dropping the
                            // row entirely so the user still knows the
                            // message exists.
                            div {
                                class: "muted",
                                "data-testid": "timeline-blocked-row",
                                {crate::i18n::tr("timeline.blocked_user")}
                            }
                            button {
                                class: "secondary",
                                "data-testid": "timeline-blocked-show-anyway",
                                onclick: {
                                    let eid = event.id.clone();
                                    move |_| {
                                        blocked_show_anyway.write().insert(eid.clone());
                                    }
                                },
                                {crate::i18n::tr("timeline.show_anyway")}
                            }
                        } else {
                            div { "data-testid": "event-body",
                                {crate::content::render_blocks(
                                    &crate::content::parse_message_body(&event.body),
                                )}
                            }
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

                                            // Resolve effective send preference per spec
                                            // discovery/client-preferences.md §3.6 (flow → space →
                                            // default). Server-side Realm `cx.realm.read_receipt_policy`
                                            // is not yet exposed to the client; until it is, treat
                                            // policy as `Optional` (no override) and defer to user pref.
                                            let topic_for_pref = marker.body.topic_id.clone();
                                            let should_send = state_store.read().read_receipt_should_send(
                                                topic_for_pref.as_deref(),
                                                Some(marker.body.space_id.as_str()),
                                            );
                                            if !should_send {
                                                receipt_status.set(format!(
                                                    "Read receipt: skipped per preference for {}",
                                                    marker.body.event_id
                                                ));
                                                return;
                                            }
                                            receipt_status.set(format!("Read receipt: sending {}", marker.body.event_id));

                                            let base = base.clone();
                                            let api_token = token();
                                            let wait_for = active_sync_token(sync_cursor());
                                            let receipt_space = marker.body.space_id.clone();
                                            let receipt_event_id = marker.body.event_id.clone();
                                            let actor_for_status = marker.actor.clone();
                                            let actor_for_audit = marker.actor.clone();
                                            let device_for_audit = marker.device_id.clone();
                                            spawn(async move {
                                                match authed_api_with_sync(&base, api_token, wait_for) {
                                                    Ok(api) => {
                                                        match api
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
                                                        }

                                                        // `cx.audit.accessed`
                                                        // is owned by the
                                                        // dedicated emitter
                                                        // wired to the MLS
                                                        // decrypt-success
                                                        // path higher up in
                                                        // this component, so
                                                        // Mark Read no
                                                        // longer double-
                                                        // fires it. Mark
                                                        // Read still emits
                                                        // the public
                                                        // `cx.receipt.read`
                                                        // above and the
                                                        // local private
                                                        // read marker
                                                        // below.
                                                        let _ = (
                                                            &receipt_event_id,
                                                            &receipt_space,
                                                            &actor_for_audit,
                                                            &device_for_audit,
                                                            &api,
                                                        );
                                                    }
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
                                                let space = selected_space.clone();
                                                let actor = account_did.clone();
                                                let emoji = emoji.to_string();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let space = space.clone();
                                                    let actor = actor.clone();
                                                    let emoji = emoji.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    spawn(async move {
                                                        if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                                            let op = reaction_add_operation(&space, &actor, &eid, &emoji);
                                                            let _ = api.submit_event_envelope(&op).await;
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
                                                let actor = account_did.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let space = space.clone();
                                                    let actor = actor.clone();
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
                                                                event_id: found.event_id.clone(),
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
                                                            Ok(api) => {
                                                                let op = message_revise_operation(
                                                                    &space,
                                                                    &actor,
                                                                    &eid,
                                                                    &content,
                                                                );
                                                                let op_id = op.local_operation_id().to_owned();
                                                                match api.submit_event_envelope(&op).await {
                                                                Ok(updated) => {
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        found.operation_id = Some(op_id.clone());
                                                                        found.event_id = Some(updated.event_id.clone());
                                                                        found.pending = false;
                                                                    }
                                                                    state_store.write().append_raw_operation(
                                                                        op_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "event_id": updated.event_id,
                                                                            "kind": "cx.message.revise",
                                                                            "status": updated.status,
                                                                        }),
                                                                    );
                                                                    frontier_state.set(updated.event_id.clone());
                                                                    write_status.set(format!("revised {op_id}"));
                                                                }
                                                                Err(error) => {
                                                                    // Rollback optimistic edit
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        if let Some(rev) = found.revisions.pop() {
                                                                            found.body = rev.body;
                                                                            found.timestamp = rev.timestamp;
                                                                            found.operation_id = rev.operation_id;
                                                                            found.event_id = rev.event_id;
                                                                        }
                                                                        found.edited = !found.revisions.is_empty();
                                                                        found.pending = false;
                                                                    }
                                                                    write_status.set(format!("edit failed: {error}"));
                                                                }
                                                                }
                                                            }
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
                                                let actor = account_did.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let space = space.clone();
                                                    let actor = actor.clone();
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
                                                            found.event_id = None;
                                                            found.redaction_id = None;
                                                            found.tombstone_reason = reason.clone();
                                                            found.timestamp = timestamp_now();
                                                            found.pending = true;
                                                            orig
                                                        });
                                                    redact_confirm.set(None);

                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => {
                                                                let op = message_redact_operation(
                                                                    &space,
                                                                    &actor,
                                                                    &eid,
                                                                    reason.as_deref(),
                                                                );
                                                                let op_id = op.local_operation_id().to_owned();
                                                                match api.submit_event_envelope(&op).await {
                                                                Ok(redacted) => {
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid) {
                                                                        found.apply_redaction(redacted.event_id.clone(), reason.clone());
                                                                    }
                                                                    state_store.write().append_raw_operation(
                                                                        op_id.clone(),
                                                                        Some(space.clone()),
                                                                        json!({
                                                                            "event_id": redacted.event_id,
                                                                            "kind": "cx.message.redact",
                                                                            "reason": reason,
                                                                            "status": redacted.status,
                                                                        }),
                                                                    );
                                                                    write_status.set(format!("tombstoned {op_id}"));
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
                                                                }
                                                            }
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
                                        if let Some(event_id) = &revision.event_id {
                                            " / {event_id}"
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
                    div { class: "event-head", span { "server" } span { "empty" } }
                    div { "No timeline events yet. Compose a dev-mode message." }
                }
            }
        }

        // A2 / AW-3.10: `composer_class` + `private_compose_target_did`
        // are precomputed above the rsx block so the let bindings live
        // in Rust statement scope rather than node-context.
        div { class: "{composer_class}", "data-testid": "composer",
            if let Some(agent_did) = private_compose_target_did.as_ref() {
                crate::views::agent_workspace::PrivateComposeBanner {
                    agent_display_name: crate::views::agent_workspace::owned_agent_display_name(
                        agent_did,
                        &private_compose_owned_agents,
                    ),
                }
            }
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
                div { class: "chat-reply-quote-banner", "data-testid": "reply-to-banner",
                    if let Some(reply_id) = events_for_composer_lookup
                        .get(reply_idx)
                        .map(|event| event.id.clone())
                    {
                        if let Some((quoted_name, quoted_body)) = timeline_reply_quote_preview(
                            &events_for_composer_lookup,
                            &reply_id,
                        ) {
                            div { class: "chat-reply-quote",
                                span { class: "chat-reply-quote-name", "{quoted_name}" }
                                div { class: "chat-reply-quote-body", "{quoted_body}" }
                            }
                        } else {
                            div { class: "chat-reply-quote chat-reply-quote-missing",
                                "Replying to a message"
                            }
                        }
                    } else {
                        div { class: "chat-reply-quote chat-reply-quote-missing",
                            "Replying to a message"
                        }
                    }
                    button {
                        class: "secondary",
                        onclick: move |_| reply_to_index.set(None),
                        "Cancel Reply"
                    }
                }
            }

            // A6.2: drag-drop attachment zone wrapping the composer
            // textarea. Drop a file → upload via `upload_blob_bytes`
            // → append `[Attachment: {ref}]` to the draft so the
            // existing Ctrl+Enter send path attaches it. `ondragover`
            // calls `prevent_default` so the browser doesn't open the
            // file in place of the app.
            div {
                class: if compose_dragover() {
                    "compose-drop-zone is-dragover"
                } else {
                    "compose-drop-zone"
                },
                "data-testid": "compose-drop-zone",
                ondragover: move |evt| {
                    evt.prevent_default();
                    if !compose_dragover() { compose_dragover.set(true); }
                },
                ondragleave: move |_| compose_dragover.set(false),
                ondrop: {
                    let base = base_url_sig.clone();
                    move |evt| {
                        evt.prevent_default();
                        compose_dragover.set(false);
                        let files = evt.files();
                        if files.is_empty() {
                            compose_upload_status.set(
                                crate::i18n::tr("compose.upload_error"),
                            );
                            return;
                        }
                        let api_token = token();
                        let base = base();
                        compose_upload_status.set(
                            crate::i18n::tr("compose.upload_progress"),
                        );
                        spawn(async move {
                            let api = match authed_api_with_sync(&base, api_token, None) {
                                Ok(api) => api,
                                Err(err) => {
                                    compose_upload_status.set(format!(
                                        "{}: {err}",
                                        crate::i18n::tr("compose.upload_error"),
                                    ));
                                    return;
                                }
                            };
                            let mut ok_count = 0usize;
                            let mut last_error: Option<String> = None;
                            for file in files {
                                let content_type = file
                                    .content_type()
                                    .unwrap_or_else(|| "application/octet-stream".to_owned());
                                let bytes = match file.read_bytes().await {
                                    Ok(b) => b.to_vec(),
                                    Err(err) => {
                                        last_error = Some(format!("{err}"));
                                        continue;
                                    }
                                };
                                match api.upload_blob_bytes(bytes, &content_type).await {
                                    Ok(resp) => {
                                        let current = draft();
                                        let needs_space = !current.is_empty()
                                            && !current.ends_with(' ')
                                            && !current.ends_with('\n');
                                        let attachment = format!(
                                            "{}[Attachment: {}]",
                                            if needs_space { " " } else { "" },
                                            resp.blob_ref
                                        );
                                        draft.set(format!("{current}{attachment}"));
                                        ok_count += 1;
                                    }
                                    Err(err) => {
                                        last_error = Some(err.to_string());
                                    }
                                }
                            }
                            if let Some(err) = last_error {
                                compose_upload_status.set(format!(
                                    "{}: {err}",
                                    crate::i18n::tr("compose.upload_error"),
                                ));
                            } else if ok_count > 0 {
                                compose_upload_status.set(format!(
                                    "{ok_count} attachment(s) uploaded"
                                ));
                            }
                        });
                    }
                },
                if compose_dragover() {
                    div {
                        class: "compose-drop-zone-hint",
                        "data-testid": "compose-drop-hint",
                        {crate::i18n::tr("compose.drop_zone.hint")}
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
                                        format!("local-encrypted-{}", uuid_v7()),
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
                                        format!("encrypt-error-{}", uuid_v7()),
                                        "local",
                                        format!("encryption failed: {error}"),
                                    ));
                                }
                            }
                        } else {
                            let event_id = format!("ev:local:{}", uuid_v7());
                            timeline.write().push(TimelineEvent {
                                space_id: Some(space_for_plain.clone()),
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
                                event_id: None,
                                redaction_id: None,
                                tombstone_reason: None,
                                revisions: Vec::new(),
                                pending: true,
                                encrypted_payload: None,
                            });
                            let base = base_url_sig();
                            let api_token = token();
                            let space = space_for_plain.clone();
                            let actor = account_did_key.clone();
                            let wait_for = active_sync_token(sync_cursor());
                            spawn(async move {
                                if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                    let op = message_create_operation(
                                        &space,
                                        &actor,
                                        thread_id.as_deref(),
                                        &body,
                                    );
                                    let op_id = op.local_operation_id().to_owned();
                                    match api.submit_event_envelope(&op).await {
                                        Ok(resp) => {
                                            if let Some(event) = timeline.write().iter_mut().find(|e| e.id == event_id) {
                                                event.apply_send_ack(resp.event_id.clone(), op_id);
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
            } // close compose-drop-zone wrapper

            if !compose_upload_status().is_empty() {
                div {
                    class: "compose-upload-progress",
                    "data-testid": "compose-upload-progress",
                    "{compose_upload_status}"
                }
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
                                            format!("local-encrypted-{}", uuid_v7()),
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
                                let local_event_id = format!("local-event-{}", uuid_v7());
                                timeline.write().push(TimelineEvent::pending_message(
                                    space_for_plain.clone(),
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
                                let actor = ac.clone();
                                spawn(async move {
                                    match authed_api_with_sync(&base, api_token, wait_for) {
                                        Ok(api) => {
                                            let op = message_create_operation(
                                                &space,
                                                &actor,
                                                thread_id.as_deref(),
                                                &body_clone,
                                            );
                                            let op_id = op.local_operation_id().to_owned();
                                            match api.submit_event_envelope(&op).await {
                                            Ok(sent) => {
                                                if let Some(found) = timeline
                                                    .write()
                                                    .iter_mut()
                                                    .find(|candidate| candidate.id == local_event_id)
                                                {
                                                    found.apply_send_ack(
                                                        sent.event_id.clone(),
                                                        op_id.clone(),
                                                    );
                                                }
                                                sync_cursor.set(sent.sync_token.clone());
                                                frontier_state.set(sent.event_id.clone());
                                                {
                                                    let mut store = state_store.write();
                                                    store.save_sync_cursor(sent.sync_token.clone());
                                                    store.append_raw_operation(
                                                        op_id.clone(),
                                                        Some(space.clone()),
                                                        json!({
                                                            "event_id": sent.event_id,
                                                            "kind": "cx.message.create",
                                                            "status": sent.status,
                                                        }),
                                                    );
                                                }
                                                write_status.set(format!("persisted {op_id}"));
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
                                            }
                                        }
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
                                let _ = with_authed_api_with_sync(
                                    &base,
                                    api_token,
                                    wait_for,
                                    |api| async move {
                                        let _ = api
                                            .report_moderation(
                                                &space,
                                                "local:event",
                                                "spam",
                                                &actor,
                                            )
                                            .await;
                                        let _ = api.send_to_device(&actor, &dev).await;
                                        Ok(())
                                    },
                                )
                                .await;
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

fn timeline_events_from_sync_spaces(
    spaces: &std::collections::BTreeMap<String, Value>,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for (space_id, body) in spaces {
        let mut summary_event = TimelineEvent::system_notice(
            format!("summary-{space_id}"),
            "server",
            format!(
                "{space_id}: {}",
                body["summary"]["summary"]
                    .as_str()
                    .unwrap_or("No summary available")
            ),
        );
        summary_event.space_id = Some(space_id.clone());
        events.push(summary_event);

        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for event in timeline_events {
            if event.get("kind").and_then(Value::as_str) != Some("cx.message.create") {
                continue;
            }
            let event_id = event
                .get("event_id")
                .and_then(Value::as_str)
                .unwrap_or("event:unknown")
                .to_owned();
            let content = event.get("content").unwrap_or(&Value::Null);
            let body = content
                .get("body")
                .and_then(Value::as_str)
                .or_else(|| event.get("body").and_then(Value::as_str))
                .or_else(|| {
                    content
                        .get("blocks")
                        .and_then(Value::as_array)
                        .and_then(|blocks| blocks.first())
                        .and_then(|block| block.get("text"))
                        .and_then(Value::as_str)
                })
                .unwrap_or("[message]")
                .to_owned();
            // B7: carry the raw `encrypted_payload` block forward so the
            // audit-accessed emitter (later in this component) can try a
            // local MLS decrypt against it and fire `cx.audit.accessed`
            // on every successful decrypt.
            let encrypted_payload = content.get("encrypted_payload").cloned();
            events.push(TimelineEvent {
                space_id: Some(space_id.clone()),
                id: event_id.clone(),
                sender: event
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("did:web:unknown")
                    .to_owned(),
                sender_display: event
                    .get("sender")
                    .and_then(Value::as_str)
                    .unwrap_or("server")
                    .to_owned(),
                body,
                timestamp: event
                    .get("created_at")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
                thread_id: event
                    .get("thread_id")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                event_id: Some(event_id),
                encrypted_payload,
                ..TimelineEvent::default()
            });
        }
    }
    events
}

fn timeline_reply_quote_preview(
    events: &[TimelineEvent],
    reply_id: &str,
) -> Option<(String, String)> {
    let quoted = events.iter().find(|e| e.id == reply_id)?;
    let body = if quoted.redacted {
        "[Message redacted]".to_owned()
    } else {
        quoted.body.clone()
    };
    Some((quoted.sender_display.clone(), body))
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

/// Attempt a local MLS decrypt of an `encrypted_payload` JSON object
/// emitted by chat.rs
/// Send Secure. Returns `Some(plaintext_bytes)` on successful decrypt,
/// `None` for every soft failure (no snapshot, snapshot can't be
/// hydrated with the supplied passphrase, payload doesn't deserialize
/// as a typed `EncryptedPayload`, group rejects the payload).
///
/// The caller — the `cx.audit.accessed` emitter inside
/// [`TimelinePanel`] — uses `Some(...)` as the firing trigger, so any
/// soft failure quietly suppresses the audit emit instead of looping.
/// Native-only because OpenMLS is gated to non-wasm. On wasm we
/// uniformly return `None` so the emitter is a no-op there.
///
/// `passphrase` is sourced from the shared `MlsPassphraseStore` context;
/// an empty string fails closed without firing audit. Only real
/// SDK-encrypted payloads should trigger the audit hook.
#[cfg(not(target_arch = "wasm32"))]
fn try_local_mls_decrypt(
    state_store: Signal<LocalStateStore>,
    space_id: &str,
    passphrase: &str,
    payload_value: &Value,
) -> Option<Vec<u8>> {
    if passphrase.is_empty() {
        return None;
    }
    let envelope = state_store.read().mls_snapshot_for(space_id)?;
    let mut group = crate::mls_persistence::restore_envelope(&envelope, passphrase, 0).ok()?;
    let payload: contrix_sdk::EncryptedPayload =
        serde_json::from_value(payload_value.clone()).ok()?;
    group.decrypt_payload(&payload).ok()
}

#[cfg(target_arch = "wasm32")]
fn try_local_mls_decrypt(
    _state_store: Signal<LocalStateStore>,
    _space_id: &str,
    _passphrase: &str,
    _payload_value: &Value,
) -> Option<Vec<u8>> {
    None
}
