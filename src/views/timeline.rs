use std::time::Duration;

use chrono::Utc;
// A6.2: HasFileData trait surfaces `event.files()` on DragData /
// FormData events; not re-exported via the prelude root.
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use crate::crypto::compose_local_encrypted_message;
use crate::local_state::{LocalStateStore, ReadMarkerRecord};
use crate::media::{hash_matches, media_type_preview_policy, sha256_hex};
use crate::operation::{EventEnvelope, OperationBuilder, uuid_v7};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    active_sync_token, authed_api_with_sync, short_protocol_id, with_authed_api,
    with_authed_api_with_sync,
};

const ATTACHMENT_BYTES: &[u8] = b"yougen encrypted bytes";

pub(crate) const TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY: &str = "timeline.encrypt_local_default";
pub(crate) const TIMELINE_INCIDENT_PRIORITY_KEY: &str = "timeline.incident_priority";
pub(crate) const TIMELINE_PUBLIC_UPDATE_GUARD_KEY: &str = "timeline.public_update_guard";
pub(crate) const TIMELINE_PRIVATE_PLAINTEXT_KEY: &str = "timeline.private_plaintext";
pub(crate) const TIMELINE_PLAINTEXT_ACK_KEY: &str = "timeline.plaintext_ack";

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
    /// Spec rename (head 37ce729 / SDK 4d5a1af): `size` → `size_bytes`
    /// on blob/media metadata.
    size_bytes: usize,
    media_type: String,
    content_digest: String,
}

/// Event model for timeline display.
#[derive(Clone, Debug, PartialEq)]
pub struct TimelineEvent {
    pub realm_id: Option<String>,
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
    pub failed: bool,
    pub error: Option<String>,
    /// When present, this message carries encrypted message content
    /// that the local MLS group may be able to decrypt.
    /// Timeline's audit-accessed emitter watches this field
    /// — on successful decrypt, fires a single `ck.audit.accessed` for
    /// `id` per session (de-duplicated by `audit_accessed_emitted`).
    pub encrypted_payload: Option<serde_json::Value>,
}

impl Default for TimelineEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            realm_id: None,
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
            failed: false,
            error: None,
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
        realm_id: impl Into<String>,
        id: impl Into<String>,
        sender: impl Into<String>,
        sender_display: impl Into<String>,
        body: impl Into<String>,
        reply_to: Option<String>,
        thread_id: Option<String>,
    ) -> Self {
        Self {
            realm_id: Some(realm_id.into()),
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
        self.failed = false;
        self.error = None;
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
        self.failed = false;
        self.error = None;
    }

    pub fn apply_redaction(&mut self, redaction_id: String, reason: Option<String>) {
        self.redacted = true;
        self.operation_id = None;
        self.event_id = None;
        self.redaction_id = Some(redaction_id);
        self.tombstone_reason = reason;
        self.timestamp = timestamp_now();
        self.pending = false;
        self.failed = false;
        self.error = None;
    }

    pub fn fact_summary(&self) -> Option<String> {
        match (
            self.operation_id.as_deref(),
            self.event_id.as_deref(),
            self.redaction_id.as_deref(),
        ) {
            (_, _, Some(redaction_id)) => {
                Some(format!("tombstone {}", short_protocol_id(redaction_id)))
            }
            (Some(operation_id), Some(event_id), _) => Some(format!(
                "fact {} / event {}",
                short_protocol_id(operation_id),
                short_protocol_id(event_id)
            )),
            (Some(operation_id), None, _) => {
                Some(format!("fact {}", short_protocol_id(operation_id)))
            }
            _ => None,
        }
    }
}

fn sdk_payload_value(result: cokret_sdk::Result<Value>, context: &str) -> Value {
    result.unwrap_or_else(|err| panic!("{context}: {err}"))
}

fn flow_id_value(value: &str) -> cokret_sdk::FlowId {
    cokret_sdk::FlowId::new(value.to_owned())
        .unwrap_or_else(|err| panic!("invalid flow id {value:?}: {err:?}"))
}

fn text_content(body: &str) -> Value {
    // Spec `event-payload.schema.json` `content_block` requires `kind` (a
    // `content_kind` string matching `^cx\.content\.[a-z0-9_]+...` or a
    // reverse-domain id) and `body` (string). Plain timeline text uses
    // `ck.content.text`. `blocks[]` is optional and, when present, MUST
    // be an array of `content_block` items — the older yougen shape
    // (`[{kind: "text", text: ...}]`) failed both the `content_kind`
    // pattern (`text` has no dot) and the `body` requirement, so it is
    // dropped here; downstream renderers should read `body` directly.
    sdk_payload_value(
        cokret_sdk::ContentBlock::text(body).to_value(),
        "timeline text content serialize",
    )
}

fn incident_priority_wire_value(priority: &str) -> Option<&'static str> {
    match priority {
        "sev1" => Some("critical"),
        "sev2" => Some("high"),
        "sev3" => Some("urgent"),
        _ => None,
    }
}

pub(crate) fn timeline_private_data_bool(
    store: &LocalStateStore,
    account_key: &str,
    key: &str,
    default_value: bool,
) -> bool {
    store
        .load_private_data(account_key, key)
        .as_deref()
        .map(|value| matches!(value, "true" | "1" | "yes" | "on"))
        .unwrap_or(default_value)
}

pub(crate) fn timeline_incident_priority_preference(
    store: &LocalStateStore,
    account_key: &str,
) -> String {
    match store.load_private_data(account_key, TIMELINE_INCIDENT_PRIORITY_KEY) {
        Some(value) if matches!(value.as_str(), "sev1" | "sev2" | "sev3" | "normal") => value,
        _ => "normal".to_owned(),
    }
}

fn public_update_requires_sanitization(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    [
        "root cause",
        "secret",
        "token",
        "credential",
        "private key",
        "customer data",
        "exploit",
        "internal only",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn message_create_operation(
    realm_id: &str,
    actor: &str,
    thread_id: Option<&str>,
    body: &str,
    incident_priority: Option<&str>,
) -> EventEnvelope {
    // Spec `event-payload.schema.json` `message_create_payload` requires
    // `flow_id` and `track_name` (`flow-and-message.md` §2). The default Flow
    // for a Realm is `ck:flow:<uuid>` (typed-id re-tag, matching
    // soland's `flow_id_from_realm_id`); the default track is "discussion".
    let flow_id = default_flow_id_for_realm(realm_id);
    let mut content = cokret_sdk::ContentBlock::text(body);
    if let Some(priority) = incident_priority.and_then(incident_priority_wire_value) {
        content = content.with_field("priority", json!(priority)).with_field(
            "notification",
            json!({
                "priority": priority,
                "priority_override": true,
            }),
        );
    }
    let mut payload = cokret_sdk::MessageCreatePayload::with_content(
        flow_id_value(&flow_id),
        "discussion",
        sdk_payload_value(content.to_value(), "timeline message content serialize"),
    );
    if let Some(thread_id) = thread_id {
        payload = payload.with_reply_to(thread_id);
    }
    OperationBuilder::new(realm_id, actor, "ck.message.create")
        .body(sdk_payload_value(
            payload.to_value(),
            "timeline ck.message.create payload serialize",
        ))
        .build("yougen")
}

fn default_flow_id_for_realm(realm_id: &str) -> String {
    realm_id
        .strip_prefix("ck:realm:")
        .map(|suffix| format!("ck:flow:{suffix}"))
        .unwrap_or_else(|| realm_id.to_owned())
}

fn message_revise_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    body: &str,
) -> EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.message.revise")
        .target_ref(event_id)
        .body(json!({
            "content": text_content(body),
            "target_ref": event_id,
        }))
        .build("yougen")
}

fn pending_send_error_is_permanent(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("capability_denied")
        || lower.contains("actor is not a member")
        || lower.contains("not a joined member")
        || lower.contains("banned")
        || lower.contains("forbidden")
        || lower.contains("403")
        || lower.contains("401")
}

async fn submit_timeline_message_with_plaintext_retry(
    api: &crate::api::CokretApi,
    realm_id: &str,
    actor_id: &str,
    operation: &EventEnvelope,
) -> anyhow::Result<crate::models::SubmitEventOutcome> {
    match api.submit_event_envelope(operation).await {
        Ok(response) => Ok(response),
        Err(error) if crate::api::is_plaintext_visibility_policy_error(&error) => {
            let description = api.describe().await?;
            let service_did = description.service_did.as_str().trim();
            if service_did.is_empty() {
                return Err(error);
            }
            api.update_realm_metadata(
                realm_id,
                actor_id,
                json!({"plaintext_visible_services": [service_did]}),
            )
            .await
            .map_err(|update_error| {
                anyhow::anyhow!(
                    "plaintext policy update failed: {update_error}; original send failed: {error}"
                )
            })?;
            api.submit_event_envelope(operation).await
        }
        Err(error) => Err(error),
    }
}

fn message_redact_operation(
    realm_id: &str,
    actor: &str,
    event_id: &str,
    reason: Option<&str>,
) -> EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.message.redact")
        .target_ref(event_id)
        .body(json!({
            "reason": reason,
            "target_event_id": event_id,
        }))
        .build("yougen")
}

fn reaction_add_operation(realm_id: &str, actor: &str, event_id: &str, key: &str) -> EventEnvelope {
    OperationBuilder::new(realm_id, actor, "ck.reaction.add")
        .target_ref(event_id)
        .body(json!({
            "target_ref": event_id,
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
    selected_realm_id: String,
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
    let initial_encrypt_local = timeline_private_data_bool(
        &state_store.read(),
        &account_did,
        TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY,
        false,
    );
    let mut encrypt_toggle = use_signal(|| initial_encrypt_local);
    let _typing_indicator = use_signal(String::new);
    let mut read_receipts = use_signal(Vec::<String>::new);
    let mut receipt_status = use_signal(|| "Read receipt: none".to_owned());
    let mut blob_status = use_signal(String::new);
    let mut attached_blob = use_signal(|| Option::<BlobAttachment>::None);
    let mut write_status = use_signal(String::new);
    let mut search_query = use_signal(String::new);
    let timeline_public_update_guard = timeline_private_data_bool(
        &state_store.read(),
        &account_did,
        TIMELINE_PUBLIC_UPDATE_GUARD_KEY,
        true,
    );
    let timeline_private_plaintext = timeline_private_data_bool(
        &state_store.read(),
        &account_did,
        TIMELINE_PRIVATE_PLAINTEXT_KEY,
        false,
    );
    let timeline_plaintext_ack = timeline_private_data_bool(
        &state_store.read(),
        &account_did,
        TIMELINE_PLAINTEXT_ACK_KEY,
        false,
    );
    let timeline_incident_priority =
        timeline_incident_priority_preference(&state_store.read(), &account_did);
    let mut initial_sync_requested = use_signal(|| false);
    // Perf (P0): the composer used to persist the whole draft state and POST a
    // `ck.typing` ephemeral on every keystroke. Debounce the draft persist and
    // throttle typing to leading-edge + trailing-stop instead.
    let draft_saver = crate::perf::use_debouncer(800);
    let typing_throttle = crate::perf::use_typing_throttle(3_000, 4_000);
    // A6.2 composer drag-drop attachment state. `compose_dragover`
    // toggles the `is-dragover` outline as the user holds a file
    // over the composer; `compose_upload_status` shows an inline
    // progress / error string for the most recent drop.
    let mut compose_dragover = use_signal(|| false);
    let mut compose_upload_status = use_signal(String::new);
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
    let account_did_c = account_did.clone();
    let device_id_c = device_id.clone();
    let selected_realm_c = selected_realm_id.clone();
    let account_did_key = account_did.clone();
    let device_id_key = device_id.clone();
    let selected_realm_key = selected_realm_id.clone();
    let latest_read_cursor = state_store.read().latest_read_cursor(&selected_realm_id);
    let latest_read_cursor_event_id = latest_read_cursor
        .as_ref()
        .map(|marker| marker.body.position.event_id.clone());
    let read_cursor_status = latest_read_cursor
        .as_ref()
        .map(read_cursor_status_label)
        .unwrap_or_else(|| "Read marker: none".to_owned());

    let timeline_snapshot = timeline();
    let events_data: Vec<(usize, TimelineEvent)> = timeline_snapshot
        .iter()
        .enumerate()
        .filter(|(_, event)| {
            selected_realm_id.trim().is_empty()
                || event
                    .realm_id
                    .as_deref()
                    .map(|realm_id| realm_id == selected_realm_id)
                    .unwrap_or(true)
        })
        .map(|(i, event)| (i, event.clone()))
        .collect();
    let events_for_reply_lookup = timeline_snapshot.clone();
    let events_for_composer_lookup = timeline_snapshot;
    // Perf: lowercase the search query ONCE per render instead of 3× per event
    // inside the timeline filter loop below.
    let search_query_lc = search_query().to_lowercase();
    let moderation_appeal_target = events_data
        .iter()
        .find(|(_, event)| timeline_event_has_moderation_decision(event))
        .map(|(_, event)| {
            let target_ref = event.event_id.clone().unwrap_or_else(|| event.id.clone());
            let decision_event_id = event.event_id.clone().unwrap_or_else(|| event.id.clone());
            (decision_event_id, target_ref)
        });
    let plaintext_blocked =
        timeline_private_plaintext && !encrypt_toggle() && !timeline_plaintext_ack;
    let timeline_incident_priority_for_keydown = timeline_incident_priority.clone();
    let timeline_incident_priority_for_button = timeline_incident_priority.clone();

    if timeline().is_empty() && !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        let base = base_url_sig();
        let api_token = token();
        let wait_for = active_sync_token(sync_cursor());
        spawn(async move {
            if let Ok(sync) =
                with_authed_api_with_sync(&base, api_token, wait_for, |api| async move {
                    api.account_subscribe_snapshot(None).await
                })
                .await
            {
                let events = timeline_events_from_sync_realms(&sync.realms);
                if !events.is_empty() {
                    let current = timeline();
                    timeline.set(crate::app::merge_timeline_events(&current, events));
                }
                sync_cursor.set(sync.cursor);
            }
        });
    }

    // Attested-audit emitter. Spec
    // `crypto-media/encryption-and-audit.md §11` says
    // `ck.audit.accessed` MUST be fired by readers on every successful
    // MLS decrypt. User-initiated Mark Read is approximately correct
    // but doesn't distinguish decrypt-success from "user clicked the
    // button". This
    // future scans the current `timeline()` snapshot for events
    // carrying encrypted content, attempts a local MLS decrypt via
    // the persisted snapshot for the Realm, and on each new success
    // emits a single `ck.audit.accessed` (dedup keyed by event_id).
    // Non-attested servers ignore the event; attested ones use it.
    let audit_accessed_emitted = use_signal(std::collections::HashSet::<String>::new);
    {
        let base_a = base_url.clone();
        let token_a = token;
        let realm_a = selected_realm_id.clone();
        let actor_a = account_did.clone();
        let device_a = device_id.clone();
        let mut emitted_sig = audit_accessed_emitted;
        use_future(move || {
            let base = base_a.clone();
            let realm = realm_a.clone();
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
                let api_token = token_a();
                for (event_id, payload_value) in candidates {
                    let Some(plaintext) =
                        try_local_mls_decrypt(state_store, &realm, &actor, &device, &payload_value)
                    else {
                        continue;
                    };
                    let _ = plaintext;
                    emitted_sig.write().insert(event_id.clone());
                    let base = base.clone();
                    let api_token = api_token.clone();
                    let realm = realm.clone();
                    let actor = actor.clone();
                    let device = device.clone();
                    spawn(async move {
                        let _ = with_authed_api(&base, api_token, |api| async move {
                            let op = crate::audit::build_audit_accessed(
                                &realm, &actor, &event_id, &device,
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

    let composer_class = "composer";

    // Round R2/R3 (T07) — Realm terminal-state projection. When the
    // selected Realm has emitted `ck.realm.destroy`, the timeline MUST
    // (a) surface a "permanently retired" banner and (b) gray out the
    // composer / send box. `realm_is_destroyed` reads the local
    // `realm_lifecycle_state` cache maintained as raw operations are
    // appended, so the render path stays constant-time.
    let realm_is_destroyed = state_store.read().realm_is_destroyed(&selected_realm_id);
    let epoch_update_required = state_store
        .read()
        .realm_has_pending_mls_binding(&selected_realm_id);
    let composer_blocked = realm_is_destroyed || epoch_update_required;

    rsx! {
        div {
            class: "timeline",
            "data-testid": "timeline",
            role: "feed",
            "aria-label": "Timeline events",
            "aria-live": "polite",

            if realm_is_destroyed {
                div {
                    class: "event",
                    "data-testid": "realm-destroyed-banner",
                    role: "alert",
                    "aria-live": "assertive",
                    div { class: "event-head",
                        span { "Realm permanently retired" }
                        span { class: "badge red", title: "ck.realm.destroy", "Destroyed" }
                    }
                    div { class: "muted",
                        "This realm has been permanently retired. No further messages, reactions, or state changes will be accepted (server-side: realm_terminal_state)."
                    }
                }
            }

            if epoch_update_required {
                div {
                    class: "event error-banner",
                    "data-testid": "epoch-update-required-banner",
                    role: "alert",
                    "aria-live": "assertive",
                    div { class: "event-head",
                        span { "epoch_update_required" }
                        span { class: "badge amber", title: "MLS membership frontier pending", "MLS" }
                    }
                    div { class: "muted",
                        "Membership changed in this encrypted Realm. Sending is paused until an MLS Remove/Commit covers the latest governance frontier."
                    }
                }
            }

            div { class: "composer", style: "margin-bottom: 8px;",
                Input {
                    r#type: "text",
                    "data-testid": "timeline-search",
                    placeholder: "Search messages...",
                    value: "{search_query}",
                    oninput: move |event: FormEvent| search_query.set(event.value()),
                }
            }

            for (idx, event) in events_data.into_iter() {
                if search_query_lc.is_empty()
                    || event.body.to_lowercase().contains(&search_query_lc)
                    || event.revisions.iter().any(|revision| {
                        revision.body.to_lowercase().contains(&search_query_lc)
                    })
                {
                    {
                        rsx! {
                            div {
                                class: if event.failed { "event is-failed" } else if event.pending { "event is-pending" } else { "event" },
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
                                if event.failed {
                                    span {
                                        class: "message-status-icon is-failed",
                                        "data-testid": "timeline-send-status",
                                        title: event.error.as_deref().unwrap_or("Send failed"),
                                        "!"
                                    }
                                } else if event.pending {
                                    span {
                                        class: "message-status-icon is-pending",
                                        "data-testid": "timeline-send-status",
                                        title: "Sending"
                                    }
                                }
                            }
                        }
                        if event.failed {
                            div {
                                class: "message-error-row",
                                "data-testid": "timeline-event-error",
                                span { class: "message-error-mark", "!" }
                                span {
                                    if let Some(error) = &event.error {
                                        "{error}"
                                    } else {
                                        "Event send failed"
                                    }
                                }
                            }
                        }

                        if latest_read_cursor_event_id.as_deref() == Some(event.id.as_str()) {
                            div { class: "muted", "data-testid": "read-cursor-badge",
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
                            Button {
                                variant: ButtonVariant::Secondary,
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
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                "data-testid": "reaction-badge",
                                                "{emoji} {senders.len()}"
                                            }
                                        }
                                    }
                                }

                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "reply-button",
                                        onclick: move |_| reply_to_index.set(Some(idx)),
                                        "Reply"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "react-button",
                                        onclick: move |_| {
                                            let current = show_reaction_picker();
                                            show_reaction_picker.set(if current == Some(idx) { None } else { Some(idx) });
                                        },
                                        "React"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
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
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "redact-button",
                                        onclick: move |_| redact_confirm.set(Some(idx)),
                                        "Redact"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "thread-button",
                                        onclick: move |_| {
                                            let current = thread_open();
                                            thread_open.set(if current == Some(idx) { None } else { Some(idx) });
                                        },
                                        "Thread"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "mark-read-button",
                                        disabled: event.pending || selected_realm_id.trim().is_empty(),
                                        onclick: {
                                            let base = base_url.clone();
                                            let event_id = event.id.clone();
                                            let realm = selected_realm_id.clone();
                                            let topic_id = event.thread_id.clone();
                                            let actor = account_did.clone();
                                            let device = device_id.clone();
                                            move |_| {
                                                if event_id.trim().is_empty() || realm.trim().is_empty() {
                                                    write_status.set("mark read skipped: missing event or realm".to_owned());
                                                    return;
                                                }

                                            let marker = state_store.write().save_read_cursor(
                                                actor.clone(),
                                                device.clone(),
                                                realm.clone(),
                                                topic_id.clone(),
                                                event_id.clone(),
                                            );
                                            write_status.set(format!(
                                                "read marker saved {}",
                                                marker.body.position.event_id
                                            ));

                                            // Resolve effective send preference per spec
                                            // discovery/client-preferences.md §3.6 (flow → realm →
                                            // default). Server-side Realm `ck.realm.read_receipt_policy`
                                            // is not yet exposed to the client; until it is, treat
                                            // policy as `Optional` (no override) and defer to user pref.
                                            let topic_for_pref = if marker.body.read_scope.kind == "thread" {
                                                marker.body.read_scope.object_ref.clone()
                                            } else {
                                                None
                                            };
                                            let should_send = state_store.read().read_receipt_should_send(
                                                topic_for_pref.as_deref(),
                                                Some(marker.body.realm_id.as_str()),
                                            );
                                            if !should_send {
                                                let marker_event_id_label =
                                                    short_protocol_id(&marker.body.position.event_id);
                                                receipt_status.set(format!(
                                                    "Read receipt: skipped per preference for {}",
                                                    marker_event_id_label
                                                ));
                                                return;
                                            }
                                            let marker_event_id_label =
                                                short_protocol_id(&marker.body.position.event_id);
                                            receipt_status.set(format!("Read receipt: sending {marker_event_id_label}"));

                                            let base = base.clone();
                                            let api_token = token();
                                            let wait_for = active_sync_token(sync_cursor());
                                            let receipt_realm = marker.body.realm_id.clone();
                                            let receipt_event_id = marker.body.position.event_id.clone();
                                            let actor_for_status = marker.actor.clone();
                                            let actor_for_audit = marker.actor.clone();
                                            let device_for_audit = marker.device_id.clone();
                                            spawn(async move {
                                                let actor_for_status_label =
                                                    short_protocol_id(&actor_for_status);
                                                let receipt_event_id_label =
                                                    short_protocol_id(&receipt_event_id);
                                                match authed_api_with_sync(&base, api_token, wait_for) {
                                                    Ok(api) => {
                                                        match api
                                                            .send_receipt(
                                                                &receipt_realm,
                                                                &actor_for_status,
                                                                &receipt_event_id,
                                                                "ck.receipt.read",
                                                            )
                                                            .await
                                                        {
                                                            Ok(receipt) if receipt.ok => {
                                                                read_receipts.write().push(format!(
                                                                    "{actor_for_status_label} -> {receipt_event_id_label}"
                                                                ));
                                                                receipt_status.set(format!(
                                                                    "Read receipt: sent ck.receipt.read for {receipt_event_id_label}"
                                                                ));
                                                            }
                                                            Ok(_) => receipt_status.set(format!(
                                                                "Read receipt: server returned not ok for {receipt_event_id_label}"
                                                            )),
                                                            Err(error) => receipt_status.set(format!(
                                                                "Read receipt failed: {error}"
                                                            )),
                                                        }

                                                        // `ck.audit.accessed`
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
                                                        // `ck.receipt.read`
                                                        // above and the
                                                        // local private
                                                        // read marker
                                                        // below.
                                                        let _ = (
                                                            &receipt_event_id,
                                                            &receipt_realm,
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            key: "{emoji}",
                                            onclick: {
                                                let base = base_url.clone();
                                                let eid = event.id.clone();
                                                let realm = selected_realm_id.clone();
                                                let actor = account_did.clone();
                                                let emoji = emoji.to_string();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let realm = realm.clone();
                                                    let actor = actor.clone();
                                                    let emoji = emoji.clone();
                                                    let api_token = token();
                                                    let wait_for = active_sync_token(sync_cursor());
                                                    spawn(async move {
                                                        if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                                            let op = reaction_add_operation(&realm, &actor, &eid, &emoji);
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
                                    Textarea {
                                        value: "{edit_draft}",
                                        oninput: move |event: FormEvent| edit_draft.set(event.value()),
                                    }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Primary,
                                            "data-testid": "save-edit-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let eid = event.id.clone();
                                                let realm = selected_realm_id.clone();
                                                let actor = account_did.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let realm = realm.clone();
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
                                                            found.failed = false;
                                                            found.error = None;
                                                            orig
                                                        });
                                                    editing_index.set(None);

                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => {
                                                                let op = message_revise_operation(
                                                                    &realm,
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
                                                                        found.failed = false;
                                                                        found.error = None;
                                                                    }
                                                                    state_store.write().append_raw_operation(
                                                                        op_id.clone(),
                                                                        Some(realm.clone()),
                                                                        json!({
                                                                            "event_id": updated.event_id,
                                                                            "kind": "ck.message.revise",
                                                                            "status": updated.status,
                                                                        }),
                                                                    );
                                                                    frontier_state.set(updated.event_id.clone());
                                                                    write_status.set(format!(
                                                                        "revised {}",
                                                                        short_protocol_id(&op_id)
                                                                    ));
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
                                                                        found.failed = true;
                                                                        found.error = Some(format!("edit failed: {error}"));
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            onclick: move |_| editing_index.set(None),
                                            "Cancel"
                                        }
                                    }
                                }
                            }

                            if redact_confirm() == Some(idx) {
                                div { class: "event", "data-testid": "redact-confirm",
                                    div { class: "entity-title", "Redact this message?" }
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Primary,
                                            "data-testid": "confirm-redact-button",
                                            onclick: {
                                                let base = base_url.clone();
                                                let eid = event.id.clone();
                                                let realm = selected_realm_id.clone();
                                                let actor = account_did.clone();
                                                move |_| {
                                                    let base = base.clone();
                                                    let eid = eid.clone();
                                                    let realm = realm.clone();
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
                                                            found.failed = false;
                                                            found.error = None;
                                                            orig
                                                        });
                                                    redact_confirm.set(None);

                                                    spawn(async move {
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => {
                                                                let op = message_redact_operation(
                                                                    &realm,
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
                                                                        Some(realm.clone()),
                                                                        json!({
                                                                            "event_id": redacted.event_id,
                                                                            "kind": "ck.message.redact",
                                                                            "reason": reason,
                                                                            "status": redacted.status,
                                                                        }),
                                                                    );
                                                                    write_status.set(format!(
                                                                        "tombstoned {}",
                                                                        short_protocol_id(&op_id)
                                                                    ));
                                                                }
                                                                Err(error) => {
                                                                    // Rollback optimistic redaction
                                                                    if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid)
                                                                        && let Some(original) = original
                                                                    {
                                                                        *found = original;
                                                                        found.failed = true;
                                                                        found.error = Some(format!("redact failed: {error}"));
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
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            onclick: move |_| redact_confirm.set(None),
                                            "Cancel"
                                        }
                                    }
                                }
                            }

                            if thread_open() == Some(idx) {
                                {
                                    let event_id_label = short_protocol_id(&event.id);
                                    rsx! {
                                        div { class: "event", "data-testid": "thread-panel",
                                            div { class: "event-head",
                                                span { "Thread" }
                                                span { title: "{event.id}", "{event_id_label}" }
                                            }
                                            div { class: "muted", "Thread messages would appear here." }
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    onclick: move |_| thread_open.set(None),
                                                    "Close Thread"
                                                }
                                            }
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
                                        {
                                            let revision_operation_id_label = revision.operation_id.as_ref().map(short_protocol_id);
                                            let revision_event_id_label = revision.event_id.as_ref().map(short_protocol_id);
                                            rsx! {
                                                div { class: "muted", "data-testid": "revision-entry",
                                                    "{revision.timestamp}: {revision.body}"
                                                    if let Some(operation_id) = &revision_operation_id_label {
                                                        " [{operation_id}]"
                                                    }
                                                    if let Some(event_id) = &revision_event_id_label {
                                                        " / {event_id}"
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

            if timeline().is_empty() {
                div { class: "event",
                    div { class: "event-head", span { "server" } span { "empty" } }
                    div { "No timeline events yet. Compose a dev-mode message." }
                }
            }
        }

        if let Some((decision_event_id, target_ref)) = moderation_appeal_target.clone() {
            crate::views::moderation_appeal::AppealEntrypoint {
                realm_id: selected_realm_c.clone(),
                appellant: account_did_c.clone(),
                decision_event_id,
                target_ref,
                base_url: base_url.clone(),
                api_token: token(),
                current_state: crate::views::moderation_appeal::AppealState::None,
            }
        }

        if !write_status().is_empty() {
            div { class: "muted", "data-testid": "write-status", "{write_status}" }
        }

        if !blob_status().is_empty() {
            div { class: "muted", "data-testid": "blob-status", "{blob_status}" }
        }

        div { class: "muted", "data-testid": "read-cursor-status", "{read_cursor_status}" }
        div { class: "muted", "data-testid": "read-receipt-status", "{receipt_status}" }

        if !read_receipts().is_empty() {
            div { class: "muted", "data-testid": "read-receipts",
                "Read by: {read_receipts:?}"
            }
        }

        div { class: "{composer_class}", "data-testid": "composer",
            if plaintext_blocked {
                div {
                    class: "compose-safety-banner",
                    "data-testid": "plaintext-boundary-warning",
                    role: "alert",
                    "Private plaintext is blocked by Timeline settings."
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
                    Button {
                        variant: ButtonVariant::Secondary,
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
                    let base = base_url_sig;
                    let realm = selected_realm_c.clone();
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
                        let realm = realm.clone();
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
                                let filename = file.name();
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
                                match api
                                    .upload_blob_bytes_scoped(
                                        bytes,
                                        &content_type,
                                        Some(&realm),
                                        Some(&filename),
                                    )
                                    .await
                                {
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
                Textarea {
                    "data-testid": "composer-input",
                    "aria-label": "Message composer",
                    value: "{draft}",
                    // Round R2/R3 (T07): disable the send box when the
                    // Realm has reached the destroy terminal state. Server
                    // rejects with `realm_terminal_state`; failing closed
                    // in the UI surfaces the boundary before a wasted
                    // round-trip.
                    disabled: composer_blocked,
                    placeholder: if realm_is_destroyed {
                        "This realm has been permanently retired."
                    } else if epoch_update_required {
                        "Waiting for MLS epoch update."
                    } else if encrypt_toggle() {
                        "Write an encrypted message (Ctrl+Enter to send)"
                    } else {
                        "Write a plaintext dev-mode message (Ctrl+Enter to send)"
                    },
                oninput: {
                    let sc = selected_realm_c.clone();
                    let actor_for_typing = account_did_c.clone();
                    let device_for_typing = device_id_c.clone();
                    move |event: FormEvent| {
                        let value = event.value();
                        // Local draft signal updates instantly for responsive
                        // typing; the (blocking) persist is debounced.
                        draft.set(value.clone());
                        let save_space = sc.clone();
                        draft_saver.call(move || {
                            state_store.write().save_draft(save_space, value);
                        });
                        // Throttle typing: leading-edge true (≤ once / 3s) plus
                        // a trailing false once the user stops — instead of one
                        // POST per character.
                        let base = base_url_sig();
                        let realm = sc.clone();
                        let actor = actor_for_typing.clone();
                        let device = device_for_typing.clone();
                        typing_throttle.on_keystroke(move |is_typing| {
                            let base = base.clone();
                            let api_token = token();
                            let realm = realm.clone();
                            let actor = actor.clone();
                            let device = device.clone();
                            let wait_for = active_sync_token(sync_cursor());
                            spawn(async move {
                                if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                    // Round R2/R3 (T02): send_typing constructs a
                                    // ck.typing EphemeralEnvelope and POSTs it to
                                    // the broadcast ephemeral channel instead of
                                    // ck.events.submit.
                                    let _ = api
                                        .send_typing(
                                            &realm,
                                            &actor,
                                            Some(device.as_str()).filter(|s| !s.is_empty()),
                                            is_typing,
                                        )
                                        .await;
                                }
                            });
                        });
                    }
                },
                onkeydown: move |event: KeyboardEvent| {
                    if event.key().to_string() == "Enter" && event.modifiers().ctrl() {
                        let body = draft().trim().to_owned();
                        if body.is_empty() {
                            return;
                        }
                        if epoch_update_required {
                            write_status.set("epoch_update_required: waiting for MLS Remove/Commit".to_owned());
                            return;
                        }
                        if timeline_public_update_guard && public_update_requires_sanitization(&body) {
                            let msg = "public update blocked: remove internal incident details before posting".to_owned();
                            write_status.set(msg);
                            return;
                        }
                        if timeline_private_plaintext && !encrypt_toggle() && !timeline_plaintext_ack {
                            write_status.set("plaintext blocked: acknowledge boundary or enable encryption".to_owned());
                            return;
                        }
                        let reply_target = reply_to_index()
                            .and_then(|idx| timeline().get(idx).map(|event| event.id.clone()));
                        let thread_id = reply_target.clone();
                        let realm_for_encrypt = selected_realm_key.clone();
                        let realm_for_plain = selected_realm_key.clone();
                        let realm_for_draft = selected_realm_key.clone();
                        let incident_priority_for_send =
                            timeline_incident_priority_for_keydown.clone();
                        if encrypt_toggle() {
                            match compose_local_encrypted_message(
                                &account_did_key,
                                &device_id_key,
                                &realm_for_encrypt,
                                "ck:message:local-compose",
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
                                realm_id: Some(realm_for_plain.clone()),
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
                                failed: false,
                                error: None,
                                encrypted_payload: None,
                            });
                            let base = base_url_sig();
                            let api_token = token();
                            let realm = realm_for_plain.clone();
                            let actor = account_did_key.clone();
                            let wait_for = active_sync_token(sync_cursor());
                            spawn(async move {
                                if let Ok(api) = authed_api_with_sync(&base, api_token, wait_for) {
                                    let op = message_create_operation(
                                        &realm,
                                        &actor,
                                        thread_id.as_deref(),
                                        &body,
                                        Some(incident_priority_for_send.as_str()),
                                    );
                                    let op_id = op.local_operation_id().to_owned();
                                    match submit_timeline_message_with_plaintext_retry(
                                        &api,
                                        &realm,
                                        &actor,
                                        &op,
                                    ).await {
                                        Ok(resp) => {
                                            if let Some(event) = timeline.write().iter_mut().find(|e| e.id == event_id) {
                                                event.apply_send_ack(resp.event_id.clone(), op_id);
                                            }
                                        }
                                        Err(error) => {
                                            if let Some(event) = timeline.write().iter_mut().find(|e| e.id == event_id) {
                                                event.pending = false;
                                                event.failed = true;
                                                event.error = Some(format!("send failed: {error}"));
                                            }
                                            write_status.set(format!("send failed: {error}"));
                                        }
                                    }
                                }
                            });
                        }
                        draft.set(String::new());
                        state_store.write().save_draft(realm_for_draft, String::new());
                        reply_to_index.set(None);
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
                    Checkbox {
                        "data-testid": "encrypt-local-button",
                        checked: if encrypt_toggle() {
                            CheckboxState::Checked
                        } else {
                            CheckboxState::Unchecked
                        },
                        on_checked_change: move |state: CheckboxState| encrypt_toggle.set(bool::from(state)),
                    }
                    " Encrypt Local"
                }

                Button {
                    variant: ButtonVariant::Secondary,
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
                                        // SDK `BlobUploadOutcome` carries typed
                                        // `Hash` / `BlobRef` / `Option<String>` fields;
                                        // flatten them to the display-only `String`s
                                        // the local `BlobAttachment` keeps.
                                        let content_digest = blob.content_digest.as_str().to_owned();
                                        let media_type = blob.media_type.clone().unwrap_or_default();
                                        let hash_state = if content_digest.trim_start_matches("sha256:") == local_hash {
                                            "upload hash ok"
                                        } else {
                                            "upload hash mismatch"
                                        };
                                        let policy = media_type_preview_policy(&media_type);
                                        attached_blob.set(Some(BlobAttachment {
                                            blob_ref: blob.blob_ref.to_string(),
                                            size_bytes: blob.size_bytes as usize,
                                            media_type,
                                            content_digest,
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
                        div { class: "muted", "Digest: {blob.content_digest}" }
                        div { class: "muted", "Size: {blob.size_bytes} bytes" }
                        div { class: "muted", "Policy: {media_type_preview_policy(&blob.media_type).label()}" }
                        div { class: "muted", "Download path uses Authorization header; bearer token is never placed in the blob URL." }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "verify-blob-download",
                                onclick: {
                                    let blob_ref = blob.blob_ref.clone();
                                    let expected_content_digest = blob.content_digest.clone();
                                    move |_| {
                                        let base = base_url_sig();
                                        let api_token = token();
                                        let wait_for = active_sync_token(sync_cursor());
                                        let blob_ref = blob_ref.clone();
                                        let expected_content_digest = expected_content_digest.clone();
                                        spawn(async move {
                                            match authed_api_with_sync(&base, api_token, wait_for) {
                                                Ok(api) => match api.get_blob_bytes(&blob_ref).await {
                                                    Ok(bytes) if hash_matches(&expected_content_digest, &bytes) => {
                                                        blob_status.set(format!(
                                                            "download verified digest {} ({} bytes)",
                                                            expected_content_digest,
                                                            bytes.len()
                                                        ));
                                                    }
                                                    Ok(bytes) => {
                                                        blob_status.set(format!(
                                                            "download hash mismatch expected {} got {}",
                                                            expected_content_digest,
                                                            sha256_hex(&bytes)
                                                        ));
                                                    }
                                                    Err(error) => {
                                                        // Round R2/R3 (T11) — fail-closed
                                                        // mapping for the 4 presign blob error
                                                        // classes. Show a translated friendly
                                                        // message and DO NOT retry / cache the
                                                        // URL / log it. Errors that don't
                                                        // classify into one of the four codes
                                                        // fall back to the raw display.
                                                        if let Some(class) = crate::api::BlobPresignError::from_error(&error) {
                                                            blob_status.set(crate::i18n::tr(class.i18n_key()));
                                                        } else {
                                                            blob_status.set(format!("download failed: {error}"));
                                                        }
                                                    }
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

                Button {
                    variant: ButtonVariant::Primary,
                    "data-testid": "send-button",
                    // Round R2/R3 (T07) — block new writes when the Realm
                    // is in the destroy terminal state. Server enforces via
                    // `realm_terminal_state` but failing closed in the UI
                    // avoids a wasted round-trip + confusing error.
                    disabled: composer_blocked,
                    onclick: {
                        let sc = selected_realm_c.clone();
                        let ac = account_did_c.clone();
                        let dc = device_id_c.clone();
                        move |_| {
                            if realm_is_destroyed {
                                write_status.set("This realm has been permanently retired.".to_owned());
                                return;
                            }
                            if epoch_update_required {
                                write_status.set("epoch_update_required: waiting for MLS Remove/Commit".to_owned());
                                return;
                            }
                            let body = draft().trim().to_owned();
                            if body.is_empty() {
                                return;
                            }
                            if timeline_public_update_guard && public_update_requires_sanitization(&body) {
                                let msg = "public update blocked: remove internal incident details before posting".to_owned();
                                write_status.set(msg);
                                return;
                            }
                            if timeline_private_plaintext && !encrypt_toggle() && !timeline_plaintext_ack {
                                write_status.set("plaintext blocked: acknowledge boundary or enable encryption".to_owned());
                                return;
                            }

                            let reply_target = reply_to_index()
                                .and_then(|idx| timeline().get(idx).map(|event| event.id.clone()));
                            let thread_id = reply_target.clone();
                            let realm_for_encrypt = sc.clone();
                            let realm_for_plain = sc.clone();
                            let realm_for_draft = sc.clone();
                            let incident_priority_for_send =
                                timeline_incident_priority_for_button.clone();
                            if encrypt_toggle() {
                                match compose_local_encrypted_message(
                                    &ac,
                                    &dc,
                                    &realm_for_encrypt,
                                    "ck:message:local-compose",
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
                                        state_store.write().save_draft(realm_for_encrypt, "");
                                        draft.set(String::new());
                                        reply_to_index.set(None);
                                    }
                                    Err(error) => crypto_state.set(format!("encrypt failed: {error}")),
                                }
                            } else {
                                let local_event_id = format!("local-event-{}", uuid_v7());
                                timeline.write().push(TimelineEvent::pending_message(
                                    realm_for_plain.clone(),
                                    local_event_id.clone(),
                                    ac.clone(),
                                    "local",
                                    body.clone(),
                                    reply_target.clone(),
                                    thread_id.clone(),
                                ));
                                state_store.write().save_draft(realm_for_draft, "");
                                draft.set(String::new());
                                reply_to_index.set(None);

                                let base = base_url_sig();
                                let realm = realm_for_plain;
                                let api_token = token();
                                let wait_for = active_sync_token(sync_cursor());
                                let body_clone = body.clone();
                                let actor = ac.clone();
                                spawn(async move {
                                    match authed_api_with_sync(&base, api_token, wait_for) {
                                        Ok(api) => {
                                            let op = message_create_operation(
                                                &realm,
                                                &actor,
                                                thread_id.as_deref(),
                                                &body_clone,
                                                Some(incident_priority_for_send.as_str()),
                                            );
                                            let op_id = op.local_operation_id().to_owned();
                                            let mut attempt = 0usize;
                                            loop {
                                                match submit_timeline_message_with_plaintext_retry(
                                                    &api,
                                                    &realm,
                                                    &actor,
                                                    &op,
                                                ).await {
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
                                                        frontier_state.set(sent.event_id.clone());
                                                        {
                                                            let mut store = state_store.write();
                                                            // This sync_token is a write barrier from POST /events;
                                                            // only /account/subscribe cursors are persisted.
                                                            store.append_raw_operation(
                                                                op_id.clone(),
                                                                Some(realm.clone()),
                                                                json!({
                                                                    "event_id": sent.event_id,
                                                                    "kind": "ck.message.create",
                                                                    "status": sent.status,
                                                                }),
                                                            );
                                                        }
                                                        write_status.set(format!(
                                                            "persisted {}",
                                                            short_protocol_id(&op_id)
                                                        ));
                                                        break;
                                                    }
                                                    Err(error) => {
                                                        let error_text = format!("{error}");
                                                        if pending_send_error_is_permanent(&error_text) {
                                                            if let Some(found) = timeline
                                                                .write()
                                                                .iter_mut()
                                                                .find(|candidate| candidate.id == local_event_id)
                                                            {
                                                                found.pending = false;
                                                                found.failed = true;
                                                                found.error = Some(format!(
                                                                    "discarded pending change: {error_text}"
                                                                ));
                                                            }
                                                            write_status.set(format!(
                                                                "discarded pending change: {error_text}"
                                                            ));
                                                            break;
                                                        }
                                                        attempt += 1;
                                                        if attempt >= 30 {
                                                            if let Some(found) = timeline
                                                                .write()
                                                                .iter_mut()
                                                                .find(|candidate| candidate.id == local_event_id)
                                                            {
                                                                found.pending = false;
                                                                found.failed = true;
                                                                found.error = Some(format!(
                                                                    "send failed after reconnect retries: {error_text}"
                                                                ));
                                                            }
                                                            write_status.set(format!(
                                                                "send failed after reconnect retries: {error_text}"
                                                            ));
                                                            break;
                                                        }
                                                        write_status.set(format!(
                                                            "pending sync: queued {} (retry {attempt})",
                                                            short_protocol_id(&op_id)
                                                        ));
                                                        crate::api::sleep_for(Duration::from_secs(1)).await;
                                                    }
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

                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "report-queue-button",
                    onclick: {
                        let sc = selected_realm_c.clone();
                        let ac = account_did_c.clone();
                        let dc = device_id_c.clone();
                        move |_| {
                            let base = base_url_sig();
                            let actor = ac.clone();
                            let dev = dc.clone();
                            let api_token = token();
                            let realm = sc.clone();
                            let wait_for = active_sync_token(sync_cursor());
                            spawn(async move {
                                let _ = with_authed_api_with_sync(
                                    &base,
                                    api_token,
                                    wait_for,
                                    |api| async move {
                                        let _ = api
                                            .report_moderation(
                                                &realm,
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
        }
    }
}

/// Read the sender identity from a timeline event envelope.
///
/// canonical envelope 主体是 `actor_id`(spec forbidden-wire-fields.json:
/// `sender → sender_actor_id`)。优先 `actor_id` / `sender_actor_id`;`sender`
/// 已废弃,降到尾部仅作向后兼容容忍服务端旧值。
fn timeline_actor_id(event: &Value) -> Option<&str> {
    ["actor_id", "sender_actor_id", "sender"]
        .into_iter()
        .find_map(|key| event.get(key).and_then(Value::as_str))
}

/// Project the `realms[*].timeline.events` of an account-subscribe response
/// into [`TimelineEvent`]s. YOU-06-003 / YOU-01-013: this is the single
/// owner of timeline wire parsing — the former Matrix-shaped `app.rs` copy
/// (read `sender`/`content` only) was deleted and both the sync engine and
/// the timeline view now call this canonical version, which reads the spec
/// envelope (`actor_id` / `sender_actor_id`, `payload`/`content` body) and
/// carries `encrypted_content` forward for local MLS decrypt.
pub fn timeline_events_from_sync_realms(
    realms: &std::collections::BTreeMap<String, Value>,
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for (realm_id, body) in realms {
        let realm_id_label = short_protocol_id(realm_id);
        let mut summary_event = TimelineEvent::system_notice(
            format!("summary-{realm_id}"),
            "server",
            format!(
                "{realm_id_label}: {}",
                body["summary"]["summary"]
                    .as_str()
                    .unwrap_or("No summary available")
            ),
        );
        summary_event.realm_id = Some(realm_id.clone());
        events.push(summary_event);

        let Some(timeline_events) = body
            .get("timeline")
            .and_then(|timeline| timeline.get("events"))
            .and_then(Value::as_array)
        else {
            continue;
        };

        for event in timeline_events {
            if event.get("kind").and_then(Value::as_str) != Some("ck.message.create") {
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
            // B7: carry the raw `encrypted_content` block forward so the
            // audit-accessed emitter (later in this component) can try a
            // local MLS decrypt against it and fire `ck.audit.accessed`
            // on every successful decrypt.
            let encrypted_payload = content.get("encrypted_content").cloned();
            events.push(TimelineEvent {
                realm_id: Some(realm_id.clone()),
                id: event_id.clone(),
                // canonical envelope 主体是 `actor_id`(spec
                // forbidden-wire-fields.json: sender → sender_actor_id)。优先
                // actor_id / sender_actor_id;`sender` 已废弃,仅作向后兼容。
                sender: timeline_actor_id(event)
                    .unwrap_or("did:web:unknown")
                    .to_owned(),
                sender_display: timeline_actor_id(event)
                    .map(short_protocol_id)
                    .unwrap_or_else(|| "server".to_owned()),
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

fn timeline_event_has_moderation_decision(event: &TimelineEvent) -> bool {
    let body = event.body.to_ascii_lowercase();
    let tombstone = event
        .tombstone_reason
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    body.contains("moderation decision")
        || body.contains("moderation blocked")
        || tombstone.contains("moderation")
}

fn timestamp_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M").to_string()
}

fn read_cursor_status_label(marker: &ReadMarkerRecord) -> String {
    let scope = match (
        marker.body.read_scope.kind.as_str(),
        marker.body.read_scope.object_ref.as_deref(),
        marker.body.read_scope.track_name.as_deref(),
    ) {
        ("thread", Some(object_ref), _) => format!("thread {}", short_protocol_id(object_ref)),
        ("flow", Some(object_ref), Some(track)) => {
            format!("{track} {}", short_protocol_id(object_ref))
        }
        ("flow", Some(object_ref), None) => format!("flow {}", short_protocol_id(object_ref)),
        (kind, ..) => kind.to_owned(),
    };
    format!(
        "Read marker: {} ({scope}) at {}",
        short_protocol_id(&marker.body.position.event_id),
        marker.updated_at.format("%Y-%m-%d %H:%M")
    )
}

pub(crate) fn plaintext_visible_service(base_url: &str) -> String {
    base_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .filter(|host| !host.is_empty())
        .map(|host| format!("configured server {host}"))
        .unwrap_or_else(|| "configured server".to_owned())
}

/// Attempt a local MLS decrypt of an encrypted message-content JSON object
/// emitted by chat.rs
/// Send Secure. Returns `Some(plaintext_bytes)` on successful decrypt,
/// `None` for every soft failure (no snapshot, snapshot can't be
/// hydrated with this device's snapshot secret, payload doesn't
/// deserialize as a typed `EncryptedPayload`, group rejects the payload).
///
/// The caller — the `ck.audit.accessed` emitter inside
/// [`TimelinePanel`] — uses `Some(...)` as the firing trigger, so any
/// soft failure quietly suppresses the audit emit instead of looping.
/// Runs on every target now that OpenMLS builds on wasm32 (the browser
/// uses the same in-tree OpenMLS via the `js` feature). Any soft failure
/// (no snapshot / wrong device secret / payload that doesn't decrypt)
/// returns `None`, so the audit emitter is a no-op in those cases.
///
/// The snapshot secret is device-scoped and read from `SecureKeyStore`.
/// Only real SDK-encrypted payloads should trigger the audit hook.
fn try_local_mls_decrypt(
    state_store: Signal<LocalStateStore>,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload_value: &Value,
) -> Option<Vec<u8>> {
    try_local_mls_decrypt_core(
        &state_store.read(),
        realm_id,
        actor_id,
        device_id,
        payload_value,
    )
}

/// Shared MLS decrypt core used by both the timeline audit emitter
/// (`try_local_mls_decrypt`, which holds a `Signal<LocalStateStore>`) and
/// the kanban decrypt-on-read path (which already holds a borrowed
/// `&LocalStateStore`). Restores the Realm's MLS group from the local
/// snapshot + this device's snapshot secret and decrypts `payload_value`
/// (a typed `EncryptedPayload` envelope). Every soft failure (no snapshot,
/// wrong/absent device secret, payload that doesn't deserialize or
/// decrypt) returns `None`.
pub(crate) fn try_local_mls_decrypt_core(
    state_store: &LocalStateStore,
    realm_id: &str,
    actor_id: &str,
    device_id: &str,
    payload_value: &Value,
) -> Option<Vec<u8>> {
    let envelope = state_store.mls_snapshot_for(realm_id)?;
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    let secret = crate::mls::runtime::load_device_snapshot_secret(
        secure_store.as_ref(),
        actor_id,
        device_id,
    )
    .ok()?;
    let mut group = crate::mls::persistence::restore_envelope(&envelope, &secret, 0).ok()?;
    let payload: cokret_sdk::EncryptedPayload =
        serde_json::from_value(payload_value.clone()).ok()?;
    group.decrypt_payload(&payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_create_operation_retags_realm_scope_to_flow_id() {
        let op = message_create_operation(
            "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            None,
            "hello",
            None,
        );

        assert_eq!(
            op.payload["flow_id"],
            "ck:flow:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22"
        );
        assert_eq!(op.payload["track_name"], "discussion");
        assert_eq!(op.payload["content"]["kind"], "ck.content.text");
        assert!(op.payload.get("body").is_none());
        assert!(op.payload.get("encrypted").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn message_create_operation_attaches_incident_priority_under_realm() {
        let op = message_create_operation(
            "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            None,
            "hello",
            Some("sev1"),
        );

        assert_eq!(
            op.payload["flow_id"],
            "ck:flow:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22"
        );
        assert!(op.payload.get("priority").is_none());
        assert!(op.payload.get("notification_priority").is_none());
        assert!(op.payload.get("priority_override").is_none());
        assert_eq!(op.payload["content"]["priority"], "critical");
        assert_eq!(
            op.payload["content"]["notification"]["priority"],
            "critical"
        );
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn public_update_guard_flags_internal_details() {
        assert!(public_update_requires_sanitization(
            "Public update: root cause is a leaked token"
        ));
        assert!(!public_update_requires_sanitization(
            "Public update: checkout latency is recovering"
        ));
    }

    #[test]
    fn message_revise_operation_carries_schema_target_ref() {
        let op = message_revise_operation(
            "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
            "edited",
        );

        assert_eq!(
            op.payload["target_ref"],
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
        );
        assert_eq!(op.payload["content"]["kind"], "ck.content.text");
        assert_eq!(op.payload["content"]["body"], "edited");
        assert!(op.payload.get("body").is_none());
        assert!(op.payload.get("target_event_id").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }

    #[test]
    fn reaction_add_operation_uses_schema_target_ref() {
        let op = reaction_add_operation(
            "ck:realm:019e4fd4-4e26-7cc9-af7e-d7102d6f4a22",
            "did:web:bob.example",
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23",
            "+1",
        );

        assert_eq!(
            op.payload["target_ref"],
            "ck:event:019e4fd4-4e26-7cc9-af7e-d7102d6f4a23"
        );
        assert_eq!(op.payload["key"], "+1");
        assert!(op.payload.get("event_id").is_none());
        assert!(op.payload.get("actor").is_none());
        cokret_sdk::schema::event_payload_validator_catalog()
            .validate_payload(&op.kind, &op.payload)
            .unwrap();
    }
}
