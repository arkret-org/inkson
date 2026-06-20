use dioxus::prelude::*;
use serde_json::json;

use super::composer::TimelineComposer;
use super::decrypt::try_local_mls_decrypt;
use super::model::{BlobAttachment, TimelineEvent, TimelineRevision, timestamp_now};
use super::operations::{
    message_redact_operation, message_revise_operation, reaction_add_operation,
    sdk_event_local_operation_id,
};
use super::preferences::{
    EMOJI_GRID, TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY, TIMELINE_PLAINTEXT_ACK_KEY,
    TIMELINE_PRIVATE_PLAINTEXT_KEY, TIMELINE_PUBLIC_UPDATE_GUARD_KEY,
    timeline_incident_priority_preference, timeline_private_data_bool,
};
use super::sync::{
    read_cursor_status_label, timeline_event_has_moderation_decision,
    timeline_events_from_sync_realms, timeline_reply_quote_preview,
};
use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    active_sync_token, authed_api_with_sync, short_protocol_id, with_authed_api,
    with_authed_api_with_sync,
};

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
    let encrypt_toggle = use_signal(|| initial_encrypt_local);
    let _typing_indicator = use_signal(String::new);
    let mut read_receipts = use_signal(Vec::<String>::new);
    let mut receipt_status = use_signal(|| "Read receipt: none".to_owned());
    let blob_status = use_signal(String::new);
    let attached_blob = use_signal(|| Option::<BlobAttachment>::None);
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
    // A6.2 composer drag-drop attachment state. `compose_dragover`
    // toggles the `is-dragover` outline as the user holds a file
    // over the composer; `compose_upload_status` shows an inline
    // progress / error string for the most recent drop.
    let compose_dragover = use_signal(|| false);
    let compose_upload_status = use_signal(String::new);
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

    if timeline().is_empty() && !initial_sync_requested() && !token().trim().is_empty() {
        initial_sync_requested.set(true);
        let base = base_url_sig();
        let api_token = token();
        let wait_for = active_sync_token(sync_cursor());
        let decrypt_actor = account_did.clone();
        let decrypt_device = device_id.clone();
        spawn(async move {
            if let Ok(sync) =
                with_authed_api_with_sync(&base, api_token, wait_for, |api| async move {
                    api.account_subscribe_snapshot(None).await
                })
                .await
            {
                {
                    let mut store = state_store.write();
                    crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                        &mut store,
                        &sync.realms,
                    );
                }
                // Merge encrypted bodies on read: author sidecar first, then
                // remote decrypt-on-read, both via the local state store. The
                // read guard outlives the parse call; `try_local_mls_decrypt_core`
                // writes its receive chain back through interior mutability.
                let store_guard = state_store.read();
                let events = timeline_events_from_sync_realms(
                    &sync.realms,
                    Some(&store_guard),
                    Some((&decrypt_actor, &decrypt_device)),
                );
                drop(store_guard);
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
                            .build_sdk_event("yougen")?;
                            api.submit_sdk_event(&op).await
                        })
                        .await;
                    });
                }
            }
        });
    }

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
                                            // discovery/client-preferences.md §3.6 (strand → realm →
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
                                                        // YOU-02-007: surface reaction submit
                                                        // failures instead of swallowing them —
                                                        // the picker is already closed, so the
                                                        // status line is the only feedback left.
                                                        match authed_api_with_sync(&base, api_token, wait_for) {
                                                            Ok(api) => {
                                                                match reaction_add_operation(&realm, &actor, &eid, &emoji) {
                                                                    Ok(op) => {
                                                                        if let Err(error) = api.submit_sdk_event(&op).await {
                                                                            write_status.set(format!("reaction failed: {error}"));
                                                                        }
                                                                    }
                                                                    Err(error) => {
                                                                        write_status.set(format!("reaction failed: {error:#}"));
                                                                    }
                                                                }
                                                            }
                                                            Err(error) => {
                                                                write_status.set(format!("reaction failed: {error}"));
                                                            }
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
                                                                let op = match message_revise_operation(
                                                                    &realm,
                                                                    &actor,
                                                                    &eid,
                                                                    &content,
                                                                ) {
                                                                    Ok(op) => op,
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
                                                                            found.error = Some(format!("edit failed: {error:#}"));
                                                                        }
                                                                        write_status.set(format!("edit failed: {error:#}"));
                                                                        return;
                                                                    }
                                                                };
                                                                let op_id = sdk_event_local_operation_id(&op).to_owned();
                                                                match api.submit_sdk_event(&op).await {
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
                                                                let op = match message_redact_operation(
                                                                    &realm,
                                                                    &actor,
                                                                    &eid,
                                                                    reason.as_deref(),
                                                                ) {
                                                                    Ok(op) => op,
                                                                    Err(error) => {
                                                                        if let Some(found) = timeline.write().iter_mut().find(|candidate| candidate.id == eid)
                                                                            && let Some(original) = original
                                                                        {
                                                                            *found = original;
                                                                            found.failed = true;
                                                                            found.error = Some(format!("redact failed: {error:#}"));
                                                                        }
                                                                        write_status.set(format!("redact failed: {error:#}"));
                                                                        return;
                                                                    }
                                                                };
                                                                let op_id = sdk_event_local_operation_id(&op).to_owned();
                                                                match api.submit_sdk_event(&op).await {
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

        TimelineComposer {
            timeline,
            draft,
            state_store,
            write_status,
            frontier_state,
            token,
            sync_cursor,
            base_url_sig,
            encrypt_toggle,
            reply_to_index,
            compose_dragover,
            compose_upload_status,
            blob_status,
            attached_blob,
            selected_realm_id: selected_realm_c.clone(),
            account_did: account_did_c.clone(),
            device_id: device_id_c.clone(),
            timeline_incident_priority: timeline_incident_priority.clone(),
            plaintext_blocked,
            realm_is_destroyed,
            epoch_update_required,
            composer_blocked,
            timeline_public_update_guard,
            timeline_private_plaintext,
            timeline_plaintext_ack,
            events_for_composer_lookup: events_for_composer_lookup.clone(),
        }
    }
}
