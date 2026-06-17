use std::time::Duration;

use chrono::Utc;
use dioxus::html::HasFileData;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::json;

use super::model::{BlobAttachment, TimelineEvent};
use super::operations::{
    message_create_operation, pending_send_error_is_permanent, public_update_requires_sanitization,
    submit_timeline_message_with_plaintext_retry,
};
use super::preferences::ATTACHMENT_BYTES;
use super::secure_send::{TimelineEncryptedSend, send_timeline_encrypted_message};
use super::sync::timeline_reply_quote_preview;
use crate::local_state::LocalStateStore;
use crate::media::{hash_matches, media_type_preview_policy, sha256_hex};
use crate::operation::uuid_v7;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{
    active_sync_token, authed_api_with_sync, short_protocol_id, with_authed_api_with_sync,
};

/// Composer footer for [`super::panel::TimelinePanel`]. Holds the
/// drag-drop attachment zone, the message textarea (plaintext + encrypted
/// send paths), the encrypt-local toggle, blob attach/verify, and the
/// report/queue action.
#[component]
pub(super) fn TimelineComposer(
    timeline: Signal<Vec<TimelineEvent>>,
    draft: Signal<String>,
    state_store: Signal<LocalStateStore>,
    write_status: Signal<String>,
    frontier_state: Signal<String>,
    token: Signal<String>,
    sync_cursor: Signal<String>,
    base_url_sig: Signal<String>,
    encrypt_toggle: Signal<bool>,
    reply_to_index: Signal<Option<usize>>,
    compose_dragover: Signal<bool>,
    compose_upload_status: Signal<String>,
    blob_status: Signal<String>,
    attached_blob: Signal<Option<BlobAttachment>>,
    selected_realm_id: String,
    account_did: String,
    device_id: String,
    timeline_incident_priority: String,
    plaintext_blocked: bool,
    realm_is_destroyed: bool,
    epoch_update_required: bool,
    composer_blocked: bool,
    timeline_public_update_guard: bool,
    timeline_private_plaintext: bool,
    timeline_plaintext_ack: bool,
    events_for_composer_lookup: Vec<TimelineEvent>,
) -> Element {
    // Local-only writable handles for the closures below.
    let mut draft = draft;
    let mut write_status = write_status;
    let mut reply_to_index = reply_to_index;
    let mut encrypt_toggle = encrypt_toggle;
    let mut compose_dragover = compose_dragover;
    let mut compose_upload_status = compose_upload_status;
    let mut blob_status = blob_status;
    let mut attached_blob = attached_blob;
    let mut timeline = timeline;
    let mut state_store = state_store;
    let mut frontier_state = frontier_state;

    // Perf (P0): the composer used to persist the whole draft state and POST a
    // `ck.typing` ephemeral on every keystroke. Debounce the draft persist and
    // throttle typing to leading-edge + trailing-stop instead.
    let draft_saver = crate::perf::use_debouncer(800);
    let typing_throttle = crate::perf::use_typing_throttle(3_000, 4_000);

    let selected_realm_c = selected_realm_id.clone();
    let selected_realm_key = selected_realm_id.clone();
    let account_did_c = account_did.clone();
    let account_did_key = account_did.clone();
    let device_id_c = device_id.clone();
    let device_id_key = device_id.clone();
    let timeline_incident_priority_for_keydown = timeline_incident_priority.clone();
    let timeline_incident_priority_for_button = timeline_incident_priority.clone();

    rsx! {
        div { class: "composer", "data-testid": "composer",
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
                            let queued = send_timeline_encrypted_message(
                                TimelineEncryptedSend {
                                    timeline,
                                    state_store,
                                    write_status,
                                    frontier_state,
                                    base_url: base_url_sig(),
                                    api_token: token(),
                                    wait_for: active_sync_token(sync_cursor()),
                                    realm: realm_for_encrypt.clone(),
                                    actor: account_did_key.clone(),
                                    device: device_id_key.clone(),
                                    body: body.clone(),
                                    reply_to: reply_target.clone(),
                                    thread_id: thread_id.clone(),
                                },
                            );
                            // Honest fail-closed: only clear the composer when the
                            // encrypted send was actually queued. On a fail-closed
                            // abort (no MLS group / seal) we keep the draft so the
                            // user can retry once the group syncs.
                            if queued {
                                draft.set(String::new());
                                state_store.write().save_draft(realm_for_draft, String::new());
                                reply_to_index.set(None);
                            }
                            return;
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
                                    let op = match message_create_operation(
                                        &realm,
                                        &actor,
                                        thread_id.as_deref(),
                                        &body,
                                        Some(incident_priority_for_send.as_str()),
                                    ) {
                                        Ok(op) => op,
                                        Err(error) => {
                                            if let Some(event) = timeline.write().iter_mut().find(|e| e.id == event_id) {
                                                event.pending = false;
                                                event.failed = true;
                                                event.error = Some(format!("send failed: {error:#}"));
                                            }
                                            write_status.set(format!("send failed: {error:#}"));
                                            return;
                                        }
                                    };
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
                                let queued = send_timeline_encrypted_message(
                                    TimelineEncryptedSend {
                                        timeline,
                                        state_store,
                                        write_status,
                                        frontier_state,
                                        base_url: base_url_sig(),
                                        api_token: token(),
                                        wait_for: active_sync_token(sync_cursor()),
                                        realm: realm_for_encrypt.clone(),
                                        actor: ac.clone(),
                                        device: dc.clone(),
                                        body: body.clone(),
                                        reply_to: reply_target.clone(),
                                        thread_id: thread_id.clone(),
                                    },
                                );
                                // Honest fail-closed: keep the draft when the
                                // encrypted send could not be queued (no MLS
                                // group / seal for this Realm yet).
                                if queued {
                                    state_store.write().save_draft(realm_for_draft, "");
                                    draft.set(String::new());
                                    reply_to_index.set(None);
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
                                            let op = match message_create_operation(
                                                &realm,
                                                &actor,
                                                thread_id.as_deref(),
                                                &body_clone,
                                                Some(incident_priority_for_send.as_str()),
                                            ) {
                                                Ok(op) => op,
                                                Err(error) => {
                                                    if let Some(found) = timeline
                                                        .write()
                                                        .iter_mut()
                                                        .find(|candidate| candidate.id == local_event_id)
                                                    {
                                                        found.pending = false;
                                                        found.failed = true;
                                                        found.error = Some(format!("send failed: {error:#}"));
                                                    }
                                                    write_status.set(format!("send failed: {error:#}"));
                                                    return;
                                                }
                                            };
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
                                // YOU-02-007: report the outcome instead of
                                // silently dropping it — offline / denied
                                // submissions used to vanish without any
                                // user-visible signal.
                                let outcome = with_authed_api_with_sync(
                                    &base,
                                    api_token,
                                    wait_for,
                                    |api| async move {
                                        api.report_moderation(
                                            &realm,
                                            "local:event",
                                            "spam",
                                            &actor,
                                        )
                                        .await?;
                                        api.send_to_device(&actor, &dev).await?;
                                        Ok(())
                                    },
                                )
                                .await;
                                match outcome {
                                    Ok(()) => write_status.set("report submitted".to_owned()),
                                    Err(error) => write_status.set(format!(
                                        "report failed: {}",
                                        error.display()
                                    )),
                                }
                            });
                        }
                    },
                    "Report / Queue"
                }
            }
        }
    }
}
