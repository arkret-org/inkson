use chrono::Utc;
use dioxus::prelude::*;

use super::model::TimelineEvent;
use super::operations::sdk_payload_value;
use crate::local_state::{LocalStateStore, default_strand_id_for_realm};
use crate::operation::uuid_v7;
use crate::views::helpers::authed_api_with_sync;

/// Inputs for an encrypted Timeline send. Bundled into a struct so the
/// `onkeydown` / Send-button handlers can hand off to one shared entrypoint
/// without a 13-argument call.
pub(super) struct TimelineEncryptedSend {
    pub(super) timeline: Signal<Vec<TimelineEvent>>,
    pub(super) state_store: Signal<LocalStateStore>,
    pub(super) write_status: Signal<String>,
    pub(super) frontier_state: Signal<String>,
    pub(super) base_url: String,
    pub(super) api_token: String,
    pub(super) wait_for: Option<String>,
    pub(super) realm: String,
    pub(super) actor: String,
    pub(super) device: String,
    pub(super) body: String,
    pub(super) reply_to: Option<String>,
    pub(super) thread_id: Option<String>,
}

/// Encrypted Timeline send: drives the shared MLS pipeline
/// (`crate::views::secure_send`) the same way Chat's "Send Secure" does, then
/// renders an optimistic `TimelineEvent` and reconciles pending→ack/fail.
///
/// Honest fail-closed: when the Realm has no synced MLS group / seal (so
/// `build_secure_send` returns `Err`), this sets a clear `write_status` and
/// returns `false` WITHOUT pushing any event — no fake "encrypted …" notice,
/// no plaintext fallback. Returns `true` once the encrypted message is
/// optimistically queued (the caller then clears the composer).
pub(super) fn send_timeline_encrypted_message(input: TimelineEncryptedSend) -> bool {
    let TimelineEncryptedSend {
        mut timeline,
        state_store,
        mut write_status,
        mut frontier_state,
        base_url,
        api_token,
        wait_for,
        realm,
        actor,
        device,
        body,
        reply_to,
        thread_id,
    } = input;

    // P1: encrypt the canonical Content Block JSON (`ck.content.text`), NOT the
    // bare body bytes — matches Chat so strict receivers parse the decrypted
    // payload as `application/vnd.cokret.message+json`.
    let content_value = match sdk_payload_value(
        cokret_sdk::ContentBlock::text(&body).to_value(),
        "timeline encrypted content block serialize",
    ) {
        Ok(value) => value,
        Err(err) => {
            write_status.set(format!("encrypt failed: could not encode content: {err:#}"));
            return false;
        }
    };
    let content_bytes = match serde_json::to_vec(&content_value) {
        Ok(bytes) => bytes,
        Err(err) => {
            write_status.set(format!("encrypt failed: could not encode content: {err}"));
            return false;
        }
    };

    let strand_id = default_strand_id_for_realm(&realm);
    let message_id = format!("ck:message:{}", uuid_v7());
    let seal_view = state_store.read().seal_view_for_realm(&realm);
    let build = match crate::views::secure_send::build_secure_send(
        state_store,
        &seal_view,
        &realm,
        &actor,
        &device,
        &strand_id,
        &message_id,
        reply_to.as_deref(),
        &content_bytes,
        None,
    ) {
        Ok(build) => build,
        Err(_) => {
            // Honest fail-closed: the Realm's MLS group / seal is not available
            // on this device yet. Do not push a fake notice or fall back to
            // plaintext — surface the boundary and keep the draft.
            write_status.set(
                "encrypted send unavailable: this Realm's MLS group has not synced yet — cannot encrypt"
                    .to_owned(),
            );
            return false;
        }
    };

    // Optimistic encrypted event: body is shown live this session; on reload
    // the author-owned sidecar (saved on accept below) carries the plaintext.
    let local_event_id = message_id.clone();
    let optimistic = TimelineEvent {
        realm_id: Some(realm.clone()),
        id: local_event_id.clone(),
        message_id: Some(message_id.clone()),
        sender: actor.clone(),
        sender_display: "you".to_owned(),
        body: body.clone(),
        timestamp: Utc::now().to_rfc3339(),
        reply_to: reply_to.clone(),
        thread_id: thread_id.clone(),
        pending: true,
        encrypted_payload: Some(build.encrypted_content.clone()),
        ..TimelineEvent::default()
    };
    timeline.write().push(optimistic);
    write_status.set("encrypting…".to_owned());

    // Capture the message op id before the build moves into the submitter; the
    // optimistic event's ack records it as its `operation_id` (fact summary).
    let msg_op_id =
        crate::views::secure_send::sdk_event_local_operation_id(&build.message_event).to_owned();

    spawn(async move {
        let Ok(api) = authed_api_with_sync(&base_url, api_token.clone(), wait_for) else {
            if let Some(found) = timeline
                .write()
                .iter_mut()
                .find(|candidate| candidate.id == local_event_id)
            {
                found.pending = false;
                found.failed = true;
                found.error = Some("encrypted send failed: could not start session".to_owned());
            }
            write_status.set("encrypted send failed: could not start session".to_owned());
            return;
        };
        // Author-owned sidecar key (mirrors Chat): persist the plaintext so a
        // reload / new device can render the author's own (otherwise
        // undecryptable) encrypted message; this shares the
        // `mls_private_plaintext` map the cross-device backup snapshots.
        let sidecar_realm = realm.clone();
        let sidecar_strand = strand_id.clone();
        let sidecar_field = format!("message:{message_id}");
        let sidecar_body = body.clone();
        let mut store = state_store;
        let outcome = crate::views::secure_send::submit_secure_send(
            &api,
            state_store,
            build,
            &realm,
            &device,
            base_url.clone(),
            api_token.clone(),
            actor.clone(),
        )
        .await;
        match outcome {
            crate::views::secure_send::SecureSendOutcome::Sent { event_id, .. } => {
                store.write().save_private_plaintext(
                    &sidecar_realm,
                    &sidecar_strand,
                    &sidecar_field,
                    &sidecar_body,
                );
                if let Some(found) = timeline
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.id == local_event_id)
                {
                    found.apply_send_ack(event_id.clone(), msg_op_id.clone());
                }
                frontier_state.set(event_id);
                write_status.set("encrypted message sent".to_owned());
            }
            crate::views::secure_send::SecureSendOutcome::CommitFailed { message }
            | crate::views::secure_send::SecureSendOutcome::MessageFailed { message } => {
                if let Some(found) = timeline
                    .write()
                    .iter_mut()
                    .find(|candidate| candidate.id == local_event_id)
                {
                    found.pending = false;
                    found.failed = true;
                    found.error = Some(message.clone());
                }
                write_status.set(message);
            }
        }
    });

    true
}
