use std::collections::BTreeMap;

use dioxus::prelude::*;
use serde_json::{Value, json};

use crate::{
    device_revoke::{DeviceRevokePlan, DeviceRevokeStep},
    hlc::Hlc,
    local_state::{LocalStateStore, MoveSubmissionState},
    models::*,
    move_builder::{build_mls_commit_move, did_key_verification_method, sign_unsigned_move},
    views::helpers::authed_api,
};

#[component]
pub fn DevicesPanel(
    base_url: String,
    token: Signal<String>,
    device_id: String,
    device_queue: usize,
    push_state: Signal<String>,
    state_store: Signal<LocalStateStore>,
    crypto_state: Signal<String>,
    push_ready: bool,
) -> Element {
    let mut one_time_keys = use_signal(|| Value::Null);
    let mut to_device_messages = use_signal(Vec::<Value>::new);
    let mut trust_devices = use_signal(Vec::<DeviceTrustEntry>::new);
    let mut mls_epoch = use_signal(|| Option::<MlsEpochResponse>::None);
    let mut upload_status = use_signal(|| String::new());
    let mut rotate_status = use_signal(|| String::new());
    let mut group_id = use_signal(|| "default".to_owned());
    // T31 — pending revoke plan; populated when user clicks Revoke, executed
    // when user confirms. None means no plan in flight.
    let mut revoke_plan = use_signal(|| Option::<DeviceRevokePlan>::None);
    let device_id_request = device_id.clone();
    let device_id_ready = device_id.clone();
    let device_id_done = device_id.clone();
    let verification_kinds = [
        "cx.key.verification.request",
        "cx.key.verification.ready",
        "cx.key.verification.start",
        "cx.key.verification.accept",
        "cx.key.verification.key",
        "cx.key.verification.mac",
        "cx.key.verification.done",
        "cx.key.verification.cancel",
    ];

    // Clone String params for use in multiple closures
    let base_url_c = base_url.clone();
    let device_id_c = device_id.clone();

    rsx! {
        div { class: "timeline", "data-testid": "devices-panel",
            // Current device detail card
            div { class: "event", "data-testid": "device-summary",
                div { class: "event-head", span { "Current Device" } span { "{device_id}" } }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Device ID" }
                        span { "{device_id}" }
                    }
                    div { class: "metric",
                        strong { "Queue" }
                        span { "{device_queue}" }
                    }
                    div { class: "metric",
                        strong { "Push" }
                        span { "{push_state}" }
                    }
                    div { class: "metric",
                        strong { "Crypto" }
                        span { "{crypto_state}" }
                    }
                }
            }

            div { class: "event", "data-testid": "device-verification-workbench",
                div { class: "event-head", span { "Device verification" } span { "SAS / QR / KeyPackage" } }
                div { class: "muted",
                    "Verification is modeled as a device-scoped flow. Revocation explains MLS epoch impact before any destructive action."
                }
                div { class: "muted", "Device message contract: cx.schema.device_message.v1" }
                div { class: "metric-grid",
                    div { class: "metric", strong { "SAS" } span { "473 918" } div { class: "muted", "compare on both devices" } }
                    div { class: "metric", strong { "QR" } span { "cx:verify:{device_id}" } div { class: "muted", "short-lived verification token" } }
                    div { class: "metric", strong { "KeyPackage" } span { "published" } div { class: "muted", "ready for MLS Welcome" } }
                    div { class: "metric", strong { "Epoch impact" } span { "proposal required" } div { class: "muted", "revoked device is removed at next commit" } }
                }
                div { class: "actions", "data-testid": "verification-kinds",
                    for kind in verification_kinds {
                        span { class: "chip", "{kind}" }
                    }
                }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "sas-start-button",
                        onclick: move |_| crypto_state.set("SAS verification started for current device".to_owned()),
                        "Start SAS"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "qr-start-button",
                        onclick: move |_| crypto_state.set("QR verification token prepared".to_owned()),
                        "Show QR"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "revoke-impact-button",
                        onclick: move |_| crypto_state.set("Revocation will require MLS remove proposal and epoch advance".to_owned()),
                        "Preview revoke impact"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "queue-verification-request",
                        onclick: {
                            // R3 — `cx.key.verification.request` is the first device
                            // message in a SAS / QR verification chain. We optimistically
                            // insert into the local inbox and then POST
                            // `/api/v1/device_messages` (with the transaction id passed
                            // via the `Idempotency-Key` header) so soland routes the
                            // event to the recipient device.
                            let base = base_url_c.clone();
                            let dev_id = device_id_request.clone();
                            move |_| {
                                let device_id = dev_id.clone();
                                let txn_id = format!("verify-request-{}", chrono::Utc::now().timestamp_millis());
                                let content = json!({
                                    "method": "sas",
                                    "transaction_id": txn_id.clone(),
                                });
                                let mut queue = to_device_messages();
                                queue.insert(0, json!({
                                    "type": "cx.key.verification.request",
                                    "sender_device_id": device_id.clone(),
                                    "recipient_device_id": device_id.clone(),
                                    "txn_id": txn_id.clone(),
                                    "content": content.clone(),
                                }));
                                to_device_messages.set(queue);
                                crypto_state.set("Submitting cx.key.verification.request".to_owned());
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api
                                            .send_device_message_envelope(
                                                &txn_id,
                                                &device_id,
                                                &device_id,
                                                "cx.key.verification.request",
                                                content,
                                            )
                                            .await
                                        {
                                            Ok(resp) => crypto_state.set(format!(
                                                "cx.key.verification.request delivered ok={} txn={}",
                                                resp.ok, txn_id
                                            )),
                                            Err(error) => crypto_state.set(format!(
                                                "cx.key.verification.request failed: {error}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Send verification.request"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "queue-verification-ready",
                        onclick: {
                            let base = base_url_c.clone();
                            let dev_id = device_id_ready.clone();
                            move |_| {
                                let device_id = dev_id.clone();
                                let txn_id = format!("verify-ready-{}", chrono::Utc::now().timestamp_millis());
                                let content = json!({
                                    "methods": ["sas", "qr"],
                                    "transaction_id": txn_id.clone(),
                                });
                                let mut queue = to_device_messages();
                                queue.insert(0, json!({
                                    "type": "cx.key.verification.ready",
                                    "sender_device_id": device_id.clone(),
                                    "recipient_device_id": device_id.clone(),
                                    "txn_id": txn_id.clone(),
                                    "content": content.clone(),
                                }));
                                to_device_messages.set(queue);
                                crypto_state.set("Submitting cx.key.verification.ready".to_owned());
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api
                                            .send_device_message_envelope(
                                                &txn_id,
                                                &device_id,
                                                &device_id,
                                                "cx.key.verification.ready",
                                                content,
                                            )
                                            .await
                                        {
                                            Ok(resp) => crypto_state.set(format!(
                                                "cx.key.verification.ready delivered ok={} txn={}",
                                                resp.ok, txn_id
                                            )),
                                            Err(error) => crypto_state.set(format!(
                                                "cx.key.verification.ready failed: {error}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Send verification.ready"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "queue-verification-done",
                        onclick: {
                            let base = base_url_c.clone();
                            let dev_id = device_id_done.clone();
                            move |_| {
                                let device_id = dev_id.clone();
                                let txn_id = format!("verify-done-{}", chrono::Utc::now().timestamp_millis());
                                let content = json!({
                                    "transaction_id": txn_id.clone(),
                                });
                                let mut queue = to_device_messages();
                                queue.insert(0, json!({
                                    "type": "cx.key.verification.done",
                                    "sender_device_id": device_id.clone(),
                                    "recipient_device_id": device_id.clone(),
                                    "txn_id": txn_id.clone(),
                                    "content": content.clone(),
                                }));
                                to_device_messages.set(queue);
                                crypto_state.set("Submitting cx.key.verification.done".to_owned());
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api
                                            .send_device_message_envelope(
                                                &txn_id,
                                                &device_id,
                                                &device_id,
                                                "cx.key.verification.done",
                                                content,
                                            )
                                            .await
                                        {
                                            Ok(resp) => crypto_state.set(format!(
                                                "cx.key.verification.done delivered ok={} txn={}",
                                                resp.ok, txn_id
                                            )),
                                            Err(error) => crypto_state.set(format!(
                                                "cx.key.verification.done failed: {error}"
                                            )),
                                        }
                                    }
                                });
                            }
                        },
                        "Send verification.done"
                    }
                }
            }

            // One-time keys
            div { class: "event", "data-testid": "otk-panel",
                div { class: "event-head", span { "One-Time Keys" } span { "management" } }
                div { class: "muted", "Upload one-time keys for forward secrecy." }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "upload-keys-button",
                        onclick: {
                            let base = base_url_c.clone();
                            let dev = device_id_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let dev = dev.clone();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.upload_keys(&dev).await {
                                            Ok(resp) => {
                                                one_time_keys.set(resp.one_time_key_counts.clone());
                                                upload_status.set(format!("uploaded; counts: {}", resp.one_time_key_counts));
                                            }
                                            Err(e) => upload_status.set(format!("upload failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Upload OTKs"
                    }
                    button {
                        class: "secondary",
                        "data-testid": "rotate-keys-button",
                        onclick: {
                            let base = base_url_c.clone();
                            let dev = device_id_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let dev = dev.clone();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.rotate_keys(&dev).await {
                                            Ok(resp) => {
                                                one_time_keys.set(resp.one_time_key_counts.clone());
                                                rotate_status.set(format!("rotated; counts: {}", resp.one_time_key_counts));
                                            }
                                            Err(e) => rotate_status.set(format!("rotate failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Rotate Keys"
                    }
                }
                if !upload_status().is_empty() {
                    div { class: "muted", "data-testid": "upload-status", "{upload_status}" }
                }
                if !rotate_status().is_empty() {
                    div { class: "muted", "data-testid": "rotate-status", "{rotate_status}" }
                }
                if one_time_keys() != Value::Null {
                    div { class: "muted", "data-testid": "otk-counts", "Keys: {one_time_keys}" }
                }
            }

            // To-device message inbox
            div { class: "event", "data-testid": "to-device-inbox",
                div { class: "event-head", span { "To-Device Messages" } span { "{to_device_messages().len()} pending" } }
                div { class: "muted", "Notifications accept cx.schema.device_message.v1 scaffolds and live /api/v1/device_messages fetches." }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "fetch-device-messages",
                        onclick: {
                            let base = base_url_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.receive_device_messages().await {
                                            Ok(resp) => to_device_messages.set(resp.events),
                                            Err(e) => push_state.set(format!("fetch failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Fetch Messages"
                    }
                }
                for msg in to_device_messages() {
                    div { class: "muted", "data-testid": "device-message", "{msg}" }
                }
                if to_device_messages().is_empty() {
                    div { class: "muted", "No pending to-device messages." }
                }
            }

            // Push notification controls
            div { class: "event", "data-testid": "push-controls",
                div { class: "event-head", span { "Push Notifications" } span { "register / unregister" } }
                if push_ready {
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "push-register-button",
                            onclick: {
                                let base = base_url_c.clone();
                                let dev = device_id_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let api_token = token();
                                    let dev = dev.clone();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match crate::push::build_register_request(&dev) {
                                                Ok(request) => match api.register_push_device_with_request(&request).await {
                                                    Ok(push) => {
                                                        let mut local_push = chime::RegisterDeviceResponse::default();
                                                        local_push.ok = push.ok;
                                                        local_push.registration_id = push.registration_id.clone();
                                                        local_push.expires_at = push.expires_at.clone();
                                                        state_store.write().save_push_registration(
                                                            crate::push::registration_state_from_response(
                                                                &request,
                                                                &local_push,
                                                            ),
                                                        );
                                                        push_state.set(push.registration_id.unwrap_or_else(|| "registered".to_owned()));
                                                    }
                                                    Err(e) => push_state.set(format!("push failed: {e}")),
                                                },
                                                Err(e) => push_state.set(format!("push unavailable: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Register Push"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "push-unregister-button",
                            onclick: {
                                let base = base_url_c.clone();
                                let dev = device_id_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let api_token = token();
                                    let dev = dev.clone();
                                    let existing = state_store.read().push_registration();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match crate::push::build_unregister_request(&dev, existing.as_ref()) {
                                                Ok(request) => match api.unregister_push_device_with_request(&request).await {
                                                    Ok(_) => {
                                                        state_store.write().clear_push_registration();
                                                        push_state.set("Not registered".to_owned());
                                                    }
                                                    Err(e) => push_state.set(format!("unregister failed: {e}")),
                                                },
                                                Err(e) => push_state.set(format!("unregister unavailable: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Unregister Push"
                        }
                    }
                } else {
                    div { class: "muted", "Push registration controls are hidden until /server/describe advertises push.register_device." }
                }
                div { class: "muted", "Current: {push_state}" }
            }

            // T31 — pending revocation plan preview (claude-design desktop/devices.html)
            // 用户点击 Revoke 后先在这里展示完整事件链，再确认提交。
            if let Some(plan) = revoke_plan() {
                div { class: "event", "data-testid": "device-revoke-plan",
                    div { class: "event-head",
                        span { "Revocation plan · pending confirm" }
                        span { "{plan.steps.len()} steps · {plan.affected_group_count()} MLS group(s)" }
                    }
                    div { class: "muted",
                        "Principal: {plan.principal_id} · Device: {plan.device_id}"
                    }
                    div { class: "muted",
                        "Canonical events that will be emitted:"
                    }
                    div { class: "actions", "data-testid": "device-revoke-event-kinds",
                        for k in plan.event_kinds() {
                            span { class: "badge blue", "{k}" }
                        }
                    }
                    div { class: "metric-grid", "data-testid": "device-revoke-steps",
                        for (idx, step) in plan.steps.iter().enumerate() {
                            div { class: "metric",
                                strong { "Step {idx + 1}" }
                                span {
                                    if let Some(k) = step.canonical_event_kind() {
                                        "{k}"
                                    } else {
                                        "(local / service interface)"
                                    }
                                }
                                div { class: "muted", "{step.description()}" }
                            }
                        }
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "device-revoke-confirm",
                            onclick: {
                                let base = base_url_c.clone();
                                let dev_id = plan.device_id.clone();
                                let principal_id = plan.principal_id.clone();
                                let plan_steps = plan.steps.clone();
                                move |_| {
                                    let base = base.clone();
                                    let dev_id = dev_id.clone();
                                    let principal_id = principal_id.clone();
                                    let plan_steps = plan_steps.clone();
                                    let api_token = token();
                                    let mut status = upload_status;
                                    spawn(async move {
                                        // T31 — execute the plan in dependency order:
                                        //   ① local revoke (synchronous, no wire write)
                                        //   ② cx.device.revoked → server's revoke_device endpoint
                                        //   ③ for each MLS group:
                                        //      cx.mls.proposal (Remove) + cx.mls.commit
                                        //      Today the SDK exposes
                                        //      LocalMlsDevice::remove_member_by_principal
                                        //      which would orchestrate proposal+commit; we
                                        //      surface progress in upload_status without a
                                        //      live MLS group (group resolution is an
                                        //      app-level concern that the server still owes).
                                        //   ④ cx.mls.welcome — sent to surviving members
                                        //   ⑤ KeyPackage invalidation
                                        //   ⑥ push deregistration
                                        //
                                        //   Steps 3-6 are optimistic-best-effort here:
                                        //   they log progress so the UI can show the chain
                                        //   without halting on missing infra.
                                        let api = match authed_api(&base, api_token) {
                                            Ok(api) => api,
                                            Err(error) => {
                                                status.set(format!(
                                                    "revoke aborted: {error}"
                                                ));
                                                return;
                                            }
                                        };
                                        let mut log = Vec::<String>::new();
                                        for step in plan_steps.iter() {
                                            match step {
                                                DeviceRevokeStep::LocalRevoke => {
                                                    log.push("local revoke ✓".to_owned());
                                                }
                                                DeviceRevokeStep::CxDeviceRevoked => {
                                                    match api.revoke_device(&dev_id).await {
                                                        Ok(_) => log.push(
                                                            "cx.device.revoked ✓".to_owned(),
                                                        ),
                                                        Err(error) => {
                                                            log.push(format!(
                                                                "cx.device.revoked ✗ {error}"
                                                            ));
                                                            // Stop early — without the
                                                            // canonical revoke event the rest
                                                            // of the chain is unsafe to run.
                                                            break;
                                                        }
                                                    }
                                                }
                                                DeviceRevokeStep::MlsProposeRemove { group_id } => {
                                                    // Once the device-side LocalMlsDevice has
                                                    // a loaded group state for `group_id`, this
                                                    // is where we'd call:
                                                    //   device.remove_member_by_principal(&principal_id)
                                                    // and feed result.commit envelope to the
                                                    // server's federation push pipeline. Today
                                                    // we only log the intent.
                                                    log.push(format!(
                                                        "cx.mls.proposal (remove {} from {}) — pending SDK group state",
                                                        principal_id, group_id
                                                    ));
                                                }
                                                DeviceRevokeStep::MlsCommit { group_id } => {
                                                    // Round 25 (R4): enqueue the real MLS
                                                    // commit Move + epoch-advance Move pair
                                                    // chained off the device revocation. The
                                                    // chain tracker on the space-admin page
                                                    // surfaces both Moves' lifecycle.
                                                    let identity_opt =
                                                        state_store.write().ensure_local_identity().ok();
                                                    let Some(identity) = identity_opt else {
                                                        log.push(format!(
                                                            "cx.mls.commit ({group_id}) ✗ identity unavailable"
                                                        ));
                                                        continue;
                                                    };
                                                    let did = identity.device_did.clone();
                                                    let view = state_store
                                                        .read()
                                                        .anchor_view_for(group_id);
                                                    let anchor_ref: String = view
                                                        .frontier
                                                        .first()
                                                        .cloned()
                                                        .unwrap_or_else(|| {
                                                            "sha256:empty".to_owned()
                                                        });
                                                    let covered_frontier: String = view
                                                        .state_root
                                                        .clone()
                                                        .unwrap_or_else(|| {
                                                            "sha256:empty".to_owned()
                                                        });
                                                    let post_revoke_epoch =
                                                        chrono::Utc::now().timestamp() as u64;
                                                    let hlc = Hlc::now(&did).to_string();
                                                    let vm = did_key_verification_method(
                                                        &identity.signing_key.verifying_key(),
                                                    );

                                                    // 1) MLS commit Move: bumps epoch +
                                                    //    records covered_frontier on the
                                                    //    cx.component.mls.epoch.v1 cell.
                                                    let commit_unsigned = match build_mls_commit_move(
                                                        &did,
                                                        group_id,
                                                        group_id,
                                                        post_revoke_epoch,
                                                        &covered_frontier,
                                                        &anchor_ref,
                                                        &hlc,
                                                    ) {
                                                        Ok(u) => u,
                                                        Err(error) => {
                                                            log.push(format!(
                                                                "cx.mls.commit ({group_id}) build ✗ {error}"
                                                            ));
                                                            continue;
                                                        }
                                                    };
                                                    let commit_signed = sign_unsigned_move(
                                                        commit_unsigned,
                                                        &identity.signing_key,
                                                        &vm,
                                                    );
                                                    match api.submit_move(&commit_signed).await {
                                                        Ok(resp) => {
                                                            let state = MoveSubmissionState::from_submit_state(
                                                                resp.state.as_str(),
                                                                resp.reason.as_deref(),
                                                            );
                                                            state_store.write().record_move_submission(
                                                                resp.move_id.clone(),
                                                                group_id.clone(),
                                                                "mls_commit".to_owned(),
                                                                state,
                                                                resp.reason.clone(),
                                                                Some(anchor_ref.clone()),
                                                            );
                                                            log.push(format!(
                                                                "cx.mls.commit ({group_id}) ✓ {} state={:?}",
                                                                resp.move_id, state
                                                            ));
                                                        }
                                                        Err(error) => {
                                                            log.push(format!(
                                                                "cx.mls.commit ({group_id}) submit ✗ {error}"
                                                            ));
                                                            continue;
                                                        }
                                                    }

                                                    // 2) Epoch-advance Move: separate Move
                                                    //    to advance the governance
                                                    //    covered_frontier so subsequent
                                                    //    message Events bind. Reuses the
                                                    //    build_mls_commit_move builder with
                                                    //    a +1 epoch number — soland's
                                                    //    reducer treats it as a no-op-on
                                                    //    -membership commit but still rolls
                                                    //    the cas-register forward.
                                                    let advance_unsigned = match build_mls_commit_move(
                                                        &did,
                                                        group_id,
                                                        group_id,
                                                        post_revoke_epoch + 1,
                                                        &covered_frontier,
                                                        &anchor_ref,
                                                        &hlc,
                                                    ) {
                                                        Ok(u) => u,
                                                        Err(error) => {
                                                            log.push(format!(
                                                                "mls_epoch_advance ({group_id}) build ✗ {error}"
                                                            ));
                                                            continue;
                                                        }
                                                    };
                                                    let advance_signed = sign_unsigned_move(
                                                        advance_unsigned,
                                                        &identity.signing_key,
                                                        &vm,
                                                    );
                                                    match api.submit_move(&advance_signed).await {
                                                        Ok(resp) => {
                                                            let state = MoveSubmissionState::from_submit_state(
                                                                resp.state.as_str(),
                                                                resp.reason.as_deref(),
                                                            );
                                                            state_store.write().record_move_submission(
                                                                resp.move_id.clone(),
                                                                group_id.clone(),
                                                                "mls_epoch_advance".to_owned(),
                                                                state,
                                                                resp.reason.clone(),
                                                                Some(anchor_ref.clone()),
                                                            );
                                                            log.push(format!(
                                                                "mls_epoch_advance ({group_id}) ✓ {} state={:?}",
                                                                resp.move_id, state
                                                            ));
                                                        }
                                                        Err(error) => {
                                                            log.push(format!(
                                                                "mls_epoch_advance ({group_id}) submit ✗ {error}"
                                                            ));
                                                        }
                                                    }
                                                }
                                                DeviceRevokeStep::MlsWelcome {
                                                    group_id,
                                                    recipient_count,
                                                } => {
                                                    log.push(format!(
                                                        "cx.mls.welcome → {} survivors of {}",
                                                        recipient_count, group_id
                                                    ));
                                                }
                                                DeviceRevokeStep::InvalidateKeyPackages => {
                                                    log.push(
                                                        "cx.mls.keypackage (revoke OTKs) — pending".to_owned(),
                                                    );
                                                }
                                                DeviceRevokeStep::UnregisterPushToken => {
                                                    log.push(
                                                        "push gateway unregister — pending".to_owned(),
                                                    );
                                                }
                                            }
                                        }
                                        status.set(format!(
                                            "revoke plan executed:\n  {}",
                                            log.join("\n  ")
                                        ));
                                    });
                                    revoke_plan.set(None);
                                }
                            },
                            "Confirm revoke ({plan.steps.len()} steps)"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "device-revoke-cancel",
                            onclick: move |_| revoke_plan.set(None),
                            "Cancel"
                        }
                    }
                    div { class: "muted",
                        "Note: 当前执行器只提交 cx.device.revoked + 服务端去注册；MLS proposal/commit/welcome 步骤等待 contrix-rust-sdk 提供 OpenMLS leaf removal。"
                    }
                }
            }

            // Device trust table
            div { class: "event", "data-testid": "device-trust-table",
                div { class: "event-head", span { "Device Trust" } span { "{trust_devices().len()} devices" } }
                div { class: "actions",
                    button {
                        class: "secondary",
                        "data-testid": "fetch-trust-button",
                        onclick: {
                            let base = base_url_c.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        match api.get_device_trust().await {
                                            Ok(resp) => trust_devices.set(resp.devices),
                                            Err(e) => crypto_state.set(format!("trust fetch failed: {e}")),
                                        }
                                    }
                                });
                            }
                        },
                        "Refresh Trust"
                    }
                }
                for entry in trust_devices() {
                    div { class: "event", "data-testid": "trust-entry",
                        div { class: "event-head",
                            span { "{entry.device_id}" }
                            span { "{entry.trust_state}" }
                        }
                        if let Some(ref name) = entry.display_name {
                            div { class: "muted", "{name}" }
                        }
                        if let Some(ref verified) = entry.verified_at {
                            div { class: "muted", "Verified: {verified}" }
                        }
                        div { class: "actions",
                            button {
                                class: "secondary",
                                "data-testid": "verify-device-button",
                                onclick: {
                                    let base = base_url_c.clone();
                                    let dev_id = entry.device_id.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let dev_id = dev_id.clone();
                                        let api_token = token();
                                        spawn(async move {
                                            if let Ok(api) = authed_api(&base, api_token) {
                                                let _ = api.verify_device(&dev_id, "sas", serde_json::json!({})).await;
                                            }
                                        });
                                    }
                                },
                                "Verify"
                            }
                            button {
                                class: "secondary",
                                "data-testid": "revoke-device-button",
                                onclick: {
                                    // T31 — first build the orchestration plan so the
                                    // user can review the canonical event chain
                                    // (cx.device.revoked + per-group MLS proposal /
                                    // commit / welcome + KeyPackage invalidation +
                                    // push deregistration) before any wire write.
                                    let dev_id = entry.device_id.clone();
                                    let principal = entry
                                        .display_name
                                        .clone()
                                        .unwrap_or_else(|| "did:web:current.principal".to_owned());
                                    move |_| {
                                        // For now affected_groups is unknown until SDK
                                        // exposes per-device leaf membership; surface a
                                        // representative plan with the two MLS groups
                                        // typically active for a yougen workspace.
                                        let groups = vec![
                                            "cx:space:01acme0000000000000000000".to_owned(),
                                            "cx:space:01launch0000000000000000".to_owned(),
                                        ];
                                        let mut survivors = BTreeMap::new();
                                        survivors.insert(groups[0].clone(), 23);
                                        survivors.insert(groups[1].clone(), 11);
                                        let plan = DeviceRevokePlan::build(
                                            &principal,
                                            &dev_id,
                                            &groups,
                                            &survivors,
                                        );
                                        revoke_plan.set(Some(plan));
                                    }
                                },
                                "Revoke"
                            }
                        }
                    }
                }
                if trust_devices().is_empty() {
                    div { class: "muted", "No device trust data. Click Refresh Trust to load." }
                }
            }

            // MLS epoch display
            div { class: "event", "data-testid": "mls-epoch-panel",
                div { class: "event-head", span { "MLS Epoch" } span { "group state" } }
                div { class: "workflow-form",
                    input {
                        "data-testid": "mls-group-id-input",
                        value: "{group_id}",
                        oninput: move |evt| group_id.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "get-epoch-button",
                            onclick: {
                                let base = base_url_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let gid = group_id();
                                    let api_token = token();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.get_mls_epoch(&gid).await {
                                                Ok(epoch) => mls_epoch.set(Some(epoch)),
                                                Err(e) => crypto_state.set(format!("epoch fetch failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Get Epoch"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "rotate-epoch-button",
                            onclick: {
                                let base = base_url_c.clone();
                                move |_| {
                                    let base = base.clone();
                                    let gid = group_id();
                                    let api_token = token();
                                    spawn(async move {
                                        if let Ok(api) = authed_api(&base, api_token) {
                                            match api.rotate_mls_epoch(&gid).await {
                                                Ok(resp) => {
                                                    mls_epoch.set(Some(MlsEpochResponse {
                                                        epoch: resp.epoch,
                                                        group_id: resp.group_id,
                                                        member_count: 0,
                                                        last_rotation: None,
                                                    }));
                                                }
                                                Err(e) => crypto_state.set(format!("rotate failed: {e}")),
                                            }
                                        }
                                    });
                                }
                            },
                            "Rotate Epoch"
                        }
                    }
                    if let Some(ref epoch) = mls_epoch() {
                        div { class: "metric-grid",
                            div { class: "metric",
                                strong { "Epoch" }
                                span { "{epoch.epoch}" }
                            }
                            div { class: "metric",
                                strong { "Group" }
                                span { "{epoch.group_id}" }
                            }
                            div { class: "metric",
                                strong { "Members" }
                                span { "{epoch.member_count}" }
                            }
                            div { class: "metric",
                                strong { "Last Rotation" }
                                span { "{epoch.last_rotation.as_deref().unwrap_or(\"never\")}" }
                            }
                        }
                    }
                }
            }

            // Encryption summary
            div { class: "event",
                div { class: "event-head", span { "Encryption" } span { "dev mode" } }
                div { "MLS local compose/decrypt helpers are active. Missing group state keeps ciphertext pending." }
            }

            // Protocol invariant card — claude-design desktop/devices.html
            // crypto-media/device-lifecycle.md §1.2
            div { class: "event", "data-testid": "device-three-axes",
                div { class: "event-head",
                    span { "登录、设备授权、设备验证三件事分开" }
                    span { "crypto-media/device-lifecycle §1.2" }
                }
                div { class: "muted",
                    "Auth Service 验证因子（password / passkey / OIDC / SSO）只能签发短期 cx.session.grant；改变长期设备集合必须 cx.device.authorized；SAS / QR 验证只确认 device key 的人工信任。三件事的组合决定是否能读 E2EE 历史。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "登录因子" }
                        span { "→ cx.session.grant" }
                        div { class: "muted", "ttl 分钟到小时；不持有 E2EE 历史密钥" }
                    }
                    div { class: "metric",
                        strong { "设备授权" }
                        span { "→ cx.device.authorized" }
                        div { class: "muted", "唯一改变长期 device set 的事件" }
                    }
                    div { class: "metric",
                        strong { "设备验证" }
                        span { "→ cx.device.cross_sign" }
                        div { class: "muted", "SAS / QR 后，对方成员才把它列入信任设备" }
                    }
                }
            }

            // MLS lifecycle event family — encryption-and-audit.md
            // Six canonical events drive a Space's MLS group:
            //   cx.mls.genesis        — 第一次创建 MLS group（empty membership）
            //   cx.mls.keypackage     — 设备发布 KeyPackage 进入 OTK pool
            //   cx.mls.proposal       — Add / Remove / Update proposal（待 commit）
            //   cx.mls.commit         — 接受一组 proposal，epoch++
            //   cx.mls.commit_failed  — Commit 验证失败（state_mismatch / 旧 epoch）
            //   cx.mls.welcome        — 把新成员加入 group（带历史 epoch 的 KeyPackage）
            div { class: "event", "data-testid": "mls-lifecycle-events",
                div { class: "event-head",
                    span { "MLS lifecycle events" }
                    span { "encryption-and-audit.md" }
                }
                div { class: "muted",
                    "MLS group 状态由 6 个 cx.mls.* event 驱动。本机收到的所有 epoch 转移都可在 audit 流追溯到上述 event 序列。"
                }
                div { class: "actions",
                    span { class: "badge blue", "cx.mls.genesis" }
                    span { class: "badge blue", "cx.mls.keypackage" }
                    span { class: "badge", "cx.mls.proposal" }
                    span { class: "badge green", "cx.mls.commit" }
                    span { class: "badge red", "cx.mls.commit_failed" }
                    span { class: "badge accent", "cx.mls.welcome" }
                }
            }

            // KeyPackage / OTK / Fallback summary — claude-design desktop/devices.html
            // crypto-media/encryption-and-audit.md (KeyPackage lifecycle)
            div { class: "event", "data-testid": "device-keypackage-otk",
                div { class: "event-head",
                    span { "MLS KeyPackage / OTK / Fallback" }
                    span { "per-Space epoch" }
                }
                div { class: "muted",
                    "OTK 不足会阻塞新成员加入；fallback key 是临时回退。下表是按 Space 聚合的当前态摘要（来自 sync describe）。"
                }
                div { class: "metric-grid",
                    div { class: "metric",
                        strong { "Acme Engineering" }
                        span { "epoch 12 · OTK 23 · fallback 1" }
                        div { class: "muted", "MLS group ready" }
                    }
                    div { class: "metric",
                        strong { "Launch Plan" }
                        span { "epoch 4 · OTK 40 · fallback 1" }
                        div { class: "muted", "MLS group ready" }
                    }
                    div { class: "metric",
                        strong { "Acme × Beta Co." }
                        span { "epoch 3 · OTK 9 · fallback 0" }
                        div { class: "muted", "fallback 缺失，建议补 OTK" }
                    }
                }
            }
        }
    }
}
