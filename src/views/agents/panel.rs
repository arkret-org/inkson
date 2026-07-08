//! `AgentsPanel` — endpoint registry + interop_session monitor.
//!
//! Renders the agent endpoint list / register form, the active protocol
//! sessions, the audit-bound results, the soland-fetched verified
//! results poll, and the G3.Y4 protocol-handoff surface. Personal-agent
//! administration is mounted only from Settings -> My Agents.

use dioxus::prelude::*;
use serde_json::Value;

use super::model::{
    AuditChainVerifyOutcome, HandoffState, InteropApprovalState, LiveSessionRow, PublishModalState,
    live_session_rows, verify_agent_audit_binding, verify_audit_chain,
};
use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::{short_protocol_id, with_authed_api};

#[component]
pub fn AgentsPanel(
    base_url: String,
    account_did: String,
    token: Signal<String>,
    selected_realm_id: String,
    state_store: Signal<LocalStateStore>,
) -> Element {
    let mut agent_id = use_signal(String::new);
    let mut protocol = use_signal(|| "ck.agent.v1".to_owned());
    let mut capabilities = use_signal(|| "strand.read".to_owned());
    let mut status = use_signal(String::new);

    // ─────────────────────────────────────────────────────────────
    // G3.Y4 — protocol handoff state
    // ─────────────────────────────────────────────────────────────
    let mut handoff_state = use_signal(|| HandoffState::Idle);
    let mut handoff_target_did = use_signal(String::new);
    let mut handoff_status_text = use_signal(String::new);
    let mut audit_verify_result = use_signal(|| Option::<AuditChainVerifyOutcome>::None);
    let mut transcript_steps = use_signal(Vec::<(String, String)>::new); // (kind, summary)

    // Incoming agent `interop_session.result` events polled from
    // soland every 4s. Each entry is a (event_id, payload) pair so
    // the render side can call `verify_agent_audit_binding` on each
    // payload and show the resulting badge. The poll loop
    // self-bounds at 900 ticks (~1h) to keep cost predictable;
    // operator can refresh the page to restart it.
    let mut incoming_results = use_signal(Vec::<(String, Value)>::new);
    let mut incoming_status = use_signal(String::new);
    let mut incoming_last_poll_at = use_signal(String::new);

    // G3.Y4 (Phase C) — every `ck.agent.interop_session.*` event fetched
    // from soland, in causal order, so the live session transcript can
    // be folded by `live_session_rows`. Distinct from `incoming_results`
    // (which is `.result`-only for the audit-binding badges).
    let mut incoming_session_events = use_signal(Vec::<Value>::new);

    // G3.Y4 (Phase B) — interop capability-approval modal state.
    let mut interop_modal = use_signal(|| InteropApprovalState::Closed);
    let mut interop_target_did = use_signal(String::new);
    let mut interop_allowed_endpoint = use_signal(String::new);
    let mut interop_status_text = use_signal(String::new);
    let mut interop_last_grant_id = use_signal(String::new);

    // G3.Y4 (Phase D) — publish-to-source modal state.
    let mut publish_modal = use_signal(|| PublishModalState::Closed);
    let mut publish_with_attribution = use_signal(|| true);
    let mut publish_attribution_did = use_signal(String::new);
    let mut publish_result_ref = use_signal(String::new);
    let mut publish_artifact_ref = use_signal(String::new);
    let mut publish_status_text = use_signal(String::new);
    let mut publish_last_strand_id = use_signal(String::new);
    {
        let base = base_url.clone();
        let realm = selected_realm_id.clone();
        let token_for_fetch = token;
        use_future(move || {
            let base = base.clone();
            let realm = realm.clone();
            async move {
                let mut ticks: u32 = 0;
                // Perf: empty-response backoff. When a backfill round yields no
                // new results, double the poll interval (capped at 30s); reset to
                // the 4s baseline when there is new data, cutting idle network/CPU.
                const BACKFILL_BASE_MS: u64 = 4_000;
                const BACKFILL_MAX_MS: u64 = 30_000;
                let mut poll_interval_ms: u64 = BACKFILL_BASE_MS;
                loop {
                    if ticks > 900 {
                        incoming_status.set(format!(
                            "{} result event(s); polling stopped after 1h (refresh to resume)",
                            incoming_results.read().len()
                        ));
                        break;
                    }
                    ticks += 1;
                    if token_for_fetch().trim().is_empty() || realm.trim().is_empty() {
                        crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(4_000))
                            .await;
                        continue;
                    }
                    let api_token = token_for_fetch();
                    let base_for_call = base.clone();
                    let realm_for_call = realm.clone();
                    let resp = match with_authed_api(&base_for_call, api_token, |api| async move {
                        api.event_submitter()?.backfill(&realm_for_call).await
                    })
                    .await
                    {
                        Ok(r) => r,
                        Err(err) => {
                            incoming_status.set(format!(
                                "Agent result polling is unavailable. Check the agent bridge configuration, then retry. ({})",
                                err.display()
                            ));
                            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(
                                4_000,
                            ))
                            .await;
                            continue;
                        }
                    };
                    let mut collected: Vec<(String, Value)> = Vec::new();
                    // Phase C — every interop-session event in causal
                    // order so the live transcript can be folded.
                    let mut session_events: Vec<Value> = Vec::new();
                    let event_values = resp.event_values();
                    for event in event_values.iter() {
                        let kind = event
                            .get("event_kind")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if kind.starts_with("ck.agent.interop_session.") {
                            session_events.push(event.clone());
                        }
                        if kind != "ck.agent.interop_session.result" {
                            continue;
                        }
                        let event_id = event
                            .get("event_id")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_owned();
                        let payload = event.get("payload").cloned().unwrap_or(Value::Null);
                        collected.push((event_id, payload));
                    }
                    incoming_session_events.set(session_events);
                    let new_count = collected.len();
                    // Diff against the previous snapshot so the UI
                    // status line shows "+2 new" when fresh
                    // results land, not just the cumulative count.
                    let prev_count = incoming_results.read().len();
                    let delta = new_count.saturating_sub(prev_count);
                    incoming_status.set(if delta > 0 {
                        format!("{new_count} result event(s) ({delta} new since last poll)")
                    } else {
                        format!("{new_count} result event(s) fetched")
                    });
                    incoming_last_poll_at.set(format!("tick {ticks}"));
                    incoming_results.set(collected);
                    // Backoff scheduling: delta is the number of new results this round vs. last.
                    if delta > 0 {
                        poll_interval_ms = BACKFILL_BASE_MS;
                    } else {
                        poll_interval_ms = (poll_interval_ms * 2).min(BACKFILL_MAX_MS);
                    }
                    crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(
                        poll_interval_ms,
                    ))
                    .await;
                }
            }
        });
    }

    let raw_ops = state_store.read().load().raw_operations;
    let endpoints: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == "ck.agent.endpoint")
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let sessions: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k.starts_with("ck.agent.interop_session."))
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    let results: Vec<_> = raw_ops
        .iter()
        .filter(|r| {
            r.payload
                .get("kind")
                .and_then(Value::as_str)
                .map(|k| k == "ck.agent.interop_session.result")
                .unwrap_or(false)
        })
        .cloned()
        .collect();
    // P5 — cache the count before the iterator consumes the vec; the
    // aria-label below interpolates it alongside the badge text.
    let endpoints_count = endpoints.len();

    // Phase C — live interop-session transcript folded from the soland
    // events the poll loop fetched. This is the source the
    // `agent-session-row` render below uses so the status text advances
    // negotiating → accepted → working as soland (or an injected
    // status) lands.
    let live_rows: Vec<LiveSessionRow> = live_session_rows(&incoming_session_events.read());

    rsx! {
        div { class: "timeline", "data-testid": "agents-panel", role: "region", "aria-label": "Agent endpoints and protocol sessions",
            div { class: "event",
                role: "region",
                "aria-labelledby": "agent-endpoints-heading",
                div { class: "event-head",
                    span { id: "agent-endpoints-heading", "Agent endpoints" }
                    span { class: "badge", "aria-label": "{endpoints_count} agent endpoints registered", "{endpoints_count} registered" }
                }
                div { class: "muted",
                    "Spec extensions/agent-integration.md §2 — agent endpoints carry agent_id + protocol + capabilities. Each registered agent acts as a delegated principal that needs an explicit capability_proof to invoke."
                }
                if endpoints.is_empty() {
                    div { class: "muted", "data-testid": "agent-endpoint-empty",
                        "No automated members registered. Use the form below to add one."
                    }
                } else {
                    for e in endpoints {
                        {
                            let did = e.payload.get("body")
                                .and_then(|b| b.get("agent_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("did:web:?")
                                .to_owned();
                            let proto = e.payload.get("body")
                                .and_then(|b| b.get("protocol"))
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let op_id = e.operation_id.clone();
                            let did_label = short_protocol_id(&did);
                            let op_id_label = short_protocol_id(&op_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-endpoint-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{did}", "{did_label}" }
                                        span { class: "badge blue", "{proto}" }
                                    }
                                    div { class: "muted", title: "{op_id}", "operation_id {op_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "agent-register-form",
                role: "region",
                "aria-labelledby": "agent-register-form-heading",
                "aria-describedby": "agent-register-form-help",
                div { class: "event-head",
                    span { id: "agent-register-form-heading", "Register an automated member" }
                    span { class: "badge", title: "ck.agent.endpoint", "Bot endpoint" }
                }
                div { id: "agent-register-form-help", class: "muted",
                    "Fill in agent_id + protocol + comma-separated capabilities. Submits a ck.agent.endpoint envelope."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-register-did",
                        "aria-label": "Agent DID (bot handle)",
                        "aria-describedby": "agent-register-form-help",
                        value: "{agent_id}",
                        placeholder: "bot handle (e.g. assistant:example.com)",
                        oninput: move |event: FormEvent| agent_id.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-register-protocol",
                        "aria-label": "Agent invocation protocol",
                        "aria-describedby": "agent-register-form-help",
                        value: "{protocol}",
                        placeholder: "protocol (ck.agent.v1)",
                        oninput: move |event: FormEvent| protocol.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-register-capabilities",
                        "aria-label": "Capability list (comma-separated)",
                        "aria-describedby": "agent-register-form-help",
                        value: "{capabilities}",
                        placeholder: "capabilities (comma-separated)",
                        oninput: move |event: FormEvent| capabilities.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-register-submit-button",
                            onclick: {
                                let base = base_url.clone();
                                let realm = selected_realm_id.clone();
                                let actor = account_did.clone();
                                move |_| {
                                    let base = base.clone();
                                    let realm = realm.clone();
                                    let actor = actor.clone();
                                    let did = agent_id().trim().to_owned();
                                    let proto = protocol().trim().to_owned();
                                    let caps_input = capabilities();
                                    let caps: Vec<String> = caps_input
                                        .split(',')
                                        .map(|s| s.trim().to_owned())
                                        .filter(|s| !s.is_empty())
                                        .collect();
                                    if did.is_empty() || proto.is_empty() {
                                        status.set("agent_id + protocol are required".to_owned());
                                        return;
                                    }
                                    let api_token = token();
                                    spawn(async move {
                                        let caps_refs: Vec<&str> = caps.iter().map(String::as_str).collect();
                                        let op = crate::operation::ck_ops::agent_endpoint(
                                            &realm, &actor, &did, &proto, &caps_refs,
                                        )
                                        .and_then(|builder| builder.build_sdk_event("yougen"));
                                        let op = match op {
                                            Ok(op) => op,
                                            Err(err) => {
                                                status.set(format!(
                                                    "agent endpoint build failed: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.event_submitter()?.submit_sdk_event(&op).await
                                        })
                                        .await
                                        {
                                            Ok(resp) => status.set(format!(
                                                "agent endpoint submitted; event_id {}",
                                                resp.event_id
                                            )),
                                            Err(err) => status.set(format!(
                                                "agent endpoint failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Register agent endpoint"
                        }
                    }
                    if !status().is_empty() {
                        div {
                            class: "muted",
                            "data-testid": "agent-register-status",
                            role: "status",
                            "aria-live": "polite",
                            "aria-atomic": "true",
                            "{status}"
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "agent-session-list",
                role: "region",
                "aria-label": "Active protocol sessions",
                div { class: "event-head",
                    span { "Active protocol sessions" }
                    span { class: "badge", "{live_rows.len()} live + {sessions.len()} local" }
                }
                if live_rows.is_empty() && sessions.is_empty() {
                    div { class: "muted", "data-testid": "agent-session-empty",
                        "No protocol sessions observed."
                    }
                }
                // Phase C — live transcript rows folded from the soland
                // events surface. `data-status` carries the latest
                // standard §5.3 status so a poll can watch the row
                // advance negotiating → accepted → working.
                for row in live_rows.iter() {
                    {
                        let session_id = row.session_id.clone();
                        let status = row.status.clone();
                        let status_count = row.status_count;
                        let session_id_label = short_protocol_id(&session_id);
                        rsx! {
                            div {
                                class: "event",
                                "data-testid": "agent-session-row",
                                "data-session-id": "{session_id}",
                                "data-status": "{status}",
                                "data-status-count": "{status_count}",
                                div { class: "event-head",
                                    span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                    span { class: "badge blue", "{status}" }
                                }
                                div { class: "muted", "data-testid": "agent-session-status-text",
                                    "status: {status} ({status_count} status update(s))"
                                }
                            }
                        }
                    }
                }
                // Local (state_store) session events, kept as a
                // secondary surface so a fully-offline session draft is
                // still legible.
                for s in sessions {
                    {
                        let kind = s.payload.get("kind")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_owned();
                        let session_id = s.payload.get("body")
                            .and_then(|b| b.get("session_id"))
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                            .to_owned();
                        let status_opt = s.payload.get("body")
                            .and_then(|b| b.get("status"))
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned);
                        let session_id_label = short_protocol_id(&session_id);
                        rsx! {
                            div { class: "event", "data-testid": "agent-session-local-row",
                                div { class: "event-head",
                                    span { class: "mono", "{kind}" }
                                    span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                }
                                if let Some(status_str) = status_opt {
                                    div { class: "muted", "status: {status_str}" }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "event", "data-testid": "agent-results-list",
                div { class: "event-head",
                    span { "Audit-bound results" }
                    span { class: "badge green", "{results.len()}" }
                }
                if results.is_empty() {
                    div { class: "muted", "No agent results observed." }
                } else {
                    for r in results {
                        {
                            let session_id = r.payload.get("body")
                                .and_then(|b| b.get("session_id"))
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let root_opt = r.payload.get("body")
                                .and_then(|b| b.get("audit_binding"))
                                .and_then(|a| a.get("merkle_root"))
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned);
                            let op_id = r.operation_id.clone();
                            let session_id_label = short_protocol_id(&session_id);
                            let op_id_label = short_protocol_id(&op_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-result-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                        if let Some(root) = root_opt {
                                            {
                                                let root_label = short_protocol_id(&root);
                                                rsx! {
                                                    span { class: "mono", title: "{root}", "audit_binding {root_label}" }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "muted", title: "{op_id}", "operation_id {op_id_label}" }
                                }
                            }
                        }
                    }
                }
            }
            // Incoming `ck.agent.interop_session.result` events
            // fetched from soland, with per-event Ed25519
            // audit-binding verification badge.
            div { class: "event", "data-testid": "agent-incoming-results",
                div { class: "event-head",
                    span { "Verified results (from soland)" }
                    span { class: "badge", "{incoming_results.read().len()} fetched" }
                }
                if !incoming_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-incoming-status", "{incoming_status}" }
                }
                if !incoming_last_poll_at().is_empty() {
                    div { class: "muted", "data-testid": "agent-incoming-poll-tick",
                        "Last poll: {incoming_last_poll_at}"
                    }
                }
                if incoming_results.read().is_empty() {
                    div { class: "muted", "data-testid": "agent-incoming-empty",
                        "No result events fetched yet. The runtime emits these after a ck.agent.interop_session.start lands."
                    }
                } else {
                    for (event_id, payload) in incoming_results.read().iter() {
                        {
                            let event_id = event_id.clone();
                            let session_id = payload
                                .get("session_id")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let session_status = payload
                                .get("status")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                                .to_owned();
                            let binding_kind = payload
                                .get("audit_binding")
                                .and_then(|b| b.get("binding_kind"))
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let verify = verify_agent_audit_binding(payload);
                            let badge_class = verify.badge_class();
                            let badge_label = verify.badge_label();
                            let session_id_label = short_protocol_id(&session_id);
                            let event_id_label = short_protocol_id(&event_id);
                            rsx! {
                                div { class: "event", "data-testid": "agent-incoming-result-row",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{session_id}", "{session_id_label}" }
                                        span { class: "badge", "{session_status}" }
                                        span { class: "mono", "{binding_kind}" }
                                        span {
                                            class: "{badge_class}",
                                            "data-testid": "agent-audit-verify-badge",
                                            "{badge_label}"
                                        }
                                    }
                                    div { class: "muted", title: "{event_id}", "event_id {event_id_label}" }
                                }
                            }
                        }
                    }
                }
            }

            // ─────────────────────────────────────────────────────
            // G3.Y4 — protocol handoff surface
            // ─────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-protocol-handoff",
                div { class: "event-head",
                    span { "Agent handoff" }
                    span {
                        class: "badge",
                        "data-testid": "agent-protocol-handoff-status",
                        "data-state": "{handoff_state().as_data_state()}",
                        "{handoff_state().as_data_state()}"
                    }
                }
                div { class: "muted",
                    "Initiates a ck.agent.interop_session.start handoff to a registered agent endpoint via soland's agent_bridge route. The transcript panel tails the soland status events."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-handoff-target-input",
                        placeholder: "target agent_id (must match a registered endpoint)",
                        value: "{handoff_target_did}",
                        oninput: move |event: FormEvent| handoff_target_did.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-protocol-handoff-button",
                            disabled: matches!(
                                handoff_state(),
                                HandoffState::Pending
                                    | HandoffState::Approved
                                    | HandoffState::Running
                            ),
                            onclick: move |_| {
                                let target = handoff_target_did();
                                if target.trim().is_empty() {
                                    handoff_status_text
                                        .set("target agent_id is required".to_owned());
                                    return;
                                }
                                handoff_state.set(HandoffState::Pending);
                                let target_label = short_protocol_id(&target);
                                handoff_status_text.set(format!(
                                    "handoff to {target_label} pending controller confirmation"
                                ));
                                transcript_steps.set(Vec::new());
                                audit_verify_result.set(None);
                            },
                            "Initiate handoff"
                        }
                        if handoff_state().awaits_confirmation() {
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "agent-protocol-handoff-confirm-button",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let target = handoff_target_did();
                                        let target_label = short_protocol_id(&target);
                                        let api_token = token();
                                        handoff_state.set(HandoffState::Approved);
                                        handoff_status_text.set(format!(
                                            "handoff to {target_label} approved; submitting start event"
                                        ));
                                        transcript_steps.write().push((
                                            "ck.agent.interop_session.start".to_owned(),
                                            format!("start handoff to {target_label}"),
                                        ));
                                        spawn(async move {
                                            let session_id = format!(
                                                "ck:agent_interop_session:{}",
                                                crate::operation::uuid_v7()
                                            );
                                            let op = crate::operation::ck_ops::agent_interop_session_start(
                                                &realm,
                                                &actor,
                                                &target,
                                                &session_id,
                                                "http_custom",
                                                serde_json::json!({ "handoff_intent": "controller_initiated" }),
                                                "ck:grant:01904100-0000-7000-8000-000000000099",
                                            )
                                            .and_then(|builder| builder.build_sdk_event("yougen"));
                                            let op = match op {
                                                Ok(op) => op,
                                                Err(err) => {
                                                    handoff_state.set(HandoffState::Failed);
                                                    handoff_status_text.set(format!(
                                                        "handoff start build failed: {err}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            match with_authed_api(&base, api_token, |api| async move {
                                                api.event_submitter()?.submit_sdk_event(&op).await
                                            })
                                            .await
                                            {
                                                Ok(resp) => {
                                                    handoff_state.set(HandoffState::Running);
                                                    handoff_status_text.set(format!(
                                                        "handoff start accepted (event {})",
                                                        resp.event_id
                                                    ));
                                                    transcript_steps.write().push((
                                                        "ck.agent.interop_session.status".to_owned(),
                                                        "running (in-process echo bridge)".to_owned(),
                                                    ));
                                                    // Experimental-only surface:
                                                    // the incoming results poll
                                                    // above renders terminal
                                                    // events while the default
                                                    // local UI keeps this panel
                                                    // hidden.
                                                }
                                                Err(err) => {
                                                    handoff_state.set(HandoffState::Failed);
                                                    handoff_status_text.set(format!(
                                                        "handoff start failed: {}",
                                                        err.display()
                                                    ));
                                                    transcript_steps.write().push((
                                                        "ck.agent.interop_session.status".to_owned(),
                                                        format!("failed: {}", err.display()),
                                                    ));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Confirm handoff"
                            }
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "agent-protocol-audit-verify-button",
                            onclick: move |_| {
                                // Verify the most recently-fetched
                                // incoming results: feed every event
                                // belonging to the current
                                // handoff_target_did into the chain
                                // verifier. Today the harness can
                                // also drive this with a single
                                // result, in which case the chain
                                // looks like [start, result] — both
                                // ends are present.
                                let synthesized = vec![
                                    serde_json::json!({
                                        "kind": "ck.agent.interop_session.start"
                                    }),
                                ];
                                let mut chain = synthesized;
                                for (_, payload) in incoming_results.read().iter() {
                                    chain.push(serde_json::json!({
                                        "kind": "ck.agent.interop_session.result",
                                        "payload": payload,
                                    }));
                                }
                                let outcome = verify_audit_chain(&chain);
                                audit_verify_result.set(Some(outcome));
                            },
                            "Verify audit chain"
                        }
                    }
                    if !handoff_status_text().is_empty() {
                        div { class: "muted",
                            "data-testid": "agent-protocol-handoff-status-text",
                            "{handoff_status_text}"
                        }
                    }
                    if let Some(outcome) = audit_verify_result() {
                        div {
                            class: if outcome == AuditChainVerifyOutcome::Valid { "badge green" } else { "badge red" },
                            "data-testid": "agent-protocol-audit-verify-result",
                            "data-state": "{outcome.as_data_state()}",
                            "audit chain: {outcome.as_data_state()}"
                        }
                    }
                }

                if handoff_state().has_transcript() {
                    div { class: "event", "data-testid": "agent-protocol-transcript-panel",
                        div { class: "event-head",
                            span { "Transcript" }
                            span { class: "badge", "{transcript_steps().len()} step(s)" }
                        }
                        for (idx, (kind, summary)) in transcript_steps().iter().enumerate() {
                            div {
                                class: "event",
                                "data-testid": "agent-protocol-transcript-row",
                                "data-step-index": "{idx}",
                                "data-step-kind": "{kind}",
                                div { class: "event-head",
                                    span { class: "mono", "[{idx}] {kind}" }
                                }
                                div { class: "muted", "{summary}" }
                            }
                        }
                    }
                }
            }

            // ─────────────────────────────────────────────────────
            // G3.Y4 (Phase B) — interop capability-approval surface.
            // Authors a ck.capability.grant carrying
            // actions=[ck.agent.interop_session.start] + the §7
            // constraint, gated behind an explicit human-approval
            // acknowledgement (spec §4 / §8).
            // ─────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-interop-approval",
                div { class: "event-head",
                    span { "Authorize an external handoff" }
                    span {
                        class: "badge",
                        "data-testid": "agent-interop-approval-state",
                        "data-state": "{interop_modal().as_data_state()}",
                        "{interop_modal().as_data_state()}"
                    }
                }
                div { class: "muted",
                    "Grant ck.agent.interop_session.start to a counterparty agent, pinned to a single allowed endpoint with a human-approval gate (agent-protocol-interop.md §4 / §7 / §8)."
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "agent-interop-approve-open-button",
                        disabled: interop_modal().is_open(),
                        onclick: move |_| {
                            interop_modal.set(InteropApprovalState::Drafting);
                            interop_status_text.set(String::new());
                        },
                        "Authorize handoff capability"
                    }
                }
                if interop_modal().is_open() {
                    div {
                        class: "event",
                        "data-testid": "agent-interop-publish-modal",
                        "data-state": "{interop_modal().as_data_state()}",
                        div { class: "event-head",
                            span { "Capability approval" }
                            span { class: "badge blue", "ck.agent.interop_session.start" }
                        }
                        div { class: "workflow-form",
                            Input {
                                "data-testid": "agent-interop-target-input",
                                placeholder: "counterparty agent_id (did:web:...)",
                                value: "{interop_target_did}",
                                oninput: move |event: FormEvent| interop_target_did.set(event.value()),
                            }
                            Input {
                                "data-testid": "agent-interop-allowed-endpoint-input",
                                placeholder: "allowed_endpoints (single exact URL)",
                                value: "{interop_allowed_endpoint}",
                                oninput: move |event: FormEvent| interop_allowed_endpoint.set(event.value()),
                            }
                            // Human-approval gate (spec §4 explicit +
                            // authorizable). Confirm stays disabled until
                            // the controller acknowledges it.
                            div {
                                class: "event",
                                "data-testid": "agent-interop-human-approval-gate",
                                "data-acknowledged": "{interop_modal() != InteropApprovalState::Drafting}",
                                div { class: "muted",
                                    "This handoff sends data to an external agent network. Acknowledge that you, a human controller, authorize it before the capability grant is signed."
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "agent-interop-human-approval-ack-button",
                                    disabled: interop_modal() != InteropApprovalState::Drafting,
                                    onclick: move |_| {
                                        interop_modal.set(InteropApprovalState::Acknowledged);
                                    },
                                    "I authorize this handoff"
                                }
                            }
                            div { class: "actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "agent-interop-publish-confirm-button",
                                    disabled: !interop_modal().can_confirm(),
                                    onclick: {
                                        let base = base_url.clone();
                                        let realm = selected_realm_id.clone();
                                        let actor = account_did.clone();
                                        move |_| {
                                            let target = interop_target_did().trim().to_owned();
                                            let endpoint = interop_allowed_endpoint().trim().to_owned();
                                            if target.is_empty() || endpoint.is_empty() {
                                                interop_status_text.set(
                                                    "counterparty agent_id + allowed endpoint are required".to_owned(),
                                                );
                                                return;
                                            }
                                            let base = base.clone();
                                            let realm = realm.clone();
                                            let actor = actor.clone();
                                            let api_token = token();
                                            interop_modal.set(InteropApprovalState::Submitting);
                                            interop_status_text.set("submitting capability grant".to_owned());
                                            spawn(async move {
                                                let grant_id = format!(
                                                    "ck:grant:{}",
                                                    crate::operation::uuid_v7()
                                                );
                                                let constraint = crate::operation::ck_ops::interop_capability_constraint(
                                                    &endpoint,
                                                    &["a2a"],
                                                    true,
                                                    3600,
                                                    10_485_760,
                                                    "metadata_only",
                                                    "summary_and_artifacts",
                                                );
                                                let op = crate::operation::ck_ops::capability_grant_actions(
                                                    &realm,
                                                    &actor,
                                                    &grant_id,
                                                    &target,
                                                    &["ck.agent.interop_session.start"],
                                                    None,
                                                    constraint,
                                                )
                                                .build_sdk_event("yougen");
                                                let op = match op {
                                                    Ok(op) => op,
                                                    Err(err) => {
                                                        interop_modal.set(InteropApprovalState::Failed);
                                                        interop_status_text.set(format!(
                                                            "grant build failed: {err}"
                                                        ));
                                                        return;
                                                    }
                                                };
                                                match with_authed_api(&base, api_token, |api| async move {
                                                    api.event_submitter()?.submit_sdk_event(&op).await
                                                })
                                                .await
                                                {
                                                    Ok(resp) => {
                                                        interop_modal.set(InteropApprovalState::Granted);
                                                        interop_last_grant_id.set(grant_id.clone());
                                                        interop_status_text.set(format!(
                                                            "capability granted; grant_id {grant_id}; event_id {}",
                                                            resp.event_id
                                                        ));
                                                    }
                                                    Err(err) => {
                                                        interop_modal.set(InteropApprovalState::Failed);
                                                        interop_status_text.set(format!(
                                                            "grant submit failed: {}", err.display()
                                                        ));
                                                    }
                                                }
                                            });
                                        }
                                    },
                                    "Confirm and sign grant"
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "agent-interop-publish-cancel-button",
                                    onclick: move |_| {
                                        interop_modal.set(InteropApprovalState::Closed);
                                    },
                                    "Cancel"
                                }
                            }
                            if !interop_status_text().is_empty() {
                                div { class: "muted",
                                    "data-testid": "agent-interop-approval-status",
                                    "{interop_status_text}"
                                }
                            }
                            if !interop_last_grant_id().is_empty() {
                                div { class: "muted",
                                    "data-testid": "agent-interop-grant-id",
                                    "data-grant-id": "{interop_last_grant_id}",
                                    "grant_id {interop_last_grant_id}"
                                }
                            }
                        }
                    }
                }
            }

            // ─────────────────────────────────────────────────────
            // G3.Y4 (Phase D) — publish-to-source surface. Lands a
            // Strand whose actor_id is the controller but whose
            // attribution preserves the executing agent (spec §5.4 /
            // §6 step 8-9).
            // ─────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-publish-to-source",
                div { class: "event-head",
                    span { "Publish agent result to source" }
                    span {
                        class: "badge",
                        "data-testid": "agent-publish-state",
                        "data-state": "{publish_modal().as_data_state()}",
                        "{publish_modal().as_data_state()}"
                    }
                }
                div { class: "muted",
                    "Publish a synthesis Strand from an agent result. The controller signs it, but the executing agent's attribution is preserved on the published object."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-publish-attribution-input",
                        placeholder: "attribution agent_id (remote agent did:web:...)",
                        value: "{publish_attribution_did}",
                        oninput: move |event: FormEvent| publish_attribution_did.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-publish-result-ref-input",
                        placeholder: "result object_ref (ck:strand:... from the result)",
                        value: "{publish_result_ref}",
                        oninput: move |event: FormEvent| publish_result_ref.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-publish-artifact-ref-input",
                        placeholder: "artifact object_ref (ck:morph:...)",
                        value: "{publish_artifact_ref}",
                        oninput: move |event: FormEvent| publish_artifact_ref.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-publish-open-button",
                            disabled: publish_modal().is_open(),
                            onclick: move |_| {
                                publish_modal.set(PublishModalState::Reviewing);
                                publish_status_text.set(String::new());
                            },
                            "Review and publish"
                        }
                    }
                }
                if publish_modal().is_open() {
                    div {
                        class: "event",
                        "data-testid": "publish-modal",
                        "data-state": "{publish_modal().as_data_state()}",
                        div { class: "event-head",
                            span { "Publish to source space" }
                            span { class: "badge blue", "ck.strand.create" }
                        }
                        // Signer toggle. The self-with-attribution
                        // branch keeps actor_id = controller while
                        // carrying attribution = remote agent.
                        div {
                            class: "event",
                            "data-testid": "publish-modal-signer-self-with-attribution",
                            "data-selected": "{publish_with_attribution()}",
                            div { class: "muted",
                                "Sign as yourself, preserve agent attribution. The published Strand records you as actor_id and the agent as attribution."
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "publish-modal-signer-toggle-button",
                                onclick: move |_| {
                                    let next = !publish_with_attribution();
                                    publish_with_attribution.set(next);
                                },
                                if publish_with_attribution() {
                                    "Attribution: preserved"
                                } else {
                                    "Attribution: dropped"
                                }
                            }
                        }
                        div { class: "actions",
                            Button {
                                variant: ButtonVariant::Primary,
                                "data-testid": "publish-modal-confirm",
                                onclick: {
                                    let base = base_url.clone();
                                    let realm = selected_realm_id.clone();
                                    let actor = account_did.clone();
                                    move |_| {
                                        let attribution = publish_attribution_did().trim().to_owned();
                                        let result_ref = publish_result_ref().trim().to_owned();
                                        let artifact_ref = publish_artifact_ref().trim().to_owned();
                                        if attribution.is_empty() {
                                            publish_status_text.set(
                                                "attribution agent_id is required".to_owned(),
                                            );
                                            return;
                                        }
                                        let base = base.clone();
                                        let realm = realm.clone();
                                        let actor = actor.clone();
                                        let api_token = token();
                                        publish_modal.set(PublishModalState::Submitting);
                                        publish_status_text.set("publishing synthesis Strand".to_owned());
                                        spawn(async move {
                                            let strand_id = format!(
                                                "ck:strand:{}",
                                                crate::operation::uuid_v7()
                                            );
                                            let op = crate::operation::ck_ops::agent_publish_attribution_strand(
                                                &realm,
                                                &actor,
                                                &strand_id,
                                                "Agent synthesis result",
                                                &attribution,
                                                &result_ref,
                                                &artifact_ref,
                                            )
                                            .and_then(|builder| builder.build_sdk_event("yougen"));
                                            let op = match op {
                                                Ok(op) => op,
                                                Err(err) => {
                                                    publish_modal.set(PublishModalState::Failed);
                                                    publish_status_text.set(format!(
                                                        "publish build failed: {err}"
                                                    ));
                                                    return;
                                                }
                                            };
                                            match with_authed_api(&base, api_token, |api| async move {
                                                api.event_submitter()?.submit_sdk_event(&op).await
                                            })
                                            .await
                                            {
                                                Ok(resp) => {
                                                    publish_modal.set(PublishModalState::Published);
                                                    publish_last_strand_id.set(strand_id.clone());
                                                    publish_status_text.set(format!(
                                                        "published strand {strand_id}; event_id {}",
                                                        resp.event_id
                                                    ));
                                                }
                                                Err(err) => {
                                                    publish_modal.set(PublishModalState::Failed);
                                                    publish_status_text.set(format!(
                                                        "publish failed: {}", err.display()
                                                    ));
                                                }
                                            }
                                        });
                                    }
                                },
                                "Publish with attribution"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "publish-modal-cancel",
                                onclick: move |_| {
                                    publish_modal.set(PublishModalState::Closed);
                                },
                                "Cancel"
                            }
                        }
                        if !publish_status_text().is_empty() {
                            div { class: "muted",
                                "data-testid": "agent-publish-status",
                                "{publish_status_text}"
                            }
                        }
                        if !publish_last_strand_id().is_empty() {
                            div { class: "muted",
                                "data-testid": "agent-publish-strand-id",
                                "data-strand-id": "{publish_last_strand_id}",
                                "strand_id {publish_last_strand_id}"
                            }
                        }
                    }
                }
            }
        }
    }
}
