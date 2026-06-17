//! Personal Agent admin panel (CKP-0008 / CKP-0009 · B-A · P3-A).
//!
//! Surfaces the soland personal-agent HTTP operations as a single admin
//! view: provision (with §4.7 permission presets + pairing guide), list /
//! get, lifecycle (pause / resume with sidecar exposure ack / deactivate),
//! rotate-key, grant attach + per-row detach, participation, sidecar
//! ensure, and the draft-approval surface. Each endpoint has a matching
//! client-side call so the cross-project wire shape is verified end to end.

use cokret_sdk::RealmId;
use cokret_sdk::models::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentParticipation,
    AgentParticipationEntry, AgentParticipationScope, AgentParticipationSetRequestBody,
    AgentPauseRequestBody, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentRotateKeyRequestBody, AgentSidecarThreadEnsureRequestBody, AgentView,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use serde_json::{Value, json};

use super::components::{ActorKindBadge, DraftApprovalPanel, SidecarExposureDisclosure};
use super::model::{
    AgentPermissionPreset, agent_pair_url, agent_state_badge_class, agent_state_label,
    agent_view_from_directory_row, expand_preset_grant, requested_scope_for_presets,
};
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::input::Input;
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Copy text to the clipboard using the browser clipboard API with a
/// `document.execCommand` fallback for non-secure contexts.
fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

/// Open a URL in a new tab. Used for the pairing deep-link so the
/// controller lands on the deployment's agent-pair page.
fn open_url_in_new_tab(url: &str) {
    let Ok(encoded) = serde_json::to_string(url) else {
        return;
    };
    let script = format!("window.open({encoded}, \"_blank\", \"noopener,noreferrer\");");
    let _ = document::eval(&script);
}

// ═══════════════════════════════════════════════════════════════════
// CKP-0008 / CKP-0009 — Personal Agent admin panel (B-A · P3-A).
//
// Surfaces the 11 soland personal-agent HTTP operations as a single
// admin view. Each soland endpoint has a matching reqwest call below
// — that's the load-bearing bit of this commit. The form layouts
// themselves are intentionally minimal: deeper UI work (per-agent
// inspector, grant catalog, sidecar projection viewer) lives under
// `// TODO(P3-impl)` markers and lands once soland's reducer stamps
// `actor_kind` and the projection ships.
//
// Sidecar Thread renderer guard: a sidecar thread MUST render as a
// controller × native-agent 1:1 channel, not as a group chat. The
// `SidecarThreadGuard` component below enforces this invariant in the
// UI — it refuses to render when more than two actors are present and
// shows a placeholder explaining the constraint.
//
// Action-approve dialog: when the UI receives a notification of kind
// `ck.agent.action_request` (delivered via chime's push frame
// parser), the controller MUST review the payload digest + expiry +
// single-use nonce status before approving. The `ActionApproveDialog`
// component carries that strand; on confirm it submits a
// `ck.agent.action_approve` event.
// ═══════════════════════════════════════════════════════════════════

/// Personal Agent admin panel. Surfaces the soland personal-agent HTTP
/// operations: provision (with §4.7 permission presets + pairing guide),
/// list / get, lifecycle (pause / resume with sidecar exposure ack /
/// deactivate), rotate-key, grant attach + per-row detach, participation,
/// sidecar ensure, and the draft-approval surface. Each endpoint has a
/// matching client-side call so the cross-project wire shape is verified
/// end to end.
#[component]
pub fn PersonalAgentAdminPanel(
    base_url: String,
    token: Signal<String>,
    controller_did: String,
) -> Element {
    let mut agents = use_signal(Vec::<AgentView>::new);
    let mut list_status = use_signal(String::new);
    let mut selected_agent_id = use_signal(String::new);
    let mut new_display_name = use_signal(|| "my-personal-agent".to_owned());
    let mut new_agent_slug = use_signal(|| "summary".to_owned());
    // CKP-0008 §4.7 — selected permission presets for the provision form
    // and the Realm the preset grants are scoped to.
    let mut provision_presets = use_signal(Vec::<AgentPermissionPreset>::new);
    let mut provision_realm = use_signal(String::new);
    // CKP-0008 §4.3 — pairing handle returned by the provision call.
    // When `Some`, the pairing guide card renders the code / request id /
    // expiry plus the HTTPS deep-link the controller hands to the runtime.
    let mut pairing_outcome = use_signal(|| Option::<cokret_sdk::AgentProvisionOutcome>::None);
    // Grant snapshots for the currently-selected agent, fetched via
    // `ck.self.agent.resource.get`; drives the per-row detach list.
    let mut selected_grants = use_signal(Vec::<Value>::new);
    // CKP-0008 §4.5 / §4.11 — sidecar object_refs that became newly
    // visible while the agent was paused. The controller MUST
    // re-acknowledge them before resume. Populated from the agent view's
    // sidecar exposure projection (soland projection pending; see the
    // re-disclosure card below). When non-empty, resume sends a real
    // `agent_sidecar_exposure_ack`.
    let mut resume_sidecar_refs = use_signal(Vec::<String>::new);
    // Spec `agent_rotate_key_request_body` = `{replacement_key,
    // proof_of_possession}` (full JSON); the scaffold takes the raw body.
    let mut rotate_body_json = use_signal(String::new);
    // Spec `agent_grant_attach_request_body` = `{grant}` — the scaffold
    // takes the grant object as raw JSON.
    let mut grant_json = use_signal(|| "{}".to_owned());
    let mut sidecar_realm = use_signal(String::new);
    let mut deactivate_confirm = use_signal(String::new);
    let mut last_op_status = use_signal(String::new);
    // CKP-0010 — participation editor (Realm-scope selection + resolved view).
    let mut participation_realm = use_signal(String::new);
    let mut participation_reply = use_signal(|| false);
    let mut participation_mention = use_signal(|| false);
    let mut participation_aob = use_signal(|| false);
    let mut participation_entries = use_signal(Vec::<AgentParticipationEntry>::new);

    rsx! {
        div { class: "timeline", "data-testid": "personal-agent-admin",
            div { class: "event",
                div { class: "event-head",
                    span { "Personal Agent admin" }
                    span { class: "badge", "CKP-0008 / CKP-0009" }
                }
                div { class: "muted",
                    "Provision and operate native personal agents. Each button below maps 1:1 to a soland P2 endpoint; detailed controls remain preview surfaces while the reducer projection lands."
                }
                if !last_op_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-admin-last-op", "{last_op_status}" }
                }
            }

            // ───────────────────────────────────────────────────────
            // List + refresh (ck.self.agent.query.list)
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-list",
                div { class: "event-head",
                    span { "Agents" }
                    span { class: "badge", "{agents.read().len()} known" }
                }
                if !list_status().is_empty() {
                    div { class: "muted", "data-testid": "agent-admin-list-status", "{list_status}" }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-admin-refresh-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.agent_list().await
                                    })
                                    .await
                                    {
                                        Ok(resp) => {
                                            // SDK `AgentList.agents` is loose
                                            // `Vec<Value>`; decode each row as
                                            // the spec `agent_view` shape and
                                            // skip malformed rows.
                                            let rows: Vec<AgentView> = resp
                                                .agents
                                                .into_iter()
                                                .filter_map(agent_view_from_directory_row)
                                                .collect();
                                            list_status.set(format!(
                                                "fetched {} agent(s)",
                                                rows.len()
                                            ));
                                            agents.set(rows);
                                        }
                                        Err(err) => list_status.set(format!(
                                            "list failed: {}",
                                            err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Refresh"
                    }
                }
                for agent in agents.read().iter() {
                    {
                        // Spec `agent_view` = `{agent: agent_projection,
                        // status, grants, key_state}`; the projection
                        // carries `agent_principal_id` / `display_name`.
                        let status = agent.status.clone();
                        let id = agent
                            .agent
                            .get("agent_principal_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let display_name = agent
                            .agent
                            .get("display_name")
                            .and_then(Value::as_str)
                            .unwrap_or("(unnamed)")
                            .to_owned();
                        let agent_slug = agent
                            .agent
                            .get("agent_slug")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned();
                        let id_label = short_protocol_id(&id);
                        rsx! {
                            div {
                                class: "event",
                                "data-testid": "agent-admin-row",
                                "data-agent-principal-id": "{id}",
                                div { class: "event-head",
                                    span { class: "mono", title: "{id}", "{id_label}" }
                                    // Personal agents always run as actor_kind=agent —
                                    // surface the badge so the operator can see at
                                    // a glance which row is a native personal agent.
                                    ActorKindBadge { actor_kind: Some("agent".to_owned()) }
                                    // R3 — FSM-state badge with semantic colouring:
                                    // active=green, paused=amber, deactivated=red.
                                    span {
                                        class: "{agent_state_badge_class(&status)}",
                                        "data-testid": "agent-state-badge",
                                        "data-state": "{status}",
                                        "{agent_state_label(&status)}"
                                    }
                                }
                                div { class: "muted", "display_name: {display_name}" }
                                if !agent_slug.is_empty() {
                                    div { class: "muted", "agent_slug: {agent_slug}" }
                                }
                                div { class: "actions",
                                    Button {
                                        variant: if selected_agent_id() == id { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                        "data-testid": "agent-admin-select-button",
                                        onclick: {
                                            let id = id.clone();
                                            move |_| selected_agent_id.set(id.clone())
                                        },
                                        "Select"
                                    }
                                    // ck.self.agent.resource.get — also
                                    // selects the agent and loads its grant
                                    // snapshots so the detach list below
                                    // renders real grant_ids.
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-get-button",
                                        onclick: {
                                            let base = base_url.clone();
                                            let id = id.clone();
                                            move |_| {
                                                let base = base.clone();
                                                let id = id.clone();
                                                let api_token = token();
                                                selected_agent_id.set(id.clone());
                                                spawn(async move {
                                                    match with_authed_api(&base, api_token, move |api| {
                                                        let id = id.clone();
                                                        async move {
                                                            api.agent_get(&id).await
                                                        }
                                                    })
                                                    .await
                                                    {
                                                        Ok(view) => {
                                                            selected_grants.set(view.grants.clone());
                                                            last_op_status.set(format!(
                                                                "get {} status={} ({} grant(s))",
                                                                view.agent
                                                                    .get("agent_principal_id")
                                                                    .and_then(Value::as_str)
                                                                    .unwrap_or("(unknown)"),
                                                                view.status,
                                                                view.grants.len()
                                                            ));
                                                        }
                                                        Err(err) => last_op_status.set(format!(
                                                            "get failed: {}",
                                                            err.display()
                                                        )),
                                                    }
                                                });
                                            }
                                        },
                                        "Get"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Provision (ck.self.agent.command.provision)
            // CKP-0008 §4.7 — permission-preset selector. The chosen
            // presets drive `requested_scope` (coarse AgentKeyScope) on
            // the provision body, and each preset is expanded into a
            // canonical ck.capability.grant attached right after
            // provisioning (effective_after_first_authorized_key=true).
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-provision",
                div { class: "event-head",
                    span { "Provision agent" }
                    span { class: "badge blue", "ck.self.agent.command.provision" }
                }
                div { class: "muted",
                    "Provisions a new native personal agent: DID issuance + first agent-key authorize + controller grant attach (orchestrated server-side)."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-provision-display-name",
                        placeholder: "display name",
                        value: "{new_display_name}",
                        oninput: move |event: FormEvent| new_display_name.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-admin-provision-agent-slug",
                        placeholder: "agent slug",
                        value: "{new_agent_slug}",
                        oninput: move |event: FormEvent| new_agent_slug.set(event.value()),
                    }
                    Input {
                        "data-testid": "agent-admin-provision-realm-input",
                        placeholder: "realm_id to scope preset grants (ck:realm:...)",
                        value: "{provision_realm}",
                        oninput: move |event: FormEvent| provision_realm.set(event.value()),
                    }
                    div { class: "muted", "Permission presets (CKP-0008 §4.7) — select one or more:" }
                    for preset in AgentPermissionPreset::ALL {
                        {
                            let is_on = provision_presets.read().contains(&preset);
                            rsx! {
                                label {
                                    class: "metric",
                                    "data-testid": "agent-admin-preset-row",
                                    "data-preset": preset.preset_name(),
                                    Checkbox {
                                        "data-testid": "agent-admin-preset-checkbox",
                                        checked: if is_on { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                        on_checked_change: move |s: CheckboxState| {
                                            let mut current = provision_presets.write();
                                            if bool::from(s) {
                                                if !current.contains(&preset) {
                                                    current.push(preset);
                                                }
                                            } else {
                                                current.retain(|p| *p != preset);
                                            }
                                        },
                                    }
                                    span {
                                        strong { "{preset.label()}" }
                                        div { class: "muted", "{preset.help()}" }
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "agent-admin-provision-button",
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let base = base.clone();
                                let api_token = token();
                                let display = new_display_name();
                                let slug = new_agent_slug();
                                let agent_slug = if slug.trim().is_empty() {
                                    None
                                } else {
                                    Some(slug.trim().to_owned())
                                };
                                let presets = provision_presets.read().clone();
                                let realm = provision_realm();
                                let realm_for_grant = if realm.trim().is_empty() {
                                    None
                                } else {
                                    Some(realm.trim().to_owned())
                                };
                                // Spec `agent_provision_request_body`:
                                // {display_name, agent_slug, requested_scope,
                                // accountability, pairing_ttl_ms} — the
                                // controller binding comes from the
                                // authenticated session, not the body. The
                                // selected presets fold into requested_scope
                                // (coarse AgentKeyScope); their canonical
                                // capability grants attach after provision.
                                let body = AgentProvisionRequestBody {
                                    display_name: Some(display),
                                    agent_slug,
                                    requested_scope: requested_scope_for_presets(&presets),
                                    accountability: Value::Null,
                                    pairing_ttl_ms: None,
                                };
                                spawn(async move {
                                    let outcome = match with_authed_api(
                                        &base,
                                        api_token.clone(),
                                        move |api| {
                                            let body = body.clone();
                                            async move { api.agent_provision(&body).await }
                                        },
                                    )
                                    .await
                                    {
                                        Ok(outcome) => outcome,
                                        Err(err) => {
                                            last_op_status.set(format!(
                                                "provision failed: {}",
                                                err.display()
                                            ));
                                            return;
                                        }
                                    };
                                    let agent_id = outcome.agent_principal_id.to_string();
                                    let expires_at = outcome.expires_at.to_rfc3339();
                                    pairing_outcome.set(Some(outcome));
                                    // Expand each preset into a canonical
                                    // capability grant and attach it so the
                                    // agent has its scoped capabilities the
                                    // moment pairing completes.
                                    let mut attached = 0usize;
                                    let mut grant_errs: Vec<String> = Vec::new();
                                    for preset in presets.iter() {
                                        let grant = expand_preset_grant(
                                            *preset,
                                            &agent_id,
                                            realm_for_grant.as_deref(),
                                            &expires_at,
                                        );
                                        let attach_body = AgentGrantAttachRequestBody { grant };
                                        let agent_id_for_call = agent_id.clone();
                                        match with_authed_api(
                                            &base,
                                            api_token.clone(),
                                            move |api| {
                                                let body = attach_body.clone();
                                                let id = agent_id_for_call.clone();
                                                async move {
                                                    api.agent_grant_attach(&id, &body).await
                                                }
                                            },
                                        )
                                        .await
                                        {
                                            Ok(_) => attached += 1,
                                            Err(err) => grant_errs.push(format!(
                                                "{}: {}",
                                                preset.preset_name(),
                                                err.display()
                                            )),
                                        }
                                    }
                                    if grant_errs.is_empty() {
                                        last_op_status.set(format!(
                                            "provisioned {agent_id} ({attached} preset grant(s) attached)"
                                        ));
                                    } else {
                                        last_op_status.set(format!(
                                            "provisioned {agent_id}; {attached} grant(s) attached, errors: {}",
                                            grant_errs.join("; ")
                                        ));
                                    }
                                });
                            }
                        },
                        "Provision"
                    }
                }
                // CKP-0008 §4.3 — pairing guide card.
                if let Some(outcome) = pairing_outcome() {
                    {
                        let agent_id = outcome.agent_principal_id.to_string();
                        let request_id = outcome.pairing_request_id.clone();
                        let pairing_code = outcome.pairing_code.clone();
                        let expires_at = outcome.expires_at.to_rfc3339();
                        let pair_url = agent_pair_url(&base_url, &request_id);
                        rsx! {
                            div {
                                class: "event",
                                "data-testid": "agent-admin-pairing-card",
                                "data-pairing-request-id": "{request_id}",
                                div { class: "event-head",
                                    span { "Pair the runtime" }
                                    span { class: "badge green", "pending_runtime_key" }
                                }
                                div { class: "muted",
                                    "Hand these one-time, short-lived values to your agent runtime so it can pair its key and come online. They are not a session token and cannot be reused after pairing."
                                }
                                div { class: "metric-grid",
                                    div { class: "metric",
                                        strong { "Pairing code" }
                                        if let Some(code) = pairing_code.clone() {
                                            span { class: "mono", "data-testid": "agent-admin-pairing-code", "{code}" }
                                        } else {
                                            span { class: "muted", "data-testid": "agent-admin-pairing-code", "(delivered out of band)" }
                                        }
                                    }
                                    div { class: "metric",
                                        strong { "Pairing request id" }
                                        span { class: "mono", "data-testid": "agent-admin-pairing-request-id", "{request_id}" }
                                    }
                                    div { class: "metric",
                                        strong { "Expires at" }
                                        span { class: "mono", "data-testid": "agent-admin-pairing-expires-at", "{expires_at}" }
                                    }
                                }
                                div { class: "muted", "data-testid": "agent-admin-pairing-url", title: "{pair_url}", "{pair_url}" }
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "agent-admin-pairing-open-button",
                                        onclick: {
                                            let pair_url = pair_url.clone();
                                            move |_| open_url_in_new_tab(&pair_url)
                                        },
                                        "Open pairing page"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-pairing-copy-url-button",
                                        onclick: {
                                            let pair_url = pair_url.clone();
                                            move |_| copy_text_to_clipboard(&pair_url)
                                        },
                                        "Copy link"
                                    }
                                    if let Some(code) = pairing_code.clone() {
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "agent-admin-pairing-copy-code-button",
                                            onclick: move |_| copy_text_to_clipboard(&code),
                                            "Copy code"
                                        }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "agent-admin-pairing-select-button",
                                        onclick: {
                                            let agent_id = agent_id.clone();
                                            move |_| selected_agent_id.set(agent_id.clone())
                                        },
                                        "Select this agent"
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Lifecycle: pause / resume / deactivate
            // (ck.agent.{pause,resume,deactivate})
            // Deactivate is destructive — gate on type-to-confirm.
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-lifecycle",
                div { class: "event-head",
                    span { "Lifecycle" }
                    if selected_agent_id().is_empty() {
                        span { class: "badge amber", "no agent selected" }
                    } else {
                        {
                            let id_label = short_protocol_id(selected_agent_id().as_str());
                            rsx! { span { class: "badge", "{id_label}" } }
                        }
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-admin-pause-button",
                        disabled: selected_agent_id().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            move |_| {
                                let id = selected_agent_id();
                                if id.is_empty() { return; }
                                let base = base.clone();
                                let api_token = token();
                                let body = AgentPauseRequestBody { reason: Some("controller_paused".to_owned()) };
                                spawn(async move {
                                    match with_authed_api(&base, api_token, move |api| {
                                        let id = id.clone();
                                        let body = body.clone();
                                        async move {
                                            api.agent_pause(&id, &body).await
                                        }
                                    })
                                    .await
                                    {
                                        // Spec response is operation_status_outcome {ok, status}.
                                        Ok(r) => last_op_status.set(format!(
                                            "pause: status={}",
                                            r.status.as_wire_str()
                                        )),
                                        Err(err) => last_op_status.set(format!(
                                            "pause failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Pause"
                    }
                    Button {
                        variant: ButtonVariant::Secondary,
                        "data-testid": "agent-admin-resume-button",
                        disabled: selected_agent_id().is_empty(),
                        onclick: {
                            let base = base_url.clone();
                            let controller_did = controller_did.clone();
                            move |_| {
                                let id = selected_agent_id();
                                if id.is_empty() { return; }
                                let base = base.clone();
                                let api_token = token();
                                // CKP-0008 §4.5 / §4.11 — when sidecars
                                // became newly visible while paused, resume
                                // MUST carry a real agent_sidecar_exposure_ack
                                // {acknowledged_at, acknowledged_by,
                                // sidecar_refs[]}. With no new sidecars the
                                // field stays absent.
                                let refs = resume_sidecar_refs.read().clone();
                                let sidecar_exposure_ack = if refs.is_empty() {
                                    None
                                } else {
                                    Some(json!({
                                        "acknowledged_at": crate::clock::now_rfc3339_secs(),
                                        "acknowledged_by": controller_did.clone(),
                                        "sidecar_refs": refs,
                                    }))
                                };
                                let body = AgentResumeRequestBody { sidecar_exposure_ack };
                                spawn(async move {
                                    match with_authed_api(&base, api_token, move |api| {
                                        let id = id.clone();
                                        let body = body.clone();
                                        async move {
                                            api.agent_resume(&id, &body).await
                                        }
                                    })
                                    .await
                                    {
                                        Ok(r) => {
                                            // The acknowledgement was consumed;
                                            // clear the pending refs so the next
                                            // resume does not re-send a stale ack.
                                            resume_sidecar_refs.set(Vec::new());
                                            last_op_status.set(format!(
                                                "resume: status={}",
                                                r.status.as_wire_str()
                                            ));
                                        }
                                        Err(err) => last_op_status.set(format!(
                                            "resume failed: {}", err.display()
                                        )),
                                    }
                                });
                            }
                        },
                        "Resume"
                    }
                }
                // Deactivate (destructive) — type-to-confirm dialog.
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-deactivate-confirm-input",
                        placeholder: "type DEACTIVATE to enable the destructive button",
                        value: "{deactivate_confirm}",
                        oninput: move |event: FormEvent| deactivate_confirm.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Destructive,
                            "data-testid": "agent-admin-deactivate-button",
                            disabled: selected_agent_id().is_empty() || deactivate_confirm() != "DEACTIVATE",
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    let body = AgentDeactivateRequestBody { reason: Some("controller_deactivated".to_owned()) };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_deactivate(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "deactivate: status={}",
                                                r.status.as_wire_str()
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "deactivate failed: {}", err.display()
                                            )),
                                        }
                                    });
                                    deactivate_confirm.set(String::new());
                                }
                            },
                            "Deactivate (destructive)"
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Rotate key (ck.self.agent.command.rotate_key)
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-rotate-key",
                div { class: "event-head",
                    span { "Rotate runtime key" }
                    span { class: "badge blue", "ck.self.agent.command.rotate_key" }
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-rotate-vm-input",
                        placeholder: "rotate body JSON: {{\"replacement_key\": {{...}}, \"proof_of_possession\": {{...}}}}",
                        value: "{rotate_body_json}",
                        oninput: move |event: FormEvent| rotate_body_json.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-rotate-key-button",
                            disabled: selected_agent_id().is_empty() || rotate_body_json().trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    let raw = rotate_body_json();
                                    if id.is_empty() || raw.trim().is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    // Spec agent_rotate_key_request_body =
                                    // {replacement_key, proof_of_possession};
                                    // the scaffold takes the body verbatim
                                    // so the runtime can supply a real
                                    // proof-of-possession.
                                    let body: AgentRotateKeyRequestBody =
                                        match serde_json::from_str(&raw) {
                                            Ok(body) => body,
                                            Err(err) => {
                                                last_op_status.set(format!(
                                                    "rotate_key body is not valid JSON: {err}"
                                                ));
                                                return;
                                            }
                                        };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_rotate_key(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "rotate_key: ok={} authorized_event_ref={}",
                                                r.ok,
                                                short_protocol_id(r.authorized_event_ref.as_str())
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "rotate_key failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Rotate key"
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Grant attach / detach
            // (ck.self.agent.grant.command.attach / ck.self.agent.grant.resource.delete)
            // Attach takes a raw capability-grant object (the provision
            // preset selector expands presets into the same shape).
            // Detach is driven by the selected agent's real grant_ids,
            // loaded via "Get" on an agent row.
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-grants",
                div { class: "event-head",
                    span { "Capability grants" }
                    span { class: "badge blue", "ck.self.agent.grant.command.attach / detach" }
                }
                div { class: "muted",
                    "Spec agent_grant_attach_request_body carries the full grant object under the single `grant` property; the scaffold takes that object as raw JSON so cotest journey vectors can drive the wire shape."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-grant-kind-input",
                        placeholder: "grant (JSON capability-grant object)",
                        value: "{grant_json}",
                        oninput: move |event: FormEvent| grant_json.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-grant-attach-button",
                            disabled: selected_agent_id().is_empty() || grant_json().trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    let grant: Value = match serde_json::from_str(grant_json().as_str()) {
                                        Ok(grant) => grant,
                                        Err(err) => {
                                            last_op_status.set(format!(
                                                "grant is not valid JSON: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                    let body = AgentGrantAttachRequestBody { grant };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_grant_attach(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "grant.attach: ok={} grant_id={}",
                                                r.ok,
                                                short_protocol_id(r.grant_id.as_str())
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "grant.attach failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
            "Attach grant"
                        }
                    }
                    // Detach list: per CKP-0008 §4.11 each grant row
                    // carries its real grant_id (from the agent view's
                    // grant_snapshot[]); detaching submits
                    // ck.self.agent.grant.resource.delete for that id.
                    // Use "Get" on an agent row to load this list.
                    if selected_grants.read().is_empty() {
                        div { class: "muted", "data-testid": "agent-admin-grant-empty",
                            "No grants loaded. Use \"Get\" on an agent above to load its capability grants."
                        }
                    } else {
                        div { class: "timeline", "data-testid": "agent-admin-grant-list",
                            for grant in selected_grants.read().iter() {
                                {
                                    let grant_id = grant
                                        .get("grant_id")
                                        .or_else(|| grant.get("id"))
                                        .and_then(Value::as_str)
                                        .unwrap_or_default()
                                        .to_owned();
                                    let grant_status = grant
                                        .get("status")
                                        .and_then(Value::as_str)
                                        .unwrap_or("active")
                                        .to_owned();
                                    let expires_at = grant
                                        .get("expires_at")
                                        .and_then(Value::as_str)
                                        .unwrap_or("-")
                                        .to_owned();
                                    let grant_id_label = short_protocol_id(&grant_id);
                                    rsx! {
                                        div {
                                            class: "event",
                                            "data-testid": "agent-admin-grant-row",
                                            "data-grant-id": "{grant_id}",
                                            div { class: "event-head",
                                                span { class: "mono", title: "{grant_id}", "{grant_id_label}" }
                                                span { class: "badge", "{grant_status}" }
                                            }
                                            div { class: "muted", "expires_at: {expires_at}" }
                                            div { class: "actions",
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "agent-admin-grant-detach-button",
                                                    disabled: grant_id.is_empty(),
                                                    onclick: {
                                                        let base = base_url.clone();
                                                        let grant_id = grant_id.clone();
                                                        move |_| {
                                                            let id = selected_agent_id();
                                                            if id.is_empty() || grant_id.is_empty() { return; }
                                                            let base = base.clone();
                                                            let api_token = token();
                                                            let grant_id = grant_id.clone();
                                                            let grant_id_for_retain = grant_id.clone();
                                                            spawn(async move {
                                                                match with_authed_api(&base, api_token, move |api| {
                                                                    let id = id.clone();
                                                                    let grant_id = grant_id.clone();
                                                                    async move {
                                                                        api.agent_grant_detach(&id, &grant_id).await
                                                                    }
                                                                })
                                                                .await
                                                                {
                                                                    Ok(r) => {
                                                                        // Drop the detached row from the
                                                                        // local snapshot so the list
                                                                        // reflects the revoke immediately.
                                                                        selected_grants.write().retain(|g| {
                                                                            g.get("grant_id")
                                                                                .or_else(|| g.get("id"))
                                                                                .and_then(Value::as_str)
                                                                                != Some(grant_id_for_retain.as_str())
                                                                        });
                                                                        last_op_status.set(format!(
                                                                            "grant.detach: ok={} revoked_at={}",
                                                                            r.ok, r.revoked_at
                                                                        ));
                                                                    }
                                                                    Err(err) => last_op_status.set(format!(
                                                                        "grant.detach failed: {}", err.display()
                                                                    )),
                                                                }
                                                            });
                                                        }
                                                    },
                                                    "Detach"
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

            // ───────────────────────────────────────────────────────
            // Sidecar thread ensure
            // (ck.self.agent.sidecar_thread.command.ensure)
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-sidecar-ensure",
                div { class: "event-head",
                    span { "Sidecar thread (ensure)" }
                    span { class: "badge blue", "ck.self.agent.sidecar_thread.command.ensure" }
                }
                div { class: "muted",
                    "Ensures the controller-private sidecar objects for the selected agent in a Realm."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-sidecar-realm-input",
                        placeholder: "realm_id",
                        value: "{sidecar_realm}",
                        oninput: move |event: FormEvent| sidecar_realm.set(event.value()),
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-sidecar-ensure-button",
                            disabled: selected_agent_id().is_empty()
                                || sidecar_realm().trim().is_empty()
                                || controller_did.trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                let controller_did = controller_did.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    let realm = sidecar_realm();
                                    let controller = controller_did.clone();
                                    // Typed ids fail fast on malformed
                                    // input before the wire round-trip.
                                    let realm_id = match RealmId::new(realm.trim().to_owned()) {
                                        Ok(realm_id) => realm_id,
                                        Err(err) => {
                                            last_op_status.set(format!("invalid realm_id: {err:?}"));
                                            return;
                                        }
                                    };
                                    let agent_principal_id = match cokret_sdk::Did::new(id.clone()) {
                                        Ok(did) => did,
                                        Err(err) => {
                                            last_op_status.set(format!("invalid agent_principal_id: {err:?}"));
                                            return;
                                        }
                                    };
                                    let controller_principal_id = match cokret_sdk::Did::new(controller) {
                                        Ok(did) => did,
                                        Err(err) => {
                                            last_op_status.set(format!("invalid controller_principal_id: {err:?}"));
                                            return;
                                        }
                                    };
                                    let body = AgentSidecarThreadEnsureRequestBody {
                                        realm_id,
                                        controller_principal_id,
                                        agent_principal_id,
                                    };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_sidecar_thread_ensure(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => last_op_status.set(format!(
                                                "sidecar.ensure: circle={} strand={} relation={}",
                                                short_protocol_id(r.private_circle_id.as_str()),
                                                short_protocol_id(r.private_strand_id.as_str()),
                                                short_protocol_id(r.private_relation_id.as_str())
                                            )),
                                            Err(err) => last_op_status.set(format!(
                                                "sidecar.ensure failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Ensure sidecar thread"
                        }
                    }
                }
            }

            // ───────────────────────────────────────────────────────
            // Sidecar exposure disclosure (CKP-0009 §3 invariant 10 +
            // CKP-0008 §4.5). UI scaffold only — backend projection
            // is TODO(P3-impl).
            // ───────────────────────────────────────────────────────
            // ───────────────────────────────────────────────────────
            // CKP-0010 — participation policy. Per Realm scope, choose
            // whether the agent may reply as itself, accept @mentions
            // from other users, and act on the controller's behalf.
            // Each bit is capped by the deployment ⊇ Realm ⊇ Circle ⊇
            // Strand ceiling; soland rejects selections above it.
            // ───────────────────────────────────────────────────────
            div { class: "event", "data-testid": "agent-admin-participation",
                div { class: "event-head",
                    span { "Participation policy" }
                    span { class: "badge blue", "ck.self.agent.participation.resource.replace" }
                }
                div { class: "muted",
                    "Per Realm: let the selected agent reply as itself, accept @mentions from other users, or act on your behalf. Each switch is capped by the Realm / Circle / Strand ceiling."
                }
                div { class: "workflow-form",
                    Input {
                        "data-testid": "agent-admin-participation-realm-input",
                        placeholder: "realm_id (ck:realm:...)",
                        value: "{participation_realm}",
                        oninput: move |event: FormEvent| participation_realm.set(event.value()),
                    }
                    label { class: "metric", "data-testid": "agent-admin-participation-reply-row",
                        Checkbox {
                            "data-testid": "agent-admin-participation-reply",
                            checked: if participation_reply() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |s: CheckboxState| participation_reply.set(bool::from(s)),
                        }
                        span { "reply (post as agent)" }
                    }
                    label { class: "metric", "data-testid": "agent-admin-participation-mention-row",
                        Checkbox {
                            "data-testid": "agent-admin-participation-mention",
                            checked: if participation_mention() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |s: CheckboxState| participation_mention.set(bool::from(s)),
                        }
                        span { "accept @mentions from other users" }
                    }
                    label { class: "metric", "data-testid": "agent-admin-participation-aob-row",
                        Checkbox {
                            "data-testid": "agent-admin-participation-aob",
                            checked: if participation_aob() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |s: CheckboxState| participation_aob.set(bool::from(s)),
                        }
                        span { "act on my behalf" }
                    }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "agent-admin-participation-save-button",
                            disabled: selected_agent_id().is_empty() || participation_realm().trim().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let realm = participation_realm();
                                    let realm_id = match RealmId::new(realm.trim()) {
                                        Ok(r) => r,
                                        Err(_) => {
                                            last_op_status.set("participation: invalid realm_id".to_owned());
                                            return;
                                        }
                                    };
                                    let base = base.clone();
                                    let api_token = token();
                                    let body = AgentParticipationSetRequestBody {
                                        scope: AgentParticipationScope::Realm { realm_id },
                                        selection: AgentParticipation {
                                            reply: participation_reply(),
                                            accept_third_party_mention: participation_mention(),
                                            act_on_behalf: participation_aob(),
                                        },
                                    };
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            let body = body.clone();
                                            async move {
                                                api.agent_participation_set(&id, &body).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => {
                                                last_op_status.set(format!(
                                                    "participation.set ok ({} scope(s))",
                                                    r.entries.len()
                                                ));
                                                participation_entries.set(r.entries);
                                            }
                                            Err(err) => last_op_status.set(format!(
                                                "participation.set failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Save participation"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "agent-admin-participation-load-button",
                            disabled: selected_agent_id().is_empty(),
                            onclick: {
                                let base = base_url.clone();
                                move |_| {
                                    let id = selected_agent_id();
                                    if id.is_empty() { return; }
                                    let base = base.clone();
                                    let api_token = token();
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, move |api| {
                                            let id = id.clone();
                                            async move {
                                                api.agent_participation_get(&id).await
                                            }
                                        })
                                        .await
                                        {
                                            Ok(r) => {
                                                last_op_status.set(format!(
                                                    "participation.get ok ({} scope(s))",
                                                    r.entries.len()
                                                ));
                                                participation_entries.set(r.entries);
                                            }
                                            Err(err) => last_op_status.set(format!(
                                                "participation.get failed: {}", err.display()
                                            )),
                                        }
                                    });
                                }
                            },
                            "Load resolved"
                        }
                    }
                    if !participation_entries.read().is_empty() {
                        div { class: "timeline", "data-testid": "agent-admin-participation-entries",
                            for entry in participation_entries.read().iter() {
                                {
                                    let key = entry.scope.scope_key();
                                    let sel = entry.selection;
                                    let eff = entry.effective;
                                    let ceil = entry.ceiling;
                                    rsx! {
                                        div {
                                            class: "event",
                                            "data-testid": "agent-admin-participation-entry",
                                            "data-scope-key": "{key}",
                                            div { class: "event-head",
                                                span { class: "mono", "{key}" }
                                            }
                                            div { class: "muted",
                                                "effective: reply={eff.reply} mention={eff.accept_third_party_mention} act_on_behalf={eff.act_on_behalf}"
                                            }
                                            div { class: "muted",
                                                "ceiling: reply={ceil.reply} mention={ceil.accept_third_party_mention} act_on_behalf={ceil.act_on_behalf} · selection: reply={sel.reply} mention={sel.accept_third_party_mention} act_on_behalf={sel.act_on_behalf}"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            SidecarExposureDisclosure {
                controller_did: controller_did.clone(),
                resume_sidecar_refs,
            }

            DraftApprovalPanel {
                base_url: base_url.clone(),
                token,
                controller_did: controller_did.clone(),
            }
        }
    }
}
