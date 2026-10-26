use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

use anyhow::Context;
use arkret_sdk::{DidCoreId, DidUrl, Hash, KeyState, NotificationId, OpaqueLocalId};
use glory::prelude::*;

use super::mls_backup_prompt::try_set_state;
use crate::presentation::widgets::{heading, line, paragraph, reactive, stack};
use crate::presentation::{InksonContext, View};
use crate::transport::auth::{with_authed_api, with_authed_sdk_client};
use crate::views::agents::{
    build_agent_key_authorization_for_pairing, build_requested_scope_disclosure_for_pairing,
    into_agent_key_pair_request, parse_runtime_key_approval_request,
    runtime_key_pairing_error_message, summarize_runtime_key_approval_request,
};
use crate::views::helpers::short_protocol_id;

const APPROVAL_FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(30);
const APPROVAL_FALLBACK_MAX_INTERVAL: Duration = Duration::from_secs(60);

fn approval_scope_summary(scope: &arkret_sdk::AgentKeyScope) -> Vec<String> {
    let mut labels = Vec::new();
    for action in &scope.actions {
        let key = match action.as_str() {
            arkret_wire::CapabilityActionId::EVENT_READ => "agent_runtime.permission_read",
            arkret_wire::CapabilityActionId::OBJECT_READ => "agent_runtime.permission_metadata",
            arkret_wire::CapabilityActionId::MESSAGE_CREATE => "agent_runtime.permission_post",
            arkret_wire::CapabilityActionId::REACTION_ADD => "agent_runtime.permission_react",
            arkret_wire::CapabilityActionId::AGENT_DRAFT_PROPOSE
            | arkret_wire::CapabilityActionId::AGENT_ACTION_REQUEST => {
                "agent_runtime.permission_draft"
            }
            arkret_wire::CapabilityActionId::STRAND_CREATE
            | arkret_wire::CapabilityActionId::STRAND_UPDATE
            | arkret_wire::CapabilityActionId::RELATION_CREATE => {
                "agent_runtime.permission_organize"
            }
            arkret_wire::CapabilityActionId::SELF_COMMITTED_EVENT_READ_SCAN_V1
            | arkret_wire::CapabilityActionId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1
            | arkret_wire::ServiceOperationId::SELF_DIRECT_CONVERSATION_READ_RESOLVE_V1 => {
                "agent_runtime.permission_sync"
            }
            arkret_wire::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1 => {
                "agent_runtime.permission_submit"
            }
            arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1
            | arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1
            | arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE_V1
            | arkret_wire::ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1
            | arkret_wire::ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1
            | arkret_wire::ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1
            | arkret_wire::CapabilityActionId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1
            | arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1
            | arkret_wire::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1 => {
                "agent_runtime.permission_encrypted"
            }
            arkret_wire::ServiceOperationId::SELF_SIGNAL_COMMAND_SEND_V1 => {
                "agent_runtime.permission_presence"
            }
            arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1 => {
                "agent_runtime.permission_resources"
            }
            _ => "",
        };
        let label = if key.is_empty() {
            crate::i18n::tr_args(
                "agent_runtime.permission_other",
                &[("action", action.clone())],
            )
        } else {
            crate::i18n::tr(key)
        };
        if !labels.contains(&label) {
            labels.push(label);
        }
    }
    if scope
        .constraints
        .iter()
        .any(|constraint| constraint.controller_approval_required == Some(true))
    {
        labels.push(crate::i18n::tr("agent_runtime.permission_review"));
    }
    labels
}

#[derive(Clone, Debug)]
struct PendingAgentRuntimeApproval {
    notification_id: Option<NotificationId>,
    request_key: OpaqueLocalId,
    agent_id: DidCoreId,
    display_name: String,
    agent_slug: String,
    pairing_code: String,
    pairing_expires_at: String,
    verification_method: DidUrl,
    public_key_fingerprint: Hash,
    key_state: KeyState,
    request_json: String,
    replacement: bool,
}

#[derive(Clone)]
struct ApprovalController {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    pending: Cage<Option<PendingAgentRuntimeApproval>>,
    handled: Cage<HashSet<OpaqueLocalId>>,
    status: Cage<String>,
    diagnostic: Cage<String>,
    prepared: Cage<Option<(OpaqueLocalId, arkret_sdk::AgentKeyPairRequestBody)>>,
    approving: Cage<bool>,
    task: Rc<RefCell<Option<glory::core::TaskToken>>>,
}
impl ApprovalController {
    fn dismiss(&self) {
        if let Some(task) = self.task.borrow_mut().take() {
            task.cancel();
        }
        if let Some(request) = self.pending.get() {
            self.handled.revise(|handled| {
                handled.insert(request.request_key);
            });
        }
        try_set_state(self.pending, None);
        try_set_state(self.prepared, None);
        try_set_state(self.status, String::new());
        try_set_state(self.diagnostic, String::new());
        try_set_state(self.approving, false);
    }
    fn discover(&self, request: PendingAgentRuntimeApproval) {
        try_set_state(self.status, String::new());
        try_set_state(self.diagnostic, String::new());
        try_set_state(self.prepared, None);
        try_set_state(self.pending, Some(request));
    }
    fn reject(&self) {
        if self.approving.get() {
            return;
        }
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        let Some(request) = self.pending.get() else {
            return;
        };
        let Some(account) = self.context.active_account.get() else {
            try_set_state(self.status, self.context.tr("agent_runtime.err_no_account"));
            return;
        };
        let base = account.server_url.to_string();
        let token = self.context.token.get();
        let agent = request.agent_id.clone();
        let state = self.clone();
        let generation = self.context.session_generation.get();
        let active = self.context.active_account.get();
        try_set_state(self.approving, true);
        try_set_state(self.status, self.context.tr("agent_runtime.rejecting"));
        let task=scope.owner().spawn(async move {
            let result=with_authed_sdk_client(&base,token,move |http|async move{
                http.agent_renew_pairing(agent.as_str(),&arkret_models_collaboration::agent_operations::AgentRenewPairingRequestBody::default()).await.map_err(anyhow::Error::from)
            }).await;
            if state.owner.upgrade().is_none()||!state.context.session_matches(generation,&active){return}
            try_set_state(state.approving,false);
            match result {
                Ok(_)=>{state.handled.revise(|handled|{handled.insert(request.request_key);});try_set_state(state.pending,None);try_set_state(state.prepared,None);try_set_state(state.status,state.context.tr("agent_runtime.rejected"));},
                Err(error)=>try_set_state(state.status,crate::i18n::substitute_args(state.context.tr("agent_runtime.err_rotate_failed"),&[("error",error.display())])),
            }
        });
        if let Ok(task) = task {
            *self.task.borrow_mut() = Some(task);
        }
    }
    fn approve(&self) {
        if self.approving.get() {
            return;
        }
        let Some(scope) = self.owner.upgrade() else {
            return;
        };
        let Some(request) = self.pending.get() else {
            return;
        };
        if approval_has_expired(&request) {
            self.dismiss();
            return;
        }
        let Some(account) = self.context.active_account.get() else {
            try_set_state(self.status, self.context.tr("agent_runtime.err_no_account"));
            return;
        };
        if self.context.principal_id.get().is_none() {
            try_set_state(self.status, self.context.tr("agent_runtime.err_no_account"));
            return;
        }
        let body = match parse_runtime_key_approval_request(&request.request_json) {
            Ok(body) => body,
            Err(error) => {
                try_set_state(
                    self.status,
                    crate::i18n::substitute_args(
                        self.context.tr("agent_runtime.err_invalid_request"),
                        &[("error", runtime_key_pairing_error_message(error))],
                    ),
                );
                return;
            }
        };
        if body.agent_id != request.agent_id {
            try_set_state(
                self.status,
                runtime_key_pairing_error_message("runtime key request targets a different agent"),
            );
            return;
        }
        let server_url = account.server_url.to_string();
        let controller_did = account.did().to_string();
        let api_token = self.context.token.get();
        let request_key = request.request_key;
        let prepared_key = request_key.clone();
        let key_state = request.key_state;
        let approval_agent_id = request.agent_id;
        let prepared = self.prepared;
        let state = self.clone();
        let generation = self.context.session_generation.get();
        let active = self.context.active_account.get();
        let fence_context = self.context.clone();
        let owner = self.owner.clone();
        let active_for_work = active.clone();
        try_set_state(self.diagnostic, String::new());
        try_set_state(self.status, self.context.tr("agent_runtime.approving"));
        try_set_state(self.approving, true);
        let task=scope.owner().spawn(async move {
            let active_for_request=active_for_work;
            let active=active_for_request.clone();
                                let result = with_authed_api(&server_url, api_token, move |api| {
                                    let body = body.clone();
                                    let key_state = key_state.clone();
                                    let controller_did = controller_did.clone();
                                    let prepared_key = prepared_key.clone();
                                    async move {
                                        let submitter = api.event_submitter()?;
                                        let cached = prepared.get().filter(|(key, _)| key == &prepared_key);
                                        let pair_request = if let Some((_, request)) = cached {
                                            request
                                        } else {
                                            let description = api.describe_cached().await.context("discover pairing Station")?;
                                            let service_id = description.service_id.to_string();
                                            let service_did =
                                                description.service_resolution.did.to_string();
                                            let authorization =
                                                build_agent_key_authorization_for_pairing(
                                                    &submitter,
                                                    &controller_did,
                                                    &service_id,
                                                    &key_state,
                                                    &body,
                                                )
                                                .await.context("author Agent runtime authorization")?;
                                            let authorize_event =
                                                authorization.authorize_event;
                                            let requested_scope_disclosure =
                                                build_requested_scope_disclosure_for_pairing(
                                                    &controller_did,
                                                    &service_did,
                                                    &key_state,
                                                    &body,
                                                )?;
                                            let authorize_submission = submitter
                                                .prepare_initial_submissions(std::slice::from_ref(
                                                    &authorize_event,
                                                ))
                                                .await.context("prepare Agent runtime authorization submission")?
                                                .into_iter()
                                                .next()
                                                .ok_or_else(|| {
                                                    anyhow::anyhow!(
                                                        "agent authorize submission was not prepared"
                                                    )
                                                })?;
                                            let pair_request = into_agent_key_pair_request(
                                                body,
                                                requested_scope_disclosure,
                                                authorize_submission,
                                            );
                                            if owner.upgrade().is_none()||!fence_context.session_matches(generation,&active){anyhow::bail!("approval owner retired")}
                                            prepared.revise(|value|*value=Some((prepared_key, pair_request.clone())));
                                            pair_request
                                        };
                                        let mut outcome = submitter.agent_key_pair(&pair_request).await.context("submit Agent runtime approval")?;
                                        for _ in 0..30 {
                                            if owner.upgrade().is_none()||!fence_context.session_matches(generation,&active){anyhow::bail!("approval owner retired")}
                                            if matches!(outcome.activation_state, arkret_sdk::AgentKeyPairActivationState::Active) {
                                                break;
                                            }
                                            crate::runtime_helpers::sleep_for(Duration::from_secs(1)).await;
                                            outcome = submitter.agent_key_pair(&pair_request).await.context("await Agent runtime activation")?;
                                        }
                                        if !matches!(
                                            outcome.activation_state,
                                            arkret_models_collaboration::agent_operations::AgentKeyPairActivationState::Active
                                        ) {
                                            anyhow::bail!("agent authorization is not yet active");
                                        }
                                        if outcome.authorize_event_ref
                                            != pair_request.authorize_event.event.event_id
                                        {
                                            anyhow::bail!(
                                                "agent key pairing returned a commit for a different authorization Event"
                                            );
                                        }
                                        let committed = submitter
                                            .http()
                                            .committed_event_get(&outcome.authorize_event_ref)
                                            .await?;
                                        committed.validate_shape()?;
                                        if committed.commit().event_ref != outcome.authorize_event_ref
                                            || committed.reducer_input()
                                                != Some(&pair_request.authorize_event.event)
                                        {
                                            anyhow::bail!(
                                                "agent key pairing authorization commit could not be verified"
                                            );
                                        }
                                        Ok::<_, anyhow::Error>(outcome)
                                    }
                                })
                                .await;

            if state.owner.upgrade().is_none()||!state.context.session_matches(generation,&active_for_request){return}
            try_set_state(state.approving,false);
            match result {
                Ok(outcome)=>{
                    state.handled.revise(|handled|{handled.insert(request_key);});try_set_state(state.pending,None);try_set_state(state.prepared,None);
                    state.context.owned_agents_rev.revise(|value|*value=value.saturating_add(1));
                    try_set_state(state.status,crate::i18n::substitute_args(state.context.tr("agent_runtime.approved_current"),&[("id",short_protocol_id(outcome.authorize_event_ref.as_str()))]));
                },
                Err(error)=>{
                    let diagnostic=error.display_diagnostic();tracing::warn!(error=%diagnostic,agent_id=%approval_agent_id,"agent runtime approval failed");
                    try_set_state(state.diagnostic,diagnostic.clone());
                    try_set_state(state.status,crate::i18n::substitute_args(state.context.tr("agent_runtime.err_approval_failed"),&[("error",runtime_key_pairing_error_message(diagnostic))]));
                },
            }
        });
        if let Ok(task) = task {
            *self.task.borrow_mut() = Some(task);
        }
    }
}
fn approval_details(scope: &Scope, key: &str, label: Lotus<String>, content: View) -> View {
    let mut content = Some(content);
    Box::new(
        sapid::collapsible(format!("{}-{key}", scope.id().slot()))
            .unstyled()
            .class("agent-approval-details")
            .label(label)
            .content_policy(sapid::ContentPolicy::KeepMounted)
            .content(move || {
                content
                    .take()
                    .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
            }),
    )
}
pub fn agent_runtime_approval_prompt(scope: &Scope, context: Rc<InksonContext>) -> View {
    let state = ApprovalController {
        context: context.clone(),
        owner: scope.downgrade(),
        pending: scope.cage(None),
        handled: scope.cage(HashSet::new()),
        status: scope.cage(String::new()),
        diagnostic: scope.cage(String::new()),
        prepared: scope.cage(None),
        approving: scope.cage(false),
        task: Rc::new(RefCell::new(None)),
    };
    let poll = state.clone();
    let owner = scope.downgrade();
    let _=scope.owner().spawn(async move {
        let mut last_generation=poll.context.session_generation.get();let mut next_fallback=0_u64;
        let mut last_revision=None;let mut retry_notifications=0_u64;
        loop {
            if owner.upgrade().is_none(){return}
            let generation=poll.context.session_generation.get();
            if generation!=last_generation {
                poll.dismiss();try_set_state(poll.handled,HashSet::new());last_generation=generation;
                last_revision=None;next_fallback=0;retry_notifications=0;
            }
            let notifications=poll.context.state_store.read(|store|store.notification_projection().iter().filter_map(agent_runtime_approval_notification).collect::<Vec<_>>());
            if let Some(request)=poll.pending.get(){
                let closed=request.notification_id.as_ref().is_some_and(|id|!notifications.iter().any(|notice|&notice.notification_id==id));
                if closed||approval_has_expired(&request){poll.dismiss();}
            }
            if poll.pending.get().is_none() {
                let now=crate::clock::now_unix_ms();let revision=poll.context.state_revision.get();
                let active=poll.context.active_account.get();let token=poll.context.token.get();
                if let Some(account)=active.as_ref().filter(|_|!token.trim().is_empty()) {
                    let base=account.server_url.to_string();
                    if last_revision!=Some(revision)||now>=retry_notifications {
                        last_revision=Some(revision);retry_notifications=now.saturating_add(5000);
                        if let Some(notice)=notifications.into_iter().find(|notice|!poll.handled.with(|handled|handled.contains(&notice.approval_request_id))) {
                            let result=fetch_agent_runtime_approval(&base,token.clone(),notice).await;
                            if owner.upgrade().is_none(){return}
                            if !poll.context.session_matches(generation,&active){continue}
                            match result {
                                Ok(Some(request))=>poll.discover(request),Ok(None)=>{},
                                Err(error)=>tracing::warn!(error=%error.display_diagnostic(),"Agent approval notification refresh failed"),
                            }
                        }
                    }
                    if poll.pending.get().is_none()&&now>=next_fallback&&fallback_poll_environment_ready()&&approval_fallback_allowed(poll.context.server_description.get().as_ref()) {
                        let result=fetch_pending_agent_runtime_approval(&base,token,poll.handled.get()).await;
                        if owner.upgrade().is_none(){return}
                        if !poll.context.session_matches(generation,&active){continue}
                        let failed=result.is_err();
                        match result {
                            Ok(Some(request))=>poll.discover(request),Ok(None)=>{},
                            Err(error)=>tracing::warn!(error=%error.display_diagnostic(),"Agent approval polling failed"),
                        }
                        next_fallback=now.saturating_add(approval_fallback_delay(failed).as_millis() as u64);
                    }
                }
            }
            crate::runtime_helpers::sleep_for(Duration::from_millis(100)).await;
        }
    });
    let source = scope.bond({
        let state = state.clone();
        let context = context.clone();
        move || (state.pending.get(), context.locale.get())
    });
    reactive(source, move |scope, (request, _)| {
        let Some(request) = request else {
            return Box::new(widget(|_| Ok(())));
        };
        if context.active_account.get().is_none() || context.token.get().trim().is_empty() {
            return Box::new(widget(|_| Ok(())));
        }
        let label = if request.display_name.trim().is_empty() {
            request.agent_slug.clone()
        } else {
            request.display_name.clone()
        };
        let code = format!(
            "{} {}",
            &request.pairing_code[..4],
            &request.pairing_code[4..]
        );
        let expiry = chrono::DateTime::parse_from_rfc3339(&request.pairing_expires_at)
            .map(|time| {
                time.with_timezone(&chrono::Local)
                    .format("%H:%M")
                    .to_string()
            })
            .unwrap_or(request.pairing_expires_at.clone());
        let mut body = vec![paragraph(
            "muted",
            context.translated(scope, "agent_runtime.body"),
        )];
        if request.replacement {
            body.push(paragraph(
                "warning",
                context.translated(scope, "agent_runtime.replacement_warning"),
            ));
        }
        let mut identity = vec![paragraph("agent-runtime-agent-label", label.clone())];
        if !request.agent_slug.trim().is_empty() && request.agent_slug != label {
            identity.push(paragraph(
                "muted",
                crate::i18n::substitute_args(
                    context.tr("agent_runtime.slug"),
                    &[("slug", request.agent_slug.clone())],
                ),
            ));
        }
        body.push(stack("device-pair-approval-device", identity));
        body.push(stack(
            "device-pair-approval-code-block",
            vec![
                paragraph(
                    "muted",
                    context.translated(scope, "agent_runtime.compare_code"),
                ),
                paragraph("device-pair-approval-code mono", code),
                paragraph(
                    "muted",
                    crate::i18n::substitute_args(
                        context.tr("agent_runtime.pairing_expires"),
                        &[("time", expiry)],
                    ),
                ),
            ],
        ));
        let mut permissions = vec![paragraph(
            "",
            context.translated(scope, "agent_runtime.permissions"),
        )];
        permissions.extend(
            approval_scope_summary(&request.key_state.requested_scope)
                .into_iter()
                .map(|permission| paragraph("agent-permission", permission)),
        );
        permissions.push(paragraph(
            "muted",
            context.translated(scope, "agent_runtime.scope_ceiling"),
        ));
        permissions.push(paragraph(
            "muted",
            context.translated(scope, "agent_runtime.until_revoked"),
        ));
        body.push(stack("agent-approval-permissions", permissions));
        let fields = [
            ("agent_runtime.agent_id", request.agent_id.to_string()),
            (
                "agent_runtime.station",
                request
                    .key_state
                    .controller_account_id
                    .station_id
                    .to_string(),
            ),
            (
                "agent_runtime.runtime_key",
                request.public_key_fingerprint.to_string(),
            ),
            (
                "agent_runtime.verification_method",
                request.verification_method.to_string(),
            ),
            (
                "agent_runtime.requested_scope",
                serde_json::to_string_pretty(&request.key_state.requested_scope)
                    .unwrap_or_default(),
            ),
        ];
        let mut details = fields
            .into_iter()
            .map(|(key, value)| {
                stack(
                    "agent-approval-detail",
                    vec![
                        paragraph("", context.translated(scope, key)),
                        paragraph("mono", value),
                    ],
                )
            })
            .collect::<Vec<_>>();
        let supersedes = request
            .key_state
            .active_authorizations
            .iter()
            .map(|authorization| {
                format!(
                    "{} / {}",
                    authorization.key_id, authorization.authorized_event_ref
                )
            })
            .collect::<Vec<_>>()
            .join(
                "
",
            );
        if !supersedes.is_empty() {
            details.push(paragraph(
                "",
                context.translated(scope, "agent_runtime.replaced_authorizations"),
            ));
            details.push(paragraph("mono", supersedes));
        }
        body.push(approval_details(
            scope,
            "agent-approval-technical",
            context
                .translated(scope, "agent_runtime.technical_details")
                .into(),
            stack("agent-approval-detail-list", details),
        ));
        body.push(paragraph("muted", state.status));
        let diagnostic = state.diagnostic;
        let ctx = context.clone();
        body.push(reactive(diagnostic, move |scope, value| {
            if value.is_empty() {
                Box::new(widget(|_| Ok(())))
            } else {
                approval_details(
                    scope,
                    "agent-approval-error",
                    ctx.translated(scope, "agent_runtime.error_details").into(),
                    paragraph("mono", value),
                )
            }
        }));
        let busy = state.approving;
        let enabled = scope.bond(move || !busy.get());
        let reject = state.clone();
        let dismiss = state.clone();
        let approve = state.clone();
        let ctx = context.clone();
        let approve_label = scope.bond(move || {
            ctx.tr(if busy.get() {
                "agent_runtime.approving_button"
            } else {
                "agent_runtime.approve"
            })
        });
        let actions = vec![
            Box::new(
                sapid::button()
                    .unstyled()
                    .class("secondary")
                    .label(context.translated(scope, "agent_runtime.reject_rotate"))
                    .enabled(enabled)
                    .on_press(move || reject.reject()),
            ) as View,
            Box::new(
                sapid::button()
                    .unstyled()
                    .class("secondary")
                    .label(context.translated(scope, "agent_runtime.dismiss"))
                    .enabled(enabled)
                    .on_press(move || dismiss.dismiss()),
            ) as View,
            Box::new(
                sapid::button()
                    .unstyled()
                    .class("primary")
                    .label(approve_label)
                    .enabled(enabled)
                    .on_press(move || approve.approve()),
            ) as View,
        ];
        let content = stack(
            "modal event agent-runtime-approval-dialog",
            vec![
                stack(
                    "modal-head event-head",
                    vec![
                        heading(3, "", context.translated(scope, "agent_runtime.title")),
                        paragraph("muted", context.translated(scope, "agent_runtime.subtitle")),
                    ],
                ),
                stack("modal-body", body),
                line("modal-foot actions", actions),
            ],
        );
        let dismiss = state.clone();
        let mut content = Some(content);
        Box::new(
            sapid::dialog("agent-runtime-approval")
                .unstyled()
                .name(context.translated(scope, "agent_runtime.aria_label"))
                .open(true)
                .show_trigger(false)
                .show_close(false)
                .on_dismiss(move |_| dismiss.dismiss())
                .content(move || {
                    content
                        .take()
                        .unwrap_or_else(|| Box::new(widget(|_| Ok(()))))
                }),
        )
    })
}

#[derive(Clone, Debug)]
struct AgentRuntimeApprovalNotification {
    notification_id: NotificationId,
    approval_request_id: OpaqueLocalId,
    agent_id: DidCoreId,
}

fn agent_runtime_approval_notification(
    value: &crate::state::StoredNotification,
) -> Option<AgentRuntimeApprovalNotification> {
    let (notification_identity, data) = value.agent_runtime_approval()?;
    let arkret_sdk::NotificationIdentity::AgentApproval(notification_id) = notification_identity
    else {
        return None;
    };
    let agent_id = value.agent_runtime_approval_agent_id()?;
    Some(AgentRuntimeApprovalNotification {
        notification_id: notification_id.clone(),
        approval_request_id: data.id.clone(),
        agent_id: agent_id.clone(),
    })
}

async fn fetch_agent_runtime_approval(
    base_url: &str,
    token: String,
    notification: AgentRuntimeApprovalNotification,
) -> std::result::Result<Option<PendingAgentRuntimeApproval>, crate::transport::auth::ApiCallError>
{
    with_authed_sdk_client(base_url, token, move |http| async move {
        let view = http.agent_get(notification.agent_id.as_str()).await?;
        let Some(mut request) = pending_runtime_approval_from_view(&view) else {
            return Ok(None);
        };
        if request.request_key != notification.approval_request_id {
            return Ok(None);
        }
        request.notification_id = Some(notification.notification_id);
        Ok(Some(request))
    })
    .await
}

async fn fetch_pending_agent_runtime_approval(
    base_url: &str,
    token: String,
    handled: HashSet<OpaqueLocalId>,
) -> std::result::Result<Option<PendingAgentRuntimeApproval>, crate::transport::auth::ApiCallError>
{
    with_authed_sdk_client(base_url, token, move |http| async move {
        let list = http.agent_page().await?;
        for row in list.agents {
            let agent_id = row.agent_id.as_str();
            if agent_id.trim().is_empty() {
                continue;
            }
            let view = http.agent_get(agent_id).await?;
            let Some(request) = pending_runtime_approval_from_view(&view) else {
                continue;
            };
            if handled.contains(&request.request_key) {
                continue;
            }
            return Ok(Some(request));
        }
        Ok(None)
    })
    .await
}

fn pending_runtime_approval_from_view(
    view: &arkret_sdk::AgentView,
) -> Option<PendingAgentRuntimeApproval> {
    // Only a terminal (deactivated) agent has no pending approval to surface;
    // a pending runtime-key request only exists while a pairing handle is open
    // (key-management.md §3.6.1).
    if matches!(
        view.agent.lifecycle,
        arkret_sdk::AgentLifecycleState::Deactivated
    ) {
        return None;
    }
    let key_state = view.key_state.as_ref()?;
    let request_value = key_state.pending_runtime_key_request.clone()?;
    let request_json = serde_json::to_string(&request_value).ok()?;
    let summary = summarize_runtime_key_approval_request(&request_json).ok()?;
    let pairing_expires_at =
        arkret_sdk::canonical::format_timestamp_canonical(key_state.pairing_expires_at?);
    if timestamp_has_expired(&pairing_expires_at) {
        return None;
    }
    let agent_id = view.agent.agent_id.clone();
    if agent_id != summary.agent_id {
        return None;
    }
    let pairing_code = key_state.pairing_code.clone()?;
    if pairing_code.len() != 8 || !pairing_code.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let request_key = key_state.approval_request_id.clone()?;
    if request_key != summary.approval_request_id {
        return None;
    }
    Some(PendingAgentRuntimeApproval {
        notification_id: None,
        request_key,
        agent_id,
        display_name: view.agent.display_name.clone().unwrap_or_default(),
        agent_slug: view.agent.slug.clone(),
        pairing_code,
        pairing_expires_at,
        verification_method: summary.verification_method,
        public_key_fingerprint: summary.public_key_fingerprint,
        key_state: key_state.clone(),
        request_json,
        // A replacement pairing is one where the agent already holds an active
        // key — projected as runtime_state replacing (key-management.md §3.6.1).
        replacement: matches!(
            crate::views::agents::model::key_state_runtime_state(key_state),
            arkret_sdk::AgentRuntimeState::Replacing
        ),
    })
}

fn approval_has_expired(request: &PendingAgentRuntimeApproval) -> bool {
    timestamp_has_expired(&request.pairing_expires_at)
}

fn timestamp_has_expired(value: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc) <= chrono::Utc::now())
        .unwrap_or(true)
}

fn approval_fallback_delay(failed: bool) -> Duration {
    let jitter = crate::clock::now_unix_ms() % 6;
    if failed {
        APPROVAL_FALLBACK_MAX_INTERVAL.saturating_sub(Duration::from_secs(jitter))
    } else {
        APPROVAL_FALLBACK_POLL_INTERVAL.saturating_add(Duration::from_secs(jitter))
    }
}

fn approval_fallback_allowed(description: Option<&arkret_sdk::ServiceDescribe>) -> bool {
    description.is_some_and(|description| {
        !description.supported_features.iter().any(|feature| {
            feature == arkret_wire::FeatureDescriptor::AGENT_RUNTIME_APPROVAL_NOTIFICATIONS_V1
        })
    })
}

fn fallback_poll_environment_ready() -> bool {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .map(|window| {
                window.navigator().on_line()
                    && window.document().is_none_or(|document| !document.hidden())
            })
            .unwrap_or(true)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_summary_preserves_unknown_permissions_and_review_requirements() {
        let mut scope = crate::views::agents::requested_scope_for_presets(
            &[
                crate::views::agents::AgentGrantPreset::Read,
                crate::views::agents::AgentGrantPreset::ActOnBehalf,
            ],
            &crate::views::agents::AgentServiceScopePreset::DEFAULTS,
        )
        .unwrap();
        scope.actions.push("ak.future.permission".to_owned());
        let labels = approval_scope_summary(&scope);
        assert_eq!(
            labels
                .iter()
                .filter(|label| **label == crate::i18n::tr("agent_runtime.permission_sync"))
                .count(),
            1
        );
        assert!(
            labels
                .iter()
                .any(|label| label.contains("ak.future.permission"))
        );
        assert!(labels.contains(&crate::i18n::tr("agent_runtime.permission_review")));
    }

    #[test]
    fn approval_list_fallback_requires_a_resolved_service_without_notifications() {
        assert!(!approval_fallback_allowed(None));
        let mut description =
            crate::transport::websocket::tests_support::describe_without_websocket();
        description.supported_features.clear();
        assert!(approval_fallback_allowed(Some(&description)));
        description
            .supported_features
            .push("ak.feature.agent_runtime_approval_notifications.v1".to_owned());
        assert!(!approval_fallback_allowed(Some(&description)));
    }
}
