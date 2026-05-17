//! Agent Workspace — controller's private mirror Space entry.
//!
//! Spec: `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md`
//! (`cx.profile.agent_workspace.v1`).
//!
//! This view is the UI surface for the mirror Space pattern: users
//! command their own agents privately while the source Flow only sees a
//! transparency stub. The dashboard shows three groups stacked from
//! most-urgent to historical:
//!
//! 1. **Pending action** (top, sticky) — tasks whose transparency cell is
//!    `lost` OR source_authority cell is `revoked`. Controller must
//!    `reconfirm` or `cancel`. Rendered with orange/red emphasis so users
//!    can find them at-a-glance even if the list grows long.
//! 2. **In flight** — `execution_state = active` and gate-passing.
//!    Normal working tasks.
//! 3. **Recently completed** — terminal-state tasks, last 10.
//!
//! The lower section lists the user's agents and which source Spaces they
//! are active in.
//!
//! Task detail page (`AgentTaskPage`) is a separate route that shows the
//! three FSM cell chips, the importer'd source context (via
//! `context_anchor`), the agent's drafts, the conversation, and the
//! publish-to-source flow.

use dioxus::prelude::*;
use dioxus_router::Link;

use crate::i18n::tr;
use crate::routes::Route;

// ─────────────────────────────────────────────────────────────────────────
// FSM cell types (UI-side mirrors of the SDK enums; we keep our own
// representation so the view doesn't depend on the SDK full-surface in
// the wasm build).
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionState {
    PendingSourceStub,
    Active,
    Completed,
    CancelledStubRejected,
    CancelledOrphan,
    CancelledByController,
}

impl ExecutionState {
    pub fn label(self) -> &'static str {
        match self {
            ExecutionState::PendingSourceStub => "等待源 stub",
            ExecutionState::Active => "进行中",
            ExecutionState::Completed => "已完成",
            ExecutionState::CancelledStubRejected => "已取消（源拒绝）",
            ExecutionState::CancelledOrphan => "已取消（超时）",
            ExecutionState::CancelledByController => "已取消",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecutionState::Completed
                | ExecutionState::CancelledStubRejected
                | ExecutionState::CancelledOrphan
                | ExecutionState::CancelledByController
        )
    }

    /// Color hint for the chip rendering. Uses CSS class names defined in
    /// `app.rs` global stylesheet (`.fsm-chip-{color}`).
    pub fn color_class(self) -> &'static str {
        match self {
            ExecutionState::Active => "fsm-chip-green",
            ExecutionState::PendingSourceStub => "fsm-chip-blue",
            ExecutionState::Completed => "fsm-chip-grey",
            ExecutionState::CancelledStubRejected
            | ExecutionState::CancelledOrphan
            | ExecutionState::CancelledByController => "fsm-chip-grey",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransparencyState {
    Ok,
    Lost,
    ReconfirmedAfterLoss,
}

impl TransparencyState {
    pub fn label(self) -> &'static str {
        match self {
            TransparencyState::Ok => "透明",
            TransparencyState::Lost => "源 stub 已撤回",
            TransparencyState::ReconfirmedAfterLoss => "已确认继续",
        }
    }

    pub fn color_class(self) -> &'static str {
        match self {
            TransparencyState::Ok => "fsm-chip-green",
            TransparencyState::Lost => "fsm-chip-orange",
            TransparencyState::ReconfirmedAfterLoss => "fsm-chip-blue",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAuthorityState {
    Ok,
    Revoked,
    ReconfirmedAfterRevoke,
}

impl SourceAuthorityState {
    pub fn label(self) -> &'static str {
        match self {
            SourceAuthorityState::Ok => "授权有效",
            SourceAuthorityState::Revoked => "源权限已撤销",
            SourceAuthorityState::ReconfirmedAfterRevoke => "已确认继续",
        }
    }

    pub fn color_class(self) -> &'static str {
        match self {
            SourceAuthorityState::Ok => "fsm-chip-green",
            SourceAuthorityState::Revoked => "fsm-chip-orange",
            SourceAuthorityState::ReconfirmedAfterRevoke => "fsm-chip-blue",
        }
    }
}

/// Returns true iff the agent runtime gate (§7.3) would allow execution.
pub fn agent_runtime_may_execute(
    execution: ExecutionState,
    transparency: TransparencyState,
    source_authority: SourceAuthorityState,
) -> bool {
    execution == ExecutionState::Active
        && matches!(
            transparency,
            TransparencyState::Ok | TransparencyState::ReconfirmedAfterLoss
        )
        && matches!(
            source_authority,
            SourceAuthorityState::Ok | SourceAuthorityState::ReconfirmedAfterRevoke
        )
}

/// One agent task summary used by the dashboard card list.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentTaskSummary {
    pub agent_task_id: String,
    pub mirror_flow_id: String,
    pub source_space_label: Option<String>, // human-readable, e.g. "ProjectX"
    pub source_flow_label: Option<String>,
    pub agent_label: String, // e.g. "primary_agent"
    pub instruction_preview: String,
    pub execution: ExecutionState,
    pub transparency: TransparencyState,
    pub source_authority: SourceAuthorityState,
    pub last_updated: String, // pre-formatted relative time
}

impl AgentTaskSummary {
    /// A task needs the controller's attention if either of the
    /// transparency / source_authority dimensions has degraded.
    pub fn needs_attention(&self) -> bool {
        matches!(self.transparency, TransparencyState::Lost)
            || matches!(self.source_authority, SourceAuthorityState::Revoked)
    }

    /// True iff the task is actively running per the gate.
    pub fn is_in_flight(&self) -> bool {
        !self.execution.is_terminal()
            && !self.needs_attention()
            && agent_runtime_may_execute(self.execution, self.transparency, self.source_authority)
    }
}

/// One agent the user controls.
#[derive(Clone, Debug, PartialEq)]
pub struct OwnedAgentSummary {
    pub agent_did: String,
    pub display_name: String,
    /// Source Space names the agent is currently an active member of.
    pub active_in_sources: Vec<String>,
    /// Whether agent is also a member of the mirror Space ("consulting" use).
    pub in_mirror_space: bool,
}

// ─────────────────────────────────────────────────────────────────────────
// Dashboard component
// ─────────────────────────────────────────────────────────────────────────

#[component]
pub fn AgentWorkspaceDashboard(
    pending: Signal<Vec<AgentTaskSummary>>,
    in_flight: Signal<Vec<AgentTaskSummary>>,
    recent: Signal<Vec<AgentTaskSummary>>,
    agents: Signal<Vec<OwnedAgentSummary>>,
) -> Element {
    let pending_count = pending.read().len();
    let in_flight_count = in_flight.read().len();
    let recent_count = recent.read().len();
    let agents_count = agents.read().len();

    rsx! {
        section {
            class: "agent-workspace-dashboard",
            "data-testid": "agent-workspace-dashboard",
            header {
                class: "agent-workspace-header",
                h1 { {tr("agent_workspace.dashboard.title")} }
                div {
                    class: "agent-workspace-header-actions",
                    button {
                        class: "primary",
                        "data-testid": "agent-workspace-add-agent",
                        title: tr("agent_workspace.add_agent.hint"),
                        "{tr(\"agent_workspace.add_agent\")}"
                    }
                    Link {
                        class: "secondary",
                        to: Route::Agents,
                        "{tr(\"agent_workspace.protocol_session_monitor\")}"
                    }
                }
            }

            // Pending attention (sticky high-priority block)
            if pending_count > 0 {
                div {
                    class: "agent-workspace-pending sticky",
                    "data-testid": "agent-workspace-pending",
                    "role": "alert",
                    "aria-live": "polite",
                    h2 {
                        class: "agent-workspace-section-title pending",
                        "⚠ "
                        "{tr(\"agent_workspace.pending\")}"
                        " ("
                        "{pending_count}"
                        ")"
                    }
                    p {
                        class: "agent-workspace-section-subtitle",
                        "{tr(\"agent_workspace.pending.subtitle\")}"
                    }
                    div {
                        class: "agent-workspace-cards",
                        for task in pending.read().iter() {
                            AgentTaskCard {
                                task: task.clone(),
                                emphasis: CardEmphasis::Pending,
                            }
                        }
                    }
                }
            }

            // In-flight (active and gate-passing tasks)
            div {
                class: "agent-workspace-in-flight",
                "data-testid": "agent-workspace-in-flight",
                h2 {
                    class: "agent-workspace-section-title",
                    "▶ "
                    "{tr(\"agent_workspace.in_flight\")}"
                    " ("
                    "{in_flight_count}"
                    ")"
                }
                if in_flight_count == 0 {
                    EmptyInFlight {}
                } else {
                    div {
                        class: "agent-workspace-cards",
                        for task in in_flight.read().iter() {
                            AgentTaskCard {
                                task: task.clone(),
                                emphasis: CardEmphasis::Normal,
                            }
                        }
                    }
                }
            }

            // Recently completed (collapsed by default if > 0)
            if recent_count > 0 {
                details {
                    class: "agent-workspace-recent",
                    "data-testid": "agent-workspace-recent",
                    summary {
                        class: "agent-workspace-section-title",
                        "✓ "
                        "{tr(\"agent_workspace.recent\")}"
                        " ("
                        "{recent_count}"
                        ")"
                    }
                    div {
                        class: "agent-workspace-cards",
                        for task in recent.read().iter() {
                            AgentTaskCard {
                                task: task.clone(),
                                emphasis: CardEmphasis::Muted,
                            }
                        }
                    }
                }
            }

            // My agents list
            div {
                class: "agent-workspace-agents",
                "data-testid": "agent-workspace-agents",
                h2 {
                    class: "agent-workspace-section-title",
                    "{tr(\"agent_workspace.my_agents\")}"
                    " ("
                    "{agents_count}"
                    ")"
                }
                if agents_count == 0 {
                    EmptyAgentList {}
                } else {
                    ul {
                        class: "agent-workspace-agent-list",
                        for agent in agents.read().iter() {
                            OwnedAgentRow { agent: agent.clone() }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CardEmphasis {
    Pending,
    Normal,
    Muted,
}

#[component]
fn AgentTaskCard(task: AgentTaskSummary, emphasis: CardEmphasis) -> Element {
    let class = match emphasis {
        CardEmphasis::Pending => "agent-task-card emphasis-pending",
        CardEmphasis::Normal => "agent-task-card",
        CardEmphasis::Muted => "agent-task-card emphasis-muted",
    };
    let test_id = format!("agent-task-card-{}", task.agent_task_id);
    let agent_task_id = task.agent_task_id.clone();
    let source_label = match (&task.source_space_label, &task.source_flow_label) {
        (Some(s), Some(f)) => format!("#{}/{}", s, f),
        (Some(s), None) => format!("#{}", s),
        _ => tr("agent_workspace.task.no_source"),
    };
    let banner_message = pending_banner_message(&task);
    rsx! {
        div {
            class: "{class}",
            "data-testid": "{test_id}",
            div {
                class: "agent-task-card-header",
                span {
                    class: "agent-task-card-source",
                    "{source_label}"
                }
                span {
                    class: "agent-task-card-agent",
                    "🤖 {task.agent_label}"
                }
                span {
                    class: "agent-task-card-updated",
                    "{task.last_updated}"
                }
            }
            div {
                class: "agent-task-card-instruction",
                "{task.instruction_preview}"
            }
            if let Some(msg) = banner_message {
                div {
                    class: "agent-task-card-banner",
                    "role": "alert",
                    "{msg}"
                }
            }
            FsmChipRow {
                execution: task.execution,
                transparency: task.transparency,
                source_authority: task.source_authority,
            }
            div {
                class: "agent-task-card-actions",
                Link {
                    class: "secondary",
                    to: Route::AgentTask { task_id: agent_task_id.clone() },
                    "{tr(\"agent_workspace.task.open\")}"
                }
                if task.needs_attention() {
                    button {
                        class: "primary",
                        "data-testid": "agent-task-card-reconfirm-{agent_task_id}",
                        "{tr(\"agent_workspace.task.reconfirm\")}"
                    }
                    button {
                        class: "danger",
                        "data-testid": "agent-task-card-cancel-{agent_task_id}",
                        "{tr(\"agent_workspace.task.cancel\")}"
                    }
                }
            }
        }
    }
}

fn pending_banner_message(task: &AgentTaskSummary) -> Option<String> {
    let mut parts = Vec::new();
    if matches!(task.transparency, TransparencyState::Lost) {
        parts.push(tr("agent_workspace.banner.transparency_lost"));
    }
    if matches!(task.source_authority, SourceAuthorityState::Revoked) {
        parts.push(tr("agent_workspace.banner.source_authority_revoked"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" · "))
    }
}

#[component]
fn FsmChipRow(
    execution: ExecutionState,
    transparency: TransparencyState,
    source_authority: SourceAuthorityState,
) -> Element {
    rsx! {
        div {
            class: "fsm-chip-row",
            "aria-label": tr("agent_workspace.fsm.aria_label"),
            FsmChip {
                kind: tr("agent_workspace.fsm.execution"),
                label: execution.label().to_owned(),
                color: execution.color_class().to_owned(),
                testid: "fsm-chip-execution".to_owned(),
            }
            FsmChip {
                kind: tr("agent_workspace.fsm.transparency"),
                label: transparency.label().to_owned(),
                color: transparency.color_class().to_owned(),
                testid: "fsm-chip-transparency".to_owned(),
            }
            FsmChip {
                kind: tr("agent_workspace.fsm.source_authority"),
                label: source_authority.label().to_owned(),
                color: source_authority.color_class().to_owned(),
                testid: "fsm-chip-source-authority".to_owned(),
            }
        }
    }
}

#[component]
fn FsmChip(kind: String, label: String, color: String, testid: String) -> Element {
    rsx! {
        div {
            class: "fsm-chip {color}",
            "data-testid": "{testid}",
            title: "{kind}: {label}",
            span { class: "fsm-chip-kind", "{kind}" }
            span { class: "fsm-chip-label", "{label}" }
        }
    }
}

#[component]
fn OwnedAgentRow(agent: OwnedAgentSummary) -> Element {
    let active_count = agent.active_in_sources.len();
    let active_label = if active_count == 0 {
        tr("agent_workspace.agent.no_active_sources")
    } else {
        agent.active_in_sources.join(", ")
    };
    rsx! {
        li {
            class: "agent-workspace-agent-row",
            "data-testid": "agent-row-{agent.agent_did}",
            span {
                class: "agent-workspace-agent-dot",
                "●"
            }
            span {
                class: "agent-workspace-agent-name",
                "{agent.display_name}"
            }
            span {
                class: "agent-workspace-agent-active",
                if agent.in_mirror_space {
                    span {
                        class: "agent-workspace-agent-consulting-pill",
                        "{tr(\"agent_workspace.agent.consulting\")}"
                    }
                }
                "{active_label}"
            }
        }
    }
}

#[component]
fn EmptyInFlight() -> Element {
    rsx! {
        div {
            class: "agent-workspace-empty",
            "data-testid": "agent-workspace-empty-in-flight",
            p {
                {tr("agent_workspace.empty.in_flight.message")}
            }
            p {
                class: "agent-workspace-empty-hint",
                {tr("agent_workspace.empty.in_flight.hint")}
            }
        }
    }
}

#[component]
fn EmptyAgentList() -> Element {
    rsx! {
        div {
            class: "agent-workspace-empty",
            "data-testid": "agent-workspace-empty-agents",
            p {
                {tr("agent_workspace.empty.agents.message")}
            }
            button {
                class: "primary",
                "data-testid": "agent-workspace-empty-add-agent",
                "{tr(\"agent_workspace.add_first_agent\")}"
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Task detail page
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct AgentTaskDetail {
    pub summary: AgentTaskSummary,
    pub source_anchor: Option<String>,
    pub instruction_full: String,
    pub agent_draft: Option<String>,
    pub conversation: Vec<TaskConversationLine>,
    pub audit_trail: Vec<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TaskConversationLine {
    pub speaker_label: String, // "你" or "🤖 agent"
    pub text: String,
    pub timestamp: String,
}

#[component]
pub fn AgentTaskDetailPage(task_id: String, detail: Signal<Option<AgentTaskDetail>>) -> Element {
    let detail_value = detail.read();
    let Some(d) = detail_value.clone() else {
        return rsx! {
            section {
                class: "agent-task-detail-loading",
                "data-testid": "agent-task-detail-loading",
                "{tr(\"agent_workspace.task.loading\")}"
            }
        };
    };
    drop(detail_value);

    let banner_message = pending_banner_message(&d.summary);
    let publish_disabled = d.summary.execution.is_terminal()
        || d.summary.needs_attention();

    rsx! {
        section {
            class: "agent-task-detail",
            "data-testid": "agent-task-detail",
            header {
                class: "agent-task-detail-header",
                Link {
                    class: "secondary",
                    to: Route::AgentWorkspace,
                    "← {tr(\"agent_workspace.back\")}"
                }
                h1 {
                    {format!("{} / {}",
                        d.summary.source_space_label.clone().unwrap_or_default(),
                        d.summary.source_flow_label.clone().unwrap_or_default())}
                }
            }

            if let Some(msg) = banner_message {
                div {
                    class: "agent-task-detail-banner",
                    "role": "alert",
                    "data-testid": "agent-task-detail-banner",
                    p { "⚠ {msg}" }
                    div {
                        class: "agent-task-detail-banner-actions",
                        button {
                            class: "primary",
                            "data-testid": "agent-task-detail-reconfirm",
                            "{tr(\"agent_workspace.task.reconfirm\")}"
                        }
                        button {
                            class: "danger",
                            "data-testid": "agent-task-detail-cancel",
                            "{tr(\"agent_workspace.task.cancel\")}"
                        }
                    }
                }
            }

            div {
                class: "agent-task-detail-fsm",
                FsmChipRow {
                    execution: d.summary.execution,
                    transparency: d.summary.transparency,
                    source_authority: d.summary.source_authority,
                }
            }

            if let Some(anchor) = &d.source_anchor {
                div {
                    class: "agent-task-detail-anchor",
                    "📍 {tr(\"agent_workspace.task.anchor\")}: "
                    span { class: "monospace", "{anchor}" }
                }
            }

            div {
                class: "agent-task-detail-section",
                h2 { "💬 {tr(\"agent_workspace.task.instruction\")}" }
                pre {
                    class: "agent-task-detail-instruction",
                    "{d.instruction_full}"
                }
            }

            if let Some(draft) = &d.agent_draft {
                div {
                    class: "agent-task-detail-section",
                    h2 { "🤖 {tr(\"agent_workspace.task.draft\")}" }
                    pre {
                        class: "agent-task-detail-draft",
                        "{draft}"
                    }
                    div {
                        class: "agent-task-detail-draft-actions",
                        button {
                            class: "primary",
                            "data-testid": "agent-task-detail-publish",
                            disabled: publish_disabled,
                            title: if publish_disabled {
                                tr("agent_workspace.task.publish_disabled_reason")
                            } else {
                                tr("agent_workspace.task.publish_hint")
                            },
                            "📤 {tr(\"agent_workspace.task.publish\")}"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "agent-task-detail-mark-complete",
                            "✓ {tr(\"agent_workspace.task.mark_complete\")}"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "agent-task-detail-rewrite",
                            "🔄 {tr(\"agent_workspace.task.rewrite\")}"
                        }
                    }
                }
            }

            div {
                class: "agent-task-detail-section",
                h2 { "📝 {tr(\"agent_workspace.task.conversation\")}" }
                ul {
                    class: "agent-task-detail-conversation",
                    for line in d.conversation.iter() {
                        li {
                            class: "agent-task-detail-conversation-line",
                            span { class: "speaker", "{line.speaker_label}: " }
                            span { class: "text", "{line.text}" }
                            span { class: "ts", "{line.timestamp}" }
                        }
                    }
                }
                div {
                    class: "agent-task-detail-conversation-compose",
                    textarea {
                        "data-testid": "agent-task-detail-compose",
                        placeholder: tr("agent_workspace.task.compose_placeholder"),
                    }
                    button {
                        class: "primary",
                        "data-testid": "agent-task-detail-send",
                        "{tr(\"agent_workspace.task.send\")}"
                    }
                }
            }

            details {
                class: "agent-task-detail-section",
                summary { h2 { "🔍 {tr(\"agent_workspace.task.audit_trail\")}" } }
                ul {
                    class: "agent-task-detail-audit",
                    for entry in d.audit_trail.iter() {
                        li { "{entry}" }
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Publish-to-source modal
// (AW-3.7 + AW-3.20: default signing identity = self + 仅文字最小披露)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishSignerChoice {
    /// `created_by = controller principal` — agent draft is sent as user's
    /// own message. **v1 default**: maximum attribution simplicity.
    AsSelf,
    /// `created_by = controller principal` + `cx.content.import_attestation`
    /// block annotating "drafted by agent X" (audit-transparent fork).
    AsSelfWithAgentAttribution,
}

impl Default for PublishSignerChoice {
    fn default() -> Self {
        // AW-3.20 — default = my-own + 仅文字 (minimal disclosure).
        PublishSignerChoice::AsSelf
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PublishToSourceArgs {
    pub task_id: String,
    pub source_flow_label: String,
    pub draft_preview: String,
    pub current_execution_state: ExecutionState,
}

impl PublishToSourceArgs {
    /// AW-3.7 + AW-3.20 + §4.7 read-then-write: publish is enabled iff the
    /// task is still `active`. Terminal / pending / locked states show a
    /// disabled button with explanatory tooltip.
    pub fn publish_enabled(&self) -> bool {
        self.current_execution_state == ExecutionState::Active
    }

    pub fn publish_disabled_reason(&self) -> Option<&'static str> {
        match self.current_execution_state {
            ExecutionState::Active => None,
            ExecutionState::PendingSourceStub => Some(
                "task pending Phase 3 reconcile; agent has not produced a final draft yet",
            ),
            ExecutionState::Completed => Some("task already completed"),
            ExecutionState::CancelledStubRejected
            | ExecutionState::CancelledOrphan
            | ExecutionState::CancelledByController => Some("task cancelled"),
        }
    }
}

#[component]
pub fn PublishToSourceModal(
    args: PublishToSourceArgs,
    visible: Signal<bool>,
    signer_choice: Signal<PublishSignerChoice>,
) -> Element {
    if !visible() {
        return rsx! { div {} };
    }
    let publish_enabled = args.publish_enabled();
    let disabled_reason = args.publish_disabled_reason();
    let current_choice = signer_choice();
    let testid = format!("publish-modal-{}", args.task_id);
    rsx! {
        div {
            class: "publish-to-source-modal-backdrop",
            "data-testid": "{testid}-backdrop",
            div {
                class: "publish-to-source-modal",
                "role": "dialog",
                "aria-modal": "true",
                "data-testid": "{testid}",
                header {
                    class: "publish-to-source-modal-header",
                    h2 { {format!("{} {}", tr("agent_workspace.task.publish"), args.source_flow_label)} }
                }
                section {
                    class: "publish-to-source-modal-body",
                    fieldset {
                        legend { "{tr(\"agent_workspace.publish.signer_legend\")}" }
                        label {
                            input {
                                r#type: "radio",
                                name: "publish-signer",
                                value: "as_self",
                                checked: current_choice == PublishSignerChoice::AsSelf,
                                "data-testid": "publish-modal-signer-self",
                                onchange: move |_| signer_choice.set(PublishSignerChoice::AsSelf),
                            }
                            "{tr(\"agent_workspace.publish.signer_self\")}"
                        }
                        label {
                            input {
                                r#type: "radio",
                                name: "publish-signer",
                                value: "as_self_with_attribution",
                                checked: current_choice == PublishSignerChoice::AsSelfWithAgentAttribution,
                                "data-testid": "publish-modal-signer-self-with-attribution",
                                onchange: move |_| signer_choice.set(PublishSignerChoice::AsSelfWithAgentAttribution),
                            }
                            "{tr(\"agent_workspace.publish.signer_self_with_attribution\")}"
                        }
                    }
                    pre {
                        class: "publish-to-source-modal-preview",
                        "{args.draft_preview}"
                    }
                    if let Some(reason) = disabled_reason {
                        p {
                            class: "publish-to-source-modal-disabled-note",
                            "role": "status",
                            "⚠ Cannot publish: {reason}"
                        }
                    }
                }
                footer {
                    class: "publish-to-source-modal-footer",
                    button {
                        class: "secondary",
                        "data-testid": "publish-modal-cancel",
                        onclick: move |_| visible.set(false),
                        "{tr(\"agent_workspace.publish.cancel\")}"
                    }
                    button {
                        class: "primary",
                        disabled: !publish_enabled,
                        title: disabled_reason.unwrap_or("Publish to source Flow"),
                        "data-testid": "publish-modal-confirm",
                        "{tr(\"agent_workspace.publish.confirm\")}"
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Add Agent modal
// (AW-3.8: add a controller-owned agent to a source Space, with capability
// preset selection)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMemberProfile {
    /// `cx.agent_member.observer` — read_history + read_messages.
    Observer,
    /// `cx.agent_member.read_only` — observer + react.
    ReadOnly,
    /// `cx.agent_member.mention_respond_only` — read_only + write only when
    /// `in_reply_to.mentions=self`. **v1 default** for newly added agents.
    MentionRespondOnly,
    /// `cx.agent_member.full_collaborator` — standard member capability set.
    FullCollaborator,
}

impl Default for AgentMemberProfile {
    fn default() -> Self {
        AgentMemberProfile::MentionRespondOnly
    }
}

impl AgentMemberProfile {
    pub fn label_key(self) -> &'static str {
        match self {
            AgentMemberProfile::Observer => "agent_workspace.add_agent.profile.observer",
            AgentMemberProfile::ReadOnly => "agent_workspace.add_agent.profile.read_only",
            AgentMemberProfile::MentionRespondOnly => {
                "agent_workspace.add_agent.profile.mention_respond_only"
            }
            AgentMemberProfile::FullCollaborator => {
                "agent_workspace.add_agent.profile.full_collaborator"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AddAgentArgs {
    /// The source Space the agent will be added to (display label).
    pub source_space_label: String,
    /// Controller-owned agent choices.
    pub available_agents: Vec<OwnedAgentSummary>,
}

#[component]
pub fn AddAgentModal(
    args: AddAgentArgs,
    visible: Signal<bool>,
    selected_agent: Signal<Option<String>>,
    selected_profile: Signal<AgentMemberProfile>,
) -> Element {
    if !visible() {
        return rsx! { div {} };
    }
    let testid = "add-agent-modal";
    let current_agent = selected_agent.read().clone();
    let current_profile = selected_profile();
    let selectable = !args.available_agents.is_empty();
    rsx! {
        div {
            class: "add-agent-modal-backdrop",
            "data-testid": "{testid}-backdrop",
            div {
                class: "add-agent-modal",
                "role": "dialog",
                "aria-modal": "true",
                "data-testid": "{testid}",
                header {
                    class: "add-agent-modal-header",
                    h2 {
                        {format!("{} {}", tr("agent_workspace.add_agent"), args.source_space_label)}
                    }
                }
                section {
                    class: "add-agent-modal-body",
                    fieldset {
                        legend { "{tr(\"agent_workspace.add_agent.select_legend\")}" }
                        if selectable {
                            for agent in args.available_agents.iter() {
                                {
                                    let did = agent.agent_did.clone();
                                    let name = agent.display_name.clone();
                                    let is_selected = current_agent.as_deref() == Some(agent.agent_did.as_str());
                                    let did_for_change = did.clone();
                                    rsx! {
                                        label {
                                            input {
                                                r#type: "radio",
                                                name: "add-agent-pick",
                                                value: "{did}",
                                                checked: is_selected,
                                                "data-testid": "add-agent-modal-pick-{did}",
                                                onchange: move |_| selected_agent.set(Some(did_for_change.clone())),
                                            }
                                            "{name}"
                                        }
                                    }
                                }
                            }
                        } else {
                            p {
                                class: "add-agent-modal-empty",
                                {tr("agent_workspace.add_agent.no_owned_agents")}
                            }
                        }
                    }
                    fieldset {
                        legend { "{tr(\"agent_workspace.add_agent.profile_legend\")}" }
                        for choice in [
                            AgentMemberProfile::Observer,
                            AgentMemberProfile::ReadOnly,
                            AgentMemberProfile::MentionRespondOnly,
                            AgentMemberProfile::FullCollaborator,
                        ] {
                            {
                                let testid_value = match choice {
                                    AgentMemberProfile::Observer => "observer",
                                    AgentMemberProfile::ReadOnly => "read-only",
                                    AgentMemberProfile::MentionRespondOnly => "mention-respond-only",
                                    AgentMemberProfile::FullCollaborator => "full-collaborator",
                                };
                                let label = tr(choice.label_key());
                                rsx! {
                                    label {
                                        input {
                                            r#type: "radio",
                                            name: "add-agent-profile",
                                            value: "{testid_value}",
                                            checked: current_profile == choice,
                                            "data-testid": "add-agent-modal-profile-{testid_value}",
                                            onchange: move |_| selected_profile.set(choice),
                                        }
                                        "{label}"
                                    }
                                }
                            }
                        }
                    }
                    p {
                        class: "add-agent-modal-disclosure",
                        {tr("agent_workspace.add_agent.disclosure")}
                    }
                }
                footer {
                    class: "add-agent-modal-footer",
                    button {
                        class: "secondary",
                        "data-testid": "add-agent-modal-cancel",
                        onclick: move |_| visible.set(false),
                        "{tr(\"agent_workspace.add_agent.cancel\")}"
                    }
                    button {
                        class: "primary",
                        disabled: current_agent.is_none() || !selectable,
                        "data-testid": "add-agent-modal-confirm",
                        "{tr(\"agent_workspace.add_agent.send_invite\")}"
                    }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Agent Workspace settings page (AW-3.4)
// ─────────────────────────────────────────────────────────────────────────

#[component]
pub fn AgentWorkspaceSettings(
    agents: Signal<Vec<OwnedAgentSummary>>,
    default_profile: Signal<AgentMemberProfile>,
) -> Element {
    let agents_count = agents.read().len();
    let current_default = default_profile();
    rsx! {
        section {
            class: "agent-workspace-settings",
            "data-testid": "agent-workspace-settings",
            header {
                class: "agent-workspace-settings-header",
                h1 { {tr("agent_workspace.settings.title")} }
            }
            div {
                class: "agent-workspace-settings-section",
                h2 { {tr("agent_workspace.settings.agents")} }
                if agents_count == 0 {
                    p { {tr("agent_workspace.empty.agents.message")} }
                } else {
                    ul {
                        class: "agent-workspace-agent-list",
                        for agent in agents.read().iter() {
                            OwnedAgentRow { agent: agent.clone() }
                        }
                    }
                }
                button {
                    class: "primary",
                    "data-testid": "agent-workspace-settings-add-agent",
                    "{tr(\"agent_workspace.add_agent\")}"
                }
            }
            div {
                class: "agent-workspace-settings-section",
                h2 { {tr("agent_workspace.settings.default_profile")} }
                p {
                    class: "agent-workspace-settings-hint",
                    {tr("agent_workspace.settings.default_profile_hint")}
                }
                for choice in [
                    AgentMemberProfile::Observer,
                    AgentMemberProfile::ReadOnly,
                    AgentMemberProfile::MentionRespondOnly,
                    AgentMemberProfile::FullCollaborator,
                ] {
                    {
                        let testid_value = match choice {
                            AgentMemberProfile::Observer => "observer",
                            AgentMemberProfile::ReadOnly => "read-only",
                            AgentMemberProfile::MentionRespondOnly => "mention-respond-only",
                            AgentMemberProfile::FullCollaborator => "full-collaborator",
                        };
                        let label = tr(choice.label_key());
                        rsx! {
                            label {
                                input {
                                    r#type: "radio",
                                    name: "default-profile",
                                    value: "{testid_value}",
                                    checked: current_default == choice,
                                    "data-testid": "agent-workspace-settings-profile-{testid_value}",
                                    onchange: move |_| default_profile.set(choice),
                                }
                                "{label}"
                            }
                        }
                    }
                }
            }
            details {
                class: "agent-workspace-settings-section danger-zone",
                summary {
                    h2 { {tr("agent_workspace.settings.danger_zone")} }
                }
                p {
                    {tr("agent_workspace.settings.teardown_hint")}
                }
                button {
                    class: "danger",
                    "data-testid": "agent-workspace-settings-teardown",
                    {tr("agent_workspace.settings.teardown")}
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Private compose banner + helpers (AW-3.10 scaffolding)
//
// Full SDK `compose_mention_redirect_pair` plumbing is a follow-up; this
// module exposes the detection helper + a tiny banner component that
// chat.rs / timeline.rs can mount when the current draft mentions a
// controller-owned agent. The actual two-Event saga (source-side
// mention_redirect + mirror-side cx.agent_task.create) is still scaffolded
// in the SDK (`contrix::agent_workspace::compute_mirror_*_reservation`)
// but the integration into chat compose send-paths lands in a later
// round (see `_todos.md` AW-3.10 follow-up).
// ─────────────────────────────────────────────────────────────────────────

/// Returns true iff `did` is one of the controller's owned agents.
///
/// chat.rs and timeline.rs MUST call this on each mention candidate's DID
/// to drive (a) the "my agents" mention candidate group highlight, and
/// (b) the private compose banner mount decision.
pub fn is_controller_owned_agent(
    did: &str,
    owned_agents: &[OwnedAgentSummary],
) -> bool {
    owned_agents.iter().any(|a| a.agent_did == did)
}

/// Returns true iff a current draft string ends with an `@my-agent`-style
/// mention pointing at one of the controller's owned agents. Compose UIs
/// should mount [`PrivateComposeBanner`] when this returns true.
///
/// This is a structural check (we don't try to parse a full structured
/// mention from a textarea here — chat.rs already has
/// `parse_structured_mentions`). Callers MAY combine this with their
/// existing mention candidate list to drive a more precise decision.
pub fn draft_mentions_owned_agent(
    last_mentioned_did: Option<&str>,
    owned_agents: &[OwnedAgentSummary],
) -> bool {
    last_mentioned_did
        .map(|did| is_controller_owned_agent(did, owned_agents))
        .unwrap_or(false)
}

/// Banner mounted under the compose textarea when the user is composing a
/// message that targets a controller-owned agent. Visually + a11y signals
/// that the message will be privately routed.
#[component]
pub fn PrivateComposeBanner(agent_display_name: String) -> Element {
    rsx! {
        div {
            class: "private-routing-banner",
            "role": "status",
            "data-testid": "private-compose-banner",
            "{tr(\"agent_workspace.compose.private_routing_notice\")}"
            br {}
            span {
                class: "private-compose-summary-warning",
                "🤖 → {agent_display_name}"
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// agent_membership_change notification renderer (AW-3.12)
// ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMembershipChangeKind {
    /// Agent was added to a source Space.
    Add,
    /// Agent was removed (or capability revoked).
    Remove,
    /// Agent's capability profile was changed.
    ProfileChange,
}

impl AgentMembershipChangeKind {
    pub fn label_key(self) -> &'static str {
        match self {
            AgentMembershipChangeKind::Add => "agent_workspace.notification.added",
            AgentMembershipChangeKind::Remove => "agent_workspace.notification.removed",
            AgentMembershipChangeKind::ProfileChange => {
                "agent_workspace.notification.profile_changed"
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentMembershipChangeNotification {
    pub change_kind: AgentMembershipChangeKind,
    pub agent_display_name: String,
    pub source_space_label: Option<String>,
    pub source_flow_label: Option<String>,
    pub new_profile_label: Option<String>,
}

#[component]
pub fn AgentMembershipChangeRow(notif: AgentMembershipChangeNotification) -> Element {
    let icon = match notif.change_kind {
        AgentMembershipChangeKind::Add => "➕",
        AgentMembershipChangeKind::Remove => "➖",
        AgentMembershipChangeKind::ProfileChange => "🔄",
    };
    let kind_label = tr(notif.change_kind.label_key());
    let target_label = match (&notif.source_space_label, &notif.source_flow_label) {
        (Some(s), Some(f)) => format!("#{}/{}", s, f),
        (Some(s), None) => format!("#{}", s),
        _ => tr("agent_workspace.notification.unknown_target"),
    };
    let testid = format!(
        "notification-agent-membership-{}",
        match notif.change_kind {
            AgentMembershipChangeKind::Add => "add",
            AgentMembershipChangeKind::Remove => "remove",
            AgentMembershipChangeKind::ProfileChange => "profile-change",
        }
    );
    rsx! {
        Link {
            class: "notification-row notification-row-agent-membership",
            "data-testid": "{testid}",
            to: Route::AgentWorkspace,
            span { class: "notification-icon", "{icon}" }
            div {
                class: "notification-body",
                span { class: "notification-headline",
                    "{notif.agent_display_name} {kind_label} {target_label}"
                }
                if let Some(profile) = &notif.new_profile_label {
                    span { class: "notification-detail", "({profile})" }
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn summary_with(
        execution: ExecutionState,
        transparency: TransparencyState,
        source_authority: SourceAuthorityState,
    ) -> AgentTaskSummary {
        AgentTaskSummary {
            agent_task_id: "cx:agent_task:01".to_owned(),
            mirror_flow_id: "cx:flow:01".to_owned(),
            source_space_label: Some("ProjectX".to_owned()),
            source_flow_label: Some("legal-review".to_owned()),
            agent_label: "primary".to_owned(),
            instruction_preview: "summarize...".to_owned(),
            execution,
            transparency,
            source_authority,
            last_updated: "2m ago".to_owned(),
        }
    }

    #[test]
    fn needs_attention_when_transparency_lost() {
        let s = summary_with(
            ExecutionState::Active,
            TransparencyState::Lost,
            SourceAuthorityState::Ok,
        );
        assert!(s.needs_attention());
        assert!(!s.is_in_flight());
    }

    #[test]
    fn needs_attention_when_source_revoked() {
        let s = summary_with(
            ExecutionState::Active,
            TransparencyState::Ok,
            SourceAuthorityState::Revoked,
        );
        assert!(s.needs_attention());
        assert!(!s.is_in_flight());
    }

    #[test]
    fn in_flight_requires_all_clear() {
        let s = summary_with(
            ExecutionState::Active,
            TransparencyState::Ok,
            SourceAuthorityState::Ok,
        );
        assert!(s.is_in_flight());
        assert!(!s.needs_attention());
    }

    #[test]
    fn reconfirmed_states_still_in_flight() {
        let s = summary_with(
            ExecutionState::Active,
            TransparencyState::ReconfirmedAfterLoss,
            SourceAuthorityState::ReconfirmedAfterRevoke,
        );
        // reconfirmed_* still allows the runtime gate to pass even though
        // they signal the controller acknowledged a degraded condition.
        assert!(agent_runtime_may_execute(
            s.execution,
            s.transparency,
            s.source_authority
        ));
        // BUT they should not appear as "pending action" anymore (controller
        // already acted). is_in_flight relies on !needs_attention which
        // checks `Lost`/`Revoked` literals (not their reconfirmed variants).
        assert!(!s.needs_attention());
        assert!(s.is_in_flight());
    }

    #[test]
    fn terminal_execution_not_in_flight() {
        let s = summary_with(
            ExecutionState::Completed,
            TransparencyState::Ok,
            SourceAuthorityState::Ok,
        );
        assert!(!s.is_in_flight());
    }

    // `pending_banner_message` exercises `tr()` (Dioxus runtime) which
    // panics outside a Dioxus scope. We check the structural predicate
    // (needs_attention()) here instead, which is what controls the
    // banner-rendering branch in the view.

    #[test]
    fn banner_rendered_iff_needs_attention() {
        let none_needed = summary_with(
            ExecutionState::Active,
            TransparencyState::Ok,
            SourceAuthorityState::Ok,
        );
        assert!(!none_needed.needs_attention());

        let transparency_only = summary_with(
            ExecutionState::Active,
            TransparencyState::Lost,
            SourceAuthorityState::Ok,
        );
        assert!(transparency_only.needs_attention());

        let source_only = summary_with(
            ExecutionState::Active,
            TransparencyState::Ok,
            SourceAuthorityState::Revoked,
        );
        assert!(source_only.needs_attention());

        let both = summary_with(
            ExecutionState::Active,
            TransparencyState::Lost,
            SourceAuthorityState::Revoked,
        );
        assert!(both.needs_attention());

        // Reconfirmed states do NOT need attention (controller already acted).
        let reconfirmed = summary_with(
            ExecutionState::Active,
            TransparencyState::ReconfirmedAfterLoss,
            SourceAuthorityState::ReconfirmedAfterRevoke,
        );
        assert!(!reconfirmed.needs_attention());
    }

    // ── AW-3.7 + AW-3.20: publish modal gating ──────────────────────────

    fn publish_args_with(state: ExecutionState) -> PublishToSourceArgs {
        PublishToSourceArgs {
            task_id: "cx:agent_task:01".to_owned(),
            source_flow_label: "ProjectX/legal".to_owned(),
            draft_preview: "agent draft text".to_owned(),
            current_execution_state: state,
        }
    }

    #[test]
    fn publish_enabled_only_when_execution_active() {
        assert!(publish_args_with(ExecutionState::Active).publish_enabled());
        assert!(!publish_args_with(ExecutionState::PendingSourceStub).publish_enabled());
        assert!(!publish_args_with(ExecutionState::Completed).publish_enabled());
        assert!(!publish_args_with(ExecutionState::CancelledByController).publish_enabled());
        assert!(!publish_args_with(ExecutionState::CancelledStubRejected).publish_enabled());
        assert!(!publish_args_with(ExecutionState::CancelledOrphan).publish_enabled());
    }

    #[test]
    fn publish_disabled_reason_present_for_terminal_states() {
        assert!(
            publish_args_with(ExecutionState::Active)
                .publish_disabled_reason()
                .is_none()
        );
        for state in [
            ExecutionState::PendingSourceStub,
            ExecutionState::Completed,
            ExecutionState::CancelledByController,
            ExecutionState::CancelledStubRejected,
            ExecutionState::CancelledOrphan,
        ] {
            assert!(
                publish_args_with(state).publish_disabled_reason().is_some(),
                "state {:?} MUST have a disabled reason",
                state
            );
        }
    }

    #[test]
    fn publish_signer_default_is_minimum_disclosure() {
        // AW-3.20: default = AsSelf (no attribution disclosure).
        assert_eq!(PublishSignerChoice::default(), PublishSignerChoice::AsSelf);
    }

    // ── AW-3.8: add-agent profile default ──────────────────────────────

    #[test]
    fn agent_member_profile_default_is_mention_respond_only() {
        // §3.1 + §3.2.5: principle of least authority.
        assert_eq!(
            AgentMemberProfile::default(),
            AgentMemberProfile::MentionRespondOnly
        );
    }

    #[test]
    fn agent_member_profile_label_keys_distinct() {
        let keys = [
            AgentMemberProfile::Observer.label_key(),
            AgentMemberProfile::ReadOnly.label_key(),
            AgentMemberProfile::MentionRespondOnly.label_key(),
            AgentMemberProfile::FullCollaborator.label_key(),
        ];
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }

    // ── AW-3.12: notification renderer kind mapping ──────────────────────

    #[test]
    fn membership_change_kinds_have_distinct_label_keys() {
        let keys = [
            AgentMembershipChangeKind::Add.label_key(),
            AgentMembershipChangeKind::Remove.label_key(),
            AgentMembershipChangeKind::ProfileChange.label_key(),
        ];
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), keys.len());
    }

    // ── AW-3.10: private compose detection ───────────────────────────────

    fn agent(did: &str) -> OwnedAgentSummary {
        OwnedAgentSummary {
            agent_did: did.to_owned(),
            display_name: did.to_owned(),
            active_in_sources: Vec::new(),
            in_mirror_space: true,
        }
    }

    #[test]
    fn is_controller_owned_agent_matches_did() {
        let owned = vec![
            agent("did:web:agent1.example"),
            agent("did:web:agent2.example"),
        ];
        assert!(is_controller_owned_agent("did:web:agent1.example", &owned));
        assert!(is_controller_owned_agent("did:web:agent2.example", &owned));
        assert!(!is_controller_owned_agent(
            "did:web:other-agent.example",
            &owned
        ));
        assert!(!is_controller_owned_agent("did:web:human.example", &owned));
    }

    #[test]
    fn draft_mentions_owned_agent_handles_none() {
        let owned = vec![agent("did:web:agent.example")];
        assert!(draft_mentions_owned_agent(
            Some("did:web:agent.example"),
            &owned
        ));
        assert!(!draft_mentions_owned_agent(None, &owned));
        assert!(!draft_mentions_owned_agent(
            Some("did:web:bob.example"),
            &owned
        ));
    }
}
