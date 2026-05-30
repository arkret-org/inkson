//! Local notification rule evaluator.
//!
//! The protocol treats notification state as a derived projection, not
//! canonical Space truth. This module evaluates the actor-private
//! `cx.push_rules` and `cx.dnd_schedule` account_data payloads against a
//! locally visible event context. It also models the required E2EE fallback:
//! server-side dispatch may issue a blind wakeup for client-side rules, but
//! the client must not show a user-visible banner until it has decrypted and
//! evaluated the rule locally.

pub use contrix_sdk::push_rule_core::WatchLevel;
use contrix_sdk::push_rule_core::{
    self, EventContext as PushRuleEventContext, ShouldNotify as PushRuleDecision,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRulesConfig {
    #[serde(default)]
    pub rules: Vec<PushRule>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushRule {
    pub rule_id: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    #[serde(default = "server_locus")]
    pub evaluation_locus: String,
    #[serde(default)]
    pub conditions: Vec<PushCondition>,
    #[serde(default)]
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushCondition {
    pub kind: String,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default)]
    pub pattern: Option<Value>,
    #[serde(default)]
    pub op: Option<String>,
    #[serde(default)]
    pub value: Option<i64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DndSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub schedule: DndSchedule,
    #[serde(default)]
    pub exceptions: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DndSchedule {
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub periods: Vec<DndPeriod>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DndPeriod {
    pub start: String,
    pub end: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NotificationEvalContext {
    pub event_kind: String,
    pub notification_type: String,
    pub space_id: String,
    pub flow_id: Option<String>,
    pub flow_track: Option<String>,
    pub sender: Option<String>,
    pub body: Option<String>,
    pub is_e2ee: bool,
    /// True when this device has already decrypted the event and can evaluate
    /// `evaluation_locus=client` rules without relying on a blind wakeup.
    pub local_decrypted: bool,
    pub mentions_actor: Option<bool>,
    pub assigned_to_actor: bool,
    pub reply_to_self: bool,
    pub participating_thread_update: bool,
    pub is_direct_message: bool,
    pub member_count: Option<u32>,
    pub priority: Option<String>,
    pub priority_override: bool,
    pub watch_level: Option<WatchLevel>,
    /// Minutes after local midnight in the DND schedule timezone. UI callers
    /// should provide this when rendering deterministic previews; dispatch
    /// callers can omit it to use the host local clock.
    pub now_minutes: Option<u16>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NotificationSound {
    #[default]
    None,
    Default,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationDecision {
    pub should_notify: bool,
    pub highlight: bool,
    pub sound: NotificationSound,
    pub matched_rule_id: Option<String>,
    pub actions: Vec<String>,
    pub muted_short_circuit: bool,
    pub watch_suppressed: bool,
    pub dnd_suppressed: bool,
    pub unresolved_client_evaluation: bool,
    pub blind_wakeup_required: bool,
    pub reason: String,
}

impl NotificationDecision {
    fn dont_notify(reason: impl Into<String>) -> Self {
        Self {
            should_notify: false,
            highlight: false,
            sound: NotificationSound::None,
            matched_rule_id: None,
            actions: Vec::new(),
            muted_short_circuit: false,
            watch_suppressed: false,
            dnd_suppressed: false,
            unresolved_client_evaluation: false,
            blind_wakeup_required: false,
            reason: reason.into(),
        }
    }
}

pub fn parse_push_rules(value: &Value) -> Option<PushRulesConfig> {
    serde_json::from_value(value.clone()).ok()
}

pub fn parse_dnd_settings(value: &Value) -> Option<DndSettings> {
    let body = value.get("dnd").cloned().unwrap_or_else(|| value.clone());
    serde_json::from_value(body).ok()
}

pub fn push_rules_from_account_data(entries: &[Value]) -> Option<PushRulesConfig> {
    account_data_content(entries, "cx.push_rules").and_then(parse_push_rules)
}

pub fn dnd_settings_from_account_data(entries: &[Value]) -> Option<DndSettings> {
    account_data_content(entries, "cx.dnd_schedule").and_then(parse_dnd_settings)
}

pub fn evaluate_notification(
    rules: Option<&PushRulesConfig>,
    dnd: Option<&DndSettings>,
    ctx: &NotificationEvalContext,
) -> NotificationDecision {
    if let Some(decision) = evaluate_watch_gate(ctx) {
        return decision;
    }

    let decision = match rules {
        Some(config) if !config.rules.is_empty() => evaluate_rule_chain(config, ctx),
        _ => default_decision(ctx),
    };

    apply_dnd(decision, dnd, ctx)
}

fn evaluate_rule_chain(
    config: &PushRulesConfig,
    ctx: &NotificationEvalContext,
) -> NotificationDecision {
    for rule in config.rules.iter().filter(|rule| rule.enabled) {
        match rule_matches(rule, ctx) {
            RuleMatch::Matched => {
                return decision_from_actions(
                    rule.actions.clone(),
                    Some(rule.rule_id.clone()),
                    "matched push rule",
                );
            }
            RuleMatch::UnresolvedClient => {
                let mut decision = NotificationDecision::dont_notify(
                    "client-side rule unresolved in E2EE context",
                );
                decision.matched_rule_id = Some(rule.rule_id.clone());
                decision.unresolved_client_evaluation = true;
                decision.blind_wakeup_required = true;
                return decision;
            }
            RuleMatch::NoMatch => {}
        }
    }
    NotificationDecision::dont_notify("no push rule matched")
}

fn default_decision(ctx: &NotificationEvalContext) -> NotificationDecision {
    let mut actions = vec!["notify".to_owned()];
    if directed_event(ctx) {
        actions.push("highlight".to_owned());
    }
    decision_from_actions(actions, None, "default notification policy")
}

fn decision_from_actions(
    actions: Vec<String>,
    matched_rule_id: Option<String>,
    reason: impl Into<String>,
) -> NotificationDecision {
    let dont_notify = actions.iter().any(|action| action == "dont_notify");
    let notify = actions.iter().any(|action| action == "notify") && !dont_notify;
    let sound = if !notify {
        NotificationSound::None
    } else if actions.iter().any(|action| action == "sound_critical") {
        NotificationSound::Critical
    } else if actions.iter().any(|action| action == "sound_default") {
        NotificationSound::Default
    } else {
        NotificationSound::None
    };
    NotificationDecision {
        should_notify: notify,
        highlight: notify && actions.iter().any(|action| action == "highlight"),
        sound,
        matched_rule_id,
        actions,
        muted_short_circuit: false,
        watch_suppressed: false,
        dnd_suppressed: false,
        unresolved_client_evaluation: false,
        blind_wakeup_required: false,
        reason: reason.into(),
    }
}

fn apply_dnd(
    mut decision: NotificationDecision,
    dnd: Option<&DndSettings>,
    ctx: &NotificationEvalContext,
) -> NotificationDecision {
    if !decision.should_notify {
        return decision;
    }
    let Some(dnd) = dnd else {
        return decision;
    };
    if !dnd.enabled || !dnd_active(dnd, ctx.now_minutes.unwrap_or_else(current_local_minute)) {
        return decision;
    }
    if ctx.priority_override
        || ctx
            .priority
            .as_deref()
            .is_some_and(|priority| matches!(priority, "critical" | "high" | "urgent"))
    {
        return decision;
    }
    if decision
        .matched_rule_id
        .as_ref()
        .is_some_and(|rule_id| dnd.exceptions.iter().any(|exception| exception == rule_id))
    {
        return decision;
    }
    decision.should_notify = false;
    decision.sound = NotificationSound::None;
    decision.dnd_suppressed = true;
    decision.reason = "suppressed by dnd schedule".to_owned();
    decision
}

fn effective_watch_level(ctx: &NotificationEvalContext) -> Option<WatchLevel> {
    ctx.watch_level
}

fn evaluate_watch_gate(ctx: &NotificationEvalContext) -> Option<NotificationDecision> {
    let level = effective_watch_level(ctx)?;
    let core_ctx = PushRuleEventContext {
        mentions_actor: ctx.mentions_actor.unwrap_or(false),
        assigned_to_actor: ctx.assigned_to_actor,
        reply_to_self: ctx.reply_to_self,
        participating_thread_update: ctx.participating_thread_update,
        is_e2ee: ctx.is_e2ee,
        local_decrypted: ctx.local_decrypted,
    };
    let (decision, reason) = push_rule_core::evaluate_watch_level(level, &core_ctx);

    match decision {
        PushRuleDecision::Notify => None,
        PushRuleDecision::DontNotify => {
            let mut decision = if reason == push_rule_core::reason_code::MUTED {
                NotificationDecision::dont_notify("watch muted")
            } else {
                NotificationDecision::dont_notify("watch level suppressed event")
            };
            decision.watch_suppressed = true;
            decision.muted_short_circuit = reason == push_rule_core::reason_code::MUTED;
            Some(decision)
        }
        PushRuleDecision::BlindWakeup => {
            let mut decision = NotificationDecision::dont_notify(
                "client-side watch evaluation unresolved in E2EE context",
            );
            decision.unresolved_client_evaluation = true;
            decision.blind_wakeup_required = true;
            Some(decision)
        }
    }
}

fn directed_event(ctx: &NotificationEvalContext) -> bool {
    ctx.mentions_actor.unwrap_or(false) || ctx.assigned_to_actor
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleMatch {
    Matched,
    NoMatch,
    UnresolvedClient,
}

fn rule_matches(rule: &PushRule, ctx: &NotificationEvalContext) -> RuleMatch {
    if rule.evaluation_locus == "client" && ctx.is_e2ee && !ctx.local_decrypted {
        return RuleMatch::UnresolvedClient;
    }

    let mut unresolved = false;
    for condition in &rule.conditions {
        match condition_matches(condition, ctx) {
            ConditionResult::Matched => {}
            ConditionResult::NoMatch => return RuleMatch::NoMatch,
            ConditionResult::UnresolvedClient => unresolved = true,
        }
    }

    if unresolved {
        RuleMatch::UnresolvedClient
    } else {
        RuleMatch::Matched
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConditionResult {
    Matched,
    NoMatch,
    UnresolvedClient,
}

fn condition_matches(condition: &PushCondition, ctx: &NotificationEvalContext) -> ConditionResult {
    match condition.kind.as_str() {
        "field_match" => {
            let Some(field) = condition.field.as_deref() else {
                return ConditionResult::NoMatch;
            };
            let Some(value) = context_field(ctx, field) else {
                return ConditionResult::NoMatch;
            };
            if pattern_matches(condition.pattern.as_ref(), value) {
                ConditionResult::Matched
            } else {
                ConditionResult::NoMatch
            }
        }
        "contains_keyword" => {
            if ctx.is_e2ee && !ctx.local_decrypted {
                return ConditionResult::UnresolvedClient;
            }
            let Some(body) = ctx.body.as_deref() else {
                return ConditionResult::NoMatch;
            };
            if keyword_matches(condition.pattern.as_ref(), body) {
                ConditionResult::Matched
            } else {
                ConditionResult::NoMatch
            }
        }
        "mentions_actor" => match ctx.mentions_actor {
            Some(true) => ConditionResult::Matched,
            Some(false) => ConditionResult::NoMatch,
            None if ctx.is_e2ee && !ctx.local_decrypted => ConditionResult::UnresolvedClient,
            None => ConditionResult::NoMatch,
        },
        "is_direct_message" => bool_result(ctx.is_direct_message),
        "member_count" => member_count_matches(condition, ctx),
        "flow_track" => {
            if ctx
                .flow_track
                .as_deref()
                .is_some_and(|track| pattern_matches(condition.pattern.as_ref(), track))
            {
                ConditionResult::Matched
            } else {
                ConditionResult::NoMatch
            }
        }
        "watch_state" => {
            let level = effective_watch_level(ctx).unwrap_or_default();
            let level = level.as_wire();
            if pattern_matches(condition.pattern.as_ref(), level) {
                ConditionResult::Matched
            } else {
                ConditionResult::NoMatch
            }
        }
        _ => ConditionResult::NoMatch,
    }
}

fn bool_result(value: bool) -> ConditionResult {
    if value {
        ConditionResult::Matched
    } else {
        ConditionResult::NoMatch
    }
}

fn member_count_matches(
    condition: &PushCondition,
    ctx: &NotificationEvalContext,
) -> ConditionResult {
    let Some(member_count) = ctx.member_count.map(i64::from) else {
        return ConditionResult::NoMatch;
    };
    let Some(expected) = condition.value else {
        return ConditionResult::NoMatch;
    };
    let matches = match condition.op.as_deref().unwrap_or("eq") {
        "lt" | "<" => member_count < expected,
        "lte" | "<=" => member_count <= expected,
        "gt" | ">" => member_count > expected,
        "gte" | ">=" => member_count >= expected,
        "neq" | "!=" => member_count != expected,
        _ => member_count == expected,
    };
    bool_result(matches)
}

fn context_field<'a>(ctx: &'a NotificationEvalContext, field: &str) -> Option<&'a str> {
    match field {
        "space_id" => Some(ctx.space_id.as_str()),
        "type" | "kind" | "event_kind" => Some(ctx.event_kind.as_str()),
        "notification_type" => Some(ctx.notification_type.as_str()),
        "flow_id" => ctx.flow_id.as_deref(),
        "sender" => ctx.sender.as_deref(),
        "flow_track" | "track_name" => ctx.flow_track.as_deref(),
        "priority" | "notification_priority" => ctx.priority.as_deref(),
        "watch_state" => effective_watch_level(ctx).map(WatchLevel::as_wire),
        _ => None,
    }
}

fn pattern_matches(pattern: Option<&Value>, value: &str) -> bool {
    match pattern {
        Some(Value::String(pattern)) => glob_match(pattern, value),
        Some(Value::Array(patterns)) => patterns.iter().any(|pattern| {
            pattern
                .as_str()
                .is_some_and(|pattern| glob_match(pattern, value))
        }),
        Some(Value::Bool(expected)) => value.parse::<bool>().ok() == Some(*expected),
        Some(Value::Number(expected)) => expected.to_string() == value,
        None => true,
        _ => false,
    }
}

fn keyword_matches(pattern: Option<&Value>, body: &str) -> bool {
    let body = body.to_lowercase();
    match pattern {
        Some(Value::String(pattern)) => pattern
            .split('|')
            .map(str::trim)
            .filter(|term| !term.is_empty())
            .any(|term| body.contains(&term.to_lowercase())),
        Some(Value::Array(patterns)) => patterns.iter().any(|pattern| {
            pattern
                .as_str()
                .is_some_and(|term| body.contains(&term.to_lowercase()))
        }),
        _ => false,
    }
}

fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }

    let mut remainder = value;
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts = pattern
        .split('*')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        return true;
    }
    if anchored_start {
        let first = parts[0];
        let Some(stripped) = remainder.strip_prefix(first) else {
            return false;
        };
        remainder = stripped;
    }
    for part in parts.iter().skip(usize::from(anchored_start)) {
        let Some(index) = remainder.find(part) else {
            return false;
        };
        remainder = &remainder[index + part.len()..];
    }
    !anchored_end || remainder.is_empty()
}

fn dnd_active(dnd: &DndSettings, minute: u16) -> bool {
    dnd.schedule.periods.iter().any(|period| {
        let Some(start) = parse_hhmm(&period.start) else {
            return false;
        };
        let Some(end) = parse_hhmm(&period.end) else {
            return false;
        };
        if start == end {
            return false;
        }
        if start < end {
            (start..end).contains(&minute)
        } else {
            minute >= start || minute < end
        }
    })
}

fn parse_hhmm(value: &str) -> Option<u16> {
    let (hour, minute) = value.split_once(':')?;
    let hour = hour.parse::<u16>().ok()?;
    let minute = minute.parse::<u16>().ok()?;
    if hour < 24 && minute < 60 {
        Some(hour * 60 + minute)
    } else {
        None
    }
}

fn current_local_minute() -> u16 {
    use chrono::Timelike;

    let now = chrono::Local::now();
    (now.hour() as u16) * 60 + now.minute() as u16
}

fn account_data_content<'a>(entries: &'a [Value], key: &str) -> Option<&'a Value> {
    entries.iter().find_map(|entry| {
        let data_type = entry
            .get("data_type")
            .or_else(|| entry.get("type"))
            .or_else(|| entry.get("key"))
            .and_then(Value::as_str)?;
        if data_type == key {
            Some(entry.get("content").unwrap_or(entry))
        } else {
            None
        }
    })
}

fn enabled_by_default() -> bool {
    true
}

fn server_locus() -> String {
    "server".to_owned()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn message_context() -> NotificationEvalContext {
        NotificationEvalContext {
            event_kind: "cx.message.create".to_owned(),
            notification_type: "message".to_owned(),
            space_id: "cx:space:demo".to_owned(),
            flow_id: Some("cx:flow:demo".to_owned()),
            flow_track: Some("discussion".to_owned()),
            body: Some("urgent launch note".to_owned()),
            watch_level: Some(WatchLevel::All),
            ..Default::default()
        }
    }

    #[test]
    fn push_rules_first_matching_rule_wins() {
        let rules = parse_push_rules(&json!({
            "rules": [
                {
                    "rule_id": "override.mute-space",
                    "kind": "override",
                    "conditions": [
                        {"kind": "field_match", "field": "space_id", "pattern": "cx:space:demo"}
                    ],
                    "actions": ["dont_notify"]
                },
                {
                    "rule_id": "content.urgent",
                    "kind": "content",
                    "conditions": [
                        {"kind": "contains_keyword", "pattern": "urgent"}
                    ],
                    "actions": ["notify", "sound_critical"]
                }
            ]
        }))
        .unwrap();

        let decision = evaluate_notification(Some(&rules), None, &message_context());
        assert!(!decision.should_notify);
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            Some("override.mute-space")
        );
        assert_eq!(decision.actions, vec!["dont_notify".to_owned()]);
    }

    #[test]
    fn watch_muted_short_circuits_before_rule_engine() {
        let rules = parse_push_rules(&json!({
            "rules": [{
                "rule_id": "underride.all",
                "conditions": [{"kind": "watch_state", "pattern": "muted"}],
                "actions": ["notify"]
            }]
        }))
        .unwrap();
        let mut ctx = message_context();
        ctx.watch_level = Some(WatchLevel::Muted);

        let decision = evaluate_notification(Some(&rules), None, &ctx);
        assert!(!decision.should_notify);
        assert!(decision.muted_short_circuit);
        assert!(decision.watch_suppressed);
        assert!(decision.matched_rule_id.is_none());
    }

    #[test]
    fn participating_filters_non_participants() {
        // T4.4 — v1 core: participating requires the receiver to have
        // operated in some cell of the flow (mentions, assigned-to,
        // reply-to-self, or a participating thread update).
        let mut ctx = message_context();
        ctx.watch_level = Some(WatchLevel::Participating);
        // Not directed, not a participant — must be suppressed.
        ctx.mentions_actor = Some(false);
        let decision = evaluate_notification(None, None, &ctx);
        assert!(!decision.should_notify);
        assert!(decision.watch_suppressed);

        // Participating in the thread → delivers.
        ctx.participating_thread_update = true;
        let decision = evaluate_notification(None, None, &ctx);
        assert!(decision.should_notify);

        // Reply-to-self also counts as participation.
        let mut ctx = message_context();
        ctx.watch_level = Some(WatchLevel::Participating);
        ctx.reply_to_self = true;
        let decision = evaluate_notification(None, None, &ctx);
        assert!(decision.should_notify);
    }

    #[test]
    fn all_passes_all_v1_core() {
        // T4.4 — v1 core: `all` delivers every event without the rule
        // engine having to match anything. (The richer rules engine
        // can still fire underrides on top, but watch=all must not
        // pre-suppress anything.)
        let mut ctx = message_context();
        ctx.watch_level = Some(WatchLevel::All);
        ctx.mentions_actor = Some(false);
        ctx.participating_thread_update = false;
        let decision = evaluate_notification(None, None, &ctx);
        assert!(decision.should_notify);
        assert!(!decision.watch_suppressed);
        assert!(!decision.muted_short_circuit);
    }

    #[test]
    fn muted_short_circuit_v1_core() {
        // T4.4 — v1 core: muted is the pre-engine deny rule even when
        // the receiver is directly mentioned.
        let mut ctx = message_context();
        ctx.watch_level = Some(WatchLevel::Muted);
        ctx.mentions_actor = Some(true);
        let decision = evaluate_notification(None, None, &ctx);
        assert!(!decision.should_notify);
        assert!(decision.muted_short_circuit);
        assert!(decision.watch_suppressed);
    }

    #[test]
    fn mentions_only_suppresses_non_directed_flow_events() {
        let mut ctx = message_context();
        ctx.watch_level = Some(WatchLevel::MentionsOnly);
        ctx.mentions_actor = Some(false);

        let decision = evaluate_notification(None, None, &ctx);
        assert!(!decision.should_notify);
        assert!(decision.watch_suppressed);

        ctx.mentions_actor = Some(true);
        let decision = evaluate_notification(None, None, &ctx);
        assert!(decision.should_notify);
        assert!(decision.highlight);
    }

    #[test]
    fn e2ee_unknown_watch_gate_uses_blind_wakeup_not_suppression() {
        for level in [
            WatchLevel::MentionsOnly,
            WatchLevel::Participating,
            WatchLevel::All,
        ] {
            let mut ctx = message_context();
            ctx.watch_level = Some(level);
            ctx.is_e2ee = true;
            ctx.local_decrypted = false;
            ctx.mentions_actor = None;

            let decision = evaluate_notification(None, None, &ctx);

            assert!(!decision.should_notify);
            assert!(!decision.watch_suppressed);
            assert!(!decision.muted_short_circuit);
            assert!(decision.blind_wakeup_required);
            assert!(decision.unresolved_client_evaluation);
        }
    }

    #[test]
    fn e2ee_client_rule_requires_blind_wakeup_until_decrypted() {
        let rules = parse_push_rules(&json!({
            "rules": [{
                "rule_id": "underride.mention",
                "evaluation_locus": "client",
                "conditions": [{"kind": "mentions_actor"}],
                "actions": ["notify", "highlight"]
            }]
        }))
        .unwrap();
        let mut ctx = message_context();
        ctx.is_e2ee = true;
        ctx.local_decrypted = false;
        ctx.mentions_actor = None;

        let decision = evaluate_notification(Some(&rules), None, &ctx);
        assert!(!decision.should_notify);
        assert!(decision.blind_wakeup_required);
        assert!(decision.unresolved_client_evaluation);

        ctx.local_decrypted = true;
        ctx.mentions_actor = Some(true);
        let decision = evaluate_notification(Some(&rules), None, &ctx);
        assert!(decision.should_notify);
        assert!(decision.highlight);
    }

    #[test]
    fn dnd_suppresses_non_exception_rule_inside_cross_midnight_window() {
        let rules = parse_push_rules(&json!({
            "rules": [{
                "rule_id": "content.urgent",
                "conditions": [{"kind": "contains_keyword", "pattern": "urgent"}],
                "actions": ["notify", "sound_critical"]
            }]
        }))
        .unwrap();
        let dnd = parse_dnd_settings(&json!({
            "dnd": {
                "enabled": true,
                "schedule": {
                    "timezone": "Asia/Shanghai",
                    "periods": [{"start": "22:00", "end": "08:00"}]
                },
                "exceptions": []
            }
        }))
        .unwrap();
        let mut ctx = message_context();
        ctx.now_minutes = Some(23 * 60);

        let decision = evaluate_notification(Some(&rules), Some(&dnd), &ctx);
        assert!(!decision.should_notify);
        assert!(decision.dnd_suppressed);

        let mut dnd_with_exception = dnd.clone();
        dnd_with_exception
            .exceptions
            .push("content.urgent".to_owned());
        let decision = evaluate_notification(Some(&rules), Some(&dnd_with_exception), &ctx);
        assert!(decision.should_notify);
        assert_eq!(decision.sound, NotificationSound::Critical);
    }

    #[test]
    fn account_data_helpers_extract_canonical_keys() {
        let entries = vec![
            json!({
                "data_type": "cx.push_rules",
                "content": {"rules": [{"rule_id": "r1", "actions": ["notify"]}]}
            }),
            json!({
                "data_type": "cx.dnd_schedule",
                "content": {"dnd": {"enabled": true}}
            }),
        ];

        assert_eq!(
            push_rules_from_account_data(&entries)
                .unwrap()
                .rules
                .first()
                .unwrap()
                .rule_id,
            "r1"
        );
        assert!(dnd_settings_from_account_data(&entries).unwrap().enabled);
    }
}
