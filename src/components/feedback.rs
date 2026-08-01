//! Unified feedback surface — toast queue + [`ToastHost`] + [`AppBanner`].
//!
//! `docs/design/unified-feedback-system.md` Wave 0: a single stacked
//! toast host replaces the per-concern feedback surfaces. Every producer
//! writes directly to this single queue.
//!
//! Producer side is a process-wide `Mutex<VecDeque<Toast>>` rather than
//! a Dioxus context/Signal on purpose: producers (the HTTP layer, sync
//! engine, arbitrary async blocks) may run on any thread and outside
//! the Dioxus runtime, so [`push_toast`] must not require a component
//! scope. The consumer ([`ToastHost`], mounted once near the app shell)
//! drains the queue at the top of each render — the renderer thread is
//! the only consumer, so the lock is uncontended in practice.
//!
//! Localization happens exclusively at render time inside the host
//! (`tr(key)` + `{placeholder}` substitution, mirroring
//! `realm_admin::durability::FormError::localize`). Business code only
//! passes i18n keys + args, which keeps `tr()` out of non-UI threads
//! and unit tests.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use dioxus::prelude::*;

use crate::circle::CircleErrorKind;
use crate::i18n::tr;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};

/// Severity of a toast; drives styling, ARIA role and auto-dismiss.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeedbackSeverity {
    Success,
    Info,
    Warning,
    Error,
}

impl FeedbackSeverity {
    /// Stable lowercase name, used for `data-severity` and CSS variants.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }

    /// Auto-dismiss window: transient confirmations disappear quickly,
    /// warnings/errors stay long enough to be read (or are dismissed
    /// manually).
    pub fn autodismiss_ms(self) -> u64 {
        match self {
            Self::Success | Self::Info => 5_000,
            Self::Warning | Self::Error => 10_000,
        }
    }
}

/// One queued feedback item. `key` is an i18n key localized at render
/// time; `args` are `{placeholder}` substitutions applied after lookup.
#[derive(Clone, Debug, PartialEq)]
pub struct Toast {
    pub severity: FeedbackSeverity,
    /// i18n key, localized at render time inside [`ToastHost`].
    pub key: String,
    /// `{placeholder}` substitutions applied to the localized string.
    pub args: Vec<(&'static str, String)>,
    /// Used when `tr(key) == key` (dictionary miss) so the user still
    /// sees a readable message instead of a raw key.
    pub fallback: Option<String>,
    /// Raw error / protocol detail. When present the toast renders a
    /// copy-to-clipboard affordance instead of stuffing the raw payload
    /// into the visible message.
    pub detail: Option<String>,
    /// Wall-clock capture timestamp (ms since unix epoch).
    pub captured_at_ms: u64,
    /// Monotonic id — keyed rendering and targeted dismissal.
    pub id: u64,
    /// Producer channel tag (`data-source` on the rendered item).
    pub source: &'static str,
}

impl Toast {
    pub fn new(
        severity: FeedbackSeverity,
        key: impl Into<String>,
        args: Vec<(&'static str, String)>,
    ) -> Self {
        Self {
            severity,
            key: key.into(),
            args,
            fallback: None,
            detail: None,
            captured_at_ms: crate::clock::now_unix_ms(),
            id: next_toast_id(),
            source: "app",
        }
    }
}

static TOAST_ID: AtomicU64 = AtomicU64::new(1);

fn next_toast_id() -> u64 {
    TOAST_ID.fetch_add(1, Ordering::Relaxed)
}

/// Queue capacity — beyond this the OLDEST entry is dropped. A burst of
/// failures should surface the most recent state, not replay history.
pub const TOAST_QUEUE_CAP: usize = 20;

/// Maximum simultaneously visible toasts; the rest collapse into a
/// single "+N more" row until expanded.
pub const TOAST_VISIBLE_MAX: usize = 3;

/// Process-wide toast queue. Concurrent successes and failures remain visible.
static TOAST_QUEUE: Mutex<VecDeque<Toast>> = Mutex::new(VecDeque::new());

fn enqueue_toast(toast: Toast) {
    if let Ok(mut queue) = TOAST_QUEUE.lock() {
        while queue.len() >= TOAST_QUEUE_CAP {
            queue.pop_front();
        }
        queue.push_back(toast);
    }
}

/// Producer entry point — callable from any thread / async block, with
/// or without a Dioxus runtime.
pub fn push_toast(
    severity: FeedbackSeverity,
    key: impl Into<String>,
    args: Vec<(&'static str, String)>,
) {
    enqueue_toast(Toast::new(severity, key, args));
}

pub fn toast_success(key: impl Into<String>, args: Vec<(&'static str, String)>) {
    push_toast(FeedbackSeverity::Success, key, args);
}

pub fn toast_info(key: impl Into<String>, args: Vec<(&'static str, String)>) {
    push_toast(FeedbackSeverity::Info, key, args);
}

pub fn toast_warning(key: impl Into<String>, args: Vec<(&'static str, String)>) {
    push_toast(FeedbackSeverity::Warning, key, args);
}

/// Error variant additionally carries the raw error / protocol detail
/// for the copy-to-clipboard affordance.
pub fn toast_error(
    key: impl Into<String>,
    args: Vec<(&'static str, String)>,
    detail: Option<String>,
) {
    let mut toast = Toast::new(FeedbackSeverity::Error, key, args);
    toast.detail = detail;
    enqueue_toast(toast);
}

/// Consumer entry point — drain everything queued so far. Only called
/// by [`ToastHost`]; public for tests.
pub fn drain_toasts() -> Vec<Toast> {
    match TOAST_QUEUE.lock() {
        Ok(mut queue) => queue.drain(..).collect(),
        Err(_) => Vec::new(),
    }
}

/// Convert an HTTP-layer policy denial into a warning toast.
pub fn policy_deny_to_toast(
    code: String,
    message: String,
    obligations: Vec<serde_json::Value>,
) -> Toast {
    let detail = serde_json::to_string(&serde_json::json!({
        "code": code,
        "message": message,
        "obligations": obligations,
    }))
    .ok();
    Toast {
        severity: FeedbackSeverity::Warning,
        key: "feedback.policy_denied".to_owned(),
        args: vec![("code", code), ("message", message)],
        fallback: None,
        detail,
        captured_at_ms: crate::clock::now_unix_ms(),
        id: next_toast_id(),
        source: "policy-deny",
    }
}

pub fn push_policy_deny_toast(
    code: impl Into<String>,
    message: impl Into<String>,
    obligations: Vec<serde_json::Value>,
) {
    enqueue_toast(policy_deny_to_toast(
        code.into(),
        message.into(),
        obligations,
    ));
}

pub fn is_policy_deny_code(code: &str) -> bool {
    code == arkret_sdk::error::ErrorCode::POLICY_DENIED
        || code == arkret_sdk::error::ErrorCode::CAPABILITY_DENIED
        || matches!(
            code,
            "policy_blocked"
                | "policy_timeout"
                | "capability_revoked"
                | "missing_capability"
                | "consent_required"
                | "consent_denied"
                | "delegation_exceeds_grantor_expiry"
                | "capability_not_held"
        )
}

/// Bridge: a queued AKP-0007 [`CircleErrorKind`] becomes an Error
/// toast. The kind's English fallback covers locales that don't carry
/// the `error.circle.*` key yet.
pub fn circle_error_to_toast(kind: CircleErrorKind) -> Toast {
    Toast {
        severity: FeedbackSeverity::Error,
        key: kind.i18n_key().to_owned(),
        args: Vec::new(),
        fallback: Some(kind.english_fallback().to_owned()),
        detail: None,
        captured_at_ms: crate::clock::now_unix_ms(),
        id: next_toast_id(),
        source: "circle-error",
    }
}

pub fn maybe_dispatch_circle_error(code: &str, reason: Option<&str>) -> bool {
    if let Some(kind) = CircleErrorKind::from_error_code(code) {
        enqueue_toast(circle_error_to_toast(kind));
        return true;
    }
    if let Some(reason) = reason
        && let Some(kind) = CircleErrorKind::from_reason_code(reason)
    {
        enqueue_toast(circle_error_to_toast(kind));
        return true;
    }
    false
}

/// Localize a toast: `tr(key)`, fall back to `toast.fallback` on a
/// dictionary miss (`tr` returns the key itself), then substitute
/// `{placeholder}` args — same pattern as
/// `realm_admin::durability::FormError::localize`.
fn localize_toast_message(toast: &Toast) -> String {
    let translated = tr(&toast.key);
    let message = if translated == toast.key {
        toast.fallback.clone().unwrap_or(translated)
    } else {
        translated
    };
    crate::i18n::substitute_args(message, &toast.args)
}

/// The stacked toast host. Mount ONCE near the top of the app shell.
///
/// Each render it drains all producer queues into a local signal,
/// schedules per-toast auto-dismiss timers, shows at most
/// [`TOAST_VISIBLE_MAX`] items and collapses the rest behind a
/// "+N more" row.
#[component]
pub fn ToastHost() -> Element {
    let mut toasts = use_signal(Vec::<Toast>::new);
    let mut expanded = use_signal(|| false);

    // Opportunistic drain, same pattern as the former PolicyDenyBanner:
    // Dioxus reruns this component whenever other signals tick, so a
    // queued toast is picked up within milliseconds of the producing
    // call. Writing the signal during render triggers exactly one extra
    // rerender (the queue is then empty, so it settles).
    let incoming = drain_toasts();
    if !incoming.is_empty() {
        for toast in &incoming {
            // Auto-dismiss: one task per toast. Removal is keyed on the
            // unique toast id, so a timer firing after a manual dismiss
            // (or after the toast was dropped by the display cap) is a
            // harmless no-op — no "still the same event?" guard needed,
            // unlike the old single-slot banner.
            let id = toast.id;
            let ttl_ms = toast.severity.autodismiss_ms();
            spawn(async move {
                crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(ttl_ms)).await;
                toasts.write().retain(|t| t.id != id);
            });
        }
        let mut list = toasts.write();
        list.extend(incoming);
        // Mirror the queue cap on the displayed list: drop oldest.
        let overflow = list.len().saturating_sub(TOAST_QUEUE_CAP);
        if overflow > 0 {
            list.drain(..overflow);
        }
    }

    let list = toasts.read().clone();
    if list.is_empty() {
        // Reset the expansion state so the next burst starts collapsed.
        if expanded() {
            expanded.set(false);
        }
        return rsx! {};
    }

    let total = list.len();
    let is_expanded = expanded();
    let visible: Vec<Toast> = if is_expanded || total <= TOAST_VISIBLE_MAX {
        list
    } else {
        list[..TOAST_VISIBLE_MAX].to_vec()
    };
    let hidden = total - visible.len();
    let overflow_label =
        crate::i18n::tr_args("feedback.toast_overflow", &[("count", hidden.to_string())]);

    rsx! {
        div {
            class: "toast-host",
            role: "status",
            "aria-live": "polite",
            "data-testid": "toast-host",
            for toast in visible {
                ToastItem { key: "{toast.id}", toast, toasts }
            }
            if hidden > 0 {
                Button {
                    variant: ButtonVariant::Secondary,
                    class: "toast-overflow",
                    "data-testid": "toast-overflow",
                    onclick: move |_| expanded.set(true),
                    "{overflow_label}"
                }
            }
        }
    }
}

/// One visible toast row. Split out so per-item event handlers can
/// capture the toast id / detail without manual loop plumbing.
#[component]
fn ToastItem(toast: Toast, toasts: Signal<Vec<Toast>>) -> Element {
    let mut toasts = toasts;
    let id = toast.id;
    let severity = toast.severity.as_str();
    let message = localize_toast_message(&toast);
    let dismiss_label = tr("feedback.dismiss");
    let copy_label = tr("feedback.copy_detail");
    let detail = toast.detail.clone();
    let icon_name = match toast.severity {
        FeedbackSeverity::Success => "check",
        FeedbackSeverity::Info => "bell",
        FeedbackSeverity::Warning | FeedbackSeverity::Error => "alert",
    };
    // Errors announce assertively on their own; the host container
    // already covers the polite path for everything else.
    let role = if toast.severity == FeedbackSeverity::Error {
        "alert"
    } else {
        "status"
    };

    rsx! {
        div {
            class: "toast toast--{severity}",
            role,
            "data-testid": "toast-item",
            "data-severity": severity,
            "data-i18n-key": "{toast.key}",
            "data-source": toast.source,
            span { class: "toast-severity-icon", "aria-hidden": "true",
                crate::components::UiIcon { name: icon_name }
            }
            div { class: "toast-body",
                p { "{message}" }
            }
            if let Some(detail) = detail {
                Button {
                    variant: ButtonVariant::Ghost,
                    size: ButtonSize::IconSm,
                    class: "btn",
                    "data-testid": "toast-copy-detail",
                    "aria-label": "{copy_label}",
                    title: "{copy_label}",
                    onclick: move |_| {
                        crate::components::mls_backup_prompt::copy_text_to_clipboard(&detail);
                    },
                    crate::components::UiIcon { name: "copy" }
                }
            }
            Button {
                variant: ButtonVariant::Ghost,
                size: ButtonSize::IconSm,
                class: "btn",
                "data-testid": "toast-dismiss",
                "aria-label": "{dismiss_label}",
                onclick: move |_| toasts.write().retain(|t| t.id != id),
                "×"
            }
        }
    }
}

/// Persistent-banner kinds, priority-ordered. Wave 0 only wires
/// `Offline`; later waves add policy (deny storms) and session
/// (expired) banners with the planned precedence
/// offline > policy > session — the single slot always shows the
/// highest-priority active kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppBannerKind {
    Offline,
    // Future (Wave 1+): Policy, SessionExpired.
}

impl AppBannerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
        }
    }

    pub fn i18n_key(self) -> &'static str {
        match self {
            Self::Offline => "feedback.banner_offline",
        }
    }
}

/// Single-slot persistent banner pinned to the top of the app shell.
/// Unlike toasts it has no lifecycle — it shows exactly while its
/// condition holds.
#[component]
pub fn AppBanner(offline: bool) -> Element {
    // Priority resolution: first active kind wins (only Offline exists
    // in Wave 0).
    let kind = if offline {
        Some(AppBannerKind::Offline)
    } else {
        None
    };
    let Some(kind) = kind else {
        return rsx! {};
    };
    let kind_str = kind.as_str();
    let message = tr(kind.i18n_key());

    rsx! {
        div {
            class: "app-banner app-banner--{kind_str}",
            role: "status",
            "aria-live": "polite",
            "data-testid": "app-banner",
            "data-banner-kind": kind_str,
            "{message}"
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // NOTE: no `tr()` in these tests — localization requires a Dioxus
    // runtime. We only test queue semantics and typed conversions.

    // Queue semantics live in ONE test because TOAST_QUEUE is a shared
    // process-wide static and `cargo test` runs tests in parallel;
    // splitting push/drain/overflow across tests would race.
    #[test]
    fn queue_push_drain_and_overflow() {
        // Hermetic start: drop anything a previous test (or another
        // module's test) left behind.
        let _ = drain_toasts();

        // Push / drain round-trip preserves FIFO order and fields.
        push_toast(FeedbackSeverity::Info, "feedback.test_a", vec![]);
        toast_error(
            "feedback.test_b",
            vec![("code", "boom".to_owned())],
            Some("raw detail".to_owned()),
        );
        let drained = drain_toasts();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].key, "feedback.test_a");
        assert_eq!(drained[0].severity, FeedbackSeverity::Info);
        assert_eq!(drained[0].source, "app");
        assert_eq!(drained[1].key, "feedback.test_b");
        assert_eq!(drained[1].severity, FeedbackSeverity::Error);
        assert_eq!(drained[1].detail.as_deref(), Some("raw detail"));
        assert_eq!(drained[1].args, vec![("code", "boom".to_owned())]);
        assert!(drained[1].id > drained[0].id, "ids are monotonic");
        assert!(drained[0].captured_at_ms > 0);
        // Second drain is empty — the queue is take-once.
        assert!(drain_toasts().is_empty());

        // Overflow: pushing past the cap drops the OLDEST entries.
        for i in 0..(TOAST_QUEUE_CAP + 5) {
            push_toast(
                FeedbackSeverity::Info,
                format!("feedback.overflow_{i}"),
                vec![],
            );
        }
        let drained = drain_toasts();
        assert_eq!(drained.len(), TOAST_QUEUE_CAP);
        assert_eq!(drained[0].key, "feedback.overflow_5");
        assert_eq!(
            drained.last().expect("non-empty").key,
            format!("feedback.overflow_{}", TOAST_QUEUE_CAP + 4)
        );
    }

    #[test]
    fn policy_deny_converts_to_warning_toast() {
        let toast = policy_deny_to_toast(
            "policy_denied".to_owned(),
            "external_policy_blocks_user".to_owned(),
            vec![json!({"kind": "log_event", "target": "audit_log"})],
        );
        assert_eq!(toast.severity, FeedbackSeverity::Warning);
        assert_eq!(toast.key, "feedback.policy_denied");
        assert_eq!(toast.source, "policy-deny");
        assert_eq!(
            toast.args,
            vec![
                ("code", "policy_denied".to_owned()),
                ("message", "external_policy_blocks_user".to_owned()),
            ]
        );
        let detail = toast.detail.expect("detail carries the raw transcript");
        assert!(detail.contains("log_event"));
        assert!(detail.contains("policy_denied"));
    }

    #[test]
    fn circle_error_converts_to_error_toast_with_fallback() {
        let toast = circle_error_to_toast(CircleErrorKind::RealmMismatch);
        assert_eq!(toast.severity, FeedbackSeverity::Error);
        assert_eq!(toast.key, CircleErrorKind::RealmMismatch.i18n_key());
        assert_eq!(toast.source, "circle-error");
        assert_eq!(
            toast.fallback.as_deref(),
            Some(CircleErrorKind::RealmMismatch.english_fallback())
        );
        assert!(toast.detail.is_none());
    }

    #[test]
    fn substitute_args_replaces_placeholders() {
        let out = crate::i18n::substitute_args(
            "blocked: {code} — {message}".to_owned(),
            &[
                ("code", "policy_denied".to_owned()),
                ("message", "nope".to_owned()),
            ],
        );
        assert_eq!(out, "blocked: policy_denied — nope");
    }

    #[test]
    fn severity_autodismiss_windows() {
        assert_eq!(FeedbackSeverity::Success.autodismiss_ms(), 5_000);
        assert_eq!(FeedbackSeverity::Info.autodismiss_ms(), 5_000);
        assert_eq!(FeedbackSeverity::Warning.autodismiss_ms(), 10_000);
        assert_eq!(FeedbackSeverity::Error.autodismiss_ms(), 10_000);
    }
}
