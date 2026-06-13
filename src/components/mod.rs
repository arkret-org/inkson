use dioxus::prelude::*;

/// CKP-0007 P3B.4 — multi-account avatar dropdown switcher.
/// Lists every profile in [`crate::config::MultiProfileConfig`] and
/// fires `on_switch` / `on_add_account` handlers.
pub mod account_switcher;
pub mod avatar_uploader;
/// CKP-0007 P3B.2 — Circle error toast surfaced from the app shell.
/// Consumes [`crate::circle::CircleErrorKind`] and renders the
/// localized user-facing string.
pub mod circle_error_toast;
/// CKP-0007 P3B.2 — Circle scope picker + composer banner + confidential-
/// discussion-of cross-link banner. Shared between the new-Flow form,
/// the composer header, and the Flow detail view.
pub mod circle_scope_picker;
pub mod device_authorization_prompt;
pub mod dismissible_popup;
pub mod empty_state;
/// Entry-time warning for accounts whose visible PCR / Realm projections do
/// not yet show the recommended metadata+content E2EE floor.
pub mod encryption_floor_prompt;
/// P5 — recoverable error display + retry affordance. Pairs with the
/// passive `ErrorBanner` below: this one carries a request_id and a
/// retry callback so users can copy the soland trace ID into bug
/// reports without leaving the failing surface.
pub mod error_boundary;
/// One-time account-MLS-secret BACKUP prompt — the mirror of `mls_unlock`.
/// Mounted once near the app shell; renders only when boot/per-Realm
/// detection flags `needs_mls_backup` (local secret exists, no server backup).
pub mod mls_backup_prompt;
/// key-management.md §7.10 — continuous `mls_history` backup job: re-uploads
/// the per-Realm group-state envelope (series successor chain) after every
/// accepted `ck.mls.commit`, once the 24-word Recovery Key is configured.
pub mod mls_history_backup;
/// Account-MLS-secret auto-unlock prompt — the recovery-passphrase banner
/// that restores encrypted history on a fresh device. Mounted once near the
/// app shell; renders only when boot detection flags `needs_mls_unlock`.
pub mod mls_unlock;
pub mod recovery_key_setup_prompt;
// YOU-02-008: the P3B.5 `offline_pending_badge` component was removed
// together with the unwired offline-queue modules (see `src/lib.rs`).
pub mod permission_pill;
/// G3.Y3 — global policy-deny toast / banner. Mounted once near the
/// app shell so any view inherits the 403 surface without needing to
/// thread its own error UI.
pub mod policy_deny_banner;
/// P3B.8 — "Report a problem" dialog + crash telemetry opt-in
/// toggle. Crash reports are off by default.
pub mod report_problem;
pub mod self_attribution;
pub mod shortcut_help;
/// P5 — skeleton loaders for feed / agent list / key-backup history.
pub mod skeleton;
pub mod sync_badge;
/// P5 — three-mode theme switcher (light / dark / follow system) with
/// persistence routed through the caller's local-state path.
pub mod theme_switcher;
/// P3B.6 — `NeedsVerificationBadge` (red, message-card) +
/// `RealmClassBadge` (Principal / Collaboration, switcher).
pub mod verify_badges;
pub mod write_state;

pub use account_switcher::AccountSwitcher;
pub use avatar_uploader::{AvatarUploader, AvatarUploaderProps};
pub use circle_error_toast::{
    CircleErrorToast, CircleErrorToastProps, maybe_dispatch_circle_error, push_circle_error,
    take_circle_error,
};
pub use circle_scope_picker::{
    CircleComposerBanner, CircleScopePicker, ConfidentialDiscussionOfBanner,
};
pub use device_authorization_prompt::DeviceAuthorizationPrompt;
pub use dismissible_popup::{DismissiblePopup, DismissiblePopupProps};
pub use empty_state::{EmptyState, EmptyStateKind};
pub use encryption_floor_prompt::EncryptionFloorPrompt;
pub use error_boundary::{ErrorBoundary, RetryableError};
pub use mls_backup_prompt::{
    MlsBackupPrompt, MlsBackupSignal, maybe_flag_mls_backup_after_encrypted_write,
    try_needs_mls_backup_signal,
};
pub(crate) use mls_backup_prompt::{
    mark_mls_recovery_backup_configured, mls_recovery_backup_configured,
    schedule_mls_private_plaintext_backup_after_encrypted_write,
};
pub use mls_history_backup::{MlsHistoryBackupStatus, mls_history_backup_status};
pub(crate) use mls_history_backup::{
    schedule_mls_history_backup_after_commit, upload_mls_history_backup_now,
};
pub use mls_unlock::{MlsRecoverySetupMissingBanner, MlsUnlockPrompt};
pub use permission_pill::{
    Discoverability, HistoryVisibility, JoinRule, PermissionPill, PermissionPillRow,
};
pub use policy_deny_banner::{
    POLICY_DENY_AUTODISMISS_MS, PolicyDenyBanner, PolicyDenyEvent, is_policy_deny_code,
    push_policy_deny, take_policy_deny,
};
pub use recovery_key_setup_prompt::RecoveryKeySetupPrompt;
pub use report_problem::{
    CrashTelemetryPrefs, CrashTelemetryToggle, ReportProblemButton, build_report_body,
};
pub use self_attribution::SelfAttributionBadge;
pub use shortcut_help::{
    ShortcutHelpOverlay, default_shortcuts, key_event_is_help_trigger, target_is_text_input,
};
pub use skeleton::{SkeletonCard, SkeletonLine, SkeletonList};
pub use sync_badge::{SyncBadge, SyncBadgeState};
pub use theme_switcher::{ThemeMode, ThemeSwitcher};
pub use verify_badges::{
    NeedsVerificationBadge, RealmClass, RealmClassBadge, TrustCacheBadge, TrustCacheState,
    trust_cache_state,
};
pub use write_state::{WriteState, WriteStateExplainer, WriteStateIcon, WriteStatePill};

// LazyLinkBadge is declared below.

#[component]
pub fn Metric(label: String, value: String) -> Element {
    rsx! {
        div { class: "metric",
            strong { "{label}" }
            span { "{value}" }
        }
    }
}

#[component]
pub fn StatusBadge(status: String, kind: Option<String>) -> Element {
    let cls = match kind.as_deref().unwrap_or("info") {
        "success" => "badge badge-success",
        "error" => "badge badge-error",
        "warning" => "badge badge-warning",
        _ => "badge badge-info",
    };
    rsx! {
        span { class: "{cls}", "{status}" }
    }
}

#[component]
pub fn SecurityStateBadge(encrypted: bool, compact: bool, test_id: Option<String>) -> Element {
    let state_class = if encrypted { "encrypted" } else { "plaintext" };
    let icon = if encrypted { "lock" } else { "alert" };
    let label = if encrypted {
        "Encrypted"
    } else {
        "Unencrypted"
    };
    let title = if encrypted {
        "Encrypted communication is enabled."
    } else {
        "Unencrypted plaintext communication."
    };
    let mut class = format!("security-state-badge security-state-badge--{state_class}");
    if compact {
        class.push_str(" security-state-badge--compact");
    }
    let testid = test_id.unwrap_or_else(|| format!("security-state-{state_class}"));

    rsx! {
        span {
            class: "{class}",
            "data-testid": "{testid}",
            role: "img",
            title: "{title}",
            "aria-label": "{title}",
            UiIcon { name: icon }
            if !compact {
                span { class: "security-state-badge-label", "{label}" }
            }
        }
    }
}

#[component]
pub fn UiIcon(name: String) -> Element {
    let path = match name.as_str() {
        "archive" => "M21 8v13H3V8M1 3h22v5H1V3Zm9 9h4",
        "activity" => "M3 12h4l3 7 4-14 3 7h4",
        "at-sign" => "M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8M16 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z",
        "alert" => {
            "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0ZM12 9v4m0 4h.01"
        }
        "bell" => "M6 8a6 6 0 0 1 12 0c0 7 3 7 3 9H3c0-2 3-2 3-9m4 13a2 2 0 0 0 4 0",
        "bot" => {
            "M12 8V4m-4 0h8M5 8h14a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-8a2 2 0 0 1 2-2Zm4 5h.01M15 13h.01M9 17h6"
        }
        "board" => "M3 3h18v18H3V3Zm6 0v18m6-18v18M3 9h18",
        "calendar" => {
            "M8 2v4M16 2v4M3 10h18M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2Z"
        }
        "check" => "M20 6 9 17l-5-5",
        "chevron-down" => "m6 9 6 6 6-6",
        "chevron-left" => "m15 18-6-6 6-6",
        "chevron-right" => "m9 18 6-6-6-6",
        "chevron-up" => "m18 15-6-6-6 6",
        "copy" => "M8 4h8l4 4v8a2 2 0 0 1-2 2h-8a2 2 0 0 1-2-2V4Zm8 0v4h4M4 8v12a2 2 0 0 0 2 2h8",
        "download" => "M12 3v12m0 0 5-5m-5 5-5-5M5 21h14",
        "file" => "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Zm0 0v6h6",
        "folder" => "M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z",
        "globe" => {
            "M2 12h20M12 2a15.3 15.3 0 0 1 0 20M12 2a15.3 15.3 0 0 0 0 20M4.93 4.93A16.1 16.1 0 0 0 19.07 19.07M19.07 4.93A16.1 16.1 0 0 1 4.93 19.07"
        }
        "home" => {
            "M3 10.5 9.5 4a3 3 0 0 1 5 0L21 10.5M5 9.5V20a1 1 0 0 0 1 1h4v-6h4v6h4a1 1 0 0 0 1-1V9.5"
        }
        "image" => {
            "M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5Zm3 13 5-6 4 5 2-3 3 4M8 8.5h.01"
        }
        "inbox" => "M22 12h-6l-2 3h-4l-2-3H2m20 0v7a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-7l3-8h14Z",
        "key" => "M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-2.8-2.8L20 2h2v2l-8.4 8.4ZM7 17h.01",
        "lock" => "M6 10V8a6 6 0 0 1 12 0v2M5 10h14v10H5V10Zm7 4v2",
        "menu" => "M4 6h16M4 12h16M4 18h16",
        "maximize" => "M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7",
        "minimize" => "M4 14h6v6M20 10h-6V4M14 10l7-7M3 21l7-7",
        "message" => "M21 15a4 4 0 0 1-4 4H8l-5 3V7a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4Z",
        "more-horizontal" => "M5 12h.01M12 12h.01M19 12h.01",
        "moon" => "M21 12.8A8.5 8.5 0 1 1 11.2 3a6.5 6.5 0 0 0 9.8 9.8Z",
        "phone" => {
            "M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.12.9.32 1.78.6 2.63a2 2 0 0 1-.45 2.11L8 9.71a16 16 0 0 0 6.29 6.29l1.25-1.25a2 2 0 0 1 2.11-.45c.85.28 1.73.48 2.63.6A2 2 0 0 1 22 16.92Z"
        }
        "pin" => {
            "M12 17v5M5 17h14v-2.76a2 2 0 0 0-1.11-1.79l-1.78-.89A2 2 0 0 1 15 9.76V5h1a2 2 0 0 0 0-4H8a2 2 0 0 0 0 4h1v4.76a2 2 0 0 1-1.11 1.79l-1.78.89A2 2 0 0 0 5 14.24Z"
        }
        "plus" => "M12 5v14M5 12h14",
        "qr-code" => {
            "M3 3h6v6H3V3Zm12 0h6v6h-6V3ZM3 15h6v6H3v-6Zm12 0h2v2h-2v-2Zm4 0h2v2h-2v-2Zm-4 4h2v2h-2v-2Zm4 0h2v2h-2v-2Z"
        }
        "panel-left-close" => {
            "M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5Zm6-2v18m6-6-3-3 3-3"
        }
        "panel-left-open" => {
            "M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5Zm6-2v18m3 6 3-3-3-3"
        }
        "panel-right-close" => {
            "M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5Zm12-2v18m-6-6 3-3-3-3"
        }
        "panel-right-open" => {
            "M3 5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5Zm12-2v18m-3 6-3-3 3-3"
        }
        "refresh" => "M21 12a9 9 0 0 1-15.5 6.3L3 16m0 0v5h5M3 12A9 9 0 0 1 18.5 5.7L21 8m0 0V3h-5",
        "search" => "m21 21-4.35-4.35M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16Z",
        "server" => {
            "M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Zm0 0v6c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"
        }
        "share" => "M4 12v7a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-7M12 16V4m0 0 5 5m-5-5-5 5",
        "settings" => {
            "M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06A1.7 1.7 0 0 0 15 19.4a1.7 1.7 0 0 0-1 1.55V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1-1.55 1.7 1.7 0 0 0-1.88.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06A1.7 1.7 0 0 0 4.6 15a1.7 1.7 0 0 0-1.55-1H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.55-1 1.7 1.7 0 0 0-.34-1.88l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.55V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1 1.55 1.7 1.7 0 0 0 1.88-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.7 1.7 0 0 0 19.4 9c.25.6.82 1 1.55 1H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.55 1Z"
        }
        "monitor" => "M3 4h18v12H3V4Zm7 16h4m-7 0h10",
        "sun" => {
            "M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72 1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z"
        }
        "timeline" => "M8 6h13M3 6h.01M8 12h13M3 12h.01M8 18h13M3 18h.01",
        "unlock" => "M7 10V8a5 5 0 0 1 9.58-2M5 10h14v10H5V10Zm7 4v2",
        "user" => "M20 21a8 8 0 0 0-16 0M12 13a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z",
        "user-plus" => "M16 21a6 6 0 0 0-12 0M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm9-4v6m-3-3h6",
        "users" => {
            "M16 21a6 6 0 0 0-12 0M10 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm12 10a5 5 0 0 0-5-5M17 3.3a4 4 0 0 1 0 7.4"
        }
        "x" => "M18 6 6 18M6 6l12 12",
        _ => "M12 5v14M5 12h14",
    };

    rsx! {
        svg {
            class: "ui-icon",
            "aria-hidden": "true",
            width: "16",
            height: "16",
            view_box: "0 0 24 24",
            fill: "none",
            stroke: "currentColor",
            stroke_width: "2",
            stroke_linecap: "round",
            stroke_linejoin: "round",
            path { d: "{path}" }
        }
    }
}

#[component]
pub fn HelpTip(text: String) -> Element {
    rsx! {
        span {
            class: "help-tip",
            tabindex: "0",
            title: "{text}",
            "aria-label": "{text}",
            "?"
        }
    }
}

// `EmptyState` lives in `components/empty_state.rs` — see the
// re-export above. The richer typed version replaced the old
// single-prop placeholder that was previously here.

#[component]
pub fn ErrorBanner(message: String) -> Element {
    rsx! {
        div { class: "event error-banner",
            div { class: "event-head", span { "Error" } span { "" } }
            div { "{message}" }
        }
    }
}

#[component]
pub fn LoadingSpinner(label: Option<String>) -> Element {
    let text = label.unwrap_or_else(|| "Loading...".to_owned());
    rsx! {
        div { class: "event loading",
            div { class: "muted", "{text}" }
        }
    }
}

/// Cross-Space lazy_link badge.
///
/// Protocol rule (`models/object-model-core.md` §2.4.1): a cross-Space
/// Relation's `from_ref` / `to_ref` may point at objects in other Spaces, but
/// only the reference fact is published — content is not copied and read
/// access is not granted. The sync / projection layer must not backfill the
/// target Space's data merely because the source Space is visible. This
/// component renders a consistent UI indicator for that boundary.
#[component]
pub fn LazyLinkBadge(
    /// Opaque reference to the target Space (sha256 digest, ck:space:… ID,
    /// or omitted).
    target_ref: Option<String>,
    /// Short reason: locked / external / restricted / quarantined.
    reason: Option<String>,
) -> Element {
    let reason_text = reason.unwrap_or_else(|| "locked".to_owned());
    let target_full = target_ref.unwrap_or_else(|| "opaque".to_owned());
    let target_text = crate::views::helpers::short_protocol_id(&target_full);
    rsx! {
        span {
            class: "badge amber",
            "data-testid": "lazy-link-badge",
            "title": "object-model-core.md §2.4.1 — cross-Space lazy link: {target_full}",
            "🔒 lazy_link · {reason_text} · {target_text}"
        }
    }
}
