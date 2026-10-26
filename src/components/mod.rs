use std::rc::Rc;

use glory::prelude::*;

use crate::presentation::widgets::{line, paragraph};
use crate::presentation::{InksonContext, View};
pub mod icons;
pub mod platform_io;
pub use icons::ui_icon;

pub mod agent_identity;
pub mod agent_runtime_approval_prompt;
pub mod avatar_uploader;
/// Generic single-flight / debounce / backoff / digest-dedupe scheduler for
/// the private-plaintext backup job.
pub(crate) mod backup_job_scheduler;
/// P3B.2 — Circle error queue. Producers push
/// [`crate::circle::CircleErrorKind`]; the unified `feedback::ToastHost`
/// drains it and renders the localized user-facing string.
/// P3B.2 — Circle scope picker + composer banner + confidential-
/// discussion-of cross-link banner. Shared between the new-Strand form,
/// the composer header, and the Strand detail view.
pub mod circle_scope_picker;
pub mod device_authorization_prompt;
pub mod did_resolution_health_banner;
pub mod dismissible_popup;
pub mod empty_state;
/// Unified feedback surface (docs/design/unified-feedback-system.md
/// Wave 0): process-wide toast queue + `ToastHost` (stacked toasts,
/// drains the policy-deny and circle-error queues too) + `AppBanner`
/// (single-slot persistent banner, offline state).
pub mod feedback;
pub mod generated_avatar;
/// One-time account-MLS-secret BACKUP prompt — the mirror of `mls_unlock`.
/// Mounted once near the app shell; renders only when boot/per-Realm
/// detection flags `needs_mls_backup` (local secret exists, no server backup).
pub mod mls_backup_prompt;
pub(crate) mod mls_creator_retry;
/// Account-MLS-secret auto-unlock prompt — the recovery-passphrase banner
/// that restores encrypted history on a fresh device. Mounted once near the
/// app shell; renders only when boot detection flags `needs_mls_unlock`.
pub mod mls_unlock;
pub mod qr_share_panel;
pub mod recovery_key_setup_prompt;
// The P3B.5 `offline_pending_badge` component was removed
// together with the unwired offline-queue modules (see `src/lib.rs`).
/// G3.Y3 — global policy-deny event queue. Producers (the HTTP layer)
/// push denies; the unified `feedback::ToastHost` mounted near the app
/// shell surfaces them so no view needs to thread its own error UI.
/// P3B.8 — crash telemetry opt-in preference. Crash reports are off
/// by default.
pub mod report_problem;
pub mod self_attribution;
pub mod shortcut_help;
pub mod sync_badge;
/// P5 — three-mode theme switcher (light / dark / follow system) with
/// persistence routed through the caller's local-state path.
pub mod theme_switcher;
/// Verification and identity-cache status badges.
pub mod visibility_pill;
pub mod write_state;

pub use agent_identity::{AgentIdentityProps, agent_identity};
pub use agent_runtime_approval_prompt::agent_runtime_approval_prompt;
pub use avatar_uploader::{AvatarUploaderProps, avatar_uploader};
pub use circle_scope_picker::{
    CircleComposerBannerProps, CircleIdentityBadgeProps, CircleScopePickerProps,
    ConfidentialDiscussionOfBannerProps, circle_composer_banner, circle_identity_badge,
    circle_scope_picker, confidential_discussion_of_banner,
};
pub use device_authorization_prompt::device_authorization_prompt;
pub use did_resolution_health_banner::{DidResolutionHealth, did_resolution_health_banner};
pub use dismissible_popup::{DismissiblePopupProps, dismissible_popup};
pub use empty_state::{EmptyStateKind, EmptyStateProps, empty_state};
pub use feedback::{
    AppBannerKind, FeedbackSeverity, Toast, app_banner, is_policy_deny_code,
    maybe_dispatch_circle_error, push_policy_deny_toast, push_toast, toast_error, toast_host,
    toast_info, toast_success, toast_warning,
};
pub use generated_avatar::{
    GeneratedAvatarProps, IdentityAvatarProps, generated_avatar, identity_avatar,
    identity_avatar_inline,
};
pub(crate) use mls_backup_prompt::{
    mark_mls_recovery_backup_configured, mls_recovery_backup_configured,
    schedule_mls_recovery_backups_after_encrypted_write,
};
pub use mls_backup_prompt::{
    maybe_auto_backup_mls_after_encrypted_write, mls_backup_prompt, try_needs_mls_backup_state,
};
pub use mls_unlock::{mls_recovery_setup_missing_banner, mls_unlock_prompt};
pub use qr_share_panel::{QrSharePanelProps, qr_share_panel};
pub use recovery_key_setup_prompt::recovery_key_setup_prompt;
pub use report_problem::CrashTelemetryPrefs;
pub use self_attribution::{
    ActorIdentityLabelProps, SelfAttributionBadgeProps, actor_identity_label,
    self_attribution_badge, self_attribution_badge_inline,
};
pub use shortcut_help::{
    default_shortcuts, key_event_is_help_trigger, shortcut_help_overlay, target_is_text_input,
};
pub use sync_badge::{SyncBadgeProps, SyncBadgeState, sync_badge};
pub use theme_switcher::{ThemeMode, ThemeSwitcherProps, theme_switcher};
pub use visibility_pill::{
    Discoverability, HistoryAccess, JoinRule, VisibilityPillProps, VisibilityPillRowProps,
    visibility_pill, visibility_pill_row,
};
pub use write_state::{WriteState, WriteStateBadgeProps, write_state_badge, write_state_icon};

#[derive(Clone, Default)]
pub struct SecurityStateBadgeProps {
    pub encrypted: bool,
    pub compact: bool,
    pub test_id: Option<String>,
    pub unknown: bool,
}
pub fn security_state_badge(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: SecurityStateBadgeProps,
) -> View {
    let state = if props.unknown {
        "unknown"
    } else if props.encrypted {
        "encrypted"
    } else {
        "plaintext"
    };
    let icon = if props.unknown {
        "help-circle"
    } else if props.encrypted {
        "shield-check"
    } else {
        "alert"
    };
    let mut children = vec![ui_icon(icon)];
    if !props.compact {
        let label = if props.unknown {
            context.translated(scope, "realm.security_unknown").into()
        } else {
            Lotus::from(if props.encrypted {
                "Encrypted".to_owned()
            } else {
                "Unencrypted".to_owned()
            })
        };
        children.push(paragraph("security-state-badge-label", label));
    }
    line(
        format!(
            "security-state-badge security-state-badge--{state}{} {}",
            if props.compact {
                " security-state-badge--compact"
            } else {
                ""
            },
            props.test_id.unwrap_or_default()
        ),
        children,
    )
}
#[derive(Clone)]
pub struct HelpTipProps {
    pub text: String,
}
#[cfg(target_arch = "wasm32")]
pub fn button_hint(
    context: Rc<InksonContext>,
    key: String,
    label: impl Into<Lotus<String>>,
    description: impl Into<Lotus<String>>,
    target: impl FnMut(sapid::FloatingTarget) -> glory::ui::Button + 'static,
) -> View {
    Box::new(
        sapid::tooltip(key)
            .theme(context.theme_tokens())
            .label(label)
            .text(description)
            .target(target),
    )
}
#[cfg(not(target_arch = "wasm32"))]
pub fn native_hint(
    scope: &Scope,
    context: Rc<InksonContext>,
    key: String,
    label: String,
    description: String,
    visual: &str,
    class: String,
) -> View {
    let id = match glory::render::SemanticId::new(format!("{key}-trigger")) {
        Ok(id) => id,
        Err(error) => {
            scope.report_error(error);
            return crate::presentation::widgets::empty();
        }
    };
    let open = scope.cage(false);
    let trigger_id = id.clone();
    let metadata = scope.bond(move || {
        Some(Box::new(glory::render::Semantics {
            id: Some(trigger_id.clone()),
            popup: Some(glory::render::PopupKind::Dialog),
            expanded: Some(open.get()),
            ..Default::default()
        }))
    });
    let trigger = button()
        .class(class)
        .name(label.clone())
        .label(visual.to_owned())
        .semantics(metadata)
        .on(glory::render::EventKind::Activate, move |_| {
            open.revise(|open| *open = !*open)
        });
    let dialog = sapid::dialog(key)
        .unstyled()
        .class("modal native-hint-panel")
        .name(label.clone())
        .title(label)
        .open(open)
        .show_trigger(false)
        .return_focus(id)
        .close_label(context.translated(scope, "common.close"))
        .on_open_change(move |next| open.revise(|open| *open = next))
        .content(move || text().content(description.clone()));
    Box::new(group().fill((trigger, dialog)))
}
pub fn help_tip(scope: &Scope, context: Rc<InksonContext>, props: HelpTipProps) -> View {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let key = format!("help-tip-{}", NEXT.fetch_add(1, Ordering::Relaxed));
    #[cfg(target_arch = "wasm32")]
    {
        let name = props.text.clone();
        let _ = scope;
        button_hint(
            context,
            key,
            props.text.clone(),
            props.text,
            move |target| target.button(button().class("help-tip").label("?").name(name.clone())),
        )
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        native_hint(
            scope,
            context,
            key,
            props.text.clone(),
            props.text,
            "?",
            "help-tip".into(),
        )
    }
}

#[cfg(all(target_arch = "wasm32", feature = "web", feature = "spec-conformance"))]
mod message_menu_fixture;

#[cfg(all(test, feature = "desktop", not(target_arch = "wasm32")))]
mod native_admission_tests;
