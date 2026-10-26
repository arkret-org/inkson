use std::rc::Rc;

use glory::prelude::*;

use super::*;
use crate::presentation::widgets::*;
use crate::presentation::{InksonContext, View};
pub(crate) fn feature_gate_notice(
    scope: &Scope,
    context: Rc<InksonContext>,
    feature: StationFeature,
    missing: Vec<String>,
    pending: bool,
) -> View {
    let details = scope.cage(false);
    let mut body = vec![
        line(
            "event-head",
            vec![
                plain(context.translated(
                    scope,
                    if pending {
                        "feature_gate.loading"
                    } else {
                        "profile_gate.title"
                    },
                )),
                plain(context.translated(scope, feature.label_key())),
            ],
        ),
        paragraph(
            "entity-title",
            context.translated(
                scope,
                if pending {
                    "feature_gate.loading_body"
                } else {
                    "profile_gate.body"
                },
            ),
        ),
    ];
    if !pending {
        body.push(Box::new(
            sapid::button()
                .unstyled()
                .class("btn secondary link-button")
                .label(scope.bond({
                    let context = context.clone();
                    move || {
                        context.tr(if details.get() {
                            "friendly.identifier.hide_technical"
                        } else {
                            "friendly.identifier.show_technical"
                        })
                    }
                }))
                .on_press(move || details.revise(|value| *value = !*value)),
        ));
        body.push(reactive(details, move |scope, show| {
            if show {
                stack(
                    "muted profile-gate-technical",
                    std::iter::once(plain(context.translated(scope, "feature_gate.missing")))
                        .chain(missing.iter().cloned().map(plain))
                        .collect(),
                )
            } else {
                empty()
            }
        }));
    }
    stack(
        "timeline",
        vec![stack(
            if pending {
                "event"
            } else {
                "event error-banner"
            },
            body,
        )],
    )
}
pub(super) fn deferred_feature_gate() -> View {
    stack("timeline", vec![])
}
/// i18n key for a route's breadcrumb label.
///
/// Returns a key rather than display text so the context bar follows the
/// active locale. Callers resolve it with [`crate::i18n::tr`]; keeping the
/// mapping key-only leaves this function free of the Dioxus runtime and
/// directly unit-testable.
pub(super) fn route_label_key(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "route.dashboard",
        Route::Login | Route::AuthCallback => "route.login",
        Route::Register => "route.register",
        Route::RealmsManage => "route.realms_manage",
        Route::PrincipalControl => "route.principal_control",
        Route::Realm { .. } => "route.realm",
        Route::Chat { .. } => "route.chat",
        Route::DirectConversation { .. } => "route.direct",
        Route::ContactsManage => "route.contacts_manage",
        Route::Contacts => "route.contacts",
        Route::Directory => "route.directory",
        Route::Setup => "route.setup_realms",
        Route::SetupSection { section } => match section.as_str() {
            "realms" => "route.setup_realms",
            "new-space" => "route.setup_new_space",
            _ => "route.setup",
        },
        Route::Settings => "route.settings",
        Route::SettingsSection { section, .. } => settings_route_label_key(section),
        Route::NotificationsSettings => "route.notifications",
        Route::RealmMembers { .. } => "route.realm_members",
        Route::Circles { .. } | Route::CircleDetail { .. } => "route.circles",
        Route::RealmAdmin { .. } => "route.realm_admin",
        Route::RealmAdminSection { section, .. } => match section.as_str() {
            "profile" => "route.realm_admin.profile",
            "access" => "route.realm_admin.access",
            "security" => "route.realm_admin.security",
            "federation" => "route.realm_admin.federation",
            "repair" => "route.realm_admin.repair",
            _ => "route.realm_admin",
        },
        Route::Audit => "route.audit",
        Route::Developer => "route.developer",
        Route::Kanban
        | Route::KanbanRealm { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => "route.board",
        Route::Notifications => "route.notifications",
        Route::Call { .. } => "route.call",
        Route::Recovery => "route.recovery",
        Route::SettingsDevices => "route.devices",
        Route::SettingsDevicesPair => "route.devices_pair",
        Route::SettingsRecovery => "route.recovery",
        Route::Onboarding => "route.onboarding",
        Route::Quarantine => "route.quarantine",
        Route::Applets => "route.applets",
        Route::Search => "route.directory",
    }
}

/// i18n key for a settings section's breadcrumb label. Several sections
/// share a destination (`security` / `key-backup` / `recovery`), so the
/// mapping collapses onto the same key.
pub(super) fn settings_route_label_key(section: &str) -> &'static str {
    match section {
        "server" => "route.settings.server",
        "devices" => "route.devices",
        "storage" => "route.settings.storage",
        "encryption" => "route.settings.encryption",
        "security" | "key-backup" | "recovery" => "route.recovery",
        "mimi" => "route.settings.mimi",
        "push" | "notifications" => "route.notifications",
        "privacy" => "route.settings.privacy",
        "invite-policy" | "invite_policy" => "route.settings.invite_policy",
        "blocklist" | "blocked-users" => "route.settings.blocklist",
        "capabilities" => "route.settings.capabilities",
        "audit" | "audit-log" => "route.audit",
        "developer" | "developer-tools" => "route.developer",
        "theme" => "route.settings.theme",
        "release" => "route.settings.release",
        _ => "route.settings",
    }
}
