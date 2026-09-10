use super::*;

/// Explain the actual view dependency, not a client conformance profile.
#[component]
pub(super) fn FeatureGateNotice(
    feature: StationFeature,
    missing: Vec<String>,
    pending: bool,
) -> Element {
    let mut show_details = use_signal(|| false);
    let title = crate::i18n::tr(if pending {
        "feature_gate.loading"
    } else {
        "profile_gate.title"
    });
    let body = crate::i18n::tr(if pending {
        "feature_gate.loading_body"
    } else {
        "profile_gate.body"
    });
    let toggle_label = crate::i18n::tr(if show_details() {
        "friendly.identifier.hide_technical"
    } else {
        "friendly.identifier.show_technical"
    });
    let friendly = crate::i18n::tr(feature.label_key());
    rsx! {
        div { class: "timeline", "data-testid": "feature-gate-notice",
            div { class: if pending { "event" } else { "event error-banner" },
                div { class: "event-head",
                    span { "{title}" }
                    span { "{friendly}" }
                }
                div { class: "entity-title", "{body}" }
                if !pending {
                    div { class: "profile-gate-details",
                        Button {
                            variant: ButtonVariant::Secondary,
                            r#type: "button",
                            class: "link-button",
                            "data-testid": "feature-gate-toggle-technical",
                            onclick: move |_| show_details.toggle(),
                            "{toggle_label}"
                        }
                        if show_details() {
                            div { class: "muted profile-gate-technical", "data-testid": "feature-gate-technical",
                                div { {crate::i18n::tr("feature_gate.missing")} }
                                for requirement in missing {
                                    div { code { "{requirement}" } }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub(super) fn DeferredFeatureGate(feature: &'static str) -> Element {
    rsx! {
        div {
            class: "timeline",
            "data-testid": "deferred-feature-gate",
            "data-feature": "{feature}",
        }
    }
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
        Route::FileTransfer => "route.files",
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
        Route::VerifyDevice => "route.verify_device",
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
