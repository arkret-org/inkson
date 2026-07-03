use super::*;

/// Translate a protocol-level profile id into the friendly product name
/// that end users see. The raw id remains available in the developer
/// details panel.
pub(super) fn friendly_profile_label(profile: &str) -> String {
    let key = match profile {
        "minimal_client" => "profile_gate.friendly.minimal_client",
        "kanban_mvp" => "profile_gate.friendly.kanban_mvp",
        "chat_mvp" => "profile_gate.friendly.chat_mvp",
        "full_client" => "profile_gate.friendly.full_client",
        "e2ee_client" => "profile_gate.friendly.e2ee_client",
        _ => "profile_gate.friendly.unknown",
    };
    crate::i18n::tr(key)
}

#[component]
pub(super) fn ProfileGateNotice(profile: &'static str) -> Element {
    let show_details = use_signal(|| false);
    let title = crate::i18n::tr("profile_gate.title");
    let body = crate::i18n::tr("profile_gate.body");
    let toggle_label = if *show_details.read() {
        crate::i18n::tr("friendly.identifier.hide_technical")
    } else {
        crate::i18n::tr("friendly.identifier.show_technical")
    };
    let friendly = friendly_profile_label(profile);
    let dev_label = crate::i18n::tr("developer.profile.required");
    let mut show_details = show_details;
    rsx! {
        div { class: "timeline", "data-testid": "profile-gate-notice",
            div { class: "event error-banner",
                div { class: "event-head",
                    span { "{title}" }
                    span { "{friendly}" }
                }
                div { class: "entity-title", "{body}" }
                div { class: "profile-gate-details",
                    Button {
                        variant: ButtonVariant::Secondary,
                        r#type: "button",
                        class: "link-button",
                        "data-testid": "profile-gate-toggle-technical",
                        onclick: move |_| {
                            let current = *show_details.read();
                            show_details.set(!current);
                        },
                        "{toggle_label}"
                    }
                    if *show_details.read() {
                        div { class: "muted profile-gate-technical", "data-testid": "profile-gate-technical",
                            div { strong { "{dev_label}: " } code { "{profile}" } }
                            div { "Write controls for this surface are hidden until /server/describe advertises the matching profile requirements." }
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

pub(super) fn route_label(route: &Route) -> &'static str {
    match route {
        Route::Dashboard => "Home",
        Route::Login | Route::AuthCallback => "Login",
        Route::RealmsManage => "Manage Realms",
        Route::Realm { .. } => "Realm",
        Route::Chat { .. } => "Discussion",
        Route::DirectConversation { .. } => "Direct",
        Route::ContactsManage => "Manage Contacts",
        Route::Contacts => "Contacts",
        Route::FileTransfer => "Files",
        Route::Directory => "Search",
        Route::Setup => "New Realm",
        Route::SetupSection { section } => match section.as_str() {
            "realms" => "New Realm",
            "new-space" => "New Space",
            _ => "Setup",
        },
        Route::Settings => "Settings",
        Route::SettingsSection { section } => settings_route_label(section),
        Route::NotificationsSettings => "Notifications",
        Route::VerifyDevice => "Verify Device",
        Route::RealmMembers { .. } => "Members",
        Route::RealmAdmin { .. } => "Realm Settings",
        Route::RealmAdminSection { section, .. } => match section.as_str() {
            "profile" => "Profile",
            "access" => "Access Policy",
            "security" => "Security & MLS",
            "federation" => "Federation Trust",
            "repair" => "Repair & Danger",
            _ => "Realm Settings",
        },
        Route::Audit => "Audit log",
        Route::Developer => "Developer tools",
        Route::Kanban
        | Route::KanbanRealm { .. }
        | Route::KanbanBoard { .. }
        | Route::KanbanBoardTask { .. }
        | Route::KanbanTask { .. } => "Board View",
        Route::Notifications => "Notifications",
        Route::Call { .. } => "Call",
        Route::Recovery => "Recovery",
        Route::SettingsDevices => "Devices",
        Route::SettingsDevicesPair => "Pair new device",
        Route::SettingsRecovery => "Recovery",
        Route::Onboarding => "Onboarding",
        Route::Quarantine => "Invite Quarantine",
        Route::Applets => "Applets",
        Route::Agents => "Agents",
        Route::Search => "Search",
    }
}

pub(super) fn settings_route_label(section: &str) -> &'static str {
    match section {
        "server" => "Account & server",
        "devices" => "Devices",
        "storage" => "Data & sync",
        "encryption" => "Security",
        "security" | "key-backup" | "recovery" => "Recovery",
        "mimi" => "Integrations",
        "push" | "notifications" => "Notifications",
        "privacy" => "Privacy & sharing",
        "invite-policy" | "invite_policy" => "Who can invite me",
        "blocklist" | "blocked-users" => "Blocked actors",
        "capabilities" => "Capabilities",
        "audit" | "audit-log" => "Audit log",
        "developer" | "developer-tools" => "Developer tools",
        "theme" => "Appearance & locale",
        "release" => "Diagnostics",
        _ => "Settings",
    }
}
