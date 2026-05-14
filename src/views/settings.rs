use dioxus::prelude::*;
use dioxus_router::{Link, hooks::use_route};
use serde_json::json;

use crate::{
    components::{HelpTip, UiIcon},
    config::LocalConfigStore,
    i18n::Locale,
    key_backup::build_key_backup_put_body,
    local_state::LocalStateStore,
    models::AccountDataSetOutcome,
    routes::Route,
    views::helpers::authed_api,
    workflows::blocked_release_workflows,
};

/// `cx.account_data` key used by the read-receipt preferences entry. Spec:
/// `discovery/client-preferences.md` §3.6.
pub(crate) const READ_RECEIPT_ACCOUNT_DATA_KEY: &str = "cx.read_receipt.preferences";

/// Build the canonical `content` body for a read-receipt preferences
/// account-data entry. Mirrors the SDK's `ReadReceiptPreferences` shape so
/// other devices reading the value via `/sync` get the same field names.
pub(crate) fn build_read_receipt_preferences_body(
    default_send: bool,
    space_overrides: &std::collections::BTreeMap<String, bool>,
    flow_overrides: &std::collections::BTreeMap<String, bool>,
) -> serde_json::Value {
    json!({
        "default_send": default_send,
        "space_overrides": space_overrides,
        "flow_overrides": flow_overrides,
    })
}

/// Round 21 helper: spawn a fire-and-forget task that pushes the current
/// read-receipt preferences to soland's `cx.account_data.set` PUT
/// endpoint. Read latest values from the local state store at call time —
/// the local state is always authoritative; the server-sync is best-effort.
/// Swallows 404/501/405 via [`AccountDataSetOutcome::Unsupported`] so older
/// soland deployments don't surface as user-visible errors.
fn push_read_receipt_account_data(
    base_url: String,
    api_token: String,
    state_store: Signal<LocalStateStore>,
) {
    let body = build_read_receipt_preferences_body(
        state_store.read().read_receipt_default_send(),
        &state_store.read().read_receipt_space_overrides(),
        &state_store.read().read_receipt_flow_overrides(),
    );
    spawn(async move {
        let api = match authed_api(&base_url, api_token) {
            Ok(api) => api,
            Err(_) => return,
        };
        match api
            .set_account_data(READ_RECEIPT_ACCOUNT_DATA_KEY, body)
            .await
        {
            Ok(AccountDataSetOutcome::Stored { .. }) => {}
            Ok(AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland account_data PUT returned {status}; local state still authoritative"
                );
            }
            Err(error) => {
                tracing::warn!("account_data PUT for read-receipt prefs failed: {error}");
            }
        }
    });
}

fn render_notification_kind_toggle(
    kind: &'static str,
    label: &'static str,
    mut state_store: Signal<LocalStateStore>,
    mut status: Signal<String>,
) -> Element {
    let enabled = state_store.read().notification_kind_enabled(kind);
    rsx! {
        div { class: "metric",
            strong { "{label}" }
            label {
                input {
                    r#type: "checkbox",
                    checked: enabled,
                    onchange: move |event| {
                        let enabled = event.value() == "true";
                        state_store.write().set_notification_kind_enabled(kind, enabled);
                        status.set(format!(
                            "{} {}.",
                            label,
                            if enabled { "enabled" } else { "muted" }
                        ));
                    },
                }
                if enabled { " Enabled" } else { " Muted" }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsSection {
    Server,
    Storage,
    Encryption,
    Mimi,
    Notifications,
    Privacy,
    Theme,
    Release,
}

impl SettingsSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or("server") {
            "storage" => Self::Storage,
            "encryption" => Self::Encryption,
            "mimi" => Self::Mimi,
            "push" | "notifications" => Self::Notifications,
            "privacy" => Self::Privacy,
            "theme" => Self::Theme,
            "release" => Self::Release,
            _ => Self::Server,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Storage => "storage",
            Self::Encryption => "encryption",
            Self::Mimi => "mimi",
            Self::Notifications => "notifications",
            Self::Privacy => "privacy",
            Self::Theme => "theme",
            Self::Release => "release",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Server => "Account & server",
            Self::Storage => "Data & sync",
            Self::Encryption => "Security & recovery",
            Self::Mimi => "Integrations",
            Self::Notifications => "Notifications",
            Self::Privacy => "Privacy & sharing",
            Self::Theme => "Appearance & locale",
            Self::Release => "Operational status",
        }
    }

    fn eyebrow(self) -> &'static str {
        match self {
            Self::Server => "Account",
            Self::Storage => "Persistence",
            Self::Encryption => "Security",
            Self::Mimi => "Integrations",
            Self::Notifications => "Notifications",
            Self::Privacy => "Privacy",
            Self::Theme => "Preferences",
            Self::Release => "Operations",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::Server => {
                "Profile, identity, principal context, and delegated service configuration."
            }
            Self::Storage => {
                "Persistence surfaces, sync channels, and export risk indicators for this client."
            }
            Self::Encryption => {
                "Device trust, recovery posture, MLS defaults, and key backup workflows."
            }
            Self::Mimi => "Connected services and MIMI interoperability controls.",
            Self::Notifications => {
                "Notification rules, push registration, routing state, and per-Space delivery controls."
            }
            Self::Privacy => {
                "Actor-private preferences, disclosure policy, and selective sharing rules."
            }
            Self::Theme => {
                "Theme, locale, and client-facing defaults that stay private to this actor."
            }
            Self::Release => "Client health, sync posture, and operational status in one place.",
        }
    }
}

const SETTINGS_ACCOUNT_GROUP: &[SettingsSection] = &[SettingsSection::Server];
const SETTINGS_SECURITY_GROUP: &[SettingsSection] = &[SettingsSection::Encryption];
const SETTINGS_DELIVERY_GROUP: &[SettingsSection] =
    &[SettingsSection::Notifications, SettingsSection::Privacy];
const SETTINGS_CLIENT_GROUP: &[SettingsSection] =
    &[SettingsSection::Theme, SettingsSection::Storage];
const SETTINGS_INTEGRATIONS_GROUP: &[SettingsSection] = &[SettingsSection::Mimi];
const SETTINGS_NAV_GROUPS: &[(&str, &str, &[SettingsSection])] = &[
    (
        "Account",
        "Principal identity, profile, and delegated service boundaries.",
        SETTINGS_ACCOUNT_GROUP,
    ),
    (
        "Security",
        "Device identity, recovery, and local encryption posture.",
        SETTINGS_SECURITY_GROUP,
    ),
    (
        "Notifications & privacy",
        "Notification delivery behavior and actor-private disclosure controls.",
        SETTINGS_DELIVERY_GROUP,
    ),
    (
        "Client",
        "Appearance, locale, storage, and sync surfaces.",
        SETTINGS_CLIENT_GROUP,
    ),
    (
        "Integrations",
        "Applets, agents, and interop-specific controls.",
        SETTINGS_INTEGRATIONS_GROUP,
    ),
];

#[component]
pub fn SettingsPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    crypto_state: String,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    push_state: Signal<String>,
    mut locale: Signal<Locale>,
    mut theme: Signal<String>,
    status: Signal<String>,
    push_ready: bool,
) -> Element {
    let route = use_route::<Route>();
    let active_section = SettingsSection::from_slug(route.settings_section());
    let mut presence_visible = use_signal(|| true);
    // Read receipt preferences (spec discovery/client-preferences.md §3.6).
    // Hydrated from persisted local state; mutations write back through
    // `state_store.set_read_receipt_*` so the timeline view can resolve
    // (flow → space → default) before sending `cx.receipt.read`.
    let mut read_receipt_default_send =
        use_signal(|| state_store.read().read_receipt_default_send());
    let mut read_receipt_space_overrides =
        use_signal(|| state_store.read().read_receipt_space_overrides());
    let mut read_receipt_override_input = use_signal(String::new);
    let mut mls_group_policy = use_signal(|| "default".to_owned());
    let mut key_backup_status = use_signal(|| "Not configured".to_owned());
    let mut key_backup_id =
        use_signal(|| "cx:backup:01964137-0000-7000-8000-000000000000".to_owned());
    let mut mimi_directory = use_signal(|| "Not loaded".to_owned());
    let mut mimi_receipt = use_signal(|| "No MIMI action receipt".to_owned());
    let blocked_count = blocked_release_workflows().len();
    let muted_spaces = state_store.read().muted_spaces();
    let active_locale = locale();
    let active_locale_code = active_locale.code();
    let active_direction = active_locale.direction().as_str();
    let push_registration = state_store.read().push_registration();
    let push_label = crate::push::push_status_label(push_registration.as_ref());
    let has_session = !token().trim().is_empty();
    let principal_label = if has_session {
        account_did()
    } else {
        "Not signed in".to_owned()
    };
    let device_label = if has_session {
        device_id()
    } else {
        "No authenticated device session".to_owned()
    };
    rsx! {
        div { class: "settings", "data-testid": "settings-panel",
            div { class: "settings-shell",
                aside { class: "settings-sidebar-column",
                    for (group_index, (_, _, sections)) in SETTINGS_NAV_GROUPS.iter().copied().enumerate() {
                        div { class: "settings-nav-cluster",
                            for section in sections.iter().copied() {
                                Link {
                                    class: if active_section == section { "settings-nav-item active" } else { "settings-nav-item" },
                                    "data-testid": "settings-nav-item-{section.slug()}",
                                    "aria-current": if active_section == section { "page" } else { "false" },
                                    to: Route::SettingsSection { section: section.slug().to_owned() },
                                    strong { "{section.label()}" }
                                }
                            }
                        }
                        if group_index + 1 < SETTINGS_NAV_GROUPS.len() {
                            div { class: "settings-nav-divider", "aria-hidden": "true" }
                        }
                    }
                }
                section { class: "settings-content-column",
                    div { class: "event settings-content-hero",
                        div { class: "event-head",
                            span { "{active_section.eyebrow()}" }
                            span { if has_session { "authenticated" } else { "local state" } }
                        }
                        div { class: "settings-content-title-row",
                            h2 { class: "settings-content-title", "{active_section.label()}" }
                            HelpTip { text: active_section.description().to_owned() }
                        }
                        div { class: "actions",
                            if active_section == SettingsSection::Server {
                                span { class: "badge green", "Principal Server context" }
                            }
                            if active_section == SettingsSection::Encryption {
                                span { class: "badge amber", "{crypto_state}" }
                            }
                            if active_section == SettingsSection::Notifications {
                                span { class: "badge green", if push_ready { "Push gateway available" } else { "Push gateway not advertised" } }
                            }
                            if active_section == SettingsSection::Release {
                                span { class: "badge amber", "Primary nav simplified" }
                            }
                        }
                    }

                    div { class: "event", "data-testid": "settings-setup-recovery-hub",
                        div { class: "event-head",
                            span { "Setup & recovery" }
                            HelpTip { text: "Identity bootstrap, device verification, recovery, and admin-side invite review now live behind Settings instead of the primary workspace navigation." }
                        }
                        div { class: "actions",
                            Link {
                                class: "secondary",
                                to: Route::Onboarding,
                                UiIcon { name: "check" }
                                "Onboarding"
                            }
                            Link {
                                class: "secondary",
                                to: Route::VerifyDevice,
                                UiIcon { name: "check" }
                                "Verify Device"
                            }
                            Link {
                                class: "secondary",
                                to: Route::Recovery,
                                UiIcon { name: "archive" }
                                "Recovery"
                            }
                            Link {
                                class: "secondary",
                                to: Route::Quarantine,
                                UiIcon { name: "inbox" }
                                "Invite Quarantine"
                            }
                            Link {
                                class: "secondary",
                                to: Route::SettingsSection { section: SettingsSection::Mimi.slug().to_owned() },
                                UiIcon { name: "server" }
                                "Integrations"
                            }
                        }
                    }

                    // ── Server / Account settings ────────────────────────
                    if active_section == SettingsSection::Server {
                        div { class: "settings-card-grid",
                            div { class: "event settings-card-span-2", "data-testid": "transport-invariant",
                                div { class: "event-head",
                                    span { "Principal Context" }
                                    span { if has_session { "authenticated" } else { "not signed in" } }
                                }
                                div { class: "metric-grid",
                                    div { class: "metric",
                                        strong { "Principal Server" }
                                        span { "{base_url}" }
                                        div { class: "muted", "delegated service boundary" }
                                    }
                                    div { class: "metric",
                                        strong { "Principal" }
                                        span { "{principal_label}" }
                                        div { class: "muted", if has_session { "signs Events; server cannot forge" } else { "loaded after server auth" } }
                                    }
                                    div { class: "metric",
                                        strong { "Device" }
                                        span { "{device_label}" }
                                        div { class: "muted", if has_session { "local client identity" } else { "not bound yet" } }
                                    }
                                    div { class: "metric",
                                        strong { "Organization" }
                                        span { "None selected" }
                                        div { class: "muted", "Organizations are principals, not servers" }
                                    }
                                }
                                div { class: "actions",
                                    span { class: "badge green", "HTTP/JSON" }
                                    span { class: "badge blue", "v1 core" }
                                }
                            }

                            div { class: "event", "data-testid": "bound-services-settings",
                                div { class: "event-head", span { "Bound Services" } span { "Principal Server delegated" } }
                                div { class: "metric-grid",
                                    div { class: "metric",
                                        strong { "soland" }
                                        span { "events, sync, projections" }
                                    }
                                    div { class: "metric",
                                        strong { "coauth" }
                                        span { "auth bridge / session grant" }
                                    }
                                    div { class: "metric",
                                        strong { "chime" }
                                        span { "push wakeups, redacted by default" }
                                    }
                                    div { class: "metric",
                                        strong { "applet runtime" }
                                        span { "capability-scoped extensions" }
                                    }
                                }
                            }

                        }
                    }

                    // ── Storage section ──────────────────────────────────
                    if active_section == SettingsSection::Storage {
                        div { class: "settings-card-grid",
                            div { class: "event", "data-testid": "storage-table",
                    div { class: "event-head", span { "Local Stores" } span { "status" } }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Config Store" }
                            span { "Active" }
                        }
                        div { class: "metric",
                            strong { "Config Size" }
                            span { "~{config_store.read().load().server_url.len()} bytes" }
                        }
                        div { class: "metric",
                            strong { "State Store" }
                            span { "Active" }
                        }
                        div { class: "metric",
                            strong { "Platform" }
                            span { if cfg!(target_arch = "wasm32") { "Web (localStorage)" } else { "Native (filesystem)" } }
                        }
                    }
                }

                            // Storage risk indicators
                            div { class: "event", "data-testid": "storage-risks",
                    div { class: "event-head", span { "Storage Risks" } span { "warnings" } }
                    if cfg!(target_arch = "wasm32") {
                        div { class: "metric",
                            strong {
                                "Web localStorage Limit "
                                HelpTip { text: "localStorage has a ~5MB limit. Large sync data, drafts, and cached operations may exceed this limit. Consider using IndexedDB for production." }
                            }
                            span { class: "badge badge-warning", "data-testid": "risk-badge",
                                "Warning"
                            }
                        }
                        div { class: "metric",
                            strong {
                                "No Encryption at Rest "
                                HelpTip { text: "Web localStorage is not encrypted. Session tokens and cached data are accessible to any script on the same origin. Use secure httpOnly cookies or IndexedDB with encryption for production." }
                            }
                            span { class: "badge badge-error",
                                "Critical"
                            }
                        }
                        div { class: "metric",
                            strong {
                                "No Cross-Tab Sync "
                                HelpTip { text: "localStorage changes in one tab are not automatically reflected in other tabs. Consider using BroadcastChannel or storage events for multi-tab sync." }
                            }
                            span { class: "badge badge-info",
                                "Info"
                            }
                        }
                    } else {
                        div { class: "metric",
                            strong {
                                "Filesystem Storage "
                                HelpTip { text: "Native filesystem storage is used. Data persists across sessions. Ensure proper file permissions for security." }
                            }
                            span { class: "badge badge-success",
                                "OK"
                            }
                        }
                    }
                }
                        }
                    }

                    // ── Encryption settings ──────────────────────────────
                    if active_section == SettingsSection::Encryption {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "encryption-settings",
                    div { class: "event-head", span { "Encryption" } span { "MLS / E2EE" } }
                    label { "MLS Group Policy" }
                    select {
                        value: "{mls_group_policy}",
                        onchange: move |evt| mls_group_policy.set(evt.value()),
                        option { value: "default", "Default" }
                        option { value: "always-encrypt", "Always Encrypt" }
                        option { value: "prefer-plaintext", "Prefer Plaintext" }
                    }
                    div { class: "muted", "Current: {crypto_state}" }
                    label { "Key Backup" }
                    div { class: "muted", "{key_backup_status}" }
                    div { class: "actions",
                        input {
                            "data-testid": "key-backup-id-input",
                            value: "{key_backup_id}",
                            oninput: move |evt| key_backup_id.set(evt.value()),
                        }
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-setup",
                            onclick: move |_| {
                                let base = base_url();
                                let api_token = token();
                                let backup_id = key_backup_id();
                                let actor = account_did();
                                let device = device_id();
                                spawn(async move {
                                    let body = build_key_backup_put_body(
                                        &backup_id,
                                        &actor,
                                        &device,
                                        "BASE64URL_OPAQUE_BLOB_PLACEHOLDER",
                                        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                                    );
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.put_key_backup(&backup_id, body).await {
                                            Ok(response) => key_backup_status.set(format!("Backup stored: {response}")),
                                            Err(error) => key_backup_status.set(format!("Backup store failed: {error}")),
                                        },
                                        Err(error) => key_backup_status.set(format!("Backup API unavailable: {error}")),
                                    }
                                });
                            },
                            "Store Backup"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-list",
                            onclick: move |_| {
                                let base = base_url();
                                let api_token = token();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.list_key_backups().await {
                                            Ok(response) => key_backup_status.set(format!("Backups: {response}")),
                                            Err(error) => key_backup_status.set(format!("Backup list failed: {error}")),
                                        },
                                        Err(error) => key_backup_status.set(format!("Backup API unavailable: {error}")),
                                    }
                                });
                            },
                            "List Backups"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-load",
                            onclick: move |_| {
                                let base = base_url();
                                let api_token = token();
                                let backup_id = key_backup_id();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.get_key_backup(&backup_id).await {
                                            Ok(response) => key_backup_status.set(format!("Backup {backup_id}: {response}")),
                                            Err(error) => key_backup_status.set(format!("Backup load failed: {error}")),
                                        },
                                        Err(error) => key_backup_status.set(format!("Backup API unavailable: {error}")),
                                    }
                                });
                            },
                            "Load Backup"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-delete",
                            onclick: move |_| {
                                let base = base_url();
                                let api_token = token();
                                let backup_id = key_backup_id();
                                spawn(async move {
                                    match authed_api(&base, api_token) {
                                        Ok(api) => match api.delete_key_backup(&backup_id).await {
                                            Ok(response) => key_backup_status.set(format!("Backup deleted: {response}")),
                                            Err(error) => key_backup_status.set(format!("Backup delete failed: {error}")),
                                        },
                                        Err(error) => key_backup_status.set(format!("Backup API unavailable: {error}")),
                                    }
                                });
                            },
                            "Delete Backup"
                        }
                    }
                    div { class: "muted", "Contract: cx.schema.key_backup.v1 over /api/v1/keys/backups/*." }
                }
                        }
                    }

                    // ── MIMI interop facade ──────────────────────────────
                    if active_section == SettingsSection::Mimi {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "mimi-interop-panel",
                    div { class: "event-head", span { "MIMI Provider Facade" } span { "interop projection" } }
                    div { class: "muted", "Profile: cx.profile.mimi_interop.v1" }
                    div { class: "metric-grid", "data-testid": "mimi-draft-pinning",
                        div { class: "metric", strong { "Protocol" } span { "draft-ietf-mimi-protocol-06" } }
                        div { class: "metric", strong { "Content" } span { "draft-ietf-mimi-content-08" } }
                        div { class: "metric", strong { "Discussion Policy" } span { "draft-ietf-mimi-room-policy-03" } }
                        div { class: "metric", strong { "Identifiers" } span { "draft-kohbrok-mimi-identifiers-01" } }
                    }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "mimi-refresh-directory",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_provider_directory().await {
                                                Ok(directory) => {
                                                    let features = directory.mimi.features.join(", ");
                                                    mimi_directory.set(format!(
                                                        "{}\n{}\n{}\n{}",
                                                        directory.mimi.provider_id,
                                                        directory.supported_profiles.join(", "),
                                                        directory.mimi.protocol_draft,
                                                        features
                                                    ));
                                                    status.set("MIMI provider directory refreshed".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI directory failed: {error}");
                                                    mimi_directory.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Refresh Directory"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-group-info",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_group_info("01JSMIMI").await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "group-info {} participants {}",
                                                        response.room_id,
                                                        response.participants.len()
                                                    ));
                                                    status.set("MIMI groupInfo loaded".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI groupInfo failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Group Info"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-identifier-query",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_identifier_query(json!({
                                                "query": "mimi://remote.example/alice",
                                                "privacy_mode": "private_identifier_query"
                                            })).await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "identifier {} reachable {} mapped {}",
                                                        response.query,
                                                        response.reachable,
                                                        response.mapped_did.unwrap_or_else(|| "none".to_owned())
                                                    ));
                                                    status.set("MIMI identifier query completed".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI identifier query failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Identifier Query"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-submit-message",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_submit_message("01JSMIMI", json!({
                                                "source_format": "text/markdown;variant=GFM-MIMI",
                                                "body": "MIMI interop test from yougen",
                                                "mimi_room_uri": "mimi://mimi.example.com/rooms/01JSMIMI"
                                            })).await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "submit-message {} {}",
                                                        response.mimi_message_id.unwrap_or_else(|| "no-message-id".to_owned()),
                                                        response.mapped_operation_id.unwrap_or_else(|| "no-operation".to_owned())
                                                    ));
                                                    status.set("MIMI test message submitted".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI submit failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Submit Test Message"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "mimi-proxy-download",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match api.mimi_proxy_download(json!({
                                                "blob_ref": "cx:blob:sha256:e2e",
                                                "asset_privacy_policy": "provider_proxy"
                                            })).await {
                                                Ok(response) => {
                                                    mimi_receipt.set(format!(
                                                        "proxy-download {} {}",
                                                        response.blob_ref,
                                                        response.media_type.unwrap_or_else(|| "unknown".to_owned())
                                                    ));
                                                    status.set("MIMI proxy download prepared".to_owned());
                                                }
                                                Err(error) => {
                                                    let message = format!("MIMI proxy download failed: {error}");
                                                    mimi_receipt.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("MIMI API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Proxy Download"
                        }
                    }
                    div { class: "event", "data-testid": "mimi-directory-result",
                        div { class: "event-head", span { "Directory" } span { "features" } }
                        pre { "{mimi_directory}" }
                    }
                    div { class: "event", "data-testid": "mimi-action-receipt",
                        div { class: "event-head", span { "Receipt" } span { "last action" } }
                        pre { "{mimi_receipt}" }
                    }
                }
                        }
                    }

                    // ── Notification settings ────────────────────────────
                    if active_section == SettingsSection::Notifications {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "notification-rules-settings",
                    div { class: "event-head",
                        span { "Notification rules" }
                        HelpTip { text: "These toggles only affect this client. Server-side moderation and retention policies remain separate." }
                    }
                    div { class: "metric-grid",
                        {render_notification_kind_toggle("mention", "Mention notifications", state_store, status)}
                        {render_notification_kind_toggle("reaction", "Reaction notifications", state_store, status)}
                        {render_notification_kind_toggle("invite", "Invite notifications", state_store, status)}
                        {render_notification_kind_toggle("message", "Message notifications", state_store, status)}
                    }
                }
                            div { class: "event", "data-testid": "push-settings",
                    div { class: "event-head", span { "Push delivery" } span { "configure" } }
                    div { class: "muted", "Push notification preferences and gateway registration." }
                    div { class: "muted", "data-testid": "push-registration-state", "Current: {push_label}" }
                    div { class: "actions",
                        button {
                            class: "secondary",
                            "data-testid": "push-register-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let dev = device_id();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match crate::push::build_register_request(&dev) {
                                                Ok(request) => match api.register_push_device_with_request(&request).await {
                                                    Ok(push) => {
                                                        let mut local_push = chime::RegisterDeviceResponse::default();
                                                        local_push.ok = push.ok;
                                                        local_push.registration_id = push.registration_id.clone();
                                                        local_push.expires_at = push.expires_at.clone();
                                                        let local_state = crate::push::registration_state_from_response(
                                                            &request,
                                                            &local_push,
                                                        );
                                                        state_store.write().save_push_registration(local_state);
                                                        let label = push.registration_id.unwrap_or_else(|| "registered".to_owned());
                                                        push_state.set(label.clone());
                                                        status.set(format!("Push registered: {label}"));
                                                    }
                                                    Err(error) => {
                                                        let message = format!("push register failed: {error}");
                                                        push_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => {
                                                    let message = format!("push unavailable: {error}");
                                                    push_state.set(message.clone());
                                                    status.set(message);
                                                }
                                            },
                                            Err(error) => status.set(format!("push API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Register Push"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "push-unregister-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let dev = device_id();
                                    let existing = state_store.read().push_registration();
                                    spawn(async move {
                                        match authed_api(&base, api_token) {
                                            Ok(api) => match crate::push::build_unregister_request(&dev, existing.as_ref()) {
                                                Ok(request) => match api.unregister_push_device_with_request(&request).await {
                                                    Ok(_) => {
                                                        state_store.write().clear_push_registration();
                                                        push_state.set("Not registered".to_owned());
                                                        status.set("Push unregistered".to_owned());
                                                    }
                                                    Err(error) => {
                                                        let message = format!("push unregister failed: {error}");
                                                        push_state.set(message.clone());
                                                        status.set(message);
                                                    }
                                                },
                                                Err(error) => status.set(format!("push unregister unavailable: {error}")),
                                            },
                                            Err(error) => status.set(format!("push API unavailable: {error}")),
                                        }
                                    });
                                }
                            },
                            "Unregister Push"
                        }
                    }
                    div { class: "event", "data-testid": "notifications-mute-summary",
                        div { class: "event-head",
                            span { "Per-space mute rules" }
                            span { "{muted_spaces.len()} muted" }
                        }
                        if muted_spaces.is_empty() {
                            div { class: "muted", "No spaces muted. Use the Notifications view to mute a noisy space." }
                        } else {
                            for space_id in muted_spaces {
                                div { class: "actions", "data-testid": "settings-muted-space-row",
                                    span { "{space_id}" }
                                    button {
                                        class: "secondary",
                                        "data-testid": "notifications-settings-unmute-space",
                                        onclick: {
                                            let space_id = space_id.clone();
                                            move |_| {
                                                state_store.write().set_space_muted(space_id.clone(), false);
                                                status.set(format!("Unmuted {space_id} from notification preferences"));
                                            }
                                        },
                                        "Unmute"
                                    }
                                }
                            }
                            button {
                                class: "secondary",
                                "data-testid": "notifications-settings-clear-muted-spaces",
                                onclick: move |_| {
                                    state_store.write().clear_muted_spaces();
                                    status.set("Cleared all per-space mute rules".to_owned());
                                },
                                "Clear All Mutes"
                            }
                        }
                    }
                }
                        }
                    }

                    // ── Privacy settings ─────────────────────────────────
                    if active_section == SettingsSection::Privacy {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "privacy-settings",
                    div { class: "event-head", span { "Privacy" } span { "visibility controls" } }
                    label {
                        input {
                            r#type: "checkbox",
                            checked: presence_visible(),
                            onchange: move |evt| presence_visible.set(evt.value() == "true"),
                        }
                        " Show presence to others (cx.presence)"
                    }
                    div { class: "event-head",
                        span { "Read receipts" }
                        span { "cx.read_receipt.preferences" }
                    }
                    label {
                        input {
                            r#type: "checkbox",
                            "data-testid": "read-receipts-default-toggle",
                            checked: read_receipt_default_send(),
                            onchange: move |evt| {
                                let send = evt.value() == "true";
                                read_receipt_default_send.set(send);
                                state_store.write().set_read_receipt_default_send(send);
                                status.set(format!(
                                    "Read receipts: default = {}",
                                    if send { "send" } else { "skip" }
                                ));
                                // Round 21: also push to soland's
                                // cx.account_data.set so other devices pick
                                // up the change. Endpoint may 404/501 — we
                                // swallow and keep local authoritative.
                                let body = build_read_receipt_preferences_body(
                                    send,
                                    &state_store
                                        .read()
                                        .read_receipt_space_overrides(),
                                    &state_store
                                        .read()
                                        .read_receipt_flow_overrides(),
                                );
                                let base = base_url();
                                let api_token = token();
                                spawn(async move {
                                    if let Ok(api) = authed_api(&base, api_token) {
                                        let _ = api
                                            .set_account_data(
                                                READ_RECEIPT_ACCOUNT_DATA_KEY,
                                                body,
                                            )
                                            .await;
                                    }
                                });
                            },
                        }
                        " Send read receipts (cx.receipt.read) by default "
                        HelpTip { text: "Resolution order is (flow → space → default). When a Space declares a read-receipt policy with disclosure=required or disabled, the server policy overrides this preference." }
                    }
                    div { class: "event-head",
                        span { "Per-space overrides" }
                        span { "{read_receipt_space_overrides().len()} configured" }
                        HelpTip { text: "Add a Space ID below to opt this Space out of (or into) read receipts independently of the global default. Server-declared policy lock is wired: when soland's Anchor view (P0 M3) surfaces a cx.space.read_receipt_policy with disclosure=required or disabled, the matching per-Space toggle shows a `locked by Space policy` badge and the controls become disabled — see LocalStateStore::read_receipt_should_send." }
                    }
                    for (space_id, send) in read_receipt_space_overrides() {
                            // Policy lock — when soland publishes a
                            // cx.space.read_receipt_policy with disclosure=
                            // required|disabled, the toggle is disabled and
                            // we show a lock badge with the reason. Until
                            // sync (P0 M3) wires the snapshot, this returns
                            // `None` for every space and the row stays
                            // editable.
                            {
                                let policy = state_store
                                    .read()
                                    .read_receipt_policy_for_space(&space_id);
                                let locked = policy
                                    .as_ref()
                                    .is_some_and(|p| p.locks_user_choice());
                                let lock_reason = policy
                                    .as_ref()
                                    .map(|p| p.lock_reason())
                                    .unwrap_or_default();
                                rsx! {
                                    div { class: "actions", "data-testid": "read-receipt-override-row",
                                        span { "{space_id}" }
                                        span { class: "badge",
                                            {if send { "sending" } else { "skipping" }}
                                        }
                                        if locked {
                                            span {
                                                class: "badge red",
                                                "data-testid": "read-receipt-override-locked",
                                                "locked by Space policy"
                                            }
                                        }
                                        button {
                                            class: "secondary",
                                            "data-testid": "read-receipt-override-toggle",
                                            disabled: locked,
                                            onclick: {
                                                let space_id = space_id.clone();
                                                move |_| {
                                                    if locked {
                                                        return;
                                                    }
                                                    let next = !send;
                                                    state_store.write().set_read_receipt_space_override(
                                                        space_id.clone(),
                                                        Some(next),
                                                    );
                                                    read_receipt_space_overrides.set(
                                                        state_store.read().read_receipt_space_overrides(),
                                                    );
                                                    status.set(format!(
                                                        "Read receipts for {space_id}: {}",
                                                        if next { "send" } else { "skip" }
                                                    ));
                                                    push_read_receipt_account_data(
                                                        base_url(),
                                                        token(),
                                                        state_store,
                                                    );
                                                }
                                            },
                                            {if send { "Switch to skip" } else { "Switch to send" }}
                                        }
                                        button {
                                            class: "secondary",
                                            "data-testid": "read-receipt-override-clear",
                                            disabled: locked,
                                            onclick: {
                                                let space_id = space_id.clone();
                                                move |_| {
                                                    if locked {
                                                        return;
                                                    }
                                                    state_store.write().set_read_receipt_space_override(
                                                        space_id.clone(),
                                                        None,
                                                    );
                                                    read_receipt_space_overrides.set(
                                                        state_store.read().read_receipt_space_overrides(),
                                                    );
                                                    status.set(format!(
                                                        "Read receipts for {space_id}: inherit default"
                                                    ));
                                                    push_read_receipt_account_data(
                                                        base_url(),
                                                        token(),
                                                        state_store,
                                                    );
                                                }
                                            },
                                            "Inherit default"
                                        }
                                    }
                                    if locked {
                                        div { class: "muted",
                                            "data-testid": "read-receipt-override-lock-reason",
                                            "{lock_reason}"
                                        }
                                    }
                                }
                            }
                        }
                    div { class: "actions", "data-testid": "read-receipt-add-override",
                        input {
                            r#type: "text",
                            placeholder: "cx:space:...",
                            value: "{read_receipt_override_input()}",
                            oninput: move |evt| read_receipt_override_input.set(evt.value()),
                        }
                        button {
                            class: "secondary",
                            "data-testid": "read-receipt-add-override-skip",
                            onclick: move |_| {
                                let space_id = read_receipt_override_input().trim().to_owned();
                                if space_id.is_empty() {
                                    status.set("Enter a Space ID first".to_owned());
                                    return;
                                }
                                state_store.write().set_read_receipt_space_override(
                                    space_id.clone(),
                                    Some(false),
                                );
                                read_receipt_space_overrides.set(
                                    state_store.read().read_receipt_space_overrides(),
                                );
                                read_receipt_override_input.set(String::new());
                                status.set(format!("Skipping read receipts in {space_id}"));
                                push_read_receipt_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                            "Add (skip)"
                        }
                        button {
                            class: "secondary",
                            "data-testid": "read-receipt-add-override-send",
                            onclick: move |_| {
                                let space_id = read_receipt_override_input().trim().to_owned();
                                if space_id.is_empty() {
                                    status.set("Enter a Space ID first".to_owned());
                                    return;
                                }
                                state_store.write().set_read_receipt_space_override(
                                    space_id.clone(),
                                    Some(true),
                                );
                                read_receipt_space_overrides.set(
                                    state_store.read().read_receipt_space_overrides(),
                                );
                                read_receipt_override_input.set(String::new());
                                status.set(format!("Sending read receipts in {space_id}"));
                                push_read_receipt_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                            "Add (send)"
                        }
                    }
                }

                // Progressive disclosure — identity-handles.md §16
                // Four canonical events drive selective claim sharing:
                //   cx.identity.disclosure_policy   — actor sets which fields are
                //                                     released to which audience.
                //   cx.identity.disclosure_receipt  — receiver acknowledges what
                //                                     they observed (audit trail).
                //   cx.identity.presentation_request  — relying party asks for a
                //                                       claim presentation.
                //   cx.identity.presentation_response — actor satisfies the request
                //                                       with a verifiable presentation.
                            div { class: "event", "data-testid": "progressive-disclosure",
                    div { class: "event-head",
                        span { "Progressive disclosure" }
                        span { "identity-handles §16" }
                        HelpTip { text: "Your DID Document is not your identity profile. Sensitive attributes (claims, handle, email) are disclosed selectively per audience: you set a disclosure policy, counterparties send a presentation_request, you reply with a presentation_response, and every disclosure is logged in a disclosure_receipt." }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "Disclosure policy" }
                            span { "cx.identity.disclosure_policy" }
                            div { class: "muted", "Declares which fields are visible to which audience" }
                        }
                        div { class: "metric",
                            strong { "Presentation request" }
                            span { "cx.identity.presentation_request" }
                            div { class: "muted", "Counterparty-initiated claim request (carries purpose + minimum field set)" }
                        }
                        div { class: "metric",
                            strong { "Presentation response" }
                            span { "cx.identity.presentation_response" }
                            div { class: "muted", "Your verifiable presentation; only authorized fields are revealed" }
                        }
                        div { class: "metric",
                            strong { "Disclosure receipt" }
                            span { "cx.identity.disclosure_receipt" }
                            div { class: "muted", "Audit trail; redactable but the hash chain is preserved" }
                        }
                    }
                    div { class: "actions",
                        button { class: "secondary", "data-testid": "disclosure-policy-edit", "Edit disclosure policy" }
                        button { class: "secondary", "data-testid": "disclosure-history-view", "View disclosure history" }
                        button { class: "secondary", "data-testid": "presentation-pending", "Handle pending request (0)" }
                    }
                }

                // Personal blocklist — discovery/client-preferences.md
                // Block 是 actor-private filter，不影响其它 actor 客户端。
                            div { class: "event", "data-testid": "personal-blocklist",
                    div { class: "event-head",
                        span { "Personal blocklist" }
                        HelpTip { text: "Local actor-private filter. Space-wide blocking belongs in moderation policy; account-data writes use cx.account.blocklist." }
                    }
                    div { class: "actions",
                        button { class: "secondary", "data-testid": "blocklist-edit", "Edit blocklist" }
                        span { class: "badge", "2 actors blocked" }
                    }
                }

                        // ── Move-flow PoC: Grant consent (C10.D 续 2026-05-09 十八轮) ────
                        // First user-facing button on the Move/Anchor pipeline. Builds a
                        // cx.consent.grant Move via move_builder, signs with a deterministic
                        // demo ed25519 key (TODO real-key-management), POSTs /api/v1/moves.
                        // Direct-event endpoints for messages / reactions / etc. stay in
                        // place per spec — only events that declare a `cell_family` move
                        // here.
                        crate::views::consent_demo::ConsentGrantDemoCard {
                            base_url,
                            token,
                            state_store,
                        }

                        // ── Account Data (actor-private View preferences) ─────
                        // models/views.md §2.6 + identity/account-lifecycle.md
                        // 共享 View 改 filter / sort / columns 写 cx.view.update（所有人可见）；
                        // 个人 View 偏好（折叠状态、临时 filter、列宽）写 cx.account_data.set
                        // 到 actor-private channel，不广播到 Space。
                        div { class: "event", "data-testid": "account-data-prefs",
                    div { class: "event-head",
                        span { "Account Data (actor-private)" }
                        span { "cx.account_data.set" }
                        HelpTip { text: "The preferences below write to your account's actor-private channel and never sync to other Space members. To change a shared View's settings, use that View's Edit button (which writes cx.view.update)." }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "View column widths" }
                            span { "actor-private" }
                            div { class: "muted", "key=ui.view.<view_id>.column_widths" }
                        }
                        div { class: "metric",
                            strong { "Folded panels" }
                            span { "actor-private" }
                            div { class: "muted", "key=ui.layout.folds" }
                        }
                        div { class: "metric",
                            strong { "Mute rules" }
                            span { "actor-private" }
                            div { class: "muted", "key=notifications.mute" }
                        }
                        div { class: "metric",
                            strong { "Profile space override" }
                            span { "cx.profile.space_override" }
                            div { class: "muted", "Show a different profile or handle inside a specific Space" }
                        }
                    }
                    div { class: "actions",
                        button { class: "secondary", "data-testid": "account-data-export", "Export account_data" }
                        button { class: "secondary", "data-testid": "account-data-clear", "Clear actor-private preferences" }
                    }
                }
                        }
                    }

                    // ── Theme selector ───────────────────────────────────
                    if active_section == SettingsSection::Theme {
                        div { class: "settings-card-grid",
                            div { class: "event", "data-testid": "theme-settings",
                    div { class: "event-head", span { "Theme" } span { "appearance" } }
                    div { class: "actions",
                        button {
                            class: if theme() == "light" { "btn icon sm primary" } else { "btn icon sm ghost" },
                            "data-testid": "theme-light",
                            title: "Light theme",
                            "aria-label": "Light theme",
                            onclick: move |_| {
                                theme.set("light".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "light");
                                status.set("Theme set to light".to_owned());
                            },
                            UiIcon { name: "sun" }
                        }
                        button {
                            class: if theme() == "night" { "btn icon sm primary" } else { "btn icon sm ghost" },
                            "data-testid": "theme-night",
                            title: "Night theme",
                            "aria-label": "Night theme",
                            onclick: move |_| {
                                theme.set("night".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "night");
                                status.set("Theme set to night".to_owned());
                            },
                            UiIcon { name: "moon" }
                        }
                        button {
                            class: if theme() == "system" { "btn icon sm primary" } else { "btn icon sm ghost" },
                            "data-testid": "theme-system",
                            title: "System theme",
                            "aria-label": "System theme",
                            onclick: move |_| {
                                theme.set("system".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "system");
                                status.set("Theme set to system".to_owned());
                            },
                            UiIcon { name: "monitor" }
                        }
                    }
                    div { class: "muted", "Current: {theme}" }
                    div { class: "muted",
                        "Theme is actor-private account data. Shared board filters/layout still require an explicit shared View save."
                    }
                }
                            div { class: "event", "data-testid": "language-settings",
                    div { class: "event-head",
                        span { "Language" }
                        span { "data-testid": "text-direction", "{active_direction}" }
                    }
                    div { class: "actions",
                        button {
                            class: if active_locale == Locale::En { "primary" } else { "secondary" },
                            "data-testid": "language-en",
                            onclick: move |_| {
                                locale.set(Locale::En);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::En.code());
                                status.set("Language set to en (ltr)".to_owned());
                            },
                            "English"
                        }
                        button {
                            class: if active_locale == Locale::Zh { "primary" } else { "secondary" },
                            "data-testid": "language-zh",
                            onclick: move |_| {
                                locale.set(Locale::Zh);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Zh.code());
                                status.set("Language set to zh (ltr)".to_owned());
                            },
                            "中文"
                        }
                        button {
                            class: if active_locale == Locale::Ar { "primary" } else { "secondary" },
                            "data-testid": "language-ar",
                            onclick: move |_| {
                                locale.set(Locale::Ar);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Ar.code());
                                status.set("Language set to ar (rtl)".to_owned());
                            },
                            "العربية"
                        }
                    }
                    div { class: "muted", "data-testid": "current-language", "Current: {active_locale_code}" }
                }
                        }
                    }

                    // ── CI / Release gate status ─────────────────────────
                    if active_section == SettingsSection::Release {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "release-moved-banner",
                                div { class: "event-head",
                                    span { "Operational status" }
                                    span { "{blocked_count} tracked blockers" }
                                    HelpTip { text: "The separate tools area has been removed from primary navigation. Keep release blockers, sync posture, and investigations summarized here so operational context stays adjacent to account settings." }
                                }
                                div { class: "actions",
                                    span { class: "badge amber", "{blocked_count} blockers" }
                                    span { class: "badge blue", "settings-owned surface" }
                                }
                            }
                        }
                    }

                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Round 21: the canonical `cx.read_receipt.preferences` body shape
    /// other devices read via `/sync` account_data. Locks the field names
    /// (`default_send`, `space_overrides`, `flow_overrides`) so a future
    /// rename can't silently desync devices.
    #[test]
    fn build_read_receipt_preferences_body_has_canonical_field_shape() {
        let mut spaces = BTreeMap::new();
        spaces.insert("cx:space:demo".to_owned(), false);
        let mut flows = BTreeMap::new();
        flows.insert("cx:flow:demo".to_owned(), true);
        let body = build_read_receipt_preferences_body(true, &spaces, &flows);
        assert_eq!(body["default_send"], serde_json::Value::Bool(true));
        assert_eq!(body["space_overrides"]["cx:space:demo"], false);
        assert_eq!(body["flow_overrides"]["cx:flow:demo"], true);
        // Keys we don't expect in this body — explicit guards so a typo
        // (e.g. `default` instead of `default_send`) regression-bisects.
        assert!(body.get("default").is_none());
        assert!(body.get("read_receipt_default_send").is_none());
    }

    /// account-data key is the exact spec key — same string the SDK uses
    /// when reading the entry back from `/sync`.
    #[test]
    fn read_receipt_account_data_key_matches_spec() {
        assert_eq!(READ_RECEIPT_ACCOUNT_DATA_KEY, "cx.read_receipt.preferences");
    }
}
