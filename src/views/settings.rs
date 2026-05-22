use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use dioxus::prelude::*;
use dioxus_router::{Link, hooks::use_route};
use serde_json::json;

use crate::{
    components::{HelpTip, UiIcon},
    config::LocalConfigStore,
    i18n::Locale,
    key_backup::build_recovery_vault_backup_body,
    local_state::LocalStateStore,
    models::AccountDataSetOutcome,
    recovery_crypto::{
        VAULT_ARGON2_M_KIB, VAULT_ARGON2_P, VAULT_ARGON2_T, derive_vault_kek, encrypt_vault,
        estimate_passphrase_strength,
    },
    routes::Route,
    views::helpers::with_authed_api,
    workflows::blocked_release_workflows,
};

/// `cx.account_data` key used by the read-receipt preferences entry. Spec:
/// `discovery/client-preferences.md` §3.6.
pub(crate) const READ_RECEIPT_ACCOUNT_DATA_KEY: &str = "cx.read_receipt.preferences";

/// `cx.account_data` key used by the cross-device UI preferences entry
/// (theme, sidebar collapsed, per-Space view). Spec:
/// `discovery/client-preferences.md` §2.
pub(crate) const CLIENT_UI_ACCOUNT_DATA_KEY: &str = "client.ui";

/// `cx.account_data` key used by the actor-private personal blocklist.
/// Spec: `discovery/client-preferences.md` §2 / §3 privacy preferences.
pub(crate) const CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY: &str = "cx.account.blocklist";

#[derive(Clone, Debug, PartialEq)]
struct PendingAvatarCrop {
    bytes: Vec<u8>,
    media_type: String,
    preview_data_url: String,
    dimensions: (u32, u32),
}

fn avatar_preview_data_url(bytes: &[u8], media_type: &str) -> String {
    let media_type = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type
    };
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}

/// A4a — push the current `client.ui` payload (theme + sidebar
/// collapsed) to soland's `cx.account_data.set` endpoint so other
/// devices pick up the same preference. Same graceful-degradation
/// contract as [`push_read_receipt_account_data`].
///
/// `local_theme` MUST already match the local `LocalConfigStore` write —
/// we never re-read it from the store here because the Signal copy from
/// the caller is the freshest one.
pub(crate) fn push_client_ui_account_data(
    base_url: String,
    api_token: String,
    local_theme: String,
) {
    push_client_ui_account_data_with_avatar(base_url, api_token, local_theme, None);
}

/// A4b — variant of [`push_client_ui_account_data`] that also carries
/// the most-recently uploaded `avatar_blob_ref`. The avatar itself is
/// also published via `cx.account.update_profile` so other actors see
/// it through the directory; mirroring the ref into `client.ui` keeps a
/// second device that signs in primed before the profile lookup
/// completes.
///
/// Pass `None` to skip the avatar mirror (theme-only sync). Pass
/// `Some("")` to tombstone the cached ref so other devices fall back to
/// the public profile when the avatar is cleared.
pub(crate) fn push_client_ui_account_data_with_avatar(
    base_url: String,
    api_token: String,
    local_theme: String,
    avatar_blob_ref: Option<String>,
) {
    if api_token.trim().is_empty() {
        // No active session — nothing to sync; the next login will pick
        // up the local value once the user signs in.
        return;
    }
    let body = crate::account_data::build_client_ui_body(
        Some(local_theme.as_str()),
        None,
        &std::collections::BTreeMap::new(),
        avatar_blob_ref.as_deref(),
    );
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.set_account_data(CLIENT_UI_ACCOUNT_DATA_KEY, body).await
        })
        .await
        {
            Ok(AccountDataSetOutcome::Stored { .. }) => {}
            Ok(AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland account_data PUT for client.ui returned {status}; \
                     local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!("account_data PUT for client.ui failed: {}", err.display());
            }
        }
    });
}

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

/// Spawn a fire-and-forget task that pushes the current read-receipt
/// preferences to soland's `cx.account_data.set` PUT
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
        match with_authed_api(&base_url, api_token, |api| async move {
            api.set_account_data(READ_RECEIPT_ACCOUNT_DATA_KEY, body)
                .await
        })
        .await
        {
            Ok(AccountDataSetOutcome::Stored { .. }) => {}
            Ok(AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland account_data PUT returned {status}; local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "account_data PUT for read-receipt prefs failed: {}",
                    err.display()
                );
            }
        }
    });
}

/// Push the actor-private personal blocklist to soland. Local state is
/// authoritative; network errors are logged only so privacy controls keep
/// working offline and against older soland builds.
pub(crate) fn push_blocklist_account_data(
    base_url: String,
    api_token: String,
    entries: Vec<crate::account_data::BlocklistEntry>,
) {
    if api_token.trim().is_empty() {
        return;
    }
    let body = crate::account_data::build_blocklist_account_data_body(&entries);
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.set_account_data(CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY, body)
                .await
        })
        .await
        {
            Ok(AccountDataSetOutcome::Stored { .. }) => {}
            Ok(AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland account_data PUT for cx.account.blocklist returned {status}; \
                     local blocklist remains authoritative"
                );
            }
            Err(err) => {
                tracing::debug!(
                    "account_data PUT for cx.account.blocklist failed: {}",
                    err.display()
                );
            }
        }
    });
}

/// F-BLOCKLIST-VALID-1: client-side DID format sanity check for live form
/// validation. Matches the canonical DID Core scheme (`did:<method>:<id>`)
/// where method is at least one ASCII letter / digit and id is at least one
/// printable character. Reused by the blocklist add form (and intended to
/// gradually replace the bare `starts_with("did:")` check in the contact
/// remark add form too). The point is to give the user *live* feedback
/// while typing, not to enforce server-side DID validity — the soland
/// reducer still has final say.
pub(crate) fn is_likely_valid_did(input: &str) -> bool {
    let trimmed = input.trim();
    let Some(rest) = trimmed.strip_prefix("did:") else {
        return false;
    };
    let mut parts = rest.splitn(2, ':');
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(id) = parts.next() else {
        return false;
    };
    // Round 4 (spec a77b995) — tightened method regex to
    // `^did:[a-z0-9]+:[^\s]+$`. The method segment MUST be lowercase
    // ASCII alphanumeric (no `.`/`-`/`_`/`:`); the method-specific id
    // MUST NOT contain whitespace.
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        || id.trim().is_empty()
        || id.chars().any(char::is_whitespace)
    {
        return false;
    }
    true
}

/// Spec client-preferences.md §3.7: push (or tombstone) a Space remark to
/// soland via `cx.account_data.set`. Same graceful-degradation contract as
/// [`push_read_receipt_account_data`] — local state is authoritative; the
/// server PUT is best-effort. `remark.is_empty()` triggers a DELETE so the
/// row tombstones cleanly across devices.
fn push_space_remark_account_data(
    base_url: String,
    api_token: String,
    space_id: String,
    remark: crate::account_data::SpaceRemark,
) {
    let key = crate::account_data::space_remark_account_data_key(&space_id);
    spawn(async move {
        if remark.is_empty() {
            let key_for_log = key.clone();
            if let Err(err) = with_authed_api(&base_url, api_token, |api| {
                let key = key.clone();
                async move { api.delete_account_data(&key).await }
            })
            .await
            {
                tracing::debug!(
                    "account_data DELETE for {key_for_log} failed: {}; local state still authoritative",
                    err.display()
                );
            }
            return;
        }
        let body = match serde_json::to_value(&remark) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("space remark serialisation failed: {error}");
                return;
            }
        };
        let key_for_log = key.clone();
        match with_authed_api(&base_url, api_token, |api| {
            let key = key.clone();
            async move { api.set_account_data(&key, body).await }
        })
        .await
        {
            Ok(crate::models::AccountDataSetOutcome::Stored { .. }) => {}
            Ok(crate::models::AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland account_data PUT for {key_for_log} returned {status}; local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "account_data PUT for {key_for_log} failed: {}",
                    err.display()
                );
            }
        }
    });
}

fn push_contact_remark_account_data(
    base_url: String,
    api_token: String,
    actor_did: String,
    remark: crate::account_data::ContactRemark,
) {
    let key = crate::account_data::contact_remark_account_data_key(&actor_did);
    spawn(async move {
        if remark.is_empty() {
            let key_for_log = key.clone();
            if let Err(err) = with_authed_api(&base_url, api_token, |api| {
                let key = key.clone();
                async move { api.delete_account_data(&key).await }
            })
            .await
            {
                tracing::debug!(
                    "account_data DELETE for {key_for_log} failed: {}; local state still authoritative",
                    err.display()
                );
            }
            return;
        }
        let body = match serde_json::to_value(&remark) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("contact remark serialisation failed: {error}");
                return;
            }
        };
        let key_for_log = key.clone();
        match with_authed_api(&base_url, api_token, |api| {
            let key = key.clone();
            async move { api.set_account_data(&key, body).await }
        })
        .await
        {
            Ok(crate::models::AccountDataSetOutcome::Stored { .. }) => {}
            Ok(crate::models::AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland account_data PUT for {key_for_log} returned {status}; local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "account_data PUT for {key_for_log} failed: {}",
                    err.display()
                );
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
    /// G3.Y3 — consent grants (`/settings/consent`).
    Consent,
    /// G3.Y3 — personal blocklist (`/settings/blocklist`).
    Blocklist,
    /// G3.Y3 — capability delegation viewer (`/settings/capabilities`).
    Capabilities,
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
            "consent" => Self::Consent,
            "blocklist" | "blocked-users" => Self::Blocklist,
            "capabilities" => Self::Capabilities,
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
            Self::Consent => "consent",
            Self::Blocklist => "blocklist",
            Self::Capabilities => "capabilities",
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
            Self::Consent => "Consent grants",
            Self::Blocklist => "Blocked actors",
            Self::Capabilities => "Capabilities",
            Self::Theme => "Appearance & locale",
            Self::Release => "Diagnostics",
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
            Self::Consent => "Consent",
            Self::Blocklist => "Blocklist",
            Self::Capabilities => "Authorization",
            Self::Theme => "Preferences",
            Self::Release => "Advanced",
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
            Self::Consent => {
                "Per-peer consent grants — who may contact you, in what scope, until when. Spec identity/consent-model.md §2."
            }
            Self::Blocklist => {
                "Actor-private personal blocklist. Spec governance/content-moderation.md §4 — client-side filter complementing server-side quarantine."
            }
            Self::Capabilities => {
                "Capability grants held or issued by this actor, with delegation chain. Spec authz/capabilities.md §3."
            }
            Self::Theme => {
                "Theme, locale, and client-facing defaults that stay private to this actor."
            }
            Self::Release => {
                "Advanced diagnostics, release blockers, sync posture, and operational status in one place."
            }
        }
    }
}

const SETTINGS_ACCOUNT_GROUP: &[SettingsSection] = &[SettingsSection::Server];
const SETTINGS_SECURITY_GROUP: &[SettingsSection] =
    &[SettingsSection::Encryption, SettingsSection::Capabilities];
const SETTINGS_DELIVERY_GROUP: &[SettingsSection] = &[
    SettingsSection::Notifications,
    SettingsSection::Privacy,
    // G3.Y3 — consent + blocklist sit next to Privacy because both are
    // actor-private disclosure controls (spec
    // identity/consent-model.md §2, governance/content-moderation.md §4).
    SettingsSection::Consent,
    SettingsSection::Blocklist,
];
const SETTINGS_CLIENT_GROUP: &[SettingsSection] =
    &[SettingsSection::Theme, SettingsSection::Storage];
const SETTINGS_INTEGRATIONS_GROUP: &[SettingsSection] = &[SettingsSection::Mimi];
const SETTINGS_ADVANCED_GROUP: &[SettingsSection] = &[SettingsSection::Release];
const SETTINGS_NAV_GROUPS: &[(&str, &str, &[SettingsSection])] = &[
    (
        "Account",
        "Principal identity, profile, and delegated service boundaries.",
        SETTINGS_ACCOUNT_GROUP,
    ),
    (
        "Security",
        "Device identity, recovery, capability grants, and local encryption posture.",
        SETTINGS_SECURITY_GROUP,
    ),
    (
        "Notifications & privacy",
        "Notification delivery behavior, actor-private disclosure controls, and consent/blocklist.",
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
    (
        "Advanced",
        "Diagnostics, release blockers, and protocol health checks.",
        SETTINGS_ADVANCED_GROUP,
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
    // Space remarks editor state (spec client-preferences.md §3.7).
    // `space_remarks_snapshot` is the resolved BTreeMap rendered for the
    // list; `space_remark_inputs` keeps unsaved text edits keyed by
    // space_id so users can type without round-tripping through soland.
    // `new_space_remark_id` / `new_space_remark_name` drive the "Add by
    // Space ID" row for Spaces the user has joined but isn't yet
    // tracking locally.
    let mut space_remarks_snapshot = use_signal(|| state_store.read().space_remarks());
    let mut space_remark_inputs = use_signal(|| {
        state_store
            .read()
            .space_remarks()
            .into_iter()
            .map(|(id, r)| (id, r.local_name))
            .collect::<std::collections::BTreeMap<String, String>>()
    });
    let mut new_space_remark_id = use_signal(String::new);
    let mut new_space_remark_name = use_signal(String::new);
    let mut contact_remarks_snapshot = use_signal(|| state_store.read().contact_remarks());
    let mut contact_remark_inputs = use_signal(|| {
        state_store
            .read()
            .contact_remarks()
            .into_iter()
            .map(|(did, r)| (did, r.local_name))
            .collect::<std::collections::BTreeMap<String, String>>()
    });
    let mut new_contact_remark_did = use_signal(String::new);
    let mut new_contact_remark_name = use_signal(String::new);
    // A4b — profile (display_name / bio / avatar) state.
    // `avatar_blob_ref` mirrors the most-recently uploaded avatar via
    // `cx.account_data.set("client.ui", { avatar_blob_ref })` and is
    // *also* published publicly to soland's
    // `POST /api/v1/account/profile { avatar_url }` so the directory
    // can index it. `avatar_upload_status` carries the inline
    // progress / error message.
    let initial_avatar_blob_ref = state_store
        .read()
        .load_private_data(&account_did(), "avatar_blob_ref")
        .unwrap_or_default();
    let mut profile_avatar_blob_ref = use_signal(|| initial_avatar_blob_ref.clone());
    let mut avatar_upload_status = use_signal(String::new);
    let mut avatar_cache_status = use_signal(String::new);
    let mut pending_avatar_crop = use_signal(|| None::<PendingAvatarCrop>);
    let mut avatar_crop_zoom = use_signal(|| 125_i32);
    let mut avatar_crop_x = use_signal(|| 0_i32);
    let mut avatar_crop_y = use_signal(|| 0_i32);
    let mut blocklist_snapshot = use_signal(|| state_store.read().client_blocklist());
    let mut blocklist_did_input = use_signal(String::new);
    let mut blocklist_reason_input = use_signal(String::new);
    let mut blocklist_status = use_signal(String::new);
    let mut mls_group_policy = use_signal(|| "default".to_owned());
    let mut key_backup_status = use_signal(|| "Not configured".to_owned());
    let mut key_backup_id =
        use_signal(|| "cx:backup:01964137-0000-7000-8000-000000000000".to_owned());
    let mut key_backup_passphrase = use_signal(String::new);
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
    {
        let account_key = account_did();
        use_effect(move || {
            let hydrated = state_store
                .read()
                .load_private_data(&account_key, "avatar_blob_ref")
                .unwrap_or_default();
            if hydrated != profile_avatar_blob_ref() {
                profile_avatar_blob_ref.set(hydrated.clone());
                avatar_cache_status.set(if hydrated.trim().is_empty() {
                    "Avatar cleared from synced preferences".to_owned()
                } else {
                    "Avatar restored from synced preferences".to_owned()
                });
            }
        });
    }
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
                                span { class: "badge amber", "Advanced diagnostics" }
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
                                    // T1.3 — show the active proof mode so
                                    // the user can spot at a glance whether
                                    // a real signer is wired before any
                                    // event leaves the device.
                                    div { class: "metric", "data-testid": "settings-proof-mode",
                                        strong { {crate::i18n::tr("settings.proof_mode.label")} }
                                        span { {crate::operation::current_proof_mode().label_en()} }
                                        div { class: "muted", {crate::i18n::tr("settings.proof_mode.hint")} }
                                    }
                                    // T5.2 — show the active signer DID, key
                                    // id, algorithm, and proof freshness so
                                    // the user can confirm the device is
                                    // signing with the expected identity and
                                    // when the last event was signed.
                                    {
                                        let status = crate::event_signer::signer_status();
                                        let (signer_did, key_id, alg, mode_tag, freshness) = match &status {
                                            Some(s) => (
                                                s.signer_did.clone(),
                                                s.verification_method.clone(),
                                                s.algorithm.clone(),
                                                s.mode_tag,
                                                s.last_signed_at
                                                    .clone()
                                                    .unwrap_or_else(|| crate::i18n::tr("settings.signer.freshness.never")),
                                            ),
                                            None => (
                                                "—".to_owned(),
                                                "—".to_owned(),
                                                "—".to_owned(),
                                                "none",
                                                crate::i18n::tr("settings.signer.freshness.never"),
                                            ),
                                        };
                                        rsx! {
                                            div {
                                                class: "metric",
                                                "data-testid": "settings-signer-info",
                                                strong { {crate::i18n::tr("settings.signer.label")} }
                                                span {
                                                    "data-testid": "settings-signer-did",
                                                    {signer_did}
                                                }
                                                div {
                                                    class: "muted",
                                                    "data-testid": "settings-signer-key-id",
                                                    {format!("{} ({mode_tag} / {alg})", key_id)}
                                                }
                                                div {
                                                    class: "muted",
                                                    "data-testid": "settings-signer-freshness",
                                                    {format!("{}: {}", crate::i18n::tr("settings.signer.freshness.label"), freshness)}
                                                }
                                            }
                                        }
                                    }
                                }
                                div { class: "actions",
                                    span { class: "badge green", "HTTP/JSON" }
                                    span { class: "badge blue", "v1 core" }
                                    {
                                        let mode = crate::operation::current_proof_mode();
                                        let badge_class = match mode {
                                            crate::operation::ProofMode::RealEd25519
                                            | crate::operation::ProofMode::ExternalSigner => "badge green",
                                            crate::operation::ProofMode::Production => "badge red",
                                        };
                                        rsx! {
                                            span {
                                                class: "{badge_class}",
                                                "data-testid": "settings-proof-mode-badge",
                                                {mode.label_en()}
                                            }
                                        }
                                    }
                                }
                            }

                            // A4b — Profile / avatar card. Renders the
                            // current avatar (resolved via the blob URL
                            // helper when a blob_ref is present), an
                            // upload control, and a clear button. The
                            // avatar is also published to soland's
                            // `cx.account.update_profile` so the
                            // directory + member lists pick it up.
                            div { class: "event settings-card-span-2", "data-testid": "settings-avatar-card",
                                div { class: "event-head",
                                    span { {crate::i18n::tr("settings.avatar.title")} }
                                    span { title: "cx.account.update_profile", "Profile" }
                                }
                                div { class: "actions", style: "align-items: center; gap: 16px;",
                                    {
                                        let blob_ref = profile_avatar_blob_ref();
                                        rsx! {
                                            if !blob_ref.trim().is_empty() {
                                                div {
                                                    "data-testid": "settings-avatar-preview",
                                                    style: "width: 64px; height: 64px; border-radius: 50%; overflow: hidden; border: 1px solid var(--border-default, #333);",
                                                    crate::content::renderer::AuthenticatedBlobImage {
                                                        blob_ref: blob_ref.trim().to_owned(),
                                                        alt_text: "Avatar".to_owned(),
                                                    }
                                                }
                                            } else {
                                                div {
                                                    "data-testid": "settings-avatar-preview",
                                                    style: "width: 64px; height: 64px; border-radius: 50%; background: var(--bg-elevated, #1a1d22); border: 1px dashed var(--border-default, #333); display: flex; align-items: center; justify-content: center; color: var(--muted, #888);",
                                                    "—"
                                                }
                                            }
                                        }
                                    }
                                    div { style: "display: flex; flex-direction: column; gap: 8px;",
                                        label {
                                            class: "secondary",
                                            "data-testid": "settings-avatar-upload-label",
                                            r#for: "settings-avatar-input",
                                            {crate::i18n::tr("settings.avatar.upload")}
                                        }
                                        input {
                                            id: "settings-avatar-input",
                                            "data-testid": "settings-avatar-input",
                                            r#type: "file",
                                            accept: "image/*",
                                            // A4b — Dioxus 0.7 `HasFileData::files()`
                                            // surfaces the dropped / picked file
                                            // list. Read bytes async then upload
                                            // via the blob endpoint + publish the
                                            // resulting blob URL to the profile.
                                            onchange: {
                                                move |evt: Event<FormData>| {
                                                    let files = evt.files();
                                                    if files.is_empty() {
                                                        avatar_upload_status.set(
                                                            crate::i18n::tr("settings.avatar.error"),
                                                        );
                                                        return;
                                                    }
                                                    let file = files.into_iter().next().expect("non-empty");
                                                    let content_type = file
                                                        .content_type()
                                                        .unwrap_or_else(|| "application/octet-stream".to_owned());
                                                    avatar_upload_status.set(
                                                        crate::i18n::tr("settings.avatar.processing"),
                                                    );
                                                    spawn(async move {
                                                        let bytes = match file.read_bytes().await {
                                                            Ok(b) => b.to_vec(),
                                                            Err(err) => {
                                                                avatar_upload_status.set(format!(
                                                                    "{}: {err}",
                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                ));
                                                                return;
                                                            }
                                                        };
                                                        if !content_type.starts_with("image/") {
                                                            avatar_upload_status.set(format!(
                                                                "{}: {}",
                                                                crate::i18n::tr("settings.avatar.error"),
                                                                crate::i18n::tr("settings.avatar.invalid_image"),
                                                            ));
                                                            return;
                                                        }
                                                        let dimensions = match crate::avatar_crop::image_dimensions(&bytes) {
                                                            Ok(dimensions) => dimensions,
                                                            Err(err) => {
                                                                avatar_upload_status.set(format!(
                                                                    "{}: {err}",
                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                ));
                                                                return;
                                                            }
                                                        };
                                                        let preview_data_url = avatar_preview_data_url(&bytes, &content_type);
                                                        pending_avatar_crop.set(Some(PendingAvatarCrop {
                                                            bytes,
                                                            media_type: content_type,
                                                            preview_data_url,
                                                            dimensions,
                                                        }));
                                                        avatar_crop_zoom.set(125);
                                                        avatar_crop_x.set(0);
                                                        avatar_crop_y.set(0);
                                                        avatar_upload_status.set(
                                                            crate::i18n::tr("settings.avatar.crop_ready"),
                                                        );
                                                    });
                                                }
                                            },
                                        }
                                        if let Some(selection) = pending_avatar_crop.read().clone() {
                                            div {
                                                "data-testid": "settings-avatar-crop-editor",
                                                style: "display: grid; grid-template-columns: minmax(128px, 180px) minmax(220px, 1fr); gap: 16px; align-items: center; max-width: 560px;",
                                                div {
                                                    "data-testid": "settings-avatar-crop-stage",
                                                    style: "position: relative; width: min(180px, 40vw); aspect-ratio: 1; border-radius: 50%; overflow: hidden; border: 1px solid var(--border-default, #333); background: var(--bg-elevated, #1a1d22);",
                                                    img {
                                                        src: "{selection.preview_data_url}",
                                                        alt: "Selected avatar",
                                                        style: format!(
                                                            "width: 100%; height: 100%; object-fit: cover; transform-origin: center; transform: translate({}% , {}%) scale({});",
                                                            avatar_crop_x() / 4,
                                                            avatar_crop_y() / 4,
                                                            avatar_crop_zoom() as f32 / 100.0,
                                                        ),
                                                    }
                                                }
                                                div { style: "display: grid; gap: 10px;",
                                                    div { class: "muted", "data-testid": "settings-avatar-source-size",
                                                        {format!("{} x {} / {}", selection.dimensions.0, selection.dimensions.1, selection.media_type)}
                                                    }
                                                    label { class: "form-field",
                                                        span { {crate::i18n::tr("settings.avatar.zoom")} }
                                                        input {
                                                            "data-testid": "settings-avatar-crop-zoom",
                                                            r#type: "range",
                                                            min: "100",
                                                            max: "300",
                                                            step: "5",
                                                            value: "{avatar_crop_zoom()}",
                                                            oninput: move |event| {
                                                                if let Ok(value) = event.value().parse::<i32>() {
                                                                    avatar_crop_zoom.set(value.clamp(100, 300));
                                                                }
                                                            },
                                                        }
                                                    }
                                                    label { class: "form-field",
                                                        span { {crate::i18n::tr("settings.avatar.pan_x")} }
                                                        input {
                                                            "data-testid": "settings-avatar-crop-x",
                                                            r#type: "range",
                                                            min: "-100",
                                                            max: "100",
                                                            step: "5",
                                                            value: "{avatar_crop_x()}",
                                                            oninput: move |event| {
                                                                if let Ok(value) = event.value().parse::<i32>() {
                                                                    avatar_crop_x.set(value.clamp(-100, 100));
                                                                }
                                                            },
                                                        }
                                                    }
                                                    label { class: "form-field",
                                                        span { {crate::i18n::tr("settings.avatar.pan_y")} }
                                                        input {
                                                            "data-testid": "settings-avatar-crop-y",
                                                            r#type: "range",
                                                            min: "-100",
                                                            max: "100",
                                                            step: "5",
                                                            value: "{avatar_crop_y()}",
                                                            oninput: move |event| {
                                                                if let Ok(value) = event.value().parse::<i32>() {
                                                                    avatar_crop_y.set(value.clamp(-100, 100));
                                                                }
                                                            },
                                                        }
                                                    }
                                                    div { class: "actions",
                                                        button {
                                                            class: "secondary",
                                                            "data-testid": "settings-avatar-upload-cropped",
                                                            onclick: {
                                                                let base = base_url();
                                                                let api_token = token();
                                                                move |_| {
                                                                    let Some(selection) = pending_avatar_crop.read().clone() else {
                                                                        avatar_upload_status.set(crate::i18n::tr("settings.avatar.error"));
                                                                        return;
                                                                    };
                                                                    let crop = crate::avatar_crop::AvatarCrop {
                                                                        zoom: avatar_crop_zoom() as f32 / 100.0,
                                                                        pan_x: avatar_crop_x() as f32 / 100.0,
                                                                        pan_y: avatar_crop_y() as f32 / 100.0,
                                                                    };
                                                                    let base = base.clone();
                                                                    let api_token = api_token.clone();
                                                                    avatar_upload_status.set(crate::i18n::tr("settings.avatar.uploading"));
                                                                    spawn(async move {
                                                                        let bytes = match crate::avatar_crop::crop_avatar_jpeg(&selection.bytes, crop) {
                                                                            Ok(bytes) => bytes,
                                                                            Err(err) => {
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let api = match crate::views::helpers::authed_api(&base, api_token.clone()) {
                                                                            Ok(api) => api,
                                                                            Err(err) => {
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                                return;
                                                                            }
                                                                        };
                                                                        match api.upload_blob_bytes(bytes, "image/jpeg").await {
                                                                            Ok(resp) => {
                                                                                let blob_ref = resp.blob_ref.clone();
                                                                                let avatar_url = api.blob_download_url(&blob_ref);
                                                                                // 1) Mirror locally + push actor-private
                                                                                //    `client.ui.avatar_blob_ref` so other
                                                                                //    devices pick up the same upload.
                                                                                profile_avatar_blob_ref.set(blob_ref.clone());
                                                                                state_store.write().save_private_data(
                                                                                    &account_did(),
                                                                                    "avatar_blob_ref",
                                                                                    blob_ref.clone(),
                                                                                );
                                                                                push_client_ui_account_data_with_avatar(
                                                                                    base.clone(),
                                                                                    api_token.clone(),
                                                                                    theme(),
                                                                                    Some(blob_ref.clone()),
                                                                                );
                                                                                // 2) Publish publicly via
                                                                                //    `cx.account.update_profile`.
                                                                                //    Best-effort: log on failure but
                                                                                //    keep the local cache intact.
                                                                                match api
                                                                                    .update_profile(None, None, Some(&avatar_url))
                                                                                    .await
                                                                                {
                                                                                    Ok(_) => {
                                                                                        pending_avatar_crop.set(None);
                                                                                        avatar_upload_status.set(String::new());
                                                                                        status.set(format!(
                                                                                            "Avatar updated ({blob_ref})"
                                                                                        ));
                                                                                    }
                                                                                    Err(err) => {
                                                                                        avatar_upload_status.set(format!(
                                                                                            "{}: {}",
                                                                                            crate::i18n::tr("settings.avatar.error"),
                                                                                            err,
                                                                                        ));
                                                                                    }
                                                                                }
                                                                            }
                                                                            Err(err) => {
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            {crate::i18n::tr("settings.avatar.upload_cropped")}
                                                        }
                                                        button {
                                                            class: "secondary",
                                                            "data-testid": "settings-avatar-crop-cancel",
                                                            onclick: move |_| {
                                                                pending_avatar_crop.set(None);
                                                                avatar_upload_status.set(String::new());
                                                            },
                                                            {crate::i18n::tr("settings.avatar.cancel_crop")}
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if !profile_avatar_blob_ref().trim().is_empty() {
                                            button {
                                                class: "secondary",
                                                "data-testid": "settings-avatar-clear",
                                                onclick: {
                                                    let base = base_url();
                                                    let api_token = token();
                                                    move |_| {
                                                        let base = base.clone();
                                                        let api_token = api_token.clone();
                                                        profile_avatar_blob_ref.set(String::new());
                                                        pending_avatar_crop.set(None);
                                                        state_store.write().save_private_data(
                                                            &account_did(),
                                                            "avatar_blob_ref",
                                                            "",
                                                        );
                                                        avatar_upload_status.set(String::new());
                                                        avatar_cache_status.set(
                                                            "Avatar removed locally; syncing clear to other devices.".to_owned(),
                                                        );
                                                        // Tombstone the actor-private mirror so
                                                        // other devices clear too.
                                                        push_client_ui_account_data_with_avatar(
                                                            base.clone(),
                                                            api_token.clone(),
                                                            theme(),
                                                            Some(String::new()),
                                                        );
                                                        // Tombstone the public profile entry.
                                                        spawn(async move {
                                                            if let Ok(api) =
                                                                crate::views::helpers::authed_api(&base, api_token)
                                                            {
                                                                if let Err(err) = api
                                                                    .update_profile(None, None, Some(""))
                                                                    .await
                                                                {
                                                                    tracing::warn!("avatar profile clear failed: {err}");
                                                                }
                                                            }
                                                        });
                                                    }
                                                },
                                                {crate::i18n::tr("settings.avatar.clear")}
                                            }
                                        }
                                        if !avatar_upload_status().is_empty() {
                                            div {
                                                class: "muted",
                                                "data-testid": "settings-avatar-upload-progress",
                                                "{avatar_upload_status}"
                                            }
                                        }
                                        if !avatar_cache_status().is_empty() {
                                            div {
                                                class: "muted",
                                                "data-testid": "settings-avatar-cache-status",
                                                "{avatar_cache_status}"
                                            }
                                        }
                                    }
                                }
                                div { class: "muted",
                                    "Published via cx.account.update_profile; mirrored to other devices via client.ui.avatar_blob_ref."
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
                    {
                        // Inline strength meter so users notice when the
                        // passphrase is too short to protect the backup.
                        let strength = estimate_passphrase_strength(&key_backup_passphrase());
                        let strength_label = match strength {
                            0 => "(passphrase required)",
                            1..=2 => "weak",
                            3 => "fair",
                            _ => "strong",
                        };
                        rsx! { div { class: "muted",
                            "Passphrase strength: {strength_label}"
                        } }
                    }
                    div { class: "actions",
                        input {
                            "data-testid": "key-backup-id-input",
                            value: "{key_backup_id}",
                            oninput: move |evt| key_backup_id.set(evt.value()),
                        }
                        input {
                            "data-testid": "key-backup-passphrase-input",
                            r#type: "password",
                            value: "{key_backup_passphrase}",
                            placeholder: "Vault passphrase",
                            oninput: move |evt| key_backup_passphrase.set(evt.value()),
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
                                let passphrase = key_backup_passphrase();
                                if passphrase.trim().is_empty() {
                                    key_backup_status.set(
                                        "Enter a vault passphrase before storing the backup."
                                            .to_owned(),
                                    );
                                    return;
                                }
                                // Backup body schema mirrors the recovery vault
                                // payload (see views/recovery.rs) so the same
                                // restore flow recovers backups created here.
                                // The plaintext carries identity refs only —
                                // device signing key + MLS state are stored in
                                // separate scoped backups by future flows.
                                let payload_plaintext = serde_json::json!({
                                    "schema_version": 1,
                                    "actor_did": actor,
                                    "device_id": device,
                                    "minted_at": chrono::Utc::now().to_rfc3339(),
                                    "source": "settings.encryption.store_backup",
                                })
                                .to_string();
                                let pass_bytes = passphrase.into_bytes();
                                spawn(async move {
                                    let kek = match derive_vault_kek(&pass_bytes) {
                                        Ok(k) => k,
                                        Err(err) => {
                                            key_backup_status.set(format!(
                                                "Argon2id stretch failed: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                    let ct = match encrypt_vault(
                                        &kek,
                                        payload_plaintext.as_bytes(),
                                    ) {
                                        Ok(c) => c,
                                        Err(err) => {
                                            key_backup_status.set(format!(
                                                "AEAD encrypt failed: {err}"
                                            ));
                                            return;
                                        }
                                    };
                                    let body = build_recovery_vault_backup_body(
                                        &backup_id,
                                        &actor,
                                        &device,
                                        &ct.ciphertext_b64,
                                        &ct.digest_sha256,
                                        &ct.salt_b64,
                                        &ct.nonce_b64,
                                        VAULT_ARGON2_M_KIB,
                                        VAULT_ARGON2_T,
                                        VAULT_ARGON2_P,
                                    );
                                    let backup_id_clone = backup_id.clone();
                                    let backup_id_for_log = backup_id.clone();
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.put_key_backup(&backup_id_clone, body).await
                                    })
                                    .await
                                    {
                                        Ok(_) => {
                                            key_backup_status.set(format!(
                                                "Backup {backup_id_for_log} stored ({} bytes ciphertext)",
                                                ct.ciphertext.len()
                                            ));
                                            key_backup_passphrase.set(String::new());
                                        }
                                        Err(err) => key_backup_status
                                            .set(format!("Backup store failed: {}", err.display())),
                                    }
                                });
                            },
                            {crate::i18n::tr("settings.store_backup")}
                        }
                        button {
                            class: "secondary",
                            "data-testid": "key-backup-list",
                            onclick: move |_| {
                                let base = base_url();
                                let api_token = token();
                                spawn(async move {
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.list_key_backups().await
                                    })
                                    .await
                                    {
                                        Ok(response) => key_backup_status
                                            .set(format!("Backups: {response}")),
                                        Err(err) => key_backup_status
                                            .set(format!("Backup list: {}", err.display())),
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
                                    let backup_id_for_msg = backup_id.clone();
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.get_key_backup(&backup_id).await
                                    })
                                    .await
                                    {
                                        Ok(response) => key_backup_status.set(format!(
                                            "Backup {backup_id_for_msg}: {response}"
                                        )),
                                        Err(err) => key_backup_status
                                            .set(format!("Backup load: {}", err.display())),
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
                                    match with_authed_api(&base, api_token, |api| async move {
                                        api.delete_key_backup(&backup_id).await
                                    })
                                    .await
                                    {
                                        Ok(response) => key_backup_status
                                            .set(format!("Backup deleted: {response}")),
                                        Err(err) => key_backup_status
                                            .set(format!("Backup delete: {}", err.display())),
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
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.mimi_provider_directory().await
                                        })
                                        .await
                                        {
                                            Ok(directory) => {
                                                let features = directory.mimi.features.join(", ");
                                                mimi_directory.set(format!(
                                                    "{}\n{}\n{}\n{}",
                                                    directory.mimi.provider_id,
                                                    directory.supported_profiles.join(", "),
                                                    directory.mimi.protocol_draft,
                                                    features,
                                                ));
                                                status.set(
                                                    "MIMI provider directory refreshed".to_owned(),
                                                );
                                            }
                                            Err(err) => {
                                                let message =
                                                    format!("MIMI directory: {}", err.display());
                                                mimi_directory.set(message.clone());
                                                status.set(message);
                                            }
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
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.mimi_group_info("01JSMIMI").await
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                mimi_receipt.set(format!(
                                                    "group-info {} participants {}",
                                                    response.room_id,
                                                    response.participants.len()
                                                ));
                                                status.set("MIMI groupInfo loaded".to_owned());
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI groupInfo failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                status.set(message);
                                            }
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
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.mimi_identifier_query(json!({
                                                "query": "mimi://remote.example/alice",
                                                "privacy_mode": "private_identifier_query"
                                            })).await
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                mimi_receipt.set(format!(
                                                    "identifier {} reachable {} mapped {}",
                                                    response.query,
                                                    response.reachable,
                                                    response.mapped_did.unwrap_or_else(|| "none".to_owned())
                                                ));
                                                status.set("MIMI identifier query completed".to_owned());
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI identifier query failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                status.set(message);
                                            }
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
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.mimi_submit_message("01JSMIMI", json!({
                                                "source_format": "text/markdown;variant=GFM-MIMI",
                                                "body": "MIMI interop test from yougen",
                                                "mimi_room_uri": "mimi://mimi.example.com/rooms/01JSMIMI"
                                            })).await
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                mimi_receipt.set(format!(
                                                    "submit-message {} {}",
                                                    response.mimi_message_id.unwrap_or_else(|| "no-message-id".to_owned()),
                                                    response.mapped_operation_id.unwrap_or_else(|| "no-operation".to_owned())
                                                ));
                                                status.set("MIMI test message submitted".to_owned());
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI submit failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                status.set(message);
                                            }
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
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.mimi_proxy_download(json!({
                                                "blob_ref": "cx:blob:sha256:e2e",
                                                "asset_privacy_policy": "provider_proxy"
                                            })).await
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                mimi_receipt.set(format!(
                                                    "proxy-download {} {}",
                                                    response.blob_ref,
                                                    response.media_type.unwrap_or_else(|| "unknown".to_owned())
                                                ));
                                                status.set("MIMI proxy download prepared".to_owned());
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI proxy download failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                status.set(message);
                                            }
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
                                        let request = match crate::push::build_register_request(&dev) {
                                            Ok(r) => r,
                                            Err(error) => {
                                                let message = format!("push unavailable: {error}");
                                                push_state.set(message.clone());
                                                status.set(message);
                                                return;
                                            }
                                        };
                                        let request_for_async = request.clone();
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.register_push_device_with_request(&request_for_async).await
                                        })
                                        .await
                                        {
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
                                            Err(err) => {
                                                let message = format!("push register failed: {}", err.display());
                                                push_state.set(message.clone());
                                                status.set(message);
                                            }
                                        }
                                    });
                                }
                            },
                            {crate::i18n::tr("settings.register_push")}
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
                                        let request = match crate::push::build_unregister_request(&dev, existing.as_ref()) {
                                            Ok(r) => r,
                                            Err(error) => {
                                                status.set(format!("push unregister unavailable: {error}"));
                                                return;
                                            }
                                        };
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.unregister_push_device_with_request(&request).await
                                        })
                                        .await
                                        {
                                            Ok(_) => {
                                                state_store.write().clear_push_registration();
                                                push_state.set("Not registered".to_owned());
                                                status.set("Push unregistered".to_owned());
                                            }
                                            Err(err) => {
                                                let message = format!("push unregister failed: {}", err.display());
                                                push_state.set(message.clone());
                                                status.set(message);
                                            }
                                        }
                                    });
                                }
                            },
                            {crate::i18n::tr("settings.unregister_push")}
                        }
                    }
                    div { class: "event", "data-testid": "notifications-mute-summary",
                        div { class: "event-head",
                            span { "Per-space mute rules" }
                            span { "{muted_spaces.len()} muted" }
                        }
                        if muted_spaces.is_empty() {
                            div { class: "muted", {crate::i18n::tr("settings.muted_spaces_empty")} }
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
                        " Show presence to others"
                    }
                    div { class: "event-head",
                        span { "Read receipts" }
                        span { title: "cx.read_receipt.preferences", "Preferences" }
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
                                // Also push to soland's cx.account_data.set
                                // so other devices pick up the change.
                                // Endpoint may 404/501 — we swallow and keep
                                // local authoritative.
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
                                    let _ = with_authed_api(&base, api_token, |api| async move {
                                        api.set_account_data(
                                            READ_RECEIPT_ACCOUNT_DATA_KEY,
                                            body,
                                        )
                                        .await
                                    })
                                    .await;
                                });
                            },
                        }
                        " Send read receipts (cx.receipt.read) by default "
                        HelpTip { text: "Resolution order is (flow → space → default). When a Space declares a read-receipt policy with disclosure=required or disabled, the server policy overrides this preference." }
                    }
                    div { class: "event-head",
                        span { "Per-space overrides" }
                        span { "{read_receipt_space_overrides().len()} configured" }
                        HelpTip { text: "Add a Space ID below to opt this Space out of (or into) read receipts independently of the global default. Server-declared policy lock is wired: when soland's Anchor view (P0 M3) surfaces a cx.realm.read_receipt_policy with disclosure=required or disabled, the matching per-Space toggle shows a `locked by Realm policy` badge and the controls become disabled — see LocalStateStore::read_receipt_should_send." }
                    }
                    for (space_id, send) in read_receipt_space_overrides() {
                            // Policy lock — when soland publishes a
                            // cx.realm.read_receipt_policy with disclosure=
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

                // ── Space remarks (spec discovery/client-preferences.md §3.7) ─
                // Actor-private local alias / note / pin for each Space the
                // user has joined. Lets users disambiguate duplicate-titled
                // Spaces without leaking the remark beyond this account.
                // Pushed to soland via `cx.account_data.set` under
                // `cx.contacts.space.<space_id>`; soland echoes the same
                // entries back on the next `/sync` so other devices pick
                // them up.
                div { class: "event", "data-testid": "space-remarks-editor",
                    div { class: "event-head",
                        span { "Space remarks" }
                        span { "cx.contacts.space.<space_id>" }
                        HelpTip { text: "Private to this account. The remark replaces the public Space title in the sidebar / dashboard. Other Space members never see it." }
                    }
                    {
                        let remarks = space_remarks_snapshot();
                        if remarks.is_empty() {
                            rsx! {
                                div {
                                    class: "muted",
                                    "data-testid": "space-remarks-empty",
                                    "No remarks yet. Add one below to distinguish duplicate-titled Spaces."
                                }
                            }
                        } else {
                            rsx! {
                                for (space_id, remark) in remarks {
                                    div {
                                        class: "actions",
                                        "data-testid": "space-remark-row",
                                        "data-space-id": "{space_id}",
                                        span { class: "mono", "{space_id}" }
                                        input {
                                            r#type: "text",
                                            "data-testid": "space-remark-input",
                                            placeholder: "Local name (private)",
                                            value: "{space_remark_inputs().get(&space_id).cloned().unwrap_or_else(|| remark.local_name.clone())}",
                                            oninput: {
                                                let id = space_id.clone();
                                                move |evt: FormEvent| {
                                                    let mut current = space_remark_inputs();
                                                    current.insert(id.clone(), evt.value());
                                                    space_remark_inputs.set(current);
                                                }
                                            },
                                        }
                                        button {
                                            class: "secondary",
                                            "data-testid": "space-remark-save",
                                            onclick: {
                                                let id = space_id.clone();
                                                let existing = remark.clone();
                                                move |_| {
                                                    let id = id.clone();
                                                    let next_name = space_remark_inputs()
                                                        .get(&id)
                                                        .cloned()
                                                        .unwrap_or_default();
                                                    let mut next = existing.clone();
                                                    next.local_name = next_name.trim().to_owned();
                                                    next.updated_at = Some(
                                                        chrono::Utc::now()
                                                            .to_rfc3339_opts(
                                                                chrono::SecondsFormat::Secs,
                                                                true,
                                                            ),
                                                    );
                                                    state_store
                                                        .write()
                                                        .set_space_remark(id.clone(), next.clone());
                                                    space_remarks_snapshot.set(
                                                        state_store.read().space_remarks(),
                                                    );
                                                    if next.is_empty() {
                                                        status.set(format!(
                                                            "Space remark cleared for {id}"
                                                        ));
                                                    } else {
                                                        status.set(format!(
                                                            "Space remark saved: {} → {}",
                                                            id, next.local_name
                                                        ));
                                                    }
                                                    push_space_remark_account_data(
                                                        base_url(),
                                                        token(),
                                                        id,
                                                        next,
                                                    );
                                                }
                                            },
                                            "Save"
                                        }
                                        button {
                                            class: "secondary",
                                            "data-testid": "space-remark-delete",
                                            onclick: {
                                                let id = space_id.clone();
                                                move |_| {
                                                    let id = id.clone();
                                                    state_store.write().remove_space_remark(&id);
                                                    let mut inputs = space_remark_inputs();
                                                    inputs.remove(&id);
                                                    space_remark_inputs.set(inputs);
                                                    space_remarks_snapshot.set(
                                                        state_store.read().space_remarks(),
                                                    );
                                                    status.set(format!(
                                                        "Space remark cleared for {id}"
                                                    ));
                                                    push_space_remark_account_data(
                                                        base_url(),
                                                        token(),
                                                        id,
                                                        crate::account_data::SpaceRemark::default(),
                                                    );
                                                }
                                            },
                                            "Delete"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "actions", "data-testid": "space-remark-add-row",
                        input {
                            r#type: "text",
                            "data-testid": "space-remark-add-id",
                            placeholder: "cx:space:...",
                            value: "{new_space_remark_id()}",
                            oninput: move |evt| new_space_remark_id.set(evt.value()),
                        }
                        input {
                            r#type: "text",
                            "data-testid": "space-remark-add-name",
                            placeholder: "Local name",
                            value: "{new_space_remark_name()}",
                            oninput: move |evt| new_space_remark_name.set(evt.value()),
                        }
                        button {
                            class: "secondary",
                            "data-testid": "space-remark-add-save",
                            onclick: move |_| {
                                let space_id = new_space_remark_id().trim().to_owned();
                                let local_name = new_space_remark_name().trim().to_owned();
                                if space_id.is_empty() || local_name.is_empty() {
                                    status.set(
                                        "Enter both a Space ID and a local name".to_owned(),
                                    );
                                    return;
                                }
                                if !space_id.starts_with("cx:space:") {
                                    status.set(
                                        "Space ID must start with cx:space:".to_owned(),
                                    );
                                    return;
                                }
                                let now_rfc3339 = chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                let remark = crate::account_data::SpaceRemark {
                                    version: 1,
                                    space_id: space_id.clone(),
                                    local_name: local_name.clone(),
                                    saved_at: Some(now_rfc3339.clone()),
                                    updated_at: Some(now_rfc3339),
                                    ..crate::account_data::SpaceRemark::default()
                                };
                                state_store
                                    .write()
                                    .set_space_remark(space_id.clone(), remark.clone());
                                space_remarks_snapshot.set(state_store.read().space_remarks());
                                new_space_remark_id.set(String::new());
                                new_space_remark_name.set(String::new());
                                status.set(format!(
                                    "Space remark saved: {space_id} → {local_name}"
                                ));
                                push_space_remark_account_data(
                                    base_url(),
                                    token(),
                                    space_id,
                                    remark,
                                );
                            },
                            "Add remark"
                        }
                    }
                }

                div { class: "event", "data-testid": "contact-remarks-editor",
                    div { class: "event-head",
                        span { "Contact remarks" }
                        span { "cx.contacts.actor.<did>" }
                        HelpTip { text: "Private to this account. The local name is shown only on this device/account and is synced through actor-private account_data." }
                    }
                    {
                        let remarks = contact_remarks_snapshot();
                        if remarks.is_empty() {
                            rsx! {
                                div {
                                    class: "muted",
                                    "data-testid": "contact-remarks-empty",
                                    "No contact remarks yet. Add a DID below to label someone privately."
                                }
                            }
                        } else {
                            rsx! {
                                for (actor_did, remark) in remarks {
                                    div {
                                        class: "actions",
                                        "data-testid": "contact-remark-row",
                                        "data-actor-did": "{actor_did}",
                                        span { class: "mono", "{actor_did}" }
                                        input {
                                            r#type: "text",
                                            "data-testid": "contact-remark-input",
                                            placeholder: "Local name (private)",
                                            value: "{contact_remark_inputs().get(&actor_did).cloned().unwrap_or_else(|| remark.local_name.clone())}",
                                            oninput: {
                                                let did = actor_did.clone();
                                                move |evt: FormEvent| {
                                                    let mut current = contact_remark_inputs();
                                                    current.insert(did.clone(), evt.value());
                                                    contact_remark_inputs.set(current);
                                                }
                                            },
                                        }
                                        button {
                                            class: "secondary",
                                            "data-testid": "contact-remark-save",
                                            onclick: {
                                                let did = actor_did.clone();
                                                let existing = remark.clone();
                                                move |_| {
                                                    let did = did.clone();
                                                    let next_name = contact_remark_inputs()
                                                        .get(&did)
                                                        .cloned()
                                                        .unwrap_or_default();
                                                    let mut next = existing.clone();
                                                    next.local_name = next_name.trim().to_owned();
                                                    next.updated_at = Some(
                                                        chrono::Utc::now()
                                                            .to_rfc3339_opts(
                                                                chrono::SecondsFormat::Secs,
                                                                true,
                                                            ),
                                                    );
                                                    state_store
                                                        .write()
                                                        .set_contact_remark(did.clone(), next.clone());
                                                    contact_remarks_snapshot.set(
                                                        state_store.read().contact_remarks(),
                                                    );
                                                    status.set(if next.is_empty() {
                                                        format!("Contact remark cleared for {did}")
                                                    } else {
                                                        format!(
                                                            "Contact remark saved: {} → {}",
                                                            did, next.local_name
                                                        )
                                                    });
                                                    push_contact_remark_account_data(
                                                        base_url(),
                                                        token(),
                                                        did,
                                                        next,
                                                    );
                                                }
                                            },
                                            "Save"
                                        }
                                        button {
                                            class: "secondary",
                                            "data-testid": "contact-remark-delete",
                                            onclick: {
                                                let did = actor_did.clone();
                                                move |_| {
                                                    let did = did.clone();
                                                    state_store.write().remove_contact_remark(&did);
                                                    let mut inputs = contact_remark_inputs();
                                                    inputs.remove(&did);
                                                    contact_remark_inputs.set(inputs);
                                                    contact_remarks_snapshot.set(
                                                        state_store.read().contact_remarks(),
                                                    );
                                                    status.set(format!(
                                                        "Contact remark cleared for {did}"
                                                    ));
                                                    push_contact_remark_account_data(
                                                        base_url(),
                                                        token(),
                                                        did,
                                                        crate::account_data::ContactRemark::default(),
                                                    );
                                                }
                                            },
                                            "Delete"
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div { class: "actions", "data-testid": "contact-remark-add-row",
                        input {
                            r#type: "text",
                            "data-testid": "contact-remark-add-did",
                            placeholder: "alice@example.com or @alice",
                            value: "{new_contact_remark_did()}",
                            oninput: move |evt| new_contact_remark_did.set(evt.value()),
                        }
                        input {
                            r#type: "text",
                            "data-testid": "contact-remark-add-name",
                            placeholder: "Local name",
                            value: "{new_contact_remark_name()}",
                            oninput: move |evt| new_contact_remark_name.set(evt.value()),
                        }
                        button {
                            class: "secondary",
                            "data-testid": "contact-remark-add-save",
                            onclick: move |_| {
                                let actor_did = new_contact_remark_did().trim().to_owned();
                                let local_name = new_contact_remark_name().trim().to_owned();
                                if actor_did.is_empty() || local_name.is_empty() {
                                    status.set(
                                        "Enter both an actor DID and a local name".to_owned(),
                                    );
                                    return;
                                }
                                if !actor_did.starts_with("did:") {
                                    status.set("Actor DID must start with did:".to_owned());
                                    return;
                                }
                                let now_rfc3339 = chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                let remark = crate::account_data::ContactRemark {
                                    version: 1,
                                    actor_did: actor_did.clone(),
                                    local_name: local_name.clone(),
                                    saved_at: Some(now_rfc3339.clone()),
                                    updated_at: Some(now_rfc3339),
                                    ..crate::account_data::ContactRemark::default()
                                };
                                state_store
                                    .write()
                                    .set_contact_remark(actor_did.clone(), remark.clone());
                                contact_remarks_snapshot.set(state_store.read().contact_remarks());
                                new_contact_remark_did.set(String::new());
                                new_contact_remark_name.set(String::new());
                                status.set(format!(
                                    "Contact remark saved: {actor_did} → {local_name}"
                                ));
                                push_contact_remark_account_data(
                                    base_url(),
                                    token(),
                                    actor_did,
                                    remark,
                                );
                            },
                            "Add contact"
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
                            span { title: "cx.identity.disclosure_policy", "Policy" }
                            div { class: "muted", "Declares which fields are visible to which audience" }
                        }
                        div { class: "metric",
                            strong { "Presentation request" }
                            span { title: "cx.identity.presentation_request", "Request" }
                            div { class: "muted", "Counterparty-initiated claim request (carries purpose + minimum field set)" }
                        }
                        div { class: "metric",
                            strong { "Presentation response" }
                            span { title: "cx.identity.presentation_response", "Response" }
                            div { class: "muted", "Your verifiable presentation; only authorized fields are revealed" }
                        }
                        div { class: "metric",
                            strong { "Disclosure receipt" }
                            span { title: "cx.identity.disclosure_receipt", "Receipt" }
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
                // Blocks are actor-private filters; they do not affect other actors' clients.
                            div { class: "event", "data-testid": "personal-blocklist",
                    div { class: "event-head",
                        span { {crate::i18n::tr("settings.privacy.blocked_users.title")} }
                        span { class: "badge", "{blocklist_snapshot.read().len()}" }
                        HelpTip { text: "Local actor-private filter. Space-wide blocking belongs in moderation policy; account-data writes use cx.account.blocklist." }
                    }
                    div { class: "settings-inline-form", "data-testid": "blocklist-add-form",
                        {
                            // F-BLOCKLIST-VALID-1: derive live validation
                            // from the current input so the user sees the
                            // red ring + hint as they type, and the Add
                            // button is disabled until the value parses.
                            let raw_did = blocklist_did_input();
                            let did_trimmed = raw_did.trim();
                            let did_empty = did_trimmed.is_empty();
                            let did_valid = !did_empty && is_likely_valid_did(did_trimmed);
                            let did_input_class = if did_empty {
                                "blocklist-did"
                            } else if did_valid {
                                "blocklist-did blocklist-did-valid"
                            } else {
                                "blocklist-did blocklist-did-invalid"
                            };
                            rsx! {
                                input {
                                    class: "{did_input_class}",
                                    "data-testid": "blocklist-did-input",
                                    placeholder: crate::i18n::tr("settings.privacy.blocked_users.did_placeholder"),
                                    value: "{blocklist_did_input}",
                                    "aria-invalid": if !did_empty && !did_valid { "true" } else { "false" },
                                    oninput: move |event| blocklist_did_input.set(event.value()),
                                }
                                input {
                                    "data-testid": "blocklist-reason-input",
                                    placeholder: crate::i18n::tr("settings.privacy.blocked_users.reason_placeholder"),
                                    value: "{blocklist_reason_input}",
                                    oninput: move |event| blocklist_reason_input.set(event.value()),
                                }
                                button {
                                    class: "secondary",
                                    "data-testid": "blocklist-add",
                                    disabled: !did_valid,
                                    onclick: {
                                        let base = base_url.clone();
                                        move |_| {
                                            let did = blocklist_did_input().trim().to_owned();
                                            if did.is_empty() {
                                                blocklist_status.set(crate::i18n::tr(
                                                    "settings.privacy.blocked_users.did_required",
                                                ));
                                                return;
                                            }
                                            if !is_likely_valid_did(&did) {
                                                blocklist_status.set(crate::i18n::tr(
                                                    "settings.privacy.blocked_users.did_invalid",
                                                ));
                                                return;
                                            }
                                            let reason = blocklist_reason_input().trim().to_owned();
                                    let reason = if reason.is_empty() {
                                        None
                                    } else {
                                        Some(reason)
                                    };
                                    let changed = state_store.write().block_user(&did, reason);
                                    let entries = state_store.read().client_blocklist();
                                    blocklist_snapshot.set(entries.clone());
                                    if changed {
                                        blocklist_did_input.set(String::new());
                                        blocklist_reason_input.set(String::new());
                                        blocklist_status.set(format!(
                                            "{} {did}",
                                            crate::i18n::tr(
                                                "settings.privacy.blocked_users.added"
                                            )
                                        ));
                                        status.set(format!(
                                            "{} {did}",
                                            crate::i18n::tr(
                                                "settings.privacy.blocked_users.added"
                                            )
                                        ));
                                        push_blocklist_account_data(base(), token(), entries);
                                    } else {
                                        blocklist_status.set(format!(
                                            "{} {did}",
                                            crate::i18n::tr(
                                                "settings.privacy.blocked_users.duplicate"
                                            )
                                        ));
                                    }
                                }
                            },
                            {crate::i18n::tr("settings.privacy.blocked_users.add")}
                        }
                            }
                        }
                        {
                            // F-BLOCKLIST-VALID-1: live hint surfaces the
                            // exact reason the Add button is disabled.
                            // Empty input is a neutral state (no hint);
                            // the warning only appears once the user has
                            // started typing something the validator
                            // rejects.
                            let raw_did = blocklist_did_input();
                            let trimmed = raw_did.trim();
                            if !trimmed.is_empty() && !is_likely_valid_did(trimmed) {
                                rsx! {
                                    div {
                                        class: "settings-inline-hint settings-inline-hint-invalid",
                                        "data-testid": "blocklist-did-invalid",
                                        {crate::i18n::tr("settings.privacy.blocked_users.did_invalid")}
                                    }
                                }
                            } else {
                                rsx! {}
                            }
                        }
                    }
                    if !blocklist_status().is_empty() {
                        div { class: "muted", "data-testid": "blocklist-status", "{blocklist_status}" }
                    }
                    if blocklist_snapshot.read().is_empty() {
                        div {
                            class: "muted",
                            "data-testid": "blocklist-empty",
                            {crate::i18n::tr("settings.privacy.blocked_users.empty")}
                        }
                    } else {
                        ul { class: "settings-list", "data-testid": "blocklist-entries",
                            for entry in blocklist_snapshot.read().iter() {
                                li { class: "settings-list-row", "data-testid": "blocklist-entry",
                                    div {
                                        strong { "{entry.did}" }
                                        if let Some(reason) = &entry.reason {
                                            div { class: "muted", "{reason}" }
                                        }
                                        if let Some(blocked_at) = &entry.blocked_at {
                                            div { class: "muted", "{blocked_at}" }
                                        }
                                    }
                                    button {
                                        class: "secondary",
                                        "data-testid": "blocklist-unblock",
                                        onclick: {
                                            let did = entry.did.clone();
                                            let base = base_url.clone();
                                            move |_| {
                                                let changed = state_store
                                                    .write()
                                                    .unblock_user(&did);
                                                let entries = state_store.read().client_blocklist();
                                                blocklist_snapshot.set(entries.clone());
                                                if changed {
                                                    blocklist_status.set(format!(
                                                        "{} {did}",
                                                        crate::i18n::tr(
                                                            "settings.privacy.blocked_users.removed"
                                                        )
                                                    ));
                                                    status.set(format!(
                                                        "{} {did}",
                                                        crate::i18n::tr(
                                                            "settings.privacy.blocked_users.removed"
                                                        )
                                                    ));
                                                    push_blocklist_account_data(
                                                        base(),
                                                        token(),
                                                        entries,
                                                    );
                                                }
                                            }
                                        },
                                        {crate::i18n::tr("settings.privacy.unblock")}
                                    }
                                }
                            }
                        }
                    }
                }

                        // ── Consent grant event PoC ────
                        // First user-facing button on the anchored cell pipeline. Builds a
                        // cx.consent.grant event, signs with a deterministic demo ed25519 key
                        // (TODO real-key-management), and submits it through cx.events.submit.
                        crate::views::consent_demo::ConsentGrantDemoCard {
                            base_url,
                            token,
                            state_store,
                        }

                        // ── Account Data (actor-private View preferences) ─────
                        // models/views.md §2.6 + identity/account-lifecycle.md
                        // Edits to a shared View's filter / sort / columns are written via
                        // cx.view.update (visible to everyone). Personal View preferences
                        // (collapsed state, ad-hoc filter, column widths) are written via
                        // cx.account_data.set to the actor-private channel and never
                        // broadcast to the Space.
                        div { class: "event", "data-testid": "account-data-prefs",
                    div { class: "event-head",
                        span { "Personal preferences" }
                        span { title: "cx.account_data.set", "Actor-private" }
                        HelpTip { text: "The preferences below write to your account's actor-private channel and never sync to other Space members. To change a shared View's settings, use that View's Edit button." }
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
                            span { title: "cx.profile.space_override", "Per-space profile" }
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

                    // ── G3.Y3 consent grants ─────────────────────────────
                    if active_section == SettingsSection::Consent {
                        div { class: "settings-content-stack",
                            crate::views::settings_consent::ConsentSettingsCard {
                                base_url,
                                account_did,
                                token,
                                state_store,
                            }
                        }
                    }

                    // ── G3.Y3 personal blocklist ─────────────────────────
                    if active_section == SettingsSection::Blocklist {
                        div { class: "settings-content-stack",
                            crate::views::settings_blocklist::BlocklistSettingsCard {
                                base_url,
                                account_did,
                                token,
                                state_store,
                            }
                        }
                    }

                    // ── G3.Y3 capability viewer ──────────────────────────
                    if active_section == SettingsSection::Capabilities {
                        div { class: "settings-content-stack",
                            crate::views::settings_capabilities::CapabilitiesSettingsCard {
                                base_url,
                                account_did,
                                token,
                                state_store,
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
                                push_client_ui_account_data(base_url(), token(), "light".to_owned());
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
                                push_client_ui_account_data(base_url(), token(), "night".to_owned());
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
                                push_client_ui_account_data(base_url(), token(), "system".to_owned());
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
                                    span { "Diagnostics" }
                                    span { "{blocked_count} tracked blockers" }
                                    HelpTip { text: "Developer diagnostics stay under Advanced so normal settings remain focused. Release blockers, sync posture, and investigations are summarized here." }
                                }
                                div { class: "actions",
                                    span { class: "badge amber", "{blocked_count} blockers" }
                                    span { class: "badge blue", "advanced diagnostics" }
                                }
                            }
                            // T7.1 — entry point into the Developer Tools /
                            // Diagnostics panel that hosts the protocol-level
                            // surfaces (raw event log, audit rows, schema /
                            // profile / event-kind references) which used to
                            // leak into the main flow.
                            div { class: "event", "data-testid": "developer-tools-entry",
                                div { class: "event-head",
                                    span { {crate::i18n::tr("developer.title")} }
                                    span { class: "badge blue", {crate::i18n::tr("developer.subtitle")} }
                                }
                                div { class: "muted", {crate::i18n::tr("developer.hint")} }
                                div { class: "actions",
                                    a {
                                        class: "secondary",
                                        href: "/developer",
                                        "data-testid": "open-developer-tools",
                                        {crate::i18n::tr("developer.title")}
                                    }
                                    a {
                                        class: "secondary",
                                        href: "/audit",
                                        "data-testid": "open-audit-from-settings",
                                        "Audit log"
                                    }
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

    /// F-BLOCKLIST-VALID-1: the live form validator should accept the
    /// DID Core shapes the rest of yougen routinely round-trips through
    /// soland (web, key, plc) and reject the obvious noise users paste
    /// in by accident. The point is to give *fast* feedback while the
    /// reducer remains the source of truth — so we don't try to be
    /// exhaustive about method-specific rules here.
    #[test]
    fn is_likely_valid_did_accepts_canonical_shapes_and_rejects_garbage() {
        assert!(is_likely_valid_did("did:web:alice.example"));
        assert!(is_likely_valid_did(
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        ));
        assert!(is_likely_valid_did("did:plc:abc123"));
        assert!(is_likely_valid_did("  did:web:alice.example  "));

        // Empty / missing scheme.
        assert!(!is_likely_valid_did(""));
        assert!(!is_likely_valid_did("   "));
        assert!(!is_likely_valid_did("alice.example"));
        // Missing method or method-specific id.
        assert!(!is_likely_valid_did("did:"));
        assert!(!is_likely_valid_did("did::alice"));
        assert!(!is_likely_valid_did("did:web:"));
        assert!(!is_likely_valid_did("did:web:   "));
        // Non-alphanumeric method.
        assert!(!is_likely_valid_did("did:we b:alice"));
        assert!(!is_likely_valid_did("did:web-x:alice")); // ROUND4-ALLOW: negative test
        // Round 4 (spec a77b995) — `.`/`-`/`_`/`:` are forbidden in
        // the method segment; method MUST be lowercase ASCII alphanum.
        assert!(!is_likely_valid_did("did:web.x:alice")); // ROUND4-ALLOW: negative test
        assert!(!is_likely_valid_did("did:web_x:alice")); // ROUND4-ALLOW: negative test
        assert!(!is_likely_valid_did("did:WEB:alice"));
        // Whitespace inside method-specific id is rejected (round-4
        // regex `^did:[a-z0-9]+:[^\s]+$`).
        assert!(!is_likely_valid_did("did:web:alice example"));
        // The method-specific id may still contain `:` (the splitn(2)
        // keeps everything after the second `:`) — e.g. did:webvh nested
        // delegations.
        assert!(is_likely_valid_did("did:webvh:authority.example:zKey"));
    }

    /// The canonical `cx.read_receipt.preferences` body shape other devices
    /// read via `/sync` account_data. Locks the field names
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

    #[test]
    fn blocklist_account_data_key_matches_spec() {
        assert_eq!(CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY, "cx.account.blocklist");
    }
}
