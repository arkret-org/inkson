//! Settings surface.
//!
//! Territory split (preserved from former sibling files):
//! - G3.Y1 (device management): [`devices`].
//! - G3.Y3 (policy / capabilities): [`blocklist`], [`capabilities`].
//! The aggregate routing entry + the generic profile card live in
//! this `mod.rs`.

pub mod blocklist;
pub mod capabilities;
pub mod connections;
pub mod consent;
pub mod devices;
/// U4 - "who can invite me" invite_receive_policy editor.
pub mod invite_policy;
pub mod mls_recovery;

mod account_data;
mod invite_locator;
mod sections;
mod widgets;

use account_data::*;
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::Link;
use dioxus_router::hooks::use_route;
use invite_locator::*;
use sections::*;
use serde_json::{Map, Value, json};
use widgets::*;

use crate::components::{HelpTip, UiIcon};
use crate::config::LocalConfigStore;
use crate::i18n::Locale;
use crate::models::AccountDataSetResult;
use crate::notification_rules::WatchLevel;
use crate::routes::Route;
use crate::transport::auth::{with_authed_sdk_client, with_event_submitter};
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::slider::Slider;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{display_name_for_did, short_protocol_id};
use crate::workflows::blocked_release_workflows;

/// `ak.account_data` key used by the read-receipt preferences entry. Spec:
/// `discovery/client-preferences.md` §3.6.
pub(crate) const READ_RECEIPT_ACCOUNT_DATA_KEY: &str = "ak.read_receipt.preferences";

/// `ak.account_data` key used by the cross-device UI preferences entry
/// (theme, sidebar collapsed, per-Realm view). Spec:
/// `discovery/client-preferences.md` §2.
pub(crate) const CLIENT_UI_ACCOUNT_DATA_KEY: &str = "client.ui";

/// `ak.account_data` key used by the actor-private personal blocklist.
/// Spec: `discovery/client-preferences.md` §2 / §3 privacy preferences.
pub(crate) const CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY: &str = "ak.account.blocklist";

/// `ak.account_data` key used by notification push-rule preferences.
pub(crate) const PUSH_RULES_ACCOUNT_DATA_KEY: &str = "ak.push_rules";

/// `ak.account_data` key used by do-not-disturb preferences.
pub(crate) const DND_ACCOUNT_DATA_KEY: &str = "ak.dnd_schedule";

/// `ak.account_data` key used by the principal-private presence policy.
pub(crate) const PRESENCE_VISIBILITY_ACCOUNT_DATA_KEY: &str = "ak.presence.visibility";

/// `ak.account_data` key used by the manual presence preference
/// (profiles-presence.md §3.6). Send-side enforced; pushed encrypted —
/// servers MUST NOT require a projection of this key.
pub(crate) const PRESENCE_PREFERENCE_ACCOUNT_DATA_KEY: &str = "ak.presence.preference";

/// Resolve the relative expiry picker choice into an absolute RFC 3339
/// UTC `clears_at` (profiles-presence.md §3.6). `never` (and anything
/// unrecognized) means no expiry.
pub(crate) fn presence_expiry_to_clears_at(choice: &str) -> Option<String> {
    let now = chrono::Utc::now();
    let clears_at = match choice {
        "30m" => now + chrono::Duration::minutes(30),
        "1h" => now + chrono::Duration::hours(1),
        "today" => {
            let next_midnight = now.date_naive().succ_opt()?.and_hms_opt(0, 0, 0)?;
            chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(next_midnight, chrono::Utc)
        }
        _ => return None,
    };
    Some(clears_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

pub(crate) fn default_avatar_initial(handles: &[String], account_did: &str) -> String {
    crate::views::helpers::identity_avatar_initial(handles, account_did)
}

pub(crate) fn default_avatar_tone(handles: &[String], account_did: &str) -> usize {
    crate::views::helpers::identity_avatar_tone(handles, account_did)
}

/// A4a — push the current `client.ui` payload (theme + sidebar
/// collapsed) to soland's `ak.account_data.set` endpoint so other
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
/// also published via `ak.self.account.command.update_profile` so other actors see
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
        match with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(&sub, CLIENT_UI_ACCOUNT_DATA_KEY, body)
                .await
        })
        .await
        {
            Ok(AccountDataSetResult::Stored { .. }) => {}
            Ok(AccountDataSetResult::Unsupported { status }) => {
                tracing::debug!(
                    "soland ak.account_data.set for client.ui returned {status}; \
                     local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "ak.account_data.set for client.ui failed: {}",
                    err.display()
                );
            }
        }
    });
}

/// Build the canonical `content` body for a read-receipt preferences
/// account-data entry. Mirrors the SDK's `ReadReceiptPreferences` shape so
/// other devices reading the value via `/sync` get the same field names.
pub(crate) fn build_read_receipt_preferences_body(
    default_send: bool,
    default_display: bool,
    realm_send_overrides: &std::collections::BTreeMap<String, bool>,
    realm_display_overrides: &std::collections::BTreeMap<String, bool>,
    strand_send_overrides: &std::collections::BTreeMap<String, bool>,
    strand_display_overrides: &std::collections::BTreeMap<String, bool>,
) -> serde_json::Value {
    fn scope_map(
        send_overrides: &std::collections::BTreeMap<String, bool>,
        display_overrides: &std::collections::BTreeMap<String, bool>,
    ) -> Value {
        let ids: std::collections::BTreeSet<String> = send_overrides
            .keys()
            .chain(display_overrides.keys())
            .cloned()
            .collect();
        let mut scopes = Map::new();
        for id in ids {
            let mut pref = Map::new();
            if let Some(send) = send_overrides.get(&id) {
                pref.insert("send".to_owned(), Value::Bool(*send));
            }
            if let Some(display) = display_overrides.get(&id) {
                pref.insert("display".to_owned(), Value::Bool(*display));
            }
            scopes.insert(id, Value::Object(pref));
        }
        Value::Object(scopes)
    }

    json!({
        "default": {
            "send": default_send,
            "display": default_display,
        },
        "realms": scope_map(realm_send_overrides, realm_display_overrides),
        "strands": scope_map(strand_send_overrides, strand_display_overrides),
    })
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
    if entries.is_empty() {
        spawn(async move {
            if let Err(err) = with_event_submitter(&base_url, api_token, |sub| async move {
                crate::transport::account::delete_account_data(
                    &sub,
                    CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY,
                )
                .await
            })
            .await
            {
                tracing::debug!(
                    "ak.account_data.delete for ak.account.blocklist failed: {}",
                    err.display()
                );
            }
        });
        return;
    }
    let plaintext_body = crate::account_data::build_blocklist_account_data_body(&entries);
    let body =
        match encrypted_account_data_marker(CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY, &plaintext_body) {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(
                    "ak.account_data.set for ak.account.blocklist skipped: {}",
                    err
                );
                return;
            }
        };
    spawn(async move {
        match with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(
                &sub,
                CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY,
                body,
            )
            .await
        })
        .await
        {
            Ok(AccountDataSetResult::Stored { .. }) => {}
            Ok(AccountDataSetResult::Unsupported { status }) => {
                tracing::debug!(
                    "soland ak.account_data.set for ak.account.blocklist returned {status}; \
                     local blocklist remains authoritative"
                );
            }
            Err(err) => {
                tracing::debug!(
                    "ak.account_data.set for ak.account.blocklist failed: {}",
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

/// Client-side DNS-domain sanity check for the blocklist `domain` target
/// (`client-preferences.md` §3.5 / `content-moderation.md` §4.3). Like
/// [`is_likely_valid_did`] this only powers *live* form feedback — the wire
/// value is normalized by `account_data::normalize_blocklist_value` and the
/// real DID/claim resolution happens client-side before the block applies.
/// Accepts a bare multi-label domain (`example.com`, `sub.acme.example`);
/// rejects schemes, ports, paths, whitespace, `@`, and single-label inputs.
pub(crate) fn is_likely_valid_domain(input: &str) -> bool {
    let value = input.trim();
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    if value.contains(|c: char| c.is_whitespace())
        || value.contains('/')
        || value.contains(':')
        || value.contains('@')
    {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Spec client-preferences.md §3.7: push (or tombstone) a Realm remark to
/// soland via `ak.account_data.set`. Same graceful-degradation contract as
/// [`push_read_receipt_account_data`] — local state is authoritative; the
/// server PUT is best-effort. `remark.is_empty()` triggers a DELETE so the
/// row tombstones cleanly across devices.
pub(crate) fn push_realm_remark_account_data(
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
) {
    push_realm_remark_account_data_impl(base_url, api_token, realm_id, remark, false);
}

/// Variant of [`push_realm_remark_account_data`] that surfaces sync failures
/// to the user via an error toast (`realm.pin_failed`).
pub(crate) fn push_realm_remark_account_data_with_failure_toast(
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
) {
    push_realm_remark_account_data_impl(base_url, api_token, realm_id, remark, true);
}

pub(crate) fn push_contact_remark_account_data(
    base_url: String,
    api_token: String,
    actor_id: String,
    remark: crate::account_data::ContactRemark,
) {
    let key = crate::account_data::contact_remark_account_data_key(&actor_id);
    spawn(async move {
        if remark.is_empty() {
            let key_for_log = key.clone();
            if let Err(err) = with_event_submitter(&base_url, api_token, |sub| {
                let key = key.clone();
                async move { crate::transport::account::delete_account_data(&sub, &key).await }
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
        tracing::warn!(
            key = %key,
            "skipping plaintext contact remark account_data upload; encrypted envelope is unavailable"
        );
    });
}

#[component]
pub fn SettingsPanel(
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    account_primary_handle: String,
    personal_handles: Vec<String>,
    personal_handles_status: String,
    can_list_handles_for_subject: bool,
    config_store: Signal<LocalConfigStore>,
    push_state: Signal<String>,
    mut locale: Signal<Locale>,
    mut theme: Signal<String>,
) -> Element {
    // A4 — base_url / state_store from session context instead of props.
    let base_url = crate::app::SessionContext::get().base_url;
    let mut state_store = crate::app::SessionContext::get().state_store;
    let route = use_route::<Route>();
    let active_section = SettingsSection::from_slug(route.settings_section());
    // Settings-nav filter: matches section labels in the active locale so the
    // sidebar collapses to the sections whose (localised) name contains the
    // query. Empty query shows every group (design/settings-ia-reorg.md §3.4).
    let mut settings_nav_filter = use_signal(String::new);
    let mut presence_visibility_choice = use_signal(|| {
        state_store
            .read()
            .presence_visibility()
            .as_wire()
            .to_owned()
    });
    let presence_visibility_selected = use_memo(move || Some(presence_visibility_choice()));
    // Manual presence preference editor state (profiles-presence.md
    // §3.6). Hydrated from persisted local state; the expiry picker is
    // relative so it always starts at "never".
    let initial_presence_preference = {
        let preference = state_store.read().presence_preference();
        if !preference.is_empty() && !preference.is_active(chrono::Utc::now()) {
            crate::state::PresencePreferenceState::default()
        } else {
            preference
        }
    };
    let initial_presence_manual_state = initial_presence_preference
        .manual_state
        .clone()
        .unwrap_or_else(|| "auto".to_owned());
    let initial_presence_status_message = initial_presence_preference
        .status_message
        .clone()
        .unwrap_or_default();
    let mut presence_manual_state = use_signal(move || initial_presence_manual_state);
    let presence_manual_state_selected = use_memo(move || Some(presence_manual_state()));
    let mut presence_status_message = use_signal(move || initial_presence_status_message);
    let mut presence_expiry_choice = use_signal(|| "never".to_owned());
    let presence_expiry_selected = use_memo(move || Some(presence_expiry_choice()));
    let mut presence_status_feedback = use_signal(String::new);
    // Hydrate DND from the persisted local snapshot so the toggle reflects
    // the last-saved state instead of always rendering "off" (the saved body
    // only carries a full-day period when the user picked "now").
    let initial_dnd_settings = state_store.read().notification_dnd_settings();
    let initial_dnd_enabled = initial_dnd_settings.as_ref().is_some_and(|dnd| dnd.enabled);
    let initial_dnd_mode = if initial_dnd_settings
        .as_ref()
        .is_some_and(|dnd| dnd.enabled && !dnd.schedule.periods.is_empty())
    {
        "now".to_owned()
    } else {
        "off".to_owned()
    };
    let mut dnd_enabled = use_signal(move || initial_dnd_enabled);
    let mut dnd_mode = use_signal(move || initial_dnd_mode);
    let dnd_mode_selected = use_memo(move || Some(dnd_mode()));
    let mut notification_settings_status = use_signal(String::new);
    let mut notification_sound_enabled = use_signal(|| {
        crate::notification_sound::notification_sound_enabled(&state_store.read(), &account_did())
    });
    // Per-realm override editor state (spec push-notifications.md §4.3.2).
    // `new_override_realm` holds the realm id picked in the "add" row;
    // `new_override_level` is the watch level to apply. New overrides default
    // to `Muted` since silencing a noisy realm is the common case.
    let mut new_override_realm = use_signal(String::new);
    let mut new_override_level = use_signal(|| WatchLevel::Muted.as_wire().to_owned());
    let new_override_realm_selected = use_memo(move || Some(new_override_realm()));
    let new_override_level_selected = use_memo(move || Some(new_override_level()));
    // Read receipt preferences (spec discovery/client-preferences.md §3.6).
    // Hydrated from persisted local state; mutations write back through
    // `state_store.set_read_receipt_*` so message readers can resolve
    // (strand → realm → default) before sending `ak.receipt.read`.
    let mut read_receipt_default_send =
        use_signal(|| state_store.read().read_receipt_default_send());
    let mut read_receipt_default_display =
        use_signal(|| state_store.read().read_receipt_default_display());
    let mut read_receipt_realm_overrides =
        use_signal(|| state_store.read().read_receipt_realm_overrides());
    let mut read_receipt_override_input = use_signal(String::new);
    // Realm remarks editor state (spec client-preferences.md §3.7).
    // `realm_remarks_snapshot` is the resolved BTreeMap rendered for the
    // list; `realm_remark_inputs` keeps unsaved text edits keyed by
    // realm_id so users can type without round-tripping through soland.
    // `new_realm_remark_id` / `new_realm_remark_name` drive the "Add by
    // Realm ID" row for Realms the user has joined but isn't yet
    // tracking locally.
    let mut realm_remarks_snapshot = use_signal(|| state_store.read().realm_remarks());
    let mut realm_remark_inputs = use_signal(|| {
        state_store
            .read()
            .realm_remarks()
            .into_iter()
            .map(|(id, r)| (id, r.local_name))
            .collect::<std::collections::BTreeMap<String, String>>()
    });
    let mut new_realm_remark_id = use_signal(String::new);
    let mut new_realm_remark_name = use_signal(String::new);
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
    // `ak.account_data.set("client.ui", { avatar_blob_ref })` and is also
    // published through the spec profile endpoint so directory projections can index it.
    let initial_avatar_blob_ref = state_store
        .read()
        .load_private_data(&account_did(), "avatar_blob_ref")
        .unwrap_or_default();
    let mut profile_avatar_blob_ref = use_signal(|| initial_avatar_blob_ref.clone());
    let mut avatar_upload_status = use_signal(String::new);
    let mut avatar_uploading = use_signal(|| false);
    let mut avatar_cache_status = use_signal(String::new);
    let mut pending_avatar_crop = use_signal(|| None::<PendingAvatarCrop>);
    let mut avatar_crop_zoom = use_signal(|| 125_i32);
    let mut avatar_crop_x = use_signal(|| 0_i32);
    let mut avatar_crop_y = use_signal(|| 0_i32);
    let mut avatar_refresh_nonce = use_signal(|| 0_u64);
    let mut blocklist_snapshot = use_signal(|| state_store.read().client_blocklist());
    let mut blocklist_did_input = use_signal(String::new);
    let mut blocklist_reason_input = use_signal(String::new);
    let mut blocklist_status = use_signal(String::new);
    let mut mimi_directory = use_signal(|| "Not loaded".to_owned());
    let mut mimi_receipt = use_signal(|| "No MIMI action receipt".to_owned());
    let blocked_count = blocked_release_workflows().len();
    let realm_watch_overrides = state_store.read().realm_watch_levels();
    let known_realms = known_realm_options(&state_store.read());
    let active_locale = locale();
    let active_locale_code = active_locale.code();
    let active_direction = active_locale.direction().as_str();
    let push_registration = state_store.read().push_registration();
    let push_label = crate::push::push_status_label(push_registration.as_ref());
    let has_session = !token().trim().is_empty();
    #[allow(clippy::redundant_closure)]
    let mut invite_locator_subject = use_signal(|| account_did());
    let mut invite_locator_token = use_signal(|| {
        let did = account_did();
        if did.trim().is_empty() {
            String::new()
        } else {
            build_invite_locator_token(&did)
        }
    });
    {
        let current_account = account_did();
        use_effect(move || {
            if current_account != invite_locator_subject() {
                invite_locator_subject.set(current_account.clone());
                invite_locator_token.set(if current_account.trim().is_empty() {
                    String::new()
                } else {
                    build_invite_locator_token(&current_account)
                });
            }
        });
    }
    let invite_locator_url = if has_session && !invite_locator_token().trim().is_empty() {
        build_invite_locator_url(&base_url(), &invite_locator_token())
    } else {
        String::new()
    };
    let invite_locator_qr_svg = render_invite_locator_qr_svg(&invite_locator_url);
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
    let account_handles_label =
        format_settings_handle_list(&personal_handles, &personal_handles_status);
    let account_handles_title = if personal_handles.is_empty() {
        account_handles_label.clone()
    } else {
        personal_handles.join(", ")
    };
    let account_default_avatar_initial = default_avatar_initial(&personal_handles, &account_did());
    let account_default_avatar_tone = default_avatar_tone(&personal_handles, &account_did());
    let account_default_avatar_class =
        format!("avatar-img lg default-avatar tone-{account_default_avatar_tone}");
    let device_short_label = short_protocol_id(&device_label);
    {
        let account_key = account_did();
        use_effect(move || {
            let hydrated = state_store
                .read()
                .load_private_data(&account_key, "avatar_blob_ref")
                .unwrap_or_default();
            if hydrated != profile_avatar_blob_ref() {
                profile_avatar_blob_ref.set(hydrated.clone());
                avatar_refresh_nonce.set(avatar_refresh_nonce() + 1);
                avatar_cache_status.set(if hydrated.trim().is_empty() {
                    "Avatar cleared from synced preferences".to_owned()
                } else {
                    "Avatar restored from synced preferences".to_owned()
                });
            }
        });
    }
    rsx! {
        div { class: "settings settings-page", "data-testid": "settings-panel",
            div { class: "settings-shell",
                aside { class: "settings-sidebar-column",
                    {
                        let query = settings_nav_filter().trim().to_lowercase();
                        rsx! {
                            div { class: "settings-nav-search",
                                input {
                                    r#type: "search",
                                    class: "settings-nav-search-input",
                                    "data-testid": "settings-nav-search",
                                    placeholder: crate::i18n::tr("settings.search.placeholder"),
                                    "aria-label": crate::i18n::tr("settings.search.placeholder"),
                                    value: "{settings_nav_filter}",
                                    oninput: move |event: FormEvent| settings_nav_filter.set(event.value()),
                                }
                            }
                            div { class: "settings-nav-list",
                            {
                                let visible_groups: Vec<_> = SETTINGS_NAV_GROUPS
                                    .iter()
                                    .copied()
                                    .filter_map(|(group_label, hint, sections)| {
                                        let matched: Vec<SettingsSection> = sections
                                            .iter()
                                            .copied()
                                            .filter(|section| {
                                                query.is_empty()
                                                    || section.label().to_lowercase().contains(&query)
                                            })
                                            .collect();
                                        if matched.is_empty() {
                                            None
                                        } else {
                                            Some((group_label, hint, matched))
                                        }
                                    })
                                    .collect();
                                let group_count = visible_groups.len();
                                rsx! {
                                    if group_count == 0 {
                                        div {
                                            class: "settings-nav-empty muted",
                                            "data-testid": "settings-nav-empty",
                                            "{crate::i18n::tr(\"settings.search.no_results\")}"
                                        }
                                    }
                                    for (group_index, (group_label, _, sections)) in visible_groups.into_iter().enumerate() {
                                        div { class: "settings-nav-cluster",
                                            div { class: "settings-nav-group-label", "{crate::i18n::tr(group_label)}" }
                                            for section in sections.into_iter() {
                                                Link {
                                                    class: if active_section == section { "settings-nav-item active" } else { "settings-nav-item" },
                                                    "data-testid": "settings-nav-item-{section.slug()}",
                                                    "aria-current": if active_section == section { "page" } else { "false" },
                                                    to: section.route(),
                                                    strong { "{section.label()}" }
                                                }
                                            }
                                        }
                                        if group_index + 1 < group_count {
                                            div { class: "settings-nav-divider", "aria-hidden": "true" }
                                        }
                                    }
                                }
                            }
                            }
                        }
                    }
                }
                section { class: "settings-content-column",
                    div { class: "event settings-content-hero",
                        div { class: "settings-content-title-row",
                            h2 { class: "settings-content-title", "{active_section.label()}" }
                        }
                    }

                    // ── Server / Account settings ────────────────────────
                    if active_section == SettingsSection::Server {
                        div { class: "settings-card-grid",
                            div { class: "event settings-card-span-2", "data-testid": "transport-invariant",
                                div { class: "event-head",
                                    span { "Server context" }
                                }
                                div { class: "metric-grid",
                                    div { class: "metric",
                                        strong { "Principal Server" }
                                        span { "{base_url}" }
                                    }
                                    div { class: "metric",
                                        strong { "Session" }
                                        span { if has_session { "Authenticated" } else { "Not signed in" } }
                                    }
                                    div { class: "metric",
                                        strong { "Push" }
                                        span { "{push_label}" }
                                    }
                                }
                            }
                        }
                    }

                    // ── Account information ──────────────────────────────
                    if active_section == SettingsSection::Account {
                        div { class: "settings-card-grid",
                            // A4b — Profile / avatar card. Renders the
                            // current avatar (resolved via the blob URL
                            // helper when a blob_ref is present), an
                            // upload control, and a clear button. The
                            // avatar is also published to soland's
                            // `ak.self.account.command.update_profile` so the
                            // directory + member lists pick it up.
                            div { class: "event settings-card-span-2 settings-avatar-card", "data-testid": "settings-avatar-card",
                                div { class: "event-head",
                                    span { "Account identity" }
                                }
                                div { class: "settings-avatar-actions",
                                    {
                                        let blob_ref = profile_avatar_blob_ref();
                                        rsx! {
                                            if !blob_ref.trim().is_empty() {
                                                div {
                                                    class: "avatar-img lg",
                                                    key: "{blob_ref}:{avatar_refresh_nonce()}",
                                                    "data-testid": "settings-avatar-preview",
                                                    crate::content::renderer::AuthenticatedBlobImage {
                                                        key: "{blob_ref}:{avatar_refresh_nonce()}",
                                                        blob_ref: blob_ref.trim().to_owned(),
                                                        alt_text: "Avatar".to_owned(),
                                                    }
                                                }
                                            } else {
                                                div {
                                                    class: "{account_default_avatar_class}",
                                                    "data-testid": "settings-avatar-preview",
                                                    "aria-label": "Default avatar",
                                                    span { "{account_default_avatar_initial}" }
                                                }
                                            }
                                        }
                                    }
                                    div { class: "settings-avatar-controls",
                                        input {
                                            id: "settings-avatar-input",
                                            "data-testid": "settings-avatar-input",
                                            r#type: "file",
                                            accept: "image/*",
                                            style: "display: none;",
                                            // A4b — Dioxus 0.7 `HasFileData::files()`
                                            // surfaces the dropped / picked file
                                            // list. Read bytes async then upload
                                            // via the blob endpoint + publish the
                                            // resulting blob URL to the profile.
                                            onchange: {
                                                move |evt: Event<FormData>| {
                                                    let files = evt.files();
                                                    if files.is_empty() {
                                                        pending_avatar_crop.set(None);
                                                        avatar_uploading.set(false);
                                                        avatar_upload_status.set(
                                                            crate::i18n::tr("settings.avatar.error"),
                                                        );
                                                        return;
                                                    }
                                                    let Some(file) = files.into_iter().next() else {
                                                        pending_avatar_crop.set(None);
                                                        avatar_uploading.set(false);
                                                        avatar_upload_status.set(
                                                            crate::i18n::tr("settings.avatar.error"),
                                                        );
                                                        return;
                                                    };
                                                    let content_type = file
                                                        .content_type()
                                                        .unwrap_or_else(|| "application/octet-stream".to_owned());
                                                    avatar_upload_status.set(
                                                        crate::i18n::tr("settings.avatar.processing"),
                                                    );
                                                    avatar_uploading.set(false);
                                                    spawn(async move {
                                                        let bytes = match file.read_bytes().await {
                                                            Ok(b) => b.to_vec(),
                                                            Err(err) => {
                                                                pending_avatar_crop.set(None);
                                                                avatar_uploading.set(false);
                                                                avatar_upload_status.set(format!(
                                                                    "{}: {err}",
                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                ));
                                                                return;
                                                            }
                                                        };
                                                        if !content_type.starts_with("image/") {
                                                            pending_avatar_crop.set(None);
                                                            avatar_uploading.set(false);
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
                                                                pending_avatar_crop.set(None);
                                                                avatar_uploading.set(false);
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
                                        if avatar_uploading() {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                r#type: "button",
                                                disabled: true,
                                                span { class: "spinner-inline", "aria-hidden": "true" }
                                                {crate::i18n::tr("settings.avatar.uploading")}
                                            }
                                        } else {
                                            Label {
                                                html_for: "settings-avatar-input",
                                                class: "avatar-upload-button",
                                                "data-testid": "settings-avatar-upload-label",
                                                UiIcon { name: "image" }
                                                {crate::i18n::tr("settings.avatar.upload")}
                                            }
                                        }
                                        if let Some(selection) = pending_avatar_crop.read().clone() {
                                            Dialog {
                                                open: true,
                                                on_open_change: move |open: bool| {
                                                    if !open {
                                                        if avatar_uploading() {
                                                            return;
                                                        }
                                                        pending_avatar_crop.set(None);
                                                        avatar_upload_status.set(String::new());
                                                    }
                                                },
                                                "data-testid": "settings-avatar-crop-editor",
                                                "aria-label": "Edit avatar",
                                                div {
                                                style: "position: fixed; left: 50%; top: 50%; transform: translate(-50%, -50%); z-index: var(--layer-modal, 300); display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 16px; align-items: center; width: min(640px, calc(100vw - 32px)); max-height: calc(100vh - 48px); overflow: auto; padding: 18px; border: 1px solid var(--border, #333); border-radius: var(--radius-lg, 12px); background: var(--surface-solid, var(--surface, #1a1d22)); box-shadow: 0 0 0 9999px rgba(20, 22, 30, 0.55), var(--shadow-lg, 0 24px 56px rgba(0, 0, 0, 0.22));",
                                                div {
                                                    "data-testid": "settings-avatar-crop-stage",
                                                    style: "position: relative; width: min(180px, 70vw); aspect-ratio: 1; justify-self: center; border-radius: 50%; overflow: hidden; border: 1px solid var(--border-default, #333); background: var(--bg-elevated, #1a1d22);",
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
                                                        Slider {
                                                            "data-testid": "settings-avatar-crop-zoom",
                                                            min: 100.0,
                                                            max: 300.0,
                                                            step: 5.0,
                                                            value: avatar_crop_zoom() as f64,
                                                            disabled: avatar_uploading(),
                                                            on_value_change: move |value: f64| {
                                                                avatar_crop_zoom.set((value as i32).clamp(100, 300));
                                                            },
                                                        }
                                                    }
                                                    label { class: "form-field",
                                                        span { {crate::i18n::tr("settings.avatar.pan_x")} }
                                                        Slider {
                                                            "data-testid": "settings-avatar-crop-x",
                                                            min: -100.0,
                                                            max: 100.0,
                                                            step: 5.0,
                                                            value: avatar_crop_x() as f64,
                                                            disabled: avatar_uploading(),
                                                            on_value_change: move |value: f64| {
                                                                avatar_crop_x.set((value as i32).clamp(-100, 100));
                                                            },
                                                        }
                                                    }
                                                    label { class: "form-field",
                                                        span { {crate::i18n::tr("settings.avatar.pan_y")} }
                                                        Slider {
                                                            "data-testid": "settings-avatar-crop-y",
                                                            min: -100.0,
                                                            max: 100.0,
                                                            step: 5.0,
                                                            value: avatar_crop_y() as f64,
                                                            disabled: avatar_uploading(),
                                                            on_value_change: move |value: f64| {
                                                                avatar_crop_y.set((value as i32).clamp(-100, 100));
                                                            },
                                                        }
                                                    }
                                                    div { class: "actions",
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            "data-testid": "settings-avatar-upload-cropped",
                                                            disabled: avatar_uploading(),
                                                            onclick: {
                                                                let base = base_url();
                                                                let api_token = token();
                                                                move |_| {
                                                                    if avatar_uploading() {
                                                                        return;
                                                                    }
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
                                                                    avatar_uploading.set(true);
                                                                    avatar_upload_status.set(crate::i18n::tr("settings.avatar.uploading"));
                                                                    spawn(async move {
                                                                        let bytes = match crate::avatar_crop::crop_avatar_jpeg(&selection.bytes, crop) {
                                                                            Ok(bytes) => bytes,
                                                                            Err(err) => {
                                                                                avatar_uploading.set(false);
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let api = match crate::transport::auth::authed_api(&base, api_token.clone()) {
                                                                            Ok(api) => api,
                                                                            Err(err) => {
                                                                                avatar_uploading.set(false);
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                                return;
                                                                            }
                                                                        };
                                                                        let clients = match api.sdk_http_client() {
                                                                            Ok(http) => crate::transport::EndpointClients::from_http(http),
                                                                            Err(err) => {
                                                                                avatar_uploading.set(false);
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                                return;
                                                                            }
                                                                        };
                                                                        match clients.blob().upload_bytes(bytes, "image/jpeg").await {
                                                                            Ok(resp) => {
                                                                                let blob_ref = resp.blob_ref.to_string();
                                                                                // Publish publicly first; only then refresh the
                                                                                // local mirror so a failed profile update does not
                                                                                // display an avatar that never became active.
                                                                                match async {
                                                                                    crate::transport::account::update_profile(
                                                                                        &api.sdk_http_client()?,
                                                                                        None,
                                                                                        None,
                                                                                        Some(&blob_ref),
                                                                                    )
                                                                                    .await
                                                                                }
                                                                                .await
                                                                                {
                                                                                    Ok(_) => {
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
                                                                                        let refreshed = state_store
                                                                                            .read()
                                                                                            .load_private_data(&account_did(), "avatar_blob_ref")
                                                                                            .filter(|value| !value.trim().is_empty())
                                                                                            .unwrap_or_else(|| blob_ref.clone());
                                                                                        profile_avatar_blob_ref.set(refreshed);
                                                                                        avatar_refresh_nonce.set(avatar_refresh_nonce() + 1);
                                                                                        avatar_uploading.set(false);
                                                                                        pending_avatar_crop.set(None);
                                                                                        avatar_upload_status.set(String::new());
                                                                                        crate::components::feedback::toast_success(
                                                                                            "feedback.avatar_updated",
                                                                                            vec![],
                                                                                        );
                                                                                    }
                                                                                    Err(err) => {
                                                                                        avatar_uploading.set(false);
                                                                                        avatar_upload_status.set(format!(
                                                                                            "{}: {}",
                                                                                            crate::i18n::tr("settings.avatar.error"),
                                                                                            err,
                                                                                        ));
                                                                                    }
                                                                                }
                                                                            }
                                                                            Err(err) => {
                                                                                avatar_uploading.set(false);
                                                                                avatar_upload_status.set(format!(
                                                                                    "{}: {err}",
                                                                                    crate::i18n::tr("settings.avatar.error"),
                                                                                ));
                                                                            }
                                                                        }
                                                                    });
                                                                }
                                                            },
                                                            if avatar_uploading() {
                                                                span { class: "spinner-inline", "aria-hidden": "true" }
                                                                {crate::i18n::tr("settings.avatar.uploading")}
                                                            } else {
                                                                {crate::i18n::tr("settings.avatar.upload_cropped")}
                                                            }
                                                        }
                                                        Button {
                                                            variant: ButtonVariant::Secondary,
                                                            "data-testid": "settings-avatar-crop-cancel",
                                                            disabled: avatar_uploading(),
                                                            onclick: move |_| {
                                                                if avatar_uploading() {
                                                                    return;
                                                                }
                                                                pending_avatar_crop.set(None);
                                                                avatar_upload_status.set(String::new());
                                                            },
                                                            {crate::i18n::tr("settings.avatar.cancel_crop")}
                                                        }
                                                    }
                                                }
                                                }
                                            }
                                        }
                                        if !profile_avatar_blob_ref().trim().is_empty() {
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                "data-testid": "settings-avatar-clear",
                                                disabled: avatar_uploading(),
                                                onclick: {
                                                    let base = base_url();
                                                    let api_token = token();
                                                    move |_| {
                                                        let base = base.clone();
                                                        let api_token = api_token.clone();
                                                        if avatar_uploading() {
                                                            return;
                                                        }
                                                        profile_avatar_blob_ref.set(String::new());
                                                        avatar_refresh_nonce.set(avatar_refresh_nonce() + 1);
                                                        pending_avatar_crop.set(None);
                                                        avatar_uploading.set(false);
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
                                                                crate::transport::auth::authed_api(&base, api_token)
                                                                && let Err(err) = async {
                                                                    crate::transport::account::update_profile(
                                                                        &api.sdk_http_client()?,
                                                                        None,
                                                                        None,
                                                                        Some(""),
                                                                    )
                                                                    .await
                                                                }
                                                                .await
                                                            {
                                                                tracing::warn!("avatar profile clear failed: {err}");
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
                                div { class: "metric-grid settings-account-identity-grid",
                                    div { class: "metric settings-identity-row",
                                        strong { "DID" }
                                        div { class: "settings-identity-value",
                                            span {
                                                class: "mono",
                                                "data-testid": "settings-account-did",
                                                title: "{principal_label}",
                                                "{principal_label}"
                                            }
                                            Button {
                                                variant: ButtonVariant::Ghost,
                                                size: ButtonSize::IconSm,
                                                class: "btn icon settings-identity-copy",
                                                "data-testid": "settings-account-copy-did",
                                                title: "Copy DID",
                                                "aria-label": "Copy DID",
                                                onclick: {
                                                    let value = principal_label.clone();
                                                    move |_| {
                                                        copy_text_to_clipboard(&value);
                                                        crate::components::feedback::toast_success("feedback.copied_did", vec![]);
                                                    }
                                                },
                                                UiIcon { name: "copy" }
                                            }
                                        }
                                    }
                                    div { class: "metric settings-identity-row",
                                        strong { "Handles" }
                                        div { class: "settings-identity-value",
                                            span {
                                                class: "mono",
                                                "data-testid": "settings-account-handles",
                                                title: "{account_handles_title}",
                                                "{account_handles_label}"
                                            }
                                            Button {
                                                variant: ButtonVariant::Ghost,
                                                size: ButtonSize::IconSm,
                                                class: "btn icon settings-identity-copy",
                                                "data-testid": "settings-account-copy-handles",
                                                title: "Copy handles",
                                                "aria-label": "Copy handles",
                                                onclick: {
                                                    let value = account_handles_title.clone();
                                                    move |_| {
                                                        copy_text_to_clipboard(&value);
                                                        crate::components::feedback::toast_success("feedback.copied_handles", vec![]);
                                                    }
                                                },
                                                UiIcon { name: "copy" }
                                            }
                                        }
                                    }
                                    div { class: "metric settings-identity-row",
                                        strong { "Current device" }
                                        div { class: "settings-identity-value",
                                            span {
                                                class: "mono",
                                                "data-testid": "settings-account-device",
                                                title: "{device_label}",
                                                "{device_short_label}"
                                            }
                                            Button {
                                                variant: ButtonVariant::Ghost,
                                                size: ButtonSize::IconSm,
                                                class: "btn icon settings-identity-copy",
                                                "data-testid": "settings-account-copy-device",
                                                title: "Copy device ID",
                                                "aria-label": "Copy device ID",
                                                onclick: {
                                                    let value = device_label.clone();
                                                    move |_| {
                                                        copy_text_to_clipboard(&value);
                                                        crate::components::feedback::toast_success("feedback.copied_device_id", vec![]);
                                                    }
                                                },
                                                UiIcon { name: "copy" }
                                            }
                                        }
                                    }
                                }
                            }

                            div { class: "event settings-card-span-2 invite-locator-card", "data-testid": "settings-invite-locator-card",
                                div { class: "event-head invite-locator-head",
                                    span { "Invite locator" }
                                    if has_session {
                                        div { class: "invite-locator-head-actions",
                                            span { class: "invite-locator-expiry", "15 min" }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                size: ButtonSize::Sm,
                                                class: "btn invite-locator-action",
                                                "data-testid": "settings-invite-locator-copy",
                                                onclick: {
                                                    let invite_url = invite_locator_url.clone();
                                                    move |_| {
                                                        copy_text_to_clipboard(&invite_url);
                                                        crate::components::feedback::toast_success("feedback.copied_invite_url", vec![]);
                                                    }
                                                },
                                                UiIcon { name: "copy" }
                                                span { "Copy URL" }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                size: ButtonSize::Sm,
                                                class: "btn invite-locator-action",
                                                "data-testid": "settings-invite-locator-refresh",
                                                onclick: move |_| {
                                                    let did = account_did();
                                                    invite_locator_token.set(if did.trim().is_empty() {
                                                        String::new()
                                                    } else {
                                                        build_invite_locator_token(&did)
                                                    });
                                                    crate::components::feedback::toast_success("feedback.invite_locator_refreshed", vec![]);
                                                },
                                                UiIcon { name: "refresh" }
                                                span { "Refresh" }
                                            }
                                        }
                                    } else {
                                        span { "offline" }
                                    }
                                }
                                if has_session {
                                    div { class: "invite-locator-panel",
                                        div { class: "invite-locator-qr-pane",
                                            strong { class: "invite-locator-pane-label", "QR" }
                                            if invite_locator_qr_svg.is_empty() {
                                                div {
                                                    class: "muted",
                                                    "data-testid": "settings-invite-locator-qr-empty",
                                                    "QR unavailable"
                                                }
                                            } else {
                                                div {
                                                    class: "qr-image",
                                                    "data-testid": "settings-invite-locator-qr",
                                                    role: "img",
                                                    "aria-label": "Invite locator QR code",
                                                    dangerous_inner_html: "{invite_locator_qr_svg}",
                                                }
                                            }
                                        }
                                        div { class: "invite-locator-url-pane",
                                            strong { class: "invite-locator-pane-label", "URL" }
                                            Textarea {
                                                id: "settings-invite-locator-url-input",
                                                class: "mono invite-locator-url-field",
                                                "data-testid": "settings-invite-locator-url",
                                                readonly: true,
                                                rows: "7",
                                                value: "{invite_locator_url}",
                                            }
                                        }
                                    }
                                } else {
                                    div {
                                        class: "muted",
                                        "data-testid": "settings-invite-locator-signed-out",
                                        "Sign in to show invite locator"
                                    }
                                }
                            }

                        }
                    }

                    // ── My Agents (AKP-0008 native personal agents) ──────
                    if active_section == SettingsSection::Agents {
                        crate::views::agents::PersonalAgentAdminPanel {
                            token,
                            controller_did: account_did(),
                        }
                    }

                    if active_section == SettingsSection::Devices {
                        crate::views::settings::devices::SettingsDevicesPanel {
                            account_did,
                            device_id,
                            token,
                        }
                    }

                    if active_section == SettingsSection::Consent {
                        crate::views::settings::consent::ConsentSettingsPanel {
                            account_did,
                            token,
                        }
                    }

                    if active_section == SettingsSection::Recovery {
                        crate::views::recovery::RecoveryPanel {
                            token,
                            account_did,
                            device_id,
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

                            details { class: "event", "data-testid": "storage-risks",
                    summary { class: "event-head", span { "Storage diagnostics" } span { "Advanced" } }
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
                                div { class: "event-head",
                                    span { "Encryption" }
                                    span { "MLS / E2EE" }
                                }
                                div { class: "muted",
                                    "End-to-end encryption is always on for encrypted Realms. Manage your recovery key below."
                                }
                            }
                            // X11.1 — persistent MLS recovery-key entry.
                            // Always reachable from this encryption section,
                            // shows live backup status, and lets the user
                            // generate/replace the recovery key regardless of the
                            // boot detection effect timing. NOT gated on
                            // `needs_mls_backup`.
                            mls_recovery::SettingsMlsRecoveryPanel {
                                token,
                                account_did,
                                device_id,
                                account_primary_handle: account_primary_handle.clone(),
                            }
                            details { class: "event", "data-testid": "key-backup-guidance",
                                summary { class: "event-head",
                                    span { "Advanced key backup diagnostics" }
                                    span { class: "badge amber", "developer tools" }
                                }
                                div { class: "muted",
                                    "Encrypted history recovery above creates key backup envelopes automatically. The recovery backup id is generated when a backup is created; it is not something to type by hand."
                                }
                                div { class: "muted",
                                    "Open Recovery when debugging a specific backup envelope."
                                }
                                div { class: "actions",
                                    Link {
                                        class: "primary",
                                        "data-testid": "key-backup-open-recovery",
                                        to: Route::SettingsRecovery,
                                        UiIcon { name: "key" }
                                        "Recovery & backups"
                                    }
                                }
                                div { class: "muted",
                                    "Contract: ak.schema.key_backup.v1 over /_arkret/self/keys/backups/*. This is not required for encrypted-history recovery setup."
                                }
                            }
                        }
                    }

                    // ── MIMI interop facade ──────────────────────────────
                    if active_section == SettingsSection::Mimi {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "mimi-interop-panel",
                    div { class: "event-head", span { "MIMI interop checks" } span { "Advanced" } }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mimi-refresh-directory",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match with_authed_sdk_client(&base, api_token, |http| async move {
                                            http.mimi_provider_directory(None, &[]).await.map_err(anyhow::Error::from)
                                        })
                                        .await
                                        {
                                            Ok(directory) => {
                                                let features = serde_json::to_string_pretty(&directory.features)
                                                    .unwrap_or_else(|_| directory.features.to_string());
                                                mimi_directory.set(format!(
                                                    "providers {}\nfeatures {}",
                                                    directory.providers.len(),
                                                    features,
                                                ));
                                            }
                                            Err(err) => {
                                                let message =
                                                    format!("MIMI directory: {}", err.display());
                                                mimi_directory.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.mimi_failed",
                                                    vec![],
                                                    Some(message),
                                                );
                                            }
                                        }
                                    });
                                }
                            },
                            "Refresh Directory"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mimi-group-info",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match with_authed_sdk_client(&base, api_token, |http| async move {
                                            http.get::<arkret_sdk::MimiGroupInfoOutcome>(
                                                "/_arkret/open/mimi/strands/01JSMIMI/group-info",
                                            )
                                            .await
                                            .map_err(anyhow::Error::from)
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                // R20: `room_id` is the MIMI-draft wire term
                                                // (interop-exempt from Room → Realm). On the
                                                // Arkret app side it identifies a Strand, so we
                                                // bind it to a `strand_id`-named local to keep
                                                // the "Room" term confined to the interop layer.
                                                mimi_receipt.set(format!(
                                                    "group-info 01JSMIMI binding {} proofs {}",
                                                    response
                                                        .room_binding_ref
                                                        .as_ref()
                                                        .map(ToString::to_string)
                                                        .unwrap_or_else(|| "none".to_owned()),
                                                    response.proofs.len()
                                                ));
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI groupInfo failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.mimi_failed",
                                                    vec![],
                                                    Some(message),
                                                );
                                            }
                                        }
                                    });
                                }
                            },
                            "Group Info"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mimi-identifier-query",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match with_authed_sdk_client(&base, api_token, |http| async move {
                                            let request = arkret_sdk::MimiIdentifierQueryRequestBody {
                                                identifiers: vec![json!({"mimi_uri": "mimi://remote.example/alice"})],
                                                requester: None,
                                                privacy_profile: Some("private_identifier_query".to_owned()),
                                                proofs: Vec::new(),
                                            };
                                            http.post::<_, arkret_sdk::MimiIdentifierQueryOutcome>(
                                                "/_arkret/open/mimi/identifiers/query",
                                                &request,
                                            )
                                            .await
                                            .map_err(anyhow::Error::from)
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                let first = response
                                                    .matches
                                                    .first()
                                                    .map(|value| {
                                                        serde_json::to_string(value)
                                                            .unwrap_or_else(|_| value.to_string())
                                                    })
                                                    .unwrap_or_else(|| "none".to_owned());
                                                mimi_receipt.set(format!(
                                                    "identifier results {} first {}",
                                                    response.matches.len(),
                                                    first
                                                ));
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI identifier query failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.mimi_failed",
                                                    vec![],
                                                    Some(message),
                                                );
                                            }
                                        }
                                    });
                                }
                            },
                            "Identifier Query"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mimi-submit-message",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let actor = account_did();
                                    let device = device_id();
                                    spawn(async move {
                                        match with_authed_sdk_client(&base, api_token, |http| async move {
                                            let request = arkret_sdk::MimiSubmitMessageRequestBody {
                                                sender_actor_id: arkret_sdk::Did::new(actor.trim().to_owned())?,
                                                device_id: arkret_sdk::DeviceId::new(device.trim().to_owned())?,
                                                ciphertext: json!({
                                                    "source_format": "text/markdown;variant=GFM-MIMI",
                                                    "body": "MIMI interop test from inkson",
                                                    "mimi_room_uri": "mimi://mimi.example.com/rooms/01JSMIMI"
                                                }),
                                                mls_group_id: None,
                                                epoch: None,
                                                associated_data: serde_json::Value::Null,
                                            };
                                            http.post::<_, arkret_sdk::MimiSubmitMessageOutcome>(
                                                "/_arkret/open/mimi/strands/01JSMIMI/messages",
                                                &request,
                                            )
                                            .await
                                            .map_err(anyhow::Error::from)
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                mimi_receipt.set(format!(
                                                    "submit-message event {} rejected {}",
                                                    response
                                                        .event_ref
                                                        .as_ref()
                                                        .map(ToString::to_string)
                                                        .unwrap_or_else(|| "no-event".to_owned()),
                                                    response.rejected.len()
                                                ));
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI submit failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.mimi_failed",
                                                    vec![],
                                                    Some(message),
                                                );
                                            }
                                        }
                                    });
                                }
                            },
                            "Submit Test Message"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mimi-proxy-download",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let actor = account_did();
                                    spawn(async move {
                                        match with_authed_sdk_client(&base, api_token, |http| async move {
                                            let request = arkret_sdk::MimiProxyDownloadRequestBody {
                                                asset_ref: "ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91".to_owned(),
                                                requester: arkret_sdk::Did::new(actor.trim().to_owned())?,
                                                strand_id: None,
                                                ohttp_context: serde_json::Value::Null,
                                                range: None,
                                            };
                                            http.post::<_, arkret_sdk::MimiProxyDownloadOutcome>(
                                                "/_arkret/open/mimi/proxy-download",
                                                &request,
                                            )
                                            .await
                                            .map_err(anyhow::Error::from)
                                        })
                                        .await
                                        {
                                            Ok(response) => {
                                                mimi_receipt.set(format!(
                                                    "proxy-download {} headers {}",
                                                    response.download_ref,
                                                    response.headers.len()
                                                ));
                                            }
                                            Err(err) => {
                                                let message = format!("MIMI proxy download failed: {}", err.display());
                                                mimi_receipt.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.mimi_failed",
                                                    vec![],
                                                    Some(message),
                                                );
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
                            div { class: "event", "data-testid": "notification-settings-panel",
                                div { class: "event-head",
                                    span { "Global notification defaults" }
                                    span { "synced" }
                                }
                                div { class: "muted",
                                    "Apply to every Realm unless you add a per-Realm override below."
                                }
                                div { class: "metric-grid",
                                    {render_notification_kind_toggle("mention", "Mention notifications", state_store)}
                                    {render_notification_kind_toggle("reaction", "Reaction notifications", state_store)}
                                    {render_notification_kind_toggle("invite", "Invite notifications", state_store)}
                                    {render_notification_kind_toggle("message", "Message notifications", state_store)}
                                }
                                div { class: "actions",
                                    label {
                                        Checkbox {
                                            "data-testid": "settings-notification-sound-toggle",
                                            checked: if notification_sound_enabled() {
                                                CheckboxState::Checked
                                            } else {
                                                CheckboxState::Unchecked
                                            },
                                            on_checked_change: move |state: CheckboxState| {
                                                let enabled = bool::from(state);
                                                notification_sound_enabled.set(enabled);
                                                crate::notification_sound::set_notification_sound_enabled(
                                                    &mut state_store.write(),
                                                    &account_did(),
                                                    enabled,
                                                );
                                                if enabled {
                                                    crate::notification_sound::initialize_notification_audio();
                                                }
                                                notification_settings_status.set(if enabled {
                                                    "Sound alerts enabled.".to_owned()
                                                } else {
                                                    "Sound alerts disabled.".to_owned()
                                                });
                                            },
                                        }
                                        if notification_sound_enabled() { " Sound alerts" } else { " Sound alerts off" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "settings-notification-sound-test",
                                        disabled: !notification_sound_enabled(),
                                        onclick: move |_| {
                                            if notification_sound_enabled() {
                                                crate::notification_sound::initialize_notification_audio();
                                                crate::notification_sound::play_notification_sound();
                                                notification_settings_status.set("Sound alert test played.".to_owned());
                                            } else {
                                                notification_settings_status.set("Enable sound alerts before testing.".to_owned());
                                            }
                                        },
                                        "Test sound"
                                    }
                                }
                                div { class: "actions",
                                    label {
                                        Checkbox {
                                            "data-testid": "dnd-enabled-toggle",
                                            checked: if dnd_enabled() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                                            on_checked_change: move |state: CheckboxState| dnd_enabled.set(bool::from(state)),
                                        }
                                        " Do not disturb"
                                    }
                                    Select::<String> {
                                        "data-testid": "dnd-mode-select",
                                        value: Some(dnd_mode_selected.into()),
                                        on_value_change: move |v: Option<String>| { if let Some(v) = v { dnd_mode.set(v); } },
                                        SelectOption::<String> { index: 0usize, value: "off".to_string(), text_value: "Off", "Off" }
                                        SelectOption::<String> { index: 1usize, value: "now".to_string(), text_value: "Now", "Now" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "save-notification-settings-button",
                                        onclick: move |_| {
                                            push_dnd_account_data(
                                                base_url(),
                                                token(),
                                                dnd_enabled(),
                                                dnd_mode(),
                                                state_store,
                                                notification_settings_status,
                                            );
                                            push_notification_rules_account_data(
                                                base_url(),
                                                token(),
                                                state_store.read().realm_watch_levels(),
                                            );
                                        },
                                        "Save"
                                    }
                                }
                                div { class: "muted", "data-testid": "notification-settings-status", "{notification_settings_status}" }
                            }
                            // (2) Per-realm overrides — choose how much a specific Realm notifies.
                            div { class: "event", "data-testid": "per-realm-overrides",
                                div { class: "event-head",
                                    span { "Per-realm overrides" }
                                    span { "{realm_watch_overrides.len()} configured" }
                                }
                                div { class: "muted",
                                    "Pick a Realm and how much it should notify you. This overrides the global defaults above for that Realm only."
                                }
                                div { class: "actions",
                                    // Each picker lives in its own `label.field` wrapper — never a raw
                                    // id box, and never two bare-adjacent Selects. Isolating each
                                    // Select keeps the VNode tree stable so opening one doesn't remount
                                    // (and snap shut) its neighbour.
                                    label { class: "field",
                                        span { class: "field-label", "Realm" }
                                        Select::<String> {
                                            class: "select",
                                            "data-testid": "realm-override-realm-select",
                                            disabled: known_realms.is_empty(),
                                            value: Some(new_override_realm_selected.into()),
                                            on_value_change: move |v: Option<String>| { if let Some(v) = v { new_override_realm.set(v); } },
                                            SelectOption::<String> {
                                                index: 0usize,
                                                value: String::new(),
                                                text_value: if known_realms.is_empty() { "No Realms available yet" } else { "Select a Realm…" },
                                                if known_realms.is_empty() { "No Realms available yet" } else { "Select a Realm…" }
                                            }
                                            for (index , (realm_id , label)) in known_realms.iter().enumerate() {
                                                SelectOption::<String> {
                                                    key: "{realm_id}",
                                                    index: index + 1,
                                                    value: realm_id.clone(),
                                                    text_value: "{label}",
                                                    "{label}"
                                                }
                                            }
                                        }
                                    }
                                    label { class: "field",
                                        span { class: "field-label", "Notify me about" }
                                        Select::<String> {
                                            class: "select",
                                            "data-testid": "realm-override-level-select",
                                            value: Some(new_override_level_selected.into()),
                                            on_value_change: move |v: Option<String>| { if let Some(v) = v { new_override_level.set(v); } },
                                            SelectOption::<String> { index: 0usize, value: "all".to_string(), text_value: "All messages", "All messages" }
                                            SelectOption::<String> { index: 1usize, value: "participating".to_string(), text_value: "Participating", "Participating" }
                                            SelectOption::<String> { index: 2usize, value: "mentions_only".to_string(), text_value: "Mentions only", "Mentions only" }
                                            SelectOption::<String> { index: 3usize, value: "muted".to_string(), text_value: "Muted", "Muted" }
                                        }
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "realm-override-add",
                                        onclick: move |_| {
                                            let realm_id = new_override_realm().trim().to_owned();
                                            if realm_id.is_empty() {
                                                crate::components::feedback::toast_info("feedback.override_pick_realm", vec![]);
                                                return;
                                            }
                                            let level = WatchLevel::from_wire(&new_override_level())
                                                .unwrap_or_default();
                                            state_store.write().set_realm_watch_level(realm_id.clone(), level);
                                            push_notification_rules_account_data(
                                                base_url(),
                                                token(),
                                                state_store.read().realm_watch_levels(),
                                            );
                                            crate::components::feedback::toast_success(
                                                "feedback.watch_level_set",
                                                vec![
                                                    ("realm", short_protocol_id(&realm_id)),
                                                    ("level", watch_level_label(level).to_owned()),
                                                ],
                                            );
                                            new_override_realm.set(String::new());
                                        },
                                        "Add override"
                                    }
                                }
                                if realm_watch_overrides.is_empty() {
                                    div { class: "muted", "data-testid": "per-realm-overrides-empty",
                                        "No per-Realm overrides yet. Unconfigured Realms follow the global defaults."
                                    }
                                } else {
                                    for realm_id in realm_watch_overrides.keys() {
                                        {
                                            let label = known_realms
                                                .iter()
                                                .find(|(id, _)| id == realm_id)
                                                .map(|(_, label)| label.clone())
                                                .unwrap_or_else(|| short_protocol_id(realm_id));
                                            rsx! {
                                                RealmOverrideRow {
                                                    key: "{realm_id}",
                                                    realm_id: realm_id.clone(),
                                                    label,
                                                    token,
                                                }
                                            }
                                        }
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "notifications-settings-clear-muted-realms",
                                        onclick: move |_| {
                                            let ids: Vec<String> = state_store
                                                .read()
                                                .realm_watch_levels()
                                                .into_keys()
                                                .collect();
                                            for id in ids {
                                                state_store
                                                    .write()
                                                    .set_realm_watch_level(id, WatchLevel::default());
                                            }
                                            push_notification_rules_account_data(
                                                base_url(),
                                                token(),
                                                state_store.read().realm_watch_levels(),
                                            );
                                            crate::components::feedback::toast_success("feedback.overrides_cleared", vec![]);
                                        },
                                        "Clear all overrides"
                                    }
                                }
                            }
                div { class: "event", "data-testid": "push-settings",
                    div { class: "event-head", span { "Push delivery" } span { "configure" } }
                    div { class: "muted", "Push notification preferences and gateway registration." }
                    div { class: "muted", "data-testid": "push-registration-state", "Current: {push_label}" }
                    div { class: "actions",
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "push-register-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let dev = device_id();
                                    let principal_id = account_did();
                                    let persisted_grant = state_store.read().session_grant();
                                    spawn(async move {
                                        let principal_id =
                                            (!principal_id.trim().is_empty()).then_some(principal_id);
                                        let context = crate::push::registration::RegisterContext {
                                            principal_server_url: base,
                                            floria_gateway_url: crate::push::floria_gateway_url(),
                                            device_id: dev,
                                            principal_id,
                                            authorization_credential: Some(api_token),
                                            session_grant: None,
                                            active_circle_id: None,
                                        };
                                        match crate::push::registration::register_via_chime(
                                            context,
                                            persisted_grant,
                                        )
                                        .await
                                        {
                                            Ok(outcome) => {
                                                state_store
                                                    .write()
                                                    .save_push_registration(outcome.state.clone());
                                                let label = outcome
                                                    .response
                                                    .registration_id
                                                    .unwrap_or_else(|| "registered".to_owned());
                                                push_state.set(label.clone());
                                                crate::components::feedback::toast_success(
                                                    "feedback.push_registered",
                                                    vec![("label", label)],
                                                );
                                            }
                                            Err(err) => {
                                                let message = format!("push register failed: {err}");
                                                push_state.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.push_register_failed",
                                                    vec![],
                                                    Some(message),
                                                );
                                            }
                                        }
                                    });
                                }
                            },
                            {crate::i18n::tr("settings.register_push")}
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "push-unregister-button",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    let dev = device_id();
                                    let persisted_grant = state_store.read().session_grant();
                                    let registration = state_store.read().push_registration();
                                    spawn(async move {
                                        let context = crate::push::registration::UnregisterContext {
                                            principal_server_url: base,
                                            device_id: dev,
                                            authorization_credential: Some(api_token),
                                            session_grant: None,
                                        };
                                        match crate::push::registration::unregister_via_chime(
                                            context,
                                            persisted_grant,
                                            registration,
                                        ).await {
                                            Ok(_) => {
                                                state_store.write().clear_push_registration();
                                                push_state.set("Not registered".to_owned());
                                                crate::components::feedback::toast_success("feedback.push_unregistered", vec![]);
                                            }
                                            Err(err) => {
                                                let message = format!("push unregister failed: {err}");
                                                push_state.set(message.clone());
                                                crate::components::feedback::toast_error(
                                                    "feedback.push_unregister_failed",
                                                    vec![],
                                                    Some(message),
                                                );
                                            }
                                        }
                                    });
                                }
                            },
                            {crate::i18n::tr("settings.unregister_push")}
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
                    // Presence visibility — the full three-tier policy
                    // (profiles-presence.md §3.4), not a binary toggle.
                    div { class: "actions",
                        span { "Presence visibility" }
                        Select::<String> {
                            "data-testid": "presence-visibility-select",
                            value: Some(presence_visibility_selected.into()),
                            on_value_change: move |v: Option<String>| {
                                let Some(v) = v else { return; };
                                let visibility = match crate::state::PresenceVisibility::try_from_wire(&v) {
                                    Some(visibility) => visibility,
                                    None => return,
                                };
                                presence_visibility_choice.set(v);
                                state_store.write().set_presence_visibility(visibility);
                                crate::components::feedback::toast_success(
                                    "feedback.presence_visibility_set",
                                    vec![("visibility", visibility.as_wire().to_owned())],
                                );
                                push_presence_visibility_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                            SelectOption::<String> { index: 0usize, value: "public".to_string(), text_value: "Everyone in shared Realms", "Everyone in shared Realms" }
                            SelectOption::<String> { index: 1usize, value: "contacts_only".to_string(), text_value: "Contacts only", "Contacts only" }
                            SelectOption::<String> { index: 2usize, value: "nobody".to_string(), text_value: "Nobody (appear offline)", "Nobody (appear offline)" }
                        }
                    }
                    // My status — manual presence preference
                    // (profiles-presence.md §3.6): pinned state, transient
                    // status message and relative expiry, applied by every
                    // device of this account at send time.
                    div { class: "event-head", span { "My status" } span { "manual presence" } }
                    div { class: "actions",
                        Select::<String> {
                            "data-testid": "presence-manual-state-select",
                            value: Some(presence_manual_state_selected.into()),
                            on_value_change: move |v: Option<String>| { if let Some(v) = v { presence_manual_state.set(v); } },
                            SelectOption::<String> { index: 0usize, value: "auto".to_string(), text_value: "Automatic", "Automatic" }
                            SelectOption::<String> { index: 1usize, value: "online".to_string(), text_value: "Online", "Online" }
                            SelectOption::<String> { index: 2usize, value: "idle".to_string(), text_value: "Idle", "Idle" }
                            SelectOption::<String> { index: 3usize, value: "dnd".to_string(), text_value: "Do not disturb (busy)", "Do not disturb (busy)" }
                        }
                        Input {
                            r#type: "text",
                            "data-testid": "presence-status-message-input",
                            placeholder: "Status message (e.g. In a meeting)",
                            value: "{presence_status_message()}",
                            oninput: move |event: FormEvent| presence_status_message.set(event.value()),
                        }
                        Select::<String> {
                            "data-testid": "presence-status-expiry-select",
                            value: Some(presence_expiry_selected.into()),
                            on_value_change: move |v: Option<String>| { if let Some(v) = v { presence_expiry_choice.set(v); } },
                            SelectOption::<String> { index: 0usize, value: "never".to_string(), text_value: "Don't clear", "Don't clear" }
                            SelectOption::<String> { index: 1usize, value: "30m".to_string(), text_value: "Clear in 30 minutes", "Clear in 30 minutes" }
                            SelectOption::<String> { index: 2usize, value: "1h".to_string(), text_value: "Clear in 1 hour", "Clear in 1 hour" }
                            SelectOption::<String> { index: 3usize, value: "today".to_string(), text_value: "Clear today", "Clear today" }
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "presence-status-save-button",
                            onclick: move |_| {
                                let manual_state = presence_manual_state();
                                let message = arkret_sdk::canonical::to_nfc(
                                    presence_status_message().trim(),
                                );
                                if let Err(error) = arkret_sdk::validate_status_message(&message) {
                                    presence_status_feedback.set(
                                        format!("Status message is invalid: {error}"),
                                    );
                                    return;
                                }
                                let has_preference = manual_state != "auto" || !message.is_empty();
                                let preference = crate::state::PresencePreferenceState {
                                    manual_state: (manual_state != "auto").then_some(manual_state),
                                    status_message: (!message.is_empty()).then_some(message),
                                    clears_at: has_preference
                                        .then(|| {
                                            presence_expiry_to_clears_at(&presence_expiry_choice())
                                        })
                                        .flatten(),
                                };
                                let cleared = preference.is_empty();
                                state_store.write().set_presence_preference(preference);
                                presence_status_feedback.set(if cleared {
                                    "Status cleared.".to_owned()
                                } else {
                                    "Status saved.".to_owned()
                                });
                                push_presence_preference_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                            "Save status"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "presence-status-clear-button",
                            onclick: move |_| {
                                presence_manual_state.set("auto".to_owned());
                                presence_status_message.set(String::new());
                                presence_expiry_choice.set("never".to_owned());
                                state_store.write().set_presence_preference(
                                    crate::state::PresencePreferenceState::default(),
                                );
                                presence_status_feedback.set("Status cleared.".to_owned());
                                push_presence_preference_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                            "Clear"
                        }
                    }
                    div { class: "muted", "data-testid": "presence-status-feedback", "{presence_status_feedback}" }
                    div { class: "event-head",
                        span { "Read receipts" }
                        span { "Default" }
                    }
                    label {
                        Checkbox {
                            "data-testid": "read-receipts-default-toggle",
                            checked: if read_receipt_default_send() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |state: CheckboxState| {
                                let send = bool::from(state);
                                read_receipt_default_send.set(send);
                                state_store.write().set_read_receipt_default_send(send);
                                crate::components::feedback::toast_success(
                                    if send {
                                        "feedback.read_receipt_default_send_on"
                                    } else {
                                        "feedback.read_receipt_default_send_off"
                                    },
                                    vec![],
                                );
                                // Also push to soland's ak.account_data.set
                                // so other devices pick up the change.
                                // Endpoint may 404/501 — we swallow and keep
                                // local authoritative.
                                push_read_receipt_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                        }
                        " Send read receipts by default"
                    }
                    label {
                        Checkbox {
                            "data-testid": "read-receipts-display-default-toggle",
                            checked: if read_receipt_default_display() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |state: CheckboxState| {
                                let display = bool::from(state);
                                read_receipt_default_display.set(display);
                                state_store.write().set_read_receipt_default_display(display);
                                crate::components::feedback::toast_success(
                                    if display {
                                        "feedback.read_receipt_default_display_on"
                                    } else {
                                        "feedback.read_receipt_default_display_off"
                                    },
                                    vec![],
                                );
                                push_read_receipt_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                        }
                        " Show others' read receipts by default"
                    }
                    div { class: "event-head",
                        span { "Realm exceptions" }
                        span { "{read_receipt_realm_overrides().len()} configured" }
                    }
                    for (realm_id, send) in read_receipt_realm_overrides() {
                            // Policy lock — when soland publishes a
                            // ak.realm.read_receipt_policy with disclosure=
                            // required|disabled, the toggle is disabled and
                            // we show a lock badge with the reason. Until
                            // sync (P0 M3) wires the snapshot, this returns
                            // `None` for every realm and the row stays
                            // editable.
                            {
                                let policy = state_store
                                    .read()
                                    .read_receipt_policy_for_realm(&realm_id);
                                let locked = policy
                                    .as_ref()
                                    .is_some_and(|p| p.locks_user_choice());
                                let lock_reason = policy
                                    .as_ref()
                                    .map(|p| p.lock_reason())
                                    .unwrap_or_default();
                                let realm_id_label = short_protocol_id(&realm_id);
                                rsx! {
                                    div { class: "actions", "data-testid": "read-receipt-override-row",
                                        span { title: "{realm_id}", "{realm_id_label}" }
                                        span { class: "badge",
                                            {if send { "sending" } else { "skipping" }}
                                        }
                                        if locked {
                                            span {
                                                class: "badge red",
                                                "data-testid": "read-receipt-override-locked",
                                                "locked by Realm policy"
                                            }
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "read-receipt-override-toggle",
                                            disabled: locked,
                                            onclick: {
                                                let realm_id = realm_id.clone();
                                                move |_| {
                                                    if locked {
                                                        return;
                                                    }
                                                    let next = !send;
                                                    state_store.write().set_read_receipt_realm_override(
                                                        realm_id.clone(),
                                                        Some(next),
                                                    );
                                                    read_receipt_realm_overrides.set(
                                                        state_store.read().read_receipt_realm_overrides(),
                                                    );
                                                    crate::components::feedback::toast_success(
                                                        if next {
                                                            "feedback.read_receipt_override_send"
                                                        } else {
                                                            "feedback.read_receipt_override_skip"
                                                        },
                                                        vec![("realm", short_protocol_id(&realm_id))],
                                                    );
                                                    push_read_receipt_account_data(
                                                        base_url(),
                                                        token(),
                                                        state_store,
                                                    );
                                                }
                                            },
                                            {if send { "Switch to skip" } else { "Switch to send" }}
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "read-receipt-override-clear",
                                            disabled: locked,
                                            onclick: {
                                                let realm_id = realm_id.clone();
                                                move |_| {
                                                    if locked {
                                                        return;
                                                    }
                                                    state_store.write().set_read_receipt_realm_override(
                                                        realm_id.clone(),
                                                        None,
                                                    );
                                                    read_receipt_realm_overrides.set(
                                                        state_store.read().read_receipt_realm_overrides(),
                                                    );
                                                    crate::components::feedback::toast_success(
                                                        "feedback.read_receipt_override_inherit",
                                                        vec![("realm", short_protocol_id(&realm_id))],
                                                    );
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
                        Input {
                            r#type: "text",
                            placeholder: "ak:realm:...",
                            value: "{read_receipt_override_input()}",
                            oninput: move |event: FormEvent| read_receipt_override_input.set(event.value()),
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "read-receipt-add-override-skip",
                            onclick: move |_| {
                                let realm_id = read_receipt_override_input().trim().to_owned();
                                if realm_id.is_empty() {
                                    crate::components::feedback::toast_info("feedback.enter_realm_id", vec![]);
                                    return;
                                }
                                state_store.write().set_read_receipt_realm_override(
                                    realm_id.clone(),
                                    Some(false),
                                );
                                read_receipt_realm_overrides.set(
                                    state_store.read().read_receipt_realm_overrides(),
                                );
                                read_receipt_override_input.set(String::new());
                                crate::components::feedback::toast_success(
                                    "feedback.read_receipt_override_skip",
                                    vec![("realm", short_protocol_id(&realm_id))],
                                );
                                push_read_receipt_account_data(
                                    base_url(),
                                    token(),
                                    state_store,
                                );
                            },
                            "Add (skip)"
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "read-receipt-add-override-send",
                            onclick: move |_| {
                                let realm_id = read_receipt_override_input().trim().to_owned();
                                if realm_id.is_empty() {
                                    crate::components::feedback::toast_info("feedback.enter_realm_id", vec![]);
                                    return;
                                }
                                state_store.write().set_read_receipt_realm_override(
                                    realm_id.clone(),
                                    Some(true),
                                );
                                read_receipt_realm_overrides.set(
                                    state_store.read().read_receipt_realm_overrides(),
                                );
                                read_receipt_override_input.set(String::new());
                                crate::components::feedback::toast_success(
                                    "feedback.read_receipt_override_send",
                                    vec![("realm", short_protocol_id(&realm_id))],
                                );
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

                // ── Realm remarks (spec discovery/client-preferences.md §3.7) ─
                // Actor-private local alias / note / pin for each Realm the
                // user has joined. Lets users disambiguate duplicate-titled
                // Realms without leaking the remark beyond this account.
                // Pushed to soland via `ak.account_data.set` under
                // `ak.contacts.realm.<realm_id>`; soland echoes the same
                // entries back on the next `/sync` so other devices pick
                // them up.
                div { class: "event", "data-testid": "realm-remarks-editor",
                    div { class: "event-head",
                        span { "Realm remarks" }
                        span { "Private" }
                    }
                    {
                        let remarks = realm_remarks_snapshot();
                        if remarks.is_empty() {
                            rsx! {
                                div {
                                    class: "muted",
                                    "data-testid": "realm-remarks-empty",
                                    "No remarks yet. Add one below to distinguish duplicate-titled Realms."
                                }
                            }
                        } else {
                            rsx! {
                                for (realm_id, remark) in remarks {
                                    {
                                        let realm_id_label = short_protocol_id(&realm_id);
                                        rsx! {
                                            div {
                                                class: "actions",
                                                "data-testid": "realm-remark-row",
                                                "data-realm-id": "{realm_id}",
                                                span { class: "mono", title: "{realm_id}", "{realm_id_label}" }
                                                Input {
                                                    r#type: "text",
                                                    "data-testid": "realm-remark-input",
                                                    placeholder: "Local name (private)",
                                                    value: "{realm_remark_inputs().get(&realm_id).cloned().unwrap_or_else(|| remark.local_name.clone())}",
                                                    oninput: {
                                                        let id = realm_id.clone();
                                                        move |event: FormEvent| {
                                                            let mut current = realm_remark_inputs();
                                                            current.insert(id.clone(), event.value());
                                                            realm_remark_inputs.set(current);
                                                        }
                                                    },
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    class: if remark.pinned { "active" } else { "" },
                                                    "data-testid": "realm-remark-pin-toggle",
                                                    title: if remark.pinned { crate::i18n::tr("realm.unpin") } else { crate::i18n::tr("realm.pin") },
                                                    "aria-pressed": if remark.pinned { "true" } else { "false" },
                                                    onclick: {
                                                        let id = realm_id.clone();
                                                        let existing = remark.clone();
                                                        let next_pinned = !remark.pinned;
                                                        move |_| {
                                                            let id = id.clone();
                                                            let now_rfc3339 = chrono::Utc::now()
                                                                .to_rfc3339_opts(
                                                                    chrono::SecondsFormat::Secs,
                                                                    true,
                                                                );
                                                            let next = crate::account_data::RealmRemark::with_pinned_preserving_fields(
                                                                id.clone(),
                                                                Some(&existing),
                                                                next_pinned,
                                                                Some(now_rfc3339),
                                                            );
                                                            state_store
                                                                .write()
                                                                .set_realm_remark(id.clone(), next.clone());
                                                            realm_remarks_snapshot.set(
                                                                state_store.read().realm_remarks(),
                                                            );
                                                            crate::components::feedback::toast_success(
                                                                if next_pinned { "realm.pinned" } else { "realm.unpinned" },
                                                                vec![],
                                                            );
                                                            push_realm_remark_account_data_with_failure_toast(
                                                                base_url(),
                                                                token(),
                                                                id,
                                                                next,
                                                            );
                                                        }
                                                    },
                                                    UiIcon { name: "pin" }
                                                    span { {if remark.pinned { crate::i18n::tr("realm.pinned") } else { crate::i18n::tr("realm.pin") }} }
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "realm-remark-save",
                                                    onclick: {
                                                        let id = realm_id.clone();
                                                        let existing = remark.clone();
                                                        move |_| {
                                                            let id = id.clone();
                                                            let next_name = realm_remark_inputs()
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
                                                                .set_realm_remark(id.clone(), next.clone());
                                                            realm_remarks_snapshot.set(
                                                                state_store.read().realm_remarks(),
                                                            );
                                                            if next.is_empty() {
                                                                crate::components::feedback::toast_success(
                                                                    "feedback.realm_remark_cleared",
                                                                    vec![("realm", short_protocol_id(&id))],
                                                                );
                                                            } else {
                                                                crate::components::feedback::toast_success(
                                                                    "feedback.realm_remark_saved",
                                                                    vec![
                                                                        ("realm", short_protocol_id(&id)),
                                                                        ("name", next.local_name.clone()),
                                                                    ],
                                                                );
                                                            }
                                                            push_realm_remark_account_data(
                                                                base_url(),
                                                                token(),
                                                                id,
                                                                next,
                                                            );
                                                        }
                                                    },
                                                    "Save"
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "realm-remark-delete",
                                                    onclick: {
                                                        let id = realm_id.clone();
                                                        move |_| {
                                                            let id = id.clone();
                                                            state_store.write().remove_realm_remark(&id);
                                                            let mut inputs = realm_remark_inputs();
                                                            inputs.remove(&id);
                                                            realm_remark_inputs.set(inputs);
                                                            realm_remarks_snapshot.set(
                                                                state_store.read().realm_remarks(),
                                                            );
                                                            crate::components::feedback::toast_success(
                                                                "feedback.realm_remark_cleared",
                                                                vec![("realm", short_protocol_id(&id))],
                                                            );
                                                            push_realm_remark_account_data(
                                                                base_url(),
                                                                token(),
                                                                id,
                                                                crate::account_data::RealmRemark::default(),
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
                        }
                    }
                    div { class: "actions", "data-testid": "realm-remark-add-row",
                        Input {
                            r#type: "text",
                            "data-testid": "realm-remark-add-id",
                            placeholder: "ak:realm:...",
                            value: "{new_realm_remark_id()}",
                            oninput: move |event: FormEvent| new_realm_remark_id.set(event.value()),
                        }
                        Input {
                            r#type: "text",
                            "data-testid": "realm-remark-add-name",
                            placeholder: "Local name",
                            value: "{new_realm_remark_name()}",
                            oninput: move |event: FormEvent| new_realm_remark_name.set(event.value()),
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "realm-remark-add-save",
                            onclick: move |_| {
                                let realm_id = new_realm_remark_id().trim().to_owned();
                                let local_name = new_realm_remark_name().trim().to_owned();
                                if realm_id.is_empty() || local_name.is_empty() {
                                    crate::components::feedback::toast_info("feedback.enter_realm_and_name", vec![]);
                                    return;
                                }
                                if !realm_id.starts_with("ak:realm:") {
                                    crate::components::feedback::toast_error("feedback.invalid_realm_id", vec![], None);
                                    return;
                                }
                                let now_rfc3339 = chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                let mut remark = crate::account_data::RealmRemark::new(
                                    realm_id.clone(),
                                    local_name.clone(),
                                );
                                remark.saved_at = Some(now_rfc3339.clone());
                                remark.updated_at = Some(now_rfc3339);
                                state_store
                                    .write()
                                    .set_realm_remark(realm_id.clone(), remark.clone());
                                realm_remarks_snapshot.set(state_store.read().realm_remarks());
                                new_realm_remark_id.set(String::new());
                                new_realm_remark_name.set(String::new());
                                crate::components::feedback::toast_success(
                                    "feedback.realm_remark_saved",
                                    vec![
                                        ("realm", short_protocol_id(&realm_id)),
                                        ("name", local_name.clone()),
                                    ],
                                );
                                push_realm_remark_account_data(
                                    base_url(),
                                    token(),
                                    realm_id,
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
                        span { "Private" }
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
                                for (actor_id, remark) in remarks {
                                    {
                                        let actor_id_label =
                                            display_name_for_did(&state_store.read(), &actor_id);
                                        rsx! {
                                            div {
                                                class: "actions",
                                                "data-testid": "contact-remark-row",
                                                "data-actor-did": "{actor_id}",
                                                span { title: "{actor_id}", "{actor_id_label}" }
                                                Input {
                                                    r#type: "text",
                                                    "data-testid": "contact-remark-input",
                                                    placeholder: "Local name (private)",
                                                    value: "{contact_remark_inputs().get(&actor_id).cloned().unwrap_or_else(|| remark.local_name.clone())}",
                                                    oninput: {
                                                        let did = actor_id.clone();
                                                        move |event: FormEvent| {
                                                            let mut current = contact_remark_inputs();
                                                            current.insert(did.clone(), event.value());
                                                            contact_remark_inputs.set(current);
                                                        }
                                                    },
                                                }
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "contact-remark-save",
                                                    onclick: {
                                                        let did = actor_id.clone();
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
                                                            let did_label =
                                                                display_name_for_did(&state_store.read(), &did);
                                                            if next.is_empty() {
                                                                crate::components::feedback::toast_success(
                                                                    "feedback.contact_remark_cleared",
                                                                    vec![("name", did_label)],
                                                                );
                                                            } else {
                                                                crate::components::feedback::toast_success(
                                                                    "feedback.contact_remark_saved",
                                                                    vec![
                                                                        ("name", did_label),
                                                                        ("local_name", next.local_name.clone()),
                                                                    ],
                                                                );
                                                            }
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
                                                Button {
                                                    variant: ButtonVariant::Secondary,
                                                    "data-testid": "contact-remark-delete",
                                                    onclick: {
                                                        let did = actor_id.clone();
                                                        move |_| {
                                                            let did = did.clone();
                                                            state_store.write().remove_contact_remark(&did);
                                                            let mut inputs = contact_remark_inputs();
                                                            inputs.remove(&did);
                                                            contact_remark_inputs.set(inputs);
                                                            contact_remarks_snapshot.set(
                                                                state_store.read().contact_remarks(),
                                                            );
                                                            let did_label =
                                                                display_name_for_did(&state_store.read(), &did);
                                                            crate::components::feedback::toast_success(
                                                                "feedback.contact_remark_cleared",
                                                                vec![("name", did_label)],
                                                            );
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
                        }
                    }
                    div { class: "actions", "data-testid": "contact-remark-add-row",
                        Input {
                            r#type: "text",
                            "data-testid": "contact-remark-add-did",
                            placeholder: "alice:example.com or did:web:...",
                            value: "{new_contact_remark_did()}",
                            oninput: move |event: FormEvent| new_contact_remark_did.set(event.value()),
                        }
                        Input {
                            r#type: "text",
                            "data-testid": "contact-remark-add-name",
                            placeholder: "Local name",
                            value: "{new_contact_remark_name()}",
                            oninput: move |event: FormEvent| new_contact_remark_name.set(event.value()),
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "contact-remark-add-save",
                            onclick: move |_| {
                                let raw_actor = new_contact_remark_did();
                                let Some(actor_id) =
                                    crate::identity::handle::principal_did_from_identifier(&raw_actor)
                                else {
                                    crate::components::feedback::toast_error("feedback.invalid_actor_identifier", vec![], None);
                                    return;
                                };
                                let local_name = new_contact_remark_name().trim().to_owned();
                                if local_name.is_empty() {
                                    crate::components::feedback::toast_info("feedback.enter_actor_and_name", vec![]);
                                    return;
                                }
                                let now_rfc3339 = chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                let remark = crate::account_data::ContactRemark {
                                    version: 1,
                                    actor_id: actor_id.clone(),
                                    local_name: local_name.clone(),
                                    saved_at: Some(now_rfc3339.clone()),
                                    updated_at: Some(now_rfc3339),
                                    ..crate::account_data::ContactRemark::default()
                                };
                                state_store
                                    .write()
                                    .set_contact_remark(actor_id.clone(), remark.clone());
                                contact_remarks_snapshot.set(state_store.read().contact_remarks());
                                new_contact_remark_did.set(String::new());
                                new_contact_remark_name.set(String::new());
                                let actor_label =
                                    display_name_for_did(&state_store.read(), &actor_id);
                                crate::components::feedback::toast_success(
                                    "feedback.contact_remark_saved",
                                    vec![
                                        ("name", actor_label),
                                        ("local_name", local_name.clone()),
                                    ],
                                );
                                push_contact_remark_account_data(
                                    base_url(),
                                    token(),
                                    actor_id,
                                    remark,
                                );
                            },
                            "Add contact"
                        }
                    }
                }

                // ── YG-HC-1 — Handle management (issuer-managed) ─────
                // Per spec §3.2.3 / §3.4 inkson MUST NOT set or override
                // handles via ak.profile.update / ak.member.identity.update.
                // Handles come from signed ak.schema.handle_claim.v1
                // evidence issued by the org's coauth issuer. So instead
                // of an "edit your handle" affordance we show a managed
                // notice + a link out to the issuer strand.
                            div { class: "event", "data-testid": "handle-managed-by-org",
                    div { class: "event-head",
                        span { "Handle" }
                        span { "Managed by your organization" }
                    }
                    div { class: "muted",
                        "Your handle is managed by your organization. This client cannot set or change it directly — request changes through your organization's issuer."
                    }
                    div { class: "actions",
                        if let Some(href) = crate::identity::account_auth::issuer_handle_management_url(&base_url()) {
                            a {
                                class: "btn secondary",
                                "data-testid": "handle-issuer-link",
                                href: "{href}",
                                target: "_blank",
                                rel: "noopener noreferrer",
                                "Manage handle at your organization's issuer"
                            }
                        } else {
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "handle-issuer-link-disabled",
                                disabled: true,
                                "Issuer link unavailable"
                            }
                        }
                    }
                    if can_list_handles_for_subject {
                        // YG-HC-2 / YG-DIR-1/2 — own visible handle claims +
                        // §3.2.1 primary handle via list_handles_for_subject.
                        crate::views::helpers::WhyThisHandlePanel {
                            token: token(),
                            subject_id: account_did(),
                        }
                    }
                }

                // Personal blocklist — discovery/client-preferences.md
                // Blocks are actor-private filters; they do not affect other actors' clients.
                            div { class: "event", "data-testid": "personal-blocklist",
                    div { class: "event-head",
                        span { {crate::i18n::tr("settings.privacy.blocked_users.title")} }
                        span { class: "badge", "{blocklist_snapshot.read().len()}" }
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
                                Input {
                                    class: "{did_input_class}",
                                    "data-testid": "blocklist-did-input",
                                    placeholder: crate::i18n::tr("settings.privacy.blocked_users.did_placeholder"),
                                    value: "{blocklist_did_input}",
                                    "aria-invalid": if !did_empty && !did_valid { "true" } else { "false" },
                                    oninput: move |event: FormEvent| blocklist_did_input.set(event.value()),
                                }
                                Input {
                                    "data-testid": "blocklist-reason-input",
                                    placeholder: crate::i18n::tr("settings.privacy.blocked_users.reason_placeholder"),
                                    value: "{blocklist_reason_input}",
                                    oninput: move |event: FormEvent| blocklist_reason_input.set(event.value()),
                                }
                                Button {
                                    variant: ButtonVariant::Secondary,
                                    "data-testid": "blocklist-add",
                                    disabled: !did_valid,
                                    onclick: {
                                        let base = base_url;
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
                                        let did_label =
                                            display_name_for_did(&state_store.read(), &did);
                                        blocklist_did_input.set(String::new());
                                        blocklist_reason_input.set(String::new());
                                        blocklist_status.set(format!(
                                            "{} {did_label}",
                                            crate::i18n::tr(
                                                "settings.privacy.blocked_users.added"
                                            )
                                        ));
                                        push_blocklist_account_data(base(), token(), entries);
                                    } else {
                                        let did_label =
                                            display_name_for_did(&state_store.read(), &did);
                                        blocklist_status.set(format!(
                                            "{} {did_label}",
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
                                {
                                    let did_label =
                                        display_name_for_did(&state_store.read(), &entry.did);
                                    rsx! {
                                        li { class: "settings-list-row", "data-testid": "blocklist-entry",
                                            div {
                                                strong { title: "{entry.did}", "{did_label}" }
                                                if let Some(reason) = &entry.reason {
                                                    div { class: "muted", "{reason}" }
                                                }
                                                if let Some(blocked_at) = &entry.blocked_at {
                                                    div { class: "muted", "{blocked_at}" }
                                                }
                                            }
                                            Button {
                                                variant: ButtonVariant::Secondary,
                                                "data-testid": "blocklist-unblock",
                                                onclick: {
                                                    let did = entry.did.clone();
                                                    let base = base_url;
                                                    move |_| {
                                                        let changed = state_store
                                                            .write()
                                                            .unblock_user(&did);
                                                        let entries = state_store.read().client_blocklist();
                                                        blocklist_snapshot.set(entries.clone());
                                                        if changed {
                                                            let did_label =
                                                                display_name_for_did(&state_store.read(), &did);
                                                            blocklist_status.set(format!(
                                                                "{} {did_label}",
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
                    }
                }

                        }
                    }

                    // ── U4 invite_receive_policy ─────────────────────────
                    if active_section == SettingsSection::InvitePolicy {
                        div { class: "settings-content-stack",
                            crate::views::settings::invite_policy::InvitePolicySettingsCard {
                                token,
                                account_did,
                            }
                        }
                    }

                    // ── G3.Y3 personal blocklist ─────────────────────────
                    if active_section == SettingsSection::Blocklist {
                        div { class: "settings-content-stack",
                            crate::views::settings::blocklist::BlocklistSettingsCard {
                                account_did,
                                token,
                            }
                        }
                    }

                    // ── G3.Y3 capability viewer ──────────────────────────
                    if active_section == SettingsSection::Capabilities {
                        div { class: "settings-content-stack",
                            crate::views::settings::capabilities::CapabilitiesSettingsCard {
                                account_did,
                                token,
                            }
                        }
                    }

                    // ── TSP connections (interop extension profile) ──────
                    if active_section == SettingsSection::Connections {
                        div { class: "settings-content-stack",
                            crate::views::settings::connections::ConnectionsSettingsCard {
                                account_did,
                                token,
                            }
                        }
                    }

                    // ── Theme selector ───────────────────────────────────
                    if active_section == SettingsSection::Theme {
                        div { class: "settings-card-grid",
                            div { class: "event", "data-testid": "theme-settings",
                    div { class: "event-head", span { "Theme" } span { "appearance" } }
                    div { class: "actions",
                        Button {
                            variant: if theme() == "light" { ButtonVariant::Primary } else { ButtonVariant::Ghost },
                            size: ButtonSize::Sm,
                            class: "btn icon",
                            "data-testid": "theme-light",
                            title: "Light theme",
                            "aria-label": "Light theme",
                            onclick: move |_| {
                                theme.set("light".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "light");
                                push_client_ui_account_data(base_url(), token(), "light".to_owned());
                            },
                            UiIcon { name: "sun" }
                        }
                        Button {
                            variant: if theme() == "night" { ButtonVariant::Primary } else { ButtonVariant::Ghost },
                            size: ButtonSize::Sm,
                            class: "btn icon",
                            "data-testid": "theme-night",
                            title: "Night theme",
                            "aria-label": "Night theme",
                            onclick: move |_| {
                                theme.set("night".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "night");
                                push_client_ui_account_data(base_url(), token(), "night".to_owned());
                            },
                            UiIcon { name: "moon" }
                        }
                        Button {
                            variant: if theme() == "system" { ButtonVariant::Primary } else { ButtonVariant::Ghost },
                            size: ButtonSize::Sm,
                            class: "btn icon",
                            "data-testid": "theme-system",
                            title: "System theme",
                            "aria-label": "System theme",
                            onclick: move |_| {
                                theme.set("system".to_owned());
                                state_store.write().save_private_data(&account_did(), "theme", "system");
                                push_client_ui_account_data(base_url(), token(), "system".to_owned());
                            },
                            UiIcon { name: "monitor" }
                        }
                    }
                    div { class: "muted", "Current: {theme}" }
                    // P5 — radiogroup-flavoured three-mode switcher
                    // alongside the existing icon-button trio. Same
                    // persistence path; adds ARIA semantics + a label
                    // surface for keyboard / screen-reader users.
                    crate::components::ThemeSwitcher {
                        theme: theme,
                        on_persist: {
                            let base = base_url();
                            let api_token = token();
                            EventHandler::new(move |next: String| {
                                state_store.write().save_private_data(&account_did(), "theme", next.clone());
                                push_client_ui_account_data(base.clone(), api_token.clone(), next);
                            })
                        },
                    }
                }
                            div { class: "event", "data-testid": "language-settings",
                    div { class: "event-head",
                        span { "Language" }
                        span { "data-testid": "text-direction", "{active_direction}" }
                    }
                    div { class: "actions",
                        Button {
                            variant: if active_locale == Locale::En { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "language-en",
                            onclick: move |_| {
                                locale.set(Locale::En);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::En.code());
                            },
                            "English"
                        }
                        Button {
                            variant: if active_locale == Locale::Zh { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "language-zh",
                            onclick: move |_| {
                                locale.set(Locale::Zh);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Zh.code());
                            },
                            "中文"
                        }
                        Button {
                            variant: if active_locale == Locale::Ar { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "language-ar",
                            onclick: move |_| {
                                locale.set(Locale::Ar);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Ar.code());
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
                            div { class: "event", "data-testid": "settings-session-diagnostics",
                                div { class: "event-head",
                                    span { "Session diagnostics" }
                                    span { "Advanced" }
                                }
                                div { class: "metric-grid",
                                    div { class: "metric", "data-testid": "settings-proof-mode",
                                        strong { {crate::i18n::tr("settings.proof_mode.label")} }
                                        span { {crate::operation::current_proof_mode().label_en()} }
                                    }
                                    {
                                        let status = crate::event_signer::signer_status();
                                        let signer_did = status
                                            .as_ref()
                                            .map(|s| s.signer_did.clone())
                                            .unwrap_or_else(|| "—".to_owned());
                                        let signer_did_label = short_protocol_id(&signer_did);
                                        rsx! {
                                            div {
                                                class: "metric",
                                                "data-testid": "settings-signer-info",
                                                strong { {crate::i18n::tr("settings.signer.label")} }
                                                span {
                                                    "data-testid": "settings-signer-did",
                                                    title: "{signer_did}",
                                                    "{signer_did_label}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ── Audit log (promoted from the Release sub-tab) ─────
                    if active_section == SettingsSection::Audit {
                        div { class: "settings-content-stack",
                            crate::views::audit::AuditPanel {}
                        }
                    }

                    // ── Developer tools (promoted from the Release sub-tab) ──
                    if active_section == SettingsSection::Developer {
                        div { class: "settings-content-stack",
                            crate::views::developer::DeveloperToolsPanel {}
                        }
                    }

                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
