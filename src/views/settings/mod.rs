//! Settings surface.
//!
//! Territory split (preserved from former sibling files):
//! - G3.Y1 (device + key-backup): [`devices`], [`recover_restore`], [`recovery`], [`security`].
//! - G3.Y3 (policy / consent / capabilities): [`blocklist`], [`capabilities`], [`consent`].
//! The aggregate routing entry + the generic profile card live in
//! this `mod.rs`.

pub mod blocklist;
pub mod capabilities;
pub mod consent;
pub mod devices;
/// U4 — "谁可以邀请我" invite_receive_policy editor.
pub mod invite_policy;
pub mod mls_recovery;
pub mod recover_restore;
pub mod recovery;
pub mod security;

use base64::Engine as _;
use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use dioxus::prelude::*;
use dioxus_primitives::checkbox::CheckboxState;
use dioxus_router::Link;
use dioxus_router::hooks::{use_navigator, use_route};
use serde_json::json;

use crate::components::{HelpTip, UiIcon};
use crate::config::LocalConfigStore;
use crate::i18n::Locale;
use crate::local_state::LocalStateStore;
use crate::models::AccountDataSetOutcome;
use crate::notification_rules::WatchLevel;
use crate::routes::Route;
use crate::ui::button::{Button, ButtonSize, ButtonVariant};
use crate::ui::checkbox::Checkbox;
use crate::ui::dialog::Dialog;
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::slider::Slider;
use crate::ui::textarea::Textarea;
use crate::views::helpers::{short_protocol_id, with_authed_api};
use crate::views::timeline::{
    TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY, TIMELINE_INCIDENT_PRIORITY_KEY, TIMELINE_PLAINTEXT_ACK_KEY,
    TIMELINE_PRIVATE_PLAINTEXT_KEY, TIMELINE_PUBLIC_UPDATE_GUARD_KEY, plaintext_visible_service,
    timeline_incident_priority_preference, timeline_private_data_bool,
};
use crate::workflows::blocked_release_workflows;

/// `ck.account_data` key used by the read-receipt preferences entry. Spec:
/// `discovery/client-preferences.md` §3.6.
pub(crate) const READ_RECEIPT_ACCOUNT_DATA_KEY: &str = "ck.read_receipt.preferences";

/// `ck.account_data` key used by the cross-device UI preferences entry
/// (theme, sidebar collapsed, per-Realm view). Spec:
/// `discovery/client-preferences.md` §2.
pub(crate) const CLIENT_UI_ACCOUNT_DATA_KEY: &str = "client.ui";

/// `ck.account_data` key used by the actor-private personal blocklist.
/// Spec: `discovery/client-preferences.md` §2 / §3 privacy preferences.
pub(crate) const CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY: &str = "ck.account.blocklist";

/// `ck.account_data` key used by notification push-rule preferences.
pub(crate) const PUSH_RULES_ACCOUNT_DATA_KEY: &str = "ck.push_rules";

/// `ck.account_data` key used by do-not-disturb preferences.
pub(crate) const DND_ACCOUNT_DATA_KEY: &str = "ck.dnd_schedule";

const INVITE_LOCATOR_TTL_MINUTES: i64 = 15;

#[derive(Clone, Debug, PartialEq)]
struct PendingAvatarCrop {
    bytes: Vec<u8>,
    media_type: String,
    preview_data_url: String,
    dimensions: (u32, u32),
}

pub(crate) fn default_avatar_initial(handles: &[String], account_did: &str) -> String {
    handles
        .iter()
        .map(|handle| handle.trim().trim_start_matches('@'))
        .chain(std::iter::once(
            account_did.rsplit(':').next().unwrap_or(account_did),
        ))
        .find_map(|value| value.chars().find(|ch| ch.is_alphanumeric()))
        .map(|ch| ch.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "?".to_owned())
}

pub(crate) fn default_avatar_tone(handles: &[String], account_did: &str) -> usize {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in handles
        .iter()
        .map(String::as_str)
        .chain(std::iter::once(account_did))
        .flat_map(str::bytes)
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize % 6) + 1
}

fn avatar_preview_data_url(bytes: &[u8], media_type: &str) -> String {
    let media_type = if media_type.trim().is_empty() {
        "application/octet-stream"
    } else {
        media_type
    };
    format!("data:{media_type};base64,{}", BASE64_STANDARD.encode(bytes))
}

fn format_settings_handle_list(handles: &[String], fallback: &str) -> String {
    if handles.is_empty() {
        fallback.to_owned()
    } else {
        handles
            .iter()
            .map(|handle| format!("@{handle}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn random_invite_locator_nonce() -> String {
    let mut bytes = [0_u8; 24];
    if getrandom::fill(&mut bytes).is_ok() {
        BASE64_URL_SAFE_NO_PAD.encode(bytes)
    } else {
        crate::operation::uuid_v7()
    }
}

fn build_invite_locator_token(account_did: &str) -> String {
    let expires_at = (chrono::Utc::now() + chrono::Duration::minutes(INVITE_LOCATOR_TTL_MINUTES))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    BASE64_URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "subject_id": account_did,
            "nonce": random_invite_locator_nonce(),
            "expires_at": expires_at,
        }))
        .unwrap_or_default(),
    )
}

fn build_invite_locator_url(base_url: &str, locator_token: &str) -> String {
    let base = base_url.trim_end_matches('/');
    format!("{base}/_cokret/open/invite-locators/resolve#token={locator_token}")
}

fn render_invite_locator_qr_svg(locator_url: &str) -> String {
    if locator_url.trim().is_empty() {
        return String::new();
    }
    match qrcode::QrCode::with_error_correction_level(locator_url.as_bytes(), qrcode::EcLevel::M) {
        Ok(code) => code
            .render::<qrcode::render::svg::Color<'_>>()
            .min_dimensions(192, 192)
            .quiet_zone(true)
            .build(),
        Err(_) => String::new(),
    }
}

fn copy_text_to_clipboard(text: &str) {
    let Ok(encoded) = serde_json::to_string(text) else {
        return;
    };
    let script = format!(
        r#"(async () => {{
    const text = {encoded};
    if (navigator.clipboard && window.isSecureContext) {{
        await navigator.clipboard.writeText(text);
        return true;
    }}
    const node = document.createElement("textarea");
    node.value = text;
    node.setAttribute("readonly", "");
    node.style.position = "fixed";
    node.style.left = "-9999px";
    document.body.appendChild(node);
    node.select();
    const copied = document.execCommand("copy");
    document.body.removeChild(node);
    return copied;
}})()"#
    );
    let _ = document::eval(&script);
}

/// A4a — push the current `client.ui` payload (theme + sidebar
/// collapsed) to soland's `ck.account_data.set` endpoint so other
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
/// also published via `ck.self.account.update_profile` so other actors see
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
                    "soland ck.account_data.set for client.ui returned {status}; \
                     local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "ck.account_data.set for client.ui failed: {}",
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
    realm_overrides: &std::collections::BTreeMap<String, bool>,
    flow_overrides: &std::collections::BTreeMap<String, bool>,
) -> serde_json::Value {
    json!({
        "default_send": default_send,
        "realm_overrides": realm_overrides,
        "flow_overrides": flow_overrides,
    })
}

/// Spawn a fire-and-forget task that pushes the current read-receipt
/// preferences to soland through `ck.account_data.set`. Read latest values
/// from the local state store at call time —
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
        &state_store.read().read_receipt_realm_overrides(),
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
                    "soland ck.account_data.set returned {status}; local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "ck.account_data.set for read-receipt prefs failed: {}",
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
                    "soland ck.account_data.set for ck.account.blocklist returned {status}; \
                     local blocklist remains authoritative"
                );
            }
            Err(err) => {
                tracing::debug!(
                    "ck.account_data.set for ck.account.blocklist failed: {}",
                    err.display()
                );
            }
        }
    });
}

/// Project the local per-realm watch levels into a spec-conformant
/// `ck.push_rules` body (push-notifications.md §4) and sync it to soland.
///
/// Every emitted rule carries the MUST-on-wire `kind` (§4.2) and
/// `evaluation_locus` (§4.3) fields. The rule chain is ordered highest
/// priority first (first match wins):
///
/// 1. `override.priority` — critical/high/urgent always notify.
/// 2. `override.mute-realm.{id}` — a `muted` realm suppresses *everything*, placed above the
///    mention rule so even direct mentions are silenced (§4.3.2: `watch_state=muted` MUST converge
///    to `dont_notify`).
/// 3. `override.mention` — direct mentions notify (client locus: in an E2EE realm the mention lives
///    in ciphertext, §4.5).
/// 4. `underride.realm-mentions-only.{id}` — a `mentions_only` realm suppresses non-mention traffic
///    (placed after the mention rule so mentions still get through). `participating` degrades to
///    the same server-side rule offline (the server can't read the receiver watch cell to tell
///    participation apart); the full `participating` semantics are resolved locally online via the
///    watch gate in `notification_rules`.
/// 5. `underride.realm-all.{id}` — an `all` realm notifies on every event.
/// 6. `default.notify` — global catch-all: unset realms notify (the same baseline the in-app drawer
///    uses for non-muted realms).
fn push_notification_rules_account_data(
    base_url: String,
    api_token: String,
    realm_watch_levels: std::collections::BTreeMap<String, WatchLevel>,
) {
    if api_token.trim().is_empty() {
        return;
    }
    let mut rules = vec![json!({
        "rule_id": "override.priority",
        "kind": "override",
        "enabled": true,
        "evaluation_locus": "server",
        "conditions": [
            {"kind": "field_match", "field": "priority", "pattern": ["critical", "high", "urgent", "priority"]}
        ],
        "actions": ["notify", "highlight", "sound_critical"]
    })];
    // (2) muted realms — above the mention rule.
    for (realm_id, level) in &realm_watch_levels {
        if *level == WatchLevel::Muted {
            rules.push(json!({
                "rule_id": format!("override.mute-realm.{realm_id}"),
                "kind": "override",
                "enabled": true,
                "evaluation_locus": "server",
                "conditions": [
                    {"kind": "field_match", "field": "realm_id", "pattern": realm_id}
                ],
                "actions": ["dont_notify"]
            }));
        }
    }
    // (3) global mention rule.
    rules.push(json!({
        "rule_id": "override.mention",
        "kind": "override",
        "enabled": true,
        "evaluation_locus": "client",
        "conditions": [{"kind": "mentions_actor"}],
        "actions": ["notify", "highlight"]
    }));
    // (4) mentions_only / participating realms — suppress non-mention traffic.
    for (realm_id, level) in &realm_watch_levels {
        if matches!(level, WatchLevel::MentionsOnly | WatchLevel::Participating) {
            rules.push(json!({
                "rule_id": format!("underride.realm-mentions-only.{realm_id}"),
                "kind": "underride",
                "enabled": true,
                "evaluation_locus": "server",
                "conditions": [
                    {"kind": "field_match", "field": "realm_id", "pattern": realm_id}
                ],
                "actions": ["dont_notify"]
            }));
        }
    }
    // (5) all-traffic realms.
    for (realm_id, level) in &realm_watch_levels {
        if *level == WatchLevel::All {
            rules.push(json!({
                "rule_id": format!("underride.realm-all.{realm_id}"),
                "kind": "underride",
                "enabled": true,
                "evaluation_locus": "server",
                "conditions": [
                    {"kind": "field_match", "field": "realm_id", "pattern": realm_id}
                ],
                "actions": ["notify"]
            }));
        }
    }
    // (6) global catch-all.
    rules.push(json!({
        "rule_id": "default.notify",
        "kind": "underride",
        "enabled": true,
        "evaluation_locus": "server",
        "conditions": [],
        "actions": ["notify"]
    }));
    let body = json!({ "rules": rules });
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.set_account_data(PUSH_RULES_ACCOUNT_DATA_KEY, body)
                .await
        })
        .await
        {
            Ok(AccountDataSetOutcome::Stored { .. }) => {}
            Ok(AccountDataSetOutcome::Unsupported { status }) => {
                tracing::debug!(
                    "soland ck.account_data.set for ck.push_rules returned {status}; local notification rules remain authoritative"
                );
            }
            Err(err) => {
                tracing::debug!(
                    "ck.account_data.set for ck.push_rules failed: {}",
                    err.display()
                );
            }
        }
    });
}

fn build_dnd_account_data_body(enabled: bool, mode: &str) -> serde_json::Value {
    let periods = if enabled && mode == "now" {
        vec![json!({"start": "00:00", "end": "23:59"})]
    } else {
        Vec::new()
    };
    json!({
        "dnd": {
            "enabled": enabled,
            "schedule": {
                "timezone": "local",
                "periods": periods
            },
            "exceptions": ["override.priority"]
        }
    })
}

fn push_dnd_account_data(
    base_url: String,
    api_token: String,
    enabled: bool,
    mode: String,
    mut notification_settings_status: Signal<String>,
) {
    if api_token.trim().is_empty() {
        notification_settings_status.set("DND settings require a signed-in session.".to_owned());
        return;
    }
    let body = build_dnd_account_data_body(enabled, &mode);
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.set_account_data(DND_ACCOUNT_DATA_KEY, body).await
        })
        .await
        {
            Ok(AccountDataSetOutcome::Stored { .. })
            | Ok(AccountDataSetOutcome::Unsupported { .. }) => {
                notification_settings_status.set(if enabled {
                    "Do not disturb enabled.".to_owned()
                } else {
                    "DND disabled.".to_owned()
                });
            }
            Err(err) => {
                notification_settings_status.set(format!("DND save failed: {}", err.display()));
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
/// soland via `ck.account_data.set`. Same graceful-degradation contract as
/// [`push_read_receipt_account_data`] — local state is authoritative; the
/// server PUT is best-effort. `remark.is_empty()` triggers a DELETE so the
/// row tombstones cleanly across devices.
pub(crate) fn push_realm_remark_account_data(
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
) {
    push_realm_remark_account_data_impl(base_url, api_token, realm_id, remark, None);
}

pub(crate) fn push_realm_remark_account_data_with_failure_status(
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
    failure_status: Signal<String>,
) {
    push_realm_remark_account_data_impl(
        base_url,
        api_token,
        realm_id,
        remark,
        Some((failure_status, crate::i18n::tr("realm.pin_failed"))),
    );
}

fn push_realm_remark_account_data_impl(
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
    mut failure_status: Option<(Signal<String>, String)>,
) {
    let key = crate::account_data::realm_remark_account_data_key(&realm_id);
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
                if let Some((status, label)) = failure_status.as_mut() {
                    status.set(format!("{label}: {}", err.display()));
                }
            }
            return;
        }
        let body = match serde_json::to_value(&remark) {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!("Realm remark serialisation failed: {error}");
                if let Some((status, label)) = failure_status.as_mut() {
                    status.set(format!("{label}: {error}"));
                }
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
                    "soland ck.account_data.set for {key_for_log} returned {status}; local state still authoritative"
                );
                if let Some((status_signal, label)) = failure_status.as_mut() {
                    status_signal.set(format!("{label}: HTTP {status}"));
                }
            }
            Err(err) => {
                tracing::warn!(
                    "ck.account_data.set for {key_for_log} failed: {}",
                    err.display()
                );
                if let Some((status, label)) = failure_status.as_mut() {
                    status.set(format!("{label}: {}", err.display()));
                }
            }
        }
    });
}

pub(crate) fn push_contact_remark_account_data(
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
                    "soland ck.account_data.set for {key_for_log} returned {status}; local state still authoritative"
                );
            }
            Err(err) => {
                tracing::warn!(
                    "ck.account_data.set for {key_for_log} failed: {}",
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
                Checkbox {
                    checked: if enabled { CheckboxState::Checked } else { CheckboxState::Unchecked },
                    on_checked_change: move |state: CheckboxState| {
                        let enabled = bool::from(state);
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

/// Human-readable label for a watch level, used by the per-realm override
/// picker. Spec values: push-notifications.md §4.3.2.
fn watch_level_label(level: WatchLevel) -> &'static str {
    match level {
        WatchLevel::All => "All messages",
        WatchLevel::Participating => "Participating",
        WatchLevel::MentionsOnly => "Mentions only",
        WatchLevel::Muted => "Muted",
    }
}

/// Realms the user can pick a per-realm override for: the union of realms with
/// a cached tree projection, a private remark, or an existing override. Each
/// entry is `(realm_id, friendly_label)` with the label resolved through the
/// local remark (falling back to the public title, then the short id). Sorted
/// by realm id (BTreeMap) for a stable picker order.
fn known_realm_options(store: &LocalStateStore) -> Vec<(String, String)> {
    let state = store.load();
    let mut titles: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (realm_id, projection) in &state.realm_tree_projections {
        let title = projection
            .get("name")
            .and_then(|value| value.as_str())
            .or_else(|| projection.get("title").and_then(|value| value.as_str()))
            .unwrap_or_default()
            .to_owned();
        titles.entry(realm_id.clone()).or_insert(title);
    }
    for realm_id in state.realm_remarks.keys() {
        titles.entry(realm_id.clone()).or_default();
    }
    for realm_id in state.realm_watch_levels.keys() {
        titles.entry(realm_id.clone()).or_default();
    }
    titles
        .into_iter()
        .map(|(realm_id, public_title)| {
            let resolved = store.display_name_for_realm(&realm_id, &public_title);
            let label = if resolved.trim().is_empty() {
                short_protocol_id(&realm_id)
            } else {
                resolved
            };
            (realm_id, label)
        })
        .collect()
}

/// One row of the per-realm override list: the realm label, a 4-level watch
/// picker bound to local state, and a remove button. Its own component so the
/// controlled `value` memo can read `state_store` reactively (a free function
/// could not hold a hook).
#[component]
fn RealmOverrideRow(
    realm_id: String,
    label: String,
    mut state_store: Signal<LocalStateStore>,
    base_url: Signal<String>,
    token: Signal<String>,
    mut status: Signal<String>,
) -> Element {
    let level = state_store.read().realm_watch_level(&realm_id);
    let selected = use_memo({
        let realm_id = realm_id.clone();
        move || {
            Some(
                state_store
                    .read()
                    .realm_watch_level(&realm_id)
                    .as_wire()
                    .to_owned(),
            )
        }
    });
    // Muted rows keep the legacy testid so existing notification e2e flows
    // (mute from drawer → confirm here) keep resolving.
    let row_testid = if level == WatchLevel::Muted {
        "settings-muted-realm-row"
    } else {
        "settings-realm-override-row"
    };
    rsx! {
        div { class: "actions", "data-testid": "{row_testid}", "data-realm-id": "{realm_id}",
            span { class: "mono", title: "{realm_id}", "{label}" }
            Select::<String> {
                "data-testid": "realm-watch-level-select",
                value: Some(selected.into()),
                on_value_change: {
                    let realm_id = realm_id.clone();
                    move |value: Option<String>| {
                        let Some(value) = value else { return };
                        let next = WatchLevel::from_wire(&value).unwrap_or_default();
                        state_store.write().set_realm_watch_level(realm_id.clone(), next);
                        push_notification_rules_account_data(
                            base_url(),
                            token(),
                            state_store.read().realm_watch_levels(),
                        );
                        status.set(format!(
                            "Set {} to {}.",
                            short_protocol_id(&realm_id),
                            watch_level_label(next)
                        ));
                    }
                },
                SelectOption::<String> { index: 0usize, value: "all".to_string(), text_value: "All messages", "All messages" }
                SelectOption::<String> { index: 1usize, value: "participating".to_string(), text_value: "Participating", "Participating" }
                SelectOption::<String> { index: 2usize, value: "mentions_only".to_string(), text_value: "Mentions only", "Mentions only" }
                SelectOption::<String> { index: 3usize, value: "muted".to_string(), text_value: "Muted", "Muted" }
            }
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "settings-realm-override-remove",
                onclick: {
                    let realm_id = realm_id.clone();
                    move |_| {
                        state_store.write().set_realm_watch_level(realm_id.clone(), WatchLevel::default());
                        push_notification_rules_account_data(
                            base_url(),
                            token(),
                            state_store.read().realm_watch_levels(),
                        );
                        status.set(format!(
                            "Removed override for {}.",
                            short_protocol_id(&realm_id)
                        ));
                    }
                },
                "Remove"
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SettingsSection {
    Account,
    Agents,
    Server,
    Devices,
    Storage,
    Encryption,
    KeyBackup,
    Recovery,
    Mimi,
    Notifications,
    Privacy,
    /// U4 invite_receive_policy (`/settings/invite-policy`).
    InvitePolicy,
    /// G3.Y3 — consent grants (`/settings/consent`).
    Consent,
    /// G3.Y3 — personal blocklist (`/settings/blocklist`).
    Blocklist,
    /// G3.Y3 — capability delegation viewer (`/settings/capabilities`).
    Capabilities,
    Timeline,
    Theme,
    Release,
}

impl SettingsSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or("account") {
            "account" => Self::Account,
            "agents" => Self::Agents,
            "devices" => Self::Devices,
            "storage" => Self::Storage,
            "encryption" => Self::Encryption,
            "security" | "key-backup" => Self::KeyBackup,
            "recovery" => Self::Recovery,
            "mimi" => Self::Mimi,
            "push" | "notifications" => Self::Notifications,
            "privacy" => Self::Privacy,
            "invite-policy" | "invite_policy" => Self::InvitePolicy,
            "consent" => Self::Consent,
            "blocklist" | "blocked-users" => Self::Blocklist,
            "capabilities" => Self::Capabilities,
            "timeline" | "composer" => Self::Timeline,
            "audit" | "audit-log" | "developer" | "developer-tools" | "release" => Self::Release,
            "theme" => Self::Theme,
            _ => Self::Server,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Agents => "agents",
            Self::Server => "server",
            Self::Devices => "devices",
            Self::Storage => "storage",
            Self::Encryption => "encryption",
            Self::KeyBackup => "security",
            Self::Recovery => "recovery",
            Self::Mimi => "mimi",
            Self::Notifications => "notifications",
            Self::Privacy => "privacy",
            Self::InvitePolicy => "invite-policy",
            Self::Consent => "consent",
            Self::Blocklist => "blocklist",
            Self::Capabilities => "capabilities",
            Self::Timeline => "timeline",
            Self::Theme => "theme",
            Self::Release => "release",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Account => "Account information",
            Self::Agents => "My Agents",
            Self::Server => "Server information",
            Self::Devices => "Devices",
            Self::Storage => "Data & sync",
            Self::Encryption => "Security",
            Self::KeyBackup => "Key backup",
            Self::Recovery => "Recovery",
            Self::Mimi => "Integrations",
            Self::Notifications => "Notifications",
            Self::Privacy => "Privacy & sharing",
            Self::InvitePolicy => "Who can invite me",
            Self::Consent => "Consent grants",
            Self::Blocklist => "Blocked actors",
            Self::Capabilities => "Capabilities",
            Self::Timeline => "Timeline & composer",
            Self::Theme => "Appearance & locale",
            Self::Release => "Diagnostics",
        }
    }

    fn route(self) -> Route {
        match self {
            Self::Devices => Route::SettingsDevices,
            Self::KeyBackup => Route::SettingsSecurity,
            Self::Recovery => Route::SettingsRecovery,
            _ => Route::SettingsSection {
                section: self.slug().to_owned(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DiagnosticsMode {
    Developer,
    Audit,
}

impl DiagnosticsMode {
    fn from_slug(slug: Option<&str>) -> Option<Self> {
        match slug {
            Some("developer" | "developer-tools") => Some(Self::Developer),
            Some("audit" | "audit-log") => Some(Self::Audit),
            _ => None,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Developer => "developer",
            Self::Audit => "audit",
        }
    }

    fn route(self) -> Route {
        Route::SettingsSection {
            section: self.slug().to_owned(),
        }
    }
}

const SETTINGS_ACCOUNT_GROUP: &[SettingsSection] = &[
    SettingsSection::Account,
    SettingsSection::Agents,
    SettingsSection::Server,
    SettingsSection::Devices,
];
const SETTINGS_SECURITY_GROUP: &[SettingsSection] =
    &[SettingsSection::KeyBackup, SettingsSection::Recovery];
const SETTINGS_DELIVERY_GROUP: &[SettingsSection] = &[
    SettingsSection::Notifications,
    SettingsSection::Privacy,
    // U4 invite_receive_policy is an actor-private
    // disclosure control, so it sits with the other privacy surfaces.
    SettingsSection::InvitePolicy,
    // G3.Y3 — consent + blocklist sit next to Privacy because both are
    // actor-private disclosure controls (spec
    // identity/consent-model.md §2, governance/content-moderation.md §4).
    SettingsSection::Consent,
    SettingsSection::Blocklist,
];
const SETTINGS_CLIENT_GROUP: &[SettingsSection] =
    &[SettingsSection::Timeline, SettingsSection::Theme];
const SETTINGS_ADVANCED_GROUP: &[SettingsSection] = &[
    SettingsSection::Capabilities,
    SettingsSection::Storage,
    SettingsSection::Release,
];
const SETTINGS_NAV_GROUPS: &[(&str, &str, &[SettingsSection])] = &[
    (
        "Account",
        "Identity, server, and signed-in devices.",
        SETTINGS_ACCOUNT_GROUP,
    ),
    (
        "Security & recovery",
        "Encrypted backup and account recovery.",
        SETTINGS_SECURITY_GROUP,
    ),
    (
        "Notifications & privacy",
        "Notification delivery behavior, actor-private disclosure controls, and consent/blocklist.",
        SETTINGS_DELIVERY_GROUP,
    ),
    ("App", "Appearance and locale.", SETTINGS_CLIENT_GROUP),
    (
        "Advanced",
        "Capability, storage, and protocol diagnostics.",
        SETTINGS_ADVANCED_GROUP,
    ),
];

#[component]
pub fn SettingsPanel(
    base_url: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    token: Signal<String>,
    personal_handles: Vec<String>,
    personal_handles_status: String,
    can_list_handles_for_subject: bool,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    push_state: Signal<String>,
    mut locale: Signal<Locale>,
    mut theme: Signal<String>,
    status: Signal<String>,
) -> Element {
    let route = use_route::<Route>();
    let navigator = use_navigator();
    let active_section = SettingsSection::from_slug(route.settings_section());
    let route_diagnostics_mode = DiagnosticsMode::from_slug(route.settings_section());
    let mut diagnostics_mode =
        use_signal(|| route_diagnostics_mode.unwrap_or(DiagnosticsMode::Developer));
    let active_diagnostics_mode = route_diagnostics_mode.unwrap_or_else(|| diagnostics_mode());
    let mut presence_visible = use_signal(|| true);
    let mut dnd_enabled = use_signal(|| false);
    let mut dnd_mode = use_signal(|| "off".to_owned());
    let dnd_mode_selected = use_memo(move || Some(dnd_mode()));
    let notification_settings_status = use_signal(String::new);
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
    // `state_store.set_read_receipt_*` so the timeline view can resolve
    // (flow → realm → default) before sending `ck.receipt.read`.
    let mut read_receipt_default_send =
        use_signal(|| state_store.read().read_receipt_default_send());
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
    // `ck.account_data.set("client.ui", { avatar_blob_ref })` and is
    // *also* published publicly to soland's
    // `POST /_soland/self/account/profile { avatar_url }` so the directory
    // can index it.
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
    let mut timeline_encrypt_local_default = use_signal(|| {
        timeline_private_data_bool(
            &state_store.read(),
            &account_did(),
            TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY,
            false,
        )
    });
    let mut timeline_public_update_guard = use_signal(|| {
        timeline_private_data_bool(
            &state_store.read(),
            &account_did(),
            TIMELINE_PUBLIC_UPDATE_GUARD_KEY,
            true,
        )
    });
    let mut timeline_private_plaintext = use_signal(|| {
        timeline_private_data_bool(
            &state_store.read(),
            &account_did(),
            TIMELINE_PRIVATE_PLAINTEXT_KEY,
            false,
        )
    });
    let mut timeline_plaintext_ack = use_signal(|| {
        timeline_private_data_bool(
            &state_store.read(),
            &account_did(),
            TIMELINE_PLAINTEXT_ACK_KEY,
            false,
        )
    });
    let mut timeline_incident_priority =
        use_signal(|| timeline_incident_priority_preference(&state_store.read(), &account_did()));
    let timeline_incident_priority_selected = use_memo(move || Some(timeline_incident_priority()));
    let mut mls_group_policy = use_signal(|| "default".to_owned());
    let mls_group_policy_selected = use_memo(move || Some(mls_group_policy()));
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
    let principal_short_label = short_protocol_id(&principal_label);
    let device_short_label = short_protocol_id(&device_label);
    let timeline_visible_service = plaintext_visible_service(&base_url());
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
        div { class: "settings", "data-testid": "settings-panel",
            div { class: "settings-shell",
                aside { class: "settings-sidebar-column",
                    for (group_index, (group_label, _, sections)) in SETTINGS_NAV_GROUPS.iter().copied().enumerate() {
                        div { class: "settings-nav-cluster",
                            div { class: "settings-nav-group-label", "{group_label}" }
                            for section in sections.iter().copied() {
                                Link {
                                    class: if active_section == section { "settings-nav-item active" } else { "settings-nav-item" },
                                    "data-testid": "settings-nav-item-{section.slug()}",
                                    "aria-current": if active_section == section { "page" } else { "false" },
                                    to: section.route(),
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
                            // `ck.self.account.update_profile` so the
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
                                                    let file = files.into_iter().next().expect("non-empty");
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
                                                                        let api = match crate::views::helpers::authed_api(&base, api_token.clone()) {
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
                                                                        match api.upload_blob_bytes(bytes, "image/jpeg").await {
                                                                            Ok(resp) => {
                                                                                let blob_ref = resp.blob_ref.to_string();
                                                                                let avatar_url = api.blob_download_url(&blob_ref);
                                                                                // Publish publicly first; only then refresh the
                                                                                // local mirror so a failed profile update does not
                                                                                // display an avatar that never became active.
                                                                                match api
                                                                                    .update_profile(None, None, Some(&avatar_url))
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
                                                                                        profile_avatar_blob_ref.set(refreshed.clone());
                                                                                        avatar_refresh_nonce.set(avatar_refresh_nonce() + 1);
                                                                                        avatar_uploading.set(false);
                                                                                        pending_avatar_crop.set(None);
                                                                                        avatar_upload_status.set(String::new());
                                                                                        status.set(format!(
                                                                                            "Avatar updated ({refreshed})"
                                                                                        ));
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
                                                                crate::views::helpers::authed_api(&base, api_token)
                                                                && let Err(err) = api
                                                                    .update_profile(None, None, Some(""))
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
                                                "{principal_short_label}"
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
                                                        status.set("DID copied".to_owned());
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
                                                        status.set("Handles copied".to_owned());
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
                                                        status.set("Device ID copied".to_owned());
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
                                                        status.set("Invite locator URL copied".to_owned());
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
                                                    status.set("Invite locator refreshed".to_owned());
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

                    // ── My Agents (CKP-0008 native personal agents) ──────
                    if active_section == SettingsSection::Agents {
                        crate::views::agents::PersonalAgentAdminPanel {
                            base_url: base_url(),
                            token,
                            controller_did: account_did(),
                        }
                    }

                    if active_section == SettingsSection::Devices {
                        crate::views::settings::devices::SettingsDevicesPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            state_store,
                        }
                    }

                    if active_section == SettingsSection::KeyBackup {
                        crate::views::settings::security::SettingsSecurityPanel {
                            base_url,
                            account_did,
                            device_id,
                            token,
                            state_store,
                        }
                    }

                    if active_section == SettingsSection::Recovery {
                        crate::views::recovery::RecoveryPanel {
                            base_url: base_url(),
                            token,
                            state_store,
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
                                label { "MLS Group Policy" }
                                Select::<String> {
                                    value: Some(mls_group_policy_selected.into()),
                                    on_value_change: move |v: Option<String>| { if let Some(v) = v { mls_group_policy.set(v); } },
                                    SelectOption::<String> { index: 0usize, value: "default".to_string(), text_value: "Default", "Default" }
                                    SelectOption::<String> { index: 1usize, value: "always-encrypt".to_string(), text_value: "Always Encrypt", "Always Encrypt" }
                                    SelectOption::<String> { index: 2usize, value: "prefer-plaintext".to_string(), text_value: "Prefer Plaintext", "Prefer Plaintext" }
                                }
                            }
                            // X11.1 — persistent MLS recovery-key entry.
                            // Always reachable here (Security & recovery),
                            // shows live backup status, and lets the user
                            // generate/replace the recovery key regardless of the
                            // boot detection effect timing. NOT gated on
                            // `needs_mls_backup`.
                            mls_recovery::SettingsMlsRecoveryPanel {
                                base_url,
                                token,
                                account_did,
                                device_id,
                                state_store,
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
                                    "Use these links only for protocol diagnostics or when debugging a specific backup envelope."
                                }
                                div { class: "actions",
                                    Link {
                                        class: "primary",
                                        "data-testid": "key-backup-open-recovery",
                                        to: Route::SettingsRecovery,
                                        UiIcon { name: "key" }
                                        "Recovery vault"
                                    }
                                    Link {
                                        class: "secondary",
                                        "data-testid": "key-backup-open-manual",
                                        to: Route::SettingsSecurity,
                                        UiIcon { name: "archive" }
                                        "Manual backup tools"
                                    }
                                }
                                div { class: "muted",
                                    "Contract: ck.schema.key_backup.v1 over /_cokret/self/keys/backups/*. This is not required for encrypted-history recovery setup."
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
                        Button {
                            variant: ButtonVariant::Secondary,
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
                                                // R20: `room_id` is the MIMI-draft wire term
                                                // (interop-exempt from Room → Realm). On the
                                                // Cokret app side it identifies a Flow, so we
                                                // bind it to a `flow_id`-named local to keep
                                                // the "Room" term confined to the interop layer.
                                                let flow_id = &response.room_id;
                                                mimi_receipt.set(format!(
                                                    "group-info {} participants {}",
                                                    flow_id,
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
                        Button {
                            variant: ButtonVariant::Secondary,
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
                        Button {
                            variant: ButtonVariant::Secondary,
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
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "mimi-proxy-download",
                            onclick: {
                                move |_| {
                                    let base = base_url();
                                    let api_token = token();
                                    spawn(async move {
                                        match with_authed_api(&base, api_token, |api| async move {
                                            api.mimi_proxy_download(json!({
                                                "blob_ref": "ck:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91",
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
                            div { class: "event", "data-testid": "notification-settings-panel",
                                div { class: "event-head",
                                    span { "Global notification defaults" }
                                    span { "synced" }
                                }
                                div { class: "muted",
                                    "Apply to every Realm unless you add a per-Realm override below."
                                }
                                div { class: "metric-grid",
                                    {render_notification_kind_toggle("mention", "Mention notifications", state_store, status)}
                                    {render_notification_kind_toggle("reaction", "Reaction notifications", state_store, status)}
                                    {render_notification_kind_toggle("invite", "Invite notifications", state_store, status)}
                                    {render_notification_kind_toggle("message", "Message notifications", state_store, status)}
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
                                    if known_realms.is_empty() {
                                        Input {
                                            "data-testid": "realm-override-id-input",
                                            value: "{new_override_realm}",
                                            placeholder: "ck:realm:...",
                                            oninput: move |event: FormEvent| new_override_realm.set(event.value()),
                                        }
                                    } else {
                                        Select::<String> {
                                            "data-testid": "realm-override-realm-select",
                                            value: Some(new_override_realm_selected.into()),
                                            on_value_change: move |v: Option<String>| { if let Some(v) = v { new_override_realm.set(v); } },
                                            SelectOption::<String> { index: 0usize, value: String::new(), text_value: "Select a Realm…", "Select a Realm…" }
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
                                    Select::<String> {
                                        "data-testid": "realm-override-level-select",
                                        value: Some(new_override_level_selected.into()),
                                        on_value_change: move |v: Option<String>| { if let Some(v) = v { new_override_level.set(v); } },
                                        SelectOption::<String> { index: 0usize, value: "all".to_string(), text_value: "All messages", "All messages" }
                                        SelectOption::<String> { index: 1usize, value: "participating".to_string(), text_value: "Participating", "Participating" }
                                        SelectOption::<String> { index: 2usize, value: "mentions_only".to_string(), text_value: "Mentions only", "Mentions only" }
                                        SelectOption::<String> { index: 3usize, value: "muted".to_string(), text_value: "Muted", "Muted" }
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "realm-override-add",
                                        onclick: move |_| {
                                            let realm_id = new_override_realm().trim().to_owned();
                                            if realm_id.is_empty() {
                                                status.set("Pick a Realm before adding an override.".to_owned());
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
                                            status.set(format!(
                                                "Set {} to {}.",
                                                short_protocol_id(&realm_id),
                                                watch_level_label(level)
                                            ));
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
                                                    state_store,
                                                    base_url,
                                                    token,
                                                    status,
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
                                            status.set("Cleared all per-realm overrides.".to_owned());
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
                                    let mut local_store = state_store.read().clone();
                                    spawn(async move {
                                        let principal_id =
                                            (!principal_id.trim().is_empty()).then_some(principal_id);
                                        let context = crate::push::registration::RegisterContext {
                                            principal_server_url: base,
                                            floria_gateway_url: crate::push::floria_gateway_url(),
                                            device_id: dev,
                                            principal_id,
                                            bearer_token: Some(api_token),
                                            session_grant: None,
                                            active_circle_id: None,
                                        };
                                        match crate::push::registration::register_via_chime(
                                            context,
                                            &mut local_store,
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
                                                status.set(format!("Push registered: {label}"));
                                            }
                                            Err(err) => {
                                                let message = format!("push register failed: {err}");
                                                push_state.set(message.clone());
                                                status.set(message);
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
                }
                        }
                    }

                    // ── Privacy settings ─────────────────────────────────
                    if active_section == SettingsSection::Privacy {
                        div { class: "settings-content-stack",
                            div { class: "event", "data-testid": "privacy-settings",
                    div { class: "event-head", span { "Privacy" } span { "visibility controls" } }
                    label {
                        Checkbox {
                            checked: if presence_visible() { CheckboxState::Checked } else { CheckboxState::Unchecked },
                            on_checked_change: move |state: CheckboxState| presence_visible.set(bool::from(state)),
                        }
                        " Show presence to others"
                    }
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
                                status.set(format!(
                                    "Read receipts: default = {}",
                                    if send { "send" } else { "skip" }
                                ));
                                // Also push to soland's ck.account_data.set
                                // so other devices pick up the change.
                                // Endpoint may 404/501 — we swallow and keep
                                // local authoritative.
                                let body = build_read_receipt_preferences_body(
                                    send,
                                    &state_store
                                        .read()
                                        .read_receipt_realm_overrides(),
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
                        " Send read receipts by default"
                    }
                    div { class: "event-head",
                        span { "Realm exceptions" }
                        span { "{read_receipt_realm_overrides().len()} configured" }
                    }
                    for (realm_id, send) in read_receipt_realm_overrides() {
                            // Policy lock — when soland publishes a
                            // ck.realm.read_receipt_policy with disclosure=
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
                                                    status.set(format!(
                                                        "Read receipts for {}: {}",
                                                        short_protocol_id(&realm_id),
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
                                                    status.set(format!(
                                                        "Read receipts for {}: inherit default",
                                                        short_protocol_id(&realm_id)
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
                        Input {
                            r#type: "text",
                            placeholder: "ck:realm:...",
                            value: "{read_receipt_override_input()}",
                            oninput: move |event: FormEvent| read_receipt_override_input.set(event.value()),
                        }
                        Button {
                            variant: ButtonVariant::Secondary,
                            "data-testid": "read-receipt-add-override-skip",
                            onclick: move |_| {
                                let realm_id = read_receipt_override_input().trim().to_owned();
                                if realm_id.is_empty() {
                                    status.set("Enter a Realm ID first".to_owned());
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
                                status.set(format!(
                                    "Skipping read receipts in {}",
                                    short_protocol_id(&realm_id)
                                ));
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
                                    status.set("Enter a Realm ID first".to_owned());
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
                                status.set(format!(
                                    "Sending read receipts in {}",
                                    short_protocol_id(&realm_id)
                                ));
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
                // Pushed to soland via `ck.account_data.set` under
                // `ck.contacts.realm.<realm_id>`; soland echoes the same
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
                                                            let action_status = if next_pinned {
                                                                crate::i18n::tr("realm.pinned")
                                                            } else {
                                                                crate::i18n::tr("realm.unpin")
                                                            };
                                                            status.set(format!(
                                                                "{action_status}: {}",
                                                                short_protocol_id(&id)
                                                            ));
                                                            push_realm_remark_account_data_with_failure_status(
                                                                base_url(),
                                                                token(),
                                                                id,
                                                                next,
                                                                status,
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
                                                                status.set(format!(
                                                                    "Realm remark cleared for {}",
                                                                    short_protocol_id(&id)
                                                                ));
                                                            } else {
                                                                status.set(format!(
                                                                    "Realm remark saved: {} → {}",
                                                                    short_protocol_id(&id), next.local_name
                                                                ));
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
                                                            status.set(format!(
                                                                "Realm remark cleared for {}",
                                                                short_protocol_id(&id)
                                                            ));
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
                            placeholder: "ck:realm:...",
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
                                    status.set(
                                        "Enter both a Realm ID and a local name".to_owned(),
                                    );
                                    return;
                                }
                                if !realm_id.starts_with("ck:realm:") {
                                    status.set(
                                        "Realm ID must start with ck:realm:".to_owned(),
                                    );
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
                                status.set(format!(
                                    "Realm remark saved: {} → {local_name}",
                                    short_protocol_id(&realm_id)
                                ));
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
                                for (actor_did, remark) in remarks {
                                    {
                                        let actor_did_label = short_protocol_id(&actor_did);
                                        rsx! {
                                            div {
                                                class: "actions",
                                                "data-testid": "contact-remark-row",
                                                "data-actor-did": "{actor_did}",
                                                span { class: "mono", title: "{actor_did}", "{actor_did_label}" }
                                                Input {
                                                    r#type: "text",
                                                    "data-testid": "contact-remark-input",
                                                    placeholder: "Local name (private)",
                                                    value: "{contact_remark_inputs().get(&actor_did).cloned().unwrap_or_else(|| remark.local_name.clone())}",
                                                    oninput: {
                                                        let did = actor_did.clone();
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
                                                                format!(
                                                                    "Contact remark cleared for {}",
                                                                    short_protocol_id(&did)
                                                                )
                                                            } else {
                                                                format!(
                                                                    "Contact remark saved: {} → {}",
                                                                    short_protocol_id(&did), next.local_name
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
                                                Button {
                                                    variant: ButtonVariant::Secondary,
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
                                                                "Contact remark cleared for {}",
                                                                short_protocol_id(&did)
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
                                let Some(actor_did) =
                                    crate::identity_handle::principal_did_from_identifier(&raw_actor)
                                else {
                                    status.set(
                                        "Enter an actor DID or handle like alice:example.com"
                                            .to_owned(),
                                    );
                                    return;
                                };
                                let local_name = new_contact_remark_name().trim().to_owned();
                                if local_name.is_empty() {
                                    status.set(
                                        "Enter both an actor identifier and a local name".to_owned(),
                                    );
                                    return;
                                }
                                let now_rfc3339 = chrono::Utc::now()
                                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                                let remark = crate::account_data::ContactRemark {
                                    version: 1,
                                    actor_id: actor_did.clone(),
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
                                    "Contact remark saved: {} → {local_name}",
                                    short_protocol_id(&actor_did)
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

                // ── YG-HC-1 — Handle management (issuer-managed) ─────
                // Per spec §3.2.3 / §3.4 yougen MUST NOT set or override
                // handles via ck.profile.update / ck.member.identity.update.
                // Handles come from signed ck.schema.handle_claim.v1
                // evidence issued by the org's coauth issuer. So instead
                // of an "edit your handle" affordance we show a managed
                // notice + a link out to the issuer flow.
                            div { class: "event", "data-testid": "handle-managed-by-org",
                    div { class: "event-head",
                        span { "Handle" }
                        span { "Managed by your organization" }
                    }
                    div { class: "muted",
                        "Your handle is managed by your organization. This client cannot set or change it directly — request changes through your organization's issuer."
                    }
                    div { class: "actions",
                        if let Some(href) = crate::coauth::issuer_handle_management_url(&base_url()) {
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
                            base_url: base_url(),
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
                                        let did_label = short_protocol_id(&did);
                                        blocklist_did_input.set(String::new());
                                        blocklist_reason_input.set(String::new());
                                        blocklist_status.set(format!(
                                            "{} {did_label}",
                                            crate::i18n::tr(
                                                "settings.privacy.blocked_users.added"
                                            )
                                        ));
                                        status.set(format!(
                                            "{} {did_label}",
                                            crate::i18n::tr(
                                                "settings.privacy.blocked_users.added"
                                            )
                                        ));
                                        push_blocklist_account_data(base(), token(), entries);
                                    } else {
                                        let did_label = short_protocol_id(&did);
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
                                    let did_label = short_protocol_id(&entry.did);
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
                                                            let did_label = short_protocol_id(&did);
                                                            blocklist_status.set(format!(
                                                                "{} {did_label}",
                                                                crate::i18n::tr(
                                                                    "settings.privacy.blocked_users.removed"
                                                                )
                                                            ));
                                                            status.set(format!(
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

                        // ── Consent grant event PoC ────
                        // First user-facing button on the anchored cell pipeline. Builds a
                        // ck.consent.grant event, signs with a deterministic demo ed25519 key
                        // (TODO real-key-management), and submits it through ck.events.submit.
                        if crate::views::agents::agents_enabled() {
                            crate::views::consent_demo::ConsentGrantDemoCard {
                                base_url,
                                token,
                                state_store,
                            }
                        }

                        }
                    }

                    // ── U4 invite_receive_policy ─────────────────────────
                    if active_section == SettingsSection::InvitePolicy {
                        div { class: "settings-content-stack",
                            crate::views::settings::invite_policy::InvitePolicySettingsCard {
                                base_url,
                                token,
                            }
                        }
                    }

                    // ── G3.Y3 consent grants ─────────────────────────────
                    if active_section == SettingsSection::Consent {
                        div { class: "settings-content-stack",
                            crate::views::settings::consent::ConsentSettingsCard {
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
                            crate::views::settings::blocklist::BlocklistSettingsCard {
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
                            crate::views::settings::capabilities::CapabilitiesSettingsCard {
                                base_url,
                                account_did,
                                token,
                                state_store,
                            }
                        }
                    }

                    // ── Timeline composer defaults ──────────────────────
                    if active_section == SettingsSection::Timeline {
                        div { class: "settings-card-grid",
                            div { class: "event settings-card-span-2", "data-testid": "settings-timeline-composer",
                                div { class: "event-head",
                                    span { "Composer defaults" }
                                    span { "Timeline" }
                                }
                                div { class: "metric-grid",
                                    label { class: "metric",
                                        Checkbox {
                                            "data-testid": "settings-timeline-encrypt-default",
                                            checked: if timeline_encrypt_local_default() {
                                                CheckboxState::Checked
                                            } else {
                                                CheckboxState::Unchecked
                                            },
                                            on_checked_change: move |state: CheckboxState| {
                                                let enabled = bool::from(state);
                                                timeline_encrypt_local_default.set(enabled);
                                                state_store.write().save_private_data(
                                                    &account_did(),
                                                    TIMELINE_ENCRYPT_LOCAL_DEFAULT_KEY,
                                                    enabled.to_string(),
                                                );
                                                status.set(if enabled {
                                                    "Timeline composer defaults to Encrypt Local.".to_owned()
                                                } else {
                                                    "Timeline composer defaults to plaintext.".to_owned()
                                                });
                                            },
                                        }
                                        strong { "Encrypt Local by default" }
                                        span { if timeline_encrypt_local_default() { "Enabled" } else { "Disabled" } }
                                    }
                                    div { class: "metric",
                                        strong { "Incident priority" }
                                        Select::<String> {
                                            "data-testid": "settings-timeline-priority-select",
                                            value: Some(timeline_incident_priority_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(value) = v {
                                                    timeline_incident_priority.set(value.clone());
                                                    state_store.write().save_private_data(
                                                        &account_did(),
                                                        TIMELINE_INCIDENT_PRIORITY_KEY,
                                                        value.clone(),
                                                    );
                                                    status.set(format!("Timeline priority set to {value}."));
                                                }
                                            },
                                            SelectOption::<String> { index: 0usize, value: "normal".to_string(), text_value: "Normal", "Normal" }
                                            SelectOption::<String> { index: 1usize, value: "sev3".to_string(), text_value: "SEV-3", "SEV-3" }
                                            SelectOption::<String> { index: 2usize, value: "sev2".to_string(), text_value: "SEV-2", "SEV-2" }
                                            SelectOption::<String> { index: 3usize, value: "sev1".to_string(), text_value: "SEV-1", "SEV-1" }
                                        }
                                    }
                                }
                            }

                            div { class: "event settings-card-span-2", "data-testid": "settings-timeline-plain-text",
                                div { class: "event-head",
                                    span { "Plaintext boundary" }
                                    span { "Configured server" }
                                }
                                div { class: "metric-grid",
                                    div { class: "metric", "data-testid": "settings-timeline-visible-service",
                                        strong { "Visible service" }
                                        span { "{timeline_visible_service}" }
                                    }
                                    div { class: "metric", "data-testid": "settings-timeline-disclosure",
                                        strong { "Disclosure" }
                                        span { "Plaintext messages may feed server-side search, previews, moderation, and notification snippets." }
                                    }
                                }
                                div { class: "actions",
                                    label {
                                        Checkbox {
                                            "data-testid": "settings-timeline-public-update-guard",
                                            checked: if timeline_public_update_guard() {
                                                CheckboxState::Checked
                                            } else {
                                                CheckboxState::Unchecked
                                            },
                                            on_checked_change: move |state: CheckboxState| {
                                                let enabled = bool::from(state);
                                                timeline_public_update_guard.set(enabled);
                                                state_store.write().save_private_data(
                                                    &account_did(),
                                                    TIMELINE_PUBLIC_UPDATE_GUARD_KEY,
                                                    enabled.to_string(),
                                                );
                                                status.set(if enabled {
                                                    "Public update guard enabled.".to_owned()
                                                } else {
                                                    "Public update guard disabled.".to_owned()
                                                });
                                            },
                                        }
                                        " Public update guard"
                                    }
                                    label {
                                        Checkbox {
                                            "data-testid": "settings-timeline-private-plaintext",
                                            checked: if timeline_private_plaintext() {
                                                CheckboxState::Checked
                                            } else {
                                                CheckboxState::Unchecked
                                            },
                                            on_checked_change: move |state: CheckboxState| {
                                                let enabled = bool::from(state);
                                                timeline_private_plaintext.set(enabled);
                                                if !enabled {
                                                    timeline_plaintext_ack.set(false);
                                                    state_store.write().save_private_data(
                                                        &account_did(),
                                                        TIMELINE_PLAINTEXT_ACK_KEY,
                                                        "false",
                                                    );
                                                }
                                                state_store.write().save_private_data(
                                                    &account_did(),
                                                    TIMELINE_PRIVATE_PLAINTEXT_KEY,
                                                    enabled.to_string(),
                                                );
                                                status.set(if enabled {
                                                    "Private plaintext guard enabled.".to_owned()
                                                } else {
                                                    "Private plaintext guard disabled.".to_owned()
                                                });
                                            },
                                        }
                                        " Treat plaintext drafts as private"
                                    }
                                    label {
                                        Checkbox {
                                            "data-testid": "settings-timeline-plaintext-ack",
                                            disabled: !timeline_private_plaintext(),
                                            checked: if timeline_plaintext_ack() {
                                                CheckboxState::Checked
                                            } else {
                                                CheckboxState::Unchecked
                                            },
                                            on_checked_change: move |state: CheckboxState| {
                                                let acknowledged = bool::from(state);
                                                timeline_plaintext_ack.set(acknowledged);
                                                state_store.write().save_private_data(
                                                    &account_did(),
                                                    TIMELINE_PLAINTEXT_ACK_KEY,
                                                    acknowledged.to_string(),
                                                );
                                                status.set(if acknowledged {
                                                    "Plaintext exposure acknowledged.".to_owned()
                                                } else {
                                                    "Plaintext exposure acknowledgement cleared.".to_owned()
                                                });
                                            },
                                        }
                                        " Acknowledge plaintext exposure"
                                    }
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
                                status.set("Theme set to light".to_owned());
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
                                status.set("Theme set to night".to_owned());
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
                                status.set("Theme set to system".to_owned());
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
                                push_client_ui_account_data(base.clone(), api_token.clone(), next.clone());
                                status.set(format!("Theme set to {next}"));
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
                                status.set("Language set to en (ltr)".to_owned());
                            },
                            "English"
                        }
                        Button {
                            variant: if active_locale == Locale::Zh { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                            "data-testid": "language-zh",
                            onclick: move |_| {
                                locale.set(Locale::Zh);
                                state_store.write().save_private_data(&account_did(), "locale", Locale::Zh.code());
                                status.set("Language set to zh (ltr)".to_owned());
                            },
                            "中文"
                        }
                        Button {
                            variant: if active_locale == Locale::Ar { ButtonVariant::Primary } else { ButtonVariant::Secondary },
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
                            // T7.1 — entry point into the Developer Tools /
                            // Diagnostics panel that hosts the protocol-level
                            // surfaces (raw event log, audit rows, schema /
                            // profile / event-kind references) which used to
                            // leak into the main flow.
                            div { class: "event settings-diagnostics-switcher", "data-testid": "settings-diagnostics-switcher",
                                div { class: "event-head",
                                    span { "Diagnostics explorer" }
                                    span { class: "badge blue", {crate::i18n::tr("developer.subtitle")} }
                                }
                                div { class: "muted", {crate::i18n::tr("developer.hint")} }
                                div { class: "actions",
                                    Button {
                                        variant: if active_diagnostics_mode == DiagnosticsMode::Developer { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                        size: ButtonSize::Sm,
                                        "data-testid": "open-developer-tools",
                                        "aria-pressed": if active_diagnostics_mode == DiagnosticsMode::Developer { "true" } else { "false" },
                                        onclick: move |_| {
                                            diagnostics_mode.set(DiagnosticsMode::Developer);
                                            let _ = navigator.push(DiagnosticsMode::Developer.route());
                                        },
                                        "Developer Tools"
                                    }
                                    Button {
                                        variant: if active_diagnostics_mode == DiagnosticsMode::Audit { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                        size: ButtonSize::Sm,
                                        "data-testid": "open-audit-from-settings",
                                        "aria-pressed": if active_diagnostics_mode == DiagnosticsMode::Audit { "true" } else { "false" },
                                        onclick: move |_| {
                                            diagnostics_mode.set(DiagnosticsMode::Audit);
                                            let _ = navigator.push(DiagnosticsMode::Audit.route());
                                        },
                                        "Audit log"
                                    }
                                }
                            }
                            if active_diagnostics_mode == DiagnosticsMode::Developer {
                                crate::views::developer::DeveloperToolsPanel { state_store }
                            }
                            if active_diagnostics_mode == DiagnosticsMode::Audit {
                                crate::views::audit::AuditPanel { state_store }
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
    use std::collections::BTreeMap;

    use super::*;

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
        assert!(!is_likely_valid_did("did:web-x:alice")); // DRIFT-ALLOW: negative test
        // Round 4 (spec a77b995) — `.`/`-`/`_`/`:` are forbidden in
        // the method segment; method MUST be lowercase ASCII alphanum.
        assert!(!is_likely_valid_did("did:web.x:alice")); // DRIFT-ALLOW: negative test
        assert!(!is_likely_valid_did("did:web_x:alice")); // DRIFT-ALLOW: negative test
        assert!(!is_likely_valid_did("did:WEB:alice"));
        // Whitespace inside method-specific id is rejected (round-4
        // regex `^did:[a-z0-9]+:[^\s]+$`).
        assert!(!is_likely_valid_did("did:web:alice example"));
        // The method-specific id may still contain `:` (the splitn(2)
        // keeps everything after the second `:`) — e.g. did:webvh nested
        // delegations.
        assert!(is_likely_valid_did("did:webvh:authority.example:zKey"));
    }

    /// The canonical `ck.read_receipt.preferences` body shape other devices
    /// read via `/sync` account_data. Locks the field names
    /// (`default_send`, `realm_overrides`, `flow_overrides`) so a future
    /// rename can't silently desync devices.
    #[test]
    fn build_read_receipt_preferences_body_has_canonical_field_shape() {
        let mut realms = BTreeMap::new();
        realms.insert("ck:realm:demo".to_owned(), false);
        let mut flows = BTreeMap::new();
        flows.insert("ck:flow:demo".to_owned(), true);
        let body = build_read_receipt_preferences_body(true, &realms, &flows);
        assert_eq!(body["default_send"], serde_json::Value::Bool(true));
        assert_eq!(body["realm_overrides"]["ck:realm:demo"], false);
        assert_eq!(body["flow_overrides"]["ck:flow:demo"], true);
        // Keys we don't expect in this body — explicit guards so a typo
        // (e.g. `default` instead of `default_send`) regression-bisects.
        assert!(body.get("default").is_none());
        assert!(body.get("read_receipt_default_send").is_none());
    }

    /// account-data key is the exact spec key — same string the SDK uses
    /// when reading the entry back from `/sync`.
    #[test]
    fn read_receipt_account_data_key_matches_spec() {
        assert_eq!(READ_RECEIPT_ACCOUNT_DATA_KEY, "ck.read_receipt.preferences");
    }

    #[test]
    fn blocklist_account_data_key_matches_spec() {
        assert_eq!(CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY, "ck.account.blocklist");
    }

    #[test]
    fn default_avatar_initial_prefers_handle_then_did() {
        assert_eq!(
            default_avatar_initial(&["alice".to_owned()], "did:web:example.test"),
            "A"
        );
        assert_eq!(default_avatar_initial(&[], "did:web:bob.example"), "B");
    }

    #[test]
    fn default_avatar_tone_is_stable_and_bounded() {
        let handles = vec!["alice".to_owned()];
        let first = default_avatar_tone(&handles, "did:web:example.test");
        let second = default_avatar_tone(&handles, "did:web:example.test");
        assert_eq!(first, second);
        assert!((1..=6).contains(&first));
    }
}
