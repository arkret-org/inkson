//! Account-data push helpers and small per-realm builders factored out of
//! the settings panel. These spawn fire-and-forget `ak.account_data.set`
//! tasks (local state stays authoritative) plus a couple of label / option
//! derivations used by the notification override picker.

use arkret_wire::AccountDataKey;
use dioxus::prelude::*;
use serde_json::json;

use super::build_read_receipt_preferences_body;
use crate::notification_rules::{WatchLevel, parse_dnd_settings};
use crate::state::{LocalStateStore, PresencePreference, PresenceVisibility};
use crate::transport::auth::with_event_submitter;
use crate::views::helpers::short_protocol_id;

pub(crate) fn encrypted_account_data_value(
    account_data_key: &str,
    plaintext: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let authority = crate::secure_key_store::active_device_seed_scope()
        .map(|scope| scope.authority)
        .ok_or_else(|| anyhow::anyhow!("active account scope is unavailable"))?;
    crate::account_data::encrypt_account_data_value(&authority, account_data_key, plaintext)
}

/// Spawn a fire-and-forget task that pushes the current read-receipt
/// preferences to soland through `ak.account_data.set`. Read latest values
/// from the local state store at call time —
/// the local state is always authoritative; the server-sync is best-effort.
pub(super) fn push_read_receipt_account_data(
    base_url: String,
    api_token: String,
    state_store: SyncSignal<LocalStateStore>,
) {
    let plaintext = build_read_receipt_preferences_body(
        state_store.read().read_receipt_default_send(),
        state_store.read().read_receipt_default_display(),
        &state_store.read().read_receipt_realm_overrides(),
        &state_store.read().read_receipt_realm_display_overrides(),
        &state_store.read().read_receipt_strand_overrides(),
        &state_store.read().read_receipt_strand_display_overrides(),
    );
    let body =
        match encrypted_account_data_value(AccountDataKey::READ_RECEIPT_PREFERENCES, &plaintext) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(%error, "ak.read_receipt.preferences encryption failed");
                return;
            }
        };
    spawn(async move {
        match with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(
                &sub,
                AccountDataKey::READ_RECEIPT_PREFERENCES,
                body,
            )
            .await
        })
        .await
        {
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    "ak.account_data.set for read-receipt prefs failed: {}",
                    err.display()
                );
            }
        }
    });
}

// SDK preference structs are plain serializable data; the `expect` documents
// that invariant rather than a reachable error path.
#[allow(clippy::expect_used)]
pub(super) fn build_presence_preference_body(preference: &PresencePreference) -> serde_json::Value {
    serde_json::to_value(preference).expect("SDK PresencePreference must serialize")
}

/// Best-effort cross-device sync of `ak.presence.preference`
/// (profiles-presence.md §3.6). Local state stays authoritative; the
/// payload goes up encrypted because servers MUST NOT read or project
/// this key (unlike the minimal `ak.presence.visibility` projection).
/// An empty preference deletes the key instead of storing an empty body.
pub(super) fn push_presence_preference_account_data(
    base_url: String,
    api_token: String,
    state_store: SyncSignal<LocalStateStore>,
) {
    if api_token.trim().is_empty() {
        return;
    }
    let preference = state_store.read().presence_preference();
    if preference.is_empty() {
        spawn(async move {
            if let Err(err) = with_event_submitter(&base_url, api_token, |sub| async move {
                crate::transport::account::delete_account_data(
                    &sub,
                    AccountDataKey::PRESENCE_PREFERENCE,
                )
                .await
            })
            .await
            {
                tracing::debug!(
                    "account_data DELETE for ak.presence.preference failed: {}; local state still authoritative",
                    err.display()
                );
            }
        });
        return;
    }
    let plaintext = build_presence_preference_body(&preference);
    let body = match encrypted_account_data_value(AccountDataKey::PRESENCE_PREFERENCE, &plaintext) {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!("ak.account_data.set for ak.presence.preference skipped: {err}");
            return;
        }
    };
    spawn(async move {
        match with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(
                &sub,
                AccountDataKey::PRESENCE_PREFERENCE,
                body,
            )
            .await
        })
        .await
        {
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    "ak.account_data.set for ak.presence.preference failed: {}",
                    err.display()
                );
            }
        }
    });
}

// SDK preference structs are plain serializable data; the `expect` documents
// that invariant rather than a reachable error path.
#[allow(clippy::expect_used)]
pub(super) fn build_presence_visibility_body(visibility: PresenceVisibility) -> serde_json::Value {
    serde_json::to_value(arkret_sdk::PresenceVisibilityPreference {
        presence_visibility: visibility,
    })
    .expect("SDK PresenceVisibilityPreference must serialize")
}

pub(super) fn push_presence_visibility_account_data(
    base_url: String,
    api_token: String,
    state_store: SyncSignal<LocalStateStore>,
) {
    let plaintext = build_presence_visibility_body(state_store.read().presence_visibility());
    let body = match encrypted_account_data_value(AccountDataKey::PRESENCE_VISIBILITY, &plaintext) {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "ak.presence.visibility encryption failed");
            return;
        }
    };
    spawn(async move {
        match with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(
                &sub,
                AccountDataKey::PRESENCE_VISIBILITY,
                body,
            )
            .await
        })
        .await
        {
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    "ak.account_data.set for ak.presence.visibility failed: {}",
                    err.display()
                );
            }
        }
    });
}

/// Project the local per-realm watch levels into a spec-conformant
/// `ak.push_rules` body (push-notifications.md §4) and sync it to soland.
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
pub(super) fn push_notification_rules_account_data(
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
        "evaluation_locus": "client",
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
                "evaluation_locus": "client",
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
                "evaluation_locus": "client",
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
                "evaluation_locus": "client",
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
        "evaluation_locus": "client",
        "conditions": [],
        "actions": ["notify"]
    }));
    let body = json!({ "rules": rules });
    let body = match encrypted_account_data_value(AccountDataKey::PUSH_RULES, &body) {
        Ok(body) => body,
        Err(err) => {
            tracing::warn!("ak.account_data.set for ak.push_rules skipped: {}", err);
            return;
        }
    };
    spawn(async move {
        match with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(&sub, AccountDataKey::PUSH_RULES, body)
                .await
        })
        .await
        {
            Ok(_) => {}
            Err(err) => {
                tracing::debug!(
                    "ak.account_data.set for ak.push_rules failed: {}",
                    err.display()
                );
            }
        }
    });
}

pub(super) fn build_dnd_account_data_body(enabled: bool, mode: &str) -> serde_json::Value {
    json!({
        "dnd": {
            "enabled": enabled,
            "schedule": {
                "timezone": "Etc/UTC",
                "tzdb_version": crate::notification_rules::DND_TZDB_VERSION,
                "all_day": enabled && mode == "now",
                "periods": []
            },
            "exceptions": ["override.priority"]
        }
    })
}

pub(super) fn push_dnd_account_data(
    base_url: String,
    api_token: String,
    authority: arkret_sdk::AccountId,
    actor_id: String,
    device_id: String,
    enabled: bool,
    mode: String,
    mut state_store: SyncSignal<LocalStateStore>,
    backup_trigger_signal: Option<Signal<bool>>,
    mut notification_settings_status: Signal<String>,
) {
    let plaintext_body = build_dnd_account_data_body(enabled, &mode);
    let parsed_settings = match parse_dnd_settings(&plaintext_body) {
        Ok(settings) => settings,
        Err(rejection) => {
            notification_settings_status
                .set(format!("DND save failed validation: {}", rejection.reason));
            return;
        }
    };
    state_store
        .write()
        .set_notification_dnd_settings(Some(parsed_settings));
    if api_token.trim().is_empty() {
        notification_settings_status.set("DND settings saved locally; sign in to sync.".to_owned());
        return;
    }
    let body = match encrypted_account_data_value(AccountDataKey::DND_SCHEDULE, &plaintext_body) {
        Ok(body) => body,
        Err(err) => {
            notification_settings_status.set(format!("DND save failed: {err}"));
            return;
        }
    };
    spawn(async move {
        match with_event_submitter(&base_url, api_token.clone(), |sub| async move {
            crate::transport::account::set_account_data(&sub, AccountDataKey::DND_SCHEDULE, body)
                .await
        })
        .await
        {
            Ok(_) => {
                if let Some(signal) = backup_trigger_signal {
                    crate::components::maybe_auto_backup_mls_after_encrypted_write(
                        base_url,
                        api_token,
                        authority,
                        actor_id,
                        device_id,
                        crate::app::runtime_adapter::state_store_handle(state_store),
                        signal,
                    )
                    .await;
                }
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

pub(super) fn push_realm_remark_account_data_impl(
    base_url: String,
    api_token: String,
    realm_id: String,
    remark: crate::account_data::RealmRemark,
    notify_failure: bool,
) {
    let key = crate::account_data::realm_remark_account_data_key(&realm_id);
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
                if notify_failure {
                    crate::components::feedback::toast_error(
                        "realm.pin_failed",
                        vec![],
                        Some(err.display()),
                    );
                }
            }
            return;
        }
        let body = match encrypted_account_data_value(
            &key,
            &serde_json::to_value(&remark).unwrap_or_default(),
        ) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(key = %key, %error, "Realm remark encryption failed");
                if notify_failure {
                    crate::components::feedback::toast_error(
                        "realm.pin_failed",
                        vec![],
                        Some(error.to_string()),
                    );
                }
                return;
            }
        };
        let key_for_request = key.clone();
        if let Err(error) = with_event_submitter(&base_url, api_token, |sub| async move {
            crate::transport::account::set_account_data(&sub, &key_for_request, body).await
        })
        .await
        {
            tracing::warn!(key = %key, error = %error.display(), "Realm remark account_data upload failed");
            if notify_failure {
                crate::components::feedback::toast_error(
                    "realm.pin_failed",
                    vec![],
                    Some(error.display()),
                );
            }
        }
    });
}

/// Human-readable label for a watch level, used by the per-realm override
/// picker. Spec values: push-notifications.md §4.3.2.
pub(super) fn watch_level_label(level: WatchLevel) -> &'static str {
    match level {
        WatchLevel::All => "All messages",
        WatchLevel::Participating => "Participating",
        WatchLevel::MentionsOnly => "Mentions only",
        WatchLevel::Muted => "Muted",
    }
}

/// Realms the user can pick a per-realm override for. Derived from the SAME
/// source the sidebar renders — `realm_tree_nodes_from_sync_realms` over the
/// cached realm-tree projections — so the picker always matches the Realms the
/// user actually sees. Spaces are folded onto their home Realm; any Realm that
/// already has an override is kept even if its projection isn't cached yet.
/// Each entry is `(realm_id, friendly_label)`, label resolved through the local
/// remark (falling back to the public title, then the short id). Sorted by
/// realm id (BTreeMap) for a stable picker order.
pub(super) fn known_realm_options(store: &LocalStateStore) -> Vec<(String, String)> {
    let state = store.load();
    let mut titles: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for node in crate::realm_tree::realm_tree_nodes_from_sync_realms_with_roles(
        &state.realm_tree_projections,
        &state.realm_collaboration_roles,
    ) {
        if node.kind == crate::models::RealmTreeNodeKind::Realm && !node.realm_id.is_empty() {
            titles.entry(node.realm_id).or_insert(node.title);
        }
    }
    // Keep Realms that already carry an override pickable even if their tree
    // projection hasn't synced into the cache yet.
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
