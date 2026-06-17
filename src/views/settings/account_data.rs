//! Account-data push helpers and small per-realm builders factored out of
//! the settings panel. These spawn fire-and-forget `ck.account_data.set`
//! tasks (local state stays authoritative) plus a couple of label / option
//! derivations used by the notification override picker.

use dioxus::prelude::*;
use serde_json::json;

use super::{
    DND_ACCOUNT_DATA_KEY, PUSH_RULES_ACCOUNT_DATA_KEY, READ_RECEIPT_ACCOUNT_DATA_KEY,
    build_read_receipt_preferences_body,
};
use crate::local_state::LocalStateStore;
use crate::models::AccountDataSetResult;
use crate::notification_rules::WatchLevel;
use crate::views::helpers::{short_protocol_id, with_authed_api};

pub(super) fn format_settings_handle_list(handles: &[String], fallback: &str) -> String {
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

/// Spawn a fire-and-forget task that pushes the current read-receipt
/// preferences to soland through `ck.account_data.set`. Read latest values
/// from the local state store at call time —
/// the local state is always authoritative; the server-sync is best-effort.
/// Swallows 404/501/405 via [`AccountDataSetResult::Unsupported`] so older
/// soland deployments don't surface as user-visible errors.
pub(super) fn push_read_receipt_account_data(
    base_url: String,
    api_token: String,
    state_store: Signal<LocalStateStore>,
) {
    let body = build_read_receipt_preferences_body(
        state_store.read().read_receipt_default_send(),
        &state_store.read().read_receipt_realm_overrides(),
        &state_store.read().read_receipt_strand_overrides(),
    );
    spawn(async move {
        match with_authed_api(&base_url, api_token, |api| async move {
            api.set_account_data(READ_RECEIPT_ACCOUNT_DATA_KEY, body)
                .await
        })
        .await
        {
            Ok(AccountDataSetResult::Stored { .. }) => {}
            Ok(AccountDataSetResult::Unsupported { status }) => {
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
            Ok(AccountDataSetResult::Stored { .. }) => {}
            Ok(AccountDataSetResult::Unsupported { status }) => {
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

pub(super) fn build_dnd_account_data_body(enabled: bool, mode: &str) -> serde_json::Value {
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

pub(super) fn push_dnd_account_data(
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
            Ok(AccountDataSetResult::Stored { .. })
            | Ok(AccountDataSetResult::Unsupported { .. }) => {
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
            Ok(crate::models::AccountDataSetResult::Stored { .. }) => {}
            Ok(crate::models::AccountDataSetResult::Unsupported { status }) => {
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
    for node in crate::realm_tree::realm_tree_nodes_from_sync_realms(&state.realm_tree_projections)
    {
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
