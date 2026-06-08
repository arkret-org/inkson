//! Background account subscribe sync loop.
//!
//! Background engine that keeps the local store + UI signals continuously
//! aligned with `/_cokret/self/account/subscribe` instead of refreshing only on
//! app boot, the Refresh button, or a server switch.
//!
//! Design contract (matches the "正经做法" laid out in the design
//! discussion):
//!
//! * **Cursor lives in `LocalStateStore.sync_cursor`** — the engine reads it on every iteration and
//!   writes back the new `cursor` after each successful response. Reload of the tab resumes from
//!   the persisted cursor without losing position.
//! * **First iteration is initial account sync** when no cursor is stored (or it's the `"-"`
//!   sentinel). Subsequent iterations resume with `after=<cursor>&catchup=true`.
//! * **Server-authoritative reconcile**: on a full sync the response is the truth for top-level
//!   Realm membership. Nested container Spaces may not appear as top-level `response.realms`
//!   entries, so locally projected Spaces are retained while their home Realm remains in the
//!   full-sync response. On incremental, soland's `left_realms` field is the prune signal.
//! * **Lifecycle via generation counter**: callers (login / logout / server-switch) bump the
//!   engine's `generation` Signal; the loop notices on the next iteration and exits cleanly. A
//!   fresh engine spawn picks up the next generation.
//! * **Backoff**: transient network errors double the sleep (capped at `MAX_BACKOFF_SECS`); a
//!   successful response resets it. Auth-expired errors stop the engine and let the refresh poller
//!   + login flow take over. Cursor-invalid errors clear the cursor and immediately retry as a full
//!     sync.
//!
//! The engine deliberately does NOT trigger session refresh inline —
//! that's owned by [`crate::session_refresh`] which runs in parallel.
//! When an iteration hits `is_auth_expired_error` the engine just exits;
//! the refresh poller mints a new bearer, the lifecycle bumps the
//! generation, and a new engine spawn picks up. This keeps refresh
//! logic in one place.

use std::collections::BTreeSet;
use std::time::Duration;

use dioxus::prelude::*;
use serde_json::Value;

use crate::api::{
    AccountSubscribeSnapshotOutcome, CokretApi, is_auth_expired_error, is_invalid_cursor_error,
    is_terminal_session_grant_error, rate_limited_retry_after, sleep_for,
};
use crate::config::MultiProfileConfig;
use crate::local_state::{LocalAnchorView, LocalStateStore};
use crate::models::{ClientSyncOutcome, RealmTreeNode, RealmTreeNodeKind};

/// Sleep ceiling between failed iterations. 60s matches what other
/// Long enough that a wedged server doesn't get DoSed by retries,
/// short enough that recovery is noticeable to the user.
const MAX_BACKOFF_SECS: u64 = 60;

/// Floor for the first backoff sleep. Doubles up to `MAX_BACKOFF_SECS`.
const MIN_BACKOFF_SECS: u64 = 1;

/// Minimum pause between successful iterations. Insurance against
/// servers that return account subscribe catch-up immediately; without
/// this, an `Ok -> loop -> Ok -> loop` cycle spins at network RTT and
/// floods the browser network panel with identical snapshots.
///
/// Yougen currently folds each NDJSON response with `Response::bytes()`,
/// so it cannot yet keep the spec's long-lived account stream open. Keep
/// the fallback poll interval human-scale until the client switches to a
/// true frame reader.
const MIN_INTER_ITERATION_MS: u64 = 5_000;

/// Bundle of signals + state-store the engine needs to apply a response.
/// `Copy` because Dioxus signals already are; the struct is just a
/// typed shorthand around them.
#[derive(Clone, Copy)]
pub struct SyncEngineContext {
    pub base_url: Signal<String>,
    pub token: Signal<String>,
    pub state_store: Signal<LocalStateStore>,
    pub realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    pub timeline: Signal<Vec<crate::views::timeline::TimelineEvent>>,
    pub sync_cursor: Signal<String>,
    pub status: Signal<String>,
    pub network_state: Signal<String>,
    pub last_error: Signal<Option<String>>,
    pub device_queue: Signal<usize>,
    pub theme: Signal<String>,
    pub account_did: Signal<String>,
    pub selected_realm_id: Signal<String>,
    /// CKP-0007 P3B.4.3 — the active multi-profile configuration. The
    /// engine reads `active_profile_id` at the top of every iteration
    /// and exits early when it differs from the profile id captured
    /// at spawn time; the lifecycle bumps `generation` so the next
    /// engine spawn picks up the new profile's cursor / token /
    /// account_did atomically. This avoids the previous race where
    /// the engine kept syncing under the prior profile while the UI
    /// already rendered the new one.
    pub profiles: Signal<MultiProfileConfig>,
}

/// Outcome of one sync iteration — used by the loop to decide whether to
/// backoff, demote, or stop.
#[derive(Debug)]
enum IterationOutcome {
    /// Response applied successfully — reset backoff, immediately
    /// re-enter the loop.
    Ok,
    /// Cursor was rejected. Clear the persisted cursor and re-enter the
    /// loop as a full sync.
    InvalidCursor,
    /// Auth expired or server otherwise told us the session is dead.
    /// Engine exits; refresh poller + login flow take over.
    AuthExpired,
    /// Transient network / 5xx error. Backoff and retry.
    Transient(String),
    /// Server explicitly said "slow down" (HTTP 429 / `rate_limited`).
    /// Sleep for the server-advertised `retry_after_ms` (0 ⇒ default
    /// floor) before the next iteration instead of the generic
    /// exponential backoff. Avoids spamming on top of a rate-limited
    /// server.
    RateLimited { retry_after_ms: u64, reason: String },
    /// Subscribe control frame advertised a minimum reconnect delay for
    /// this scope. This is not an HTTP error; the stream closed cleanly.
    ReconnectAfter {
        reconnect_after_ms: u64,
        reason: Option<String>,
    },
    /// Configuration is incomplete (empty base URL or token). Engine
    /// exits — caller will respawn when the missing piece arrives.
    NotReady,
}

/// Main entry point. Spawn this once per "session generation" — see the
/// module-level doc for what bumps the generation.
///
/// The engine returns when the generation moves past `start_generation`
/// (signal that a new engine should be spawned with the next number) or
/// when an unrecoverable error fires (auth-expired, missing config).
pub async fn run_sync_engine(
    start_generation: u64,
    generation: Signal<u64>,
    ctx: SyncEngineContext,
) {
    // Snapshot the active profile id at spawn time. If the UI rotates
    // profiles mid-loop, the engine exits cleanly and a fresh spawn
    // picks up the new profile's cursor / token / account_did.
    let start_profile_id = ctx.profiles.read().active_profile_id.clone();
    let mut backoff_secs = MIN_BACKOFF_SECS;
    loop {
        // Cancellation check at the top of every iteration. A change to
        // `generation` mid-iteration is best-effort detected here; the
        // network call below can't be cancelled in flight without
        // platform-specific abort machinery, so a stale response from
        // the previous generation may still arrive — `apply_response`
        // re-checks generation before touching signals.
        if generation() != start_generation {
            return;
        }
        // Profile rotation guard. The shell bumps `generation`
        // separately, but a generation bump can lag the active profile
        // signal by a tick; comparing the snapshot here keeps the
        // engine from emitting a stale request under the new profile.
        if ctx.profiles.read().active_profile_id != start_profile_id {
            return;
        }

        match run_iteration(start_generation, generation, &ctx).await {
            IterationOutcome::Ok => {
                backoff_secs = MIN_BACKOFF_SECS;
                // Recovery: clear any stale error the user has been
                // staring at. Without this, a single Transient or
                // RateLimited blip sticks in the status bar forever
                // because apply_response doesn't touch last_error.
                ctx.last_error.clone().set(None);
                // Server-side long-poll absorbs the idle wait on a
                // spec-compliant server; if the server returns
                // immediately (older soland), MIN_INTER_ITERATION_MS
                // keeps the loop from spinning at network RTT.
                sleep_for(Duration::from_millis(MIN_INTER_ITERATION_MS)).await;
            }
            IterationOutcome::InvalidCursor => {
                // Demote to full sync next iteration. The persisted
                // cursor was already cleared inside the iteration.
                // Also clear the visible error so the UI doesn't
                // show the cursor-rejection that just got handled.
                backoff_secs = MIN_BACKOFF_SECS;
                ctx.last_error.clone().set(None);
                sleep_for(Duration::from_millis(MIN_INTER_ITERATION_MS)).await;
            }
            IterationOutcome::AuthExpired => {
                // Hand off to the refresh poller / login flow. The
                // lifecycle code will bump generation and respawn us.
                return;
            }
            IterationOutcome::NotReady => {
                // Nothing to do until base_url / token are populated.
                // Caller's `use_effect` will respawn when they are.
                return;
            }
            IterationOutcome::RateLimited {
                retry_after_ms,
                reason,
            } => {
                {
                    let mut last_error = ctx.last_error;
                    last_error.set(Some(reason));
                }
                // Honour the server's hint with a floor of
                // `MIN_BACKOFF_SECS` so a buggy server that returns
                // `retry_after_ms = 0` still gives us a beat.
                let wait_ms = retry_after_ms.max(MIN_BACKOFF_SECS.saturating_mul(1000));
                sleep_for(Duration::from_millis(wait_ms)).await;
                // Don't escalate `backoff_secs` — the server told us
                // exactly how long to wait, so the next iteration
                // restarts the generic backoff ladder from the floor.
                backoff_secs = MIN_BACKOFF_SECS;
            }
            IterationOutcome::ReconnectAfter {
                reconnect_after_ms,
                reason,
            } => {
                {
                    let mut last_error = ctx.last_error;
                    last_error.set(reason.map(|reason| format!("sync_engine: {reason}")));
                }
                let wait_ms = reconnect_after_ms.max(MIN_BACKOFF_SECS.saturating_mul(1000));
                sleep_for(Duration::from_millis(wait_ms)).await;
                backoff_secs = MIN_BACKOFF_SECS;
            }
            IterationOutcome::Transient(reason) => {
                {
                    let mut last_error = ctx.last_error;
                    last_error.set(Some(reason));
                }
                sleep_for(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs.saturating_mul(2)).min(MAX_BACKOFF_SECS);
            }
        }
    }
}

async fn run_iteration(
    start_generation: u64,
    generation: Signal<u64>,
    ctx: &SyncEngineContext,
) -> IterationOutcome {
    let base = ctx.base_url.read().clone();
    let token = ctx.token.read().clone();
    if base.trim().is_empty() || token.trim().is_empty() {
        return IterationOutcome::NotReady;
    }
    let api = match CokretApi::new(&base) {
        Ok(api) => api.with_bearer(token),
        Err(error) => {
            return IterationOutcome::Transient(format!("sync_engine: invalid base URL: {error}"));
        }
    };

    // Read cursor freshly each iteration — login flow / server switch
    // may have cleared it underneath us.
    let cursor = ctx
        .state_store
        .read()
        .load()
        .sync_cursor
        .clone()
        .filter(|c| !c.trim().is_empty() && c != "-");
    let is_full_sync = cursor.is_none();

    match api
        .account_subscribe_snapshot_outcome(cursor.as_deref())
        .await
    {
        Ok(AccountSubscribeSnapshotOutcome::Delta(response)) => {
            // Late-arriving response from a stale generation must not
            // overwrite signals owned by the new generation. The
            // state_store write below is still safe because it's keyed
            // by content, but the UI signals are not.
            if generation() != start_generation {
                return IterationOutcome::Ok;
            }
            let invite_notifications = match api.invites().await {
                Ok(response) => Some(response.invites),
                Err(error) if is_auth_expired_error(&error) => {
                    return IterationOutcome::AuthExpired;
                }
                Err(error) => {
                    tracing::debug!(?error, "sync engine could not refresh invite notifications");
                    None
                }
            };
            apply_response(&response, is_full_sync, ctx, invite_notifications);
            IterationOutcome::Ok
        }
        Ok(AccountSubscribeSnapshotOutcome::ReconnectAfter {
            reconnect_after_ms,
            reason,
            reset_cursor,
        }) => {
            if reset_cursor {
                let mut state_store = ctx.state_store;
                let mut sync_cursor = ctx.sync_cursor;
                state_store.write().save_sync_cursor("-");
                sync_cursor.set("-".to_owned());
            }
            IterationOutcome::ReconnectAfter {
                reconnect_after_ms,
                reason,
            }
        }
        Err(error) if is_terminal_session_grant_error(&error) => {
            crate::session::invalidate_current_session("session grant is no longer active");
            IterationOutcome::AuthExpired
        }
        Err(error) if is_auth_expired_error(&error) => IterationOutcome::AuthExpired,
        Err(error) if let Some(retry_after_ms) = rate_limited_retry_after(&error) => {
            IterationOutcome::RateLimited {
                retry_after_ms,
                reason: format!("sync_engine: {error}"),
            }
        }
        Err(error) if is_invalid_cursor_error(&error) => {
            let _ = error;
            // Signals are Copy — take local mutable handles so the
            // outer `&SyncEngineContext` doesn't need to be &mut.
            let mut state_store = ctx.state_store;
            let mut sync_cursor = ctx.sync_cursor;
            state_store.write().save_sync_cursor("-");
            sync_cursor.set("-".to_owned());
            IterationOutcome::InvalidCursor
        }
        Err(error) => IterationOutcome::Transient(format!("sync_engine: {error}")),
    }
}

/// Apply an account subscribe response: persist projections (server-authoritatively
/// reconciled when full-sync), hydrate Anchor views + account-data, and
/// publish derived UI signals (realm tree nodes / timeline / device queue /
/// status / cursor).
///
/// Exposed at module scope so tests can drive it without spinning up
/// the loop. `connect()` in `app.rs` shares the same code path — once
/// the engine fully owns sync, `connect()` is just a "force one
/// iteration now" entry that calls this.
pub fn apply_response(
    response: &ClientSyncOutcome,
    is_full_sync: bool,
    ctx: &SyncEngineContext,
    invite_notifications: Option<Vec<Value>>,
) {
    // Local mutable handles for the signals we touch — Signal<T> is
    // Copy so this is cheap.
    let mut state_store = ctx.state_store;
    let realm_tree_nodes = ctx.realm_tree_nodes;
    let mut timeline = ctx.timeline;
    let mut sync_cursor = ctx.sync_cursor;
    let mut status = ctx.status;
    let mut network_state = ctx.network_state;
    let mut last_error = ctx.last_error;
    let mut device_queue = ctx.device_queue;
    let mut theme = ctx.theme;
    let mut selected_realm_id = ctx.selected_realm_id;
    let account_did = ctx.account_did.read().clone();

    {
        let mut store = state_store.write();
        // Perf (P0): a single sync response can touch the cursor, dozens of
        // realm-tree projections, anchor views, member identity events and account
        // data — each setter used to flush the *entire* `ClientLocalState` to
        // disk/localStorage. Wrap the whole apply in one batch so it persists
        // exactly once.
        store.batch(|store| {
            store.save_sync_cursor(response.cursor.clone());

            if is_full_sync {
                // Server-authoritative for top-level Realm membership:
                // drop projections the server didn't include, except local
                // Space-container projections whose home Realm is still
                // present. Containers are not guaranteed to arrive as
                // top-level sync entries.
                let server_set: BTreeSet<String> = response.realms.keys().cloned().collect();
                let keep_set = crate::app::full_sync_projection_keep_set(
                    &server_set,
                    &store.load().realm_tree_projections,
                );
                let pruned = store.retain_realm_tree_projections(|id| keep_set.contains(id));
                if !pruned.is_empty() {
                    tracing::info!(
                        pruned_count = pruned.len(),
                        "sync engine: full-sync pruned stale realm-tree projections",
                    );
                }
            }
            // Explicit `left_realms` deltas — meaningful primarily on
            // incremental sync, but cheap to apply on full sync too.
            for left_id in &response.left_realms {
                store.forget_realm_tree_projection(left_id);
            }
            for (id, body) in &response.realms {
                store.save_realm_tree_projection(id.clone(), body.clone());
                let view = LocalAnchorView::from_sync_body(body);
                store.set_realm_anchor_view(id.clone(), view);
                store.ingest_move_event_states(id, body);
                // R3.1 MID-2 — harvest inlined `ck.member.identity.update`
                // event envelopes off the `members[]` roster entries. The
                // SDK's effective-set filter is applied lazily when a UI
                // surface needs to resolve a display identity.
                ingest_member_identity_events_from_projection(store, id, body);
            }

            apply_account_data(store, response, &account_did, &mut theme, &mut last_error);
            apply_notification_projection(store, response, invite_notifications);
            store.save_presence_projection(response.presence.clone());
        }); // store.batch — single coalesced flush happens here
    }

    // The `realm_tree_nodes` Signal is derived from `state_store.realm_tree_projections`
    // via a use_effect in `RouterView` — we don't `set` it here. We do
    // still need a reconciled snapshot for status text + selected_realm_id
    // bookkeeping.
    let _ = realm_tree_nodes; // suppress unused capture; consumed by the derive effect
    let reconciled = crate::app::realm_tree_nodes_from_sync_realms(
        &state_store.read().load().realm_tree_projections,
    );
    if reconciled.is_empty() {
        status.set(crate::views::ConnectionState::Empty.label().to_owned());
    } else {
        status.set(format!(
            "{}: synced {} realm-tree node(s)",
            crate::views::ConnectionState::Online.label(),
            reconciled.len()
        ));
    }
    network_state.set("online".to_owned());
    let first_realm = reconciled
        .iter()
        .find(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| node.id.clone());
    {
        let current = selected_realm_id.read().clone();
        let trimmed = current.trim();
        let needs_reset = trimmed.is_empty() || !reconciled.iter().any(|node| node.id == trimmed);
        if needs_reset {
            selected_realm_id.set(first_realm.unwrap_or_default());
        }
    }

    let synced_timeline = crate::app::timeline_events_from_sync_realms(&response.realms);
    let next_timeline = if is_full_sync {
        synced_timeline
    } else {
        crate::app::merge_timeline_events(&timeline.read(), synced_timeline)
    };
    timeline.set(next_timeline);

    device_queue.set(response.to_device.len());
    sync_cursor.set(response.cursor.clone());
}

/// R3.1 MID-2 — walk a Realm projection's `members[]` roster looking
/// for inlined `identity_events[]` arrays. Each
/// `ck.member.identity.update` envelope is recorded on the
/// `LocalStateStore` keyed by `(realm_id, actor_id)`. Also handles the
/// `state.events[]` form where the roster only carries
/// `identity_event_ids[]` and the events themselves live in the
/// frame-level event log.
fn ingest_member_identity_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) {
    // Build a quick lookup over any `state.events[]` array on the
    // projection so that referenced identity_event_ids can be resolved
    // without a separate query.
    let state_events: BTreeSet<String> = body
        .get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|event| {
                    event
                        .get("event_id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default();
    let state_event_by_id: std::collections::BTreeMap<String, Value> = body
        .get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|event| {
                    event
                        .get("event_id")
                        .and_then(Value::as_str)
                        .map(|id| (id.to_owned(), event.clone()))
                })
                .collect()
        })
        .unwrap_or_default();

    for source in [
        body.get("members"),
        body.get("summary").and_then(|s| s.get("members")),
    ]
    .into_iter()
    .flatten()
    {
        let Some(items) = source.as_array() else {
            continue;
        };
        for entry in items {
            let Some(map) = entry.as_object() else {
                continue;
            };
            let Some(actor_id) = map
                .get("actor_id")
                .or_else(|| map.get("did"))
                .and_then(Value::as_str)
            else {
                continue;
            };
            // Inline events have priority — they're complete envelopes.
            if let Some(events) = map.get("identity_events").and_then(Value::as_array) {
                store.ingest_member_identity_events(realm_id, actor_id, events);
            }
            // Otherwise hydrate envelopes from `state.events[]` keyed
            // by id. Missing references are dropped silently — the
            // server will resend them on the next subscribe frame, or
            // a `ck.self.events.query` backfill will catch up.
            if let Some(refs) = map.get("identity_event_ids").and_then(Value::as_array) {
                let mut resolved: Vec<Value> = Vec::new();
                for r in refs {
                    if let Some(id) = r.as_str()
                        && state_events.contains(id)
                        && let Some(envelope) = state_event_by_id.get(id)
                    {
                        resolved.push(envelope.clone());
                    }
                }
                if !resolved.is_empty() {
                    store.ingest_member_identity_events(realm_id, actor_id, &resolved);
                }
            }
        }
    }
}

fn apply_notification_projection(
    store: &mut LocalStateStore,
    response: &ClientSyncOutcome,
    invite_notifications: Option<Vec<Value>>,
) {
    let projection_from_sync =
        crate::views::notifications::notification_items_from_value(&response.notifications);
    let account_notification_projection = response
        .account_data
        .iter()
        .filter(|entry| crate::views::notifications::is_notification_account_data(entry))
        .cloned()
        .collect::<Vec<_>>();
    let should_save_notification_projection = projection_from_sync.is_some()
        || !account_notification_projection.is_empty()
        || invite_notifications.is_some();
    let mut notification_projection = projection_from_sync.unwrap_or_else(|| {
        if account_notification_projection.is_empty() {
            store.notification_projection()
        } else {
            account_notification_projection
        }
    });
    if let Some(invites) = invite_notifications {
        let joined_realms = response.realms.keys().cloned().collect::<BTreeSet<_>>();
        crate::views::notifications::merge_invite_notifications(
            &mut notification_projection,
            invites,
            &joined_realms,
        );
    }
    if should_save_notification_projection {
        store.save_notification_projection(notification_projection);
    }
}

fn apply_account_data(
    store: &mut LocalStateStore,
    response: &ClientSyncOutcome,
    account_did: &str,
    theme: &mut Signal<String>,
    last_error: &mut Signal<Option<String>>,
) {
    let _ = last_error; // reserved for future malformed-payload reports
    for entry in &response.account_data {
        let Some(data_type) = entry.get("data_type").and_then(Value::as_str) else {
            continue;
        };
        // client.ui — theme + avatar pointer.
        if data_type == "client.ui" {
            if let Some(content) = entry.get("content") {
                let local_theme = theme.read().clone();
                if let Some(remote_theme) =
                    crate::account_data::merge_client_ui_theme(&local_theme, content)
                {
                    theme.set(remote_theme.clone());
                    store.save_private_data(account_did, "theme", remote_theme);
                }
                if let Some(avatar_blob_ref) =
                    crate::account_data::avatar_blob_ref_from_client_ui(content)
                {
                    store.save_private_data(account_did, "avatar_blob_ref", avatar_blob_ref);
                } else if crate::account_data::avatar_blob_ref_tombstoned_from_client_ui(content) {
                    store.save_private_data(account_did, "avatar_blob_ref", "");
                }
            }
            continue;
        }
        // ck.account.blocklist — personal block list.
        if data_type == "ck.account.blocklist" {
            let Some(content) = entry.get("content") else {
                continue;
            };
            match crate::account_data::blocklist_entries_from_account_data(content) {
                Ok(entries) => store.set_client_blocklist(entries),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed ck.account.blocklist account_data: {error}",
                    );
                }
            }
            continue;
        }
        // ck.contacts.actor.<did> — actor-private contact remarks.
        if let Some(actor_did) = crate::account_data::actor_did_from_contact_remark_key(data_type) {
            let Some(content) = entry.get("content") else {
                continue;
            };
            match serde_json::from_value::<crate::account_data::ContactRemark>(content.clone()) {
                Ok(remark) => store.set_contact_remark(actor_did.to_owned(), remark),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed Contact remark for {actor_did}: {error}",
                    );
                }
            }
            continue;
        }
        // ck.contacts.realm.<realm_id> — actor-private Realm remarks.
        let Some(realm_id) = crate::account_data::realm_id_from_realm_remark_key(data_type) else {
            continue;
        };
        let Some(content) = entry.get("content") else {
            continue;
        };
        match serde_json::from_value::<crate::account_data::RealmRemark>(content.clone()) {
            Ok(remark) => store.set_realm_remark(realm_id.to_owned(), remark),
            Err(error) => {
                tracing::warn!(
                    "sync engine: ignoring malformed Realm remark for {realm_id}: {error}",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn empty_response(cursor: &str) -> ClientSyncOutcome {
        ClientSyncOutcome {
            cursor: cursor.to_owned(),
            realms: Default::default(),
            left_realms: Vec::new(),
            to_device: Vec::new(),
            account_data: Vec::new(),
            device_lists: json!({}),
            presence: Vec::new(),
            notifications: serde_json::Value::Null,
            partial: false,
        }
    }

    fn temp_store(tag: &str) -> LocalStateStore {
        let path = std::env::temp_dir().join(format!(
            "yougen-engine-{tag}-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        LocalStateStore::with_path(path)
    }

    #[test]
    fn notification_projection_merges_pending_invites_from_authz() {
        let mut store = temp_store("invite-notifications");
        store.save_notification_projection(vec![json!({
            "notification_id": "message-1",
            "notification_kind": "message",
            "realm_id": "ck:realm:existing",
            "timestamp": "2026-06-01T00:00:00Z"
        })]);
        let response = empty_response("sx:invite");

        apply_notification_projection(
            &mut store,
            &response,
            Some(vec![json!({
                "invite_id": "ck:invite:0196419b-0000-7000-8000-000000000010",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000011",
                "created_at": "2026-06-01T00:00:01Z"
            })]),
        );

        let projection = store.notification_projection();
        assert!(projection.iter().any(|entry| {
            entry.get("notification_id").and_then(Value::as_str) == Some("message-1")
        }));
        assert!(projection.iter().any(|entry| {
            entry.get("notification_id").and_then(Value::as_str)
                == Some("invite:ck:realm:0196419b-0000-7000-8000-000000000011")
        }));
    }

    #[test]
    fn full_sync_response_prunes_cached_projection() {
        // Bench against the store directly — we don't need the dioxus
        // signals to verify the reconcile semantics. The signal-side
        // wiring is exercised by the lib's integration tests; the unit
        // contract here is "after a full sync, server-reported ids
        // remain, plus nested Space containers under still-joined
        // Realms".
        let mut store = temp_store("prune");
        store.save_realm_tree_projection("ck:realm:a", json!({"summary": {"title": "A"}}));
        store.save_realm_tree_projection(
            "ck:space:child",
            json!({
                "__kind": "space",
                "realm_id": "ck:realm:a",
                "summary": {"title": "Child"}
            }),
        );
        store.save_realm_tree_projection("ck:space:b", json!({"summary": {"title": "B"}}));
        store.save_draft("ck:space:b", "draft-b");

        let mut response = empty_response("sx:42");
        response
            .realms
            .insert("ck:realm:a".to_owned(), json!({"summary": {"title": "A"}}));

        // Mirror the engine's full-sync prune step.
        let server_set: BTreeSet<String> = response.realms.keys().cloned().collect();
        let keep_set = crate::app::full_sync_projection_keep_set(
            &server_set,
            &store.load().realm_tree_projections,
        );
        let pruned = store.retain_realm_tree_projections(|id| keep_set.contains(id));
        assert_eq!(pruned, vec!["ck:space:b".to_owned()]);

        let state = store.load();
        assert!(state.realm_tree_projections.contains_key("ck:realm:a"));
        assert!(state.realm_tree_projections.contains_key("ck:space:child"));
        assert!(!state.realm_tree_projections.contains_key("ck:space:b"));
        assert!(!state.drafts.contains_key("ck:space:b"));
    }

    #[test]
    fn incremental_response_forgets_left_realms() {
        let mut store = temp_store("left");
        store.save_realm_tree_projection("ck:space:a", json!({"name": "A"}));
        store.save_realm_tree_projection("ck:space:b", json!({"name": "B"}));
        store.save_draft("ck:space:b", "draft-b");

        let mut response = empty_response("sx:43");
        response.left_realms = vec!["ck:realm:b".to_owned()];

        // Mirror the engine's left_realms step.
        for id in &response.left_realms {
            store.forget_realm_tree_projection(id);
        }

        let state = store.load();
        assert!(state.realm_tree_projections.contains_key("ck:space:a"));
        assert!(!state.realm_tree_projections.contains_key("ck:space:b"));
        assert!(!state.drafts.contains_key("ck:space:b"));
    }
}
