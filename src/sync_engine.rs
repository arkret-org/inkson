//! Background long-poll sync loop.
//!
//! Replaces the historical one-shot `auto_refresh_pending` block in
//! `app.rs` with a streaming-style engine that keeps the local store +
//! UI signals continuously aligned with `/api/v1/sync` instead of
//! refreshing only on app boot, the Refresh button, or a server switch.
//!
//! Design contract (matches the "正经做法" laid out in the design
//! discussion):
//!
//! * **Cursor lives in `LocalStateStore.sync_cursor`** — the engine
//!   reads it on every iteration and writes back the new
//!   `next_batch` after each successful response. Reload of the tab
//!   resumes from the persisted cursor without losing position.
//! * **First iteration is full sync** when no cursor is stored (or it's
//!   the `"-"` sentinel). Subsequent iterations are long-poll
//!   incremental with `timeout_ms = LONG_POLL_TIMEOUT_MS`.
//! * **Server-authoritative reconcile**: on a full sync the response is
//!   the truth — any cached projection not in `response.spaces` gets
//!   pruned via `LocalStateStore::retain_space_projections`. On
//!   incremental, soland's `left_spaces` field is the prune signal.
//! * **Lifecycle via generation counter**: callers (login / logout /
//!   server-switch) bump the engine's `generation` Signal; the loop
//!   notices on the next iteration and exits cleanly. A fresh engine
//!   spawn picks up the next generation.
//! * **Backoff**: transient network errors double the sleep
//!   (capped at `MAX_BACKOFF_SECS`); a successful response resets it.
//!   Auth-expired errors stop the engine and let the refresh poller +
//!   login flow take over. Cursor-invalid errors clear the cursor and
//!   immediately retry as a full sync.
//!
//! The engine deliberately does NOT trigger session refresh inline —
//! that's owned by [`crate::session_refresh`] which runs in parallel.
//! When an iteration hits `is_auth_expired_error` the engine just exits;
//! the refresh poller mints a new bearer, the lifecycle bumps the
//! generation, and a new engine spawn picks up. This keeps refresh
//! logic in one place.

use std::collections::BTreeSet;
use std::time::Duration;

use contrix_sdk::EncryptedPayload;
use dioxus::prelude::*;
use serde_json::Value;

use crate::api::{
    ContrixApi, is_auth_expired_error, is_invalid_cursor_error, sleep_for,
};
use crate::local_state::{LocalAnchorView, LocalStateStore};
use crate::models::{ClientSyncResponse, SpacePreview};

/// How long to hold an incremental `/sync` request open. soland clamps
/// the server-side wait independently; this is the client's upper
/// bound on a single HTTP round-trip.
const LONG_POLL_TIMEOUT_MS: u64 = 30_000;

/// Sleep ceiling between failed iterations. 60s matches what other
/// Matrix-style sync clients use — long enough that a wedged server
/// doesn't get DoSed by retries, short enough that recovery is
/// noticeable to the user.
const MAX_BACKOFF_SECS: u64 = 60;

/// Floor for the first backoff sleep. Doubles up to `MAX_BACKOFF_SECS`.
const MIN_BACKOFF_SECS: u64 = 1;

/// Bundle of signals + state-store the engine needs to apply a response.
/// `Copy` because Dioxus signals already are; the struct is just a
/// typed shorthand around them.
#[derive(Clone, Copy)]
pub struct SyncEngineContext {
    pub base_url: Signal<String>,
    pub token: Signal<String>,
    pub state_store: Signal<LocalStateStore>,
    pub spaces: Signal<Vec<SpacePreview>>,
    pub timeline: Signal<Vec<crate::views::timeline::TimelineEvent>>,
    pub sync_cursor: Signal<String>,
    pub status: Signal<String>,
    pub network_state: Signal<String>,
    pub last_error: Signal<Option<String>>,
    pub device_queue: Signal<usize>,
    pub theme: Signal<String>,
    pub account_did: Signal<String>,
    pub selected_space: Signal<String>,
    pub agent_workspace_pending:
        Signal<Vec<crate::views::agent_workspace::AgentTaskSummary>>,
    pub agent_workspace_in_flight:
        Signal<Vec<crate::views::agent_workspace::AgentTaskSummary>>,
    pub agent_workspace_recent:
        Signal<Vec<crate::views::agent_workspace::AgentTaskSummary>>,
    pub agent_workspace_agents:
        Signal<Vec<crate::views::agent_workspace::OwnedAgentSummary>>,
    pub agent_workspace_details:
        Signal<std::collections::BTreeMap<String, crate::views::agent_workspace::AgentTaskDetail>>,
    pub owned_agents_context: crate::views::agent_workspace::OwnedAgentsContext,
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

        match run_iteration(start_generation, generation, &ctx).await {
            IterationOutcome::Ok => {
                backoff_secs = MIN_BACKOFF_SECS;
                // Tight loop: long-poll already absorbed the idle
                // wait, no extra sleep needed.
            }
            IterationOutcome::InvalidCursor => {
                // Demote to full sync next iteration. The persisted
                // cursor was already cleared inside the iteration.
                backoff_secs = MIN_BACKOFF_SECS;
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
    let api = match ContrixApi::new(&base) {
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
    let timeout_ms = if is_full_sync { 0 } else { LONG_POLL_TIMEOUT_MS };

    match api.sync_with_timeout(cursor.as_deref(), timeout_ms).await {
        Ok(response) => {
            // Late-arriving response from a stale generation must not
            // overwrite signals owned by the new generation. The
            // state_store write below is still safe because it's keyed
            // by content, but the UI signals are not.
            if generation() != start_generation {
                return IterationOutcome::Ok;
            }
            apply_response(&response, is_full_sync, ctx);
            IterationOutcome::Ok
        }
        Err(error) if is_auth_expired_error(&error) => IterationOutcome::AuthExpired,
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

/// Apply a `/sync` response: persist projections (server-authoritatively
/// reconciled when full-sync), hydrate Anchor views + account-data, and
/// publish derived UI signals (spaces / timeline / agent workspace /
/// device queue / status / cursor).
///
/// Exposed at module scope so tests can drive it without spinning up
/// the loop. `connect()` in `app.rs` shares the same code path — once
/// the engine fully owns sync, `connect()` is just a "force one
/// iteration now" entry that calls this.
pub fn apply_response(
    response: &ClientSyncResponse,
    is_full_sync: bool,
    ctx: &SyncEngineContext,
) {
    // Local mutable handles for the signals we touch — Signal<T> is
    // Copy so this is cheap.
    let mut state_store = ctx.state_store;
    let spaces = ctx.spaces;
    let mut timeline = ctx.timeline;
    let mut sync_cursor = ctx.sync_cursor;
    let mut status = ctx.status;
    let mut network_state = ctx.network_state;
    let mut last_error = ctx.last_error;
    let mut device_queue = ctx.device_queue;
    let mut theme = ctx.theme;
    let mut selected_space = ctx.selected_space;
    let mut agent_workspace_pending = ctx.agent_workspace_pending;
    let mut agent_workspace_in_flight = ctx.agent_workspace_in_flight;
    let mut agent_workspace_recent = ctx.agent_workspace_recent;
    let mut agent_workspace_agents = ctx.agent_workspace_agents;
    let mut agent_workspace_details = ctx.agent_workspace_details;
    let mut owned_agents_context = ctx.owned_agents_context;
    let account_did = ctx.account_did.read().clone();

    {
        let mut store = state_store.write();
        store.save_sync_cursor(response.next_batch.clone());

        if is_full_sync {
            // Server-authoritative: drop projections the server didn't
            // include. Without this, a Space the viewer left would
            // linger because `save_space_projection` is upsert-only.
            let server_set: BTreeSet<String> = response.spaces.keys().cloned().collect();
            let pruned = store.retain_space_projections(|id| server_set.contains(id));
            if !pruned.is_empty() {
                tracing::info!(
                    pruned_count = pruned.len(),
                    "sync engine: full-sync pruned stale space projections",
                );
            }
        }
        // Explicit `left_spaces` deltas — meaningful primarily on
        // incremental sync, but cheap to apply on full sync too.
        for left_id in &response.left_spaces {
            store.forget_space(left_id);
        }
        for (id, body) in &response.spaces {
            store.save_space_projection(id.clone(), body.clone());
            let view = LocalAnchorView::from_sync_body(body);
            store.set_anchor_view(id.clone(), view);
        }

        apply_account_data(
            &mut store,
            response,
            &account_did,
            &mut theme,
            &mut last_error,
        );

        if let Err(error) = store.flush() {
            last_error.set(Some(format!("state_store flush failed: {error}")));
        }
    }

    // The `spaces` Signal is derived from `state_store.space_projections`
    // via a use_effect in `RouterView` — we don't `set` it here. We do
    // still need a reconciled snapshot for status text + selected_space
    // bookkeeping.
    let _ = spaces; // suppress unused capture; consumed by the derive effect
    let reconciled = crate::app::space_previews_from_sync_spaces(
        &state_store.read().load().space_projections,
    );
    if reconciled.is_empty() {
        status.set(crate::views::ConnectionState::Empty.label().to_owned());
    } else {
        status.set(format!(
            "{}: synced {} space(s)",
            crate::views::ConnectionState::Online.label(),
            reconciled.len()
        ));
    }
    network_state.set("online".to_owned());
    let first_space = reconciled.first().map(|space| space.space_id.clone());
    {
        let current = selected_space.read().clone();
        let trimmed = current.trim();
        let needs_reset = trimmed.is_empty()
            || !reconciled.iter().any(|s| s.space_id == trimmed);
        if needs_reset {
            selected_space.set(first_space.unwrap_or_default());
        }
    }

    let synced_timeline =
        crate::app::timeline_events_from_sync_spaces(&response.spaces);
    timeline.set(synced_timeline);

    let workspace_projection = crate::app::agent_workspace_projection_from_sync_spaces(
        &state_store.read().load().space_projections,
    );
    agent_workspace_pending.set(workspace_projection.pending);
    agent_workspace_in_flight.set(workspace_projection.in_flight);
    agent_workspace_recent.set(workspace_projection.recent);
    agent_workspace_agents.set(workspace_projection.agents.clone());
    owned_agents_context.set(workspace_projection.agents);
    agent_workspace_details.set(workspace_projection.details);

    device_queue.set(response.to_device.len());
    sync_cursor.set(response.next_batch.clone());
}

fn apply_account_data(
    store: &mut LocalStateStore,
    response: &ClientSyncResponse,
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
        // cx.account.blocklist — personal block list.
        if data_type == "cx.account.blocklist" || data_type == "client.blocklist" {
            let Some(content) = entry.get("content") else {
                continue;
            };
            match crate::account_data::blocklist_entries_from_account_data(content) {
                Ok(entries) => store.set_client_blocklist(entries),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed cx.account.blocklist account_data: {error}",
                    );
                }
            }
            continue;
        }
        // cx.contacts.space.<space_id> — actor-private Space remarks.
        let Some(space_id) =
            crate::account_data::space_id_from_space_remark_key(data_type)
        else {
            continue;
        };
        let Some(content) = entry.get("content") else {
            continue;
        };
        match serde_json::from_value::<crate::account_data::SpaceRemark>(content.clone()) {
            Ok(remark) => store.set_space_remark(space_id.to_owned(), remark),
            Err(error) => {
                tracing::warn!(
                    "sync engine: ignoring malformed Space remark for {space_id}: {error}",
                );
            }
        }
    }
}

/// `EncryptedPayload` is re-exported here so app.rs can build a
/// `SyncEngineContext` without pulling contrix_sdk into its surface
/// imports.
#[allow(dead_code)]
pub(crate) type _EnsureSdkLink = EncryptedPayload;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn empty_response(next_batch: &str) -> ClientSyncResponse {
        ClientSyncResponse {
            next_batch: next_batch.to_owned(),
            spaces: Default::default(),
            left_spaces: Vec::new(),
            to_device: Vec::new(),
            account_data: Vec::new(),
            device_lists: json!({}),
        }
    }

    #[test]
    fn full_sync_response_prunes_cached_projection() {
        // Bench against the store directly — we don't need the dioxus
        // signals to verify the reconcile semantics. The signal-side
        // wiring is exercised by the lib's integration tests; the unit
        // contract here is "after a full sync, only server-reported
        // ids remain in the store".
        let path = std::env::temp_dir().join(format!(
            "yougen-engine-prune-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let mut store = LocalStateStore::with_path(path);
        store.save_space_projection("cx:space:a", json!({"name": "A"}));
        store.save_space_projection("cx:space:b", json!({"name": "B"}));
        store.save_draft("cx:space:b", "draft-b");

        let mut response = empty_response("sx:42");
        response
            .spaces
            .insert("cx:space:a".to_owned(), json!({"name": "A"}));

        // Mirror the engine's full-sync prune step.
        let server_set: BTreeSet<String> = response.spaces.keys().cloned().collect();
        let pruned = store.retain_space_projections(|id| server_set.contains(id));
        assert_eq!(pruned, vec!["cx:space:b".to_owned()]);

        let state = store.load();
        assert!(state.space_projections.contains_key("cx:space:a"));
        assert!(!state.space_projections.contains_key("cx:space:b"));
        assert!(!state.drafts.contains_key("cx:space:b"));
    }

    #[test]
    fn incremental_response_forgets_left_spaces() {
        let path = std::env::temp_dir().join(format!(
            "yougen-engine-left-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        let mut store = LocalStateStore::with_path(path);
        store.save_space_projection("cx:space:a", json!({"name": "A"}));
        store.save_space_projection("cx:space:b", json!({"name": "B"}));
        store.save_draft("cx:space:b", "draft-b");

        let mut response = empty_response("sx:43");
        response.left_spaces = vec!["cx:space:b".to_owned()];

        // Mirror the engine's left_spaces step.
        for id in &response.left_spaces {
            store.forget_space(id);
        }

        let state = store.load();
        assert!(state.space_projections.contains_key("cx:space:a"));
        assert!(!state.space_projections.contains_key("cx:space:b"));
        assert!(!state.drafts.contains_key("cx:space:b"));
    }
}
