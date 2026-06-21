//! Background account subscribe sync loop.
//!
//! Background engine that keeps the local store + UI signals continuously
//! aligned with `/_cokret/self/account/subscribe` instead of refreshing only on
//! app boot, the Refresh button, or a server switch.
//!
//! Design contract (matches the intended approach laid out in the design
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
//!   + login strand take over. Cursor-invalid errors clear the cursor and immediately retry as a
//!     full sync.
//!
//! The engine deliberately does NOT trigger session refresh inline —
//! that's owned by [`crate::session_refresh`] which runs in parallel.
//! When an iteration hits `is_auth_expired_error` the engine just exits;
//! the refresh poller updates the session credential, the lifecycle bumps
//! the generation, and a new engine spawn picks up. This keeps refresh
//! logic in one place.

use std::collections::BTreeSet;
use std::time::Duration;

use dioxus::prelude::*;
use serde_json::Value;

use crate::api::{
    AccountSubscribeSnapshotResult, CokretApi, MAX_RETRY_DELAY, is_auth_expired_error,
    is_invalid_cursor_error, is_stale_frontier_error, is_terminal_session_grant_error,
    rate_limited_retry_after, sleep_for,
};
use crate::config::MultiProfileConfig;
use crate::local_state::{LocalSealView, LocalStateStore};
use crate::models::{
    ClientSyncOutcome, DeviceMessagesGetOutcome, RealmTreeNode, RealmTreeNodeKind,
};

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
/// so it cannot yet keep the spec's long-lived account stream open
/// (YOU-01-010 residual: wasm needs a web-sys ReadableStream frame reader
/// before this can become a resident stream). Every frame of each response IS consumed and the
/// cursor advances to the response's last cursor-bearing frame, so the
/// poll only bounds realtime latency, not catchup correctness. Keep the
/// fallback poll interval human-scale until the client switches to a
/// true frame reader.
const MIN_INTER_ITERATION_MS: u64 = 5_000;

/// How many successful delta iterations may pass before the engine
/// re-pulls `GET /_cokret/self/authz/invites`.
///
/// Pending invites are low-churn, so refetching the full list on *every*
/// sync delta (~`MIN_INTER_ITERATION_MS` apart) just floods the network
/// panel with identical responses — the symptom of the original
/// "`invites` keeps firing" report. We refresh at most once per this many
/// deltas (≈30s at the 5s poll floor) and additionally force a refresh on
/// every full sync (login / reconnect / cursor reset) so a fresh session
/// always lands with current invites. Between refreshes the engine passes
/// `None` to `apply_response`, which preserves the last merged invite
/// projection rather than clearing it.
const INVITES_REFRESH_EVERY_N_DELTAS: u32 = 6;
const TO_DEVICE_PAGE_LIMIT: u32 = 1000;
const MAX_TO_DEVICE_BACKFILL_PAGES: usize = 32;

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
    /// YOU-02-004R (§5.6) — the local device id, needed by the idle
    /// self-update driver to load the device snapshot secret and build the
    /// background `self_update_commit`. Sourced from the active profile config
    /// (same value the chat / realm-admin send paths use).
    pub device_id: Signal<String>,
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
    /// Y1/Y2 - session-scoped DID resolution cache handle, provided by
    /// `app.rs` via `use_context_provider` as documented there. While ingesting
    /// projections, the Y2 invalidation hook uses it to call `invalidate` for
    /// related actor DIDs when `ck.cross_signing.reset` / `ck.device.revoke`
    /// arrive, and `clear` on logout / trust-bundle reset. `Signal<T>` is
    /// `Copy`, so storing it here is zero-cost.
    pub did_cache: Signal<crate::did_resolver::DidResolutionCache>,
    /// Receive side of `ck.call.signal`. The engine routes inbound
    /// call-signal envelopes from each incremental sync body into this hub
    /// (dedup → incoming ring / per-call inbox). `Copy`, zero-cost to hold.
    /// See `crate::views::call_signals`.
    pub call_signal_hub: crate::views::call_signals::CallSignalHub,
}

/// Outcome of one sync iteration — used by the loop to decide whether to
/// backoff, demote, or stop.
#[derive(Debug)]
enum IterationOutcome {
    /// Response applied successfully — reset backoff, immediately
    /// re-enter the loop.
    Ok { realm_ids: Vec<String> },
    /// Cursor was rejected (`cursor_expired` / `cursor_integrity_invalid`
    /// / `cursor_unrecognized`). Clear the persisted cursor and re-enter
    /// the loop as a full sync (client-sync.md §12.3).
    InvalidCursor,
    /// `stale_frontier` — the cursor is still valid but the service
    /// frontier lags. Per client-sync.md §4 the cursor MUST NOT be
    /// cleared; the iteration already refreshed the frontier via
    /// `account/describe`, so just retry with the same cursor after a
    /// beat.
    StaleFrontier,
    /// Auth expired or server otherwise told us the session is dead.
    /// Engine exits; refresh poller + login strand take over.
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
    // Counts delta syncs since the last invite refetch; see
    // `INVITES_REFRESH_EVERY_N_DELTAS`. Seeded at the threshold so the first
    // delta after spawn refreshes immediately even if it isn't a full sync.
    let mut deltas_since_invites = INVITES_REFRESH_EVERY_N_DELTAS;
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

        match run_iteration(
            start_generation,
            generation,
            &ctx,
            &mut deltas_since_invites,
        )
        .await
        {
            IterationOutcome::Ok { realm_ids } => {
                backoff_secs = MIN_BACKOFF_SECS;
                // Recovery: clear any stale error the user has been
                // staring at. Without this, a single Transient or
                // RateLimited blip sticks in the status bar forever
                // because apply_response doesn't touch last_error.
                ctx.last_error.clone().set(None);
                run_circle_scope_rotate_pass(start_generation, generation, &ctx, &realm_ids).await;
                // YOU-02-004R (`encryption-and-audit.md` §5.6) — non-send
                // self-preservation trigger. A long-lived read-only member's
                // epoch is otherwise never force-advanced (the send path only
                // fires while encrypting). After each successful sync — when
                // the local membership/pending-commit view is freshest — drive
                // the idle self-update pass. It is a no-op for every Realm not
                // yet over the §5.6 floor / before this member's jitter slot,
                // so the common case costs one cheap scan.
                run_idle_self_update_pass(start_generation, generation, &ctx).await;
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
            IterationOutcome::StaleFrontier => {
                // Keep the cursor (spec MUST NOT clear it) and retry
                // after a beat — the iteration already consulted
                // `account/describe` for the current frontier.
                backoff_secs = MIN_BACKOFF_SECS;
                sleep_for(Duration::from_millis(MIN_INTER_ITERATION_MS)).await;
            }
            IterationOutcome::AuthExpired => {
                // Hand off to the refresh poller / login strand. The
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
                let wait_ms = retry_after_ms
                    .max(MIN_BACKOFF_SECS.saturating_mul(1000))
                    .min(u64::try_from(MAX_RETRY_DELAY.as_millis()).unwrap_or(u64::MAX));
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
                let wait_ms = reconnect_after_ms
                    .max(MIN_BACKOFF_SECS.saturating_mul(1000))
                    .min(u64::try_from(MAX_RETRY_DELAY.as_millis()).unwrap_or(u64::MAX));
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

/// Background Circle MLS scope-rotate worker.
///
/// Scans the Realm ids that changed in the just-applied sync response, discovers
/// pending Circle remove obligations from the typed Circle list endpoint, builds
/// a real OpenMLS remove commit from the local Circle snapshot, and persists the
/// post-commit snapshot only after the server accepts or deduplicates the event.
/// One commit is submitted per pass so competing clients and multi-Realm
/// accounts do not burst writes after a sync wakeup.
async fn run_circle_scope_rotate_pass(
    start_generation: u64,
    generation: Signal<u64>,
    ctx: &SyncEngineContext,
    realm_ids: &[String],
) {
    if generation() != start_generation {
        return;
    }
    let base = ctx.base_url.read().clone();
    let token = ctx.token.read().clone();
    let actor_id = ctx.account_did.read().trim().to_owned();
    let device_id = ctx.device_id.read().trim().to_owned();
    if base.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.is_empty()
        || device_id.is_empty()
    {
        return;
    }
    let realm_ids: BTreeSet<String> = realm_ids
        .iter()
        .map(|realm_id| realm_id.trim())
        .filter(|realm_id| realm_id.starts_with("ck:realm:"))
        .map(str::to_owned)
        .collect();
    if realm_ids.is_empty() {
        return;
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    for realm_id in realm_ids {
        if generation() != start_generation {
            return;
        }
        let circles = match crate::views::helpers::with_authed_api(&base, token.clone(), {
            let realm_id = realm_id.clone();
            move |api| async move { api.list_circles(&realm_id).await }
        })
        .await
        {
            Ok(circles) => circles,
            Err(err) => {
                if err.is_auth_expired() {
                    return;
                }
                tracing::debug!(
                    %realm_id,
                    error = %err.display(),
                    "sync_engine: Circle scope-rotate scan skipped",
                );
                continue;
            }
        };
        for circle in circles.circles {
            if generation() != start_generation {
                return;
            }
            let circle_id = circle.circle_id.to_string();
            if circle.state != cokret_sdk::CircleState::Active
                || circle.encryption_profile != cokret_sdk::EncryptionProfile::MlsRfc9420
                || circle.pending_mls_removals.is_empty()
            {
                continue;
            }
            if !circle
                .members
                .iter()
                .any(|member| member.to_string() == actor_id)
            {
                tracing::debug!(
                    %realm_id,
                    %circle_id,
                    "sync_engine: Circle scope-rotate skipped for non-member actor",
                );
                continue;
            }
            if ctx
                .state_store
                .read()
                .mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id))
                .is_none()
            {
                tracing::debug!(
                    %realm_id,
                    %circle_id,
                    "sync_engine: Circle scope-rotate skipped without local MLS snapshot",
                );
                continue;
            }
            for target in circle.pending_mls_removals {
                if generation() != start_generation {
                    return;
                }
                let target_principal_id = target.to_string();
                let draft = {
                    let store = ctx.state_store.read();
                    crate::circle_mls::build_circle_remove_scope_rotate_draft(
                        &store,
                        secure_store.as_ref(),
                        &realm_id,
                        &circle_id,
                        &actor_id,
                        &device_id,
                        &target_principal_id,
                    )
                };
                let draft = match draft {
                    Ok(draft) => draft,
                    Err(err) => {
                        tracing::debug!(
                            %realm_id,
                            %circle_id,
                            %target_principal_id,
                            error = %err,
                            "sync_engine: Circle scope-rotate draft build skipped",
                        );
                        continue;
                    }
                };
                let events = draft.events;
                let post_commit_snapshot = draft.post_commit_snapshot;
                let removed_leaves = draft.removed_leaves;
                let removed_principals = draft.removed_principals;
                let outcome = match crate::views::helpers::with_authed_api(&base, token.clone(), {
                    let circle_id = circle_id.clone();
                    move |api| async move {
                        api.submit_circle_scope_rotate_events(&circle_id, &events, None)
                            .await
                    }
                })
                .await
                {
                    Ok(outcome) => outcome,
                    Err(err) => {
                        if err.is_auth_expired() {
                            return;
                        }
                        tracing::debug!(
                            %realm_id,
                            %circle_id,
                            %target_principal_id,
                            error = %err.display(),
                            "sync_engine: Circle scope-rotate submit failed",
                        );
                        continue;
                    }
                };
                if !outcome.accepted.is_empty() || !outcome.duplicate.is_empty() {
                    if generation() != start_generation {
                        return;
                    }
                    ctx.state_store
                        .clone()
                        .write()
                        .save_mls_snapshot_for_effective_scope(
                            realm_id.clone(),
                            Some(&circle_id),
                            post_commit_snapshot,
                        );
                    tracing::info!(
                        %realm_id,
                        %circle_id,
                        %target_principal_id,
                        ?removed_leaves,
                        ?removed_principals,
                        accepted = outcome.accepted.len(),
                        duplicate = outcome.duplicate.len(),
                        cleared_pending_removals = outcome.cleared_pending_removals.len(),
                        "sync_engine: Circle scope-rotate commit accepted",
                    );
                    return;
                }
                tracing::debug!(
                    %realm_id,
                    %circle_id,
                    %target_principal_id,
                    rejected = outcome.rejected.len(),
                    quarantine = outcome.quarantine.len(),
                    "sync_engine: Circle scope-rotate commit not accepted",
                );
            }
        }
    }
}

/// Background idle self-preservation commit driver.
///
/// Walks persisted MLS Realm snapshots and submits at most one due
/// self-update commit per pass. The snapshot is persisted only after
/// server acceptance, matching the send path and epoch-rotation button.
async fn run_idle_self_update_pass(
    start_generation: u64,
    generation: Signal<u64>,
    ctx: &SyncEngineContext,
) {
    if generation() != start_generation {
        return;
    }
    let base = ctx.base_url.read().clone();
    let token = ctx.token.read().clone();
    let actor_id = ctx.account_did.read().trim().to_owned();
    let device_id = ctx.device_id.read().trim().to_owned();
    if base.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.is_empty()
        || device_id.is_empty()
    {
        return;
    }
    let now = crate::clock::now_utc();
    let realm_ids: Vec<String> = ctx.state_store.read().mls_snapshots().into_keys().collect();
    let secure_store = crate::secure_key_store::default_secure_key_store("yougen");
    for realm_id in realm_ids {
        // Re-check cancellation between Realms: a logout / profile rotation
        // mid-pass must not keep minting commits under the dead generation.
        if generation() != start_generation {
            return;
        }
        // Build the gated idle commit under a read borrow. `Ok(None)` is the
        // overwhelmingly common case (Realm not yet due / before this member's
        // jitter slot / a pending commit already suppresses it).
        let built = {
            let store = ctx.state_store.read();
            crate::mls::runtime::build_idle_self_update_commit(
                &store,
                secure_store.as_ref(),
                &realm_id,
                &actor_id,
                &device_id,
                now,
            )
            .map_err(|err| err.user_message())
            .and_then(|maybe| match maybe {
                None => Ok(None),
                Some((commit_envelope, snapshot)) => {
                    let schedule_hash = commit_envelope.commit_digest.clone();
                    crate::views::kanban::kanban_mls_commit_event_from_store(
                        &store,
                        &realm_id,
                        &actor_id,
                        &schedule_hash,
                        &commit_envelope,
                    )
                    .map(|event| Some((event, commit_envelope.epoch, snapshot)))
                }
            })
        };
        let (commit_event, next_epoch, snapshot) = match built {
            Ok(Some(parts)) => parts,
            Ok(None) => continue,
            Err(err) => {
                // Soft failure (missing secret, build error): log once and move
                // on. Local state is untouched; the next pass retries.
                tracing::debug!(
                    %realm_id,
                    error = %err,
                    "sync_engine: idle §5.6 self-update build skipped",
                );
                continue;
            }
        };
        // Submit the canonical ck.mls.commit. The server's expected-prev-epoch
        // CAS (§5.4) rejects the loser of any concurrent commit race; either
        // way the epoch advances, so a rejection is fine — we simply do NOT
        // persist the local snapshot (persist-on-accept).
        let submit_token = token.clone();
        match crate::views::helpers::with_authed_api(&base, submit_token, |api| async move {
            api.submit_sdk_event(&commit_event).await
        })
        .await
        {
            Ok(_) => {
                if generation() != start_generation {
                    // A late accept under a stale generation must not write the
                    // snapshot into the new generation's store.
                    return;
                }
                ctx.state_store
                    .clone()
                    .write()
                    .save_mls_snapshot(realm_id.clone(), snapshot);
                tracing::info!(
                    %realm_id,
                    epoch = next_epoch,
                    "sync_engine: §5.6 idle self-update commit accepted",
                );
                // One commit per pass: a multi-Realm client staggers the rest
                // across subsequent sync iterations rather than bursting.
                return;
            }
            Err(err) => {
                tracing::debug!(
                    %realm_id,
                    error = %err.display(),
                    "sync_engine: idle §5.6 self-update commit not accepted (race or transient)",
                );
                // Lost the §5.4 CAS or a transient error — discard the local
                // change (never persisted) and let the next pass re-evaluate.
                continue;
            }
        }
    }
}

async fn run_iteration(
    start_generation: u64,
    generation: Signal<u64>,
    ctx: &SyncEngineContext,
    deltas_since_invites: &mut u32,
) -> IterationOutcome {
    let base = ctx.base_url.read().clone();
    let token = ctx.token.read().clone();
    if base.trim().is_empty() || token.trim().is_empty() {
        return IterationOutcome::NotReady;
    }
    // ②(A+②): `token` is the `ck.session.grant`; attach the device DPoP key so
    // the account-subscribe self-path request is sender-constrained (§3.3).
    let api = match CokretApi::new(&base) {
        Ok(api) => crate::views::helpers::attach_device_dpop(api.with_bearer(token.clone())),
        Err(error) => {
            return IterationOutcome::Transient(format!("sync_engine: invalid base URL: {error}"));
        }
    };

    // Read cursor freshly each iteration — login strand / server switch
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
        Ok(AccountSubscribeSnapshotResult::Delta(response)) => {
            // Late-arriving response from a stale generation must not
            // overwrite signals owned by the new generation. The
            // state_store write below is still safe because it's keyed
            // by content, but the UI signals are not.
            if generation() != start_generation {
                return IterationOutcome::Ok {
                    realm_ids: Vec::new(),
                };
            }
            // Throttle invite refetches: full syncs always refresh, delta
            // syncs only every `INVITES_REFRESH_EVERY_N_DELTAS` iterations.
            // Otherwise pass `None`, which preserves the last merged invite
            // projection instead of clearing it. See the constant's doc.
            let refresh_invites =
                is_full_sync || *deltas_since_invites >= INVITES_REFRESH_EVERY_N_DELTAS;
            let invite_notifications = if refresh_invites {
                let latest_token = ctx.token.read().clone();
                let invite_api = if !latest_token.trim().is_empty() && latest_token != token {
                    api.clone().with_bearer(latest_token)
                } else {
                    api.clone()
                };
                match invite_api.invites().await {
                    Ok(response) => {
                        *deltas_since_invites = 0;
                        Some(response.invites)
                    }
                    Err(error) if is_auth_expired_error(&error) => {
                        return IterationOutcome::AuthExpired;
                    }
                    Err(error) => {
                        tracing::debug!(
                            ?error,
                            "sync engine could not refresh invite notifications"
                        );
                        // Leave the counter saturated so the next iteration
                        // retries rather than waiting another full window.
                        None
                    }
                }
            } else {
                *deltas_since_invites += 1;
                None
            };
            // YOU-02-006: the invite refetch above is a full network await; a
            // logout / profile switch / server switch during it bumps the
            // generation and rebinds `state_store`. Re-check before applying so a
            // stale-generation `response` (old account's realms / cursor /
            // timeline) can't be written into the new generation's store and UI
            // signals. The generation bump covers the profile/server switch case.
            if generation() != start_generation {
                return IterationOutcome::Ok {
                    realm_ids: Vec::new(),
                };
            }
            apply_response(&response, is_full_sync, ctx, invite_notifications);
            // Receiver side of `ck.call.signal` (async, needs the directory):
            // verify each inbound envelope's proof against the sender's
            // authoritative verify key and route only verified signals
            // (fail-closed). Done here, not inside the synchronous
            // `apply_response`, because the directory query is async.
            route_inbound_call_signals(&api, &response, ctx).await;
            if let Err(error) = process_to_device_delivery(&api, &response, ctx).await {
                if is_auth_expired_error(&error) {
                    return IterationOutcome::AuthExpired;
                }
                let mut last_error = ctx.last_error;
                last_error.set(Some(format!("sync_engine to-device: {error}")));
                return IterationOutcome::Transient(format!("sync_engine to-device: {error}"));
            }
            IterationOutcome::Ok {
                realm_ids: response.realms.keys().cloned().collect(),
            }
        }
        Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
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
        Err(error) if is_stale_frontier_error(&error) => {
            // client-sync.md §4 / §12.3: stale_frontier keeps the
            // cursor. Refresh the service frontier via account/describe
            // (step 2 of the recovery strand) before retrying with the
            // SAME cursor; failures here are best-effort — the retry
            // itself is the recovery.
            if let Err(describe_error) = api.sync_describe().await {
                tracing::debug!(
                    ?describe_error,
                    "stale_frontier recovery: account/describe failed"
                );
            }
            let selected_realm_id = ctx.selected_realm_id.read().clone();
            if !selected_realm_id.is_empty() {
                let mut state_store = ctx.state_store;
                match api.snapshot_head(&selected_realm_id).await {
                    Ok(Some(manifest)) => {
                        tracing::debug!(
                            realm_id = %selected_realm_id,
                            snapshot_id = %manifest.id,
                            "stale_frontier recovery: snapshot head available for replay fallback"
                        );
                    }
                    Ok(None) => {
                        state_store.write().mark_snapshot_degraded(
                            selected_realm_id.clone(),
                            "snapshot head unavailable after stale_frontier",
                        );
                    }
                    Err(snapshot_error) => {
                        tracing::debug!(
                            ?snapshot_error,
                            realm_id = %selected_realm_id,
                            "stale_frontier recovery: snapshot head probe failed"
                        );
                        state_store.write().mark_snapshot_degraded(
                            selected_realm_id.clone(),
                            format!("snapshot head probe failed: {snapshot_error}"),
                        );
                    }
                }
            }
            let mut last_error = ctx.last_error;
            last_error.set(Some(format!("sync_engine: {error}")));
            IterationOutcome::StaleFrontier
        }
        Err(error) => IterationOutcome::Transient(format!("sync_engine: {error}")),
    }
}

/// Async receiver pass for inbound `ck.call.signal`: for each realm body,
/// verify every call-signal envelope's `proof` against the sender's
/// authoritative directory verify key (`device_directory`) and route only
/// verified signals into the call-signal hub (fail-closed). Runs after the
/// synchronous `apply_response` because directory resolution needs `keys/query`.
async fn route_inbound_call_signals(
    api: &CokretApi,
    response: &ClientSyncOutcome,
    ctx: &SyncEngineContext,
) {
    let account_did = ctx.account_did.read().clone();
    let mut hub = ctx.call_signal_hub;
    let mut did_cache = ctx.did_cache;

    // Tier-2 (device-lifecycle.md §8.3): the call-signal receiver verifies the
    // sender device key's full cross-signing chain, which needs the sender's
    // DID document. Build a resolver-backed anchor from a snapshot of the
    // session DID cache so the SAME authority-grade resolver / cache that login
    // and trust UI use also governs device-key trust. The anchor back-fills
    // resolved documents into its private cache copy; write it back afterwards
    // so subsequent iterations reuse it.
    let anchor = crate::did_resolver::ResolverDidAnchor::from_profile(
        crate::did_resolver::DeploymentProfile::PersonalNode,
        did_cache.read().clone(),
    );

    for (id, body) in &response.realms {
        crate::views::call_signals::route_realm_call_signals(
            &mut hub,
            id,
            body,
            &account_did,
            Some(api),
            &anchor,
        )
        .await;
    }

    *did_cache.write() = anchor.into_cache();
}

/// Apply an account subscribe response: persist projections (server-authoritatively
/// reconciled when full-sync), hydrate Seal views + account-data, and
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
    let mut did_cache = ctx.did_cache;
    let account_did = ctx.account_did.read().clone();

    // Y2 invalidation hook: scan identity events in this response before writing
    // projections. On `ck.cross_signing.reset` / `ck.device.revoke`, invalidate
    // the related actor DID so the next authority resolution (`resolve_with_cache`)
    // walks the resolver chain instead of trusting a stale cache entry (old key
    // set). Keep this separate from the `state_store.write()` borrow so the two
    // Signal borrows do not overlap.
    {
        let mut cache = did_cache.write();
        for body in response.realms.values() {
            invalidate_cache_for_revocation_events(&mut cache, body);
        }
    }

    {
        let mut store = state_store.write();
        // Perf (P0): a single sync response can touch the cursor, dozens of
        // realm-tree projections, seal views, member identity events and account
        // data — each setter used to flush the *entire* `ClientLocalState` to
        // disk/localStorage. Wrap the whole apply in one batch so it persists
        // exactly once.
        let cursor_can_advance =
            to_device_batch_allows_cursor_advance(&response.to_device, response.to_device_limited);
        store.batch(|store| {
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
                let view = LocalSealView::from_sync_body(body);
                store.set_realm_seal_view(id.clone(), view);
                store.ingest_move_event_states(id, body);
                // R3.1 MID-2 — harvest inlined `ck.member.identity.update`
                // event envelopes off the `members[]` roster entries. The
                // SDK's effective-set filter is applied lazily when a UI
                // surface needs to resolve a display identity.
                ingest_member_identity_events_from_projection(store, id, body);
            }
            crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                store,
                &response.realms,
            );

            apply_account_data(store, response, &account_did, &mut theme, &mut last_error);
            apply_notification_projection(store, response, invite_notifications);
            store.save_presence_projection(response.presence.clone());
            store.ingest_to_device_messages(&response.to_device);
            if cursor_can_advance {
                store.save_sync_cursor(response.cursor.clone());
            }
        }); // store.batch — single coalesced flush happens here
    }

    // Receive side of `ck.call.signal`: route inbound call-signal envelopes
    // from each realm body into the hub (dedup → incoming ring / per-call
    // inbox). Done after the `store` write guard is dropped so the hub Signal
    // writes don't nest inside the store borrow.
    //
    // NB: receiver proof verification + directory resolve for inbound
    // `ck.call.signal` is async (needs `keys/query`); it cannot run here
    // because `apply_response` is synchronous and holds no authenticated
    // client. The async routing pass lives in `run_iteration`
    // (`route_inbound_call_signals`) right after this call returns.

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

    // Merge encrypted bodies on read (author sidecar → remote decrypt-on-read).
    // The `store` write guard above is out of scope; take a fresh read guard.
    let device_id = ctx.device_id.read().clone();
    let synced_timeline = {
        let store_guard = state_store.read();
        crate::views::timeline::timeline_events_from_sync_realms(
            &response.realms,
            Some(&store_guard),
            Some((&account_did, &device_id)),
        )
    };
    let next_timeline = if is_full_sync {
        synced_timeline
    } else {
        crate::app::merge_timeline_events(&timeline.read(), synced_timeline)
    };
    timeline.set(next_timeline);

    device_queue.set(state_store.read().load().to_device_inbox.len());
    if to_device_batch_allows_cursor_advance(&response.to_device, response.to_device_limited) {
        sync_cursor.set(response.cursor.clone());
    } else {
        tracing::debug!(
            cursor = %response.cursor,
            to_device_count = response.to_device.len(),
            "sync engine: deferred cursor advancement until to-device key material is durable"
        );
    }
}

/// R3.1 MID-2 — walk a Realm projection's `members[]` roster looking
/// for inlined `identity_events[]` arrays. Each
/// `ck.member.identity.update` envelope is recorded on the
/// `LocalStateStore` keyed by `(realm_id, actor_id)`. Also handles the
/// `state.events[]` form where the roster only carries
/// `identity_event_ids[]` and the events themselves live in the
/// frame-level event log.
async fn process_to_device_delivery(
    api: &CokretApi,
    response: &ClientSyncOutcome,
    ctx: &SyncEngineContext,
) -> anyhow::Result<()> {
    let mut ack_safe_prefix = to_device_batch_all_ack_safe(&response.to_device)
        && ctx.state_store.read().persist_error().is_none();
    if ack_safe_prefix
        && !response.to_device.is_empty()
        && let Some(ack_token) = response.to_device_ack_token.as_deref()
    {
        api.ack_device_messages(ack_token).await?;
    }

    let mut next_cursor = if response.to_device_limited {
        response.to_device_next_cursor.clone()
    } else {
        None
    };
    let mut page_count = 0usize;
    while let Some(cursor) = next_cursor {
        page_count += 1;
        if page_count > MAX_TO_DEVICE_BACKFILL_PAGES {
            anyhow::bail!(
                "to-device backfill exceeded {MAX_TO_DEVICE_BACKFILL_PAGES} pages without finishing"
            );
        }
        let page = api
            .receive_device_messages_page(Some(&cursor), Some(TO_DEVICE_PAGE_LIMIT))
            .await?;
        let messages = device_messages_get_values(&page)?;
        let persisted = {
            let mut state_store = ctx.state_store;
            state_store.write().ingest_to_device_messages(&messages);
            state_store.read().persist_error().is_none()
        };
        if !persisted || !to_device_batch_all_ack_safe(&messages) {
            ack_safe_prefix = false;
        }
        if ack_safe_prefix
            && !messages.is_empty()
            && let Some(ack_token) = page.ack_token.as_deref()
        {
            api.ack_device_messages(ack_token).await?;
        }
        if !(page.has_more || page.limited) {
            break;
        }
        next_cursor = page.next_cursor.clone();
        if next_cursor.is_none() {
            anyhow::bail!("to-device page reported more data without next_cursor");
        }
    }
    let mut device_queue = ctx.device_queue;
    device_queue.set(ctx.state_store.read().load().to_device_inbox.len());
    Ok(())
}

fn device_messages_get_values(page: &DeviceMessagesGetOutcome) -> anyhow::Result<Vec<Value>> {
    page.messages
        .iter()
        .map(|message| serde_json::to_value(message).map_err(Into::into))
        .collect()
}

fn to_device_batch_all_ack_safe(messages: &[Value]) -> bool {
    messages.iter().all(|message| {
        let kind = message
            .get("kind")
            .or_else(|| message.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        kind.starts_with("ck.key.verification.")
            || kind == crate::mls::secret_share::SECRET_SHARE_KIND_REQUEST
    })
}

fn to_device_batch_allows_cursor_advance(messages: &[Value], limited: bool) -> bool {
    !limited && to_device_batch_all_ack_safe(messages)
}

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
            // a `ck.self.events.query.scan` backfill will catch up.
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

/// Core scanner for the Y2 invalidation hook.
///
/// Finds `ck.cross_signing.reset` / `ck.device.revoke` events in one Realm
/// projection `body`, then calls
/// [`crate::did_resolver::DidResolutionCache::invalidate`] for the related actor
/// DID. Events may appear in:
/// - inline `identity_events[]` on each member roster entry;
/// - top-level projection event logs at `state.events[]` / `events[]`.
///
/// Actor DID is read from the event `actor_id` / `did`, falling back to the
/// roster entry `actor_id` / `did`. Forbidden `actor` / `sender` fields are
/// ignored. The value is validated via `Did::new`; invalid DID syntax is
/// skipped because this best-effort invalidation hook must not panic.
///
/// TRUST-CACHE boundary: this only clears cache entries so the next resolution
/// walks the authority chain again; it does not replace authority validation.
fn invalidate_cache_for_revocation_events(
    cache: &mut crate::did_resolver::DidResolutionCache,
    body: &Value,
) {
    /// Return whether the event kind is reset / revoke.
    fn is_revocation_kind(event: &Value) -> bool {
        let kind = event
            .get("kind")
            .and_then(Value::as_str)
            .or_else(|| event.get("type").and_then(Value::as_str))
            .unwrap_or("");
        kind == "ck.cross_signing.reset" || kind == "ck.device.revoke"
    }

    /// Read the actor DID string from the event, falling back to the roster entry.
    fn actor_id_str<'a>(event: &'a Value, fallback: Option<&'a Value>) -> Option<&'a str> {
        let from = |v: &'a Value| {
            v.get("actor_id")
                .or_else(|| v.get("did"))
                .and_then(Value::as_str)
        };
        from(event).or_else(|| fallback.and_then(from))
    }

    /// Invalidate for a batch of events when kind matches and DID syntax is valid.
    fn invalidate_from_events(
        cache: &mut crate::did_resolver::DidResolutionCache,
        events: &[Value],
        fallback: Option<&Value>,
    ) {
        for event in events {
            if !is_revocation_kind(event) {
                continue;
            }
            if let Some(did_str) = actor_id_str(event, fallback)
                && let Ok(did) = cokret_sdk::Did::new(did_str.to_owned())
            {
                cache.invalidate(&did);
            }
        }
    }

    // Scan both top-level event log shapes: `state.events[]` and `events[]`.
    for events in [
        body.get("state").and_then(|s| s.get("events")),
        body.get("events"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(arr) = events.as_array() {
            invalidate_from_events(cache, arr, None);
        }
    }

    // Inline `identity_events[]` on each member roster entry.
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
            if let Some(events) = entry.get("identity_events").and_then(Value::as_array) {
                invalidate_from_events(cache, events, Some(entry));
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
        if let Some(actor_id) = crate::account_data::actor_id_from_contact_remark_key(data_type) {
            let Some(content) = entry.get("content") else {
                continue;
            };
            match serde_json::from_value::<crate::account_data::ContactRemark>(content.clone()) {
                Ok(remark) => store.set_contact_remark(actor_id.to_owned(), remark),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed Contact remark for {actor_id}: {error}",
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
            to_device_ack_token: None,
            to_device_limited: false,
            to_device_next_cursor: None,
            to_device_lost: None,
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

    fn to_device_message(kind: &str) -> Value {
        json!({
            "kind": kind,
            "content": {
                "transaction_id": "txn-1",
                "request_id": "request-1"
            }
        })
    }

    #[test]
    fn to_device_ack_safe_batches_exclude_key_material() {
        assert!(to_device_batch_all_ack_safe(&[]));
        assert!(to_device_batch_all_ack_safe(&[
            to_device_message("ck.key.verification.request"),
            to_device_message(crate::mls::secret_share::SECRET_SHARE_KIND_REQUEST),
        ]));
        assert!(to_device_batch_allows_cursor_advance(
            &[to_device_message("ck.key.verification.request")],
            false,
        ));
        assert!(!to_device_batch_allows_cursor_advance(
            &[to_device_message("ck.key.verification.request")],
            true,
        ));

        assert!(!to_device_batch_all_ack_safe(&[to_device_message(
            "ck.mls.welcome"
        )]));
        assert!(!to_device_batch_all_ack_safe(&[to_device_message(
            crate::mls::secret_share::SECRET_SHARE_KIND_SEND,
        )]));
        assert!(!to_device_batch_all_ack_safe(&[to_device_message(
            "ck.future.secret.material"
        )]));
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
        // The invite notification is keyed on the unique invite id, not the
        // realm id, so a re-invite to the same realm cannot inherit stale
        // archive/read client-state from an earlier invite.
        assert!(projection.iter().any(|entry| {
            entry.get("notification_id").and_then(Value::as_str)
                == Some("invite:ck:invite:0196419b-0000-7000-8000-000000000010")
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
        // Fixture typo fix: the forgotten projection id must match the
        // `ck:space:b` saved above. `forget_realm_tree_projection` deletes by
        // exact id, without prefix normalization, so otherwise the
        // `!contains_key("ck:space:b")` assertion would always be false.
        response.left_realms = vec!["ck:space:b".to_owned()];

        // Mirror the engine's left_realms step.
        for id in &response.left_realms {
            store.forget_realm_tree_projection(id);
        }

        let state = store.load();
        assert!(state.realm_tree_projections.contains_key("ck:space:a"));
        assert!(!state.realm_tree_projections.contains_key("ck:space:b"));
        assert!(!state.drafts.contains_key("ck:space:b"));
    }

    // ── Y2 invalidation hook ──────────────────────────────────────────

    use cokret_sdk::{Did, DidDocument};

    use crate::did_resolver::DidResolutionCache;

    fn seed_cache(did_str: &str) -> (DidResolutionCache, Did) {
        let mut cache = DidResolutionCache::new(8);
        let did = Did::new(did_str.to_owned()).expect("valid did");
        let doc = DidDocument::new(did.clone(), "key-1", "z6Mksample");
        cache.insert(
            did.clone(),
            doc,
            chrono::Utc::now(),
            chrono::Duration::seconds(600),
        );
        (cache, did)
    }

    #[test]
    fn cross_signing_reset_event_invalidates_actor_in_inline_member_events() {
        let (mut cache, did) = seed_cache("did:web:alice.example");
        let body = json!({
            "members": [{
                "actor_id": "did:web:alice.example",
                "identity_events": [
                    { "event_id": "e1", "kind": "ck.cross_signing.reset" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(
            cache.get(&did, chrono::Utc::now()).is_none(),
            "reset event must drop the cached actor entry"
        );
    }

    #[test]
    fn device_revoke_event_in_state_events_invalidates_actor() {
        // Top-level state.events[] use canonical `actor_id`; forbidden
        // `actor` / `sender` fields are ignored by the scanner.
        let (mut cache, did) = seed_cache("did:web:bob.example");
        let body = json!({
            "state": { "events": [
                { "event_id": "e9", "kind": "ck.device.revoke", "actor_id": "did:web:bob.example" }
            ]}
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(cache.get(&did, chrono::Utc::now()).is_none());
    }

    #[test]
    fn device_revoke_event_with_removed_actor_key_is_ignored() {
        // Negative case: revoke events carrying only forbidden `actor` /
        // `sender` keys must not drive cache invalidation.
        let (mut cache, did) = seed_cache("did:web:dave.example");
        let body = json!({
            "state": { "events": [
                { "event_id": "e10", "kind": "ck.device.revoke", "actor": "did:web:dave.example" },
                { "event_id": "e11", "kind": "ck.device.revoke", "sender": "did:web:dave.example" }
            ]}
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(
            cache.get(&did, chrono::Utc::now()).is_some(),
            "forbidden actor/sender keys must not drive cache invalidation"
        );
    }

    #[test]
    fn non_revocation_events_do_not_invalidate() {
        // Ordinary identity update events must not clear the cache.
        let (mut cache, did) = seed_cache("did:web:carol.example");
        let body = json!({
            "members": [{
                "actor_id": "did:web:carol.example",
                "identity_events": [
                    { "event_id": "e2", "kind": "ck.member.identity.update" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(
            cache.get(&did, chrono::Utc::now()).is_some(),
            "unrelated event must leave the cache intact"
        );
    }

    #[test]
    fn revocation_for_other_actor_leaves_unrelated_entry() {
        // Alice is cached, but the revocation targets Mallory, so Alice should
        // not be affected.
        let (mut cache, alice) = seed_cache("did:web:alice.example");
        let body = json!({
            "members": [{
                "actor_id": "did:web:mallory.example",
                "identity_events": [
                    { "event_id": "e3", "kind": "ck.device.revoke" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(cache.get(&alice, chrono::Utc::now()).is_some());
    }
}
