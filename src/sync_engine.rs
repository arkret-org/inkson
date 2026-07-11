//! Background account subscribe sync loop.
//!
//! Background engine that keeps the local store + UI signals continuously
//! aligned with `/_arkret/self/account/subscribe` instead of refreshing only on
//! app boot, the Refresh button, or a server switch.
//!
//! Design contract (matches the intended approach laid out in the design
//! discussion):
//!
//! * **Cursor lives in `LocalStateStore.sync_cursor`** — the engine reads it on every iteration and
//!   writes back the new `cursor` after each successful response. Reload of the tab resumes from
//!   the persisted cursor without losing position.
//! * **First iteration is initial account sync** when no cursor is stored. Subsequent iterations
//!   resume with `after=<cursor>&catchup=true`.
//! * **Server-authoritative reconcile**: on a full sync the response is the truth for top-level
//!   Realm membership. Nested container Spaces may not appear as top-level `response.realms`
//!   entries, so locally projected Spaces are retained while their home Realm remains in the
//!   full-sync response. On incremental, soland's `left_realms` field is the prune signal.
//! * **Lifecycle via generation counter**: callers (login / logout / server-switch) bump the
//!   engine's `generation` Signal; the loop notices on the next iteration and exits cleanly. A
//!   fresh engine spawn picks up the next generation.
//! * **Backoff**: transient network errors double the sleep via [`garth::Backoff`] (capped at
//!   `BACKOFF_CEILING`); a successful response resets it. Auth-expired errors stop the engine and
//!   let the refresh poller
//!   + login strand take over. Cursor-invalid errors clear the cursor and immediately retry as a
//!     full sync.
//!
//! When an iteration hits `is_auth_expired_error`, the engine calls the
//! app-wide single-flight refresher and either continues with the refreshed
//! token, backs off on retryable restore failures, or exits after terminal
//! invalidation. This keeps refresh policy in one place without turning
//! auth failures into a spawn/exit/render loop.

#[cfg(test)]
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::time::Duration;

#[cfg(test)]
use arkret_sdk::{DecodedInbound, InboundDecoder};
#[cfg(test)]
use garth::{ClientEvent, ClientProjector};
use serde_json::{Value, json};

use crate::api_error::{
    is_auth_expired_error, is_invalid_cursor_error, is_stale_frontier_error,
    is_terminal_session_grant_error, rate_limited_retry_after,
};
use crate::models::{ClientSyncOutcome, DeviceMessagesGetOutcome, RealmTreeNodeKind};
use crate::runtime::engine_loop::{EngineLoopDirective, run_engine_loop};
use crate::runtime::projection::{ClientProjectionEvent, ProjectionSink, SyncStatusEvent};
use crate::runtime_helpers::MAX_RETRY_DELAY;
use crate::state::{LocalSealView, LocalStateStore, RawOperationRecord};
use crate::sync_parse::AccountSubscribeSnapshotResult;
use crate::transport::TransportClient;

/// Connection-status label surfaced to the app shell's status signal.
/// A pure sync-layer concept (no Dioxus state, no rendering); the app views
/// consume it via the `crate::views::ConnectionState` re-export.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Offline,
    Loading,
    Online,
    Reconnecting,
    Empty,
    Error,
}

impl ConnectionState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Offline => "Offline",
            Self::Loading => "Loading",
            Self::Online => "Online",
            Self::Reconnecting => "Reconnecting",
            Self::Empty => "Empty",
            Self::Error => "Error",
        }
    }
}

/// Failure-backoff bounds for the account subscribe loop. The doubling ladder
/// itself is [`garth::Backoff`]; these are just its floor/ceiling. A 1s floor
/// keeps recovery noticeable to the user; a 60s ceiling stops a wedged server
/// from being hammered by retries. Kept as `Duration` so there is a single unit
/// (F-10: the old seconds-vs-milliseconds split across engines is gone).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Minimum pause between successful iterations. Insurance against
/// servers that return account subscribe catch-up immediately; without
/// this, an `Ok -> loop -> Ok -> loop` cycle spins at network RTT and
/// floods the browser network panel with identical snapshots.
///
/// Inkson currently folds each NDJSON response with `Response::bytes()`,
/// so it cannot yet keep the spec's long-lived account stream open
/// (YOU-01-010 residual: wasm needs a web-sys ReadableStream frame reader
/// before this can become a resident stream). Every frame of each response IS consumed and the
/// cursor advances to the response's last cursor-bearing frame, so the
/// poll only bounds realtime latency, not catchup correctness. Keep the
/// fallback poll interval human-scale until the client switches to a
/// true frame reader.
const MIN_INTER_ITERATION_MS: u64 = 5_000;

/// How many successful delta iterations may pass before the engine
/// re-pulls `GET /_arkret/self/authz/invites`.
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

/// Session snapshot plus the remaining app adapters needed while response
/// application migrates fully behind runtime traits. UI outputs are emitted
/// exclusively through `projection_sink`.
#[derive(Clone)]
pub struct SyncEngineContext {
    pub base_url: String,
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub account_did: String,
    /// YOU-02-004R (§5.6) — the local device id, needed by the idle
    /// self-update driver to load the device snapshot secret and build the
    /// background `self_update_commit`. Sourced from the active profile config
    /// (same value the chat / realm-admin send paths use).
    pub device_id: String,
    pub selected_realm_id: crate::runtime::input::ValueReader<String>,
    /// Y1/Y2 - session-scoped DID resolution cache handle, provided by
    /// `app.rs` via `use_context_provider` as documented there. While ingesting
    /// projections, the Y2 invalidation hook uses it to call `invalidate` for
    /// related actor DIDs when `ak.cross_signing.reset` / `ak.device.revoke`
    /// arrive, and `clear` on logout / trust-bundle reset.
    pub did_cache:
        crate::runtime::input::ValueCell<crate::identity::did_resolver::DidResolutionCache>,
    /// Receive side of `ak.call.signal`. The engine routes inbound
    /// call-signal envelopes from each incremental sync body into this hub
    /// (dedup → incoming ring / per-call inbox). `Copy`, zero-cost to hold.
    /// See `crate::views::call_signals`.
    pub call_signal_hub: crate::views::call_signals::CallSignalHub,
    pub session: crate::runtime::session::SessionCoordinator,
    pub effect: crate::runtime::effects::EffectHandle,
    pub projection_sink: crate::runtime::projection::ProjectionRouter,
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

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AccountClientEventReport {
    account_updates: usize,
    realm_deltas: usize,
    decoded_messages: usize,
    decoded_events: usize,
    to_device: usize,
    notifications: usize,
    malformed_realms: Vec<String>,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct AccountClientEventProjector {
    report: RefCell<AccountClientEventReport>,
}

#[cfg(test)]
impl AccountClientEventProjector {
    fn report(&self) -> AccountClientEventReport {
        self.report.borrow().clone()
    }

    fn record(&self, event: ClientEvent) {
        let mut report = self.report.borrow_mut();
        match event {
            ClientEvent::AccountUpdates(updates) => {
                report.account_updates += 1;
                report.malformed_realms.extend(updates.malformed_realms);
            }
            ClientEvent::RealmDelta { .. } => {
                report.realm_deltas += 1;
            }
            ClientEvent::Message(_) => {
                report.decoded_messages += 1;
            }
            ClientEvent::Event(_) => {
                report.decoded_events += 1;
            }
            ClientEvent::Notification(_) => {
                report.notifications += 1;
            }
            ClientEvent::ToDevice(_) => {
                report.to_device += 1;
            }
            ClientEvent::Backfill { .. } => {}
        }
    }
}

#[cfg(test)]
impl ClientProjector for AccountClientEventProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = arkret_sdk::Result<()>> + '_ {
        async move {
            for event in batch {
                self.record(event);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
fn push_decoded_account_event(
    decoder: &InboundDecoder,
    batch: &mut Vec<ClientEvent>,
    event: arkret_sdk::Event,
) {
    match decoder.decode_event(event) {
        DecodedInbound::Message(message) => batch.push(ClientEvent::Message(message)),
        DecodedInbound::Event(event) => batch.push(ClientEvent::Event(event)),
    }
}

#[cfg(test)]
fn push_account_event_payload(
    decoder: &InboundDecoder,
    batch: &mut Vec<ClientEvent>,
    payload: &Value,
) {
    match serde_json::from_value::<arkret_sdk::Event>(payload.clone()) {
        Ok(event) => push_decoded_account_event(decoder, batch, event),
        Err(error) => {
            tracing::debug!(
                error = %error,
                "account sync event payload was not a typed Event; ignoring payload"
            );
        }
    }
}

#[cfg(test)]
fn push_account_realm_update_events(
    decoder: &InboundDecoder,
    batch: &mut Vec<ClientEvent>,
    update: &arkret_sdk::RealmUpdate,
) {
    for payload in &update.state {
        push_account_event_payload(decoder, batch, payload);
    }
    if let Some(timeline) = &update.timeline {
        for payload in &timeline.events {
            push_account_event_payload(decoder, batch, payload);
        }
    }
}

#[cfg(test)]
async fn project_account_response_client_events<P>(
    response: &ClientSyncOutcome,
    decoder: &InboundDecoder,
    projector: &P,
) -> anyhow::Result<()>
where
    P: ClientProjector + ?Sized,
{
    let mut processor = arkret_sdk::SyncResponseProcessor::new();
    let updates = processor.process(response.clone())?;
    let realm_updates = updates.realm_updates.clone();
    let mut batch = garth::account_updates_to_events(updates);

    for update in &realm_updates {
        push_account_realm_update_events(decoder, &mut batch, update);
    }
    projector.project(batch).await?;

    Ok(())
}

/// Main entry point. Spawn this once per "session generation" — see the
/// module-level doc for what bumps the generation.
///
/// The engine returns when the generation moves past `start_generation`
/// (signal that a new engine should be spawned with the next number) or
/// when an unrecoverable error fires (auth-expired, missing config).
pub async fn run_sync_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: SyncEngineContext,
) {
    // Snapshot the active profile id at spawn time. If the UI rotates
    // profiles mid-loop, the engine exits cleanly and a fresh spawn
    // picks up the new profile's cursor / token / account_did.
    // Counts delta syncs since the last invite refetch; see
    // `INVITES_REFRESH_EVERY_N_DELTAS`. Seeded at the threshold so the first
    // delta after spawn refreshes immediately even if it isn't a full sync.
    let mut deltas_since_invites = INVITES_REFRESH_EVERY_N_DELTAS;
    ctx.projection_sink.sync_status(SyncStatusEvent::Connecting);
    run_engine_loop(
        BACKOFF_FLOOR,
        BACKOFF_CEILING,
        || generation.get() == start_generation && !ctx.effect.is_cancelled(),
        async || match run_iteration(
            start_generation,
            generation.clone(),
            &ctx,
            &mut deltas_since_invites,
        )
        .await
        {
            IterationOutcome::Ok { realm_ids } => {
                ctx.projection_sink.sync_status(SyncStatusEvent::Online);
                run_circle_scope_rotate_pass(
                    start_generation,
                    generation.clone(),
                    &ctx,
                    &realm_ids,
                )
                .await;
                // YOU-02-004R (`encryption-and-audit.md` §5.6) — non-send
                // self-preservation trigger. A long-lived read-only member's
                // epoch is otherwise never force-advanced (the send path only
                // fires while encrypting). After each successful sync — when
                // the local membership/pending-commit view is freshest — drive
                // the idle self-update pass. It is a no-op for every Realm not
                // yet over the §5.6 floor / before this member's jitter slot,
                // so the common case costs one cheap scan.
                run_idle_self_update_pass(start_generation, generation.clone(), &ctx).await;
                // Server-side long-poll absorbs the idle wait on a
                // spec-compliant server; if the server returns
                // immediately (older soland), MIN_INTER_ITERATION_MS
                // keeps the loop from spinning at network RTT.
                EngineLoopDirective::ContinueAfter(Duration::from_millis(MIN_INTER_ITERATION_MS))
            }
            IterationOutcome::InvalidCursor => {
                // Demote to full sync next iteration. The persisted
                // cursor was already cleared inside the iteration.
                EngineLoopDirective::ContinueAfter(Duration::from_millis(MIN_INTER_ITERATION_MS))
            }
            IterationOutcome::StaleFrontier => {
                ctx.projection_sink.sync_status(SyncStatusEvent::Retryable {
                    reason: "service frontier is stale".to_owned(),
                });
                // Keep the cursor (spec MUST NOT clear it) and retry
                // after a beat — the iteration already consulted
                // `account/describe` for the current frontier.
                EngineLoopDirective::ContinueAfter(Duration::from_millis(MIN_INTER_ITERATION_MS))
            }
            IterationOutcome::AuthExpired => match ctx.session.refresh().await {
                crate::runtime::session::CurrentSessionRefresh::Credential(_) => {
                    EngineLoopDirective::ContinueAfter(Duration::from_millis(
                        MIN_INTER_ITERATION_MS,
                    ))
                }
                crate::runtime::session::CurrentSessionRefresh::SignInRequired { reason } => {
                    ctx.projection_sink
                        .sync_status(SyncStatusEvent::NeedsSignIn { reason });
                    EngineLoopDirective::Stop
                }
                crate::runtime::session::CurrentSessionRefresh::RetryLater { reason } => {
                    ctx.projection_sink
                        .sync_status(SyncStatusEvent::Retryable { reason });
                    EngineLoopDirective::Retry {
                        minimum_delay: None,
                    }
                }
                crate::runtime::session::CurrentSessionRefresh::LoginRequired { reason } => {
                    ctx.projection_sink.sync_status(SyncStatusEvent::Terminal {
                        reason: reason.clone(),
                    });
                    EngineLoopDirective::Stop
                }
            },
            IterationOutcome::NotReady => {
                ctx.projection_sink.sync_status(SyncStatusEvent::Offline);
                // Nothing to do until base_url / token are populated.
                // Caller's `use_effect` will respawn when they are.
                EngineLoopDirective::Stop
            }
            IterationOutcome::RateLimited {
                retry_after_ms,
                reason,
            } => {
                ctx.projection_sink.sync_status(SyncStatusEvent::Retryable {
                    reason: reason.clone(),
                });
                // Honour the server's hint with a floor of `BACKOFF_FLOOR` so a
                // buggy server that returns `retry_after_ms = 0` still gives us a
                // beat.
                let wait_ms = retry_after_ms
                    .max(u64::try_from(BACKOFF_FLOOR.as_millis()).unwrap_or(1_000))
                    .min(u64::try_from(MAX_RETRY_DELAY.as_millis()).unwrap_or(u64::MAX));
                EngineLoopDirective::Pause(Duration::from_millis(wait_ms))
            }
            IterationOutcome::ReconnectAfter {
                reconnect_after_ms,
                reason,
            } => {
                ctx.projection_sink.sync_status(SyncStatusEvent::Retryable {
                    reason: reason
                        .clone()
                        .unwrap_or_else(|| "sync stream requested reconnect".to_owned()),
                });
                let wait_ms = reconnect_after_ms
                    .max(u64::try_from(BACKOFF_FLOOR.as_millis()).unwrap_or(1_000))
                    .min(u64::try_from(MAX_RETRY_DELAY.as_millis()).unwrap_or(u64::MAX));
                EngineLoopDirective::Pause(Duration::from_millis(wait_ms))
            }
            IterationOutcome::Transient(reason) => {
                ctx.projection_sink.sync_status(SyncStatusEvent::Retryable {
                    reason: reason.clone(),
                });
                EngineLoopDirective::Retry {
                    minimum_delay: None,
                }
            }
        },
    )
    .await;
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
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
    realm_ids: &[String],
) {
    if generation.get() != start_generation {
        return;
    }
    let base = ctx.base_url.clone();
    let token = ctx.token.get();
    let actor_id = ctx.account_did.trim().to_owned();
    let device_id = ctx.device_id.trim().to_owned();
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
        .filter(|realm_id| realm_id.starts_with("ak:realm:"))
        .map(str::to_owned)
        .collect();
    if realm_ids.is_empty() {
        return;
    }
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    for realm_id in realm_ids {
        if generation.get() != start_generation {
            return;
        }
        let circles = match crate::transport::auth::with_authed_sdk_client(&base, token.clone(), {
            let realm_id = realm_id.clone();
            move |http| async move { crate::transport::circle::list_circles(&http, &realm_id).await }
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
            if generation.get() != start_generation {
                return;
            }
            let circle_id = circle.circle_id.to_string();
            if circle.state != arkret_sdk::CircleState::Active
                || circle.encryption_profile != arkret_sdk::EncryptionProfile::MlsRfc9420
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
            if ctx.state_store.read(|store| {
                store
                    .mls_snapshot_for_effective_scope(&realm_id, Some(&circle_id))
                    .is_none()
            }) {
                tracing::debug!(
                    %realm_id,
                    %circle_id,
                    "sync_engine: Circle scope-rotate skipped without local MLS snapshot",
                );
                continue;
            }
            for target in circle.pending_mls_removals {
                if generation.get() != start_generation {
                    return;
                }
                let target_principal_id = target.principal_id().to_string();
                let revocation_membership_frontier = target.membership_frontier().to_vec();
                if revocation_membership_frontier.is_empty() {
                    tracing::debug!(
                        %realm_id,
                        %circle_id,
                        %target_principal_id,
                        "sync_engine: Circle scope-rotate skipped without revoke/import membership frontier",
                    );
                    continue;
                }
                let draft = ctx.state_store.read(|store| {
                    crate::circle_mls::build_circle_remove_scope_rotate_draft(
                        store,
                        secure_store.as_ref(),
                        &realm_id,
                        &circle_id,
                        &actor_id,
                        &device_id,
                        &target_principal_id,
                        &revocation_membership_frontier,
                    )
                });
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
                let outcome =
                    match crate::transport::auth::with_event_submitter(&base, token.clone(), {
                        let circle_id = circle_id.clone();
                        move |sub| async move {
                            crate::transport::circle::submit_circle_scope_rotate_events(
                                &sub, &circle_id, &events, None,
                            )
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
                    if generation.get() != start_generation {
                        return;
                    }
                    ctx.state_store.write(|store| {
                        store.save_mls_snapshot_for_effective_scope(
                            realm_id.clone(),
                            Some(&circle_id),
                            post_commit_snapshot,
                        )
                    });
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
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
) {
    if generation.get() != start_generation {
        return;
    }
    let base = ctx.base_url.clone();
    let token = ctx.token.get();
    let actor_id = ctx.account_did.trim().to_owned();
    let device_id = ctx.device_id.trim().to_owned();
    if base.trim().is_empty()
        || token.trim().is_empty()
        || actor_id.is_empty()
        || device_id.is_empty()
    {
        return;
    }
    let now = crate::clock::now_utc();
    let realm_ids: Vec<String> = ctx
        .state_store
        .read(|store| store.mls_snapshots().into_keys().collect());
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    for realm_id in realm_ids {
        // Re-check cancellation between Realms: a logout / profile rotation
        // mid-pass must not keep minting commits under the dead generation.
        if generation.get() != start_generation {
            return;
        }
        // Build the gated idle commit under a read borrow. `Ok(None)` is the
        // overwhelmingly common case (Realm not yet due / before this member's
        // jitter slot / a pending commit already suppresses it).
        let built = ctx.state_store.read(|store| {
            crate::mls::runtime::build_idle_self_update_commit(
                store,
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
                    crate::mls::group_events::mls_commit_event_from_store(
                        store,
                        &realm_id,
                        &actor_id,
                        &schedule_hash,
                        &commit_envelope,
                    )
                    .map(|event| Some((event, commit_envelope.epoch, snapshot)))
                }
            })
        });
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
        // Submit the canonical ak.mls.commit. The server's expected-prev-epoch
        // CAS (§5.4) rejects the loser of any concurrent commit race; either
        // way the epoch advances, so a rejection is fine — we simply do NOT
        // persist the local snapshot (persist-on-accept).
        let submit_token = token.clone();
        match crate::transport::auth::with_authed_api(&base, submit_token, |api| async move {
            api.event_submitter()?.submit_sdk_event(&commit_event).await
        })
        .await
        {
            Ok(_) => {
                if generation.get() != start_generation {
                    // A late accept under a stale generation must not write the
                    // snapshot into the new generation's store.
                    return;
                }
                ctx.state_store
                    .write(|store| store.save_mls_snapshot(realm_id.clone(), snapshot));
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
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: &SyncEngineContext,
    deltas_since_invites: &mut u32,
) -> IterationOutcome {
    let base = ctx.base_url.clone();
    let token = ctx.token.get();
    if base.trim().is_empty() || token.trim().is_empty() {
        return IterationOutcome::NotReady;
    }
    #[cfg(target_arch = "wasm32")]
    if let Err(error) = crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson").await
    {
        return IterationOutcome::Transient(format!(
            "sync_engine: secure key store is not ready for authenticated sync: {error}"
        ));
    }

    // ②(A+②): `token` is the `ak.session.grant`; every self-path sync request
    // must include the grant-binding (DPoP) key instead of falling back to a bare
    // bearer request that the server will reject.
    let api = match crate::transport::auth::authed_api(&base, token.clone()) {
        Ok(api) => api,
        Err(error) => {
            return IterationOutcome::Transient(format!(
                "sync_engine: authenticated API unavailable: {error}"
            ));
        }
    };

    // Read cursor freshly each iteration — login strand / server switch
    // may have cleared it underneath us.
    let cursor = ctx.state_store.read(|store| {
        store
            .load()
            .sync_cursor
            .clone()
            .filter(|c| !c.trim().is_empty())
    });
    let is_full_sync = cursor.is_none();

    let sdk_http = match api.sdk_http_client() {
        Ok(client) => client,
        Err(error) => {
            return IterationOutcome::Transient(format!(
                "sync_engine: SDK account subscribe client unavailable: {error}"
            ));
        }
    };

    if !ctx.account_did.trim().is_empty() {
        let submitter = crate::event_submit::EventSubmitter::new(sdk_http.clone());
        match submitter.drain_outbound(ctx.account_did.trim()).await {
            Ok(completed) if completed > 0 => {
                tracing::debug!(completed, "sync engine drained durable outbound events");
            }
            Ok(_) => {}
            Err(error) => {
                tracing::debug!(?error, "sync engine deferred durable outbound drain");
            }
        }
    }

    match crate::client_core::account_subscribe_snapshot_outcome(&sdk_http, cursor.as_deref()).await
    {
        Ok(AccountSubscribeSnapshotResult::Delta(response)) => {
            // Late-arriving response from a stale generation must not
            // overwrite signals owned by the new generation. The
            // state_store write below is still safe because it's keyed
            // by content, but the UI signals are not.
            if generation.get() != start_generation {
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
                let latest_token = ctx.token.get();
                let invite_api = if !latest_token.trim().is_empty() && latest_token != token {
                    api.clone().with_bearer(latest_token)
                } else {
                    api.clone()
                };
                match async {
                    crate::transport::account::invites(&invite_api.sdk_http_client()?).await
                }
                .await
                {
                    Ok(response) => {
                        *deltas_since_invites = 0;
                        // The notification pipeline folds invites through lenient
                        // `Value` accessors; project the typed `Invite` rows back
                        // to their wire JSON.
                        Some(
                            response
                                .invites
                                .into_iter()
                                .filter_map(|invite| serde_json::to_value(invite).ok())
                                .collect::<Vec<Value>>(),
                        )
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
            // event projections) can't be written into the new generation's store and UI
            // signals. The generation bump covers the profile/server switch case.
            if generation.get() != start_generation {
                return IterationOutcome::Ok {
                    realm_ids: Vec::new(),
                };
            }
            apply_response(&response, is_full_sync, ctx, invite_notifications);
            // Receiver side of `ak.call.signal` (async, needs the directory):
            // verify each inbound envelope's proof against the sender's
            // authoritative verify key and route only verified signals
            // (fail-closed). Done here, not inside the synchronous
            // `apply_response`, because the directory query is async.
            route_inbound_call_signals(&api, &response, ctx).await;
            let state_store_for_profiles = ctx.state_store.clone();
            if prefetch_persistent_event_sender_keys(
                &api,
                &response,
                ctx.did_cache.clone(),
                |realm_id| {
                    state_store_for_profiles
                        .read(|store| store.realm_projection_is_minimal_metadata(realm_id))
                },
            )
            .await
            {
                refresh_projection_events_from_sync_response(&response, is_full_sync, ctx);
            }
            // MID-5: prime the authoritative device signing keys for every
            // `ak.member.identity.update` asserter in this response so the
            // synchronous `MemberIdentityStore::current_identity` proof verifier
            // can resolve them (a Miss is fail-closed → the identity would be
            // dropped). Keyed by the proof `verification_method` (`actor#device`).
            prefetch_member_identity_proof_keys(&api, &response, ctx.did_cache.clone()).await;
            if let Err(error) = process_to_device_delivery(&api, &response, ctx).await {
                if is_auth_expired_error(&error) {
                    return IterationOutcome::AuthExpired;
                }
                return IterationOutcome::Transient(format!("sync_engine to-device: {error}"));
            }
            if let Err(error) = poll_device_message_queue(&api, ctx).await {
                if is_auth_expired_error(&error) {
                    return IterationOutcome::AuthExpired;
                }
                return IterationOutcome::Transient(format!("sync_engine to-device poll: {error}"));
            }
            IterationOutcome::Ok {
                realm_ids: response.realms.keys().cloned().collect(),
            }
        }
        Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
            reconnect_after_ms,
            reconnect_cursor,
            reason,
            reset_cursor,
        }) => {
            if reset_cursor {
                ctx.state_store.write(LocalStateStore::clear_sync_cursor);
                ctx.projection_sink
                    .projection(ClientProjectionEvent::CursorReset {
                        scope: "account".to_owned(),
                    });
            } else if let Some(cursor) = reconnect_cursor {
                // §1.1 rule 4 — a validated `dropped` cursor IS the reconnect
                // position: persist it so the next subscribe resumes there
                // instead of replaying from the stale pre-drop cursor.
                ctx.state_store
                    .write(|store| store.save_sync_cursor(cursor.clone()));
                ctx.projection_sink
                    .projection(ClientProjectionEvent::CursorCheckpoint {
                        scope: "account".to_owned(),
                        cursor,
                    });
            }
            IterationOutcome::ReconnectAfter {
                reconnect_after_ms,
                reason,
            }
        }
        Err(error) if is_terminal_session_grant_error(&error) => {
            ctx.session.invalidate("session grant is no longer active");
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
            ctx.state_store.write(LocalStateStore::clear_sync_cursor);
            ctx.projection_sink
                .projection(ClientProjectionEvent::CursorReset {
                    scope: "account".to_owned(),
                });
            IterationOutcome::InvalidCursor
        }
        Err(error) if is_stale_frontier_error(&error) => {
            // client-sync.md §4 / §12.3: stale_frontier keeps the
            // cursor. Refresh the service frontier via account/describe
            // (step 2 of the recovery strand) before retrying with the
            // SAME cursor; failures here are best-effort — the retry
            // itself is the recovery.
            if let Err(describe_error) =
                async { crate::transport::account::sync_describe(&api.sdk_http_client()?).await }
                    .await
            {
                tracing::debug!(
                    ?describe_error,
                    "stale_frontier recovery: account/describe failed"
                );
            }
            let selected_realm_id = ctx.selected_realm_id.get();
            if !selected_realm_id.is_empty() {
                if let Ok(http) = api.sdk_http_client() {
                    let snapshot_clients = crate::transport::EndpointClients::from_http(http);
                    match snapshot_clients
                        .directory()
                        .snapshot_head(&selected_realm_id)
                        .await
                    {
                        Ok(Some(manifest)) => {
                            tracing::debug!(
                                realm_id = %selected_realm_id,
                                snapshot_id = %manifest.id,
                                "stale_frontier recovery: snapshot head available for replay fallback"
                            );
                        }
                        Ok(None) => {
                            ctx.state_store.write(|store| {
                                store.mark_snapshot_degraded(
                                    selected_realm_id.clone(),
                                    "snapshot head unavailable after stale_frontier",
                                )
                            });
                        }
                        Err(snapshot_error) => {
                            tracing::debug!(
                                ?snapshot_error,
                                realm_id = %selected_realm_id,
                                "stale_frontier recovery: snapshot head probe failed"
                            );
                            ctx.state_store.write(|store| {
                                store.mark_snapshot_degraded(
                                    selected_realm_id.clone(),
                                    format!("snapshot head probe failed: {snapshot_error}"),
                                )
                            });
                        }
                    }
                }
            }
            IterationOutcome::StaleFrontier
        }
        Err(error) => IterationOutcome::Transient(format!("sync_engine: {error}")),
    }
}

/// Async receiver pass for inbound `ak.call.signal`: for each realm body,
/// verify every call-signal envelope's `proof` against the sender's
/// authoritative directory verify key (`device_directory`) and route only
/// verified signals into the call-signal hub (fail-closed). Runs after the
/// synchronous `apply_response` because directory resolution needs `keys/query`.
async fn route_inbound_call_signals(
    api: &TransportClient,
    response: &ClientSyncOutcome,
    ctx: &SyncEngineContext,
) {
    let account_did = ctx.account_did.clone();
    let mut hub = ctx.call_signal_hub;
    let did_cache = ctx.did_cache.clone();

    // Tier-2 (device-lifecycle.md §8.3): the call-signal receiver verifies the
    // sender device key's full cross-signing chain, which needs the sender's
    // DID document. Build a resolver-backed anchor from a snapshot of the
    // session DID cache so the SAME authority-grade resolver / cache that login
    // and trust UI use also governs device-key trust. The anchor back-fills
    // resolved documents into its private cache copy; write it back afterwards
    // so subsequent iterations reuse it.
    let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        did_cache.get(),
    );

    for (id, body) in &response.realms {
        // Retained in `views::call_signals` on purpose: this router operates
        // on `&mut CallSignalHub`, which owns Dioxus `Signal` state and is
        // deliberately kept in the view layer (YGN-ARCH-01). Relocating the
        // router without the hub would gain nothing, so both stay together.
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

    did_cache.set(anchor.into_cache());
}

/// Prime the same device-directory cache used by the synchronous chat proof
/// verifier for proof-bearing persistent events in the current sync response.
/// Chat projection cannot await `keys/query` inline, so `apply_response` first
/// renders unresolved proofs conservatively; this pass resolves missing sender
/// device keys and the caller then recomputes the projection.
///
/// SPI-INK-001 (encryption-and-audit.md §2.10.3): Realms for which
/// `is_minimal_metadata_realm(realm_id)` returns true are excluded — content
/// authorship there is anchored to the active MLS LeafNode and MUST NOT form
/// a principal-scoped `(actor, device)` `keys/query` pair.
pub(crate) async fn prefetch_persistent_event_sender_keys(
    api: &TransportClient,
    response: &ClientSyncOutcome,
    did_cache: crate::runtime::input::ValueCell<crate::identity::did_resolver::DidResolutionCache>,
    is_minimal_metadata_realm: impl Fn(&str) -> bool,
) -> bool {
    let pairs = collect_persistent_proof_sender_devices(response, &is_minimal_metadata_realm);
    prefetch_persistent_event_sender_key_pairs(api, pairs, did_cache).await
}

/// MID-5: resolve the authoritative device signing key for every
/// `ak.member.identity.update` asserter referenced by this sync response, so the
/// synchronous [`crate::identity::member_identity_store::MemberIdentityStore`] proof
/// verifier (which is cache-only and fail-closed) can validate the proofs. The
/// `(actor, device)` pair is derived from each proof's `verification_method`
/// (`did:method:identifier#device`); the controller MUST be the asserting actor.
async fn prefetch_member_identity_proof_keys(
    api: &TransportClient,
    response: &ClientSyncOutcome,
    did_cache: crate::runtime::input::ValueCell<crate::identity::did_resolver::DidResolutionCache>,
) -> bool {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for (_realm_id, body) in &response.realms {
        collect_member_identity_proof_devices_from_value(body, 0, &mut pairs);
    }
    prefetch_persistent_event_sender_key_pairs(api, pairs.into_iter().collect(), did_cache).await
}

/// Recursively scan a projection `Value` for `ak.member.identity.update`
/// proofs, extracting `(controller_id, device_id)` from each
/// `member_identity.proof.verification_method`. Depth-bounded to mirror the
/// persistent-event scanner.
fn collect_member_identity_proof_devices_from_value(
    value: &Value,
    depth: usize,
    out: &mut BTreeSet<(String, String)>,
) {
    const MAX_DEPTH: usize = 12;
    if depth > MAX_DEPTH {
        return;
    }
    match value {
        Value::Object(map) => {
            // A `member_identity` object carries `actor_id` + `proof`.
            if let Some(proof) = map.get("proof").and_then(Value::as_object)
                && let Some(vm) = proof.get("verification_method").and_then(Value::as_str)
                && let Some((controller, device)) = split_verification_method(vm)
            {
                // Bind to the object's own actor_id when present (defence in
                // depth: the controller already equals the asserter at verify
                // time, but we prefetch whatever the proof names so resolution
                // can run).
                out.insert((controller, device));
            }
            for nested in map.values() {
                collect_member_identity_proof_devices_from_value(nested, depth + 1, out);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_member_identity_proof_devices_from_value(item, depth + 1, out);
            }
        }
        _ => {}
    }
}

/// Split a `did:method:identifier#device` verification-method URL into its
/// controller DID and device fragment. Returns `None` when there is no
/// fragment (no device selector).
fn split_verification_method(verification_method: &str) -> Option<(String, String)> {
    let (controller, fragment) = verification_method.split_once('#')?;
    let controller = controller
        .split_once('?')
        .map_or(controller, |(head, _)| head)
        .trim();
    let device = fragment.trim();
    if controller.is_empty() || device.is_empty() {
        return None;
    }
    Some((controller.to_owned(), device.to_owned()))
}

pub(crate) async fn prefetch_persistent_event_sender_keys_from_values(
    api: &TransportClient,
    values: &[Value],
    did_cache: crate::runtime::input::ValueCell<crate::identity::did_resolver::DidResolutionCache>,
) -> bool {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for value in values {
        collect_proof_sender_devices_from_value(value, 0, &mut pairs);
    }
    prefetch_persistent_event_sender_key_pairs(api, pairs.into_iter().collect(), did_cache).await
}

/// Public alias of [`prefetch_persistent_event_sender_key_pairs`] for callers
/// outside the persistent-event projection path (e.g. the history-share install
/// loop priming `ak.realm_key.share` sender device keys before SEC-02
/// fail-closed verification).
pub(crate) async fn prefetch_device_key_pairs(
    api: &TransportClient,
    pairs: Vec<(String, String)>,
    did_cache: crate::runtime::input::ValueCell<crate::identity::did_resolver::DidResolutionCache>,
) -> bool {
    prefetch_persistent_event_sender_key_pairs(api, pairs, did_cache).await
}

async fn prefetch_persistent_event_sender_key_pairs(
    api: &TransportClient,
    pairs: Vec<(String, String)>,
    did_cache: crate::runtime::input::ValueCell<crate::identity::did_resolver::DidResolutionCache>,
) -> bool {
    if pairs.is_empty() {
        return false;
    }
    let missing: Vec<(String, String)> = pairs
        .into_iter()
        .filter(|(actor, device)| {
            matches!(
                crate::identity::device_directory::cached_device_signing_key(actor, device),
                crate::identity::device_directory::CacheLookup::Miss
            )
        })
        .collect();
    if missing.is_empty() {
        return false;
    }

    let mut did_cache = did_cache;
    let anchor = crate::identity::did_resolver::ResolverDidAnchor::from_profile(
        crate::identity::did_resolver::DeploymentProfile::PersonalNode,
        did_cache.get(),
    );
    crate::identity::device_directory::prefetch_device_keys(api, &anchor, &missing).await;
    did_cache.set(anchor.into_cache());
    true
}

fn refresh_projection_events_from_sync_response(
    response: &ClientSyncOutcome,
    is_full_sync: bool,
    ctx: &SyncEngineContext,
) {
    let state_store = ctx.state_store.clone();
    let account_did = ctx.account_did.clone();
    let device_id = ctx.device_id.clone();
    let synced_projection_events = state_store.read(|store| {
        crate::state::projection::projection_events_from_sync_realms(
            &response.realms,
            Some(store),
            Some((&account_did, &device_id)),
        )
    });
    if is_full_sync {
        ctx.projection_sink.projection(ClientProjectionEvent::Reset);
    }
    for event in synced_projection_events {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Account(event));
    }
}

fn collect_persistent_proof_sender_devices(
    response: &ClientSyncOutcome,
    is_minimal_metadata_realm: &impl Fn(&str) -> bool,
) -> Vec<(String, String)> {
    let mut pairs = BTreeSet::<(String, String)>::new();
    for (realm_id, body) in &response.realms {
        // §2.10.3 — a minimal-metadata Realm's content authorship never forms
        // a directory pair; its authors verify against the MLS LeafNode.
        if is_minimal_metadata_realm(realm_id) {
            continue;
        }
        collect_proof_sender_devices_from_value(body, 0, &mut pairs);
    }
    pairs.into_iter().collect()
}

fn collect_proof_sender_devices_from_value(
    value: &Value,
    depth: usize,
    pairs: &mut BTreeSet<(String, String)>,
) {
    if depth > 32 {
        return;
    }
    match value {
        Value::Object(object) => {
            if let Some((actor, device)) = proof_bearing_sender_device(object) {
                pairs.insert((actor, device));
            }
            for child in object.values() {
                collect_proof_sender_devices_from_value(child, depth + 1, pairs);
            }
        }
        Value::Array(values) => {
            for child in values {
                collect_proof_sender_devices_from_value(child, depth + 1, pairs);
            }
        }
        _ => {}
    }
}

fn proof_bearing_sender_device(
    object: &serde_json::Map<String, Value>,
) -> Option<(String, String)> {
    object
        .get("proofs")
        .and_then(Value::as_array)
        .filter(|proofs| !proofs.is_empty())?;
    let actor = object
        .get("actor_id")
        .or_else(|| object.get("sender_actor_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|actor| !actor.is_empty())?;
    let device = object
        .get("device_id")
        .or_else(|| object.get("sender_device_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|device| !device.is_empty())
        .map(str::to_owned)
        .or_else(|| proof_sender_device_from_verification_method(object, actor))?;
    Some((actor.to_owned(), device))
}

fn proof_sender_device_from_verification_method(
    object: &serde_json::Map<String, Value>,
    actor: &str,
) -> Option<String> {
    object
        .get("proofs")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|proof| proof.get("verification_method").and_then(Value::as_str))
        .find_map(|method| {
            let no_query = method
                .split_once('?')
                .map(|(head, _)| head)
                .unwrap_or(method);
            let (controller, fragment) = no_query.split_once('#')?;
            (controller == actor && fragment.starts_with("ak:device:")).then(|| fragment.to_owned())
        })
}

/// Apply an account subscribe response: persist projections (server-authoritatively
/// reconciled when full-sync), hydrate Seal views + account-data, and
/// publish derived UI signals (realm tree nodes / event projections / device queue /
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
    // Clone runtime adapter handles before applying this response.
    let state_store = ctx.state_store.clone();
    let did_cache = ctx.did_cache.clone();
    let account_did = ctx.account_did.clone();
    let mut synced_theme = None;

    // Y2 invalidation hook: scan identity events in this response before writing
    // projections. On `ak.cross_signing.reset` / `ak.device.revoke`, invalidate
    // the related actor DID so the next authority resolution (`resolve_with_cache`)
    // walks the resolver chain instead of trusting a stale cache entry (old key
    // set). Keep this separate from the state-store write callback.
    did_cache.update(|cache| {
        for body in response.realms.values() {
            invalidate_cache_for_revocation_events(cache, body);
        }
    });

    state_store.write(|store| {
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
                ingest_kanban_state_events_from_projection(store, id, body);
                ingest_discussion_state_events_from_projection(store, id, body);
                ingest_membership_events_from_projection(store, id, body);
                // Fold the discussion timeline into `raw_operations` too so the
                // card-detail Discussion tab renders local-first instead of
                // refetching + redecrypting the realm on every open.
                ingest_message_events_from_projection(store, id, body);
                // R3.1 MID-2 — harvest inlined `ak.member.identity.update`
                // event envelopes off the `members[]` roster entries. The
                // SDK's effective-set filter is applied lazily when a UI
                // surface needs to resolve a display identity.
                ingest_member_identity_events_from_projection(store, id, body);
            }
            crate::disappearing::shred_expired_message_plaintext_from_sync_realms(
                store,
                &response.realms,
            );

            synced_theme = apply_account_data(store, response, &account_did);
            apply_notification_projection(store, response, invite_notifications);
            store.save_presence_projection(response.presence.clone());
            store.ingest_to_device_messages(&response.to_device);
            if cursor_can_advance {
                store.save_sync_cursor(response.cursor.clone());
            }
        }); // store.batch — single coalesced flush happens here
    });
    if let Some(value) = synced_theme {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Theme { value });
    }

    // Receive side of `ak.call.signal`: route inbound call-signal envelopes
    // from each realm body into the hub (dedup → incoming ring / per-call
    // inbox). Done after the `store` write guard is dropped so the hub Signal
    // writes don't nest inside the store borrow.
    //
    // NB: receiver proof verification + directory resolve for inbound
    // `ak.call.signal` is async (needs `keys/query`); it cannot run here
    // because `apply_response` is synchronous and holds no authenticated
    // client. The async routing pass lives in `run_iteration`
    // (`route_inbound_call_signals`) right after this call returns.

    // Realm tree nodes are derived in the app projection adapter from the
    // canonical local-state projection; the engine only computes a snapshot
    // for status and selected-Realm bookkeeping.
    let reconciled = state_store.read(|store| {
        crate::app::realm_tree_nodes_from_sync_realms(&store.load().realm_tree_projections)
    });
    ctx.projection_sink.sync_status(SyncStatusEvent::Online);
    let first_realm = reconciled
        .iter()
        .find(|node| node.kind == RealmTreeNodeKind::Realm)
        .map(|node| node.id.clone());
    {
        let current = ctx.selected_realm_id.get();
        let trimmed = current.trim();
        let needs_reset = trimmed.is_empty() || !reconciled.iter().any(|node| node.id == trimmed);
        if needs_reset {
            ctx.projection_sink
                .projection(ClientProjectionEvent::SelectedRealm {
                    realm_id: first_realm.unwrap_or_default(),
                });
        }
    }

    // Merge encrypted bodies on read (author sidecar → remote decrypt-on-read).
    // The `store` write guard above is out of scope; take a fresh read guard.
    let device_id = ctx.device_id.clone();
    let synced_projection_events = state_store.read(|store| {
        crate::state::projection::projection_events_from_sync_realms(
            &response.realms,
            Some(store),
            Some((&account_did, &device_id)),
        )
    });
    if is_full_sync {
        ctx.projection_sink.projection(ClientProjectionEvent::Reset);
    }
    for event in synced_projection_events {
        ctx.projection_sink
            .projection(ClientProjectionEvent::Account(event));
    }

    ctx.projection_sink
        .projection(ClientProjectionEvent::DeviceQueue {
            pending: state_store.read(|store| store.load().to_device_inbox.len()),
        });
    if to_device_batch_allows_cursor_advance(&response.to_device, response.to_device_limited) {
        ctx.projection_sink
            .projection(ClientProjectionEvent::CursorCheckpoint {
                scope: "account".to_owned(),
                cursor: response.cursor.clone(),
            });
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
/// `ak.member.identity.update` envelope is recorded on the
/// `LocalStateStore` keyed by `(realm_id, actor_id)`. Also handles the
/// canonical `state.events[]` form where the roster only carries
/// `identity_event_ids[]` and the events themselves live in the
/// frame-level event log.
async fn process_to_device_delivery(
    api: &TransportClient,
    response: &ClientSyncOutcome,
    ctx: &SyncEngineContext,
) -> anyhow::Result<()> {
    let key_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let keys = key_clients.keys();
    let mut ack_safe_prefix = to_device_batch_all_ack_safe(&response.to_device)
        && ctx
            .state_store
            .read(|store| store.persist_error().is_none());
    if ack_safe_prefix
        && !response.to_device.is_empty()
        && let Some(ack_token) = response.to_device_ack_token.as_deref()
    {
        keys.ack_device_messages(ack_token).await?;
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
        let page = keys
            .receive_device_messages_page(Some(&cursor), Some(TO_DEVICE_PAGE_LIMIT))
            .await?;
        let messages = device_messages_get_values(&page)?;
        let persisted = ctx.state_store.write(|store| {
            store.ingest_to_device_messages(&messages);
            store.persist_error().is_none()
        });
        if !persisted || !to_device_batch_all_ack_safe(&messages) {
            ack_safe_prefix = false;
        }
        if ack_safe_prefix
            && !messages.is_empty()
            && let Some(ack_token) = page.ack_token.as_deref()
        {
            keys.ack_device_messages(ack_token).await?;
        }
        if !(page.has_more || page.limited) {
            break;
        }
        next_cursor = page.next_cursor.clone();
        if next_cursor.is_none() {
            anyhow::bail!("to-device page reported more data without next_cursor");
        }
    }
    ctx.projection_sink
        .projection(ClientProjectionEvent::DeviceQueue {
            pending: ctx
                .state_store
                .read(|store| store.load().to_device_inbox.len()),
        });
    Ok(())
}

async fn poll_device_message_queue(
    api: &TransportClient,
    ctx: &SyncEngineContext,
) -> anyhow::Result<()> {
    let key_clients = crate::transport::EndpointClients::from_http(api.sdk_http_client()?);
    let keys = key_clients.keys();
    let first_page = keys.receive_device_messages().await?;
    ingest_device_message_pages(&keys, first_page, ctx).await
}

async fn ingest_device_message_pages(
    keys: &crate::transport::KeysEndpoints<'_>,
    first_page: DeviceMessagesGetOutcome,
    ctx: &SyncEngineContext,
) -> anyhow::Result<()> {
    let mut page = first_page;
    let mut page_count = 0usize;
    loop {
        let messages = device_messages_get_values(&page)?;
        let persisted = ctx.state_store.write(|store| {
            store.ingest_to_device_messages(&messages);
            store.persist_error().is_none()
        });
        if persisted
            && to_device_batch_all_ack_safe(&messages)
            && !messages.is_empty()
            && let Some(ack_token) = page.ack_token.as_deref()
        {
            keys.ack_device_messages(ack_token).await?;
        }
        if !(page.has_more || page.limited) {
            break;
        }
        page_count += 1;
        if page_count > MAX_TO_DEVICE_BACKFILL_PAGES {
            anyhow::bail!(
                "to-device poll exceeded {MAX_TO_DEVICE_BACKFILL_PAGES} pages without finishing"
            );
        }
        let Some(cursor) = page.next_cursor.clone() else {
            anyhow::bail!("to-device poll page reported more data without next_cursor");
        };
        page = keys
            .receive_device_messages_page(Some(&cursor), Some(TO_DEVICE_PAGE_LIMIT))
            .await?;
    }
    ctx.projection_sink
        .projection(ClientProjectionEvent::DeviceQueue {
            pending: ctx
                .state_store
                .read(|store| store.load().to_device_inbox.len()),
        });
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
        kind.starts_with("ak.key.verification.")
            || kind == crate::mls::secret_share::SECRET_SHARE_KIND_REQUEST
            || kind == "ak.realm_key.request"
    })
}

fn to_device_batch_allows_cursor_advance(messages: &[Value], limited: bool) -> bool {
    !limited && to_device_batch_all_ack_safe(messages)
}

fn sync_realm_state_events(body: &Value) -> Vec<Value> {
    body.get("state")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn ingest_kanban_state_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    let events = sync_realm_state_events(body);
    ingest_kanban_projection_events(store, realm_id, &events)
}

/// Discussion message events ride a SEPARATE projection array from the kanban
/// state log: `timeline.events[]` (see `chat_messages_from_sync_realms_*`).
fn sync_realm_timeline_events(body: &Value) -> Vec<Value> {
    body.get("timeline")
        .and_then(|timeline| timeline.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Fold the realm's discussion timeline into the shared `raw_operations` log so
/// the Discussion tab projects local-first — no per-open realm backfill /
/// redecrypt — mirroring [`ingest_kanban_state_events_from_projection`].
/// Returns the number of newly inserted / changed records. Stores only
/// ciphertext envelopes / tombstones (never decrypted plaintext); dedup is by
/// the message event id via `upsert_raw_operation`.
fn ingest_message_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    ingest_message_projection_events(store, realm_id, &sync_realm_timeline_events(body))
}

fn discussion_state_control_event_kind(event: &Value) -> Option<&str> {
    event
        .get("kind")
        .or_else(|| event.get("event_kind"))
        .or_else(|| event.get("type"))
        .or_else(|| event.get("op_type"))
        .or_else(|| event.get("event_type"))
        .and_then(Value::as_str)
}

fn discussion_state_control_event_is_ingestable(event: &Value) -> bool {
    matches!(
        discussion_state_control_event_kind(event),
        Some("ak.pin.add" | "ak.pin.remove" | "ak.pin.reorder")
    )
}

fn ingest_discussion_state_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    let events = sync_realm_state_events(body)
        .into_iter()
        .filter(discussion_state_control_event_is_ingestable)
        .collect::<Vec<_>>();
    ingest_message_projection_events(store, realm_id, &events)
}

/// Fold a batch of discussion message events into `raw_operations`. Shared by
/// the account-aggregate sync path (above) and the per-realm `events/subscribe`
/// engine ([`crate::realm_events_engine`]) — a cross-member message that the
/// account stream never routed (unroutable delivery binding) still lands
/// locally through the realm stream — both deduping via the message event id.
pub(crate) fn ingest_message_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[Value],
) -> usize {
    if events.is_empty() {
        return 0;
    }
    let records =
        crate::state::projection::message_ops::message_operations_from_events(realm_id, events);
    let mut changed = 0;
    for record in records {
        if store.upsert_raw_operation(record.operation_id, record.realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

pub(crate) fn ingest_message_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> usize {
    let records = crate::state::projection::message_ops::message_operations_from_client_events(
        realm_id, events,
    );
    let mut changed = 0;
    for record in records {
        if store.upsert_raw_operation(record.operation_id, record.realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

/// Fold a batch of realm events into the local kanban `raw_operations` overlay,
/// returning the number of records that were newly inserted / changed. Shared
/// by the account-aggregate sync path (above) and the per-realm
/// `events/subscribe` engine ([`crate::realm_events_engine`]) so both sources
/// dedupe through the same `operation_id` upsert. Events are the projection
/// event JSON shape (`event_kind` / `payload` / `operation_id`), matching both
/// `account.subscribe` `state.events[]` and `events/subscribe` Event frames.
pub(crate) fn ingest_kanban_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[Value],
) -> usize {
    if events.is_empty() {
        return 0;
    }
    // Single ingest funnel: fold EVERY kanban-relevant kind (space.create,
    // strand.create, strand.update, strand.move/reorder, strand.archive/restore,
    // relation.*) into `raw_operations` so the event-sourced `project_board`
    // sees the full log. The prior code ingested only strand.update +
    // space.create, which silently dropped remote `ak.strand.create` — the
    // root cause of cross-member cards never appearing.
    let records = crate::state::projection::kanban_ops::kanban_operations_from_events(events);
    let mut changed = 0;
    for record in records {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

pub(crate) fn ingest_kanban_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> usize {
    let records =
        crate::state::projection::kanban_ops::kanban_operations_from_client_events(events);
    let mut changed = 0;
    for record in records {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

fn sync_event_string(value: Option<&Value>, path: &[&str]) -> Option<String> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn membership_operation_from_event(event: &Value) -> Option<RawOperationRecord> {
    let kind = sync_event_string(Some(event), &["event_kind"])
        .or_else(|| sync_event_string(Some(event), &["kind"]))?;
    if !matches!(kind.as_str(), "ak.member.state" | "ak.invite.accept") {
        return None;
    }
    let body = event
        .get("payload")
        .or_else(|| event.get("content"))
        .cloned()
        .unwrap_or(Value::Null);
    let event_id = sync_event_string(Some(event), &["event_id"])?;
    let operation_id =
        sync_event_string(Some(event), &["operation_id"]).unwrap_or_else(|| event_id.clone());
    let actor_id = sync_event_string(Some(event), &["actor_id"])
        .or_else(|| sync_event_string(Some(event), &["sender_actor_id"]))
        .or_else(|| sync_event_string(Some(&body), &["actor_id"]))
        .or_else(|| sync_event_string(Some(&body), &["sender_actor_id"]))
        .or_else(|| sync_event_string(Some(&body), &["sender"]))
        .unwrap_or_default();
    let created_at = sync_event_string(Some(event), &["created_at"])
        .or_else(|| sync_event_string(Some(&body), &["created_at"]))
        .unwrap_or_default();
    let received_at = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    let mut payload = json!({
        "kind": kind,
        "operation_id": operation_id,
        "actor_id": actor_id,
        "created_at": created_at,
        "write_state": "synced",
        "body": body,
    });
    if let Some(object) = payload.as_object_mut() {
        object.insert("event_id".to_owned(), Value::String(event_id));
    }

    Some(RawOperationRecord {
        operation_id: payload
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or("remote-membership")
            .to_owned(),
        realm_id: sync_event_string(Some(event), &["realm_id"])
            .or_else(|| sync_event_string(payload.get("body"), &["realm_id"]))
            .or_else(|| sync_event_string(payload.get("body"), &["object", "realm_id"])),
        received_at,
        payload,
    })
}

pub(crate) fn ingest_membership_projection_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[Value],
) -> usize {
    if events.is_empty() {
        return 0;
    }
    let mut changed = 0;
    for record in events.iter().filter_map(membership_operation_from_event) {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

fn membership_operation_from_client_event(
    client_event: &garth::ClientEvent,
) -> Option<RawOperationRecord> {
    let event = match client_event {
        garth::ClientEvent::Message(message) => &message.event,
        garth::ClientEvent::Event(event) => event,
        _ => return None,
    };
    let kind = event.kind.as_str();
    if !matches!(kind, "ak.member.state" | "ak.invite.accept") {
        return None;
    }
    let operation_id = event.event_id.as_str().to_owned();
    Some(RawOperationRecord {
        operation_id: operation_id.clone(),
        realm_id: Some(event.realm_id.as_str().to_owned()),
        received_at: event.created_at,
        payload: json!({
            "kind": kind,
            "operation_id": operation_id,
            "event_id": event.event_id.as_str(),
            "actor_id": event.actor_id.as_str(),
            "created_at": event.created_at.to_rfc3339(),
            "write_state": "synced",
            "body": event.payload,
        }),
    })
}

pub(crate) fn ingest_membership_events(
    store: &mut LocalStateStore,
    realm_id: &str,
    events: &[garth::ClientEvent],
) -> usize {
    let mut changed = 0;
    for record in events
        .iter()
        .filter_map(membership_operation_from_client_event)
    {
        let operation_id = record.operation_id;
        let record_realm_id = record.realm_id.or_else(|| Some(realm_id.to_owned()));
        if store.upsert_raw_operation(operation_id, record_realm_id, record.payload) {
            changed += 1;
        }
    }
    changed
}

fn ingest_membership_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) -> usize {
    ingest_membership_projection_events(store, realm_id, &sync_realm_state_events(body))
}

fn ingest_member_identity_events_from_projection(
    store: &mut LocalStateStore,
    realm_id: &str,
    body: &Value,
) {
    // Build a quick lookup over the canonical `state.events[]` array on the
    // projection so that referenced identity_event_ids can be resolved
    // without a separate query.
    let state_log_events = sync_realm_state_events(body);
    let state_events: BTreeSet<String> = state_log_events
        .iter()
        .filter_map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let state_event_by_id: std::collections::BTreeMap<String, Value> = state_log_events
        .iter()
        .filter_map(|event| {
            event
                .get("event_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), event.clone()))
        })
        .collect();

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
            // a `ak.self.events.query.scan` backfill will catch up.
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
/// Finds `ak.cross_signing.reset` / `ak.device.revoke` events in one Realm
/// projection `body`, then calls
/// [`crate::identity::did_resolver::DidResolutionCache::invalidate`] for the related actor
/// DID. Events may appear in:
/// - inline `identity_events[]` on each member roster entry;
/// - projection event logs at `state.events[]`.
///
/// Actor DID is read from the event `actor_id` / `did`, falling back to the
/// roster entry `actor_id` / `did`. Forbidden `actor` / `sender` fields are
/// ignored. The value is validated via `Did::new`; invalid DID syntax is
/// skipped because this best-effort invalidation hook must not panic.
///
/// TRUST-CACHE boundary: this only clears cache entries so the next resolution
/// walks the authority chain again; it does not replace authority validation.
fn invalidate_cache_for_revocation_events(
    cache: &mut crate::identity::did_resolver::DidResolutionCache,
    body: &Value,
) {
    /// Return whether the event kind is reset / revoke.
    fn is_revocation_kind(event: &Value) -> bool {
        let kind = event
            .get("kind")
            .and_then(Value::as_str)
            .or_else(|| event.get("type").and_then(Value::as_str))
            .unwrap_or("");
        kind == "ak.cross_signing.reset" || kind == "ak.device.revoke"
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
        cache: &mut crate::identity::did_resolver::DidResolutionCache,
        events: &[Value],
        fallback: Option<&Value>,
    ) {
        for event in events {
            if !is_revocation_kind(event) {
                continue;
            }
            if let Some(did_str) = actor_id_str(event, fallback)
                && let Ok(did) = arkret_sdk::Did::new(did_str.to_owned())
            {
                cache.invalidate(&did);
            }
        }
    }

    // Scan the canonical top-level `state[]` event log.
    let state_events = sync_realm_state_events(body);
    invalidate_from_events(cache, &state_events, None);

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
        crate::state::projection::notifications::notification_items_from_value(
            &response.notifications,
        );
    let account_notification_projection = response
        .account_data
        .iter()
        .filter(|entry| {
            crate::state::projection::notifications::is_notification_account_data(entry)
        })
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
        crate::state::projection::notifications::merge_invite_notifications(
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
) -> Option<String> {
    let mut synced_theme = None;
    for entry in &response.account_data {
        let Some(data_type) = entry.get("data_type").and_then(Value::as_str) else {
            continue;
        };
        // client.ui — theme + avatar pointer.
        if data_type == "client.ui" {
            if let Some(content) = entry.get("content") {
                let local_theme = store
                    .load_private_data(account_did, "theme")
                    .unwrap_or_else(|| "night".to_owned());
                if let Some(remote_theme) =
                    crate::account_data::merge_client_ui_theme(&local_theme, content)
                {
                    store.save_private_data(account_did, "theme", remote_theme.clone());
                    synced_theme = Some(remote_theme);
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
        // ak.account.blocklist — personal block list.
        if data_type == "ak.presence.visibility" {
            let Some(visibility) = entry
                .get("content")
                .and_then(|content| content.get("presence_visibility"))
                .and_then(Value::as_str)
                .and_then(crate::state::PresenceVisibility::try_from_wire)
            else {
                tracing::warn!(
                    "sync engine: ignoring malformed ak.presence.visibility account_data"
                );
                continue;
            };
            store.set_presence_visibility(visibility);
            continue;
        }
        // ak.presence.preference — manual presence preference
        // (profiles-presence.md §3.6). The server stores only the standard
        // account-data AEAD envelope; decrypt before applying it locally.
        if data_type == "ak.presence.preference" {
            match crate::account_data::decrypt_account_data_entry(account_did, data_type, entry)
                .and_then(|content| serde_json::from_value(content).map_err(Into::into))
            {
                Ok(preference) => store.set_presence_preference(preference),
                Err(error) => tracing::warn!(
                    "sync engine: ignoring undecryptable ak.presence.preference: {error}"
                ),
            }
            continue;
        }
        if data_type == "ak.dnd_schedule" {
            match crate::account_data::decrypt_account_data_entry(account_did, data_type, entry) {
                Ok(content) => store.set_notification_dnd_settings(
                    crate::notification_rules::parse_dnd_settings(&content),
                ),
                Err(error) => {
                    tracing::warn!("sync engine: ignoring undecryptable ak.dnd_schedule: {error}")
                }
            }
            continue;
        }
        if data_type == "ak.account.blocklist" {
            match crate::account_data::decrypt_account_data_entry(account_did, data_type, entry)
                .and_then(|content| {
                    crate::account_data::blocklist_entries_from_account_data(&content)
                        .map_err(anyhow::Error::msg)
                }) {
                Ok(entries) => store.set_client_blocklist(entries),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed ak.account.blocklist account_data: {error}",
                    );
                }
            }
            continue;
        }
        // ak.contacts.actor.<did> — actor-private contact remarks.
        if let Some(actor_id) = crate::account_data::actor_id_from_contact_remark_key(data_type) {
            match crate::account_data::decrypt_account_data_entry(account_did, data_type, entry)
                .and_then(|content| serde_json::from_value(content).map_err(Into::into))
            {
                Ok(remark) => store.set_contact_remark(actor_id.to_owned(), remark),
                Err(error) => {
                    tracing::warn!(
                        "sync engine: ignoring malformed Contact remark for {actor_id}: {error}",
                    );
                }
            }
            continue;
        }
        // ak.contacts.realm.<realm_id> — actor-private Realm remarks.
        let Some(realm_id) = crate::account_data::realm_id_from_realm_remark_key(data_type) else {
            continue;
        };
        match crate::account_data::decrypt_account_data_entry(account_did, data_type, entry)
            .and_then(|content| serde_json::from_value(content).map_err(Into::into))
        {
            Ok(remark) => store.set_realm_remark(realm_id.to_owned(), remark),
            Err(error) => {
                tracing::warn!(
                    "sync engine: ignoring malformed Realm remark for {realm_id}: {error}",
                );
            }
        }
    }
    synced_theme
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
            "inkson-engine-{tag}-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        LocalStateStore::with_path(path)
    }

    fn sdk_realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000000").unwrap()
    }

    fn sdk_actor_id() -> arkret_sdk::Did {
        arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn sdk_event(kind: &str, payload: Value) -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            kind,
            sdk_realm_id(),
            sdk_actor_id(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn minimal_metadata_realms_never_form_directory_prefetch_pairs() {
        // §2.10.3 / SPI-INK-001: a proof-bearing persistent event inside a
        // minimal-metadata Realm must not contribute an `(actor, device)`
        // `keys/query` prefetch pair; the same shape in an ordinary Realm
        // does. This is the receiver-side "principal_directory_queries = 0"
        // guarantee — no pair, no query.
        let pairwise_envelope = json!({
            "actor_id": "did:key:z6MkpairwiseAlice",
            "device_id": "ak:device:0196419b-0000-7000-8000-0000000000aa",
            "proofs": [{
                "verification_method": "did:key:z6MkpairwiseAlice#z6MkpairwiseAuthorKey"
            }],
        });
        let directory_envelope = json!({
            "actor_id": "did:webvh:z6mkfixture:bob.example",
            "device_id": "ak:device:0196419b-0000-7000-8000-0000000000bb",
            "proofs": [{
                "verification_method": "did:webvh:z6mkfixture:bob.example#key-1"
            }],
        });
        let minimal_realm = "ak:realm:0196419b-0000-7000-8000-00000000aaaa";
        let ordinary_realm = "ak:realm:0196419b-0000-7000-8000-00000000bbbb";
        let mut response = empty_response("ak:cursor:minimal-metadata");
        response.realms.insert(
            minimal_realm.to_owned(),
            json!({ "events": [pairwise_envelope] }),
        );
        response.realms.insert(
            ordinary_realm.to_owned(),
            json!({ "events": [directory_envelope] }),
        );

        let pairs = collect_persistent_proof_sender_devices(&response, &|realm_id: &str| {
            realm_id == minimal_realm
        });
        assert_eq!(
            pairs,
            vec![(
                "did:webvh:z6mkfixture:bob.example".to_owned(),
                "ak:device:0196419b-0000-7000-8000-0000000000bb".to_owned()
            )]
        );

        // Control: without the minimal-metadata classification both realms
        // would have contributed pairs.
        let all = collect_persistent_proof_sender_devices(&response, &|_: &str| false);
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn account_response_projects_client_events_and_decodes_realm_payloads() {
        let message_event = sdk_event(
            arkret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "strand_id": "ak:strand:0196419b-0000-7000-8000-000000000011",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }),
        );
        let state_event = sdk_event(
            "ak.space.create",
            json!({
                "object": {
                    "id": "ak:space:0196419b-0000-7000-8000-000000000001",
                    "schema": "ak.schema.space.v1",
                    "realm_id": sdk_realm_id().as_str(),
                    "kind": "board",
                    "title": "Adapter Board"
                }
            }),
        );
        let mut response = empty_response("ak:cursor:account-adapter");
        response.realms.insert(
            sdk_realm_id().as_str().to_owned(),
            json!({
                "timeline": {
                    "events": [serde_json::to_value(message_event).unwrap()],
                    "limited": false
                },
                "state": [serde_json::to_value(state_event).unwrap()],
                "summary": {}
            }),
        );

        let projector = AccountClientEventProjector::default();
        project_account_response_client_events(&response, &InboundDecoder::new(), &projector)
            .await
            .expect("account response projects through client-core adapter");

        let report = projector.report();
        assert_eq!(report.account_updates, 1);
        assert_eq!(report.realm_deltas, 1);
        assert_eq!(report.decoded_messages, 1);
        assert_eq!(report.decoded_events, 1);
        assert!(report.malformed_realms.is_empty());
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn account_subscription_engine_accepts_inkson_local_state_adapter() {
        let store = temp_store("subscription-engine-adapter");
        let adapter = crate::client_core::InksonLocalStateStoreAdapter::new(store);
        let engine =
            garth::SubscriptionEngine::new(garth::NativeExecutor, adapter.clone(), adapter);

        let _control = engine.control();
    }

    /// The per-realm `events/subscribe` engine ingest contract: a realistic
    /// NDJSON stream (history Event frames + `catchup_complete` + `heartbeat`)
    /// parses into typed frames, whose Event payloads fold through the SHARED
    /// [`ingest_kanban_events`] into `raw_operations` — and re-folding the same
    /// frames is idempotent (operation_id dedupe), so a buffered long-poll that
    /// re-delivers history never double-inserts.
    #[test]
    fn realm_subscribe_frames_ingest_into_raw_operations_and_dedupe() {
        use arkret_sdk::EventsSubscribeFrameKind;

        let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
        let board_id = "ak:space:0196419b-0000-7000-8000-000000000001";
        // Mirrors the server's `events/subscribe` framing: one `event` frame
        // carrying the projection-event JSON, a `catchup_complete`, a heartbeat.
        let ndjson = format!(
            "{}\n{}\n{}\n",
            json!({
                "kind": "event",
                "seq": 1,
                "cursor": "ak:cursor:realmframe1",
                "payload": {
                    "event_id": "ak:event:0196419b-0000-7000-8000-000000000101",
                    "event_kind": "ak.space.create",
                    "realm_id": realm_id,
                    "actor_id": "did:web:bob.example",
                    "created_at": "2026-06-29T00:00:00Z",
                    "operation_id": "sha256:remote-board-create",
                    "payload": {
                        "object": {
                            "id": board_id,
                            "schema": "ak.schema.space.v1",
                            "realm_id": realm_id,
                            "kind": "board",
                            "title": "Cross-member board"
                        }
                    }
                }
            }),
            json!({ "kind": "catchup_complete", "cursor": "ak:cursor:realmframe1" }),
            json!({ "kind": "heartbeat", "ts": "2026-06-29T00:00:01Z" }),
        );

        let frames = ndjson
            .lines()
            .map(|line| {
                arkret_sdk::EventsSubscribeFrame::from_ndjson_line(line)
                    .expect("events/subscribe NDJSON parses")
                    .expect("fixture lines are non-empty")
            })
            .collect::<Vec<_>>();
        // event + catchup_complete + heartbeat.
        assert_eq!(frames.len(), 3);

        let event_payloads: Vec<Value> = frames
            .iter()
            .filter(|frame| frame.kind == EventsSubscribeFrameKind::Event)
            .map(|frame| frame.payload.clone())
            .collect();
        assert_eq!(event_payloads.len(), 1);

        let mut store = temp_store("realm-subscribe-ingest");
        let changed = ingest_kanban_projection_events(&mut store, realm_id, &event_payloads);
        assert_eq!(changed, 1, "the remote space-create folds in once");
        assert_eq!(store.load().raw_operations.len(), 1);

        // Re-folding the same frames (buffered long-poll re-delivers history) is
        // idempotent: operation_id dedupe means zero new inserts.
        let changed_again = ingest_kanban_projection_events(&mut store, realm_id, &event_payloads);
        assert_eq!(changed_again, 0, "re-ingest is deduped by operation_id");
        assert_eq!(store.load().raw_operations.len(), 1);
    }

    #[test]
    fn membership_events_ingest_into_raw_operations() {
        let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
        let mut store = temp_store("membership-events");
        let changed = ingest_membership_projection_events(
            &mut store,
            realm_id,
            &[
                json!({
                    "event_id": "ak:event:0196419b-0000-7000-8000-000000000201",
                    "event_kind": "ak.member.state",
                    "realm_id": realm_id,
                    "actor_id": "did:web:alice.example",
                    "created_at": "2026-06-29T00:00:00Z",
                    "payload": {
                        "actor_id": "did:web:bob.example",
                        "membership": "join"
                    }
                }),
                json!({
                    "event_id": "ak:event:0196419b-0000-7000-8000-000000000202",
                    "kind": "ak.invite.accept",
                    "realm_id": realm_id,
                    "actor_id": "did:web:carol.example",
                    "created_at": "2026-06-29T00:00:01Z",
                    "payload": {
                        "invite_ref": "ak:invite:0196419b-0000-7000-8000-000000000301"
                    }
                }),
                json!({
                    "event_id": "ak:event:0196419b-0000-7000-8000-000000000203",
                    "kind": "ak.mls.commit",
                    "realm_id": realm_id,
                    "payload": {}
                }),
                json!({
                    "kind": "ak.member.state",
                    "realm_id": realm_id,
                    "actor_id": "did:web:dave.example",
                    "created_at": "2026-06-29T00:00:02Z",
                    "payload": {
                        "actor_id": "did:web:dave.example",
                        "membership": "join"
                    }
                }),
            ],
        );

        assert_eq!(changed, 2);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 2);
        assert_eq!(state.raw_operations[0].payload["kind"], "ak.member.state");
        assert_eq!(
            state.raw_operations[0].payload["body"]["membership"],
            "join"
        );
        assert_eq!(state.raw_operations[1].payload["kind"], "ak.invite.accept");
        assert_eq!(
            state.raw_operations[1].payload["body"]["invite_ref"],
            "ak:invite:0196419b-0000-7000-8000-000000000301"
        );
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
            to_device_message("ak.key.verification.request"),
            to_device_message(crate::mls::secret_share::SECRET_SHARE_KIND_REQUEST),
            to_device_message("ak.realm_key.request"),
        ]));
        assert!(to_device_batch_allows_cursor_advance(
            &[to_device_message("ak.key.verification.request")],
            false,
        ));
        assert!(!to_device_batch_allows_cursor_advance(
            &[to_device_message("ak.key.verification.request")],
            true,
        ));

        assert!(!to_device_batch_all_ack_safe(&[to_device_message(
            "ak.mls.welcome"
        )]));
        assert!(!to_device_batch_all_ack_safe(&[to_device_message(
            crate::mls::secret_share::SECRET_SHARE_KIND_SEND,
        )]));
        assert!(!to_device_batch_all_ack_safe(&[to_device_message(
            "ak.future.secret.material"
        )]));
    }

    #[test]
    fn sync_state_events_ingest_kanban_strand_updates_as_synced_raw_operations() {
        let temp = std::env::temp_dir().join(format!(
            "inkson-sync-state-events-{}.json",
            crate::operation::uuid_v7()
        ));
        let mut store = LocalStateStore::with_path(temp);
        let body = json!({
            "state": { "events": [{
                    "event_id": "ak:event:01904100-0000-7000-8000-0000000000a1",
                    "operation_id": "ak:operation:01904100-0000-7000-8000-0000000000a1",
                    "event_kind": "ak.strand.update",
                    "actor_id": "did:web:bob.example",
                    "created_at": "2026-06-24T10:00:00Z",
                    "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
                    "payload": {
                        "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                        "patch": {
                            "synthesis": {"$op": "set", "value": "bob synthesis"}
                        }
                    }
                }] }
        });

        let changed = ingest_kanban_state_events_from_projection(
            &mut store,
            "ak:realm:01904100-0000-7000-8000-000000000001",
            &body,
        );

        assert_eq!(changed, 1);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 1);
        assert_eq!(
            state.raw_operations[0].payload["actor_id"],
            "did:web:bob.example"
        );
        assert_eq!(state.raw_operations[0].payload["write_state"], "synced");
        assert_eq!(
            state.raw_operations[0].payload["body"]["patch"]["synthesis"]["value"],
            "bob synthesis"
        );
    }

    #[test]
    fn sync_state_events_ingest_discussion_pin_controls_as_raw_operations() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let strand_id = "ak:strand:01904100-0000-7000-8000-000000000002";
        let mut store = temp_store("discussion-pin-state-events");
        let body = json!({
            "state": { "events": [{
                    "event_id": "ak:event:01904100-0000-7000-8000-0000000000b1",
                    "event_kind": "ak.pin.add",
                    "actor_id": "did:web:mei.example",
                    "created_at": "2026-06-24T10:00:00Z",
                    "realm_id": realm_id,
                    "payload": {
                        "pin_scope": {"kind": "strand", "id": strand_id},
                        "target_ref": "ak:message:01904100-0000-7000-8000-000000000101",
                        "rank": "r001"
                    }
                }] }
        });

        let changed = ingest_discussion_state_events_from_projection(&mut store, realm_id, &body);

        assert_eq!(changed, 1);
        let state = store.load();
        assert_eq!(state.raw_operations.len(), 1);
        assert_eq!(
            state.raw_operations[0].operation_id,
            "ak:event:01904100-0000-7000-8000-0000000000b1"
        );
        assert_eq!(state.raw_operations[0].payload["event_kind"], "ak.pin.add");
        assert_eq!(
            state.raw_operations[0].payload["payload"]["pin_scope"]["id"],
            strand_id
        );
    }

    #[test]
    fn sync_state_events_skip_message_lifecycle_rows_for_discussion_raw_operations() {
        let realm_id = "ak:realm:01904100-0000-7000-8000-000000000001";
        let strand_id = "ak:strand:01904100-0000-7000-8000-000000000002";
        let mut store = temp_store("discussion-message-state-events");
        let body = json!({
            "state": { "events": [
                    {
                        "event_id": "ak:event:01904100-0000-7000-8000-0000000000c1",
                        "event_kind": "ak.message.revise",
                        "actor_id": "did:web:bob.example",
                        "created_at": "2026-06-24T10:00:00Z",
                        "realm_id": realm_id,
                        "payload": {
                            "event_id": "ak:event:01904100-0000-7000-8000-0000000000c1",
                            "target_ref": "ak:message:01904100-0000-7000-8000-000000000101",
                            "strand_id": strand_id,
                            "content": {
                                "kind": "ak.content.text",
                                "body": "edited state projection"
                            }
                        }
                    },
                    {
                        "event_id": "ak:event:01904100-0000-7000-8000-0000000000c2",
                        "event_kind": "ak.message.redact",
                        "actor_id": "did:web:bob.example",
                        "created_at": "2026-06-24T10:01:00Z",
                        "realm_id": realm_id,
                        "payload": {
                            "event_id": "ak:event:01904100-0000-7000-8000-0000000000c2",
                            "message_id": "ak:message:01904100-0000-7000-8000-000000000101",
                            "reason": "user requested tombstone"
                        }
                    }
                ] }
        });

        let changed = ingest_discussion_state_events_from_projection(&mut store, realm_id, &body);

        assert_eq!(changed, 0);
        assert!(
            store.load().raw_operations.is_empty(),
            "message lifecycle rows belong to timeline.events/backfill, not state.events"
        );
    }

    #[test]
    fn persistent_proof_sender_device_collection_dedupes_nested_events() {
        let mut response = empty_response("cursor-1");
        response.realms.insert(
            "ak:realm:01904100-0000-7000-8000-000000000001".to_owned(),
            json!({
                "timeline": {
                    "events": [
                        {
                            "event": {
                                "actor_id": "did:web:alice.example",
                                "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                                "proofs": [{"verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"}]
                            }
                        },
                        {
                            "actor_id": "did:web:alice.example",
                            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
                            "proofs": [{"verification_method": "did:web:alice.example#ak:device:01904100-0000-7000-8000-000000000001"}]
                        },
                        {
                            "actor_id": "did:web:bob.example",
                            "proofs": [{"verification_method": "did:web:bob.example#device"}]
                        },
                        {
                            "actor_id": "did:web:carol.example",
                            "proofs": [{"verification_method": "did:web:carol.example#ak:device:01904100-0000-7000-8000-000000000002"}]
                        }
                    ]
                }
            }),
        );
        assert_eq!(
            collect_persistent_proof_sender_devices(&response, &|_: &str| false),
            vec![
                (
                    "did:web:alice.example".to_owned(),
                    "ak:device:01904100-0000-7000-8000-000000000001".to_owned()
                ),
                (
                    "did:web:carol.example".to_owned(),
                    "ak:device:01904100-0000-7000-8000-000000000002".to_owned()
                )
            ]
        );
    }

    #[test]
    fn notification_projection_merges_pending_invites_from_authz() {
        let mut store = temp_store("invite-notifications");
        store.save_notification_projection(vec![json!({
            "notification_id": "message-1",
            "notification_kind": "message",
            "realm_id": "ak:realm:existing",
            "timestamp": "2026-06-01T00:00:00Z"
        })]);
        let response = empty_response("sx:invite");

        apply_notification_projection(
            &mut store,
            &response,
            Some(vec![json!({
                "invite_id": "ak:invite:0196419b-0000-7000-8000-000000000010",
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000011",
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
                == Some("invite:ak:invite:0196419b-0000-7000-8000-000000000010")
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
        store.save_realm_tree_projection("ak:realm:a", json!({"summary": {"title": "A"}}));
        store.save_realm_tree_projection(
            "ak:space:child",
            json!({
                "__kind": "space",
                "realm_id": "ak:realm:a",
                "summary": {"title": "Child"}
            }),
        );
        store.save_realm_tree_projection("ak:space:b", json!({"summary": {"title": "B"}}));
        store.save_draft("ak:space:b", "draft-b");

        let mut response = empty_response("sx:42");
        response
            .realms
            .insert("ak:realm:a".to_owned(), json!({"summary": {"title": "A"}}));

        // Mirror the engine's full-sync prune step.
        let server_set: BTreeSet<String> = response.realms.keys().cloned().collect();
        let keep_set = crate::app::full_sync_projection_keep_set(
            &server_set,
            &store.load().realm_tree_projections,
        );
        let pruned = store.retain_realm_tree_projections(|id| keep_set.contains(id));
        assert_eq!(pruned, vec!["ak:space:b".to_owned()]);

        let state = store.load();
        assert!(state.realm_tree_projections.contains_key("ak:realm:a"));
        assert!(state.realm_tree_projections.contains_key("ak:space:child"));
        assert!(!state.realm_tree_projections.contains_key("ak:space:b"));
        assert!(!state.drafts.contains_key("ak:space:b"));
    }

    #[test]
    fn incremental_response_forgets_left_realms() {
        let mut store = temp_store("left");
        store.save_realm_tree_projection("ak:space:a", json!({"name": "A"}));
        store.save_realm_tree_projection("ak:space:b", json!({"name": "B"}));
        store.save_draft("ak:space:b", "draft-b");

        let mut response = empty_response("sx:43");
        // Fixture typo fix: the forgotten projection id must match the
        // `ak:space:b` saved above. `forget_realm_tree_projection` deletes by
        // exact id, without prefix normalization, so otherwise the
        // `!contains_key("ak:space:b")` assertion would always be false.
        response.left_realms = vec!["ak:space:b".to_owned()];

        // Mirror the engine's left_realms step.
        for id in &response.left_realms {
            store.forget_realm_tree_projection(id);
        }

        let state = store.load();
        assert!(state.realm_tree_projections.contains_key("ak:space:a"));
        assert!(!state.realm_tree_projections.contains_key("ak:space:b"));
        assert!(!state.drafts.contains_key("ak:space:b"));
    }

    // ── Y2 invalidation hook ──────────────────────────────────────────

    use arkret_sdk::{Did, DidDocument};

    use crate::identity::did_resolver::DidResolutionCache;

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
                    { "event_id": "e1", "kind": "ak.cross_signing.reset" }
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
        // state.events[] use canonical `actor_id`; forbidden
        // `actor` / `sender` fields are ignored by the scanner.
        let (mut cache, did) = seed_cache("did:web:bob.example");
        let body = json!({
            "state": { "events": [
                { "event_id": "e9", "kind": "ak.device.revoke", "actor_id": "did:web:bob.example" }
            ] }
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
                { "event_id": "e10", "kind": "ak.device.revoke", "actor": "did:web:dave.example" },
                { "event_id": "e11", "kind": "ak.device.revoke", "sender": "did:web:dave.example" }
            ] }
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
                    { "event_id": "e2", "kind": "ak.member.identity.update" }
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
                    { "event_id": "e3", "kind": "ak.device.revoke" }
                ]
            }]
        });
        invalidate_cache_for_revocation_events(&mut cache, &body);
        assert!(cache.get(&alice, chrono::Utc::now()).is_some());
    }
}
