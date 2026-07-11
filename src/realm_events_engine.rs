//! Per-realm `ak.self.events.stream.subscribe` long-poll engine.
//!
//! This is the realm-scoped counterpart to [`crate::sync_engine`]. The account
//! engine drives `/_arkret/self/account/subscribe` (the account-aggregate
//! stream); this engine drives `/_arkret/self/events/subscribe?realms=<R>` for
//! the currently-selected realm.
//!
//! Why a SECOND engine instead of reusing the account stream's cursor:
//! `service-surface.md` forbids merging the account-aggregate stream and the
//! bare realm events read into one "stream" — their selectors / auth / frame
//! schema / freshness all differ. Concretely, each cursor is bound to a
//! `filter_digest` (`encoding.md` §8.3.1): the account stream and a realm
//! stream have different selectors, so their cursors are NOT interchangeable
//! (cross-use is `cursor_integrity_invalid`). The realm cursor therefore lives
//! in its own store slot ([`LocalStateStore::realm_events_cursor`]).
//!
//! Why this fixes cross-member sync: a realm's `events/subscribe` history +
//! live frames are served from the projection layer + per-realm broadcast
//! fan-out, NOT from the per-member delivery routing that
//! `account.subscribe` push is gated by. A member whose delivery binding is
//! still `unroutable` is dropped from account-push routing (so the account
//! cursor never advances for the other member's events), but their durable
//! events are fully visible through this realm stream.
//!
//! Transport reality (wasm): the shared SDK http-client opens the canonical
//! `events/subscribe` stream, and inkson wraps it as a client-core typed frame
//! source. The all-target adapter buffers the response and parses typed NDJSON
//! frames at stream close. The server holds the stream open for
//! `max_duration_ms`, so that window doubles as this engine's liveness latency.
//! Native can later switch this adapter to the SDK streaming frame source
//! without changing the ingest / cursor contract here.

use std::cell::Cell;
use std::time::Duration;

use garth::{
    ClientEvent, ClientProjector, RealmStreamStopReason, RunOptions, SyncLoopControl,
    TransportProvider,
};

use crate::api_error::{is_auth_expired_error, is_invalid_cursor_error, rate_limited_retry_after};
use crate::config::MultiProfileConfig;
use crate::runtime::engine_loop::{EngineLoopDirective, run_engine_loop};
use crate::state::LocalStateStore;

/// Floor / ceiling for the failure backoff. Mirrors the account engine's
/// human-scale recovery cadence. The doubling ladder is [`garth::Backoff`];
/// these are just its bounds, kept as `Duration` so the account and realm
/// engines share one unit (F-10).
const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// Runtime inputs consumed by the realm events engine. UI frameworks are
/// confined to the app adapter that constructs these handles.
#[derive(Clone)]
pub struct RealmEventsEngineContext {
    pub base_url: crate::runtime::input::ValueReader<String>,
    pub token: crate::runtime::input::ValueReader<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    /// The realm the kanban view is currently showing. The engine exits when
    /// this no longer matches the realm it was spawned for, so a realm switch
    /// retires the old loop while `app` spawns a fresh one for the new realm.
    pub selected_realm_id: crate::runtime::input::ValueReader<String>,
    /// Whether the current route actually consumes a Realm stream. This lets a
    /// stream spawned on Board/Chat exit when navigation returns to Home.
    pub route_enabled: crate::runtime::input::ValueReader<bool>,
    /// Bumped once per iteration that folded ≥1 new operation into the local
    /// store, so the kanban panel can re-project off a signal that is NOT the
    /// (cross-member-lossy) account `sync_cursor`.
    pub realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    /// Active multi-profile config — the engine exits when the active profile
    /// rotates (mirrors the account engine's profile guard).
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub client_runtime: crate::client_core::InksonClientRuntime,
    pub effect: crate::runtime::effects::EffectHandle,
}

/// Outcome of a single subscribe iteration, telling the loop how to pace.
enum RealmIterationOutcome {
    /// Iteration completed; pause the short inter-iteration beat then re-poll.
    Ok,
    /// Recoverable failure; back off via the shared ladder. `retry_after_ms`
    /// carries a server-advertised hint (rate-limit / reconnect-after) honored as
    /// a hard floor for this step; `None` means "no hint, use the ladder base".
    Backoff { retry_after_ms: Option<u64> },
    /// Base URL / token not yet populated; exit and let `app` respawn.
    NotReady,
    /// Terminal session loss; exit and let the account engine / app drive
    /// re-auth (a generation bump retires this loop).
    AuthExpired,
}

/// [`ClientProjector`] that folds each driver-emitted batch into the shared
/// local store (kanban / message / membership), tracking whether anything
/// changed so the caller bumps `realm_live_epoch` once per subscribe window
/// (preserving the batch re-projection cadence). The ingest is durable BEFORE
/// the driver checkpoints the cursor (the projector gates cursor advance), and
/// the cursor stays coherent because the garth adapter writes the same root
/// state backend used by the projector.
struct RealmIngestProjector {
    state_store: crate::runtime::input::StateStoreHandle,
    realm_id: String,
    changed: Cell<usize>,
}

impl ClientProjector for RealmIngestProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = arkret_sdk::Result<()>> + '_ {
        async move {
            if !batch.is_empty() {
                let changed = self.state_store.write(|store| {
                    crate::sync_engine::ingest_kanban_events(store, &self.realm_id, &batch)
                        + crate::sync_engine::ingest_message_events(store, &self.realm_id, &batch)
                        + crate::sync_engine::ingest_membership_events(
                            store,
                            &self.realm_id,
                            &batch,
                        )
                });
                self.changed.set(self.changed.get() + changed);
            }
            Ok(())
        }
    }
}

/// Run the realm events subscribe loop for `realm_id` until the generation is
/// bumped, the active profile rotates, or the selected realm changes.
pub async fn run_realm_events_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    realm_id: String,
    ctx: RealmEventsEngineContext,
) {
    if realm_id.trim().is_empty() {
        return;
    }
    let start_profile_id = ctx.profiles.get().active_profile_id;
    let realm_id_typed = match arkret_sdk::RealmId::new(realm_id.clone()) {
        Ok(realm_id) => realm_id,
        Err(error) => {
            tracing::warn!(error = %error, realm_id, "invalid realm id for events subscribe");
            return;
        }
    };
    let provider = RealmTransportProvider {
        ctx: ctx.clone(),
        generation,
        start_generation,
        start_profile_id,
        realm_id: realm_id.clone(),
    };
    let projector = RealmIngestProjector {
        state_store: ctx.state_store.clone(),
        realm_id,
        changed: Cell::new(0),
    };
    let result = ctx
        .client_runtime
        .client()
        .run_realm(
            &provider,
            realm_id_typed,
            &projector,
            &SyncLoopControl::new(),
            RunOptions {
                beat: Duration::from_millis(250),
                min_backoff: BACKOFF_FLOOR,
                max_backoff: BACKOFF_CEILING,
                jitter_ratio: 0.2,
            },
        )
        .await;
    if let Err(error) = result {
        tracing::warn!(error = %error, "realm events runner stopped with error");
    }
    if projector.changed.get() > 0 {
        ctx.realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }
}

struct RealmTransportProvider {
    ctx: RealmEventsEngineContext,
    generation: crate::runtime::input::ValueReader<u64>,
    start_generation: u64,
    start_profile_id: Option<String>,
    realm_id: String,
}

impl TransportProvider for RealmTransportProvider {
    type Transport = crate::client_core::InksonRealmEventsTransport;

    async fn provide(&self) -> arkret_sdk::Result<Self::Transport> {
        let base = self.ctx.base_url.get();
        let token = self.ctx.token.get();
        let http = crate::transport::auth::authed_api(&base, token)
            .and_then(|api| api.sdk_http_client())
            .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
        Ok(crate::client_core::InksonRealmEventsTransport::new(http))
    }

    fn is_active(&self) -> bool {
        self.generation.get() == self.start_generation
            && self.ctx.profiles.get().active_profile_id == self.start_profile_id
            && self.ctx.selected_realm_id.get() == self.realm_id
            && self.ctx.route_enabled.get()
            && !self.ctx.effect.is_cancelled()
            && !self.ctx.base_url.get().trim().is_empty()
            && !self.ctx.token.get().trim().is_empty()
    }
}

async fn run_realm_iteration(
    realm_id: &str,
    ctx: &RealmEventsEngineContext,
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
) -> RealmIterationOutcome {
    let base = ctx.base_url.get();
    let token = ctx.token.get();
    if base.trim().is_empty() || token.trim().is_empty() {
        return RealmIterationOutcome::NotReady;
    }
    #[cfg(target_arch = "wasm32")]
    if crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .is_err()
    {
        return RealmIterationOutcome::Backoff {
            retry_after_ms: None,
        };
    }

    let sdk_http = match crate::transport::auth::authed_api(&base, token)
        .and_then(|api| api.sdk_http_client())
    {
        Ok(sdk_http) => sdk_http,
        Err(_) => {
            return RealmIterationOutcome::Backoff {
                retry_after_ms: None,
            };
        }
    };

    let realm_id_typed = match arkret_sdk::RealmId::new(realm_id.to_owned()) {
        Ok(realm_id) => realm_id,
        Err(error) => {
            tracing::warn!(error = %error, realm_id, "invalid realm id for events subscribe");
            return RealmIterationOutcome::Backoff {
                retry_after_ms: None,
            };
        }
    };

    // A late response from a retired generation must not touch the store.
    if generation.get() != start_generation {
        return RealmIterationOutcome::Ok;
    }

    // The transport passes the request-aware trace context (`catchup` from
    // cursor presence) into the SDK frame stream, whose StreamTraceValidator
    // — plus the garth driver's — enforces the §1.1 sequence rules on every
    // frame. Stream duration is bounded by the server's own subscribe window
    // (the client-side max_duration knob no longer exists in the SDK options).
    let transport = crate::client_core::InksonRealmEventsTransport::new(sdk_http);

    // The garth driver loads/checkpoints this realm's cursor and remembers
    // dedupe ids through the root runtime adapter, which writes the exact
    // `SyncSignal` store used by this projector. The driver emits/awaits the projector
    // BEFORE checkpointing the cursor, so ingest gates cursor advance.
    let projector = RealmIngestProjector {
        state_store: ctx.state_store.clone(),
        realm_id: realm_id.to_owned(),
        changed: Cell::new(0),
    };

    let reason = match ctx
        .client_runtime
        .subscription_engine()
        .run_realm_stream(&transport, realm_id_typed, &projector)
        .await
    {
        Ok(reason) => reason,
        Err(error) => {
            let error: anyhow::Error = error.into();
            if is_auth_expired_error(&error) {
                return RealmIterationOutcome::AuthExpired;
            }
            if let Some(retry_after_ms) = rate_limited_retry_after(&error) {
                return RealmIterationOutcome::Backoff {
                    retry_after_ms: Some(retry_after_ms),
                };
            }
            if is_invalid_cursor_error(&error) {
                // Broken/expired realm cursor — clear it so the next subscribe
                // rebuilds from history.
                ctx.state_store
                    .write(|store| store.save_realm_events_cursor(realm_id, None));
            }
            return RealmIterationOutcome::Backoff {
                retry_after_ms: None,
            };
        }
    };

    // Bump the live epoch once per window when the projector folded ≥1 op, so
    // the kanban/chat panels re-project on real content (unchanged cadence).
    if projector.changed.get() > 0 {
        ctx.realm_live_epoch
            .update(|epoch| *epoch = epoch.wrapping_add(1));
    }

    match reason {
        RealmStreamStopReason::StreamEnded => RealmIterationOutcome::Ok,
        RealmStreamStopReason::Dropped {
            reconnect_after_ms, ..
        } => {
            // Server lost our position — clear the realm cursor so the next
            // subscribe rebuilds from history (inkson rebuilds from history for
            // realm drops rather than scan-catchup).
            ctx.state_store
                .write(|store| store.save_realm_events_cursor(realm_id, None));
            RealmIterationOutcome::Backoff {
                retry_after_ms: reconnect_after_ms,
            }
        }
        RealmStreamStopReason::ResyncRequired { reconnect_after_ms } => {
            // The driver already cleared the cursor on resync (via the adapter).
            RealmIterationOutcome::Backoff {
                retry_after_ms: reconnect_after_ms,
            }
        }
        RealmStreamStopReason::Unauthorized { .. } => RealmIterationOutcome::AuthExpired,
    }
}
