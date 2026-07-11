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

use std::time::Duration;

use garth::{
    ClientEvent, ClientProjector, RunOptions, ScanCatchupOptions, SyncLoopControl,
    TransportProvider,
};

use crate::config::MultiProfileConfig;

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

/// [`ClientProjector`] that folds each driver-emitted batch into the shared
/// local store (kanban / message / membership), bumping `realm_live_epoch`
/// immediately after each batch that changes the projection. The runner owns a
/// long-lived reconnect loop, so deferring the signal until that loop returns
/// would leave the UI stale even though the event was already durable locally.
/// The ingest is durable BEFORE
/// the driver checkpoints the cursor (the projector gates cursor advance), and
/// the cursor stays coherent because the garth adapter writes the same root
/// state backend used by the projector.
struct RealmIngestProjector {
    state_store: crate::runtime::input::StateStoreHandle,
    realm_id: String,
    realm_live_epoch: crate::runtime::input::ValueCell<u64>,
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
                if changed > 0 {
                    self.realm_live_epoch
                        .update(|epoch| *epoch = epoch.wrapping_add(1));
                }
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
        realm_live_epoch: ctx.realm_live_epoch.clone(),
    };
    // `events/subscribe` without `after` is a live tail, not a history
    // endpoint. Bootstrap durable history through events.query.scan and let
    // the shared client core checkpoint only after the projector commits it.
    let bootstrap_transport = match provider.provide().await {
        Ok(transport) => transport,
        Err(error) => {
            tracing::warn!(error = %error, "realm history transport is not ready");
            return;
        }
    };
    if let Err(error) = ctx
        .client_runtime
        .subscription_engine()
        .bootstrap_realm_history(
            &bootstrap_transport,
            realm_id_typed.clone(),
            &projector,
            ScanCatchupOptions::default(),
        )
        .await
    {
        tracing::warn!(error = %error, "realm history bootstrap failed");
        return;
    }
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
