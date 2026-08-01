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
    pub token: crate::runtime::input::ValueCell<String>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    /// The realm the kanban view is currently showing. The engine exits when
    /// this no longer matches the realm it was spawned for, so a realm switch
    /// retires the old loop while `app` spawns a fresh one for the new realm.
    pub selected_realm_id: crate::runtime::input::ValueReader<String>,
    /// Whether the current route actually consumes a Realm stream. This lets a
    /// stream spawned on Board/Chat exit when navigation returns to Home.
    pub route_enabled: crate::runtime::input::ValueReader<bool>,
    /// The session's optional WebSocket. A live rail supplies the events
    /// channel; a scan always stays on HTTPS.
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
    /// Bumped once per iteration that folded ≥1 new operation into the local
    /// store, so the kanban panel can re-project off a signal that is NOT the
    /// (cross-member-lossy) account `sync_cursor`.
    pub realm_live_epoch: crate::runtime::input::ValueCell<u64>,
    /// Removes transient message previews only after the matching final Event
    /// has been durably folded by this projector.
    pub message_stream_hub: crate::views::message_streams::MessageStreamHub,
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
    message_stream_hub: crate::views::message_streams::MessageStreamHub,
}

impl ClientProjector for RealmIngestProjector {
    async fn project(&self, batch: Vec<ClientEvent>) -> garth::Result<()> {
        if !batch.is_empty() {
            let finals = batch
                .iter()
                .filter_map(accepted_direct_message_final)
                .collect::<Vec<_>>();
            let changed = self.state_store.write(|store| {
                crate::sync_engine::ingest_kanban_events(store, &self.realm_id, &batch)
                    + crate::sync_engine::ingest_message_events(store, &self.realm_id, &batch)
                    + crate::sync_engine::ingest_membership_events(store, &self.realm_id, &batch)
                    + crate::sync_engine::ingest_moderation_events(store, &batch)
            });
            // The local fold above is the durable gate. A preview is never
            // removed merely because a frame with the same message id was
            // observed on the wire.
            let mut message_stream_hub = self.message_stream_hub;
            for (event, sender_device_id) in finals {
                if let Err(error) = message_stream_hub.bind_verified_final(event, &sender_device_id)
                {
                    tracing::warn!(%error, event_id = %event.event_id, "message stream final binding failed closed");
                }
            }
            if changed > 0 {
                self.realm_live_epoch
                    .update(|epoch| *epoch = epoch.wrapping_add(1));
            }
        }
        Ok(())
    }
}

/// Extract the sender device from a service-accepted direct Message Event.
///
/// The Realm stream contains the canonical Event only after Soland's normal
/// schema, proof, authorization and reducer gates. This function does not
/// invent a second proof verifier: it accepts only the unique ordinary Event
/// proof whose method is the exact `{actor_id}#{device_id}` mapping and hands
/// that already-admitted device identity to Garth's §7.5 binder.
fn accepted_direct_message_final(
    client_event: &ClientEvent,
) -> Option<(&arkret_sdk::Event, arkret_sdk::DeviceId)> {
    let ClientEvent::Message(message) = client_event else {
        return None;
    };
    let event = &message.event;
    if event.kind != arkret_sdk::EventKind::MessageCreate
        || event.executed_by.is_some()
        || event.proofs.len() != 1
    {
        return None;
    }
    let method = event.proofs[0].verification_method.as_str();
    let device = method
        .strip_prefix(event.actor_id.as_str())?
        .strip_prefix('#')?;
    let device = arkret_sdk::DeviceId::new(device.to_owned()).ok()?;
    Some((event, device))
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
        message_stream_hub: ctx.message_stream_hub,
    };
    // `events/subscribe` without `after` is a live tail, not a history
    // endpoint. Bootstrap durable history through events.query.scan and let
    // the shared client core checkpoint only after the projector commits it.
    let has_stream_cursor = ctx
        .state_store
        .read(|store| store.realm_events_cursor(realm_id_typed.as_str()).is_some());
    if !has_stream_cursor {
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
    type Transport = crate::transport::websocket_rail::StreamRail<
        crate::client_core::InksonRealmEventsTransport,
    >;

    /// A scan is not a covered operation (§1), so it stays on HTTPS even while
    /// the rail is live; only the subscribe half moves.
    async fn provide(&self) -> garth::Result<Self::Transport> {
        let base = self.ctx.base_url.get();
        let http = crate::identity::session_refresh::provide_authenticated_sdk_client(&base)
            .await
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        Ok(crate::transport::websocket_rail::StreamRail::select(
            &self.ctx.websocket_rail,
            crate::client_core::InksonRealmEventsTransport::new(http),
        ))
    }

    async fn recover_unauthorized(&self) -> garth::Result<bool> {
        crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(
            &self.ctx.base_url.get(),
        )
        .await
        .map(|_| true)
        .map_err(|error| garth::Error::Http(error.to_string()))
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const REALM_ID: &str = "ak:realm:01904100-0000-7000-8000-000000000001";
    const STRAND_ID: &str = "ak:strand:01904100-0000-7000-8000-000000000002";
    const ACTOR_ID: &str = "did:web:alice.example";
    const DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000003";

    fn direct_message_event() -> ClientEvent {
        let realm_id = arkret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap();
        let mut event = arkret_sdk::Event::new(
            arkret_sdk::EventKind::MESSAGE_CREATE,
            arkret_sdk::ScopeRef::Realm { realm_id },
            arkret_sdk::Did::new(ACTOR_ID.to_owned()).unwrap(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({
                "strand_id": STRAND_ID,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "final"}
            }),
        )
        .unwrap();
        let event_digest = arkret_sdk::Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs.push(arkret_sdk::Proof {
            kind: "detached_jws".to_owned(),
            verification_method: arkret_sdk::DidUrl::new(format!("{ACTOR_ID}#{DEVICE_ID}"))
                .unwrap(),
            alg: "EdDSA".to_owned(),
            event_digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        });
        match garth::InboundDecoder::new()
            .try_decode_event(event)
            .unwrap()
        {
            garth::DecodedInbound::Message(message) => ClientEvent::Message(*message),
            garth::DecodedInbound::Event(_) => panic!("message.create must decode as a message"),
        }
    }

    #[test]
    fn final_binding_extracts_only_the_exact_accepted_actor_device_proof() {
        let event = direct_message_event();
        let (final_event, device_id) =
            accepted_direct_message_final(&event).expect("direct final is bindable");
        assert_eq!(final_event.actor_id.as_str(), ACTOR_ID);
        assert_eq!(device_id.as_str(), DEVICE_ID);
    }

    #[test]
    fn final_binding_rejects_delegated_or_ambiguous_sender_identity() {
        let mut delegated = direct_message_event();
        let ClientEvent::Message(message) = &mut delegated else {
            unreachable!();
        };
        message.event.executed_by = Some(arkret_sdk::Did::new("did:web:agent.example").unwrap());
        assert!(accepted_direct_message_final(&delegated).is_none());

        let mut ambiguous = direct_message_event();
        let ClientEvent::Message(message) = &mut ambiguous else {
            unreachable!();
        };
        message.event.proofs.push(message.event.proofs[0].clone());
        assert!(accepted_direct_message_final(&ambiguous).is_none());
    }
}
