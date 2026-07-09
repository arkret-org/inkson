//! Per-realm `ck.self.events.stream.subscribe` long-poll engine.
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

use dioxus::prelude::*;
use garth::{ClientEvent, ClientProjector, RealmEventsDriver, RealmStreamStopReason};
use serde_json::Value;

use crate::api_error::{is_auth_expired_error, is_invalid_cursor_error, rate_limited_retry_after};
use crate::config::MultiProfileConfig;
use crate::local_state::LocalStateStore;
use crate::runtime_helpers::sleep_for;

/// How long the server holds each realm `events/subscribe` long-poll open. The
/// buffered (wasm) reader only surfaces frames at close, so this is also the
/// realtime latency floor for the board. Small enough to keep the board fresh,
/// large enough to behave as a long-poll rather than a tight poll.
const REALM_EVENTS_POLL_WINDOW_MS: u64 = 5_000;

/// Floor / ceiling for the failure backoff. Mirrors the account engine's
/// human-scale recovery cadence.
const MIN_BACKOFF_MS: u64 = 1_000;
const MAX_BACKOFF_MS: u64 = 60_000;

/// Signals the realm events engine needs. `Copy` because Dioxus signals are.
#[derive(Clone, Copy)]
pub struct RealmEventsEngineContext {
    pub base_url: Signal<String>,
    pub token: Signal<String>,
    pub state_store: Signal<LocalStateStore>,
    /// The realm the kanban view is currently showing. The engine exits when
    /// this no longer matches the realm it was spawned for, so a realm switch
    /// retires the old loop while `app` spawns a fresh one for the new realm.
    pub selected_realm_id: Signal<String>,
    /// Whether the current route actually consumes a Realm stream. This lets a
    /// stream spawned on Board/Chat exit when navigation returns to Home.
    pub route_enabled: Signal<bool>,
    /// Bumped once per iteration that folded ≥1 new operation into the local
    /// store, so the kanban panel can re-project off a signal that is NOT the
    /// (cross-member-lossy) account `sync_cursor`.
    pub realm_live_epoch: Signal<u64>,
    /// Active multi-profile config — the engine exits when the active profile
    /// rotates (mirrors the account engine's profile guard).
    pub profiles: Signal<MultiProfileConfig>,
}

/// Outcome of a single subscribe iteration, telling the loop how to pace.
enum RealmIterationOutcome {
    /// Iteration completed; pause the short inter-iteration beat then re-poll.
    Ok,
    /// Recoverable failure; sleep `delay_ms` (already chosen by the caller).
    Backoff { delay_ms: u64 },
    /// Base URL / token not yet populated; exit and let `app` respawn.
    NotReady,
    /// Terminal session loss; exit and let the account engine / app drive
    /// re-auth (a generation bump retires this loop).
    AuthExpired,
}

/// Convert a driver-emitted [`ClientEvent`] into the legacy `Value` payload the
/// inkson realm ingest functions consume. The realm driver only emits decoded
/// `Message` / `Event` (the account-only variants never occur on this stream).
fn client_event_to_legacy_payload(event: ClientEvent) -> Option<Value> {
    let event = match event {
        ClientEvent::Message(message) => message.event,
        ClientEvent::Event(event) => event,
        ClientEvent::AccountUpdates(_)
        | ClientEvent::RealmDelta { .. }
        | ClientEvent::Backfill { .. }
        | ClientEvent::Notification(_)
        | ClientEvent::ToDevice(_) => return None,
    };
    match serde_json::to_value(event) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!(error = %error, "failed to serialize decoded realm event for ingest");
            None
        }
    }
}

/// [`ClientProjector`] that folds each driver-emitted batch into the shared
/// local store (kanban / message / membership), tracking whether anything
/// changed so the caller bumps `realm_live_epoch` once per subscribe window
/// (preserving the batch re-projection cadence). The ingest is durable BEFORE
/// the driver checkpoints the cursor (the projector gates cursor advance), and
/// the cursor stays coherent with this ingest through the shared
/// `ClientCoreSyncOverlay` (E7 store-handle unification).
struct RealmIngestProjector {
    state_store: Signal<LocalStateStore>,
    realm_id: String,
    changed: Cell<usize>,
}

impl ClientProjector for RealmIngestProjector {
    fn project(
        &self,
        batch: Vec<ClientEvent>,
    ) -> impl std::future::Future<Output = arkret_sdk::Result<()>> + '_ {
        let payloads: Vec<Value> = batch
            .into_iter()
            .filter_map(client_event_to_legacy_payload)
            .collect();
        async move {
            if !payloads.is_empty() {
                let mut state_store = self.state_store;
                let mut guard = state_store.write();
                let changed =
                    crate::sync_engine::ingest_kanban_events(&mut guard, &self.realm_id, &payloads)
                        + crate::sync_engine::ingest_message_events(
                            &mut guard,
                            &self.realm_id,
                            &payloads,
                        )
                        + crate::sync_engine::ingest_membership_events(
                            &mut guard,
                            &self.realm_id,
                            &payloads,
                        );
                drop(guard);
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
    generation: Signal<u64>,
    realm_id: String,
    ctx: RealmEventsEngineContext,
) {
    if realm_id.trim().is_empty() {
        return;
    }
    let start_profile_id = ctx.profiles.read().active_profile_id.clone();
    let mut backoff_ms = MIN_BACKOFF_MS;
    loop {
        // Cancellation: generation bump (login / logout / server switch),
        // profile rotation, or the user navigating to a different realm.
        if generation() != start_generation {
            return;
        }
        if ctx.profiles.read().active_profile_id != start_profile_id {
            return;
        }
        if ctx.selected_realm_id.read().as_str() != realm_id {
            return;
        }
        if !(ctx.route_enabled)() {
            return;
        }

        match run_realm_iteration(&realm_id, &ctx, start_generation, generation).await {
            RealmIterationOutcome::Ok => {
                backoff_ms = MIN_BACKOFF_MS;
                // Brief beat between long-polls so an immediately-returning
                // server can't spin the loop at network RTT.
                sleep_for(std::time::Duration::from_millis(250)).await;
            }
            RealmIterationOutcome::Backoff { delay_ms } => {
                // Honor the server's retry-after as a floor, escalating with
                // the local exponential backoff on repeated failures
                // (backoff_ms starts at MIN_BACKOFF_MS, so the old
                // MIN_BACKOFF_MS floor is preserved).
                sleep_for(std::time::Duration::from_millis(delay_ms.max(backoff_ms))).await;
                backoff_ms = (backoff_ms.saturating_mul(2)).min(MAX_BACKOFF_MS);
            }
            RealmIterationOutcome::NotReady | RealmIterationOutcome::AuthExpired => {
                return;
            }
        }
    }
}

async fn run_realm_iteration(
    realm_id: &str,
    ctx: &RealmEventsEngineContext,
    start_generation: u64,
    generation: Signal<u64>,
) -> RealmIterationOutcome {
    let base = ctx.base_url.read().clone();
    let token = ctx.token.read().clone();
    if base.trim().is_empty() || token.trim().is_empty() {
        return RealmIterationOutcome::NotReady;
    }
    #[cfg(target_arch = "wasm32")]
    if crate::secure_key_store::ensure_wasm_secure_key_store_ready("inkson")
        .await
        .is_err()
    {
        return RealmIterationOutcome::Backoff {
            delay_ms: MIN_BACKOFF_MS,
        };
    }

    let sdk_http =
        match crate::authed_api::authed_api(&base, token).and_then(|api| api.sdk_http_client()) {
            Ok(sdk_http) => sdk_http,
            Err(_) => {
                return RealmIterationOutcome::Backoff {
                    delay_ms: MIN_BACKOFF_MS,
                };
            }
        };

    let realm_id_typed = match arkret_sdk::RealmId::new(realm_id.to_owned()) {
        Ok(realm_id) => realm_id,
        Err(error) => {
            tracing::warn!(error = %error, realm_id, "invalid realm id for events subscribe");
            return RealmIterationOutcome::Backoff {
                delay_ms: MIN_BACKOFF_MS,
            };
        }
    };

    // A late response from a retired generation must not touch the store.
    if generation() != start_generation {
        return RealmIterationOutcome::Ok;
    }

    let transport = crate::client_core::InksonRealmEventsTransport::new(sdk_http)
        .with_max_duration_ms(REALM_EVENTS_POLL_WINDOW_MS);

    // The garth driver loads/checkpoints this realm's cursor and remembers
    // dedupe ids through this adapter, which shares the E7 `ClientCoreSyncOverlay`
    // with the Dioxus `Signal` store (a clone of the same instance) — so the
    // driver's cursor/dedupe writes stay coherent with the projector's ingest
    // (no clone-divergence clobber). The driver also emits/awaits the projector
    // BEFORE checkpointing the cursor, so ingest gates cursor advance.
    let adapter =
        crate::client_core::InksonLocalStateStoreAdapter::new(ctx.state_store.read().clone());
    let driver = RealmEventsDriver::new(adapter.clone(), adapter);
    let projector = RealmIngestProjector {
        state_store: ctx.state_store,
        realm_id: realm_id.to_owned(),
        changed: Cell::new(0),
    };

    let reason = match driver
        .run_stream(&transport, realm_id_typed, &projector)
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
                    delay_ms: retry_after_ms,
                };
            }
            if is_invalid_cursor_error(&error) {
                // Broken/expired realm cursor — clear it so the next subscribe
                // rebuilds from history.
                let mut state_store = ctx.state_store;
                state_store.write().save_realm_events_cursor(realm_id, None);
            }
            return RealmIterationOutcome::Backoff {
                delay_ms: MIN_BACKOFF_MS,
            };
        }
    };

    // Bump the live epoch once per window when the projector folded ≥1 op, so
    // the kanban/chat panels re-project on real content (unchanged cadence).
    if projector.changed.get() > 0 {
        let mut realm_live_epoch = ctx.realm_live_epoch;
        let next = realm_live_epoch.peek().wrapping_add(1);
        realm_live_epoch.set(next);
    }

    match reason {
        RealmStreamStopReason::StreamEnded => RealmIterationOutcome::Ok,
        RealmStreamStopReason::Dropped {
            reconnect_after_ms, ..
        } => {
            // Server lost our position — clear the realm cursor so the next
            // subscribe rebuilds from history (inkson rebuilds from history for
            // realm drops rather than scan-catchup).
            let mut state_store = ctx.state_store;
            state_store.write().save_realm_events_cursor(realm_id, None);
            RealmIterationOutcome::Backoff {
                delay_ms: reconnect_after_ms.unwrap_or(MIN_BACKOFF_MS),
            }
        }
        RealmStreamStopReason::ResyncRequired { reconnect_after_ms } => {
            // The driver already cleared the cursor on resync (via the adapter).
            RealmIterationOutcome::Backoff {
                delay_ms: reconnect_after_ms.unwrap_or(MIN_BACKOFF_MS),
            }
        }
        RealmStreamStopReason::Unauthorized { .. } => RealmIterationOutcome::AuthExpired,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEST_REALM: &str = "ak:realm:01904100-0000-7000-8000-000000000001";

    fn test_realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new(TEST_REALM).unwrap()
    }

    fn test_actor_id() -> arkret_sdk::Did {
        arkret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn test_event(kind: &str, payload: Value) -> arkret_sdk::Event {
        arkret_sdk::Event::new(
            kind,
            test_realm_id(),
            test_actor_id(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn client_event_message_converts_to_legacy_ingest_payload() {
        let event = test_event(
            arkret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        );
        let event_value = serde_json::to_value(&event).unwrap();
        // The garth driver decodes a message frame into `ClientEvent::Message`;
        // the projector converts it back to the legacy ingest payload shape.
        let decoded = garth::InboundDecoder::new()
            .try_decode_event(event)
            .unwrap();
        let client_event = match decoded {
            garth::DecodedInbound::Message(message) => ClientEvent::Message(message),
            other => panic!("expected a decoded message, got {other:?}"),
        };

        let payload = client_event_to_legacy_payload(client_event).expect("message -> payload");

        assert_eq!(payload["event_id"], event_value["event_id"]);
        assert_eq!(payload["kind"], event_value["kind"]);
        assert_eq!(payload["payload"], event_value["payload"]);
    }

    #[test]
    fn client_event_generic_event_converts_to_legacy_ingest_payload() {
        let event = test_event(
            arkret_sdk::events::kinds::STRAND_UPDATE,
            json!({"target_ref": "ak:strand:01904100-0000-7000-8000-000000000002", "patch": {}}),
        );
        let event_value = serde_json::to_value(&event).unwrap();

        let payload =
            client_event_to_legacy_payload(ClientEvent::Event(event)).expect("event -> payload");

        assert_eq!(payload["event_id"], event_value["event_id"]);
        assert_eq!(payload["kind"], event_value["kind"]);
    }
}
