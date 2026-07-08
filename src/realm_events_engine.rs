//! Per-realm `ck.self.events.stream.subscribe` long-poll engine.
//!
//! This is the realm-scoped counterpart to [`crate::sync_engine`]. The account
//! engine drives `/_cokret/self/account/subscribe` (the account-aggregate
//! stream); this engine drives `/_cokret/self/events/subscribe?realms=<R>` for
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

use std::cell::RefCell;

use cokret_client::{
    ClientEvent, ClientEventSink, DecodedInbound, InboundDecoder, RealmEventsFrameSource,
    RealmEventsTransport,
};
use cokret_sdk::EventsSubscribeFrameKind;
use dioxus::prelude::*;
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

#[derive(Debug)]
enum RealmIngestPayload {
    Event(cokret_sdk::Event),
    Raw(Value),
}

#[derive(Debug, Default)]
struct RealmEventsIngestSink {
    payloads: RefCell<Vec<RealmIngestPayload>>,
}

impl RealmEventsIngestSink {
    fn push_raw(&self, payload: Value) {
        self.payloads
            .borrow_mut()
            .push(RealmIngestPayload::Raw(payload));
    }

    fn into_legacy_payloads(self) -> Vec<Value> {
        self.payloads
            .into_inner()
            .into_iter()
            .filter_map(|payload| match payload {
                RealmIngestPayload::Event(event) => match serde_json::to_value(event) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            "failed to serialize decoded realm event for legacy ingest"
                        );
                        None
                    }
                },
                RealmIngestPayload::Raw(value) => Some(value),
            })
            .collect()
    }
}

impl ClientEventSink for RealmEventsIngestSink {
    fn emit(&self, event: ClientEvent) {
        let event = match event {
            ClientEvent::Message(message) => Some(message.event),
            ClientEvent::Event(event) => Some(event),
            ClientEvent::AccountUpdates(_)
            | ClientEvent::RealmDelta { .. }
            | ClientEvent::Backfill { .. }
            | ClientEvent::Notification(_)
            | ClientEvent::ToDevice(_)
            | ClientEvent::Interrupt(_) => None,
        };

        if let Some(event) = event {
            self.payloads
                .borrow_mut()
                .push(RealmIngestPayload::Event(event));
        }
    }
}

fn emit_decoded_realm_event<S>(decoder: &InboundDecoder, sink: &S, event: cokret_sdk::Event)
where
    S: ClientEventSink + ?Sized,
{
    match decoder.decode_event(event) {
        DecodedInbound::Message(message) => sink.emit(ClientEvent::Message(message)),
        DecodedInbound::Notification(notification) => {
            sink.emit(ClientEvent::Event(notification.event));
        }
        DecodedInbound::Event(event) => sink.emit(ClientEvent::Event(event)),
    }
}

fn route_realm_event_payload_for_legacy_ingest(
    decoder: &InboundDecoder,
    sink: &RealmEventsIngestSink,
    payload: Value,
) {
    match serde_json::from_value::<cokret_sdk::Event>(payload.clone()) {
        Ok(event) => emit_decoded_realm_event(decoder, sink, event),
        Err(error) => {
            tracing::debug!(
                error = %error,
                "realm events frame payload was not a typed Event; preserving legacy ingest payload"
            );
            sink.push_raw(payload);
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
                sleep_for(std::time::Duration::from_millis(
                    delay_ms.max(MIN_BACKOFF_MS),
                ))
                .await;
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

    // Resume from this realm's OWN cursor — never the account cursor.
    let after = ctx
        .state_store
        .read()
        .realm_events_cursor(realm_id)
        .filter(|cursor| !cursor.trim().is_empty() && cursor != "-");
    let realm_id_typed = match cokret_sdk::RealmId::new(realm_id.to_owned()) {
        Ok(realm_id) => realm_id,
        Err(error) => {
            tracing::warn!(error = %error, realm_id, "invalid realm id for events subscribe");
            return RealmIterationOutcome::Backoff {
                delay_ms: MIN_BACKOFF_MS,
            };
        }
    };
    let transport = crate::client_core::InksonRealmEventsTransport::new(sdk_http)
        .with_max_duration_ms(REALM_EVENTS_POLL_WINDOW_MS);
    let mut source = match transport
        .open_realm_events(&realm_id_typed, after.as_deref())
        .await
    {
        Ok(source) => source,
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
                // The realm cursor is broken/expired — clear it so the next
                // subscribe rebuilds from history, then retry promptly.
                let mut state_store = ctx.state_store;
                state_store.write().save_realm_events_cursor(realm_id, None);
                return RealmIterationOutcome::Backoff {
                    delay_ms: MIN_BACKOFF_MS,
                };
            }
            return RealmIterationOutcome::Backoff {
                delay_ms: MIN_BACKOFF_MS,
            };
        }
    };

    // A late response from a retired generation must not touch the store.
    if generation() != start_generation {
        return RealmIterationOutcome::Ok;
    }

    let decoder = InboundDecoder::new();
    let ingest_sink = RealmEventsIngestSink::default();
    let mut next_cursor = after.clone();
    let mut resubscribe = false;
    let mut reconnect_after_ms: Option<u64> = None;

    loop {
        let frame = match source.next_frame().await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
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
                    let mut state_store = ctx.state_store;
                    state_store.write().save_realm_events_cursor(realm_id, None);
                }
                return RealmIterationOutcome::Backoff {
                    delay_ms: MIN_BACKOFF_MS,
                };
            }
        };
        match frame.kind {
            EventsSubscribeFrameKind::Event => {
                if !frame.payload.is_null() {
                    route_realm_event_payload_for_legacy_ingest(
                        &decoder,
                        &ingest_sink,
                        frame.payload,
                    );
                }
                if let Some(cursor) = frame.cursor {
                    next_cursor = Some(cursor.into_string());
                }
            }
            EventsSubscribeFrameKind::CatchupComplete => {
                if let Some(cursor) = frame.cursor {
                    next_cursor = Some(cursor.into_string());
                }
            }
            // Heartbeat / frontier / epoch-rotation are liveness or
            // account-engine concerns; they carry no kanban operations.
            EventsSubscribeFrameKind::Heartbeat
            | EventsSubscribeFrameKind::Frontier
            | EventsSubscribeFrameKind::EpochRotation => {}
            // Dropped / resync: the server lost our position. Clear the realm
            // cursor and rebuild from history on the next iteration.
            EventsSubscribeFrameKind::Dropped | EventsSubscribeFrameKind::ResyncRequired => {
                resubscribe = true;
                reconnect_after_ms = reconnect_after_ms.or(frame.reconnect_after_ms);
            }
            EventsSubscribeFrameKind::Unauthorized => {
                return RealmIterationOutcome::AuthExpired;
            }
            // Fail-closed for unknown future frame kinds (`EventsSubscribeFrameKind`
            // is #[non_exhaustive]): no interpretable payload for this engine, so
            // skip the frame without advancing the cursor.
            _ => {}
        }
    }

    // Fold new events into the shared kanban overlay; bump the live epoch only
    // when something actually changed so the panel re-projects on real content.
    let event_payloads = ingest_sink.into_legacy_payloads();
    if !event_payloads.is_empty() {
        let changed = {
            let mut state_store = ctx.state_store;
            let mut guard = state_store.write();
            // Fold both the kanban board ops and the discussion message events
            // this realm stream carries — a cross-member message the account
            // stream never routed (unroutable) still lands locally here.
            let kanban_changed =
                crate::sync_engine::ingest_kanban_events(&mut guard, realm_id, &event_payloads);
            let message_changed =
                crate::sync_engine::ingest_message_events(&mut guard, realm_id, &event_payloads);
            let membership_changed =
                crate::sync_engine::ingest_membership_events(&mut guard, realm_id, &event_payloads);
            kanban_changed + message_changed + membership_changed
        };
        if changed > 0 {
            let mut realm_live_epoch = ctx.realm_live_epoch;
            let next = realm_live_epoch.peek().wrapping_add(1);
            realm_live_epoch.set(next);
        }
    }

    if resubscribe {
        let mut state_store = ctx.state_store;
        state_store.write().save_realm_events_cursor(realm_id, None);
        return RealmIterationOutcome::Backoff {
            delay_ms: reconnect_after_ms.unwrap_or(MIN_BACKOFF_MS),
        };
    }

    if let Some(cursor) = next_cursor {
        let mut state_store = ctx.state_store;
        state_store
            .write()
            .save_realm_events_cursor(realm_id, Some(cursor));
    }

    RealmIterationOutcome::Ok
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEST_REALM: &str = "ck:realm:01904100-0000-7000-8000-000000000001";

    fn test_realm_id() -> cokret_sdk::RealmId {
        cokret_sdk::RealmId::new(TEST_REALM).unwrap()
    }

    fn test_actor_id() -> cokret_sdk::Did {
        cokret_sdk::Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn test_event(kind: &str, payload: Value) -> cokret_sdk::Event {
        cokret_sdk::Event::new(
            kind,
            test_realm_id(),
            test_actor_id(),
            1,
            cokret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    }

    #[test]
    fn realm_events_sink_adapter_decodes_message_events_for_legacy_ingest() {
        let event = test_event(
            cokret_sdk::events::kinds::MESSAGE_CREATE,
            json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-000000000002",
                "track_name": "discussion",
                "content": {"kind": "ck.content.text", "body": "hello"}
            }),
        );
        let event_value = serde_json::to_value(&event).unwrap();
        let decoder = InboundDecoder::new();
        let sink = RealmEventsIngestSink::default();

        route_realm_event_payload_for_legacy_ingest(&decoder, &sink, event_value.clone());
        let payloads = sink.into_legacy_payloads();

        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0]["event_id"], event_value["event_id"]);
        assert_eq!(payloads[0]["kind"], event_value["kind"]);
        assert_eq!(payloads[0]["payload"], event_value["payload"]);
        let decoded = decoder
            .try_decode_event(serde_json::from_value(payloads[0].clone()).unwrap())
            .unwrap();
        assert!(matches!(decoded, DecodedInbound::Message(_)));
    }

    #[test]
    fn realm_events_sink_adapter_preserves_untyped_payload_for_legacy_ingest() {
        let raw = json!({
            "event_id": "remote-legacy",
            "event_kind": "ck.strand.update",
            "payload": {"title": "from projection shape"}
        });
        let decoder = InboundDecoder::new();
        let sink = RealmEventsIngestSink::default();

        route_realm_event_payload_for_legacy_ingest(&decoder, &sink, raw.clone());
        let payloads = sink.into_legacy_payloads();

        assert_eq!(payloads, vec![raw]);
    }
}
