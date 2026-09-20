//! The one WebSocket a session may hold, and the transports the stream engines
//! take off it.
//!
//! `ak.profile.binding.websocket.v1` asks an authenticated Station session to
//! establish a single Arkret WebSocket and multiplex the covered operations on
//! it. inkson runs the account aggregate and the Signal rail as independently
//! spawned engines, so "one socket" has to be a shared service rather than
//! something one engine owns.
//!
//! [`WebSocketRail`] is that service. A dedicated engine establishes the
//! connection, publishes the delivered frames here, and pumps; the stream
//! engines ask the rail for a transport each time they (re)connect and get the
//! socket-backed delivery when the rail is live, or the canonical HTTP client
//! when it is not.
//!
//! Falling back is therefore the ordinary path, not an error path: the rail
//! detaches, the next connection attempt returns HTTP, and the engine keeps
//! running.
//!
//! The binding carries **one** subscription per socket
//! (`WebSocketSubscribeRequest`), which fans out `account` frames and — when
//! `include_signals` is set — `signal` envelopes. There is no separate per-Realm
//! events channel: Realm commits ride the account frames, and a stream tail
//! pull is `ak.self.events.read.scan.v1` over the canonical HTTPS binding.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeSnapshotResult, SyncRequestBody,
};
use arkret_wire::SignalEnvelope;
use garth::websocket::{BoxSocketFuture, WebSocketPacer};

use super::websocket::{
    WebSocketHandshakeFailure, WebSocketTransportDecision, WebSocketTransportSelector,
};

/// How a channel adapter yields to the pump loop. The cadence matches the
/// engines' own beat, so an adapter never becomes the slow part of a frame that
/// the pump has already read.
#[derive(Clone, Copy, Debug, Default)]
pub struct InksonPacer;

impl WebSocketPacer for InksonPacer {
    fn pace(&self) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move {
            crate::runtime_helpers::sleep_for(garth::websocket::socket::CHANNEL_PACE).await;
            Ok(())
        })
    }
}

/// Largest number of undelivered frames the rail buffers per kind.
///
/// The socket's own byte ceiling bounds one frame; this bounds how many the
/// pump may run ahead of a consumer before the rail stops being a useful
/// low-latency path and the connection is torn down instead of growing without
/// bound.
const MAX_BUFFERED_FRAMES: usize = 256;

/// The frames one live connection has delivered and not yet handed to a
/// consumer.
#[derive(Debug, Default)]
struct RailQueues {
    account: VecDeque<AccountSubscribeFrame>,
    signals: VecDeque<SignalEnvelope>,
    /// The Station asked for a reconnect; the consumer stops after draining.
    reconnect_after_ms: Option<u64>,
    /// The last cursor the Station acknowledged for this subscription.
    cursor: Option<String>,
    closed: bool,
}

/// A live connection's shared delivery state.
///
/// Held behind `Arc<Mutex<_>>` rather than `Rc<RefCell<_>>` so the rail can be
/// observed from the run loops the shared client runtime drives, which are
/// `Send` on native.
#[derive(Clone, Debug, Default)]
pub struct SharedConnection {
    queues: Arc<Mutex<RailQueues>>,
}

impl SharedConnection {
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, apply: impl FnOnce(&mut RailQueues) -> R) -> R {
        let mut queues = self
            .queues
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        apply(&mut queues)
    }

    /// Publish one delivered account frame. `false` means the buffer is full
    /// and the connection must be torn down rather than silently dropping it.
    #[must_use]
    pub fn push_account_frame(&self, frame: AccountSubscribeFrame) -> bool {
        self.with(|queues| {
            if queues.account.len() >= MAX_BUFFERED_FRAMES {
                return false;
            }
            queues.account.push_back(frame);
            true
        })
    }

    /// Publish one delivered Signal envelope.
    #[must_use]
    pub fn push_signal(&self, envelope: SignalEnvelope) -> bool {
        self.with(|queues| {
            if queues.signals.len() >= MAX_BUFFERED_FRAMES {
                return false;
            }
            queues.signals.push_back(envelope);
            true
        })
    }

    pub fn set_cursor(&self, cursor: String) {
        self.with(|queues| queues.cursor = Some(cursor));
    }

    pub fn request_reconnect(&self, after_ms: u64) {
        self.with(|queues| queues.reconnect_after_ms = Some(after_ms));
    }

    pub fn close(&self) {
        self.with(|queues| queues.closed = true);
    }

    fn take_account_batch(&self) -> Option<AccountSubscribeSnapshotResult> {
        self.with(|queues| {
            if let Some(reconnect_after_ms) = queues.reconnect_after_ms.take() {
                return Some(AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms,
                    reconnect_cursor: queues.cursor.clone(),
                    reason: None,
                    reset_cursor: false,
                });
            }
            let cursor = queues.cursor.clone()?;
            if queues.account.is_empty() {
                return None;
            }
            Some(AccountSubscribeSnapshotResult::Batch(
                AccountSubscribeBatch {
                    frames: queues.account.drain(..).collect(),
                    cursor,
                },
            ))
        })
    }

    fn take_signal(&self) -> Option<SignalEnvelope> {
        self.with(|queues| queues.signals.pop_front())
    }

    fn is_closed(&self) -> bool {
        self.with(|queues| queues.closed)
    }
}

/// The session's single WebSocket, shared across the stream engines.
#[derive(Clone, Debug, Default)]
pub struct WebSocketRail {
    inner: Arc<Mutex<RailState>>,
}

#[derive(Debug, Default)]
struct RailState {
    connection: Option<SharedConnection>,
    selector: Option<WebSocketTransportSelector>,
}

impl WebSocketRail {
    fn with<R>(&self, apply: impl FnOnce(&mut RailState) -> R) -> R {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        apply(&mut state)
    }

    /// Record the descriptor decision for this session. A `None` descriptor —
    /// no advertised binding, or one this build cannot honour — keeps every
    /// stream on HTTP.
    pub fn set_selector(&self, selector: WebSocketTransportSelector) {
        self.with(|state| state.selector = Some(selector));
    }

    /// Whether a usable descriptor is currently known.
    pub fn is_advertised(&self) -> bool {
        self.with(|state| {
            state
                .selector
                .as_ref()
                .is_some_and(|selector| selector.descriptor().is_some())
        })
    }

    /// The canonical `base_url` to connect to, if any.
    pub fn base_url(&self) -> Option<String> {
        self.with(|state| {
            state
                .selector
                .as_ref()
                .and_then(|selector| selector.descriptor())
                .map(|descriptor| descriptor.base_url.clone())
        })
    }

    /// The advertised frame ceiling of the current descriptor.
    pub fn max_frame_bytes(&self) -> Option<u32> {
        self.with(|state| {
            state
                .selector
                .as_ref()
                .and_then(|selector| selector.descriptor())
                .map(|descriptor| descriptor.max_frame_bytes)
        })
    }

    /// Publish a live connection. From here the stream engines take delivery.
    pub fn attach(&self, connection: SharedConnection) {
        self.with(|state| state.connection = Some(connection));
    }

    /// Withdraw the connection. Every engine's next attempt returns HTTP.
    pub fn detach(&self) {
        self.with(|state| state.connection = None);
    }

    pub fn is_live(&self) -> bool {
        self.with(|state| state.connection.is_some())
    }

    /// Apply the §8.1 decision table to a finished connection and report
    /// whether the rail should try the WebSocket again.
    pub fn on_close(
        &self,
        code: arkret_wire::websocket_binding::WebSocketCloseCode,
        drain_reconnect_after_ms: Option<u32>,
    ) -> WebSocketTransportDecision {
        self.detach();
        self.with(|state| match state.selector.as_mut() {
            Some(selector) => selector.on_close(code, drain_reconnect_after_ms),
            None => WebSocketTransportDecision::FallbackHttp,
        })
    }

    /// An upgrade / subprotocol / proxy failure. §8.1 gives these no retry, and
    /// the descriptor is dropped until discovery changes.
    pub fn on_handshake_failure(
        &self,
        failure: WebSocketHandshakeFailure,
    ) -> WebSocketTransportDecision {
        self.detach();
        self.with(|state| match state.selector.as_mut() {
            Some(selector) => selector.on_handshake_failure(failure),
            None => WebSocketTransportDecision::FallbackHttp,
        })
    }

    /// A connection reached `welcome`: both retry budgets reset.
    pub fn welcomed(&self) {
        self.with(|state| {
            if let Some(selector) = state.selector.as_mut() {
                selector.welcomed();
            }
        });
    }

    fn connection(&self) -> Option<SharedConnection> {
        self.with(|state| state.connection.clone())
    }
}

/// The transport one stream engine uses for one connection attempt.
///
/// The HTTP client is always present. The binding covers exactly the account
/// subscription and the Signal rail, so everything else an engine does — a
/// stream scan, a submission, a blob — keeps using the canonical HTTPS binding
/// whether the rail is live or not.
///
/// §8 forbids holding a WebSocket and an HTTP consumer for the *same* stream at
/// once, and that holds structurally here: a covered operation resolves to one
/// or the other, never both.
#[derive(Clone, Debug)]
pub struct StreamRail<H> {
    http: H,
    websocket: Option<SharedConnection>,
}

impl<H> StreamRail<H> {
    /// Take the rail's connection when it is live.
    pub fn select(rail: &WebSocketRail, http: H) -> Self {
        let selected = Self {
            http,
            websocket: rail.connection(),
        };
        // Which binding a stream actually landed on is the first thing worth
        // knowing when a deployment reports latency or reconnect behaviour, and
        // it is not otherwise observable from outside.
        tracing::debug!(
            websocket = selected.is_websocket(),
            "stream transport selected"
        );
        selected
    }

    /// The canonical HTTP client, for everything the profile does not cover.
    pub fn http(&self) -> &H {
        &self.http
    }

    pub fn is_websocket(&self) -> bool {
        self.websocket.is_some()
    }
}

impl<H> garth::AccountSubscribeTransport for StreamRail<H>
where
    H: garth::AccountSubscribeTransport,
{
    /// One bounded delivery window of the account aggregate.
    ///
    /// On the socket the request was already installed by the rail engine's
    /// `subscribe` frame, so this only drains what the pump delivered. A rail
    /// that ended mid-window reports a reconnect rather than a short batch, so
    /// the caller resumes from the durable cursor instead of treating the gap
    /// as the tail.
    async fn subscribe(
        &self,
        request: &SyncRequestBody,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let Some(connection) = self.websocket.as_ref() else {
            return self.http.subscribe(request).await;
        };
        loop {
            if let Some(result) = connection.take_account_batch() {
                return Ok(result);
            }
            if connection.is_closed() {
                return Ok(AccountSubscribeSnapshotResult::ReconnectAfter {
                    reconnect_after_ms:
                        arkret_models_collaboration::sync_frames::account_subscribe::DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
                    reconnect_cursor: None,
                    reason: Some("websocket rail closed".to_owned()),
                    reset_cursor: false,
                });
            }
            InksonPacer.pace().await?;
        }
    }
}

// The Signal rail deliberately has no WebSocket source here.
//
// `garth::SignalReceiver` admits an envelope only together with the
// Station-issued `arkret_wire::SignalDeliveryAuthority` that
// `SignalStreamFrame::Signal` carries, but the WebSocket binding's own
// `signal` server frame
// (`arkret_models_collaboration::sync_frames::websocket::WebSocketServerFrame`)
// carries the bare `SignalEnvelope` and no delivery authority. Admitting a
// socket-delivered envelope would therefore mean inventing an authority in the
// client, which is exactly what the sender-key resolver removal forbids, so the
// Signal engine stays on the canonical `ak.self.signal.stream.subscribe.v1`
// binding until the socket frame carries one.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rail_without_a_selector_keeps_every_stream_on_http() {
        let rail = WebSocketRail::default();
        assert!(!rail.is_advertised());
        assert!(!rail.is_live());
        assert!(rail.base_url().is_none());
        let selected: StreamRail<()> = StreamRail::select(&rail, ());
        assert!(!selected.is_websocket());
    }

    #[test]
    fn an_unadvertised_binding_never_becomes_live() {
        let rail = WebSocketRail::default();
        rail.set_selector(WebSocketTransportSelector::from_describe(
            &crate::transport::websocket::tests_support::describe_without_websocket(),
        ));
        assert!(!rail.is_advertised());
        assert!(rail.base_url().is_none());
    }

    #[test]
    fn an_advertised_binding_publishes_its_canonical_target() {
        let rail = WebSocketRail::default();
        rail.set_selector(WebSocketTransportSelector::from_describe(
            &crate::transport::websocket::tests_support::describe_with_websocket(),
        ));
        assert!(rail.is_advertised());
        assert_eq!(
            rail.base_url().as_deref(),
            Some("wss://server.example/_arkret/ws")
        );
        // Advertised is not live: nothing is usable until the rail engine has
        // completed a handshake and attached the connection.
        assert!(!rail.is_live());
    }

    #[test]
    fn an_incompatible_close_detaches_and_stops_retrying() {
        let rail = WebSocketRail::default();
        rail.set_selector(WebSocketTransportSelector::from_describe(
            &crate::transport::websocket::tests_support::describe_with_websocket(),
        ));
        rail.welcomed();
        assert_eq!(
            rail.on_close(
                arkret_wire::websocket_binding::WebSocketCloseCode::ProtocolError,
                None
            ),
            WebSocketTransportDecision::FallbackHttp
        );
        assert!(!rail.is_live());
        assert!(!rail.is_advertised());
    }

    #[test]
    fn a_full_account_buffer_refuses_the_frame_instead_of_growing() {
        let connection = SharedConnection::new();
        let frame: AccountSubscribeFrame =
            serde_json::from_value(serde_json::json!({"kind": "heartbeat"})).unwrap();
        for _ in 0..MAX_BUFFERED_FRAMES {
            assert!(connection.push_account_frame(frame.clone()));
        }
        assert!(!connection.push_account_frame(frame));
    }

    #[test]
    fn a_drained_window_without_a_cursor_is_not_a_batch() {
        let connection = SharedConnection::new();
        let frame: AccountSubscribeFrame =
            serde_json::from_value(serde_json::json!({"kind": "heartbeat"})).unwrap();
        assert!(connection.push_account_frame(frame));
        // The Station acknowledges the subscription cursor before any frame is
        // a resumable batch; without it there is nothing to checkpoint.
        assert!(connection.take_account_batch().is_none());
        connection.set_cursor("ak:cursor:one".to_owned());
        let Some(AccountSubscribeSnapshotResult::Batch(batch)) = connection.take_account_batch()
        else {
            panic!("a cursor-acknowledged window is a batch");
        };
        assert_eq!(batch.frames.len(), 1);
        assert_eq!(batch.cursor, "ak:cursor:one");
    }
}
