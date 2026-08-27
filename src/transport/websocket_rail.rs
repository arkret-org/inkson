//! The one WebSocket a session may hold, and the transports the three stream
//! engines take off it.
//!
//! §1 asks an authenticated Principal Server session to establish a single
//! Arkret WebSocket and multiplex the covered operations as channels on it.
//! inkson runs account, events and Signal as three independently spawned
//! engines, so "one socket" has to be a shared service rather than something
//! any one engine owns.
//!
//! [`WebSocketRail`] is that service. A dedicated engine establishes the
//! connection, publishes the shared channel state here, and pumps; the three
//! stream engines ask the rail for a transport each time they (re)connect and
//! get a WebSocket channel when the rail is live, or the canonical HTTP client
//! when it is not.
//!
//! Falling back is therefore the ordinary path, not an error path: the rail
//! detaches, the next `provide()` returns HTTP, and the engine keeps running.

use std::cell::RefCell;
use std::rc::Rc;

use garth::subscribe::realm::{BoxRealmStreamFuture, RealmEventsFrameSource, RealmEventsTransport};
use garth::subscribe::signal::{
    BoxSignalStreamFuture, SignalStreamFrameSource, SignalStreamTransport,
};
use garth::websocket::socket::{BoxSocketFuture, WebSocketPacer};
use garth::websocket::{
    SharedConnection, WebSocketEventsChannel, WebSocketSignalChannel, WebSocketTransport,
};
use garth::{AsyncSyncTransport, BoxSyncFuture};

use super::websocket::WebSocketTransportSelector;

/// How a channel adapter yields to the pump loop. The cadence matches the
/// engines' own beat, so an adapter never becomes the slow part of a frame that
/// the pump has already read.
#[derive(Clone, Copy, Debug, Default)]
pub struct InksonPacer;

impl WebSocketPacer for InksonPacer {
    fn pace(&self) -> BoxSocketFuture<'_, ()> {
        Box::pin(async move {
            crate::runtime_helpers::sleep_for(std::time::Duration::from_millis(10)).await;
            Ok(())
        })
    }
}

type RailTransport = WebSocketTransport<InksonPacer>;

/// The session's single WebSocket, shared across the stream engines.
///
/// `Rc<RefCell<_>>` like the other runtime services: inkson drives every engine
/// on one thread, and the borrow here only ever spans a synchronous read.
#[derive(Clone, Default)]
pub struct WebSocketRail {
    inner: Rc<RefCell<RailState>>,
}

#[derive(Default)]
struct RailState {
    connection: Option<SharedConnection>,
    selector: Option<WebSocketTransportSelector>,
}

impl WebSocketRail {
    /// Record the descriptor decision for this session. `None` — no advertised
    /// binding, or one this build cannot honour — keeps every stream on HTTP.
    pub fn set_selector(&self, selector: WebSocketTransportSelector) {
        self.inner.borrow_mut().selector = Some(selector);
    }

    /// Whether a usable descriptor is currently known.
    pub fn is_advertised(&self) -> bool {
        self.inner
            .borrow()
            .selector
            .as_ref()
            .is_some_and(|selector| selector.descriptor().is_some())
    }

    /// The canonical `base_url` to connect to, if any.
    pub fn base_url(&self) -> Option<String> {
        self.inner
            .borrow()
            .selector
            .as_ref()
            .and_then(|selector| selector.descriptor())
            .map(|descriptor| descriptor.base_url.clone())
    }

    /// The advertised frame ceiling of the current descriptor.
    pub fn max_frame_bytes(&self) -> Option<u32> {
        self.inner
            .borrow()
            .selector
            .as_ref()
            .and_then(|selector| selector.descriptor())
            .map(|descriptor| descriptor.max_frame_bytes)
    }

    /// Publish a live connection. From here the stream engines take channels.
    pub fn attach(&self, connection: SharedConnection) {
        self.inner.borrow_mut().connection = Some(connection);
    }

    /// Withdraw the connection. Every engine's next `provide()` returns HTTP.
    pub fn detach(&self) {
        self.inner.borrow_mut().connection = None;
    }

    pub fn is_live(&self) -> bool {
        self.inner.borrow().connection.is_some()
    }

    /// Apply the §8.1 decision table to a finished connection and report
    /// whether the rail should try the WebSocket again.
    pub fn on_close(
        &self,
        code: arkret_wire::websocket_binding::WebSocketCloseCode,
        drain_reconnect_after_ms: Option<u32>,
    ) -> garth::websocket::WebSocketTransportDecision {
        self.detach();
        let mut state = self.inner.borrow_mut();
        match state.selector.as_mut() {
            Some(selector) => selector.on_close(code, drain_reconnect_after_ms),
            None => garth::websocket::WebSocketTransportDecision::FallbackHttp,
        }
    }

    /// An upgrade / subprotocol / proxy failure. §8.1 gives these no retry, and
    /// the descriptor is dropped until discovery changes.
    pub fn on_handshake_failure(
        &self,
        failure: garth::websocket::WebSocketHandshakeFailure,
    ) -> garth::websocket::WebSocketTransportDecision {
        self.detach();
        let mut state = self.inner.borrow_mut();
        match state.selector.as_mut() {
            Some(selector) => selector.on_handshake_failure(failure),
            None => garth::websocket::WebSocketTransportDecision::FallbackHttp,
        }
    }

    /// A connection reached `welcome`: both retry budgets reset.
    pub fn welcomed(&self) {
        if let Some(selector) = self.inner.borrow_mut().selector.as_mut() {
            selector.welcomed();
        }
    }

    fn transport(&self) -> Option<RailTransport> {
        self.inner
            .borrow()
            .connection
            .as_ref()
            .map(|connection| WebSocketTransport::new(connection.clone(), InksonPacer))
    }
}

/// The transport one stream engine uses for one connection attempt.
///
/// The HTTP client is always present. §1 covers exactly three stream
/// operations, so everything else an engine does — a scan, a post-commit
/// write, a blob — keeps using the canonical HTTPS binding whether the rail is
/// live or not. Only the covered operations consult `websocket`.
///
/// §8 forbids holding a WebSocket and an HTTP consumer for the *same* stream at
/// once, and that holds structurally here: a covered operation resolves to one
/// or the other, never both.
pub struct StreamRail<H> {
    http: H,
    websocket: Option<RailTransport>,
}

impl<H> StreamRail<H> {
    /// Take the rail's connection when it is live.
    pub fn select(rail: &WebSocketRail, http: H) -> Self {
        let selected = Self {
            http,
            websocket: rail.transport(),
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

impl<H> AsyncSyncTransport for StreamRail<H>
where
    H: AsyncSyncTransport,
{
    fn sync_async<'a>(
        &'a self,
        request: arkret_sdk::SyncRequestBody,
        options: arkret_sdk::http_client::ClientRequestOptions,
    ) -> BoxSyncFuture<'a, arkret_sdk::AccountSubscribeBatch> {
        let Some(transport) = self.websocket.as_ref() else {
            return self.http.sync_async(request, options);
        };
        Box::pin(async move {
            // The channel carries the resume cursor in its `open`, so the
            // per-batch request body is the same one `SyncLoop` would have sent
            // over HTTP and is consumed there.
            let channel = transport.open_account(request.after.as_deref())?;
            channel.sync_async(request, options).await
        })
    }
}

/// One events source, whichever transport produced it.
pub enum RealmEventsSource<S> {
    Http(S),
    WebSocket(WebSocketEventsChannel<InksonPacer>),
}

impl<S> RealmEventsFrameSource for RealmEventsSource<S>
where
    S: RealmEventsFrameSource,
{
    fn next_frame<'a>(
        &'a mut self,
    ) -> BoxRealmStreamFuture<'a, Option<arkret_sdk::EventsSubscribeFrame>> {
        match self {
            Self::Http(source) => source.next_frame(),
            Self::WebSocket(channel) => channel.next_frame(),
        }
    }
}

impl<H> RealmEventsTransport for StreamRail<H>
where
    H: RealmEventsTransport + Sync,
{
    type Source = RealmEventsSource<H::Source>;

    fn open_realm_events<'a>(
        &'a self,
        realm_id: &'a arkret_sdk::RealmId,
        after: Option<&'a str>,
    ) -> BoxRealmStreamFuture<'a, Self::Source> {
        let Some(transport) = self.websocket.as_ref() else {
            let http = &self.http;
            return Box::pin(async move {
                http.open_realm_events(realm_id, after)
                    .await
                    .map(RealmEventsSource::Http)
            });
        };
        Box::pin(async move {
            transport
                .open_events(vec![realm_id.clone()], after)
                .map(RealmEventsSource::WebSocket)
        })
    }
}

impl<H> garth::EventsScanTransport for StreamRail<H>
where
    H: garth::EventsScanTransport,
{
    /// §1 — `ak.self.events.read.scan.v1` is not a covered operation, so a scan
    /// always uses the canonical HTTPS binding even while the rail is live.
    fn scan_events<'a>(
        &'a self,
        request: garth::EventsScanRequest,
    ) -> garth::subscribe::scan::BoxScanFuture<'a, arkret_sdk::EventsQueryOutcome> {
        self.http.scan_events(request)
    }
}

/// One Signal source, whichever transport produced it.
pub enum SignalSource<S> {
    Http(S),
    WebSocket(WebSocketSignalChannel<InksonPacer>),
}

impl<S> SignalStreamFrameSource for SignalSource<S>
where
    S: SignalStreamFrameSource,
{
    fn next_frame<'a>(
        &'a mut self,
    ) -> BoxSignalStreamFuture<'a, Option<arkret_wire::SignalStreamFrame>> {
        match self {
            Self::Http(source) => source.next_frame(),
            Self::WebSocket(channel) => channel.next_frame(),
        }
    }
}

impl<H> SignalStreamTransport for StreamRail<H>
where
    H: SignalStreamTransport + Sync,
{
    type Source = SignalSource<H::Source>;

    fn open_signal_stream<'a>(&'a self) -> BoxSignalStreamFuture<'a, Self::Source> {
        let Some(transport) = self.websocket.as_ref() else {
            let http = &self.http;
            return Box::pin(
                async move { http.open_signal_stream().await.map(SignalSource::Http) },
            );
        };
        Box::pin(async move { transport.open_signal().map(SignalSource::WebSocket) })
    }
}

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
            garth::websocket::WebSocketTransportDecision::FallbackHttp
        );
        assert!(!rail.is_live());
        assert!(!rail.is_advertised());
    }
}
