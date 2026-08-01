//! Host wiring for `ak.profile.binding.websocket.v1`.
//!
//! The protocol lives in the SDK and the connection lives in garth; this module
//! only supplies what neither can own: the platform socket, the holder-key
//! signature, and the decision of *whether to use the binding at all*.
//!
//! That decision is the important half. §2 makes an unknown, incomplete or
//! non-canonical descriptor a fallback condition, not an error, and §10 forbids
//! a service from advertising the profile before its conformance suite passes.
//! So the WebSocket binding is never a precondition here: every stream keeps
//! working on canonical HTTP/JSON + bounded NDJSON, and the socket is an
//! optimisation the client takes only when the service says it may.

#[cfg(not(target_arch = "wasm32"))]
use arkret_wire::websocket_binding::WEBSOCKET_HARD_MAX_FRAME_BYTES;
use arkret_wire::websocket_binding::WebSocketCloseCode;
use garth::websocket::socket::{
    AuthProofRequest, BoxSocketFuture, WebSocketConnector, WebSocketInbound, WebSocketSocket,
};
use garth::websocket::{
    WebSocketBindingDescriptor, WebSocketConsumerHandoff, WebSocketConsumerOwner,
    WebSocketFallbackPolicy, WebSocketHandshakeFailure, WebSocketTransportDecision,
    select_websocket_binding,
};

/// The largest reassembled frame this client will buffer, independent of what
/// a service advertises. §4 caps the effective limit at the minimum of
/// discovery, `welcome` and the 1 MiB hard ceiling; this is the client's own
/// term in that minimum.
pub const CLIENT_MAX_FRAME_BYTES: u32 = 262_144;

/// Which transport the stream engines should use right now.
///
/// `None` means the mandatory HTTP binding, and it is the answer for every
/// condition §2 and §8.1 list: no descriptor, an unusable descriptor, a
/// handshake that never reached `101`, a protocol or oversize close, a second
/// policy failure, or a third restart without a `welcome`.
pub struct WebSocketTransportSelector {
    descriptor: Option<WebSocketBindingDescriptor>,
    policy: WebSocketFallbackPolicy,
    handoff: WebSocketConsumerHandoff,
}

impl WebSocketTransportSelector {
    /// Read the service description once. An entry this build cannot honour is
    /// skipped silently — §2 says to ignore the binding and stay on HTTP, never
    /// to guess an endpoint.
    pub fn from_describe(describe: &arkret_sdk::ServiceDescribe) -> Self {
        Self {
            descriptor: select_websocket_binding(describe, CLIENT_MAX_FRAME_BYTES),
            policy: WebSocketFallbackPolicy::new(),
            handoff: WebSocketConsumerHandoff::new(),
        }
    }

    /// The binding to connect to, or `None` to stay on HTTP.
    pub fn descriptor(&self) -> Option<&WebSocketBindingDescriptor> {
        self.descriptor.as_ref()
    }

    /// A connection reached `welcome`: both §8.1 retry budgets reset.
    pub fn welcomed(&mut self) {
        self.policy.welcomed();
    }

    /// Decide what to do after a connection ended.
    pub fn on_close(
        &mut self,
        code: WebSocketCloseCode,
        drain_reconnect_after_ms: Option<u32>,
    ) -> WebSocketTransportDecision {
        let decision = self.policy.on_close(code, drain_reconnect_after_ms);
        if matches!(decision, WebSocketTransportDecision::FallbackHttp) {
            // §8.1 — `1002` / `1009` mean this binding is incompatible with the
            // client, so the descriptor is dropped until discovery changes.
            if code.forces_http_fallback() {
                self.descriptor = None;
            }
        }
        decision
    }

    /// An upgrade, subprotocol or proxy failure. §8.1 gives these no retry.
    pub fn on_handshake_failure(
        &mut self,
        failure: WebSocketHandshakeFailure,
    ) -> WebSocketTransportDecision {
        self.descriptor = None;
        self.policy.on_handshake_failure(failure)
    }

    /// The ordered handoff §8 requires: stop the old owner, persist its durable
    /// cursors, only then start the new one. Holding both is what the rule
    /// exists to prevent.
    pub fn switch_owner(&mut self, owner: WebSocketConsumerOwner) -> garth::Result<()> {
        self.handoff.stop();
        self.handoff.persist_cursors();
        self.handoff
            .switch_to(owner)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }

    pub fn owner(&self) -> WebSocketConsumerOwner {
        self.handoff.owner()
    }

    /// Start the first owner of this session's stream consumers.
    pub fn start_owner(&mut self, owner: WebSocketConsumerOwner) -> garth::Result<()> {
        self.handoff
            .start(owner)
            .map_err(|error| garth::Error::Protocol(error.to_string()))
    }
}

/// Signs `challenge_dpop_session_v1` with the session's holder key and opens
/// the platform socket.
///
/// The key stays inside the DPoP handle: this connector asks it for a proof
/// rather than holding private bytes of its own, so the WebSocket context adds
/// no second place a holder key can leak from.
pub struct InksonWebSocketConnector {
    session_grant: String,
    holder: crate::identity::account_auth::grant_dpop::DpopHandle,
}

impl InksonWebSocketConnector {
    pub fn new(
        session_grant: String,
        holder: crate::identity::account_auth::grant_dpop::DpopHandle,
    ) -> Self {
        Self {
            session_grant,
            holder,
        }
    }

    /// The grant this connector authenticates with, for a reauth that needs to
    /// bind `ath` to the same value.
    pub fn grant(&self) -> String {
        self.session_grant.clone()
    }
}

impl WebSocketConnector for InksonWebSocketConnector {
    type Socket = PlatformWebSocket;

    fn connect<'a>(&'a self, base_url: &'a str) -> BoxSocketFuture<'a, Self::Socket> {
        Box::pin(async move { PlatformWebSocket::open(base_url).await })
    }

    fn session_grant(&self) -> BoxSocketFuture<'_, String> {
        let grant = self.session_grant.clone();
        Box::pin(async move { Ok(grant) })
    }

    fn sign_auth_proof<'a>(&'a self, request: &'a AuthProofRequest) -> BoxSocketFuture<'a, String> {
        Box::pin(async move {
            self.holder
                .mint_websocket_auth_proof(
                    &request.base_url,
                    &request.session_grant,
                    &request.nonce,
                    &request.jti,
                    crate::clock::now_utc(),
                )
                .map_err(|error| garth::Error::Protocol(error.to_string()))
        })
    }
}

#[cfg(target_arch = "wasm32")]
pub use browser::PlatformWebSocket;
#[cfg(not(target_arch = "wasm32"))]
pub use native::PlatformWebSocket;

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::http::HeaderValue;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
    use tokio_tungstenite::tungstenite::protocol::{CloseFrame, WebSocketConfig};

    use super::*;

    type Stream = tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >;

    /// Native socket. Reassembly and the byte ceiling are tungstenite's, which
    /// is why `max_message_size` is set from the client's own limit: §4 wants
    /// the gate to trip before an unbounded buffer exists.
    pub struct PlatformWebSocket {
        stream: Stream,
    }

    impl PlatformWebSocket {
        pub(super) async fn open(base_url: &str) -> garth::Result<Self> {
            let mut request = base_url
                .into_client_request()
                .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            request.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static(arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL),
            );
            let config = WebSocketConfig::default()
                .max_message_size(Some(CLIENT_MAX_FRAME_BYTES as usize))
                .max_frame_size(Some(WEBSOCKET_HARD_MAX_FRAME_BYTES));
            let (stream, response) =
                tokio_tungstenite::connect_async_with_config(request, Some(config), false)
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))?;
            // §2 / §8.1 — a connection whose subprotocol was not selected is
            // not an Arkret sync binding, and it gets no WebSocket retry.
            let selected = response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok());
            if selected != Some(arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL) {
                return Err(garth::Error::Protocol(
                    "the service did not select the arkret.v1 subprotocol".to_owned(),
                ));
            }
            Ok(Self { stream })
        }
    }

    impl WebSocketSocket for PlatformWebSocket {
        fn recv(&mut self) -> BoxSocketFuture<'_, Option<WebSocketInbound>> {
            Box::pin(async move {
                loop {
                    return match self.stream.next().await {
                        None => Ok(None),
                        Some(Ok(Message::Text(text))) => {
                            Ok(Some(WebSocketInbound::Text(text.to_string())))
                        }
                        Some(Ok(Message::Binary(_))) => Ok(Some(WebSocketInbound::Binary)),
                        Some(Ok(Message::Close(frame))) => Ok(Some(WebSocketInbound::Closed(
                            frame.map(|frame| u16::from(frame.code)),
                        ))),
                        // Transport-level keepalives are answered by
                        // tungstenite and carry no Arkret frame.
                        Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {
                            continue;
                        }
                        Some(Err(tokio_tungstenite::tungstenite::Error::Capacity(_))) => {
                            Ok(Some(WebSocketInbound::TooLarge))
                        }
                        Some(Err(error)) => Err(garth::Error::Protocol(error.to_string())),
                    };
                }
            })
        }

        fn send_text(&mut self, payload: String) -> BoxSocketFuture<'_, ()> {
            Box::pin(async move {
                self.stream
                    .send(Message::text(payload))
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))
            })
        }

        fn close<'a>(
            &'a mut self,
            code: WebSocketCloseCode,
            reason: &'a str,
        ) -> BoxSocketFuture<'a, ()> {
            Box::pin(async move {
                let frame = CloseFrame {
                    code: CloseCode::from(code.as_u16()),
                    reason: reason.into(),
                };
                let _ = self.stream.send(Message::Close(Some(frame))).await;
                self.stream
                    .close(None)
                    .await
                    .map_err(|error| garth::Error::Protocol(error.to_string()))
            })
        }
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::time::Duration;

    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    use web_sys::{CloseEvent, MessageEvent};

    use super::*;

    /// How often a pending `recv` re-checks the event queue.
    ///
    /// The browser delivers messages through event callbacks, and this build
    /// has no cross-callback waker. Polling on the same cadence garth uses for
    /// its channel adapters keeps the two consistent and adds no dependency.
    const POLL: Duration = Duration::from_millis(5);

    #[derive(Default)]
    struct Inbox {
        messages: VecDeque<WebSocketInbound>,
        opened: bool,
        failed: bool,
    }

    /// Browser socket over the platform `WebSocket`.
    pub struct PlatformWebSocket {
        socket: web_sys::WebSocket,
        inbox: Rc<RefCell<Inbox>>,
        // Kept alive for the socket's lifetime; dropping a closure detaches the
        // handler and would silently stop delivery.
        _on_message: Closure<dyn FnMut(MessageEvent)>,
        _on_close: Closure<dyn FnMut(CloseEvent)>,
        _on_error: Closure<dyn FnMut(web_sys::Event)>,
        _on_open: Closure<dyn FnMut(web_sys::Event)>,
    }

    impl PlatformWebSocket {
        pub(super) async fn open(base_url: &str) -> garth::Result<Self> {
            let socket = web_sys::WebSocket::new_with_str(
                base_url,
                arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL,
            )
            .map_err(|_| garth::Error::Protocol("the browser refused the WebSocket".to_owned()))?;

            let inbox = Rc::new(RefCell::new(Inbox::default()));
            let message_inbox = inbox.clone();
            let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                let entry = match event.data().as_string() {
                    Some(text) => WebSocketInbound::Text(text),
                    // §4 — anything that is not a text message is a protocol
                    // error, surfaced rather than dropped.
                    None => WebSocketInbound::Binary,
                };
                message_inbox.borrow_mut().messages.push_back(entry);
            });
            socket.set_onmessage(Some(on_message.as_ref().unchecked_ref()));

            let close_inbox = inbox.clone();
            let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |event: CloseEvent| {
                close_inbox
                    .borrow_mut()
                    .messages
                    .push_back(WebSocketInbound::Closed(Some(event.code())));
            });
            socket.set_onclose(Some(on_close.as_ref().unchecked_ref()));

            let error_inbox = inbox.clone();
            let on_error = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                error_inbox.borrow_mut().failed = true;
            });
            socket.set_onerror(Some(on_error.as_ref().unchecked_ref()));

            let open_inbox = inbox.clone();
            let on_open = Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                open_inbox.borrow_mut().opened = true;
            });
            socket.set_onopen(Some(on_open.as_ref().unchecked_ref()));

            // Wait for the handshake to settle. `protocol` is only meaningful
            // once the socket is open, and §2 makes a missing `arkret.v1` a
            // hard stop rather than a degraded connection.
            loop {
                {
                    let state = inbox.borrow();
                    if state.failed {
                        return Err(garth::Error::Protocol(
                            "the WebSocket upgrade failed".to_owned(),
                        ));
                    }
                    if state.opened {
                        break;
                    }
                }
                gloo_timers::future::sleep(POLL).await;
            }
            if socket.protocol() != arkret_wire::websocket_binding::WEBSOCKET_SUBPROTOCOL {
                return Err(garth::Error::Protocol(
                    "the service did not select the arkret.v1 subprotocol".to_owned(),
                ));
            }

            Ok(Self {
                socket,
                inbox,
                _on_message: on_message,
                _on_close: on_close,
                _on_error: on_error,
                _on_open: on_open,
            })
        }
    }

    impl WebSocketSocket for PlatformWebSocket {
        fn recv(&mut self) -> BoxSocketFuture<'_, Option<WebSocketInbound>> {
            Box::pin(async move {
                loop {
                    {
                        let mut state = self.inbox.borrow_mut();
                        if let Some(message) = state.messages.pop_front() {
                            return Ok(Some(message));
                        }
                        if state.failed {
                            return Ok(None);
                        }
                    }
                    gloo_timers::future::sleep(POLL).await;
                }
            })
        }

        fn send_text(&mut self, payload: String) -> BoxSocketFuture<'_, ()> {
            Box::pin(async move {
                self.socket
                    .send_with_str(&payload)
                    .map_err(|_| garth::Error::Protocol("the browser refused the frame".to_owned()))
            })
        }

        fn close<'a>(
            &'a mut self,
            code: WebSocketCloseCode,
            reason: &'a str,
        ) -> BoxSocketFuture<'a, ()> {
            Box::pin(async move {
                let _ = self
                    .socket
                    .close_with_code_and_reason(code.as_u16(), reason);
                Ok(())
            })
        }
    }
}

/// Describe fixtures shared with the rail tests: the selector's behaviour is
/// only meaningful against a real `ServiceDescribe`, and both modules need the
/// advertised and the unadvertised shape.
#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) fn describe_without_websocket() -> arkret_sdk::ServiceDescribe {
        super::tests::describe_with(vec![arkret_sdk::SupportedBinding::new("http_json")])
    }

    pub(crate) fn describe_with_websocket() -> arkret_sdk::ServiceDescribe {
        let descriptor = super::WebSocketBindingDescriptor::new(
            "wss://server.example/_arkret/ws",
            super::CLIENT_MAX_FRAME_BYTES,
            16,
        );
        super::tests::describe_with(vec![descriptor.to_supported_binding().unwrap()])
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn describe_with(
        bindings: Vec<arkret_sdk::SupportedBinding>,
    ) -> arkret_sdk::ServiceDescribe {
        let mut describe = arkret_sdk::ServiceDescribe::development(
            arkret_sdk::Did::new("did:web:server.example").unwrap(),
            arkret_sdk::TypedTrustDomainId::new("ak:trust_domain:server.example").unwrap(),
            arkret_sdk::ServiceKind::PrincipalServer,
        );
        describe.supported_bindings = bindings;
        describe
    }

    #[test]
    fn a_service_without_the_profile_stays_on_http() {
        let selector = WebSocketTransportSelector::from_describe(&describe_with(vec![
            arkret_sdk::SupportedBinding::new("http_json"),
        ]));
        assert!(selector.descriptor().is_none());
    }

    #[test]
    fn an_advertised_binding_is_used_when_this_build_can_honour_it() {
        let descriptor = WebSocketBindingDescriptor::new(
            "wss://server.example/_arkret/ws",
            CLIENT_MAX_FRAME_BYTES,
            16,
        );
        let selector = WebSocketTransportSelector::from_describe(&describe_with(vec![
            descriptor.to_supported_binding().unwrap(),
        ]));
        assert_eq!(
            selector.descriptor().map(|entry| entry.base_url.as_str()),
            Some("wss://server.example/_arkret/ws")
        );
    }

    #[test]
    fn a_frame_ceiling_above_this_build_is_ignored() {
        // §4 makes the effective limit a minimum, and a client that cannot
        // buffer what the service may send has no usable binding.
        let descriptor = WebSocketBindingDescriptor::new(
            "wss://server.example/_arkret/ws",
            CLIENT_MAX_FRAME_BYTES + 1024,
            16,
        );
        let selector = WebSocketTransportSelector::from_describe(&describe_with(vec![
            descriptor.to_supported_binding().unwrap(),
        ]));
        assert!(selector.descriptor().is_none());
    }

    #[test]
    fn an_incompatible_close_drops_the_binding_until_discovery_changes() {
        let descriptor = WebSocketBindingDescriptor::new(
            "wss://server.example/_arkret/ws",
            CLIENT_MAX_FRAME_BYTES,
            16,
        );
        let mut selector = WebSocketTransportSelector::from_describe(&describe_with(vec![
            descriptor.to_supported_binding().unwrap(),
        ]));
        selector.welcomed();
        assert_eq!(
            selector.on_close(WebSocketCloseCode::ProtocolError, None),
            WebSocketTransportDecision::FallbackHttp
        );
        assert!(selector.descriptor().is_none());
    }

    #[test]
    fn a_policy_failure_keeps_one_retry_and_keeps_the_binding() {
        let descriptor = WebSocketBindingDescriptor::new(
            "wss://server.example/_arkret/ws",
            CLIENT_MAX_FRAME_BYTES,
            16,
        );
        let mut selector = WebSocketTransportSelector::from_describe(&describe_with(vec![
            descriptor.to_supported_binding().unwrap(),
        ]));
        selector.welcomed();
        assert!(matches!(
            selector.on_close(WebSocketCloseCode::PolicyViolation, None),
            WebSocketTransportDecision::RetryWebSocket { .. }
        ));
        assert!(selector.descriptor().is_some());
        assert_eq!(
            selector.on_close(WebSocketCloseCode::PolicyViolation, None),
            WebSocketTransportDecision::FallbackHttp
        );
        // §8.1 only bans the binding outright for 1002 / 1009; a policy failure
        // may succeed again once the grant is refreshed.
        assert!(selector.descriptor().is_some());
    }

    #[test]
    fn the_owner_switch_is_ordered() {
        let mut selector = WebSocketTransportSelector::from_describe(&describe_with(Vec::new()));
        selector
            .start_owner(WebSocketConsumerOwner::WebSocket)
            .unwrap();
        selector
            .start_owner(WebSocketConsumerOwner::Http)
            .expect_err("a second owner must not start");
        selector.switch_owner(WebSocketConsumerOwner::Http).unwrap();
        assert_eq!(selector.owner(), WebSocketConsumerOwner::Http);
    }
}
