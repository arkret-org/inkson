//! The engine that owns the session's single WebSocket.
//!
//! It is the optional stream engine: the account aggregate and the Signal rail
//! keep working on canonical HTTP/JSON + bounded NDJSON whether this one runs or
//! not. That is the binding's own default, and it is why nothing here is
//! allowed to fail a session — every failure path ends in "stay on HTTP".
//!
//! garth owns the physical socket only
//! ([`garth::websocket::WebSocketSocket`] / [`WebSocketConnector`]); the frame
//! protocol DTOs are SDK-owned
//! (`arkret_models_collaboration::sync_frames::websocket`). This engine is the
//! host half between them: it authenticates the upgrade, installs the one
//! subscription the binding allows, and pumps server frames into the shared
//! [`WebSocketRail`] queues the stream engines read. When the connection ends,
//! the §8.1 decision table says whether to reconnect (honouring any drain
//! delay) or to stop trying; either way the rail detaches first, so an engine's
//! next reconnect lands on HTTP and the two consumers never overlap.

use std::time::Duration;

use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind;
use arkret_models_collaboration::sync_frames::websocket::{
    WebSocketAccountOpenParameters, WebSocketChannelControlPayload, WebSocketClientFrame,
    WebSocketDataPayload, WebSocketOpenParameters, WebSocketServerFrame,
};
use arkret_wire::websocket_binding::{WebSocketCloseCode, WebSocketOperationId};
use garth::websocket::{AuthProofRequest, WebSocketConnector, WebSocketInbound, WebSocketSocket};

use crate::config::MultiProfileConfig;
use crate::transport::websocket::{
    InksonWebSocketConnector, WebSocketHandshakeFailure, WebSocketTransportDecision,
    WebSocketTransportSelector,
};
use crate::transport::websocket_rail::{SharedConnection, WebSocketRail};

/// Delay before re-establishing after a close that carried no drain hint.
const RECONNECT_FLOOR: Duration = Duration::from_secs(1);

/// Runtime inputs of the rail engine.
#[derive(Clone)]
pub struct WebSocketRailContext {
    pub base_url: crate::runtime::input::ValueReader<String>,
    pub token: crate::runtime::input::ValueReader<String>,
    /// Active multi-profile snapshot — the engine exits when the active profile
    /// rotates, like the other stream engines.
    pub profiles: crate::runtime::input::ValueReader<MultiProfileConfig>,
    pub state_store: crate::runtime::input::StateStoreHandle,
    pub effect: crate::runtime::effects::EffectHandle,
    pub rail: WebSocketRail,
}

/// Run the optional WebSocket rail until the generation is bumped, the profile
/// rotates, the session ends, or §8.1 says to stay on HTTP.
pub async fn run_websocket_rail_engine(
    start_generation: u64,
    generation: crate::runtime::input::ValueReader<u64>,
    ctx: WebSocketRailContext,
) {
    let start_profile_id = ctx.profiles.get().active_profile_id;
    let is_active = || {
        generation.get() == start_generation
            && ctx.profiles.get().active_profile_id == start_profile_id
            && !ctx.effect.is_cancelled()
            && !ctx.base_url.get().trim().is_empty()
            && !ctx.token.get().trim().is_empty()
    };

    // Discovery decides whether this engine has anything to do at all. An
    // absent, incomplete or non-canonical descriptor is a fallback condition,
    // so a service that does not advertise the profile simply ends the engine.
    let describe = match crate::identity::session_refresh::provide_authenticated_sdk_client(
        &ctx.base_url.get(),
    )
    .await
    {
        Ok(client) => match client.describe().await {
            Ok(describe) => describe,
            Err(error) => {
                tracing::debug!(%error, "no service description; the WebSocket rail stays off");
                return;
            }
        },
        Err(error) => {
            tracing::debug!(%error, "no authenticated client; the WebSocket rail stays off");
            return;
        }
    };
    ctx.rail
        .set_selector(WebSocketTransportSelector::from_describe(&describe));
    if !ctx.rail.is_advertised() {
        return;
    }

    while is_active() {
        let Some(base_url) = ctx.rail.base_url() else {
            break;
        };
        let Some(max_frame_bytes) = ctx.rail.max_frame_bytes() else {
            break;
        };
        let Some(connector) = connector_for(&ctx).await else {
            break;
        };

        let socket = match connector.connect(&base_url).await {
            Ok(socket) => socket,
            Err(error) => {
                // An upgrade that never reached `101`, a subprotocol the
                // service did not select, or an intermediary that refused the
                // upgrade. §8.1 gives none of these a WebSocket retry.
                tracing::debug!(%error, "WebSocket upgrade failed; staying on HTTP");
                ctx.rail.on_handshake_failure(
                    WebSocketHandshakeFailure::UpgradeStatusNotSwitchingProtocols,
                );
                break;
            }
        };

        let connection = SharedConnection::new();
        // The connection is not usable yet: §3.1 puts a challenge/authenticate
        // exchange between the upgrade and the first channel, so both the retry
        // budget reset and the rail attachment happen inside the pump, after
        // the server's `welcome` and the account channel's `opened`.
        let (code, drain_reconnect_after_ms) = pump_until_closed(
            socket,
            &connection,
            &connector,
            &base_url,
            max_frame_bytes,
            &ctx,
            &is_active,
        )
        .await;
        connection.close();
        match ctx.rail.on_close(code, drain_reconnect_after_ms) {
            WebSocketTransportDecision::RetryWebSocket { after_ms } => {
                crate::runtime_helpers::sleep_for(reconnect_delay(after_ms)).await;
            }
            WebSocketTransportDecision::FallbackHttp => break,
        }
    }
    // Whatever ended the loop, the rail must not keep advertising a connection
    // the engines could still take delivery from.
    ctx.rail.detach();
}

/// Drive one connection through the binding's handshake, then fan the account
/// channel's frames into the shared queues until the peer closes or the frame
/// contract is broken.
///
/// The order is fixed and one-way (`websocket-binding.md` §3.1): the server
/// challenges, the client answers with a holder-signed proof over that exact
/// nonce, the server welcomes with its authoritative limits, and only then may
/// a channel be opened. Nothing is published to the rail before the account
/// channel is `opened`, so a socket that never authenticated can never become
/// a delivery path.
async fn pump_until_closed<S, F>(
    mut socket: S,
    connection: &SharedConnection,
    connector: &InksonWebSocketConnector,
    base_url: &str,
    advertised_max_frame_bytes: u32,
    ctx: &WebSocketRailContext,
    is_active: &F,
) -> (WebSocketCloseCode, Option<u32>)
where
    S: WebSocketSocket,
    F: Fn() -> bool,
{
    // Until `welcome` lands, the descriptor's ceiling is the only bound we
    // have; afterwards the server's own limit applies and the smaller wins.
    let mut max_frame_bytes = advertised_max_frame_bytes;
    let channel_id = crate::operation::uuid_v7();
    let mut welcomed = false;
    let mut opened = false;

    loop {
        if ctx.effect.is_cancelled() || !is_active() {
            let _ = socket.close(WebSocketCloseCode::Normal, "cancelled").await;
            return (WebSocketCloseCode::Normal, None);
        }
        let inbound = match socket.recv().await {
            Ok(Some(inbound)) => inbound,
            Ok(None) => return (WebSocketCloseCode::Normal, None),
            Err(error) => {
                tracing::debug!(%error, "WebSocket receive failed");
                let _ = socket.close(WebSocketCloseCode::InternalError, "recv").await;
                return (WebSocketCloseCode::InternalError, None);
            }
        };
        let text = match inbound {
            WebSocketInbound::Text(text) => text,
            // A binary message is a protocol error, not a frame.
            WebSocketInbound::Binary => {
                let _ = socket
                    .close(WebSocketCloseCode::ProtocolError, "binary_frame")
                    .await;
                return (WebSocketCloseCode::ProtocolError, None);
            }
            WebSocketInbound::TooLarge => {
                let _ = socket
                    .close(WebSocketCloseCode::MessageTooBig, "frame_too_large")
                    .await;
                return (WebSocketCloseCode::MessageTooBig, None);
            }
            WebSocketInbound::Closed(code) => {
                let code = code
                    .and_then(WebSocketCloseCode::from_u16)
                    .unwrap_or(WebSocketCloseCode::Normal);
                return (code, None);
            }
        };
        if text.len() > max_frame_bytes as usize {
            let _ = socket
                .close(WebSocketCloseCode::MessageTooBig, "frame_too_large")
                .await;
            return (WebSocketCloseCode::MessageTooBig, None);
        }
        let frame: WebSocketServerFrame = match serde_json::from_str(&text) {
            Ok(frame) => frame,
            Err(error) => {
                tracing::debug!(%error, "WebSocket server frame is not canonical");
                let _ = socket
                    .close(WebSocketCloseCode::ProtocolError, "invalid_frame")
                    .await;
                return (WebSocketCloseCode::ProtocolError, None);
            }
        };
        // The schema's own bounds, applied before anything acts on the frame.
        if let Err(error) = frame.validate() {
            tracing::debug!(%error, "WebSocket server frame failed its schema bounds");
            let _ = socket
                .close(WebSocketCloseCode::ProtocolError, "invalid_frame")
                .await;
            return (WebSocketCloseCode::ProtocolError, None);
        }

        match frame {
            // ── handshake ──────────────────────────────────────────────────
            WebSocketServerFrame::Challenge {
                connection_id,
                nonce,
                ..
            } => {
                if welcomed {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "late_challenge")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, None);
                }
                let Some(payload) =
                    authenticate_frame(connector, base_url, &connection_id, &nonce).await
                else {
                    // The holder could not sign this exact nonce; a connection
                    // that cannot authenticate is not retried on the socket.
                    let _ = socket
                        .close(WebSocketCloseCode::InternalError, "auth_proof")
                        .await;
                    return (WebSocketCloseCode::InternalError, None);
                };
                if socket.send_text(payload).await.is_err() {
                    return (WebSocketCloseCode::InternalError, None);
                }
            }
            WebSocketServerFrame::ReauthRequired {
                connection_id,
                nonce,
                ..
            } => {
                // A fresh proof over the new nonce, never a replay of the one
                // that opened the connection.
                let Some(payload) =
                    authenticate_frame(connector, base_url, &connection_id, &nonce).await
                else {
                    let _ = socket
                        .close(WebSocketCloseCode::InternalError, "auth_proof")
                        .await;
                    return (WebSocketCloseCode::InternalError, None);
                };
                if socket.send_text(payload).await.is_err() {
                    return (WebSocketCloseCode::InternalError, None);
                }
            }
            WebSocketServerFrame::Welcome { limits, .. } => {
                // The server's budget is authoritative; a client that reads
                // past it is closed rather than throttled.
                max_frame_bytes = max_frame_bytes.min(limits.max_frame_bytes);
                if !welcomed {
                    welcomed = true;
                    // §8.1: reaching `welcome` is what resets both retry
                    // budgets.
                    ctx.rail.welcomed();
                    let open = WebSocketClientFrame::Open {
                        channel_id: channel_id.clone(),
                        operation_id: WebSocketOperationId::AccountStreamSubscribe,
                        parameters: WebSocketOpenParameters::Account(
                            WebSocketAccountOpenParameters {
                                after: ctx.state_store.read(|store| store.sync_cursor()),
                                catchup: None,
                                filter: None,
                                wait_for: None,
                                realm_list: None,
                                replace_filter: None,
                            },
                        ),
                    };
                    let Ok(payload) = serde_json::to_string(&open) else {
                        return (WebSocketCloseCode::InternalError, None);
                    };
                    if socket.send_text(payload).await.is_err() {
                        return (WebSocketCloseCode::InternalError, None);
                    }
                }
            }
            WebSocketServerFrame::Opened {
                channel_id: acknowledged,
                operation_id,
            } => {
                if acknowledged != channel_id
                    || operation_id != WebSocketOperationId::AccountStreamSubscribe
                {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "channel_id")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, None);
                }
                opened = true;
                // Only now may the stream engines take delivery from it.
                ctx.rail.attach(connection.clone());
            }

            // ── the account channel ────────────────────────────────────────
            WebSocketServerFrame::Data {
                channel_id: delivered,
                payload,
            } => {
                if delivered != channel_id || !opened {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "channel_id")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, None);
                }
                // The account channel is the only one this engine opens, so an
                // events or Signal payload here is the service answering
                // something that was never asked for. The socket's Signal frame
                // in particular carries no delivery authority, so a Signal
                // admitted from it could not be verified.
                let WebSocketDataPayload::Account(frame) = payload else {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "unsolicited_channel")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, None);
                };
                if !publish_account_frame(connection, *frame) {
                    // The consumer is too far behind for the socket to stay a
                    // low-latency path; drop back to HTTP rather than growing
                    // an unbounded buffer.
                    let _ = socket
                        .close(WebSocketCloseCode::InternalError, "consumer_backlog")
                        .await;
                    return (WebSocketCloseCode::InternalError, None);
                }
            }
            WebSocketServerFrame::ChannelControl {
                channel_id: delivered,
                payload,
                ..
            } => {
                if delivered != channel_id || !opened {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "channel_id")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, None);
                }
                let WebSocketChannelControlPayload::Account(frame) = payload else {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "unsolicited_channel")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, None);
                };
                // `dropped`, `resync_required` and `unauthorized` are terminal
                // for this connection: the consumer cannot resume from the
                // cursor it holds, so the account stream goes back to its
                // canonical HTTP binding and re-establishes there.
                let terminal = matches!(
                    frame.kind,
                    AccountSubscribeFrameKind::Dropped
                        | AccountSubscribeFrameKind::ResyncRequired
                        | AccountSubscribeFrameKind::Unauthorized
                );
                if !publish_account_frame(connection, *frame) {
                    let _ = socket
                        .close(WebSocketCloseCode::InternalError, "consumer_backlog")
                        .await;
                    return (WebSocketCloseCode::InternalError, None);
                }
                if terminal {
                    let _ = socket
                        .close(WebSocketCloseCode::Normal, "stream_interrupted")
                        .await;
                    return (WebSocketCloseCode::Normal, None);
                }
            }
            WebSocketServerFrame::Closed { .. } => {
                return (WebSocketCloseCode::Normal, None);
            }
            WebSocketServerFrame::ChannelError { .. } => {
                let _ = socket
                    .close(WebSocketCloseCode::InternalError, "channel_error")
                    .await;
                return (WebSocketCloseCode::InternalError, None);
            }
            WebSocketServerFrame::ConnectionError { .. } => {
                let _ = socket
                    .close(WebSocketCloseCode::InternalError, "connection_error")
                    .await;
                return (WebSocketCloseCode::InternalError, None);
            }

            // ── connection control ─────────────────────────────────────────
            WebSocketServerFrame::ConnectionControl { payload, .. } => {
                connection.request_reconnect(u64::from(payload.reconnect_after_ms));
                let _ = socket.close(WebSocketCloseCode::GoingAway, "drain").await;
                return (
                    WebSocketCloseCode::GoingAway,
                    Some(payload.reconnect_after_ms),
                );
            }
            WebSocketServerFrame::Ping { ping_id, .. } => {
                let pong = WebSocketClientFrame::Pong { ping_id };
                let Ok(payload) = serde_json::to_string(&pong) else {
                    return (WebSocketCloseCode::InternalError, None);
                };
                if socket.send_text(payload).await.is_err() {
                    return (WebSocketCloseCode::InternalError, None);
                }
            }
        }
    }
}

/// Serialize one `authenticate` frame answering this exact challenge nonce.
///
/// `jti` is minted per proof and never reused, which is what keeps a reauth
/// from being answerable by replaying the proof that opened the connection.
async fn authenticate_frame(
    connector: &InksonWebSocketConnector,
    base_url: &str,
    connection_id: &str,
    nonce: &str,
) -> Option<String> {
    let session_grant = connector.session_grant().await.ok()?;
    let request = AuthProofRequest {
        base_url: base_url.to_owned(),
        session_grant: session_grant.clone(),
        nonce: nonce.to_owned(),
        jti: crate::operation::uuid_v7(),
    };
    let dpop_proof = connector.sign_auth_proof(&request).await.ok()?;
    serde_json::to_string(&WebSocketClientFrame::Authenticate {
        connection_id: connection_id.to_owned(),
        session_grant,
        dpop_proof,
    })
    .ok()
}

/// Hand one account frame to the shared queues, carrying its cursor first.
///
/// The cursor is what makes a drained window a resumable batch, so it is
/// recorded before the frame is published rather than after.
#[must_use]
fn publish_account_frame(
    connection: &SharedConnection,
    frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame,
) -> bool {
    if let Some(cursor) = frame.cursor.clone() {
        connection.set_cursor(cursor);
    }
    connection.push_account_frame(frame)
}

/// Build a connector against the session's current grant and holder key.
///
/// Asked per attempt, so a retry after a policy failure picks up a refreshed
/// grant instead of replaying the one that was rejected.
async fn connector_for(ctx: &WebSocketRailContext) -> Option<InksonWebSocketConnector> {
    let grant = ctx.token.get();
    if grant.trim().is_empty() {
        return None;
    }
    // The same device key the HTTP DPoP path uses. The proof is bound to the
    // grant's `cnf.jkt`, so a different key here would fail closed.
    let holder = ctx
        .state_store
        .write(crate::identity::account_auth::grant_dpop::load_or_recover_device_key)
        .ok()
        .flatten()?;
    Some(InksonWebSocketConnector::new(grant, holder))
}

fn reconnect_delay(after_ms: u32) -> Duration {
    Duration::from_millis(u64::from(after_ms)).max(RECONNECT_FLOOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_drain_delay_is_never_shortened_by_the_floor() {
        assert_eq!(reconnect_delay(5_000), Duration::from_millis(5_000));
        // §8 only sets a lower bound; a close with no hint still waits rather
        // than reconnecting in a tight loop.
        assert_eq!(reconnect_delay(0), RECONNECT_FLOOR);
    }
}
