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
//! host half between them: it authenticates the upgrade, sends each consumer's
//! channel commands, and pumps canonical server frames into the shared
//! [`WebSocketRail`] queues the stream engines read. When the connection ends,
//! the §8.1 decision table says whether to reconnect (honouring any drain
//! delay) or to stop trying; either way the rail detaches first, so an engine's
//! next reconnect lands on HTTP and the two consumers never overlap.

use std::time::Duration;

use arkret_models_collaboration::sync_frames::websocket::{
    WebSocketClientFrame, WebSocketServerFrame,
};
use arkret_wire::websocket_binding::WebSocketCloseCode;
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
        // the server's `welcome`. Consumers then open their own channels.
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
                if code == WebSocketCloseCode::PolicyViolation
                    && crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(&ctx.base_url.get()).await.is_err() {
                    break;
                }
                crate::runtime_helpers::sleep_for(reconnect_delay(after_ms)).await;
            }
            WebSocketTransportDecision::FallbackHttp => break,
        }
    }
    // Whatever ended the loop, the rail must not keep advertising a connection
    // the engines could still take delivery from.
    ctx.rail.detach();
}

/// Drive one connection through the binding's handshake, then dispatch each
/// channel's frames into its bounded queue until the peer closes or the frame
/// contract is broken.
///
/// The order is fixed and one-way (`websocket-binding.md` §3.1): the server
/// challenges, the client answers with a holder-signed proof over that exact
/// nonce, the server welcomes with its authoritative limits, and only then may
/// a channel be opened. Nothing is published to the rail before `welcome`,
/// so a socket that never authenticated can never become
/// a delivery path.
async fn pump_until_closed<S: WebSocketSocket, F: Fn() -> bool>(
    mut socket: S,
    connection: &SharedConnection,
    connector: &InksonWebSocketConnector,
    base_url: &str,
    max_frame_bytes: u32,
    ctx: &WebSocketRailContext,
    is_active: &F,
) -> (WebSocketCloseCode, Option<u32>) {
    let result = pump_until_closed_inner(
        &mut socket,
        connection,
        connector,
        base_url,
        max_frame_bytes,
        ctx,
        is_active,
    )
    .await;
    connection.close();
    let _ = socket.close(result.0, "connection_closed").await;
    result
}
async fn pump_until_closed_inner<S, F>(
    socket: &mut S,
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
    use arkret_models_collaboration::sync_frames::websocket::{
        WebSocketConnectionPhase, WebSocketConnectionState, WebSocketFrameIngress,
    };
    let mut state = WebSocketConnectionState::new();
    let mut ingress = WebSocketFrameIngress::new(advertised_max_frame_bytes, None);
    let mut drain = None;
    let mut reconnect = None;
    loop {
        if !is_active() || ctx.effect.is_cancelled() {
            let _ = socket.close(WebSocketCloseCode::Normal, "cancelled").await;
            return (WebSocketCloseCode::Normal, reconnect);
        }
        if drain.is_some_and(|deadline| crate::clock::now_utc() >= deadline) {
            let _ = socket.close(WebSocketCloseCode::GoingAway, "drain").await;
            return (WebSocketCloseCode::GoingAway, reconnect);
        }
        if let Some(command) = connection.next_command() {
            let id = command.channel_id().map(ToOwned::to_owned);
            if matches!(&command, WebSocketClientFrame::Close { channel_id, .. }
                if state.channel(channel_id).is_none_or(|c| c.closed))
            {
                continue;
            }
            if state.observe_client(&command).is_err() {
                if let Some(id) = id {
                    connection.refuse(&id, "channel cannot open within current limits");
                    continue;
                }
                let _ = socket
                    .close(WebSocketCloseCode::ProtocolError, "state")
                    .await;
                return (WebSocketCloseCode::ProtocolError, reconnect);
            }
            if send_client_frame(socket, &command).await.is_err() {
                return (WebSocketCloseCode::InternalError, reconnect);
            }
            continue;
        }
        let inbound = {
            use futures_util::future::{Either, select};
            match select(
                socket.recv(),
                Box::pin(crate::runtime_helpers::sleep_for(Duration::from_millis(
                    100,
                ))),
            )
            .await
            {
                Either::Left((inbound, _)) => inbound,
                Either::Right(_) => continue,
            }
        };
        let text = match inbound {
            Ok(Some(WebSocketInbound::Text(text))) => text,
            Ok(Some(WebSocketInbound::Closed(code))) => {
                return (
                    code.and_then(WebSocketCloseCode::from_u16)
                        .unwrap_or(WebSocketCloseCode::Normal),
                    reconnect,
                );
            }
            Ok(None) => return (WebSocketCloseCode::Normal, reconnect),
            Ok(Some(WebSocketInbound::Binary)) => {
                let _ = socket
                    .close(WebSocketCloseCode::ProtocolError, "binary")
                    .await;
                return (WebSocketCloseCode::ProtocolError, reconnect);
            }
            Ok(Some(WebSocketInbound::TooLarge)) => {
                let _ = socket
                    .close(WebSocketCloseCode::MessageTooBig, "frame_size")
                    .await;
                return (WebSocketCloseCode::MessageTooBig, reconnect);
            }
            Err(_) => return (WebSocketCloseCode::InternalError, reconnect),
        };
        let generic = match ingress.decode_server_frame(text.as_bytes()) {
            Ok(frame) => frame,
            Err(error) => {
                let code = error
                    .close_code
                    .unwrap_or(WebSocketCloseCode::ProtocolError);
                let _ = socket.close(code, "frame_schema").await;
                return (code, reconnect);
            }
        };
        let frame = match ingress.decode_server_frame_for_channels(text.as_bytes(), |id| {
            state.channel(id).map(|channel| channel.operation_id)
        }) {
            Ok(frame) => frame,
            Err(error) => {
                if let Some(id) = generic.channel_id()
                    && state.channel(id).is_some()
                {
                    connection.refuse(id, "channel payload schema mismatch");
                    continue;
                }
                let code = error
                    .close_code
                    .unwrap_or(WebSocketCloseCode::ProtocolError);
                let _ = socket.close(code, "frame_schema").await;
                return (code, reconnect);
            }
        };
        if state.observe_server(&frame).is_err() {
            if let Some(id) = frame.channel_id()
                && state.channel(id).is_some()
            {
                connection.refuse(id, "channel operation or state mismatch");
                continue;
            }
            let _ = socket
                .close(WebSocketCloseCode::ProtocolError, "state")
                .await;
            return (WebSocketCloseCode::ProtocolError, reconnect);
        }
        match &frame {
            WebSocketServerFrame::Challenge {
                connection_id,
                nonce,
                expires_at,
            } => {
                if *expires_at <= crate::clock::now_utc() {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                }
                let Some(auth) =
                    authenticate_frame(connector, base_url, connection_id, nonce).await
                else {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                };
                if state.observe_client(&auth).is_err()
                    || send_client_frame(socket, &auth).await.is_err()
                {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                }
            }
            WebSocketServerFrame::ReauthRequired {
                connection_id,
                nonce,
                expires_at,
                ..
            } => {
                connection.set_ready(false);
                let refreshed = crate::identity::session_refresh::refresh_authenticated_session_after_unauthorized(&ctx.base_url.get()).await;
                if refreshed.is_err() || *expires_at <= crate::clock::now_utc() {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                }
                let Some(fresh_connector) = connector_for(ctx).await else {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                };
                let Some(auth) =
                    authenticate_frame(&fresh_connector, base_url, connection_id, nonce).await
                else {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                };
                if state.observe_client(&auth).is_err()
                    || send_client_frame(socket, &auth).await.is_err()
                {
                    return (WebSocketCloseCode::PolicyViolation, reconnect);
                }
            }
            WebSocketServerFrame::Welcome { limits, .. } => {
                ingress = WebSocketFrameIngress::new(
                    advertised_max_frame_bytes,
                    Some(limits.max_frame_bytes),
                );
                connection.set_ready(state.phase() == WebSocketConnectionPhase::Ready);
                ctx.rail.welcomed();
                ctx.rail.attach(connection.clone());
            }
            WebSocketServerFrame::ConnectionControl { payload, .. } => {
                connection.set_ready(false);
                reconnect = Some(payload.reconnect_after_ms);
                drain = Some(
                    payload
                        .deadline
                        .min(crate::clock::now_utc() + chrono::Duration::seconds(30)),
                );
            }
            WebSocketServerFrame::Ping { ping_id, .. } => {
                let pong = WebSocketClientFrame::Pong {
                    ping_id: ping_id.clone(),
                };
                if state.observe_client(&pong).is_err()
                    || send_client_frame(socket, &pong).await.is_err()
                {
                    return (WebSocketCloseCode::InternalError, reconnect);
                }
            }
            WebSocketServerFrame::ConnectionError { error, .. } => {
                let code = if matches!(
                    error.code.as_str(),
                    "unauthenticated" | "session_grant_expired" | "session_grant_revoked"
                ) {
                    WebSocketCloseCode::PolicyViolation
                } else {
                    WebSocketCloseCode::InternalError
                };
                let _ = socket.close(code, "connection_error").await;
                return (code, reconnect);
            }
            _ => {
                if connection.publish(frame).is_err() {
                    let _ = socket
                        .close(WebSocketCloseCode::ProtocolError, "channel_state")
                        .await;
                    return (WebSocketCloseCode::ProtocolError, reconnect);
                }
            }
        }
    }
}

async fn send_client_frame<S: WebSocketSocket>(
    socket: &mut S,
    frame: &WebSocketClientFrame,
) -> garth::Result<()> {
    frame.validate()?;
    let bytes = arkret_sdk::canonical::canonical_json_bytes(frame)?;
    socket
        .send_text(String::from_utf8(bytes).map_err(|e| garth::Error::Protocol(e.to_string()))?)
        .await
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
) -> Option<WebSocketClientFrame> {
    let session_grant = connector.session_grant().await.ok()?;
    let request = AuthProofRequest {
        base_url: base_url.to_owned(),
        session_grant: session_grant.clone(),
        nonce: nonce.to_owned(),
        jti: crate::operation::uuid_v7(),
    };
    let dpop_proof = connector.sign_auth_proof(&request).await.ok()?;
    Some(WebSocketClientFrame::Authenticate {
        connection_id: connection_id.to_owned(),
        session_grant,
        dpop_proof,
    })
}

/// Build a connector against the session's current grant and holder key.
///
/// Asked per attempt, so a retry after a policy failure picks up a refreshed
/// grant instead of replaying the one that was rejected.
async fn connector_for(ctx: &WebSocketRailContext) -> Option<InksonWebSocketConnector> {
    let session =
        crate::identity::session_refresh::provide_authenticated_session(&ctx.base_url.get())
            .await
            .ok()?;
    let user = crate::secure_key_store::UserLocalStore::new(
        session.grant.account_id.clone(),
        session.grant.device_id.clone(),
    )
    .ok()?;
    let holder = crate::identity::account_auth::grant_dpop::load_user_device_key_with_secure_store(
        &user,
        crate::secure_key_store::default_secure_key_store("inkson").as_ref(),
    )
    .ok()
    .flatten()?;
    Some(InksonWebSocketConnector::new(
        session.grant.grant_jwt,
        holder,
    ))
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
