//! The engine that owns the session's single WebSocket.
//!
//! It is the fourth stream engine, and the only one that is optional: the three
//! others keep working on canonical HTTP/JSON + bounded NDJSON whether this one
//! runs or not. That is the §2 default, and it is why nothing here is allowed to
//! fail a session — every failure path ends in "stay on HTTP".
//!
//! The loop is the one garth's [`WebSocketConnection`] documents: this task owns
//! the socket and is the only writer, while the three stream engines read the
//! per-channel queues it fills through [`WebSocketRail`]. When the connection
//! ends, §8.1's decision table says whether to reconnect (honouring any drain
//! delay) or to stop trying; either way the rail detaches first, so an engine's
//! next reconnect lands on HTTP and the two consumers never overlap.

use std::time::Duration;

use arkret_wire::websocket_binding::WebSocketCloseCode;
use garth::websocket::{
    PumpOutcome, WebSocketConnection, WebSocketConnector, WebSocketTransportDecision,
};

use crate::config::MultiProfileConfig;
use crate::transport::websocket::{InksonWebSocketConnector, WebSocketTransportSelector};
use crate::transport::websocket_rail::WebSocketRail;

/// Delay before re-establishing after a close that carried no drain hint.
const RECONNECT_FLOOR: Duration = Duration::from_secs(1);

/// Runtime inputs of the rail engine.
#[derive(Clone)]
pub struct WebSocketRailContext {
    pub base_url: crate::runtime::input::ValueReader<String>,
    pub token: crate::runtime::input::ValueReader<String>,
    /// Active multi-profile snapshot — the engine exits when the active profile
    /// rotates, like the three stream engines.
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

    // Discovery decides whether this engine has anything to do at all. §2 makes
    // an absent, incomplete or non-canonical descriptor a fallback condition,
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
        let connector = match connector_for(&ctx).await {
            Some(connector) => connector,
            None => break,
        };

        let socket = match connector.connect(&base_url).await {
            Ok(socket) => socket,
            Err(error) => {
                // An upgrade that never reached `101`, a subprotocol the
                // service did not select, or an intermediary that refused the
                // upgrade. §8.1 gives none of these a WebSocket retry.
                tracing::debug!(%error, "WebSocket upgrade failed; staying on HTTP");
                ctx.rail.on_handshake_failure(
                    garth::websocket::WebSocketHandshakeFailure::UpgradeStatusNotSwitchingProtocols,
                );
                break;
            }
        };
        let mut connection =
            match WebSocketConnection::establish(&connector, &base_url, max_frame_bytes, socket)
                .await
            {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::debug!(%error, "WebSocket authentication failed");
                    match ctx.rail.on_close(WebSocketCloseCode::PolicyViolation, None) {
                        WebSocketTransportDecision::RetryWebSocket { after_ms } => {
                            crate::runtime_helpers::sleep_for(reconnect_delay(after_ms)).await;
                            continue;
                        }
                        WebSocketTransportDecision::FallbackHttp => break,
                    }
                }
            };

        // `welcome` landed: publish the connection so the stream engines pick
        // channels off it on their next reconnect, and reset the retry budgets.
        ctx.rail.welcomed();
        ctx.rail.attach(connection.shared());

        let (code, drain_reconnect_after_ms) = pump_until_closed(&mut connection, &ctx).await;
        match ctx.rail.on_close(code, drain_reconnect_after_ms) {
            WebSocketTransportDecision::RetryWebSocket { after_ms } => {
                crate::runtime_helpers::sleep_for(reconnect_delay(after_ms)).await;
            }
            WebSocketTransportDecision::FallbackHttp => break,
        }
    }
    // Whatever ended the loop, the rail must not keep advertising a connection
    // the engines could still take channels from.
    ctx.rail.detach();
}

/// Drive one connection to its end, answering a reauth in place.
async fn pump_until_closed<S>(
    connection: &mut WebSocketConnection<S>,
    ctx: &WebSocketRailContext,
) -> (WebSocketCloseCode, Option<u32>)
where
    S: garth::websocket::WebSocketSocket,
{
    loop {
        if ctx.effect.is_cancelled() {
            connection
                .shutdown(WebSocketCloseCode::Normal, "cancelled")
                .await;
            return (WebSocketCloseCode::Normal, None);
        }
        match connection.pump().await {
            Ok(PumpOutcome::Continue) => {}
            Ok(PumpOutcome::Closed {
                code,
                drain_reconnect_after_ms,
            }) => return (code, drain_reconnect_after_ms),
            Ok(PumpOutcome::ReauthRequired { nonce }) => {
                // §3 — a fresh nonce needs a fresh grant, `ath`, `iat` and
                // `jti`. Failing to answer inside the deadline closes the whole
                // connection with 1008, which the caller treats as a policy
                // failure.
                let Some(connector) = connector_for(ctx).await else {
                    connection
                        .shutdown(WebSocketCloseCode::PolicyViolation, "reauth")
                        .await;
                    return (WebSocketCloseCode::PolicyViolation, None);
                };
                let request = connection
                    .shared()
                    .with_mut(|state| state.reauth_proof_request(&nonce, connector.grant()));
                match connector.sign_auth_proof(&request).await {
                    Ok(proof) => {
                        let queued = connection
                            .shared()
                            .with_mut(|state| state.enqueue_authenticate(&request, proof));
                        if queued.is_err() {
                            connection
                                .shutdown(WebSocketCloseCode::PolicyViolation, "reauth")
                                .await;
                            return (WebSocketCloseCode::PolicyViolation, None);
                        }
                    }
                    Err(error) => {
                        tracing::debug!(%error, "WebSocket reauth proof failed");
                        connection
                            .shutdown(WebSocketCloseCode::PolicyViolation, "reauth")
                            .await;
                        return (WebSocketCloseCode::PolicyViolation, None);
                    }
                }
            }
            Err(error) => {
                tracing::debug!(%error, "WebSocket pump failed");
                connection
                    .shutdown(WebSocketCloseCode::InternalError, "pump")
                    .await;
                return (WebSocketCloseCode::InternalError, None);
            }
        }
    }
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
    // The same device key the HTTP DPoP path uses. §3.1 binds the proof to the
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
