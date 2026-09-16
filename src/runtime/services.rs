use super::effects::EffectRegistry;
use super::projection::{ProjectionRouter, SignalProductRouter};
use crate::runtime::session::SessionCoordinator;

#[derive(Clone)]
pub struct RuntimeServices {
    pub client: crate::client_core::InksonClientRuntime,
    pub session: SessionCoordinator,
    pub effects: EffectRegistry,
    pub projection_sink: ProjectionRouter,
    /// Product routes for the encrypted Signal receive rail. Installed by the
    /// app shell once the Signal hubs are mounted.
    pub signal_product_sink: SignalProductRouter,
    /// The session's single optional WebSocket. Empty until the rail engine
    /// completes a handshake; every stream engine reads HTTP while it is.
    pub websocket_rail: crate::transport::websocket_rail::WebSocketRail,
}

impl RuntimeServices {
    pub fn new(
        state_store: crate::client_core::InksonLocalStateStoreAdapter,
        session: SessionCoordinator,
    ) -> Self {
        Self {
            client: crate::client_core::InksonClientRuntime::from_state_adapter(state_store),
            session,
            effects: EffectRegistry::default(),
            projection_sink: ProjectionRouter::default(),
            signal_product_sink: SignalProductRouter::default(),
            websocket_rail: crate::transport::websocket_rail::WebSocketRail::default(),
        }
    }
}
