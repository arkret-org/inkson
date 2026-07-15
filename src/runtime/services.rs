use super::effects::EffectRegistry;
use super::projection::ProjectionRouter;
use crate::runtime::session::SessionCoordinator;

#[derive(Clone)]
pub struct RuntimeServices {
    pub client: crate::client_core::InksonClientRuntime,
    pub session: SessionCoordinator,
    pub effects: EffectRegistry,
    pub projection_sink: ProjectionRouter,
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
        }
    }
}
