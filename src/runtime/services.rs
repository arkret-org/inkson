use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::effects::EffectRegistry;
use super::projection::{ProjectionRouter, SharedProjectionSink};
use crate::runtime::session::SessionCoordinator;

pub trait RuntimeClock: Send + Sync {
    fn unix_timestamp(&self) -> i64;
}

#[derive(Default)]
pub struct SystemRuntimeClock;

impl RuntimeClock for SystemRuntimeClock {
    fn unix_timestamp(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or_default()
    }
}

pub trait RuntimeTelemetry: Send + Sync {
    fn record(&self, name: &'static str);
}

#[derive(Default)]
pub struct TracingRuntimeTelemetry;

impl RuntimeTelemetry for TracingRuntimeTelemetry {
    fn record(&self, name: &'static str) {
        tracing::debug!(runtime_event = name);
    }
}

#[derive(Clone)]
pub struct RuntimeServices {
    pub client: crate::client_core::InksonClientRuntime,
    pub session: SessionCoordinator,
    pub effects: EffectRegistry,
    pub projection_sink: ProjectionRouter,
    pub clock: Arc<dyn RuntimeClock>,
    pub telemetry: Arc<dyn RuntimeTelemetry>,
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
            clock: Arc::new(SystemRuntimeClock),
            telemetry: Arc::new(TracingRuntimeTelemetry),
        }
    }

    pub fn install_projection_sink(&self, projection_sink: SharedProjectionSink) {
        self.projection_sink.install(projection_sink);
    }
}
