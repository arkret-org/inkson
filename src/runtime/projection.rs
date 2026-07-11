use std::sync::Arc;

#[derive(Clone, Debug, PartialEq)]
pub enum ClientProjectionEvent {
    Account(crate::projection::ProjectionEvent),
    Realm(crate::projection::ProjectionEvent),
    CursorCheckpoint { scope: String, cursor: String },
    Reset,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncStatusEvent {
    Offline,
    Connecting,
    Online,
    Retryable { reason: String },
    NeedsSignIn { reason: String },
    Terminal { reason: String },
}

pub trait ProjectionSink: Send + Sync {
    fn projection(&self, event: ClientProjectionEvent);
    fn sync_status(&self, event: SyncStatusEvent);
}

#[derive(Clone, Default)]
pub struct NoopProjectionSink;

impl ProjectionSink for NoopProjectionSink {
    fn projection(&self, _event: ClientProjectionEvent) {}

    fn sync_status(&self, _event: SyncStatusEvent) {}
}

pub type SharedProjectionSink = Arc<dyn ProjectionSink>;
