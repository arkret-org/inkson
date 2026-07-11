use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Debug, PartialEq)]
pub enum ClientProjectionEvent {
    Account(crate::state::projection::ProjectionEvent),
    Realm(crate::state::projection::ProjectionEvent),
    CursorCheckpoint { scope: String, cursor: String },
    CursorReset { scope: String },
    DeviceQueue { pending: usize },
    Theme { value: String },
    SelectedRealm { realm_id: String },
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

pub trait ProjectionSink {
    fn projection(&self, event: ClientProjectionEvent);
    fn sync_status(&self, event: SyncStatusEvent);
}

#[derive(Clone, Default)]
pub struct NoopProjectionSink;

impl ProjectionSink for NoopProjectionSink {
    fn projection(&self, _event: ClientProjectionEvent) {}

    fn sync_status(&self, _event: SyncStatusEvent) {}
}

pub type SharedProjectionSink = Rc<dyn ProjectionSink>;

#[derive(Clone)]
pub struct ProjectionRouter {
    sink: Rc<RefCell<SharedProjectionSink>>,
}

impl Default for ProjectionRouter {
    fn default() -> Self {
        Self {
            sink: Rc::new(RefCell::new(Rc::new(NoopProjectionSink))),
        }
    }
}

impl ProjectionRouter {
    pub fn install(&self, sink: SharedProjectionSink) {
        *self.sink.borrow_mut() = sink;
    }
}

impl ProjectionSink for ProjectionRouter {
    fn projection(&self, event: ClientProjectionEvent) {
        self.sink.borrow().projection(event);
    }

    fn sync_status(&self, event: SyncStatusEvent) {
        self.sink.borrow().sync_status(event);
    }
}
