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

type LocalBoxFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>;

/// Product routes for admitted Signal plaintext.
///
/// The Signal receive engine performs every protocol-level check (envelope,
/// Seal-relative sender authorization, device proof, MLS AEAD, TTL, replay)
/// before anything reaches this trait, so an implementation only owns the
/// product projection. It exists so the engine stays free of UI types: the
/// call and message-stream hubs are Dioxus signals living in the app tree.
pub trait SignalProductSink {
    /// Resolve the sending device's directory key into the process-wide cache
    /// the synchronous Signal receiver reads, before the envelope is admitted.
    ///
    /// Without it the first Signal from any peer whose key is not yet cached
    /// fails admission closed — including the `invite` that starts a call.
    /// It grants nothing: admission is still decided by the receiver.
    fn prefetch_sender_key<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
    ) -> LocalBoxFuture<'a>;

    /// One decrypted `ak.call.signal` body with the envelope it was
    /// authenticated from. Async because call routing resolves the sender's
    /// directory key and the moderation action before it may ring a user.
    fn call_signal<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
        body: serde_json::Value,
    ) -> LocalBoxFuture<'a>;

    /// One decrypted `ak.message.stream` preview frame. Async because
    /// `signal.md` §7.1 makes the recipient re-verify `ak.message.stream.send`
    /// and the target `ak.message.create` at the envelope's `seal_ref` before
    /// any body may be shown.
    fn message_stream<'a>(&'a self, plaintext: &'a garth::SignalPlaintext) -> LocalBoxFuture<'a>;

    /// One decrypted `ak.receipt.read` plaintext. Synchronous: the receipt is a
    /// UI hint whose only gate is the envelope admission that already ran, and
    /// `read-receipts.md` §2.4 makes rendering it depend on a local display
    /// preference rather than on any further authorization round trip.
    fn read_receipt(&self, plaintext: &garth::SignalPlaintext);

    /// Advance the TTL state of Signal-backed projections: `signal.md` §7.4
    /// marks a preview stalled after 30 seconds without a valid frame and
    /// discards it after ten minutes. A producer that goes quiet emits nothing
    /// to drive that, so the rail's own keepalive cadence drives it instead.
    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>);
}

#[derive(Clone, Default)]
pub struct NoopSignalProductSink;

impl SignalProductSink for NoopSignalProductSink {
    fn prefetch_sender_key<'a>(
        &'a self,
        _envelope: &'a arkret_wire::SignalEnvelope,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async {})
    }

    fn call_signal<'a>(
        &'a self,
        _envelope: &'a arkret_wire::SignalEnvelope,
        _body: serde_json::Value,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async {})
    }

    fn message_stream<'a>(&'a self, _plaintext: &'a garth::SignalPlaintext) -> LocalBoxFuture<'a> {
        Box::pin(async {})
    }

    fn read_receipt(&self, _plaintext: &garth::SignalPlaintext) {}

    fn advance_clock(&self, _now: chrono::DateTime<chrono::Utc>) {}
}

pub type SharedSignalProductSink = Rc<dyn SignalProductSink>;

#[derive(Clone)]
pub struct SignalProductRouter {
    sink: Rc<RefCell<SharedSignalProductSink>>,
}

impl Default for SignalProductRouter {
    fn default() -> Self {
        Self {
            sink: Rc::new(RefCell::new(Rc::new(NoopSignalProductSink))),
        }
    }
}

impl SignalProductRouter {
    pub fn install(&self, sink: SharedSignalProductSink) {
        *self.sink.borrow_mut() = sink;
    }
}

impl SignalProductSink for SignalProductRouter {
    fn prefetch_sender_key<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
    ) -> LocalBoxFuture<'a> {
        let sink = Rc::clone(&self.sink.borrow());
        Box::pin(async move { sink.prefetch_sender_key(envelope).await })
    }

    fn call_signal<'a>(
        &'a self,
        envelope: &'a arkret_wire::SignalEnvelope,
        body: serde_json::Value,
    ) -> LocalBoxFuture<'a> {
        let sink = Rc::clone(&self.sink.borrow());
        Box::pin(async move { sink.call_signal(envelope, body).await })
    }

    fn message_stream<'a>(&'a self, plaintext: &'a garth::SignalPlaintext) -> LocalBoxFuture<'a> {
        let sink = Rc::clone(&self.sink.borrow());
        Box::pin(async move { sink.message_stream(plaintext).await })
    }

    fn read_receipt(&self, plaintext: &garth::SignalPlaintext) {
        self.sink.borrow().read_receipt(plaintext);
    }

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        self.sink.borrow().advance_clock(now);
    }
}
