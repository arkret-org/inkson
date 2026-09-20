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

/// One admitted, sender-bound Signal, as the product sinks consume it.
///
/// `garth::SignalReceiver` verifies the Station-issued delivery authority, the
/// producer proof, the AEAD and the per-endpoint sequence, then hands back the
/// typed closed profile plus the verified sender domain. This carrier is the
/// host-side pairing of the two, with the envelope instants the TTL projections
/// need: the rail carries no durable coordinates, so there is nothing else to
/// retain.
#[derive(Clone, Debug, PartialEq)]
pub struct AdmittedSignal {
    /// The verified sender actor, endpoint and scope the sequence high-water
    /// was enforced against.
    pub domain: arkret_sdk::SignalSequenceDomain,
    /// The registered closed profile this plaintext parsed as. Consumers match
    /// this union; hand-parsing a Signal body by field name is forbidden.
    pub payload: arkret_sdk::SignalPlaintext,
    /// The earlier of the outer `expires_at` and `sent_at + ttl_ms`, as the
    /// receiver computed it. The rail carries no durable coordinates, so this
    /// is the only instant a TTL projection needs.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl AdmittedSignal {
    pub fn kind(&self) -> arkret_sdk::SignalPlaintextKind {
        self.payload.kind()
    }

    pub fn payload_sequence(&self) -> u64 {
        self.payload.payload_sequence()
    }

    pub fn actor_id(&self) -> &arkret_sdk::ActorId {
        &self.domain.sender_actor_id
    }

    pub fn scope_ref(&self) -> &arkret_sdk::ScopeRef {
        &self.domain.scope_ref
    }

    pub fn sender_endpoint(&self) -> &arkret_sdk::SignalSequenceEndpoint {
        &self.domain.endpoint
    }
}

/// Product routes for admitted Signal plaintext.
///
/// The Signal receive engine performs every protocol-level check (envelope,
/// Seal-relative sender authorization, device proof, MLS AEAD, TTL, replay)
/// before anything reaches this trait, so an implementation only owns the
/// product projection. It exists so the engine stays free of UI types: the
/// call and message-stream hubs are Dioxus signals living in the app tree.
pub trait SignalProductSink {
    /// One decrypted `ak.call.signal` body with the envelope it was
    /// authenticated from. Async because call routing resolves the sender's
    /// directory key and the moderation action before it may ring a user.
    fn call_signal<'a>(
        &'a self,
        signal: &'a AdmittedSignal,
        body: serde_json::Value,
    ) -> LocalBoxFuture<'a>;

    /// One decrypted `ak.message.stream` preview frame. Async because
    /// `signal.md` §7.1 makes the recipient re-verify `ak.message.stream.send`
    /// and the target `ak.message.create` at the envelope's `seal_ref` before
    /// any body may be shown.
    fn message_stream<'a>(&'a self, plaintext: &'a AdmittedSignal) -> LocalBoxFuture<'a>;

    /// One decrypted `ak.receipt.read` plaintext. Synchronous: the receipt is a
    /// UI hint whose only gate is the envelope admission that already ran, and
    /// `read-receipts.md` §2.4 makes rendering it depend on a local display
    /// preference rather than on any further authorization round trip.
    /// `policy` is the Realm's accepted `ak.realm.read_receipt_policy`.
    /// `read-receipts.md` §2.5 makes the `disclosure="disabled"` /
    /// `visibility="private"` discard a **client** obligation — the receipt is
    /// Signal plaintext, so no service can apply it — which is why the sink
    /// receives the policy instead of assuming the transport already filtered.
    fn read_receipt(&self, plaintext: &AdmittedSignal, policy: &arkret_sdk::ReadReceiptPolicy);

    /// Advance the TTL state of Signal-backed projections: `signal.md` §7.4
    /// marks a preview stalled after 30 seconds without a valid frame and
    /// discards it after ten minutes. A producer that goes quiet emits nothing
    /// to drive that, so the rail's own keepalive cadence drives it instead.
    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>);
}

#[derive(Clone, Default)]
pub struct NoopSignalProductSink;

impl SignalProductSink for NoopSignalProductSink {
    fn call_signal<'a>(
        &'a self,
        _signal: &'a AdmittedSignal,
        _body: serde_json::Value,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async {})
    }

    fn message_stream<'a>(&'a self, _plaintext: &'a AdmittedSignal) -> LocalBoxFuture<'a> {
        Box::pin(async {})
    }

    fn read_receipt(&self, _plaintext: &AdmittedSignal, _policy: &arkret_sdk::ReadReceiptPolicy) {}

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
    fn call_signal<'a>(
        &'a self,
        signal: &'a AdmittedSignal,
        body: serde_json::Value,
    ) -> LocalBoxFuture<'a> {
        let sink = Rc::clone(&self.sink.borrow());
        Box::pin(async move { sink.call_signal(signal, body).await })
    }

    fn message_stream<'a>(&'a self, plaintext: &'a AdmittedSignal) -> LocalBoxFuture<'a> {
        let sink = Rc::clone(&self.sink.borrow());
        Box::pin(async move { sink.message_stream(plaintext).await })
    }

    fn read_receipt(&self, plaintext: &AdmittedSignal, policy: &arkret_sdk::ReadReceiptPolicy) {
        self.sink.borrow().read_receipt(plaintext, policy);
    }

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        self.sink.borrow().advance_clock(now);
    }
}
