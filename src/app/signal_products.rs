//! App-tree implementation of [`SignalProductSink`].
//!
//! The Signal receive engine has already admitted the envelope (structure,
//! TTL, Station delivery authority, device proof, MLS AEAD, replay) by the time anything here
//! runs, so this module owns only the product half: the receiver-side
//! authorization each profile requires before a body may drive UI, and the
//! handoff into the two Dioxus hubs mounted at the app root.

use dioxus::prelude::*;

use crate::runtime::projection::SignalProductSink;

pub(super) struct AppSignalProductSink {
    call_hub: crate::views::call_signals::CallSignalHub,
    message_hub: crate::views::message_streams::MessageStreamHub,
    read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
}

impl AppSignalProductSink {
    pub(super) fn new(
        call_hub: crate::views::call_signals::CallSignalHub,
        message_hub: crate::views::message_streams::MessageStreamHub,
        read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
        principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    ) -> Self {
        Self {
            call_hub,
            message_hub,
            read_receipt_hub,
            principal_id,
        }
    }
}

type LocalBoxFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + 'a>>;

impl SignalProductSink for AppSignalProductSink {
    fn call_signal<'a>(
        &'a self,
        signal: &'a crate::runtime::projection::AdmittedSignal,
        _body: serde_json::Value,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async move {
            let mut hub = self.call_hub;
            let local_actor = self.principal_id.peek().clone();
            crate::views::call_signals::route_decrypted_call_signals(
                &mut hub,
                std::slice::from_ref(signal),
                crate::app::principal_id_text(&local_actor),
            )
            .await;
        })
    }

    fn message_stream<'a>(
        &'a self,
        signal: &'a crate::runtime::projection::AdmittedSignal,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async move {
            let mut hub = self.message_hub;
            if let Err(error) = hub.apply_admitted(signal, crate::clock::now_utc()) {
                tracing::debug!(%error, "message stream preview frame was not applied");
            }
        })
    }

    fn read_receipt(
        &self,
        signal: &crate::runtime::projection::AdmittedSignal,
        policy: &arkret_sdk::ReadReceiptPolicy,
    ) {
        // No further authorization probe: unlike a message-stream preview, a
        // read receipt discloses no Message body, and `read-receipts.md` §2.4
        // makes display a local preference rather than a protocol gate. The
        // envelope admission already proved the sending device and bound the
        // plaintext `actor_id` to the authenticated `sender_actor_id`.
        //
        // §2.5 is the exception and is enforced inside the hub: `disabled` and
        // `private` are client-side discards, because a Sync Service cannot
        // read the receipt to apply them.
        let local_actor = self.principal_id.peek().clone();
        let mut hub = self.read_receipt_hub;
        hub.apply_authorized(signal, policy, crate::app::principal_id_text(&local_actor));
    }

    fn retained_message_streams(&self) -> Vec<crate::runtime::projection::AdmittedSignal> {
        self.message_hub.retained()
    }
    fn retain_message_streams(&self, eligible: &[crate::runtime::projection::AdmittedSignal]) {
        let mut hub = self.message_hub;
        hub.retain_eligible(eligible);
    }

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        let mut hub = self.message_hub;
        hub.maintain(now);
    }
}
