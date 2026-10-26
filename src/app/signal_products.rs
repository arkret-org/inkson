//! App-tree implementation of [`SignalProductSink`].
//!
//! The Signal receive engine has already admitted the envelope (structure,
//! TTL, Station delivery authority, device proof, MLS AEAD, replay) by the time anything here
//! runs, so this module owns only the product half: the receiver-side
//! authorization each profile requires before a body may drive UI, and the
//! handoff into the application-owned hubs mounted at the app root.

use std::rc::{Rc, Weak};

use crate::presentation::InksonContext;
use crate::runtime::projection::SignalProductSink;

pub(super) struct AppSignalProductSink {
    call_hub: crate::views::call_signals::CallSignalHub,
    message_hub: crate::views::message_streams::MessageStreamHub,
    read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
    context: Weak<InksonContext>,
    generation: u64,
    account: Option<crate::config::ActiveAccountContext>,
}

impl AppSignalProductSink {
    pub(super) fn new(
        call_hub: crate::views::call_signals::CallSignalHub,
        message_hub: crate::views::message_streams::MessageStreamHub,
        read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
        context: Rc<InksonContext>,
    ) -> Self {
        Self {
            call_hub,
            message_hub,
            read_receipt_hub,
            context: Rc::downgrade(&context),
            generation: context.session_generation.get_untracked(),
            account: context.active_account.get_untracked(),
        }
    }

    fn live_context(&self) -> Option<Rc<InksonContext>> {
        self.context
            .upgrade()
            .filter(|context| context.session_matches(self.generation, &self.account))
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
            let Some(context) = self.live_context() else {
                return;
            };
            let (local_actor, local_device) = context
                .active_account
                .get_untracked()
                .map(|account| {
                    (
                        arkret_sdk::ActorId::account(account.authority).to_string(),
                        account.device_id.to_string(),
                    )
                })
                .unwrap_or_default();
            crate::views::call_signals::route_decrypted_call_signals(
                &mut hub,
                std::slice::from_ref(signal),
                &local_actor,
                &local_device,
            )
            .await;
        })
    }

    fn message_stream<'a>(
        &'a self,
        signal: &'a crate::runtime::projection::AdmittedSignal,
    ) -> LocalBoxFuture<'a> {
        Box::pin(async move {
            let Some(_context) = self.live_context() else {
                return;
            };
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
        let Some(context) = self.live_context() else {
            return;
        };
        let Some(account) = context.active_account.get_untracked() else {
            return;
        };
        let local_actor = arkret_sdk::ActorId::account(account.authority);
        let state = context.snapshot();
        let mut hub = self.read_receipt_hub;
        hub.apply_authorized(signal, policy, &local_actor, &state);
    }

    fn retained_message_streams(&self) -> Vec<crate::runtime::projection::AdmittedSignal> {
        if self.live_context().is_none() {
            return Vec::new();
        }
        self.message_hub.retained()
    }
    fn retain_message_streams(&self, eligible: &[crate::runtime::projection::AdmittedSignal]) {
        if self.live_context().is_none() {
            return;
        }
        let mut hub = self.message_hub;
        hub.retain_eligible(eligible);
    }

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        if self.live_context().is_none() {
            return;
        }
        let mut hub = self.message_hub;
        hub.maintain(now);
    }
}

#[cfg(test)]
mod tests;
