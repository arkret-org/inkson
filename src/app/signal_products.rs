//! App-tree implementation of [`SignalProductSink`].
//!
//! The Signal receive engine has already admitted the envelope (structure,
//! TTL, Station delivery authority, device proof, MLS AEAD, replay) by the time anything here
//! runs, so this module owns only the product half: the receiver-side
//! authorization each profile requires before a body may drive UI, and the
//! handoff into the two Dioxus hubs mounted at the app root.

use dioxus::prelude::*;

use crate::runtime::projection::SignalProductSink;

fn signal_authorization_request(
    actor: &arkret_sdk::ActorId,
    action: &str,
    resource: arkret_sdk::WireResourceSelector,
) -> arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
    arkret_models_collaboration::governance::authorization::AuthzCheckRequestBody {
        actor_id: actor.clone(),
        action: action.to_owned(),
        resource: Some(resource),
        context: None,
    }
}

pub(super) struct AppSignalProductSink {
    call_hub: crate::views::call_signals::CallSignalHub,
    message_hub: crate::views::message_streams::MessageStreamHub,
    read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
    base_url: Signal<String>,
    token: Signal<String>,
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
}

impl AppSignalProductSink {
    pub(super) fn new(
        call_hub: crate::views::call_signals::CallSignalHub,
        message_hub: crate::views::message_streams::MessageStreamHub,
        read_receipt_hub: crate::views::read_receipts::ReadReceiptHub,
        base_url: Signal<String>,
        token: Signal<String>,
        principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    ) -> Self {
        Self {
            call_hub,
            message_hub,
            read_receipt_hub,
            base_url,
            token,
            principal_id,
        }
    }

    fn authenticated_api(&self) -> Option<crate::transport::TransportClient> {
        let base_url = self.base_url.peek().clone();
        let token = self.token.peek().clone();
        if base_url.trim().is_empty() || token.trim().is_empty() {
            return None;
        }
        crate::transport::auth::authed_api(&base_url, token).ok()
    }

    /// Fail-closed authorization probe for one exact product action and
    /// resource. Every frame reaches the governing Station's current
    /// projection through the authenticated account Station; no local verdict
    /// cache may outlive a revocation or governance-head change. A transport
    /// failure is a denial: §7.1 forbids showing a body whose authorization
    /// could not be verified.
    async fn action_allowed(
        &self,
        signal: &crate::runtime::projection::AdmittedSignal,
        action: &str,
        resource: arkret_sdk::WireResourceSelector,
    ) -> bool {
        let Some(api) = self.authenticated_api() else {
            return false;
        };
        // Admission already authenticated the full sender Actor. Reconstructing
        // an account from its principal and our Station would query a different
        // participant, losing the verified account's Station binding.
        let request = signal_authorization_request(signal.actor_id(), action, resource);
        match api.sdk_http_client() {
            Ok(http) => crate::transport::realm_read::authz_check_request(&http, &request)
                .await
                .is_ok_and(|outcome| crate::transport::realm_read::authz_allowed(&outcome)),
            Err(_) => false,
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
            let arkret_sdk::SignalPlaintext::MessageStream(frame) = &signal.payload else {
                return;
            };
            let resource = arkret_sdk::WireResourceSelector::strand(
                signal.scope_ref().realm_id().clone(),
                frame.strand_id().clone(),
            );
            // §7.1 — the sender must hold BOTH the preview action and the
            // authorization the final Message create needs. Neither is
            // observable from the outer envelope, so the recipient re-checks
            // both for the exact decrypted Strand against the governing
            // Station's current authority before any body reaches a surface.
            for action in [
                arkret_sdk::CapabilityActionId::MESSAGE_STREAM_SEND,
                arkret_sdk::CapabilityActionId::MESSAGE_CREATE,
            ] {
                if !self.action_allowed(signal, action, resource.clone()).await {
                    tracing::debug!(
                        action,
                        actor = %signal.actor_id(),
                        "dropping message stream preview: sender is not currently authorized"
                    );
                    return;
                }
            }
            let mut hub = self.message_hub;
            if let Err(error) = hub.apply_authorized(signal, crate::clock::now_utc()) {
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

    fn advance_clock(&self, now: chrono::DateTime<chrono::Utc>) {
        let mut hub = self.message_hub;
        hub.maintain(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_authorization_preserves_the_verified_actor_and_station() {
        let principal = arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station_a = arkret_sdk::DidCoreId::new("ak:did_core:web:station-a.example").unwrap();
        let station_b = arkret_sdk::DidCoreId::new("ak:did_core:web:station-b.example").unwrap();
        let actors = [
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                station_a.clone(),
            )),
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal.clone(), station_b)),
            arkret_sdk::ActorId::service(principal),
        ];
        let realm =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        for actor in actors {
            let strand =
                arkret_sdk::StrandId::new("ak:strand:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap();
            let request = signal_authorization_request(
                &actor,
                "ak.message.create",
                arkret_sdk::WireResourceSelector::strand(realm.clone(), strand.clone()),
            );
            assert_eq!(request.actor_id, actor);
            let resource = request.resource.unwrap();
            assert_eq!(resource.realm_id.as_ref(), Some(&realm));
            assert_eq!(resource.strand_id.as_ref(), Some(&strand));
        }
    }
}
