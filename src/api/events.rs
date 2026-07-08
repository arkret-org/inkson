//! Transitional `CokretApi` delegators onto the extracted
//! [`crate::event_submit::EventSubmitter`]. The durable/ephemeral event
//! submission logic now lives in `crate::event_submit`; these thin forwarders
//! keep the remaining `CokretApi` call sites (views + sibling `src/api`
//! submodules) compiling while they migrate to `with_event_submitter`. Each
//! forwarder builds a fresh `EventSubmitter` from the current authenticated SDK
//! client, matching the former per-`CokretApi` describe-cache lifetime.

use super::*;

impl CokretApi {
    pub(crate) fn event_submitter(&self) -> anyhow::Result<crate::event_submit::EventSubmitter> {
        Ok(crate::event_submit::EventSubmitter::new(
            self.sdk_http_client()?,
        ))
    }

    pub async fn backfill(&self, realm_id: &str) -> anyhow::Result<BackfillView> {
        self.event_submitter()?.backfill(realm_id).await
    }

    pub(crate) async fn find_mls_genesis_event_id(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<Option<cokret_sdk::EventId>> {
        self.event_submitter()?
            .find_mls_genesis_event_id(realm_id)
            .await
    }

    pub async fn send_typing(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        strand_id: &str,
        typing: bool,
    ) -> anyhow::Result<TypingResult> {
        self.event_submitter()?
            .send_typing(realm_id, actor, device_id, strand_id, typing)
            .await
    }

    pub async fn send_presence(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        state: &str,
        status_message: Option<&str>,
        last_active_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> anyhow::Result<PresenceResult> {
        self.event_submitter()?
            .send_presence(
                realm_id,
                actor,
                device_id,
                state,
                status_message,
                last_active_at,
            )
            .await
    }

    pub async fn send_receipt(
        &self,
        realm_id: &str,
        actor: &str,
        device_id: &str,
        strand_id: &str,
        event_id: &str,
        receipt_type: &str,
    ) -> anyhow::Result<ReceiptResult> {
        self.event_submitter()?
            .send_receipt(
                realm_id,
                actor,
                device_id,
                strand_id,
                event_id,
                receipt_type,
            )
            .await
    }

    pub async fn events_frontier_realm_seal_view(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<cokret_sdk::RealmSealFrontierView> {
        self.event_submitter()?
            .events_frontier_realm_seal_view(realm_id)
            .await
    }

    pub async fn events_frontier_actor(
        &self,
        actor_id: &str,
    ) -> anyhow::Result<cokret_sdk::ActorFrontierView> {
        self.event_submitter()?
            .events_frontier_actor(actor_id)
            .await
    }

    pub async fn events_describe(&self) -> anyhow::Result<cokret_sdk::ServiceDescribe> {
        self.event_submitter()?.events_describe().await
    }

    pub(crate) async fn event_proof_context(
        &self,
    ) -> anyhow::Result<crate::event_signer::EventProofContext> {
        self.event_submitter()?.event_proof_context().await
    }

    pub(crate) async fn submit_signed_sdk_event(
        &self,
        signed: &cokret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.event_submitter()?
            .submit_signed_sdk_event(signed)
            .await
    }

    pub(crate) async fn submit_sdk_event(
        &self,
        event: &cokret_sdk::Event,
    ) -> anyhow::Result<SubmitEventResult> {
        self.event_submitter()?.submit_sdk_event(event).await
    }

    pub(crate) async fn stamp_cba_basis_for_sdk_event(
        &self,
        event: &mut cokret_sdk::Event,
    ) -> anyhow::Result<()> {
        self.event_submitter()?
            .stamp_cba_basis_for_sdk_event(event)
            .await
    }

    pub(crate) async fn submit_signed_sdk_events_batch(
        &self,
        sdk_events: &[cokret_sdk::Event],
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::EventsSubmitOutcome> {
        self.event_submitter()?
            .submit_signed_sdk_events_batch(sdk_events, idempotency_key)
            .await
    }

    pub(crate) async fn submit_sdk_events_batch(
        &self,
        realm_id: &str,
        events: Vec<cokret_sdk::Event>,
        idempotency_key: Option<&str>,
    ) -> anyhow::Result<cokret_sdk::EventsSubmitOutcome> {
        self.event_submitter()?
            .submit_sdk_events_batch(realm_id, events, idempotency_key)
            .await
    }

    pub async fn submit_ephemeral_envelope(
        &self,
        envelope: &cokret_sdk::EphemeralEnvelope,
    ) -> anyhow::Result<cokret_sdk::EphemeralSubmitOutcome> {
        self.event_submitter()?
            .submit_ephemeral_envelope(envelope)
            .await
    }
}
