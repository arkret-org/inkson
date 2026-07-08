use super::*;

impl CokretApi {
    // CKP-0008 / CKP-0009 — the agent HTTP surface (provision / list / get /
    // lifecycle / grants / participation) moved to the SDK http-client via
    // `with_authed_sdk_client`. The one remaining forwarder covers the
    // controller-signed key-pair path, which threads through the extracted
    // event submitter (`prepare_sdk_event_for_submit`).
    pub(crate) async fn agent_key_pair_with_authorize_event(
        &self,
        body: cokret_sdk::models::AgentKeyPairRequestBody,
        authorize_event: &cokret_sdk::Event,
    ) -> anyhow::Result<cokret_sdk::models::AgentKeyPairOutcome> {
        self.event_submitter()?
            .agent_key_pair_with_authorize_event(body, authorize_event)
            .await
    }
}
