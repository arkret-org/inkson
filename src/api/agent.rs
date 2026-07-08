use cokret_sdk::models::{AgentKeyPairOutcome, AgentKeyPairRequestBody};

use super::*;

impl CokretApi {
    // ────────────────────────────────────────────────────────────────
    // CKP-0008 / CKP-0009 — Personal Agent HTTP surface. YOU-01-005:
    // every method below is typed against the SDK's authoritative
    // wire models (mirrors of `agent-operations.schema.json`); the
    // former hand-rolled `Agent*ReqBody` / `Agent*ResBody` local
    // mirrors were removed.
    // ────────────────────────────────────────────────────────────────

    /// `POST /_cokret/gate/account/agent-key-pair` —
    /// `ck.gate.account.command.pair_agent_key`. The runtime generated the
    /// key and PoP; the controller signs `authorize_event` locally before this
    /// method submits the pairing request.
    async fn agent_key_pair(
        &self,
        body: &AgentKeyPairRequestBody,
    ) -> anyhow::Result<AgentKeyPairOutcome> {
        self.sdk_http_client()?
            .agent_key_pair(body)
            .await
            .map_err(anyhow::Error::from)
    }

    pub(crate) async fn agent_key_pair_with_authorize_event(
        &self,
        mut body: AgentKeyPairRequestBody,
        authorize_event: &cokret_sdk::Event,
    ) -> anyhow::Result<AgentKeyPairOutcome> {
        let (signed, _) = self.prepare_sdk_event_for_submit(authorize_event).await?;
        body.authorize_event = serde_json::to_value(signed)?;
        self.agent_key_pair(&body).await
    }
}
