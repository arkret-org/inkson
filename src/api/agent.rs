use cokret_sdk::models::{AgentParticipationOutcome, AgentParticipationSetRequestBody};

use super::*;

impl CokretApi {
    // ────────────────────────────────────────────────────────────────
    // CKP-0008 / CKP-0009 — Personal Agent HTTP surface. YOU-01-005:
    // every method below is typed against the SDK's authoritative
    // wire models (mirrors of `agent-operations.schema.json`); the
    // former hand-rolled `Agent*ReqBody` / `Agent*ResBody` local
    // mirrors were removed.
    // ────────────────────────────────────────────────────────────────

    /// `POST /_cokret/self/agents` — `ck.self.agent.command.provision`. Provisions a new
    /// personal agent principal; the spec outcome is the pairing handle
    /// (`agent_principal_id` + `pairing_request_id` + `expires_at`).
    pub async fn agent_provision(
        &self,
        body: &cokret_sdk::AgentProvisionRequestBody,
    ) -> anyhow::Result<cokret_sdk::AgentProvisionOutcome> {
        self.post_json("_cokret/self/agents", body).await
    }

    /// `GET /_cokret/self/agents` — `ck.self.agent.query.list`. Returns the
    /// controller-self list of agent views (soland enforces caller binding).
    pub async fn agent_list(&self) -> anyhow::Result<cokret_sdk::AgentList> {
        self.get_json("_cokret/self/agents").await
    }

    /// `GET /_cokret/self/agents/{id}` — `ck.self.agent.resource.get`.
    pub async fn agent_get(
        &self,
        agent_principal_id: &str,
    ) -> anyhow::Result<cokret_sdk::AgentView> {
        let agent_principal_id = path_component(agent_principal_id);
        self.get_json(&format!("_cokret/self/agents/{agent_principal_id}"))
            .await
    }

    /// `POST /_cokret/self/agents/{id}/pause` — `ck.self.agent.command.pause`.
    /// The accepted reducer-input event remains `ck.self.agent.pause`. Auth Server flushes
    /// capability cache with reason `agent_paused`. The spec response is
    /// `operation_status_outcome` (`{ok, status}`).
    pub async fn agent_pause(
        &self,
        agent_principal_id: &str,
        body: &cokret_sdk::AgentPauseRequestBody,
    ) -> anyhow::Result<cokret_sdk::OperationStatusOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/pause"),
            body,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/resume` — `ck.self.agent.command.resume`.
    pub async fn agent_resume(
        &self,
        agent_principal_id: &str,
        body: &cokret_sdk::AgentResumeRequestBody,
    ) -> anyhow::Result<cokret_sdk::OperationStatusOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/resume"),
            body,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/deactivate` — `ck.self.agent.command.deactivate`.
    /// Triggers a cascade: `ck.agent.key.revoke` +
    /// `ck.capability.revoke` + runtime endpoint revocation on the
    /// soland side. Destructive — callers MUST gate this on an
    /// explicit "DEACTIVATE" type-to-confirm dialog.
    pub async fn agent_deactivate(
        &self,
        agent_principal_id: &str,
        body: &cokret_sdk::AgentDeactivateRequestBody,
    ) -> anyhow::Result<cokret_sdk::OperationStatusOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/deactivate"),
            body,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/rotate-key` — `ck.self.agent.command.rotate_key`.
    /// Writes the `ck.agent.key.{revoke,authorize}` pair atomically.
    pub async fn agent_rotate_key(
        &self,
        agent_principal_id: &str,
        body: &cokret_sdk::AgentRotateKeyRequestBody,
    ) -> anyhow::Result<cokret_sdk::AgentRotateKeyOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/rotate-key"),
            body,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/grants` — `ck.self.agent.grant.command.attach`.
    /// Attaches a capability grant scoped to the agent. The spec body
    /// carries the full grant object under the single `grant` property.
    pub async fn agent_grant_attach(
        &self,
        agent_principal_id: &str,
        body: &cokret_sdk::AgentGrantAttachRequestBody,
    ) -> anyhow::Result<cokret_sdk::AgentGrantAttachOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/grants"),
            body,
        )
        .await
    }

    /// `DELETE /_cokret/self/agents/{id}/grants/{grant_id}` —
    /// `ck.self.agent.grant.resource.delete`.
    pub async fn agent_grant_detach(
        &self,
        agent_principal_id: &str,
        grant_id: &str,
    ) -> anyhow::Result<cokret_sdk::AgentGrantDetachOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        let grant_id = path_component(grant_id);
        self.delete_json(&format!(
            "_cokret/self/agents/{agent_principal_id}/grants/{grant_id}"
        ))
        .await
    }

    /// `PUT /_cokret/self/agents/{id}/participation` —
    /// `ck.self.agent.participation.resource.replace` (CKP-0010). Sets the
    /// controller's participation selection for one scope; soland
    /// rejects selections that exceed the effective ceiling.
    pub async fn agent_participation_set(
        &self,
        agent_principal_id: &str,
        body: &AgentParticipationSetRequestBody,
    ) -> anyhow::Result<AgentParticipationOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.put_json(
            &format!("_cokret/self/agents/{agent_principal_id}/participation"),
            body,
        )
        .await
    }

    /// `GET /_cokret/self/agents/{id}/participation` —
    /// `ck.self.agent.participation.resource.get` (CKP-0010). Returns the
    /// resolved per-scope selection / ceiling / effective triples.
    pub async fn agent_participation_get(
        &self,
        agent_principal_id: &str,
    ) -> anyhow::Result<AgentParticipationOutcome> {
        let agent_principal_id = path_component(agent_principal_id);
        self.get_json(&format!(
            "_cokret/self/agents/{agent_principal_id}/participation"
        ))
        .await
    }

    /// `POST /_cokret/self/agent-sidecar-threads:ensure` —
    /// `ck.self.agent.sidecar_thread.command.ensure`. Idempotently derives the
    /// controller_agent_circle_key and ensures a sidecar Circle exists
    /// for the controller and the addressed native agents.
    pub async fn agent_sidecar_thread_ensure(
        &self,
        body: &cokret_sdk::AgentSidecarThreadEnsureRequestBody,
    ) -> anyhow::Result<cokret_sdk::AgentSidecarThreadEnsureOutcome> {
        if body.controller_principal_id.as_str().trim().is_empty() {
            anyhow::bail!("controller_principal_id is required");
        }
        if body.context_ref.realm_id.as_str().trim().is_empty() {
            anyhow::bail!("context_ref.realm_id is required");
        }
        if body.context_ref.strand_id.is_none() && body.context_ref.relation_id.is_none() {
            anyhow::bail!("context_ref must include strand_id or relation_id");
        }
        self.post_json("_cokret/self/agent-sidecar-threads:ensure", body)
            .await
    }
}
