use super::*;

impl CokretApi {
    // ────────────────────────────────────────────────────────────────
    // CKP-0008 / CKP-0009 — Personal Agent HTTP surface (11 endpoints
    // landed in soland P2 aa76b91). Each method here verifies the
    // cross-project HTTP contract so the wire shape is exercised end
    // to end even while deeper UI form layouts remain
    // `// TODO(P3-impl)` stubs.
    // ────────────────────────────────────────────────────────────────

    /// `POST /_cokret/gate/account/agent-key-pair` — `ck.gate.account.agent_key_pair`.
    /// Authorizes a fresh agent runtime key pair against an agent
    /// principal.
    pub async fn agent_key_pair(
        &self,
        body: &AgentKeyPairReqBody,
    ) -> anyhow::Result<AgentKeyPairResBody> {
        self.post_json(
            "_cokret/gate/account/agent-key-pair",
            serde_json::to_value(body)?,
        )
        .await
    }

    /// `POST /_cokret/self/agents` — `ck.self.agent.provision`. Provisions a new
    /// personal agent: DID issuance + first agent key authorize +
    /// controller grant attach in one orchestrated request.
    pub async fn agent_provision(
        &self,
        body: &AgentProvisionReqBody,
    ) -> anyhow::Result<AgentResBody> {
        self.post_json("_cokret/self/agents", serde_json::to_value(body)?)
            .await
    }

    /// `GET /_cokret/self/agents` — `ck.self.agent.list`. Returns the
    /// controller-self list of agents (soland enforces caller binding).
    pub async fn agent_list(&self) -> anyhow::Result<AgentListResBody> {
        self.get_json("_cokret/self/agents").await
    }

    /// `GET /_cokret/self/agents/{id}` — `ck.self.agent.get`.
    pub async fn agent_get(&self, agent_principal_id: &str) -> anyhow::Result<AgentResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        self.get_json(&format!("_cokret/self/agents/{agent_principal_id}"))
            .await
    }

    /// `POST /_cokret/self/agents/{id}/pause` — `ck.self.agent.pause` (durable
    /// reducer-input event). Auth Server flushes capability cache with
    /// reason `agent_paused`.
    pub async fn agent_pause(
        &self,
        agent_principal_id: &str,
        body: &AgentLifecycleReqBody,
    ) -> anyhow::Result<AgentLifecycleResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/pause"),
            serde_json::to_value(body)?,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/resume` — `ck.self.agent.resume`.
    pub async fn agent_resume(
        &self,
        agent_principal_id: &str,
        body: &AgentLifecycleReqBody,
    ) -> anyhow::Result<AgentLifecycleResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/resume"),
            serde_json::to_value(body)?,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/deactivate` — `ck.self.agent.deactivate`.
    /// Triggers a cascade: `ck.agent.key.revoke` +
    /// `ck.capability.revoke` + runtime endpoint revocation on the
    /// soland side. Destructive — callers MUST gate this on an
    /// explicit "DEACTIVATE" type-to-confirm dialog.
    pub async fn agent_deactivate(
        &self,
        agent_principal_id: &str,
        body: &AgentLifecycleReqBody,
    ) -> anyhow::Result<AgentLifecycleResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/deactivate"),
            serde_json::to_value(body)?,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/rotate-key` — `ck.self.agent.rotate_key`.
    /// Writes the `ck.agent.key.{revoke,authorize}` pair atomically.
    pub async fn agent_rotate_key(
        &self,
        agent_principal_id: &str,
        body: &AgentRotateKeyReqBody,
    ) -> anyhow::Result<AgentRotateKeyResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/rotate-key"),
            serde_json::to_value(body)?,
        )
        .await
    }

    /// `POST /_cokret/self/agents/{id}/grants` — `ck.self.agent.grant.attach`.
    /// Attaches a capability grant scoped to the agent. `grant_kind`
    /// SHOULD be one of the 14 CKP-0008 capability actions.
    pub async fn agent_grant_attach(
        &self,
        agent_principal_id: &str,
        body: &AgentGrantAttachReqBody,
    ) -> anyhow::Result<AgentGrantResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        self.post_json(
            &format!("_cokret/self/agents/{agent_principal_id}/grants"),
            serde_json::to_value(body)?,
        )
        .await
    }

    /// `DELETE /_cokret/self/agents/{id}/grants/{grant_id}` —
    /// `ck.self.agent.grant.detach`.
    pub async fn agent_grant_detach(
        &self,
        agent_principal_id: &str,
        grant_id: &str,
    ) -> anyhow::Result<AgentGrantDetachResBody> {
        let agent_principal_id = path_component(agent_principal_id);
        let grant_id = path_component(grant_id);
        self.delete_json(&format!(
            "_cokret/self/agents/{agent_principal_id}/grants/{grant_id}"
        ))
        .await
    }

    /// `POST /_cokret/self/agent-sidecar-threads:ensure` —
    /// `ck.self.agent.sidecar_thread.ensure`. Idempotently derives the
    /// controller_agent_circle_key and ensures a sidecar Circle exists
    /// between the controller and the native agent.
    pub async fn agent_sidecar_thread_ensure(
        &self,
        agent_principal_id: &str,
        body: &AgentSidecarThreadEnsureReqBody,
    ) -> anyhow::Result<AgentSidecarThreadEnsureResBody> {
        let mut body = body.clone();
        if body.agent_principal_id.trim().is_empty() {
            body.agent_principal_id = agent_principal_id.to_owned();
        } else if body.agent_principal_id.trim() != agent_principal_id.trim() {
            anyhow::bail!("agent_principal_id path argument does not match request body");
        }
        if body.realm_id.trim().is_empty() {
            anyhow::bail!("realm_id is required");
        }
        if body.controller_principal_id.trim().is_empty() {
            anyhow::bail!("controller_principal_id is required");
        }
        self.post_json(
            "_cokret/self/agent-sidecar-threads:ensure",
            serde_json::to_value(&body)?,
        )
        .await
    }
}
