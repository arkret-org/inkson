use super::*;

impl CokretApi {
    pub(crate) async fn list_circles(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<cokret_sdk::CircleList> {
        self.get_json(&format!("_cokret/self/circles?realm_id={realm_id}"))
            .await
    }

    pub(crate) async fn submit_circle_scope_rotate_events(
        &self,
        circle_id: &str,
        events: &[cokret_sdk::Event],
        idempotency_key: Option<String>,
    ) -> anyhow::Result<cokret_sdk::CircleScopeRotateOutcome> {
        let circle_id = circle_id.trim();
        if circle_id.is_empty() {
            anyhow::bail!("circle_id is required for scope rotate");
        }
        let mut signed_events = Vec::with_capacity(events.len());
        let proof_context = self.event_proof_context().await?;
        for event in events {
            let mut signed = event.clone();
            if signed.seal_ref.is_none() && !signed.effects.is_empty() {
                let seal = self.current_seal_for(signed.realm_id.as_str()).await?;
                signed.seal_ref = Some(
                    cokret_sdk::SealId::new(seal)
                        .map_err(|err| anyhow::anyhow!("current seal id is invalid: {err}"))?,
                );
            }
            if signed.proofs.is_empty() {
                crate::event_signer::sign_sdk_event_with_active_context(
                    &mut signed,
                    proof_context.clone(),
                )
                .map_err(|err| {
                    anyhow::anyhow!(
                        "no active signer configured \u{2014} cannot submit Circle scope rotate event: {err}"
                    )
                })?;
            }
            signed_events.push(signed);
        }
        let idem = idempotency_key.unwrap_or_else(uuid_v7);
        let body = cokret_sdk::CircleScopeRotateRequestBody {
            events: signed_events,
            idempotency_key: Some(idem.clone()),
        };
        let request = self
            .http
            .post(self.endpoint(&format!("_cokret/self/circles/{circle_id}/scope-rotate"))?)
            .json(&body);
        let request = self.with_write_request_headers(request, &idem);
        self.send_json_retryable(self.prepare_request(request), Method::POST)
            .await
    }
}
