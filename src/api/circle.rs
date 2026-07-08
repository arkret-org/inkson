use super::*;

impl CokretApi {
    pub(crate) async fn list_circles(
        &self,
        realm_id: &str,
    ) -> anyhow::Result<cokret_sdk::CircleList> {
        self.sdk_http_client()?
            .circle_list(realm_id)
            .await
            .map_err(anyhow::Error::from)
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
            self.stamp_cba_basis_for_sdk_event(&mut signed).await?;
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
        self.sdk_http_client()?
            .circle_scope_rotate(circle_id, &idem, &body)
            .await
            .map_err(anyhow::Error::from)
    }
}
