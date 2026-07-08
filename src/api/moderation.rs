use super::*;

impl CokretApi {
    pub async fn report_moderation(
        &self,
        realm_id: &str,
        target_ref: &str,
        report_reason_code: &str,
        reporter: &str,
    ) -> anyhow::Result<ModerationReportOutcome> {
        let realm = cokret_sdk::RealmId::new(realm_id)
            .map_err(|err| anyhow::anyhow!("invalid realm_id `{realm_id}`: {err}"))?;
        let reporter_did = cokret_sdk::Did::new(reporter.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid reporter `{reporter}`: {err}"))?;
        let body = cokret_sdk::models::ModerationReportRequestBody {
            realm_id: realm,
            effective_scope: None,
            target_ref: target_ref.to_owned(),
            report_reason_code: report_reason_code.to_owned(),
            description: None,
            reporter: reporter_did,
            evidence_refs: Vec::new(),
            evidence_package: Value::Null,
            franking_proof: Value::Null,
        };
        self.sdk_http_client()?
            .moderation_report(&body)
            .await
            .map_err(anyhow::Error::from)
    }

    /// Client-side telemetry has no spec-defined Cokret ingest endpoint.
    /// Callers should keep the local buffer instead of reaching into
    /// deployment-private server surfaces.
    pub async fn post_audit_user_action(&self, payload: Value) -> Result<(), AuditPostError> {
        let _ = payload;
        Err(AuditPostError::NotWired)
    }
}
