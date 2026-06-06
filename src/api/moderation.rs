use super::*;

impl CokretApi {
    pub async fn report_moderation(
        &self,
        realm_id: &str,
        target_ref: &str,
        report_reason_code: &str,
        reporter: &str,
    ) -> anyhow::Result<ModerationReportOutcome> {
        self.post_json(
            "_cokret/self/moderation/report",
            json!({
                "realm_id": realm_id,
                "target_ref": target_ref,
                "report_reason_code": report_reason_code,
                "reporter": reporter,
                "description": null,
                "evidence_refs": []
            }),
        )
        .await
    }

    /// Ship a single client-side telemetry entry to
    /// soland's deployment-local audit ingest endpoint.
    ///
    /// The endpoint shape mirrors sodmin's audit feed: a plain JSON
    /// body keyed by actor/action/outcome/note/recorded_at. The
    /// 404-tolerant return type lets the caller distinguish "not
    /// wired" (re-buffer) from "rejected" (drop) without parsing
    /// error strings.
    pub async fn post_audit_user_action(&self, payload: Value) -> Result<(), AuditPostError> {
        let request = self
            .http
            .post(
                self.endpoint("_soland/admin/audit/user-action")
                    .map_err(|err| AuditPostError::Other(err.to_string()))?,
            )
            .json(&payload);
        let response = self
            .prepare_request(request)
            .send()
            .await
            .map_err(|err| AuditPostError::Other(err.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        if status == StatusCode::NOT_FOUND {
            return Err(AuditPostError::NotWired);
        }
        Err(AuditPostError::Other(format!("HTTP {status}")))
    }
}
