use super::*;
use crate::api_error::AuditPostError;

impl CokretApi {
    /// Client-side telemetry has no spec-defined Cokret ingest endpoint.
    /// Callers should keep the local buffer instead of reaching into
    /// deployment-private server surfaces.
    pub async fn post_audit_user_action(&self, payload: Value) -> Result<(), AuditPostError> {
        let _ = payload;
        Err(AuditPostError::NotWired)
    }
}
