//! Ephemeral navigation state for an Agent Sidecar handoff.
//!
//! This state deliberately stays in memory. It carries UI context from the
//! ensure action into `/direct/...` without inventing a wire type or persisting
//! message plaintext outside the existing composer lifecycle.

use dioxus::prelude::*;

#[derive(Clone, Debug, PartialEq)]
pub struct SidecarSession {
    pub trace_id: String,
    pub controller_id: String,
    pub addressed_agent_ids: Vec<String>,
    pub addressed_agent_label: String,
    pub source_realm_id: String,
    pub source_strand_id: String,
    pub private_circle_id: String,
    pub private_strand_id: String,
    pub private_relation_id: String,
    pub pending_member_reconciliations: Vec<serde_json::Value>,
    pub migrated_draft: String,
    pub opened_at: chrono::DateTime<chrono::Utc>,
}

impl SidecarSession {
    pub fn matches_route(&self, realm_id: &str, strand_id: &str) -> bool {
        self.source_realm_id == realm_id && self.private_strand_id == strand_id
    }

    pub fn membership_ready(&self) -> bool {
        self.pending_member_reconciliations.is_empty()
    }

    pub fn pending_reconciliation_count(&self) -> usize {
        self.pending_member_reconciliations.len()
    }

    pub fn diagnostic_summary(&self, encryption_state: &str) -> String {
        format!(
            "Trace ID: {}\nEnsure: complete\nCircle membership: {}\nEncryption: {}\nMessage submit: not started\nNotification fanout: not started\nAgent receipt: not received",
            self.trace_id,
            if self.membership_ready() {
                "complete".to_owned()
            } else {
                format!(
                    "reconciling ({} pending)",
                    self.pending_reconciliation_count()
                )
            },
            encryption_state,
        )
    }
}

#[derive(Clone, Copy)]
pub struct SidecarSessionContext(pub Signal<Option<SidecarSession>>);

#[cfg(test)]
mod tests {
    use super::*;

    fn session(pending: Vec<serde_json::Value>) -> SidecarSession {
        SidecarSession {
            trace_id: "019f0000-0000-7000-8000-000000000001".to_owned(),
            controller_id: "did:web:alice.example".to_owned(),
            addressed_agent_ids: vec!["did:web:agents.example:assistant".to_owned()],
            addressed_agent_label: "Assistant".to_owned(),
            source_realm_id: "ak:realm:019f0000-0000-7000-8000-000000000002".to_owned(),
            source_strand_id: "ak:strand:019f0000-0000-7000-8000-000000000003".to_owned(),
            private_circle_id: "ak:circle:019f0000-0000-7000-8000-000000000004".to_owned(),
            private_strand_id: "ak:strand:019f0000-0000-7000-8000-000000000005".to_owned(),
            private_relation_id: "ak:relation:019f0000-0000-7000-8000-000000000006".to_owned(),
            pending_member_reconciliations: pending,
            migrated_draft: String::new(),
            opened_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn pending_reconciliation_is_not_ready() {
        let session = session(vec![serde_json::json!({
            "agent_id": "did:web:agents.example:assistant",
            "reason": "membership_projection_pending"
        })]);
        assert!(!session.membership_ready());
        assert_eq!(session.pending_reconciliation_count(), 1);
        assert!(
            session
                .diagnostic_summary("Reconciling access")
                .contains("reconciling (1 pending)")
        );
    }

    #[test]
    fn route_match_requires_realm_and_private_strand() {
        let session = session(Vec::new());
        assert!(session.matches_route(&session.source_realm_id, &session.private_strand_id));
        assert!(!session.matches_route(&session.source_realm_id, &session.source_strand_id));
    }
}
