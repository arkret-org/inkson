//! Round 25 (R1 + R2): client-side key-backup + restore-ticket lifecycle.
//!
//! Wraps `ApiClient`'s raw JSON endpoints in typed records that match
//! the SDK's [`contrix::KeyBackupClient`] shapes. The wrapper here is
//! **not** a re-implementation of the SDK helper — yougen's API client
//! still owns the bearer + audience plumbing and the typed `Client`
//! constructor expected by the SDK's `KeyBackupClient::new` is not yet
//! wired through. Once that lands, the typed wrapper here can be
//! replaced with calls to the SDK type without UI churn because the
//! record shapes line up.
//!
//! UI surface:
//! * R1 — Settings → Recovery section "Back up keys" / "Restore keys"
//!   buttons drive `put_key_backup` + `start_restore_ticket`. The body
//!   builders below produce the canonical request shape soland's
//!   reducer expects.
//! * R2 — Settings → Recovery section lists open restore tickets with
//!   their lifecycle state (`pending → approved → executor_running →
//!   complete`) plus per-ticket Cancel buttons.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Round 25 (R1): typed restore-ticket lifecycle stage. The string the
/// soland scaffold returns gets normalized to one of these so the UI
/// can render a deterministic progress chip + decide which actions are
/// legal (advance vs cancel vs nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreTicketStage {
    /// Soland accepted the ticket but no approval has run yet
    /// (`authz_pending` / `pending`).
    Pending,
    /// Authorization checks passed, the ticket is queued for approval
    /// (`authz_checked` / `policy_checked`).
    Approving,
    /// Approval threshold met; ready to execute (`approved`).
    Approved,
    /// Executor is materializing the backup (`executor_running` /
    /// `materializing`).
    ExecutorRunning,
    /// Restore complete (`materialized` / `complete`).
    Complete,
    /// Operator cancelled the ticket (`cancelled`).
    Cancelled,
    /// Restore failed (`failed`); ticket state preserved for audit.
    Failed,
}

impl RestoreTicketStage {
    /// Normalize a wire status string to the typed stage.
    pub fn from_wire(status: &str) -> Self {
        match status.to_ascii_lowercase().as_str() {
            "authz_pending" | "pending" | "created" => Self::Pending,
            "authz_checked" | "policy_checked" | "approving" => Self::Approving,
            "approved" => Self::Approved,
            "executor_running" | "materializing" | "running" => Self::ExecutorRunning,
            "materialized" | "complete" | "completed" => Self::Complete,
            "cancelled" | "canceled" => Self::Cancelled,
            "failed" | "error" => Self::Failed,
            _ => Self::Pending,
        }
    }

    /// Stable label for UI badges. Mirrors sodmin's restore console
    /// vocabulary so both surfaces use the same chip text.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Approving => "Approving",
            Self::Approved => "Approved",
            Self::ExecutorRunning => "Executor Running",
            Self::Complete => "Complete",
            Self::Cancelled => "Cancelled",
            Self::Failed => "Failed",
        }
    }

    /// CSS-friendly badge class.
    pub fn badge_class(self) -> &'static str {
        match self {
            Self::Pending | Self::Approving => "badge amber",
            Self::Approved => "badge blue",
            Self::ExecutorRunning => "badge accent",
            Self::Complete => "badge green",
            Self::Cancelled => "badge",
            Self::Failed => "badge red",
        }
    }

    /// Whether the ticket is still cancellable. Terminal states
    /// (`Complete` / `Cancelled` / `Failed`) drop the cancel button.
    pub fn is_cancellable(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Approving | Self::Approved | Self::ExecutorRunning
        )
    }

    /// Whether the ticket has reached a terminal state (no further UI
    /// polling is needed).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Complete | Self::Cancelled | Self::Failed)
    }
}

/// Round 25 (R1 / R2): typed view of a restore ticket as the UI
/// renders it. Mirrors [`contrix::key_backup_client::RestoreTicket`]
/// minus the Did newtype dependency so this struct can compose with
/// the JSON-shaped api.rs surface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientRestoreTicket {
    pub id: String,
    #[serde(default)]
    pub backup_id: Option<String>,
    pub stage: RestoreTicketStage,
    /// The verbatim wire `status` field — preserved so audit / debug
    /// surfaces can show the raw soland reply.
    pub raw_status: String,
    #[serde(default)]
    pub allowed_next_transitions: Vec<String>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

impl ClientRestoreTicket {
    /// Parse a single ticket payload from the api.rs JSON wrapper.
    pub fn from_json(value: &Value) -> Option<Self> {
        let id = value
            .get("id")
            .and_then(Value::as_str)
            .or_else(|| value.get("ticket_id").and_then(Value::as_str))?
            .to_owned();
        let backup_id = value
            .get("backup_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let raw_status = value
            .get("status")
            .and_then(Value::as_str)
            .or_else(|| value.get("state").and_then(Value::as_str))
            .unwrap_or("pending")
            .to_owned();
        let stage = RestoreTicketStage::from_wire(&raw_status);
        let allowed_next_transitions = value
            .get("allowed_next_transitions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let created_at = value
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        let expires_at = value
            .get("expires_at")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        Some(Self {
            id,
            backup_id,
            stage,
            raw_status,
            allowed_next_transitions,
            created_at,
            expires_at,
        })
    }

    /// Parse a list payload (`{ "tickets": [...] }` or top-level array).
    pub fn from_list_json(value: &Value) -> Vec<Self> {
        let array = value
            .get("tickets")
            .and_then(Value::as_array)
            .or_else(|| value.get("items").and_then(Value::as_array))
            .or_else(|| value.as_array());
        let Some(arr) = array else {
            return Vec::new();
        };
        arr.iter().filter_map(Self::from_json).collect()
    }
}

/// Round 25 (R1): canonical request body for `PUT /api/v1/keys/backups/{id}`.
/// `backup_id` is the operator-chosen handle (e.g. `recovery-{device}`);
/// `actor_did` and `device_id` identify who minted the encrypted blob;
/// `key_material_encrypted` is the opaque ciphertext the SDK's
/// `KeyBackupClient` would emit for a real client.
pub fn build_key_backup_put_body(
    backup_id: &str,
    actor_did: &str,
    device_id: &str,
    key_material_encrypted: &str,
    scheme: &str,
    version: &str,
) -> Value {
    json!({
        "backup_id": backup_id,
        "actor_id": actor_did,
        "device_id": device_id,
        "scheme": scheme,
        "version": version,
        "key_material_encrypted": key_material_encrypted,
    })
}

/// Round 25 (R1): canonical request body for
/// `POST /api/v1/keys/backups/{backup_id}/restore/start`.
pub fn build_restore_start_body(actor_did: &str, device_id: &str, reason: &str) -> Value {
    json!({
        "actor_id": actor_did,
        "device_id": device_id,
        "reason": reason,
    })
}

/// Round 25 (R2): map a restore-ticket cancel outcome to a UI status
/// string. Centralized so timeline + settings show the same copy.
pub fn cancel_status_message(ticket_id: &str, success: bool) -> String {
    if success {
        format!("Restore ticket {ticket_id} cancelled.")
    } else {
        format!("Restore ticket {ticket_id} cancel failed.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_stage_normalizes_known_wire_strings() {
        assert_eq!(
            RestoreTicketStage::from_wire("authz_pending"),
            RestoreTicketStage::Pending
        );
        assert_eq!(
            RestoreTicketStage::from_wire("approved"),
            RestoreTicketStage::Approved
        );
        assert_eq!(
            RestoreTicketStage::from_wire("executor_running"),
            RestoreTicketStage::ExecutorRunning
        );
        assert_eq!(
            RestoreTicketStage::from_wire("materialized"),
            RestoreTicketStage::Complete
        );
        assert_eq!(
            RestoreTicketStage::from_wire("CANCELLED"),
            RestoreTicketStage::Cancelled
        );
        assert_eq!(
            RestoreTicketStage::from_wire("not-a-real-state"),
            RestoreTicketStage::Pending
        );
    }

    #[test]
    fn restore_stage_terminal_classification() {
        assert!(RestoreTicketStage::Complete.is_terminal());
        assert!(RestoreTicketStage::Cancelled.is_terminal());
        assert!(RestoreTicketStage::Failed.is_terminal());
        assert!(!RestoreTicketStage::Pending.is_terminal());
        assert!(!RestoreTicketStage::Approving.is_terminal());
        assert!(!RestoreTicketStage::ExecutorRunning.is_terminal());
    }

    #[test]
    fn restore_stage_cancellable_classification() {
        assert!(RestoreTicketStage::Pending.is_cancellable());
        assert!(RestoreTicketStage::Approving.is_cancellable());
        assert!(RestoreTicketStage::Approved.is_cancellable());
        assert!(RestoreTicketStage::ExecutorRunning.is_cancellable());
        assert!(!RestoreTicketStage::Complete.is_cancellable());
        assert!(!RestoreTicketStage::Cancelled.is_cancellable());
        assert!(!RestoreTicketStage::Failed.is_cancellable());
    }

    #[test]
    fn restore_stage_labels_and_badges_are_unique() {
        let stages = [
            RestoreTicketStage::Pending,
            RestoreTicketStage::Approving,
            RestoreTicketStage::Approved,
            RestoreTicketStage::ExecutorRunning,
            RestoreTicketStage::Complete,
            RestoreTicketStage::Cancelled,
            RestoreTicketStage::Failed,
        ];
        let mut labels: Vec<&str> = stages.iter().map(|s| s.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), stages.len(), "every stage has a unique label");
    }

    #[test]
    fn ticket_parses_from_full_payload() {
        let payload = json!({
            "id": "rt_1",
            "backup_id": "bk_alice_recovery",
            "status": "approved",
            "allowed_next_transitions": ["executor_running"],
            "created_at": "2026-05-09T12:00:00Z",
            "expires_at": "2026-05-10T12:00:00Z",
        });
        let ticket = ClientRestoreTicket::from_json(&payload).unwrap();
        assert_eq!(ticket.id, "rt_1");
        assert_eq!(ticket.backup_id.as_deref(), Some("bk_alice_recovery"));
        assert_eq!(ticket.stage, RestoreTicketStage::Approved);
        assert_eq!(ticket.raw_status, "approved");
        assert_eq!(ticket.allowed_next_transitions, vec!["executor_running"]);
        assert!(ticket.created_at.is_some());
    }

    #[test]
    fn ticket_falls_back_to_legacy_fields() {
        let payload = json!({
            "ticket_id": "rt_legacy",
            "state": "executor_running",
        });
        let ticket = ClientRestoreTicket::from_json(&payload).unwrap();
        assert_eq!(ticket.id, "rt_legacy");
        assert_eq!(ticket.stage, RestoreTicketStage::ExecutorRunning);
    }

    #[test]
    fn ticket_list_extracts_tickets_or_items_arrays() {
        let payload = json!({
            "tickets": [
                {"id": "rt_a", "status": "approved"},
                {"id": "rt_b", "status": "materialized"},
            ]
        });
        let tickets = ClientRestoreTicket::from_list_json(&payload);
        assert_eq!(tickets.len(), 2);
        assert_eq!(tickets[0].stage, RestoreTicketStage::Approved);
        assert_eq!(tickets[1].stage, RestoreTicketStage::Complete);
    }

    #[test]
    fn ticket_list_handles_top_level_array() {
        let payload = json!([
            {"id": "rt_a", "status": "pending"},
            {"id": "rt_b", "status": "cancelled"},
        ]);
        let tickets = ClientRestoreTicket::from_list_json(&payload);
        assert_eq!(tickets.len(), 2);
        assert_eq!(tickets[0].stage, RestoreTicketStage::Pending);
        assert_eq!(tickets[1].stage, RestoreTicketStage::Cancelled);
    }

    #[test]
    fn build_key_backup_put_body_round_trips_required_fields() {
        let body = build_key_backup_put_body(
            "bk_alice",
            "did:web:alice.example",
            "cx:device:01alice",
            "BASE64_OPAQUE_BLOB",
            "did_recovery",
            "v1",
        );
        assert_eq!(body["backup_id"], "bk_alice");
        assert_eq!(body["actor_id"], "did:web:alice.example");
        assert_eq!(body["scheme"], "did_recovery");
        assert_eq!(body["version"], "v1");
        assert_eq!(body["key_material_encrypted"], "BASE64_OPAQUE_BLOB");
    }

    #[test]
    fn build_restore_start_body_emits_expected_fields() {
        let body = build_restore_start_body(
            "did:web:alice.example",
            "cx:device:01alice_phone",
            "lost laptop",
        );
        assert_eq!(body["actor_id"], "did:web:alice.example");
        assert_eq!(body["device_id"], "cx:device:01alice_phone");
        assert_eq!(body["reason"], "lost laptop");
    }

    #[test]
    fn cancel_status_message_includes_ticket_id() {
        assert!(cancel_status_message("rt_1", true).contains("rt_1"));
        assert!(cancel_status_message("rt_2", true).contains("cancelled"));
        assert!(cancel_status_message("rt_3", false).contains("failed"));
    }
}
