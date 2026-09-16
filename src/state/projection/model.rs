use chrono::Utc;

/// Event model for account event projection snapshots.
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectionEvent {
    pub realm_id: Option<String>,
    pub strand_id: Option<String>,
    pub id: String,
    pub message_id: Option<String>,
    pub sender: String,
    pub sender_display: String,
    pub body: String,
    pub timestamp: String,
    pub reply_to: Option<String>,
    pub reactions: Vec<(String, Vec<String>)>,
    pub redacted: bool,
    pub edited: bool,
    pub blob_ref: Option<String>,
    pub operation_id: Option<String>,
    pub event_id: Option<String>,
    pub redaction_id: Option<String>,
    pub tombstone_reason: Option<String>,
    pub pending: bool,
    pub failed: bool,
    pub error: Option<String>,
    /// When present, this message carries encrypted message content
    /// that the local MLS group may be able to decrypt.
    pub encrypted_payload: Option<serde_json::Value>,
}

impl Default for ProjectionEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            message_id: None,
            realm_id: None,
            strand_id: None,
            sender: "inkson".to_owned(),
            sender_display: "local".to_owned(),
            body: String::new(),
            timestamp: String::new(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            blob_ref: None,
            operation_id: None,
            event_id: None,
            redaction_id: None,
            tombstone_reason: None,
            pending: false,
            failed: false,
            error: None,
            encrypted_payload: None,
        }
    }
}

impl ProjectionEvent {
    pub fn system_notice(
        id: impl Into<String>,
        sender_display: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            sender: "did:web:server.local".to_owned(),
            sender_display: sender_display.into(),
            body: body.into(),
            timestamp: timestamp_now(),
            ..Self::default()
        }
    }
}

pub(super) fn timestamp_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M").to_string()
}
