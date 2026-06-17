use chrono::Utc;

use crate::views::helpers::short_protocol_id;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct TimelineRevision {
    pub body: String,
    pub timestamp: String,
    pub operation_id: Option<String>,
    pub event_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct BlobAttachment {
    pub(super) blob_ref: String,
    /// Spec rename (head 37ce729 / SDK 4d5a1af): `size` → `size_bytes`
    /// on blob/media metadata.
    pub(super) size_bytes: usize,
    pub(super) media_type: String,
    pub(super) content_digest: String,
}

/// Event model for timeline display.
#[derive(Clone, Debug, PartialEq)]
pub struct TimelineEvent {
    pub realm_id: Option<String>,
    pub id: String,
    pub sender: String,
    pub sender_display: String,
    pub body: String,
    pub timestamp: String,
    pub reply_to: Option<String>,
    pub reactions: Vec<(String, Vec<String>)>,
    pub redacted: bool,
    pub edited: bool,
    pub thread_id: Option<String>,
    pub blob_ref: Option<String>,
    pub operation_id: Option<String>,
    pub event_id: Option<String>,
    pub redaction_id: Option<String>,
    pub tombstone_reason: Option<String>,
    pub revisions: Vec<TimelineRevision>,
    pub pending: bool,
    pub failed: bool,
    pub error: Option<String>,
    /// When present, this message carries encrypted message content
    /// that the local MLS group may be able to decrypt.
    /// Timeline's audit-accessed emitter watches this field
    /// — on successful decrypt, fires a single `ck.audit.accessed` for
    /// `id` per session (de-duplicated by `audit_accessed_emitted`).
    pub encrypted_payload: Option<serde_json::Value>,
}

impl Default for TimelineEvent {
    fn default() -> Self {
        Self {
            id: String::new(),
            realm_id: None,
            sender: "yougen".to_owned(),
            sender_display: "local".to_owned(),
            body: String::new(),
            timestamp: String::new(),
            reply_to: None,
            reactions: Vec::new(),
            redacted: false,
            edited: false,
            thread_id: None,
            blob_ref: None,
            operation_id: None,
            event_id: None,
            redaction_id: None,
            tombstone_reason: None,
            revisions: Vec::new(),
            pending: false,
            failed: false,
            error: None,
            encrypted_payload: None,
        }
    }
}

impl TimelineEvent {
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

    pub fn pending_message(
        realm_id: impl Into<String>,
        id: impl Into<String>,
        sender: impl Into<String>,
        sender_display: impl Into<String>,
        body: impl Into<String>,
        reply_to: Option<String>,
        thread_id: Option<String>,
    ) -> Self {
        Self {
            realm_id: Some(realm_id.into()),
            id: id.into(),
            sender: sender.into(),
            sender_display: sender_display.into(),
            body: body.into(),
            timestamp: timestamp_now(),
            reply_to,
            thread_id,
            pending: true,
            ..Self::default()
        }
    }

    pub fn apply_send_ack(&mut self, event_id: String, operation_id: String) {
        self.id = event_id;
        self.operation_id = Some(operation_id);
        self.event_id = None;
        self.pending = false;
        self.failed = false;
        self.error = None;
    }

    pub fn apply_revision(
        &mut self,
        new_body: String,
        operation_id: Option<String>,
        event_id: Option<String>,
    ) {
        self.revisions.push(TimelineRevision {
            body: self.body.clone(),
            timestamp: self.timestamp.clone(),
            operation_id: self.operation_id.clone(),
            event_id: self.event_id.clone(),
        });
        self.body = new_body;
        self.timestamp = timestamp_now();
        self.operation_id = operation_id;
        self.event_id = event_id;
        self.redacted = false;
        self.redaction_id = None;
        self.tombstone_reason = None;
        self.edited = true;
        self.pending = false;
        self.failed = false;
        self.error = None;
    }

    pub fn apply_redaction(&mut self, redaction_id: String, reason: Option<String>) {
        self.redacted = true;
        self.operation_id = None;
        self.event_id = None;
        self.redaction_id = Some(redaction_id);
        self.tombstone_reason = reason;
        self.timestamp = timestamp_now();
        self.pending = false;
        self.failed = false;
        self.error = None;
    }

    pub fn fact_summary(&self) -> Option<String> {
        match (
            self.operation_id.as_deref(),
            self.event_id.as_deref(),
            self.redaction_id.as_deref(),
        ) {
            (_, _, Some(redaction_id)) => {
                Some(format!("tombstone {}", short_protocol_id(redaction_id)))
            }
            (Some(operation_id), Some(event_id), _) => Some(format!(
                "fact {} / event {}",
                short_protocol_id(operation_id),
                short_protocol_id(event_id)
            )),
            (Some(operation_id), None, _) => {
                Some(format!("fact {}", short_protocol_id(operation_id)))
            }
            _ => None,
        }
    }
}

pub(super) fn timestamp_now() -> String {
    Utc::now().format("%Y-%m-%d %H:%M").to_string()
}
