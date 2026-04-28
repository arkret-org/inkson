use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_sdk::EncryptedPayload;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawOperationRecord {
    pub operation_id: String,
    pub space_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientLocalState {
    pub sync_cursor: Option<String>,
    pub raw_operations: Vec<RawOperationRecord>,
    pub space_projections: BTreeMap<String, Value>,
    pub drafts: BTreeMap<String, String>,
    pub pending_encrypted_messages: BTreeMap<String, EncryptedPayload>,
}

#[derive(Clone, Debug, Default)]
pub struct LocalStateStore {
    cached: ClientLocalState,
}

impl LocalStateStore {
    pub fn load(&self) -> ClientLocalState {
        self.cached.clone()
    }

    pub fn save(&mut self, state: ClientLocalState) {
        self.cached = state;
    }

    pub fn save_sync_cursor(&mut self, cursor: impl Into<String>) {
        self.cached.sync_cursor = Some(cursor.into());
    }

    pub fn append_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        space_id: Option<String>,
        payload: Value,
    ) {
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id: operation_id.into(),
            space_id,
            received_at: Utc::now(),
            payload,
        });
    }

    pub fn save_space_projection(&mut self, space_id: impl Into<String>, projection: Value) {
        self.cached
            .space_projections
            .insert(space_id.into(), projection);
    }

    pub fn save_draft(&mut self, space_id: impl Into<String>, draft: impl Into<String>) {
        let space_id = space_id.into();
        let draft = draft.into();
        if draft.trim().is_empty() {
            self.cached.drafts.remove(&space_id);
        } else {
            self.cached.drafts.insert(space_id, draft);
        }
    }

    pub fn draft_for(&self, space_id: &str) -> String {
        self.cached
            .drafts
            .get(space_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn preserve_encrypted_message(
        &mut self,
        message_id: impl Into<String>,
        payload: EncryptedPayload,
    ) {
        self.cached
            .pending_encrypted_messages
            .insert(message_id.into(), payload);
    }

    pub fn pending_encrypted_count(&self) -> usize {
        self.cached.pending_encrypted_messages.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_state_store_tracks_cursor_operations_projections_and_drafts() {
        let mut store = LocalStateStore::default();
        store.save_sync_cursor("sx:next");
        store.append_raw_operation(
            "cx:operation:local-01",
            Some("cx:space:demo".to_owned()),
            serde_json::json!({"type": "cx.message.send"}),
        );
        store.save_space_projection("cx:space:demo", serde_json::json!({"name": "Demo"}));
        store.save_draft("cx:space:demo", "hello");

        let state = store.load();
        assert_eq!(state.sync_cursor.as_deref(), Some("sx:next"));
        assert_eq!(
            state.raw_operations[0].operation_id,
            "cx:operation:local-01"
        );
        assert_eq!(state.space_projections["cx:space:demo"]["name"], "Demo");
        assert_eq!(store.draft_for("cx:space:demo"), "hello");

        store.save_draft("cx:space:demo", " ");
        assert!(store.draft_for("cx:space:demo").is_empty());
    }
}
