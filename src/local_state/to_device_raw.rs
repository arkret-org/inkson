use super::*;

impl LocalStateStore {
    pub fn save_sync_cursor(&mut self, cursor: impl Into<String>) {
        self.ensure_cached_loaded();
        let cursor = cursor.into();
        if self.cached.sync_cursor.as_deref() == Some(cursor.as_str()) {
            return; // cursor unchanged — skip flush
        }
        self.cached.sync_cursor = Some(cursor);
        let _ = self.flush();
    }

    /// Resume cursor for this realm's `ck.self.events.stream.subscribe`. Kept
    /// separate from `sync_cursor` (account stream); see
    /// [`crate::local_state::types::ClientLocalState::realm_events_cursors`].
    pub fn realm_events_cursor(&self, realm_id: &str) -> Option<String> {
        self.load().realm_events_cursors.get(realm_id).cloned()
    }

    /// Persist the realm events stream resume cursor. A `None` cursor clears the
    /// stored value so the next subscribe rebuilds from history.
    pub fn save_realm_events_cursor(&mut self, realm_id: &str, cursor: Option<String>) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.trim();
        if realm_id.is_empty() {
            return;
        }
        match cursor {
            Some(cursor) => {
                if self.cached.realm_events_cursors.get(realm_id) == Some(&cursor) {
                    return; // unchanged — skip flush
                }
                self.cached
                    .realm_events_cursors
                    .insert(realm_id.to_owned(), cursor);
            }
            None => {
                if self.cached.realm_events_cursors.remove(realm_id).is_none() {
                    return; // nothing to clear — skip flush
                }
            }
        }
        let _ = self.flush();
    }

    pub fn save_presence_projection(&mut self, events: Vec<Value>) {
        self.ensure_cached_loaded();
        if self.cached.presence_projection == events {
            return;
        }
        self.cached.presence_projection = events;
        let _ = self.flush();
    }

    pub fn ingest_to_device_messages(&mut self, messages: &[Value]) -> usize {
        if messages.is_empty() {
            return 0;
        }
        self.ensure_cached_loaded();
        let now = Utc::now();
        let before_retain = self.cached.to_device_inbox.len();
        self.cached
            .to_device_inbox
            .retain(|message| !to_device_message_expired(message, now));
        let pruned_expired = before_retain != self.cached.to_device_inbox.len();
        let mut seen: BTreeSet<String> = self
            .cached
            .to_device_inbox
            .iter()
            .map(to_device_message_dedup_key)
            .collect();
        let mut inserted = 0;
        let mut read_cursor_updated = false;
        for message in messages {
            read_cursor_updated |= self.ingest_read_cursor_update_message(message);
            if to_device_message_expired(message, now) {
                continue;
            }
            let key = to_device_message_dedup_key(message);
            if !seen.insert(key) {
                continue;
            }
            self.cached.to_device_inbox.push(message.clone());
            inserted += 1;
        }
        let overflow = self
            .cached
            .to_device_inbox
            .len()
            .saturating_sub(TO_DEVICE_INBOX_MAX);
        if overflow > 0 {
            self.cached.to_device_inbox.drain(0..overflow);
        }
        if inserted > 0 || pruned_expired || overflow > 0 || read_cursor_updated {
            let _ = self.flush();
        }
        inserted
    }

    pub fn to_device_inbox(&self) -> Vec<Value> {
        self.load().to_device_inbox
    }

    /// Drop a handled same-principal pairing request from the to-device inbox so
    /// the approval prompt does not nag again after the user approves or rejects
    /// it. Matches the `ck.key.verification.request` whose
    /// `content.from_device` and `content.pairing_code` identify the request.
    /// Returns the number of messages removed.
    pub fn dismiss_pairing_to_device_message(
        &mut self,
        requesting_device_id: &str,
        pairing_code: &str,
    ) -> usize {
        self.ensure_cached_loaded();
        let before = self.cached.to_device_inbox.len();
        self.cached.to_device_inbox.retain(|message| {
            if message.get("kind").and_then(Value::as_str) != Some("ck.key.verification.request") {
                return true;
            }
            let Some(content) = message.get("content") else {
                return true;
            };
            let from_device = content.get("from_device").and_then(Value::as_str);
            let code = content.get("pairing_code").and_then(Value::as_str);
            !(from_device == Some(requesting_device_id) && code == Some(pairing_code))
        });
        let removed = before - self.cached.to_device_inbox.len();
        if removed > 0 {
            let _ = self.flush();
        }
        removed
    }

    pub fn append_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        realm_id: Option<String>,
        payload: Value,
    ) {
        self.ensure_cached_loaded();
        let operation_id = operation_id.into();
        if raw_operation_kind(&payload) == Some("ck.realm.destroy")
            && let Some(realm_id) = realm_id.as_deref().filter(|id| !id.trim().is_empty())
        {
            self.cached.realm_lifecycle_state.insert(
                realm_id.to_owned(),
                RealmLifecycleState::destroyed(operation_id.clone()),
            );
        }
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id,
            realm_id,
            received_at: Utc::now(),
            payload,
        });
        // YOU-02-003: roll the audit log so it can't grow without bound (and,
        // on wasm, eventually exhaust the localStorage quota and make all
        // persistence fail silently). Drop the oldest records past the cap.
        let len = self.cached.raw_operations.len();
        if len > RAW_OPERATIONS_MAX {
            self.cached
                .raw_operations
                .drain(0..len - RAW_OPERATIONS_MAX);
        }
        let _ = self.flush();
    }

    pub fn upsert_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        realm_id: Option<String>,
        payload: Value,
    ) -> bool {
        self.ensure_cached_loaded();
        let operation_id = operation_id.into();
        let incoming_event_id = raw_payload_string(&payload, "event_id");
        let incoming_payload_operation_id = raw_payload_string(&payload, "operation_id");
        let existing_index = self.cached.raw_operations.iter().position(|record| {
            record.operation_id == operation_id
                || incoming_event_id.as_deref().is_some_and(|event_id| {
                    raw_payload_string(&record.payload, "event_id").as_deref() == Some(event_id)
                })
                || incoming_payload_operation_id
                    .as_deref()
                    .is_some_and(|payload_operation_id| {
                        raw_payload_string(&record.payload, "operation_id").as_deref()
                            == Some(payload_operation_id)
                    })
        });
        if let Some(index) = existing_index {
            let existing = &mut self.cached.raw_operations[index];
            if realm_id.is_some() {
                existing.realm_id = realm_id;
            }
            existing.payload = merge_synced_raw_operation_payload(&existing.payload, payload);
            existing.received_at = Utc::now();
            let _ = self.flush();
            return false;
        }
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id,
            realm_id,
            received_at: Utc::now(),
            payload,
        });
        let len = self.cached.raw_operations.len();
        if len > RAW_OPERATIONS_MAX {
            self.cached
                .raw_operations
                .drain(0..len - RAW_OPERATIONS_MAX);
        }
        let _ = self.flush();
        true
    }

    pub fn update_raw_operation_write_state(
        &mut self,
        operation_id: &str,
        write_state: &str,
        event_id: Option<String>,
        error: Option<String>,
    ) -> bool {
        self.ensure_cached_loaded();
        let Some(record) = self
            .cached
            .raw_operations
            .iter_mut()
            .find(|record| record.operation_id == operation_id)
        else {
            return false;
        };
        let Some(payload) = record.payload.as_object_mut() else {
            return false;
        };
        payload.insert(
            "write_state".to_owned(),
            Value::String(write_state.to_owned()),
        );
        match event_id {
            Some(event_id) => {
                payload.insert("event_id".to_owned(), Value::String(event_id));
            }
            None => {
                payload.remove("event_id");
            }
        }
        match error {
            Some(error) => {
                payload.insert("error".to_owned(), Value::String(error));
            }
            None => {
                payload.remove("error");
            }
        }
        let _ = self.flush();
        true
    }
}

fn raw_payload_string(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn merge_synced_raw_operation_payload(existing: &Value, mut incoming: Value) -> Value {
    let Some(incoming_object) = incoming.as_object_mut() else {
        return incoming;
    };
    let Some(existing_object) = existing.as_object() else {
        return incoming;
    };
    for key in [
        "synthesis_entry_id",
        "synthesis_revision_body",
        "encrypted_payload_local",
    ] {
        if incoming_object.get(key).is_none_or(|value| value.is_null())
            && let Some(value) = existing_object.get(key).filter(|value| !value.is_null())
        {
            incoming_object.insert(key.to_owned(), value.clone());
        }
    }
    incoming
}
