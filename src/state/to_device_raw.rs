use super::*;

impl LocalStateStore {
    pub fn load_client_cursor(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        Ok(match scope {
            garth::CursorScope::Account { .. } => self
                .sync_cursor()
                .filter(|cursor| !cursor.trim().is_empty()),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                self.realm_events_cursor(realm_id.as_str())
            }
            garth::CursorScope::DeviceMessages {
                service_id,
                actor_id,
                device_id,
            } => self.device_message_cursor(&crate::client_core::device_message_cursor_key(
                service_id.as_ref(),
                actor_id,
                device_id,
            )?),
        })
    }

    pub fn save_client_cursor(
        &mut self,
        scope: &garth::CursorScope,
        cursor: garth::OpaqueCursor,
    ) -> arkret_sdk::Result<()> {
        match scope {
            garth::CursorScope::Account { .. } => self.save_sync_cursor(cursor),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                self.save_realm_events_cursor(realm_id.as_str(), Some(cursor));
            }
            garth::CursorScope::DeviceMessages {
                service_id,
                actor_id,
                device_id,
            } => self.save_device_message_cursor(
                crate::client_core::device_message_cursor_key(
                    service_id.as_ref(),
                    actor_id,
                    device_id,
                )?,
                Some(cursor),
            ),
        }
        Ok(())
    }

    pub fn clear_client_cursor(&mut self, scope: &garth::CursorScope) -> arkret_sdk::Result<()> {
        match scope {
            garth::CursorScope::Account { .. } => self.clear_sync_cursor(),
            garth::CursorScope::RealmEvents { realm_id, .. } => {
                self.save_realm_events_cursor(realm_id.as_str(), None);
            }
            garth::CursorScope::DeviceMessages {
                service_id,
                actor_id,
                device_id,
            } => self.save_device_message_cursor(
                crate::client_core::device_message_cursor_key(
                    service_id.as_ref(),
                    actor_id,
                    device_id,
                )?,
                None,
            ),
        }
        Ok(())
    }

    pub fn sync_cursor(&self) -> Option<String> {
        self.load().sync_cursor
    }

    pub fn save_sync_cursor(&mut self, cursor: impl Into<String>) {
        self.ensure_cached_loaded();
        let cursor = cursor.into();
        if self.cached.sync_cursor.as_deref() == Some(cursor.as_str()) {
            return;
        }
        self.cached.sync_cursor = Some(cursor);
        let _ = self.flush();
    }

    pub fn clear_sync_cursor(&mut self) {
        self.ensure_cached_loaded();
        if self.cached.sync_cursor.is_none() {
            return;
        }
        self.cached.sync_cursor = None;
        let _ = self.flush();
    }

    /// Resume cursor for this realm's `ak.self.events.stream.subscribe`. Kept
    /// separate from `sync_cursor` (account stream); see
    /// [`crate::state::types::ClientLocalState::realm_events_cursors`].
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
        if self.cached.realm_events_cursors.get(realm_id).cloned() == cursor {
            return;
        }
        match cursor {
            Some(cursor) => {
                self.cached
                    .realm_events_cursors
                    .insert(realm_id.to_owned(), cursor);
            }
            None => {
                self.cached.realm_events_cursors.remove(realm_id);
            }
        }
        let _ = self.flush();
    }

    pub fn client_core_event_seen(&self, event_id: &str) -> bool {
        garth::BoundedSeenWindow::from_entries(
            self.load().client_core_seen_event_ids,
            garth::DEFAULT_SEEN_EVENTS_CAPACITY,
        )
        .contains(event_id)
    }

    pub fn remember_client_core_event(&mut self, event_id: impl Into<String>) {
        self.ensure_cached_loaded();
        let event_id = event_id.into();
        let mut window = garth::BoundedSeenWindow::from_entries(
            std::mem::take(&mut self.cached.client_core_seen_event_ids),
            garth::DEFAULT_SEEN_EVENTS_CAPACITY,
        );
        let inserted = window.remember(event_id);
        self.cached.client_core_seen_event_ids = window.into_entries();
        if !inserted {
            return;
        }
        let _ = self.flush();
    }

    pub fn device_message_cursor(&self, key: &str) -> Option<String> {
        self.load().device_message_cursors.get(key).cloned()
    }

    pub fn save_device_message_cursor(&mut self, key: String, cursor: Option<String>) {
        self.ensure_cached_loaded();
        match cursor {
            Some(cursor) => {
                self.cached.device_message_cursors.insert(key, cursor);
            }
            None => {
                self.cached.device_message_cursors.remove(&key);
            }
        }
        let _ = self.flush();
    }

    pub fn save_presence_projection(&mut self, events: &[arkret_sdk::EphemeralEnvelope]) {
        let events = events
            .iter()
            .filter_map(|event| serde_json::to_value(event).ok())
            .collect::<Vec<_>>();
        self.ensure_cached_loaded();
        if self.cached.presence_projection == events {
            return;
        }
        self.cached.presence_projection = events;
        let _ = self.flush();
    }

    pub fn ingest_to_device_messages(
        &mut self,
        messages: &[arkret_sdk::DeviceMessageEnvelope],
    ) -> usize {
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
            let Ok(message) = serde_json::to_value(message) else {
                continue;
            };
            read_cursor_updated |= self.ingest_read_cursor_update_message(&message);
            if to_device_message_expired(&message, now) {
                continue;
            }
            let key = to_device_message_dedup_key(&message);
            if !seen.insert(key) {
                continue;
            }
            self.cached.to_device_inbox.push(message);
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
    /// it. Matches the `ak.key.verification.request` whose
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
            if message.get("kind").and_then(Value::as_str) != Some("ak.key.verification.request") {
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

    /// Drop a handled `ak.realm_key.request` from the local to-device inbox.
    /// The server-delivered envelope carries `request_id` at top-level, while
    /// older local/test envelopes may nest it under `content`; accept both so a
    /// successfully answered request does not trigger duplicate shares forever.
    pub fn dismiss_realm_key_request_to_device_message(&mut self, request_id: &str) -> usize {
        self.ensure_cached_loaded();
        let request_id = request_id.trim();
        if request_id.is_empty() {
            return 0;
        }
        let before = self.cached.to_device_inbox.len();
        self.cached.to_device_inbox.retain(|message| {
            if message.get("kind").and_then(Value::as_str) != Some("ak.realm_key.request") {
                return true;
            }
            realm_key_request_message_id(message).as_deref() != Some(request_id)
        });
        let removed = before - self.cached.to_device_inbox.len();
        if removed > 0 {
            let _ = self.flush();
        }
        removed
    }

    /// Drop a handled `ak.realm_key.share` from the local to-device inbox once
    /// its history secrets were installed. soland projects durable shares with
    /// the source Event `operation_id`, while event-shaped envelopes may expose
    /// `event_id`; accept both identifiers.
    pub fn dismiss_realm_key_share_to_device_message(&mut self, operation_id: &str) -> usize {
        self.ensure_cached_loaded();
        let operation_id = operation_id.trim();
        if operation_id.is_empty() {
            return 0;
        }
        let before = self.cached.to_device_inbox.len();
        self.cached.to_device_inbox.retain(|message| {
            if message.get("kind").and_then(Value::as_str) != Some("ak.realm_key.share") {
                return true;
            }
            realm_key_share_message_id(message).as_deref() != Some(operation_id)
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
        if raw_operation_kind(&payload) == Some("ak.realm.destroy")
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
        let incoming_message_id = raw_payload_string(&payload, "message_id")
            .filter(|_| raw_payload_is_message_create(&payload));
        let existing_index = self.cached.raw_operations.iter().position(|record| {
            record.operation_id == operation_id
                || incoming_event_id.as_deref().is_some_and(|event_id| {
                    raw_payload_string(&record.payload, "event_id").as_deref() == Some(event_id)
                })
                || incoming_message_id.as_deref().is_some_and(|message_id| {
                    raw_payload_is_message_create(&record.payload)
                        && raw_payload_string(&record.payload, "message_id").as_deref()
                            == Some(message_id)
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
            let mut changed = false;
            if let Some(realm_id) = realm_id
                && existing.realm_id.as_deref() != Some(realm_id.as_str())
            {
                existing.realm_id = Some(realm_id);
                changed = true;
            }
            let merged_payload = merge_synced_raw_operation_payload(&existing.payload, payload);
            if existing.payload != merged_payload {
                existing.payload = merged_payload;
                changed = true;
            }
            if changed {
                existing.received_at = Utc::now();
                let _ = self.flush();
            }
            return changed;
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

fn realm_key_request_message_id(message: &Value) -> Option<String> {
    message
        .get("request_id")
        .or_else(|| {
            message
                .get("content")
                .and_then(|content| content.get("request_id"))
        })
        .or_else(|| {
            message
                .get("payload")
                .and_then(|payload| payload.get("request_id"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn realm_key_share_message_id(message: &Value) -> Option<String> {
    message
        .get("operation_id")
        .or_else(|| message.get("event_id"))
        .or_else(|| {
            message
                .get("content")
                .and_then(|content| content.get("operation_id"))
        })
        .or_else(|| {
            message
                .get("content")
                .and_then(|content| content.get("event_id"))
        })
        .or_else(|| {
            message
                .get("payload")
                .and_then(|payload| payload.get("operation_id"))
        })
        .or_else(|| {
            message
                .get("payload")
                .and_then(|payload| payload.get("event_id"))
        })
        .or_else(|| {
            message
                .get("unsigned")
                .and_then(|unsigned| unsigned.get("source_event_id"))
        })
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn raw_payload_string(payload: &Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn raw_payload_is_message_create(payload: &Value) -> bool {
    raw_operation_kind(payload) == Some("ak.message.create")
        && raw_payload_string(payload, "message_id")
            .as_deref()
            .is_some_and(|message_id| message_id.starts_with("ak:message:"))
}

fn merge_synced_raw_operation_payload(existing: &Value, mut incoming: Value) -> Value {
    if raw_payload_is_redaction_tombstone(existing)
        && !raw_payload_is_redaction_tombstone(&incoming)
    {
        return existing.clone();
    }
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

fn raw_payload_is_redaction_tombstone(payload: &Value) -> bool {
    payload.get("redacted").and_then(Value::as_bool) == Some(true)
        || payload.get("state").and_then(Value::as_str) == Some("redacted")
        || payload
            .get("payload")
            .is_some_and(raw_payload_is_redaction_tombstone)
}
