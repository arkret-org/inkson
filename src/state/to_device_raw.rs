use arkret_wire::event_kind_str;

use super::*;

fn commit_stream_cursor_key(scope: &garth::CursorScope) -> arkret_sdk::Result<String> {
    debug_assert!(matches!(scope, garth::CursorScope::CommitStream { .. }));
    serde_json::to_string(scope).map_err(Into::into)
}

impl LocalStateStore {
    fn set_client_cursor_cached(
        &mut self,
        scope: &garth::CursorScope,
        cursor: Option<String>,
    ) -> arkret_sdk::Result<()> {
        match scope {
            garth::CursorScope::Account { .. } => self.cached.sync_cursor = cursor,
            garth::CursorScope::CommitStream { .. } => match cursor {
                Some(cursor) => {
                    let key = commit_stream_cursor_key(scope)?;
                    self.cached.commit_stream_cursors.insert(key, cursor);
                }
                None => {
                    let key = commit_stream_cursor_key(scope)?;
                    self.cached.commit_stream_cursors.remove(&key);
                }
            },
            garth::CursorScope::DeviceMessages {
                service_id,
                actor_id,
                device_id,
            } => {
                let key = crate::client_core::device_message_cursor_key(
                    service_id.as_ref(),
                    actor_id,
                    device_id,
                )?;
                match cursor {
                    Some(cursor) => {
                        self.cached.device_message_cursors.insert(key, cursor);
                    }
                    None => {
                        self.cached.device_message_cursors.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn commit_client_delivery(
        &mut self,
        scope: garth::CursorScope,
        cursor: Option<String>,
        events: Vec<garth::ClientEvent>,
    ) -> arkret_sdk::Result<Option<garth::DeliveryId>> {
        self.ensure_cached_loaded();
        if !events.is_empty()
            && self.cached.client_core_pending_deliveries.len() >= garth::MAX_PENDING_DELIVERIES
        {
            return Err(arkret_sdk::Error::Protocol(
                "durable inbox capacity reached; acknowledge pending deliveries before polling"
                    .to_owned(),
            ));
        }
        if !events.is_empty() && self.cached.client_core_next_delivery_id >= u64::MAX - 1 {
            return Err(arkret_sdk::Error::Protocol(
                "delivery id overflow".to_owned(),
            ));
        }
        let previous = self.cached.clone();
        self.set_client_cursor_cached(&scope, cursor.clone())?;
        let delivery_id = if events.is_empty() {
            None
        } else {
            let next_id = self
                .cached
                .client_core_next_delivery_id
                .checked_add(1)
                .ok_or_else(|| arkret_sdk::Error::Protocol("delivery id overflow".to_owned()))?;
            let id = garth::DeliveryId::from_stored_u64(next_id)
                .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?;
            self.cached.client_core_next_delivery_id = next_id;
            self.cached.client_core_pending_deliveries.push_back(
                crate::state::types::StoredClientDelivery {
                    id: id.get(),
                    scope,
                    cursor,
                    events: serde_json::to_value(events)?,
                    attempts: 0,
                    next_attempt_at_ms: None,
                    error_class: None,
                    last_error: None,
                },
            );
            Some(id)
        };
        if let Err(error) = self.flush() {
            self.cached = previous;
            return Err(arkret_sdk::Error::Protocol(format!(
                "persist durable inbox commit: {error}"
            )));
        }
        Ok(delivery_id)
    }

    pub(crate) fn pending_client_deliveries(
        &self,
        limit: usize,
    ) -> arkret_sdk::Result<Vec<garth::PendingDelivery<Vec<garth::ClientEvent>>>> {
        self.load()
            .client_core_pending_deliveries
            .iter()
            .take(limit.clamp(1, garth::MAX_PENDING_READ))
            .map(|delivery| {
                Ok(garth::PendingDelivery {
                    id: garth::DeliveryId::from_stored_u64(delivery.id)
                        .map_err(|error| arkret_sdk::Error::Protocol(error.to_string()))?,
                    scope: delivery.scope.clone(),
                    cursor: delivery.cursor.clone(),
                    payload: serde_json::from_value(delivery.events.clone())?,
                    attempts: delivery.attempts,
                    next_attempt_at_ms: delivery.next_attempt_at_ms,
                    error_class: delivery.error_class,
                    last_error: delivery.last_error.clone(),
                })
            })
            .collect()
    }

    pub(crate) fn client_delivery_snapshot(
        &self,
        id: garth::DeliveryId,
    ) -> Option<crate::state::types::StoredClientDelivery> {
        self.load()
            .client_core_pending_deliveries
            .into_iter()
            .find(|delivery| delivery.id == id.get())
    }

    pub(crate) fn restore_client_delivery(
        &mut self,
        delivery: crate::state::types::StoredClientDelivery,
    ) -> arkret_sdk::Result<()> {
        self.ensure_cached_loaded();
        if let Some(current) = self
            .cached
            .client_core_pending_deliveries
            .iter_mut()
            .find(|current| current.id == delivery.id)
        {
            *current = delivery;
        } else {
            self.cached
                .client_core_pending_deliveries
                .push_back(delivery);
            self.cached
                .client_core_pending_deliveries
                .make_contiguous()
                .sort_by_key(|delivery| delivery.id);
        }
        self.flush().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("restore durable inbox delivery: {error}"))
        })
    }

    pub(crate) fn rollback_client_delivery_commit(
        &mut self,
        scope: &garth::CursorScope,
        previous_cursor: Option<String>,
        delivery_id: Option<garth::DeliveryId>,
    ) -> arkret_sdk::Result<()> {
        self.ensure_cached_loaded();
        self.set_client_cursor_cached(scope, previous_cursor)?;
        if let Some(delivery_id) = delivery_id {
            self.cached
                .client_core_pending_deliveries
                .retain(|delivery| delivery.id != delivery_id.get());
        }
        self.flush().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("rollback durable inbox commit: {error}"))
        })
    }

    pub(crate) fn ack_client_delivery(
        &mut self,
        id: garth::DeliveryId,
    ) -> arkret_sdk::Result<bool> {
        self.ensure_cached_loaded();
        let previous = self.cached.clone();
        let before = self.cached.client_core_pending_deliveries.len();
        self.cached
            .client_core_pending_deliveries
            .retain(|delivery| delivery.id != id.get());
        if self.cached.client_core_pending_deliveries.len() == before {
            return Ok(false);
        }
        if let Err(error) = self.flush() {
            self.cached = previous;
            return Err(arkret_sdk::Error::Protocol(format!(
                "persist durable inbox acknowledgement: {error}"
            )));
        }
        Ok(true)
    }

    pub(crate) fn retry_client_delivery(
        &mut self,
        id: garth::DeliveryId,
        next_attempt_at_ms: Option<i64>,
        error_class: garth::DeliveryErrorClass,
        mut error: String,
    ) -> arkret_sdk::Result<bool> {
        self.ensure_cached_loaded();
        let previous = self.cached.clone();
        let Some(delivery) = self
            .cached
            .client_core_pending_deliveries
            .iter_mut()
            .find(|delivery| delivery.id == id.get())
        else {
            return Ok(false);
        };
        delivery.attempts = delivery
            .attempts
            .checked_add(1)
            .ok_or_else(|| arkret_sdk::Error::Protocol("delivery attempts overflow".to_owned()))?;
        delivery.next_attempt_at_ms = next_attempt_at_ms;
        delivery.error_class = Some(error_class);
        if error.len() > garth::MAX_DELIVERY_ERROR_BYTES {
            let mut end = garth::MAX_DELIVERY_ERROR_BYTES;
            while !error.is_char_boundary(end) {
                end -= 1;
            }
            error.truncate(end);
        }
        delivery.last_error = Some(error);
        if let Err(error) = self.flush() {
            self.cached = previous;
            return Err(arkret_sdk::Error::Protocol(format!(
                "persist durable inbox retry: {error}"
            )));
        }
        Ok(true)
    }

    pub fn load_client_cursor(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::OpaqueCursor>> {
        Ok(match scope {
            garth::CursorScope::Account { .. } => self
                .sync_cursor()
                .filter(|cursor| !cursor.trim().is_empty()),
            garth::CursorScope::CommitStream { .. } => self
                .load()
                .commit_stream_cursors
                .get(&commit_stream_cursor_key(scope)?)
                .cloned(),
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
            garth::CursorScope::CommitStream { .. } => {
                self.ensure_cached_loaded();
                self.cached
                    .commit_stream_cursors
                    .insert(commit_stream_cursor_key(scope)?, cursor);
                self.flush().map_err(|error| {
                    arkret_sdk::Error::Protocol(format!("persist commit-stream cursor: {error}"))
                })?;
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
            garth::CursorScope::CommitStream { .. } => {
                self.ensure_cached_loaded();
                self.cached
                    .commit_stream_cursors
                    .remove(&commit_stream_cursor_key(scope)?);
                self.flush().map_err(|error| {
                    arkret_sdk::Error::Protocol(format!("clear commit-stream cursor: {error}"))
                })?;
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

    pub(crate) fn load_account_checkpoint(
        &self,
        scope: &garth::CursorScope,
    ) -> arkret_sdk::Result<Option<garth::AccountCursorCheckpoint>> {
        if !matches!(scope, garth::CursorScope::Account { .. }) {
            return Err(arkret_sdk::Error::Protocol(
                "account checkpoint requires an account cursor scope".to_owned(),
            ));
        }
        Ok(self
            .sync_cursor()
            .map(|cursor| garth::AccountCursorCheckpoint {
                cursor,
                station_cas: self.load().station_cas_projection,
            }))
    }

    pub(crate) fn save_account_checkpoint(
        &mut self,
        scope: &garth::CursorScope,
        checkpoint: garth::AccountCursorCheckpoint,
    ) -> arkret_sdk::Result<()> {
        if !matches!(scope, garth::CursorScope::Account { .. }) {
            return Err(arkret_sdk::Error::Protocol(
                "account checkpoint requires an account cursor scope".to_owned(),
            ));
        }
        self.ensure_cached_loaded();
        let previous_cursor = self.cached.sync_cursor.clone();
        let previous_station_cas = self.cached.station_cas_projection.clone();
        self.cached.sync_cursor = Some(checkpoint.cursor);
        self.cached.station_cas_projection = checkpoint.station_cas;
        if let Err(error) = self.flush() {
            self.cached.sync_cursor = previous_cursor;
            self.cached.station_cas_projection = previous_station_cas;
            return Err(arkret_sdk::Error::Protocol(format!(
                "persist account cursor checkpoint: {error}"
            )));
        }
        Ok(())
    }

    pub(crate) fn restore_account_checkpoint(
        &mut self,
        scope: &garth::CursorScope,
        checkpoint: Option<garth::AccountCursorCheckpoint>,
    ) -> arkret_sdk::Result<()> {
        if !matches!(scope, garth::CursorScope::Account { .. }) {
            return Err(arkret_sdk::Error::Protocol(
                "account checkpoint requires an account cursor scope".to_owned(),
            ));
        }
        self.ensure_cached_loaded();
        match checkpoint {
            Some(checkpoint) => {
                self.cached.sync_cursor = Some(checkpoint.cursor);
                self.cached.station_cas_projection = checkpoint.station_cas;
            }
            None => {
                self.cached.sync_cursor = None;
                self.cached.station_cas_projection = garth::StationCasProjection::default();
            }
        }
        self.flush().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("restore account cursor checkpoint: {error}"))
        })
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

    /// Replace the local presence projection with decrypted Signal bodies.
    ///
    /// v1 removed the plaintext presence bucket from account sync; presence now
    /// arrives as `ak.presence` AEAD plaintext inside a `SignalEnvelope`, so
    /// this takes already-decrypted bodies rather than wire envelopes.
    pub fn save_presence_projection(&mut self, bodies: &[serde_json::Value]) {
        let events = bodies.to_vec();
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
        let receipts_before_retain = self.cached.to_device_receipts.len();
        self.cached
            .to_device_receipts
            .retain(|_, receipt| receipt.expires_at > now);
        let pruned_receipts = receipts_before_retain != self.cached.to_device_receipts.len();
        for persisted in &self.cached.to_device_inbox {
            if let (Ok(key), Ok(digest), Some(expires_at)) = (
                to_device_message_dedup_key(persisted),
                arkret_sdk::canonical::canonical_sha256(persisted),
                to_device_message_expiry(persisted),
            ) {
                self.cached
                    .to_device_receipts
                    .entry(key)
                    .or_insert(DeviceMessageReceipt {
                        canonical_digest: digest,
                        expires_at,
                    });
            }
        }
        let mut inserted = 0;
        let mut read_cursor_updated = false;
        let mut invite_delivery_updated = false;
        let mut conflict = None;
        for message in messages {
            let key = to_device_envelope_dedup_key(message);
            let Ok(message) = serde_json::to_value(message) else {
                continue;
            };
            if to_device_message_expired(&message, now) {
                continue;
            }
            let Some(expires_at) = to_device_message_expiry(&message) else {
                conflict = Some(format!("device_message_conflict: invalid expiry for {key}"));
                break;
            };
            let Ok(digest) = arkret_sdk::canonical::canonical_sha256(&message) else {
                conflict = Some(format!(
                    "device_message_conflict: canonicalization failed for {key}"
                ));
                break;
            };
            match self.cached.to_device_receipts.get(&key) {
                Some(existing) if existing.canonical_digest == digest => continue,
                Some(_) => {
                    conflict = Some(format!(
                        "device_message_conflict: envelope changed for {key}"
                    ));
                    break;
                }
                None => {
                    if self.cached.to_device_receipts.len() >= TO_DEVICE_RECEIPTS_MAX {
                        conflict = Some(
                            "device_message_receipt_capacity: durable receipt capacity exhausted"
                                .to_owned(),
                        );
                        break;
                    }
                    self.cached.to_device_receipts.insert(
                        key,
                        DeviceMessageReceipt {
                            canonical_digest: digest,
                            expires_at,
                        },
                    );
                }
            }
            read_cursor_updated |= self.ingest_read_cursor_update_message(&message);
            invite_delivery_updated |= self.ingest_invite_delivery_update_message(&message);
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
        if inserted > 0 || pruned_expired || overflow > 0 {
            // Rebuild only during bounded inbox maintenance, never per Realm read.
            let mut index: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (position, message) in self.cached.to_device_inbox.iter().enumerate() {
                // A Welcome is not an Event and carries no Event kind: it is a
                // producer-signed `MlsWelcomeDelivery` recipient object. The
                // only sound test is whether the delivery parses closed and
                // passes its own shape validation.
                let Some(delivery) = message
                    .get("content")
                    .and_then(|content| {
                        serde_json::from_value::<arkret_wire::MlsWelcomeDelivery>(content.clone())
                            .ok()
                    })
                    .filter(|delivery| delivery.validate_shape().is_ok())
                else {
                    continue;
                };
                if let Ok(key) = serde_json::to_string(&delivery.effective_scope) {
                    index.entry(key).or_default().push(position);
                }
            }
            self.cached.mls_welcome_inbox_index = index;
        }
        if inserted > 0
            || pruned_expired
            || pruned_receipts
            || overflow > 0
            || read_cursor_updated
            || invite_delivery_updated
        {
            let _ = self.flush();
        }
        if let Some(conflict) = conflict {
            *self.lock_persist_health() = Some(conflict);
        }
        inserted
    }

    pub fn to_device_inbox(&self) -> Vec<Value> {
        self.load().to_device_inbox
    }

    pub(crate) fn welcome_inbox_for_scope(&self, scope: &arkret_sdk::ScopeRef) -> Vec<Value> {
        let Ok(key) = serde_json::to_string(scope) else {
            return Vec::new();
        };
        let now = Utc::now();
        self.cached
            .mls_welcome_inbox_index
            .get(&key)
            .into_iter()
            .flatten()
            .rev()
            .take(4)
            .filter_map(|position| self.cached.to_device_inbox.get(*position))
            .filter(|message| !to_device_message_expired(message, now))
            .cloned()
            .collect()
    }

    pub fn append_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        realm_id: Option<String>,
        payload: Value,
    ) {
        self.ensure_cached_loaded();
        let operation_id = operation_id.into();
        if raw_operation_kind(&payload) == Some(event_kind_str::REALM_DESTROY)
            && let Some(realm_id) = realm_id.as_deref().filter(|id| !id.trim().is_empty())
        {
            self.cached.realm_destroy_receipts.insert(
                realm_id.to_owned(),
                RealmDestroyReceipt::destroyed(operation_id.clone()),
            );
        }
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id,
            realm_id,
            received_at: Utc::now(),
            payload,
        });
        // Roll the audit log so it can't grow without bound (and,
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
        let incoming_local_operation_alias =
            raw_payload_string(&payload, "local_operation_idempotency_alias");
        let incoming_message_id = raw_payload_string(&payload, "message_id")
            .filter(|_| raw_payload_is_message_create(&payload));
        let existing_index = self.cached.raw_operations.iter().position(|record| {
            record.operation_id == operation_id
                // An optimistic Event is keyed by its local operation alias.
                // Once accepted, `update_raw_operation_write_state` records the
                // final content-bound Event id in `payload.event_id`; realm
                // backfill is keyed by that final id. Join those two identities
                // here so the canonical row replaces the optimistic row instead
                // of surviving beside it as a second create.
                || raw_payload_string(&record.payload, "event_id")
                    .as_deref()
                    == Some(operation_id.as_str())
                || incoming_local_operation_alias
                    .as_deref()
                    .is_some_and(|alias| record.operation_id == alias)
                || incoming_event_id.as_deref().is_some_and(|event_id| {
                    record.operation_id == event_id
                        || raw_payload_string(&record.payload, "event_id").as_deref()
                            == Some(event_id)
                })
                || incoming_message_id.as_deref().is_some_and(|message_id| {
                    raw_payload_is_message_create(&record.payload)
                        && raw_payload_string(&record.payload, "message_id").as_deref()
                            == Some(message_id)
                })
                || incoming_payload_operation_id
                    .as_deref()
                    .is_some_and(|payload_operation_id| {
                        record.operation_id == payload_operation_id
                            || raw_payload_string(&record.payload, "operation_id").as_deref()
                                == Some(payload_operation_id)
                            || raw_payload_string(&record.payload, "event_id").as_deref()
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

    /// Fill in an optimistic row's `body` once the write it stands for exists.
    ///
    /// An encrypted write cannot be built until the epoch's Event is authored,
    /// so its row is enqueued by holder-local operation id first and the body
    /// lands here.
    pub fn update_raw_operation_body(&mut self, operation_id: &str, body: Value) -> bool {
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
        payload.insert("body".to_owned(), body);
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
        if let Some(record) = self
            .cached
            .raw_operations
            .iter_mut()
            .find(|record| record.operation_id == operation_id)
            && update_operation_write_state_payload(
                &mut record.payload,
                write_state,
                event_id.as_deref(),
                error.as_deref(),
            )
        {
            let _ = self.flush();
            return true;
        }

        // A fast submit response can arrive before Dioxus runs the projector
        // effect that drains `pending_projection_commands`. Reconcile the
        // receipt into that queued record as well; otherwise the later
        // projection writes the stale `queued` payload and the card spins
        // forever even though the server already accepted it.
        self.pending_projection_commands.iter_mut().any(|command| {
            let super::LocalProjectionCommand::AppendRawOperation {
                operation_id: queued_operation_id,
                payload,
                ..
            } = command;
            queued_operation_id == operation_id
                && update_operation_write_state_payload(
                    payload,
                    write_state,
                    event_id.as_deref(),
                    error.as_deref(),
                )
        })
    }
}

fn update_operation_write_state_payload(
    payload: &mut Value,
    write_state: &str,
    event_id: Option<&str>,
    error: Option<&str>,
) -> bool {
    let Some(payload) = payload.as_object_mut() else {
        return false;
    };
    payload.insert(
        "write_state".to_owned(),
        Value::String(write_state.to_owned()),
    );
    match event_id {
        Some(event_id) => {
            payload.insert("event_id".to_owned(), Value::String(event_id.to_owned()));
        }
        None => {
            payload.remove("event_id");
        }
    }
    match error {
        Some(error) => {
            payload.insert("error".to_owned(), Value::String(error.to_owned()));
        }
        None => {
            payload.remove("error");
        }
    }
    true
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
    raw_operation_kind(payload) == Some(event_kind_str::MESSAGE_CREATE)
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
        // Accepted optimistic rows keep their holder-local record key.  The
        // receipt's content-bound identity remains authoritative after a later
        // canonical Event backfill replaces the payload shape.
        "event_id",
        "local_operation_idempotency_alias",
        // Calendar RSVP authoring records the deterministic schedule winner it
        // observed. The canonical Event intentionally does not repeat this
        // holder-local observation, but reconciliation must not erase it.
        "locally_observed_schedule_winner",
        "synthesis_entry_id",
        "synthesis_revision_body",
        "encrypted_payload_local",
        // The accepted invite authoring path pins this from its typed delivery
        // target. Realm Event projections intentionally do not repeat the
        // private service route, so preserve it for deferred MLS claim retry.
        "recipient_id",
        // The producer's draft-time object handle. Losing it would strand every
        // reference other rows recorded against the temporary id (see below).
        "local_temporary_target_ref",
    ] {
        if incoming_object.get(key).is_none_or(|value| value.is_null())
            && let Some(value) = existing_object.get(key).filter(|value| !value.is_null())
        {
            incoming_object.insert(key.to_owned(), value.clone());
        }
    }
    // An event-derived create's optimistic row is keyed by the DRAFT object id
    // (`local_target_ref` = retype(draft event_id)); the canonical row that
    // replaces it re-derives `local_target_ref` from the ACCEPTED event id.
    // The draft handle is what the pending-create derivation and any child
    // optimistically created while the accept receipt was in flight still point
    // at, so keep it on the merged row as `local_temporary_target_ref` — the
    // alias source `event_derived_target_aliases` resolves those references
    // with.
    if incoming_object
        .get("local_temporary_target_ref")
        .is_none_or(Value::is_null)
        && let (Some(existing_ref), Some(incoming_ref)) = (
            existing_object
                .get("local_target_ref")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()),
            incoming_object
                .get("local_target_ref")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty()),
        )
        && existing_ref != incoming_ref
    {
        let existing_ref = existing_ref.to_owned();
        incoming_object.insert(
            "local_temporary_target_ref".to_owned(),
            Value::String(existing_ref),
        );
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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod durable_inbox_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use arkret_models_collaboration::sync_frames::account_subscribe::{
        NotificationDelta, NotificationDeltaAction,
    };
    use serde_json::json;

    use super::LocalStateStore;

    fn temp_path() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("inkson-realm-inbox-{nonce}.json"))
    }

    #[test]
    fn realm_cursor_and_delivery_survive_restart_until_ack() {
        let path = temp_path();
        let realm_id =
            arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap();
        let scope = garth::CursorScope::CommitStream {
            service_id: None,
            stream_ref: garth::CommitStreamRef::Realm { realm_id },
        };
        let event = garth::ClientEvent::Notification(NotificationDelta {
            id: arkret_sdk::NotificationIdentity::AgentApproval(
                arkret_sdk::NotificationId::new(
                    "ak:notification:01964137-0000-7000-8000-000000000012",
                )
                .unwrap(),
            ),
            action: NotificationDeltaAction::Remove,
            data: None,
        });

        let delivery_id = LocalStateStore::with_path(&path)
            .commit_client_delivery(
                scope.clone(),
                Some("ak:cursor:realm-committed".to_owned()),
                vec![event],
            )
            .unwrap()
            .unwrap();

        let mut restarted = LocalStateStore::with_path(&path);
        assert_eq!(
            restarted.load_client_cursor(&scope).unwrap().as_deref(),
            Some("ak:cursor:realm-committed")
        );
        let pending = restarted.pending_client_deliveries(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, delivery_id);
        restarted
            .retry_client_delivery(
                delivery_id,
                Some(42),
                garth::DeliveryErrorClass::Processing,
                "projection failed".to_owned(),
            )
            .unwrap();

        let mut after_retry = LocalStateStore::with_path(&path);
        let pending = after_retry.pending_client_deliveries(10).unwrap();
        assert_eq!(pending[0].attempts, 1);
        assert_eq!(pending[0].next_attempt_at_ms, Some(42));
        assert!(after_retry.ack_client_delivery(delivery_id).unwrap());
        assert!(
            LocalStateStore::with_path(&path)
                .pending_client_deliveries(10)
                .unwrap()
                .is_empty()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn canonical_event_backfill_replaces_accepted_optimistic_alias_row() {
        let path = temp_path();
        let realm_id = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";
        let operation_alias = "ak:operation:01904100-0000-7000-8000-000000000099";
        let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let temporary_target = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
        let canonical_target = "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut store = LocalStateStore::with_path(&path);

        assert!(store.upsert_raw_operation(
            operation_alias,
            Some(realm_id.to_owned()),
            json!({
                "kind": "ak.space.create",
                "operation_id": operation_alias,
                "locally_observed_schedule_winner": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "local_target_ref": temporary_target,
                "write_state": "queued",
                "body": { "object": { "kind": "list", "title": "Todo", "realm_id": realm_id } }
            }),
        ));
        assert!(store.update_raw_operation_write_state(
            operation_alias,
            "accepted",
            Some(event_id.to_owned()),
            None,
        ));

        assert!(store.upsert_raw_operation(
            event_id,
            Some(realm_id.to_owned()),
            json!({
                "kind": "ak.space.create",
                "operation_id": event_id,
                "local_target_ref": canonical_target,
                "write_state": "synced",
                "body": { "object": { "kind": "list", "title": "Todo", "realm_id": realm_id } }
            }),
        ));

        let rows = store.load().raw_operations;
        assert_eq!(rows.len(), 1, "backfill must replace the alias row");
        assert_eq!(rows[0].operation_id, operation_alias);
        assert_eq!(rows[0].payload["write_state"], json!("synced"));
        assert_eq!(rows[0].payload["event_id"], json!(event_id));
        assert_eq!(
            rows[0].payload["locally_observed_schedule_winner"],
            json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(rows[0].payload["local_target_ref"], json!(canonical_target));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn canonical_event_alias_reconciles_pre_fix_optimistic_row_without_receipt_id() {
        let path = temp_path();
        let realm_id = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";
        let operation_alias = "ak:operation:01904100-0000-7000-8000-000000000098";
        let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut store = LocalStateStore::with_path(&path);
        store.upsert_raw_operation(
            operation_alias,
            Some(realm_id.to_owned()),
            json!({
                "kind": "ak.space.create",
                "operation_id": operation_alias,
                "local_target_ref": "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR",
                "write_state": "queued",
                "body": { "object": { "kind": "list", "title": "Todo", "realm_id": realm_id } }
            }),
        );

        store.upsert_raw_operation(
            event_id,
            Some(realm_id.to_owned()),
            json!({
                "kind": "ak.space.create",
                "operation_id": event_id,
                "local_operation_idempotency_alias": operation_alias,
                "local_target_ref": "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
                "write_state": "synced",
                "body": { "object": { "kind": "list", "title": "Todo", "realm_id": realm_id } }
            }),
        );

        let rows = store.load().raw_operations;
        assert_eq!(
            rows.len(),
            1,
            "the signed Event's local alias heals old rows"
        );
        assert_eq!(rows[0].payload["write_state"], json!("synced"));
        let _ = std::fs::remove_file(path);
    }

    /// The canonical row replacing an optimistic create must keep the draft
    /// object handle: the pending-create derivation and children optimistically
    /// created while the accept receipt was in flight all still reference it,
    /// and `event_derived_target_aliases` can only resolve them if the merged
    /// row records draft -> accepted. (2026-08-19 board-title incident: the
    /// merge dropped the handle, the alias vanished, and the switcher showed
    /// the raw draft id with "No lists yet".)
    #[test]
    fn canonical_event_merge_preserves_draft_target_handle() {
        let path = temp_path();
        let realm_id = "ak:realm:AeEFmfOZxsx5kLi2kpOJu8m7TFXZ_G8E4019rUp4wmT6";
        let operation_alias = "ak:operation:01904100-0000-7000-8000-000000000097";
        let event_id = "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let temporary_target = "ak:space:AaDn_ypTG8vV4ToKfz6JtG2xnepF9QDlafPZCT-UYPyR";
        let canonical_target = "ak:space:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let mut store = LocalStateStore::with_path(&path);
        store.upsert_raw_operation(
            operation_alias,
            Some(realm_id.to_owned()),
            json!({
                "kind": "ak.space.create",
                "operation_id": operation_alias,
                "local_target_ref": temporary_target,
                "write_state": "queued",
                "body": { "object": { "kind": "board", "title": "Board", "realm_id": realm_id } }
            }),
        );

        store.upsert_raw_operation(
            event_id,
            Some(realm_id.to_owned()),
            json!({
                "kind": "ak.space.create",
                "operation_id": event_id,
                "local_operation_idempotency_alias": operation_alias,
                "local_target_ref": canonical_target,
                "write_state": "synced",
                "body": { "object": { "kind": "board", "title": "Board", "realm_id": realm_id } }
            }),
        );

        let rows = store.load().raw_operations;
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].payload["local_target_ref"],
            json!(canonical_target),
            "the merged row is keyed by the accepted object id"
        );
        assert_eq!(
            rows[0].payload["local_temporary_target_ref"],
            json!(temporary_target),
            "the draft handle survives the merge as the alias source"
        );
        let _ = std::fs::remove_file(path);
    }
}
