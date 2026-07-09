use super::*;
use crate::hlc::Hlc;

impl LocalStateStore {
    pub fn save_notification_projection(&mut self, notifications: Vec<Value>) {
        self.ensure_cached_loaded();
        self.cached.notification_projection = notifications;
        let _ = self.flush();
    }

    pub fn notification_projection(&self) -> Vec<Value> {
        self.load().notification_projection
    }

    pub fn set_notification_read(&mut self, notification_id: impl Into<String>, read: bool) {
        self.ensure_cached_loaded();
        let entry = self
            .cached
            .notification_client_state
            .entry(notification_id.into())
            .or_default();
        if entry.read == read {
            return; // no change — don't dirty the store
        }
        entry.read = read;
        let _ = self.flush();
    }

    pub fn set_notification_archived(
        &mut self,
        notification_id: impl Into<String>,
        archived: bool,
    ) {
        self.ensure_cached_loaded();
        self.cached
            .notification_client_state
            .entry(notification_id.into())
            .or_default()
            .archived = archived;
        let _ = self.flush();
    }

    pub fn notification_state_for(&self, notification_id: &str) -> NotificationClientState {
        self.load()
            .notification_client_state
            .get(notification_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn save_read_cursor(
        &mut self,
        actor: impl Into<String>,
        device_id: impl Into<String>,
        realm_id: impl Into<String>,
        topic_id: Option<String>,
        event_id: impl Into<String>,
    ) -> ReadMarkerRecord {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        let device_id = device_id.into();
        let event_id = event_id.into();
        let topic_id = topic_id.filter(|topic| !topic.trim().is_empty());
        let read_scope = read_scope_for_cursor(&realm_id, topic_id.as_deref());
        let position = ReadCursorPosition {
            event_id,
            hlc: Hlc::now(&device_id).to_string(),
        };
        let marker = ReadMarkerRecord {
            marker_type: "ck.read_cursor.advance".to_owned(),
            body: ReadMarkerBody {
                id: new_read_cursor_id(),
                schema: "ck.schema.read_cursor.v1".to_owned(),
                realm_id: realm_id.clone(),
                read_scope: read_scope.clone(),
                position,
            },
            actor: actor.into(),
            device_id,
            updated_at: Utc::now(),
        };
        self.cached
            .read_cursors
            .insert(read_cursor_key(&realm_id, &read_scope), marker.clone());
        let _ = self.flush();
        marker
    }

    pub fn read_cursor_for(
        &self,
        realm_id: &str,
        topic_id: Option<&str>,
    ) -> Option<ReadMarkerRecord> {
        self.load()
            .read_cursors
            .get(&read_cursor_key(
                realm_id,
                &read_scope_for_cursor(realm_id, topic_id),
            ))
            .cloned()
    }

    pub fn latest_read_cursor(&self, realm_id: &str) -> Option<ReadMarkerRecord> {
        self.load()
            .read_cursors
            .into_values()
            .filter(|marker| marker.body.realm_id == realm_id)
            .max_by(|left, right| left.updated_at.cmp(&right.updated_at))
    }

    pub(crate) fn ingest_read_cursor_update_message(&mut self, message: &Value) -> bool {
        if message
            .get("kind")
            .or_else(|| message.get("type"))
            .and_then(Value::as_str)
            != Some("ck.read_cursor.update")
        {
            return false;
        }
        let content = message.get("content").unwrap_or(message);
        let Some(actor_id) = content.get("actor_id").and_then(Value::as_str) else {
            return false;
        };
        let Some(device_id) = content.get("device_id").and_then(Value::as_str) else {
            return false;
        };
        let Some(realm_id) = content.get("realm_id").and_then(Value::as_str) else {
            return false;
        };
        let Some(read_scope_value) = content.get("read_scope") else {
            return false;
        };
        let Some(position_value) = content.get("position") else {
            return false;
        };
        let Ok(read_scope) = serde_json::from_value::<ReadScope>(read_scope_value.clone()) else {
            return false;
        };
        let Ok(position) = serde_json::from_value::<ReadCursorPosition>(position_value.clone())
        else {
            return false;
        };
        let updated_at = content
            .get("updated_at")
            .and_then(Value::as_str)
            .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let marker = ReadMarkerRecord {
            marker_type: "ck.read_cursor.advance".to_owned(),
            body: ReadMarkerBody {
                id: content
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(new_read_cursor_id),
                schema: "ck.schema.read_cursor.v1".to_owned(),
                realm_id: realm_id.to_owned(),
                read_scope: read_scope.clone(),
                position,
            },
            actor: actor_id.to_owned(),
            device_id: device_id.to_owned(),
            updated_at,
        };
        let key = read_cursor_key(realm_id, &read_scope);
        if self
            .cached
            .read_cursors
            .get(&key)
            .is_some_and(|existing| !incoming_read_marker_wins(existing, &marker))
        {
            return false;
        }
        self.cached.read_cursors.insert(key, marker);
        true
    }

    // ── Per-realm watch level (spec push-notifications.md §4.3.2) ──
    //
    // A realm with no stored entry resolves to the protocol default
    // `WatchLevel::MentionsOnly`; only non-default levels are persisted.
    // Binary "mute" is just the `Muted` end of this scale, so the
    // `*_muted` helpers below stay as thin wrappers for the notification
    // drawer / chat sidebar toggles.

    /// Set (or clear) the per-realm watch level. Storing the default
    /// (`MentionsOnly`) removes the override so the realm follows global
    /// defaults again.
    pub fn set_realm_watch_level(&mut self, realm_id: impl Into<String>, level: WatchLevel) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        if level == WatchLevel::default() {
            self.cached.realm_watch_levels.remove(&realm_id);
        } else {
            self.cached.realm_watch_levels.insert(realm_id, level);
        }
        let _ = self.flush();
    }

    /// Effective per-realm watch level (default `MentionsOnly` when unset).
    pub fn realm_watch_level(&self, realm_id: &str) -> WatchLevel {
        self.load()
            .realm_watch_levels
            .get(realm_id)
            .copied()
            .unwrap_or_default()
    }

    /// All non-default per-realm watch level overrides.
    pub fn realm_watch_levels(&self) -> BTreeMap<String, WatchLevel> {
        self.load().realm_watch_levels
    }

    pub fn set_realm_muted(&mut self, realm_id: impl Into<String>, muted: bool) {
        let level = if muted {
            WatchLevel::Muted
        } else {
            WatchLevel::default()
        };
        self.set_realm_watch_level(realm_id, level);
    }

    pub fn clear_muted_realms(&mut self) {
        self.ensure_cached_loaded();
        self.cached
            .realm_watch_levels
            .retain(|_, level| *level != WatchLevel::Muted);
        let _ = self.flush();
    }

    pub fn is_realm_muted(&self, realm_id: &str) -> bool {
        self.realm_watch_level(realm_id) == WatchLevel::Muted
    }

    pub fn muted_realms(&self) -> Vec<String> {
        self.load()
            .realm_watch_levels
            .into_iter()
            .filter_map(|(realm_id, level)| (level == WatchLevel::Muted).then_some(realm_id))
            .collect()
    }

    pub fn presence_visibility(&self) -> PresenceVisibility {
        self.load().presence_visibility
    }

    pub fn set_presence_visibility(&mut self, visibility: PresenceVisibility) {
        self.ensure_cached_loaded();
        self.cached.presence_visibility = visibility;
        let _ = self.flush();
    }

    pub fn presence_should_send(&self) -> bool {
        self.presence_visibility().allows_presence_send()
    }

    // ── Manual presence preference (profiles-presence.md §3.6) ─

    pub fn presence_preference(&self) -> PresencePreferenceState {
        self.load().presence_preference
    }

    pub fn set_presence_preference(&mut self, preference: PresencePreferenceState) {
        self.ensure_cached_loaded();
        self.cached.presence_preference = preference;
        let _ = self.flush();
    }

    // ── Read receipt preferences (spec client-preferences.md §3.6) ─

    pub fn read_receipt_default_send(&self) -> bool {
        self.load().read_receipt_default_send
    }

    pub fn set_read_receipt_default_send(&mut self, send: bool) {
        self.ensure_cached_loaded();
        self.cached.read_receipt_default_send = send;
        let _ = self.flush();
    }

    pub fn read_receipt_default_display(&self) -> bool {
        self.load().read_receipt_default_display
    }

    pub fn set_read_receipt_default_display(&mut self, display: bool) {
        self.ensure_cached_loaded();
        self.cached.read_receipt_default_display = display;
        let _ = self.flush();
    }

    pub fn read_receipt_realm_override(&self, realm_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_realm_overrides
            .get(realm_id)
            .copied()
    }

    pub fn set_read_receipt_realm_override(
        &mut self,
        realm_id: impl Into<String>,
        send: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        match send {
            Some(value) => {
                self.cached
                    .read_receipt_realm_overrides
                    .insert(realm_id, value);
            }
            None => {
                self.cached.read_receipt_realm_overrides.remove(&realm_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_realm_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_realm_overrides
    }

    pub fn read_receipt_realm_display_override(&self, realm_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_realm_display_overrides
            .get(realm_id)
            .copied()
    }

    pub fn set_read_receipt_realm_display_override(
        &mut self,
        realm_id: impl Into<String>,
        display: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        match display {
            Some(value) => {
                self.cached
                    .read_receipt_realm_display_overrides
                    .insert(realm_id, value);
            }
            None => {
                self.cached
                    .read_receipt_realm_display_overrides
                    .remove(&realm_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_realm_display_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_realm_display_overrides
    }

    pub fn read_receipt_strand_override(&self, strand_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_strand_overrides
            .get(strand_id)
            .copied()
    }

    pub fn set_read_receipt_strand_override(
        &mut self,
        strand_id: impl Into<String>,
        send: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let strand_id = strand_id.into();
        match send {
            Some(value) => {
                self.cached
                    .read_receipt_strand_overrides
                    .insert(strand_id, value);
            }
            None => {
                self.cached.read_receipt_strand_overrides.remove(&strand_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_strand_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_strand_overrides
    }

    pub fn read_receipt_strand_display_override(&self, strand_id: &str) -> Option<bool> {
        self.load()
            .read_receipt_strand_display_overrides
            .get(strand_id)
            .copied()
    }

    pub fn set_read_receipt_strand_display_override(
        &mut self,
        strand_id: impl Into<String>,
        display: Option<bool>,
    ) {
        self.ensure_cached_loaded();
        let strand_id = strand_id.into();
        match display {
            Some(value) => {
                self.cached
                    .read_receipt_strand_display_overrides
                    .insert(strand_id, value);
            }
            None => {
                self.cached
                    .read_receipt_strand_display_overrides
                    .remove(&strand_id);
            }
        }
        let _ = self.flush();
    }

    pub fn read_receipt_strand_display_overrides(&self) -> BTreeMap<String, bool> {
        self.load().read_receipt_strand_display_overrides
    }

    // ── Realm remarks (spec client-preferences.md §3.7) ─

    /// Get the server-declared read-receipt policy for a Realm (when known).
    /// `None` means the client hasn't synced a policy snapshot yet and the
    /// user's override is still authoritative.
    pub fn read_receipt_policy_for_realm(
        &self,
        realm_id: &str,
    ) -> Option<ReadReceiptPolicySnapshot> {
        self.load()
            .read_receipt_policy_snapshots
            .get(realm_id)
            .cloned()
    }

    /// Replace the server-declared policy snapshot for a Realm. Called from
    /// the sync path once the Seal view (P0 M3) surfaces
    /// `ck.component.realm.read_receipt_policy.v1` cell value; tests use
    /// this to seed lock-state UI behavior.
    pub fn set_read_receipt_policy_snapshot(
        &mut self,
        realm_id: impl Into<String>,
        snapshot: Option<ReadReceiptPolicySnapshot>,
    ) {
        self.ensure_cached_loaded();
        let realm_id = realm_id.into();
        match snapshot {
            Some(value) => {
                self.cached
                    .read_receipt_policy_snapshots
                    .insert(realm_id, value);
            }
            None => {
                self.cached.read_receipt_policy_snapshots.remove(&realm_id);
            }
        }
        let _ = self.flush();
    }

    /// All known server-declared read-receipt policy snapshots.
    pub fn read_receipt_policy_snapshots(&self) -> BTreeMap<String, ReadReceiptPolicySnapshot> {
        self.load().read_receipt_policy_snapshots
    }

    /// Resolve effective send preference per spec (server policy → strand →
    /// realm → default). Mirror of
    /// `arkret_sdk::ReadReceiptPreferences::effective_send` extended with
    /// server-declared policy lock: when the Realm publishes a
    /// `ck.realm.read_receipt_policy` with `disclosure="required"` the
    /// answer is forced `true`; with `disclosure="disabled"` it's forced
    /// `false`. User-level overrides are ignored in those cases (matching
    /// the lock UI in settings).
    pub fn read_receipt_should_send(
        &self,
        strand_id: Option<&str>,
        realm_id: Option<&str>,
    ) -> bool {
        let snapshot = self.load();
        if let Some(rid) = realm_id
            && let Some(policy) = snapshot.read_receipt_policy_snapshots.get(rid)
        {
            match policy.disclosure.as_str() {
                "required" => return true,
                "disabled" => return false,
                _ => {}
            }
        }
        if let Some(fid) = strand_id
            && let Some(value) = snapshot.read_receipt_strand_overrides.get(fid)
        {
            return *value;
        }
        if let Some(rid) = realm_id
            && let Some(value) = snapshot.read_receipt_realm_overrides.get(rid)
        {
            return *value;
        }
        snapshot.read_receipt_default_send
    }

    pub fn read_receipt_should_display(
        &self,
        strand_id: Option<&str>,
        realm_id: Option<&str>,
    ) -> bool {
        let snapshot = self.load();
        if let Some(fid) = strand_id
            && let Some(value) = snapshot.read_receipt_strand_display_overrides.get(fid)
        {
            return *value;
        }
        if let Some(rid) = realm_id
            && let Some(value) = snapshot.read_receipt_realm_display_overrides.get(rid)
        {
            return *value;
        }
        snapshot.read_receipt_default_display
    }

    pub fn set_notification_kind_enabled(&mut self, kind: impl Into<String>, enabled: bool) {
        self.ensure_cached_loaded();
        self.cached
            .muted_notification_kinds
            .insert(kind.into(), enabled);
        let _ = self.flush();
    }

    pub fn notification_kind_enabled(&self, kind: &str) -> bool {
        self.load()
            .muted_notification_kinds
            .get(kind)
            .copied()
            .unwrap_or(true)
    }

    pub fn notification_kind_preferences(&self) -> BTreeMap<String, bool> {
        self.load().muted_notification_kinds
    }

    pub fn notification_dnd_settings(&self) -> Option<crate::notification_rules::DndSettings> {
        self.load().notification_dnd_settings
    }

    pub fn set_notification_dnd_settings(
        &mut self,
        settings: Option<crate::notification_rules::DndSettings>,
    ) {
        self.ensure_cached_loaded();
        self.cached.notification_dnd_settings = settings;
        let _ = self.flush();
    }
}

fn incoming_read_marker_wins(existing: &ReadMarkerRecord, incoming: &ReadMarkerRecord) -> bool {
    existing.body.position.hlc < incoming.body.position.hlc
        || existing.body.position.hlc == incoming.body.position.hlc
            && existing.device_id <= incoming.device_id
}
