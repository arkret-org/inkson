use std::collections::BTreeMap;
#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use contrix_sdk::EncryptedPayload;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(target_arch = "wasm32")]
const LOCAL_STATE_STORAGE_KEY: &str = "chask.local_state.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawOperationRecord {
    pub operation_id: String,
    pub space_id: Option<String>,
    pub received_at: DateTime<Utc>,
    pub payload: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationClientState {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub archived: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientLocalState {
    pub sync_cursor: Option<String>,
    pub raw_operations: Vec<RawOperationRecord>,
    pub space_projections: BTreeMap<String, Value>,
    pub drafts: BTreeMap<String, String>,
    pub pending_encrypted_messages: BTreeMap<String, EncryptedPayload>,
    #[serde(default)]
    pub notification_projection: Vec<Value>,
    #[serde(default)]
    pub notification_client_state: BTreeMap<String, NotificationClientState>,
    #[serde(default)]
    pub muted_spaces: BTreeMap<String, bool>,
    #[serde(default)]
    pub muted_notification_kinds: BTreeMap<String, bool>,
    /// Encrypted private account data (preferences, tags, custom emojis).
    /// Values are XOR-encrypted with account_key and hex-encoded.
    #[serde(default)]
    pub private_data: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct LocalStateStore {
    cached: ClientLocalState,
    #[cfg(not(target_arch = "wasm32"))]
    path: PathBuf,
}

impl Default for LocalStateStore {
    fn default() -> Self {
        Self {
            cached: ClientLocalState::default(),
            #[cfg(not(target_arch = "wasm32"))]
            path: default_state_path(),
        }
    }
}

impl LocalStateStore {
    pub fn load(&self) -> ClientLocalState {
        if self.cached != ClientLocalState::default() {
            return self.cached.clone();
        }
        self.read_persisted_state().unwrap_or_default()
    }

    pub fn save(&mut self, state: ClientLocalState) {
        self.cached = state;
        let _ = self.flush();
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        self.write_persisted_state(&self.cached)
    }

    pub fn save_sync_cursor(&mut self, cursor: impl Into<String>) {
        self.ensure_cached_loaded();
        self.cached.sync_cursor = Some(cursor.into());
        let _ = self.flush();
    }

    pub fn append_raw_operation(
        &mut self,
        operation_id: impl Into<String>,
        space_id: Option<String>,
        payload: Value,
    ) {
        self.ensure_cached_loaded();
        self.cached.raw_operations.push(RawOperationRecord {
            operation_id: operation_id.into(),
            space_id,
            received_at: Utc::now(),
            payload,
        });
        let _ = self.flush();
    }

    pub fn save_space_projection(&mut self, space_id: impl Into<String>, projection: Value) {
        self.ensure_cached_loaded();
        self.cached
            .space_projections
            .insert(space_id.into(), projection);
        let _ = self.flush();
    }

    pub fn save_draft(&mut self, space_id: impl Into<String>, draft: impl Into<String>) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        let draft = draft.into();
        if draft.trim().is_empty() {
            self.cached.drafts.remove(&space_id);
        } else {
            self.cached.drafts.insert(space_id, draft);
        }
        let _ = self.flush();
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
        self.ensure_cached_loaded();
        self.cached
            .pending_encrypted_messages
            .insert(message_id.into(), payload);
        let _ = self.flush();
    }

    pub fn pending_encrypted_count(&self) -> usize {
        self.cached.pending_encrypted_messages.len()
    }

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
        self.cached
            .notification_client_state
            .entry(notification_id.into())
            .or_default()
            .read = read;
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

    pub fn set_space_muted(&mut self, space_id: impl Into<String>, muted: bool) {
        self.ensure_cached_loaded();
        let space_id = space_id.into();
        if muted {
            self.cached.muted_spaces.insert(space_id, true);
        } else {
            self.cached.muted_spaces.remove(&space_id);
        }
        let _ = self.flush();
    }

    pub fn clear_muted_spaces(&mut self) {
        self.ensure_cached_loaded();
        self.cached.muted_spaces.clear();
        let _ = self.flush();
    }

    pub fn is_space_muted(&self, space_id: &str) -> bool {
        self.load()
            .muted_spaces
            .get(space_id)
            .copied()
            .unwrap_or(false)
    }

    pub fn muted_spaces(&self) -> Vec<String> {
        self.load()
            .muted_spaces
            .into_iter()
            .filter_map(|(space_id, muted)| muted.then_some(space_id))
            .collect()
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

    /// Save a private preference encrypted with the account key.
    /// The account_key is typically the account DID or a derived secret.
    pub fn save_private_data(
        &mut self,
        account_key: &str,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.ensure_cached_loaded();
        let plaintext = value.into();
        let encrypted = xor_encrypt(account_key, &plaintext);
        self.cached.private_data.insert(key.into(), encrypted);
        let _ = self.flush();
    }

    /// Load and decrypt a private preference.
    pub fn load_private_data(&self, account_key: &str, key: &str) -> Option<String> {
        let encrypted = self.load().private_data.get(key)?.clone();
        xor_decrypt(account_key, &encrypted)
    }

    /// Remove a private preference.
    pub fn remove_private_data(&mut self, key: &str) {
        self.ensure_cached_loaded();
        self.cached.private_data.remove(key);
        let _ = self.flush();
    }

    /// List all private data keys.
    pub fn private_data_keys(&self) -> Vec<String> {
        self.load().private_data.keys().cloned().collect()
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cached: ClientLocalState::default(),
            path: path.into(),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        let bytes = fs::read(&self.path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    #[cfg(target_arch = "wasm32")]
    fn read_persisted_state(&self) -> Option<ClientLocalState> {
        browser_storage()
            .and_then(|storage| storage.get_item(LOCAL_STATE_STORAGE_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(state)?)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_persisted_state(&self, state: &ClientLocalState) -> anyhow::Result<()> {
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(LOCAL_STATE_STORAGE_KEY, &serde_json::to_string(state)?)
            .map_err(|error| anyhow::anyhow!("localStorage write failed: {error:?}"))?;
        Ok(())
    }

    fn ensure_cached_loaded(&mut self) {
        if self.cached == ClientLocalState::default() {
            if let Some(state) = self.read_persisted_state() {
                self.cached = state;
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

#[cfg(not(target_arch = "wasm32"))]
fn default_state_path() -> PathBuf {
    std::env::var_os("CLIENTX_STATE_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_dir().join("state.json"))
}

#[cfg(not(target_arch = "wasm32"))]
fn app_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config").into()))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("chask")
}

/// XOR-based symmetric encryption for client-side private data.
/// This is a simple obfuscation, not production-grade crypto.
/// The same function encrypts and decrypts since XOR is its own inverse.
fn xor_encrypt(key: &str, data: &str) -> String {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return data.to_owned();
    }
    let encrypted: Vec<u8> = data
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    // Encode as hex for safe storage
    encrypted.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode hex-encoded XOR-encrypted data back to plaintext.
fn xor_decrypt(key: &str, hex_data: &str) -> Option<String> {
    let key_bytes = key.as_bytes();
    if key_bytes.is_empty() {
        return Some(hex_data.to_owned());
    }
    let bytes = hex_to_bytes(hex_data)?;
    let decrypted: Vec<u8> = bytes
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key_bytes[i % key_bytes.len()])
        .collect();
    String::from_utf8(decrypted).ok()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn local_state_store_tracks_cursor_operations_projections_and_drafts() {
        let path = temp_state_path("tracks");
        let mut store = LocalStateStore::with_path(path);
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

    #[test]
    fn local_state_store_persists_to_disk_between_instances() {
        let path = temp_state_path("persisted");
        let mut writer = LocalStateStore::with_path(path.clone());
        writer.save_sync_cursor("sx:persisted");
        writer.save_draft("cx:space:persisted", "draft survives restart");

        let reader = LocalStateStore::with_path(path);
        let state = reader.load();
        assert_eq!(state.sync_cursor.as_deref(), Some("sx:persisted"));
        assert_eq!(state.drafts["cx:space:persisted"], "draft survives restart");
    }

    #[test]
    fn local_state_store_persists_notifications_and_mute_preferences() {
        let path = temp_state_path("notifications");
        let mut store = LocalStateStore::with_path(path.clone());
        store.save_notification_projection(vec![serde_json::json!({
            "notification_id": "notif-1",
            "space_id": "cx:space:demo",
            "kind": "message",
            "body": "Hello"
        })]);
        store.set_notification_read("notif-1", true);
        store.set_notification_archived("notif-1", true);
        store.set_space_muted("cx:space:demo", true);
        store.set_notification_kind_enabled("message", false);

        let reader = LocalStateStore::with_path(path);
        assert_eq!(reader.notification_projection().len(), 1);
        assert!(reader.notification_state_for("notif-1").read);
        assert!(reader.notification_state_for("notif-1").archived);
        assert!(reader.is_space_muted("cx:space:demo"));
        assert!(!reader.notification_kind_enabled("message"));
    }

    fn temp_state_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("chask-state-{name}-{stamp}.json"))
    }

    #[test]
    fn xor_encrypt_decrypt_roundtrip() {
        let key = "did:web:alice.example";
        let plaintext = "my secret preference";
        let encrypted = xor_encrypt(key, plaintext);
        assert_ne!(encrypted, plaintext);
        let decrypted = xor_decrypt(key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn xor_encrypt_empty_key_returns_original() {
        assert_eq!(xor_encrypt("", "hello"), "hello");
    }

    #[test]
    fn private_data_store_encrypts_and_persists() {
        let path = temp_state_path("private");
        let mut store = LocalStateStore::with_path(path.clone());
        let account_key = "did:web:alice.example";
        store.save_private_data(account_key, "theme", "dark");
        store.save_private_data(account_key, "custom_emoji", "party_parrot");

        assert_eq!(
            store.load_private_data(account_key, "theme"),
            Some("dark".to_owned())
        );
        assert_eq!(
            store.load_private_data(account_key, "custom_emoji"),
            Some("party_parrot".to_owned())
        );
        assert!(store.load_private_data(account_key, "missing").is_none());
        assert_eq!(store.private_data_keys().len(), 2);

        // Verify data is encrypted on disk
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("dark"));
        assert!(!raw.contains("party_parrot"));

        // Verify wrong key cannot decrypt
        assert_ne!(
            store.load_private_data("wrong-key", "theme"),
            Some("dark".to_owned())
        );
    }

    #[test]
    fn private_data_remove_works() {
        let path = temp_state_path("private-remove");
        let mut store = LocalStateStore::with_path(path);
        store.save_private_data("key", "temp", "value");
        assert!(store.load_private_data("key", "temp").is_some());
        store.remove_private_data("temp");
        assert!(store.load_private_data("key", "temp").is_none());
    }
}
