#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use cokret_sdk::DeviceId;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::operation::uuid_v7;

const DEFAULT_SERVER_URL: &str = "https://local.host";
const DEFAULT_PRINCIPAL_SERVERS: &[&str] = &[DEFAULT_SERVER_URL];
const LOCAL_PROXY_SERVER_URL: &str = "https://local.host";
const LOCAL_PROXY_SERVER_PORT: u16 = 8787;
const DEFAULT_ACCOUNT_DID: &str = "";
const DEVICE_ID_PREFIX: &str = "ak:device:";
#[cfg(target_arch = "wasm32")]
const CONFIG_STORAGE_KEY: &str = "inkson.config.v1";
/// P3B.4: localStorage key for the multi-profile config holding the
/// `MultiProfileConfig`.
#[cfg(target_arch = "wasm32")]
const PROFILES_STORAGE_KEY: &str = "inkson.profiles.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_url: String,
    #[serde(default = "default_principal_servers")]
    pub principal_servers: Vec<String>,
    pub account_did: String,
    pub device_id: String,
    pub session_credential: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            principal_servers: default_principal_servers(),
            account_did: DEFAULT_ACCOUNT_DID.to_owned(),
            device_id: new_device_id(),
            session_credential: String::new(),
        }
    }
}

impl ClientConfig {
    pub fn from_fields(
        server_url: impl Into<String>,
        account_did: impl Into<String>,
        device_id: impl Into<String>,
        session_credential: impl Into<String>,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            principal_servers: default_principal_servers(),
            account_did: account_did.into(),
            device_id: device_id.into(),
            session_credential: session_credential.into(),
        }
        .normalized()
    }

    fn normalized(mut self) -> Self {
        self.server_url = normalize_server_url(&self.server_url);
        self.principal_servers = normalize_principal_server_presets(&self.principal_servers);
        let current = self.device_id.trim().to_owned();
        if is_valid_device_id(&current) {
            self.device_id = current;
            return self;
        }

        self.device_id = new_device_id();
        self.session_credential.clear();
        self
    }
}

fn default_principal_servers() -> Vec<String> {
    DEFAULT_PRINCIPAL_SERVERS
        .iter()
        .map(|server| normalize_server_url(server))
        .collect()
}

pub fn server_url_key(server_url: &str) -> String {
    normalize_server_url(server_url)
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

pub fn same_server_url(left: &str, right: &str) -> bool {
    server_url_key(left) == server_url_key(right)
}

fn push_unique_principal_server(options: &mut Vec<String>, server_url: &str) {
    let normalized = normalize_server_url(server_url);
    if normalized.trim().is_empty()
        || options
            .iter()
            .any(|existing| same_server_url(existing, &normalized))
    {
        return;
    }
    options.push(normalized);
}

pub fn normalize_principal_server_presets(principal_servers: &[String]) -> Vec<String> {
    let mut options = Vec::<String>::new();
    for server_url in principal_servers {
        push_unique_principal_server(&mut options, server_url);
    }
    if options.is_empty() {
        for server_url in DEFAULT_PRINCIPAL_SERVERS {
            push_unique_principal_server(&mut options, server_url);
        }
    }
    options
}

pub fn principal_server_options_for(
    current_server_url: &str,
    configured_principal_servers: &[String],
) -> Vec<String> {
    let mut options = Vec::<String>::new();
    push_unique_principal_server(&mut options, current_server_url);
    for server_url in configured_principal_servers {
        push_unique_principal_server(&mut options, server_url);
    }
    for server_url in DEFAULT_PRINCIPAL_SERVERS {
        push_unique_principal_server(&mut options, server_url);
    }
    options
}

/// CKP-0007 P3B.4 — multi-account profile primitive. A profile is the
/// (server_url, account_did, device_id, session_credential) tuple that the
/// existing single-profile `ClientConfig` already carries, plus a
/// stable `profile_id` so the switcher UI can address profiles by a
/// non-secret handle (account_did + device_id could rotate; profile_id
/// stays put for the life of the profile).
///
/// The single-profile `ClientConfig` continues to exist as the *active*
/// view onto the multi-profile store — every call site that reads
/// `LocalConfigStore::load()` keeps working unchanged. The switcher UI
/// (P3B.4.2) calls into the multi-profile API to enumerate / switch /
/// add profiles.
///
/// Profile switching is fully event-driven now. Callers (sync engine,
/// push registration, offline drain) react to
/// [`ProfileSwitchEvent`] instead of peeking at `ClientConfig`
/// directly. The shell publishes the active
/// [`MultiProfileConfig`] through a `Signal` so subsystems can pick
/// up the rotation atomically without the previous per-subsystem
/// peek pattern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProfile {
    /// Stable, opaque id (UUIDv7 prefixed `ck:profile:`). NOT derived
    /// from the account_did — DIDs can rotate via inception-upgrade,
    /// but the profile id should stay put so the switcher UI doesn't
    /// lose its row.
    pub profile_id: String,
    /// Optional human label (e.g. "Work", "Personal"). Falls back to
    /// the account DID's last segment when empty.
    #[serde(default)]
    pub label: String,
    /// Same four fields as `ClientConfig`.
    pub server_url: String,
    pub account_did: String,
    pub device_id: String,
    pub session_credential: String,
}

impl AccountProfile {
    pub fn new(
        server_url: impl Into<String>,
        account_did: impl Into<String>,
        device_id: impl Into<String>,
        session_credential: impl Into<String>,
    ) -> Self {
        Self {
            profile_id: format!("ak:profile:{}", uuid_v7()),
            label: String::new(),
            server_url: server_url.into(),
            account_did: account_did.into(),
            device_id: device_id.into(),
            session_credential: session_credential.into(),
        }
    }

    /// Human label used by the avatar dropdown switcher. Falls back
    /// to the DID's last `:` segment when no label is set.
    pub fn display_label(&self) -> &str {
        if !self.label.is_empty() {
            return self.label.as_str();
        }
        self.account_did
            .rsplit(':')
            .next()
            .unwrap_or(self.account_did.as_str())
    }
}

/// Multi-profile config. Persisted under `PROFILES_STORAGE_KEY` on
/// wasm and `app_data_dir()/profiles.json` on native.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultiProfileConfig {
    /// `profile_id` of the profile currently driving the UI.
    /// `None` means "no profile yet — show onboarding".
    #[serde(default)]
    pub active_profile_id: Option<String>,
    /// All known profiles. Length 0 = first launch.
    #[serde(default)]
    pub profiles: Vec<AccountProfile>,
}

impl MultiProfileConfig {
    pub fn active(&self) -> Option<&AccountProfile> {
        let id = self.active_profile_id.as_deref()?;
        self.profiles.iter().find(|p| p.profile_id == id)
    }

    pub fn active_mut(&mut self) -> Option<&mut AccountProfile> {
        let id = self.active_profile_id.clone()?;
        self.profiles.iter_mut().find(|p| p.profile_id == id)
    }

    /// Add or replace a profile (matched by `account_did + server_url`)
    /// and mark it active. Returns the active profile id.
    pub fn upsert_and_activate(&mut self, profile: AccountProfile) -> String {
        let key = (profile.account_did.clone(), profile.server_url.clone());
        if let Some(existing) = self
            .profiles
            .iter_mut()
            .find(|p| (p.account_did.clone(), p.server_url.clone()) == key)
        {
            existing.device_id = profile.device_id;
            existing.session_credential = profile.session_credential;
            if !profile.label.is_empty() {
                existing.label = profile.label;
            }
            let id = existing.profile_id.clone();
            self.active_profile_id = Some(id.clone());
            return id;
        }
        let id = profile.profile_id.clone();
        self.profiles.push(profile);
        self.active_profile_id = Some(id.clone());
        id
    }

    /// Switch the active profile. Returns `false` if the requested
    /// profile_id is not in the store.
    pub fn activate(&mut self, profile_id: &str) -> bool {
        if self.profiles.iter().any(|p| p.profile_id == profile_id) {
            self.active_profile_id = Some(profile_id.to_owned());
            true
        } else {
            false
        }
    }

    /// Remove a profile by id. If it was the active one, the active
    /// pointer is reset to the first remaining profile (or `None` if
    /// the list is now empty).
    pub fn remove(&mut self, profile_id: &str) {
        self.profiles.retain(|p| p.profile_id != profile_id);
        if self.active_profile_id.as_deref() == Some(profile_id) {
            self.active_profile_id = self.profiles.first().map(|p| p.profile_id.clone());
        }
    }

    /// Build a single-profile `ClientConfig` view of the active
    /// profile. Returns `None` when no profile is active (e.g. fresh
    /// install).
    pub fn active_as_client_config(&self) -> Option<ClientConfig> {
        let active = self.active()?;
        Some(ClientConfig::from_fields(
            active.server_url.as_str(),
            active.account_did.as_str(),
            active.device_id.as_str(),
            active.session_credential.as_str(),
        ))
    }

    /// Build the typed [`ProfileSwitchEvent`] payload that callers
    /// (account switcher, login strand, server change) emit when the
    /// active profile rotates. Returns `None` if the requested
    /// profile is not in the store.
    pub fn build_switch_event(&self, target_profile_id: &str) -> Option<ProfileSwitchEvent> {
        let prior = self.active_profile_id.clone();
        let target = self
            .profiles
            .iter()
            .find(|p| p.profile_id == target_profile_id)?
            .clone();
        Some(ProfileSwitchEvent {
            prior_profile_id: prior,
            next_profile: target,
        })
    }
}

/// Typed payload published when the active profile rotates.
///
/// CKP-0007 P3B.4.3 — the sync engine, push registration, offline
/// drain worker, and chat subscription paths each subscribe to this
/// event so they can rotate per-profile cursors / session credentials /
/// gateway registrations atomically. The previous "each subsystem
/// peeks at `ClientConfig`" pattern raced when two of them refreshed
/// out of order across a single user click.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileSwitchEvent {
    /// `profile_id` that was active before the switch. `None` on the
    /// first activation after a fresh install.
    pub prior_profile_id: Option<String>,
    /// Profile the shell is switching into. Carries the resolved
    /// `(server_url, account_did, device_id, session_credential)` tuple so
    /// reactors don't need a follow-up store read.
    pub next_profile: AccountProfile,
}

impl ProfileSwitchEvent {
    /// `true` when the prior profile id matches the next profile id —
    /// i.e. the switcher refreshed the active profile in place (token
    /// rotation) without actually swapping accounts.
    pub fn is_in_place_refresh(&self) -> bool {
        self.prior_profile_id.as_deref() == Some(self.next_profile.profile_id.as_str())
    }
}

/// SecureKeyStore key for the current session credential of `account_did`.
/// The namespace is per-DID — two profiles for the same DID on different
/// servers share one slot, matching the existing single-active-profile model.
fn session_credential_secret_key(account_did: &str) -> String {
    format!("coauth.session_credential.{account_did}")
}

/// Process-wide secure store handle used to keep `session_credential` out
/// of the plaintext `config.json` / `profiles.json` / localStorage
/// blobs. Unit tests run against a process-local in-memory store so
/// they stay hermetic (no OS keyring access) — same precedent as
/// `account_auth::grant_dpop::ensure_device_key`.
fn config_secure_store() -> std::sync::Arc<dyn crate::secure_key_store::SecureKeyStore> {
    #[cfg(not(test))]
    {
        crate::secure_key_store::default_secure_key_store("inkson")
    }
    #[cfg(test)]
    {
        use std::sync::{Arc, OnceLock};
        static TEST_STORE: OnceLock<Arc<dyn crate::secure_key_store::SecureKeyStore>> =
            OnceLock::new();
        TEST_STORE
            .get_or_init(|| Arc::new(crate::secure_key_store::MemorySecureKeyStore::new()))
            .clone()
    }
}

/// In-process read-through cache so the hot `LocalConfigStore::load()`
/// path doesn't hit the OS keyring / localStorage AEAD unwrap on every
/// call. `None` values negative-cache "no credential stored" for the DID.
fn session_credential_cache()
-> &'static std::sync::Mutex<std::collections::HashMap<String, Option<String>>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Option<String>>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Move `session_credential` into the SecureKeyStore. Returns `true` when
/// the on-disk copy must be redacted. If the secure store rejects the
/// write, persistence still proceeds without the plaintext credential.
fn persist_session_credential_secret(account_did: &str, session_credential: &str) -> bool {
    if account_did.is_empty() {
        // No namespace to key the secret under; only an empty token is
        // "safe" to drop from the persisted blob.
        return session_credential.is_empty();
    }
    let store = config_secure_store();
    let key = session_credential_secret_key(account_did);
    if session_credential.is_empty() {
        // Empty config writes also happen during first-paint restore and
        // profile/bootstrap churn. Do not treat them as logout; explicit
        // session invalidation calls `clear_session_credential_secret`.
        return true;
    }
    match store.store_secret(&key, session_credential) {
        Ok(()) => {
            if let Ok(mut cache) = session_credential_cache().lock() {
                cache.insert(account_did.to_owned(), Some(session_credential.to_owned()));
            }
            true
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "secure_key_store session_credential write failed; config persisted without credential",
            );
            true
        }
    }
}

pub(crate) fn clear_session_credential_secret(account_did: &str) {
    if account_did.is_empty() {
        return;
    }
    let store = config_secure_store();
    let _ = store.delete_secret(&session_credential_secret_key(account_did));
    if let Ok(mut cache) = session_credential_cache().lock() {
        cache.insert(account_did.to_owned(), None);
    }
}

/// Companion read: the session credential for `account_did`, from the
/// in-process cache first, then the SecureKeyStore.
fn restore_session_credential_secret_from_store(
    account_did: &str,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<String> {
    if account_did.is_empty() {
        return None;
    }
    if let Ok(cache) = session_credential_cache().lock()
        && let Some(entry) = cache.get(account_did)
    {
        return entry.clone();
    }
    let result = match store.get_secret(&session_credential_secret_key(account_did)) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                ?error,
                "secure_key_store session_credential read failed; config loaded without credential",
            );
            // Don't negative-cache a transient backend error.
            return None;
        }
    };
    if let Ok(mut cache) = session_credential_cache().lock() {
        cache.insert(account_did.to_owned(), result.clone());
    }
    result
}

fn restore_session_credential_secret(account_did: &str) -> Option<String> {
    let store = config_secure_store();
    restore_session_credential_secret_from_store(account_did, store.as_ref())
}

/// Build the copy of `config` that is allowed to touch the plaintext
/// persistence layer: the `session_credential` is moved into the
/// SecureKeyStore and blanked.
fn redact_config_for_disk(config: &ClientConfig) -> ClientConfig {
    let mut redacted = config.clone();
    if persist_session_credential_secret(&redacted.account_did, &redacted.session_credential) {
        redacted.session_credential = String::new();
    }
    redacted
}

/// Profile-store analogue of [`redact_config_for_disk`].
fn redact_profiles_for_disk(profiles: &MultiProfileConfig) -> MultiProfileConfig {
    let mut redacted = profiles.clone();
    for profile in &mut redacted.profiles {
        if persist_session_credential_secret(&profile.account_did, &profile.session_credential) {
            profile.session_credential = String::new();
        }
    }
    redacted
}

pub fn new_device_id() -> String {
    format!("{DEVICE_ID_PREFIX}{}", uuid_v7())
}

pub fn normalize_device_id(device_id: &str) -> String {
    let trimmed = device_id.trim();
    if is_valid_device_id(trimmed) {
        trimmed.to_owned()
    } else {
        new_device_id()
    }
}

pub fn normalize_server_url(server_url: &str) -> String {
    let trimmed = server_url.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let Ok(url) = Url::parse(trimmed) else {
        return trimmed.to_owned();
    };
    let Some(host) = url.host_str() else {
        return trimmed.to_owned();
    };
    let path = url.path().trim_end_matches('/');
    let is_root_path = path.is_empty();
    let has_no_suffix = url.query().is_none() && url.fragment().is_none();

    if has_no_suffix
        && is_root_path
        && url.scheme() == "http"
        && url.port_or_known_default() == Some(LOCAL_PROXY_SERVER_PORT)
        && matches!(host, "127.0.0.1" | "localhost" | "::1")
    {
        return LOCAL_PROXY_SERVER_URL.to_owned();
    }

    if has_no_suffix && is_root_path && url.scheme() == "https" && host == "local.host" {
        return LOCAL_PROXY_SERVER_URL.to_owned();
    }

    trimmed.to_owned()
}

pub fn is_valid_device_id(device_id: &str) -> bool {
    DeviceId::new(device_id.to_owned()).is_ok()
}

pub fn validate_server_url(server_url: &str) -> anyhow::Result<Url> {
    let url = Url::parse(server_url)?;
    let scheme = url.scheme();
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("server URL must include a host"))?;

    if scheme == "https" || is_loopback_host(host) {
        return Ok(url);
    }

    Err(anyhow::anyhow!(
        "HTTPS is required for non-local servers; use https:// or a loopback host"
    ))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

#[derive(Clone, Debug)]
pub struct LocalConfigStore {
    cached: Option<ClientConfig>,
    /// Same persist-health latch pattern as `LocalStateStore::persist_health`:
    /// fire-and-forget `save()` drops the flush `Result`, so a failed write
    /// (localStorage quota, file IO error) latches here for the UI to read via
    /// [`Self::persist_error`]. Shared across clones.
    persist_health: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    #[cfg(not(target_arch = "wasm32"))]
    path: PathBuf,
}

impl Default for LocalConfigStore {
    fn default() -> Self {
        Self {
            cached: None,
            persist_health: std::sync::Arc::new(std::sync::Mutex::new(None)),
            #[cfg(not(target_arch = "wasm32"))]
            path: default_config_path(),
        }
    }
}

impl LocalConfigStore {
    pub fn load(&self) -> ClientConfig {
        self.cached
            .clone()
            .or_else(|| {
                self.read_persisted_config()
                    .map(|config| self.rehydrate_config(config))
            })
            .unwrap_or_default()
            .normalized()
    }

    /// Load the active config while forcing session credential rehydration
    /// through an already-initialised secure-store backend. On wasm this lets
    /// the boot path use IndexedDB after async upgrade, without relaxing the
    /// synchronous localStorage fallback that rejects credential keys.
    pub fn load_with_secure_store(
        &self,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> ClientConfig {
        self.cached
            .clone()
            .or_else(|| {
                self.read_persisted_config()
                    .map(|config| self.rehydrate_config_with_secure_store(config, secure_store))
            })
            .unwrap_or_default()
            .normalized()
    }

    /// Reattach the session credential to a config freshly read from the
    /// plaintext persistence layer (default secure store).
    fn rehydrate_config(&self, config: ClientConfig) -> ClientConfig {
        let store = config_secure_store();
        self.reattach_session_credential(config, store.as_ref())
    }

    fn rehydrate_config_with_secure_store(
        &self,
        config: ClientConfig,
        secure_store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> ClientConfig {
        self.reattach_session_credential(config, secure_store)
    }

    /// Reattach the session credential to `config` through `store`: prefer the value
    /// already in the SecureKeyStore; otherwise, if the credential exists only in
    /// the plaintext config blob (legacy persistence, or a test/old-browser
    /// injection), migrate it into `store` and use it. The store write is
    /// best-effort — when the wasm IndexedDB-only hardening is enforced it is
    /// refused and the token is still used in-memory for this load. Production
    /// blobs never carry a credential (redacted on save), so the migration branch is
    /// inert there.
    fn reattach_session_credential(
        &self,
        mut config: ClientConfig,
        store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> ClientConfig {
        if config.account_did.is_empty() {
            return config;
        }
        let blob_token = std::mem::take(&mut config.session_credential);
        if let Some(token) =
            restore_session_credential_secret_from_store(&config.account_did, store)
        {
            config.session_credential = token;
        } else if !blob_token.trim().is_empty() {
            let _ = store.store_secret(
                &session_credential_secret_key(&config.account_did),
                &blob_token,
            );
            if let Ok(mut cache) = session_credential_cache().lock() {
                cache.insert(config.account_did.clone(), Some(blob_token.clone()));
            }
            config.session_credential = blob_token;
        }
        config
    }

    pub fn save(&mut self, config: ClientConfig) {
        let mut config = config.normalized();
        self.preserve_principal_servers_for_runtime_save(&mut config);
        self.cached = Some(config);
        // Fire-and-forget by design; a failed flush is latched (and logged)
        // by `flush` itself so the UI can still surface it.
        let _ = self.flush();
    }

    fn preserve_principal_servers_for_runtime_save(&self, config: &mut ClientConfig) {
        if normalize_principal_server_presets(&config.principal_servers)
            != default_principal_servers()
        {
            return;
        }

        let existing = self
            .cached
            .as_ref()
            .map(|cached| cached.principal_servers.clone())
            .or_else(|| {
                self.read_persisted_config()
                    .map(|persisted| persisted.principal_servers)
            })
            .map(|servers| normalize_principal_server_presets(&servers))
            .unwrap_or_else(default_principal_servers);

        if existing != default_principal_servers() {
            config.principal_servers = existing;
        }
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        let result = match &self.cached {
            Some(config) => self.write_persisted_config(config),
            None => Ok(()),
        };
        self.record_persist_result(&result);
        result
    }

    /// Latch the outcome of a persist attempt (same pattern as
    /// `LocalStateStore::record_persist_result`) so fire-and-forget callers
    /// that drop the `Result` still leave a durable signal for the UI.
    fn record_persist_result(&self, result: &anyhow::Result<()>) {
        let mut health = self
            .persist_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match result {
            Ok(()) => {
                health.take();
            }
            Err(error) => {
                tracing::warn!(%error, "local config persist failed (latched for UI)");
                *health = Some(error.to_string());
            }
        }
    }

    /// Current config persistence-health message, if the last flush failed.
    /// `None` once a subsequent flush succeeds.
    pub fn persist_error(&self) -> Option<String> {
        self.persist_health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn save_fields(
        &mut self,
        server_url: String,
        account_did: String,
        device_id: String,
        session_credential: String,
    ) {
        self.save(ClientConfig::from_fields(
            server_url,
            account_did,
            device_id,
            session_credential,
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cached: None,
            persist_health: std::sync::Arc::new(std::sync::Mutex::new(None)),
            path: path.into(),
        }
    }

    /// P3B.4 — load the multi-profile config.
    pub fn load_profiles(&self) -> MultiProfileConfig {
        if let Some(v2) = self.read_persisted_profiles()
            && !v2.profiles.is_empty()
        {
            return self.rehydrate_profiles(v2);
        }
        MultiProfileConfig::default()
    }

    /// Profile-store analogue of [`Self::rehydrate_config`]: reattach
    /// each profile's credential from the SecureKeyStore.
    fn rehydrate_profiles(&self, mut profiles: MultiProfileConfig) -> MultiProfileConfig {
        for profile in &mut profiles.profiles {
            if profile.account_did.is_empty() {
                continue;
            }
            profile.session_credential.clear();
            if let Some(token) = restore_session_credential_secret(&profile.account_did) {
                profile.session_credential = token;
            }
        }
        profiles
    }

    /// P3B.4 — persist the multi-profile config. Session credentials are
    /// moved into the SecureKeyStore; the plaintext blob only carries
    /// redacted rows.
    pub fn save_profiles(&mut self, profiles: &MultiProfileConfig) -> anyhow::Result<()> {
        self.write_persisted_profiles(profiles)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn profiles_path(&self) -> PathBuf {
        self.path.with_file_name("profiles.json")
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_persisted_profiles(&self) -> Option<MultiProfileConfig> {
        let bytes = fs::read(self.profiles_path()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Persist the profiles blob with every `session_credential` moved into
    /// the SecureKeyStore (see [`redact_profiles_for_disk`]).
    fn write_persisted_profiles(&self, profiles: &MultiProfileConfig) -> anyhow::Result<()> {
        self.write_profiles_blob(&redact_profiles_for_disk(profiles))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_profiles_blob(&self, profiles: &MultiProfileConfig) -> anyhow::Result<()> {
        let path = self.profiles_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(profiles)?)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn read_persisted_profiles(&self) -> Option<MultiProfileConfig> {
        browser_storage()
            .and_then(|storage| storage.get_item(PROFILES_STORAGE_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_profiles_blob(&self, profiles: &MultiProfileConfig) -> anyhow::Result<()> {
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(PROFILES_STORAGE_KEY, &serde_json::to_string(profiles)?)
            .map_err(|error| anyhow::anyhow!("localStorage profiles write failed: {error:?}"))?;
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn read_persisted_config(&self) -> Option<ClientConfig> {
        let bytes = fs::read(&self.path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    #[cfg(target_arch = "wasm32")]
    fn read_persisted_config(&self) -> Option<ClientConfig> {
        browser_storage()
            .and_then(|storage| storage.get_item(CONFIG_STORAGE_KEY).ok().flatten())
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    /// Persist the config blob with the `session_credential` moved into the
    /// SecureKeyStore (see [`redact_config_for_disk`]). The plaintext
    /// `config.json` / localStorage blob never carries the credential when
    /// a secure backend is available.
    fn write_persisted_config(&self, config: &ClientConfig) -> anyhow::Result<()> {
        self.write_config_blob(&redact_config_for_disk(config))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_config_blob(&self, config: &ClientConfig) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(config)?)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_config_blob(&self, config: &ClientConfig) -> anyhow::Result<()> {
        let Some(storage) = browser_storage() else {
            return Ok(());
        };
        storage
            .set_item(CONFIG_STORAGE_KEY, &serde_json::to_string(config)?)
            .map_err(|error| anyhow::anyhow!("localStorage write failed: {error:?}"))?;
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
fn browser_storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|window| window.local_storage().ok().flatten())
}

#[cfg(not(target_arch = "wasm32"))]
fn default_config_path() -> PathBuf {
    std::env::var_os("INKSON_CONFIG_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| app_data_dir().join("config.json"))
}

#[cfg(not(target_arch = "wasm32"))]
fn app_data_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .or_else(|| std::env::var_os("APPDATA"))
        .or_else(|| std::env::var_os("HOME").map(|home| Path::new(&home).join(".config").into()))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("inkson")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn default_config_matches_dev_server_bootstrap() {
        let config = ClientConfig::default();
        assert_eq!(config.server_url, "https://local.host");
        assert_eq!(config.principal_servers, vec!["https://local.host"]);
        assert!(config.account_did.is_empty());
        assert!(config.device_id.starts_with("ak:device:"));
        assert!(is_valid_device_id(&config.device_id));
        assert!(config.session_credential.is_empty());
    }

    #[test]
    fn validate_server_url_allows_https_and_loopback_http() {
        assert_eq!(
            validate_server_url("https://arkret.example")
                .unwrap()
                .as_str(),
            "https://arkret.example/"
        );
        assert_eq!(
            validate_server_url("http://127.0.0.1:8787")
                .unwrap()
                .as_str(),
            "http://127.0.0.1:8787/"
        );
        assert_eq!(
            validate_server_url("http://localhost:8787")
                .unwrap()
                .as_str(),
            "http://localhost:8787/"
        );
    }

    #[test]
    fn validate_server_url_rejects_insecure_remote_http() {
        let error = validate_server_url("http://arkret.example").unwrap_err();
        assert!(
            error
                .to_string()
                .contains("HTTPS is required for non-local servers")
        );
    }

    #[test]
    fn local_config_store_round_trips_latest_config() {
        let path = temp_config_path("round_trip");
        let mut store = LocalConfigStore::with_path(path);
        store.save_fields(
            "http://server.local".to_owned(),
            "did:web:bob.example".to_owned(),
            "ak:device:01964137-0000-7000-8000-000000000001".to_owned(),
            "sx_token".to_owned(),
        );

        assert_eq!(
            store.load(),
            ClientConfig::from_fields(
                "http://server.local",
                "did:web:bob.example",
                "ak:device:01964137-0000-7000-8000-000000000001",
                "sx_token",
            )
        );
    }

    #[test]
    fn local_config_store_persists_to_disk_between_instances() {
        let path = temp_config_path("persisted");

        let mut writer = LocalConfigStore::with_path(path.clone());
        writer.save_fields(
            "http://persisted.local".to_owned(),
            "did:web:persisted.example".to_owned(),
            "ak:device:01964137-0000-7000-8000-000000000002".to_owned(),
            "sx_persisted".to_owned(),
        );

        let reader = LocalConfigStore::with_path(path);
        assert_eq!(
            reader.load(),
            ClientConfig::from_fields(
                "http://persisted.local",
                "did:web:persisted.example",
                "ak:device:01964137-0000-7000-8000-000000000002",
                "sx_persisted",
            )
        );
    }

    #[test]
    fn invalid_device_id_is_replaced_and_token_cleared() {
        let config = ClientConfig::from_fields(
            "https://local.host",
            "did:web:alice.example",
            "dev_inkson",
            "old_token",
        );

        assert_eq!(config.server_url, "https://local.host");
        assert_eq!(config.account_did, "did:web:alice.example");
        assert!(is_valid_device_id(&config.device_id));
        assert_ne!(config.device_id, "dev_inkson");
        assert!(config.session_credential.is_empty());
    }

    #[test]
    fn canonicalizes_known_local_proxy_aliases() {
        assert_eq!(
            normalize_server_url("https://local.host/"),
            "https://local.host"
        );
        assert_eq!(
            normalize_server_url("http://127.0.0.1:8787/"),
            "https://local.host"
        );
        assert_eq!(
            ClientConfig::from_fields("http://localhost:8787", "", new_device_id(), "").server_url,
            "https://local.host"
        );
    }

    #[test]
    fn client_config_reads_legacy_json_without_principal_servers() {
        let config: ClientConfig = serde_json::from_str(
            r#"{
                "server_url": "https://legacy.example",
                "account_did": "",
                "device_id": "ak:device:01964137-0000-7000-8000-000000000003",
                "session_credential": ""
            }"#,
        )
        .expect("legacy config");

        assert_eq!(config.principal_servers, vec!["https://local.host"]);
    }

    #[test]
    fn principal_server_options_merge_current_configured_and_default() {
        let configured = vec![
            "https://prod.example/".to_owned(),
            "http://127.0.0.1:8787/".to_owned(),
            "https://prod.example".to_owned(),
        ];

        assert_eq!(
            principal_server_options_for("https://custom.example", &configured),
            vec![
                "https://custom.example".to_owned(),
                "https://prod.example/".to_owned(),
                "https://local.host".to_owned(),
            ]
        );
    }

    #[test]
    fn runtime_config_save_preserves_configured_principal_servers() {
        let path = temp_config_path("principal-server-presets");
        let seeded = ClientConfig {
            server_url: "https://local.host".to_owned(),
            principal_servers: vec![
                "https://prod.example".to_owned(),
                "https://stage.example".to_owned(),
            ],
            account_did: String::new(),
            device_id: "ak:device:01964137-0000-7000-8000-000000000004".to_owned(),
            session_credential: String::new(),
        };
        let writer = LocalConfigStore::with_path(path.clone());
        writer.write_config_blob(&seeded).expect("seed config");

        let mut updater = LocalConfigStore::with_path(path.clone());
        updater.save_fields(
            "https://stage.example".to_owned(),
            "did:web:stage.example:users:alice".to_owned(),
            "ak:device:01964137-0000-7000-8000-000000000005".to_owned(),
            String::new(),
        );

        let reader = LocalConfigStore::with_path(path);
        assert_eq!(
            reader.load().principal_servers,
            vec![
                "https://prod.example".to_owned(),
                "https://stage.example".to_owned(),
            ]
        );
    }

    // --- P3B.4 multi-profile coverage ----------------------------------

    #[test]
    fn upsert_and_activate_replaces_matching_profile() {
        let mut multi = MultiProfileConfig::default();
        let first = AccountProfile::new(
            "https://arkret.example",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000005",
            "token-a",
        );
        let first_id = multi.upsert_and_activate(first);

        // Same (server_url, account_did) — should overwrite rather
        // than append a new row.
        let updated = AccountProfile::new(
            "https://arkret.example",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000006",
            "token-b",
        );
        let updated_id = multi.upsert_and_activate(updated);

        assert_eq!(multi.profiles.len(), 1);
        assert_eq!(first_id, updated_id);
        assert_eq!(multi.active().unwrap().session_credential, "token-b");
    }

    #[test]
    fn activate_rejects_unknown_profile_id() {
        let mut multi = MultiProfileConfig::default();
        let profile = AccountProfile::new(
            "https://arkret.example",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000007",
            "token",
        );
        multi.upsert_and_activate(profile);
        assert!(!multi.activate("ak:profile:nonexistent"));
    }

    #[test]
    fn remove_resets_active_pointer_when_active_removed() {
        let mut multi = MultiProfileConfig::default();
        let first = AccountProfile::new(
            "https://arkret.example",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-000000000008",
            "token-a",
        );
        let first_id = multi.upsert_and_activate(first);
        let second = AccountProfile::new(
            "https://arkret.example",
            "did:web:bob.example",
            "ak:device:01964137-0000-7000-8000-000000000009",
            "token-b",
        );
        let second_id = multi.upsert_and_activate(second);

        // Active is currently `second_id`. Removing it should bump
        // active back to `first_id`.
        multi.remove(&second_id);
        assert_eq!(multi.active_profile_id.as_deref(), Some(first_id.as_str()));

        // Now remove the only remaining profile.
        multi.remove(&first_id);
        assert!(multi.active_profile_id.is_none());
        assert!(multi.profiles.is_empty());
    }

    #[test]
    fn active_as_client_config_round_trips_active_profile() {
        let mut multi = MultiProfileConfig::default();
        let profile = AccountProfile::new(
            "https://arkret.example",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-00000000000a",
            "token",
        );
        multi.upsert_and_activate(profile);
        let view = multi.active_as_client_config().expect("active config");
        assert_eq!(view.account_did, "did:web:alice.example");
        assert_eq!(view.session_credential, "token");
    }

    #[test]
    fn store_round_trips_multi_profile_blob() {
        let path = temp_config_path("multi-profile");
        let mut store = LocalConfigStore::with_path(path.clone());

        let mut multi = MultiProfileConfig::default();
        multi.upsert_and_activate(AccountProfile::new(
            "https://arkret.example",
            "did:web:alice.example",
            "ak:device:01964137-0000-7000-8000-00000000000b",
            "tok",
        ));
        store.save_profiles(&multi).expect("write profiles");

        let reader = LocalConfigStore::with_path(path);
        let loaded = reader.load_profiles();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(loaded.profiles[0].account_did, "did:web:alice.example");
    }

    // --- session_credential SecureKeyStore redaction --------------------------

    #[test]
    fn session_credential_is_redacted_from_disk_blob() {
        let path = temp_config_path("redacted");
        let mut store = LocalConfigStore::with_path(path.clone());
        store.save_fields(
            "https://redacted.example".to_owned(),
            "did:web:redacted.example".to_owned(),
            "ak:device:01964137-0000-7000-8000-00000000000c".to_owned(),
            "sx_secret_credential".to_owned(),
        );

        // The plaintext blob MUST NOT contain the credential.
        let raw = fs::read_to_string(&path).expect("config blob");
        assert!(
            !raw.contains("sx_secret_credential"),
            "credential leaked into plaintext config blob: {raw}"
        );

        // A fresh store instance reattaches it from the secure store.
        let reader = LocalConfigStore::with_path(path);
        assert_eq!(reader.load().session_credential, "sx_secret_credential");
    }

    #[test]
    fn load_with_secure_store_rehydrates_redacted_config_from_supplied_store() {
        let path = temp_config_path("explicit-secure-store");
        let account_did = "did:web:explicit-secure-store.example";
        let redacted = ClientConfig::from_fields(
            "https://explicit-secure-store.example",
            account_did,
            "ak:device:01964137-0000-7000-8000-0000000000aa",
            "",
        );
        let writer = LocalConfigStore::with_path(path.clone());
        writer
            .write_config_blob(&redacted)
            .expect("seed redacted config");

        let secure_store = crate::secure_key_store::MemorySecureKeyStore::new();
        crate::secure_key_store::SecureKeyStore::store_secret(
            &secure_store,
            &session_credential_secret_key(account_did),
            "sx_from_supplied_store",
        )
        .expect("seed secure token");

        let reader = LocalConfigStore::with_path(path);
        assert_eq!(
            reader
                .load_with_secure_store(&secure_store)
                .session_credential,
            "sx_from_supplied_store"
        );
    }

    #[test]
    fn profiles_blob_redacts_session_credentials() {
        // Own subdirectory — `profiles_path()` derives `profiles.json`
        // next to the config path, which would collide with other
        // tests' blobs in the shared temp dir.
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("inkson-profiles-redacted-{stamp}"));
        let path = dir.join("config.json");
        let mut store = LocalConfigStore::with_path(path.clone());

        let mut multi = MultiProfileConfig::default();
        multi.upsert_and_activate(AccountProfile::new(
            "https://arkret.example",
            "did:web:profile-redacted.example",
            "ak:device:01964137-0000-7000-8000-00000000000e",
            "sx_profile_credential",
        ));
        store.save_profiles(&multi).expect("write profiles");

        let profiles_raw =
            fs::read_to_string(path.with_file_name("profiles.json")).expect("profiles blob");
        assert!(
            !profiles_raw.contains("sx_profile_credential"),
            "credential leaked into plaintext profiles blob: {profiles_raw}"
        );

        // A fresh store reattaches the credential per profile.
        let reader = LocalConfigStore::with_path(path);
        let loaded = reader.load_profiles();
        assert_eq!(loaded.profiles.len(), 1);
        assert_eq!(
            loaded.profiles[0].session_credential,
            "sx_profile_credential"
        );
        assert_eq!(
            loaded
                .active_as_client_config()
                .expect("active config")
                .session_credential,
            "sx_profile_credential"
        );
    }

    fn temp_config_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("inkson-{name}-{stamp}.json"))
    }
}
