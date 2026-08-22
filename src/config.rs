#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use arkret_sdk::{
    DeviceId, DidCoreId, DidFullId, PrincipalAuthorityKey, PrincipalResolutionProjection,
    project_full_id_to_core_id,
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::operation::uuid_v7;

const DEFAULT_SERVER_URL: &str = "https://local.host";
const DEFAULT_PRINCIPAL_SERVERS: &[&str] = &[DEFAULT_SERVER_URL];
const LOCAL_PROXY_SERVER_URL: &str = "https://local.host";
const LOCAL_PROXY_SERVER_PORT: u16 = 8787;
const DEVICE_ID_PREFIX: &str = "ak:device:";
#[cfg(target_arch = "wasm32")]
const CONFIG_STORAGE_KEY: &str = "inkson.config.v1";
/// P3B.4: localStorage key for the multi-profile config holding the
/// `MultiProfileConfig`.
#[cfg(target_arch = "wasm32")]
const PROFILES_STORAGE_KEY: &str = "inkson.profiles.v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub principal_servers: Vec<String>,
    #[serde(default)]
    pub active_account: Option<ActiveAccountContext>,
    #[serde(default, skip_serializing)]
    pub session_credential: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            principal_servers: default_principal_servers(),
            active_account: None,
            session_credential: String::new(),
        }
    }
}

impl ClientConfig {
    pub fn from_fields(
        active_account: Option<ActiveAccountContext>,
        session_credential: impl Into<String>,
    ) -> Self {
        Self {
            principal_servers: default_principal_servers(),
            active_account,
            session_credential: session_credential.into(),
        }
        .normalized()
    }

    fn normalized(mut self) -> Self {
        self.principal_servers = normalize_principal_server_presets(&self.principal_servers);
        if self.active_account.is_none() {
            self.session_credential.clear();
        }
        self
    }

    #[must_use]
    pub fn active_account(&self) -> Option<&ActiveAccountContext> {
        self.active_account.as_ref()
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

/// AKP-0007 P3B.4 — multi-account profile primitive. The stable authority
/// identifies the account while resolution and route remain independently
/// replaceable projections. `profile_id` is the installation-local UI key.
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountProfile {
    /// Stable, opaque id (UUIDv7 prefixed `ak:profile:`). It is never derived
    /// from identity coordinates and remains stable across resolution or route
    /// refreshes.
    pub profile_id: String,
    /// Optional human label (e.g. "Work", "Personal"). Falls back to
    /// the stable principal identifier's last segment when empty.
    #[serde(default)]
    pub label: String,
    pub authority: PrincipalAuthorityKey,
    pub resolution: PrincipalResolutionProjection,
    pub device_id: DeviceId,
    pub server_url: Url,
    /// Runtime-only credential; plaintext profile persistence never carries it.
    #[serde(default, skip_serializing)]
    pub session_credential: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedAccountProfile {
    profile_id: String,
    #[serde(default)]
    label: String,
    authority: PrincipalAuthorityKey,
    resolution: PrincipalResolutionProjection,
    device_id: DeviceId,
    server_url: Url,
}

impl<'de> Deserialize<'de> for AccountProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = SerializedAccountProfile::deserialize(deserializer)?;
        let profile = Self {
            profile_id: value.profile_id,
            label: value.label,
            authority: value.authority,
            resolution: value.resolution,
            device_id: value.device_id,
            server_url: value.server_url,
            session_credential: String::new(),
        };
        profile.active_context().map_err(serde::de::Error::custom)?;
        Ok(profile)
    }
}

impl AccountProfile {
    pub(crate) fn new(
        authority: PrincipalAuthorityKey,
        resolution: PrincipalResolutionProjection,
        device_id: DeviceId,
        server_url: Url,
        session_credential: impl Into<String>,
    ) -> Result<Self, ActiveAccountContextError> {
        let profile = Self {
            profile_id: format!("ak:profile:{}", uuid_v7()),
            label: String::new(),
            server_url,
            authority,
            resolution,
            device_id,
            session_credential: session_credential.into(),
        };
        profile.active_context()?;
        Ok(profile)
    }

    /// Human label used by the avatar dropdown switcher. Falls back to the
    /// stable principal identifier's last `:` segment when no label is set.
    pub fn display_label(&self) -> &str {
        if !self.label.is_empty() {
            return self.label.as_str();
        }
        self.authority
            .principal_id
            .as_str()
            .rsplit(':')
            .next()
            .unwrap_or(self.authority.principal_id.as_str())
    }

    pub fn active_context(&self) -> Result<ActiveAccountContext, ActiveAccountContextError> {
        ActiveAccountContext::new(
            self.profile_id.clone(),
            self.authority.clone(),
            self.resolution.clone(),
            self.device_id.clone(),
            self.server_url.clone(),
        )
    }
}

/// Multi-profile config. Persisted under `PROFILES_STORAGE_KEY` on
/// wasm and `app_data_dir()/profiles.json` on native.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Add or replace a profile (matched only by account authority)
    /// and mark it active. Returns the active profile id.
    pub fn upsert_and_activate(
        &mut self,
        profile: AccountProfile,
    ) -> Result<String, ActiveAccountContextError> {
        profile.active_context()?;
        let key = profile.authority.clone();
        if let Some(existing) = self.profiles.iter_mut().find(|p| p.authority == key) {
            existing.resolution = profile.resolution;
            existing.server_url = profile.server_url;
            existing.device_id = profile.device_id;
            existing.session_credential = profile.session_credential;
            if !profile.label.is_empty() {
                existing.label = profile.label;
            }
            let id = existing.profile_id.clone();
            self.active_profile_id = Some(id.clone());
            return Ok(id);
        }
        let id = profile.profile_id.clone();
        self.profiles.push(profile);
        self.active_profile_id = Some(id.clone());
        Ok(id)
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
        let active_account = active.active_context().ok()?;
        Some(ClientConfig::from_fields(
            Some(active_account),
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
/// AKP-0007 P3B.4.3 — the sync engine, push registration, offline
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
    /// Profile the shell is switching into, including its typed authority,
    /// accepted resolution, device and current route.
    pub next_profile: AccountProfile,
}

/// SecureKeyStore key for a current session credential. Both the account
/// authority pair and device participate in the namespace; resolution and
/// route deliberately do not.
fn session_credential_secret_key(
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> anyhow::Result<String> {
    let authority_digest = crate::secure_key_store::principal_authority_storage_digest(authority)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let device_digest = crate::secure_key_store::device_storage_digest(device_id);
    Ok(format!(
        "coauth.session_credential.{authority_digest}.{device_digest}"
    ))
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
/// call. `None` values negative-cache "no credential stored" for the exact
/// authority/device slot.
fn session_credential_cache()
-> &'static std::sync::Mutex<std::collections::HashMap<String, Option<String>>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, Option<String>>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// Move `session_credential` into the SecureKeyStore. Plaintext persistence is
/// always redacted, including when the secure backend rejects the write.
fn persist_session_credential_secret(
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    session_credential: &str,
) {
    if session_credential.is_empty() {
        return;
    }
    let store = config_secure_store();
    let Ok(key) = session_credential_secret_key(authority, device_id) else {
        tracing::warn!("session credential scope canonicalization failed");
        return;
    };
    match store.store_secret(&key, session_credential) {
        Ok(()) => {
            if let Ok(mut cache) = session_credential_cache().lock() {
                cache.insert(key, Some(session_credential.to_owned()));
            }
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "secure_key_store session_credential write failed; config persisted without credential",
            );
        }
    }
}

pub(crate) fn clear_session_credential_secret(
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) {
    let Ok(key) = session_credential_secret_key(authority, device_id) else {
        return;
    };
    let store = config_secure_store();
    let _ = store.delete_secret(&key);
    if let Ok(mut cache) = session_credential_cache().lock() {
        cache.insert(key, None);
    }
}

/// Companion read for one authority/device slot, from the
/// in-process cache first, then the SecureKeyStore.
fn restore_session_credential_secret_from_store(
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<String> {
    let key = session_credential_secret_key(authority, device_id).ok()?;
    // The synchronous first-paint wasm store is intentionally forbidden from
    // reading session credentials. Wait for the IndexedDB/SubtleCrypto tier
    // instead of probing the forbidden localStorage path on every render and
    // flooding the console with an expected `Unsupported` warning.
    #[cfg(target_arch = "wasm32")]
    if !crate::secure_key_store::wasm_secure_store_ready() {
        return None;
    }
    if let Ok(cache) = session_credential_cache().lock()
        && let Some(entry) = cache.get(&key)
    {
        return entry.clone();
    }
    let result = match store.get_secret(&key) {
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
        cache.insert(key, result.clone());
    }
    result
}

fn restore_session_credential_secret(
    authority: &PrincipalAuthorityKey,
    device_id: &DeviceId,
) -> Option<String> {
    let store = config_secure_store();
    restore_session_credential_secret_from_store(authority, device_id, store.as_ref())
}

/// Build the copy of `config` that is allowed to touch the plaintext
/// persistence layer: the `session_credential` is moved into the
/// SecureKeyStore and blanked.
fn redact_config_for_disk(config: &ClientConfig) -> ClientConfig {
    let mut redacted = config.clone();
    if let Some(active) = &redacted.active_account {
        persist_session_credential_secret(
            &active.authority,
            &active.device_id,
            &redacted.session_credential,
        );
    }
    redacted.session_credential.clear();
    redacted
}

/// Profile-store analogue of [`redact_config_for_disk`].
fn redact_profiles_for_disk(profiles: &MultiProfileConfig) -> MultiProfileConfig {
    let mut redacted = profiles.clone();
    for profile in &mut redacted.profiles {
        persist_session_credential_secret(
            &profile.authority,
            &profile.device_id,
            &profile.session_credential,
        );
        profile.session_credential.clear();
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

    /// Reattach the session credential exclusively through `store`. Plaintext
    /// config blobs are never accepted as a credential source.
    fn reattach_session_credential(
        &self,
        mut config: ClientConfig,
        store: &dyn crate::secure_key_store::SecureKeyStore,
    ) -> ClientConfig {
        config.session_credential.clear();
        if let Some(active) = &config.active_account
            && let Some(token) = restore_session_credential_secret_from_store(
                &active.authority,
                &active.device_id,
                store,
            )
        {
            config.session_credential = token;
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
        active_account: Option<ActiveAccountContext>,
        session_credential: String,
    ) {
        self.save(ClientConfig::from_fields(
            active_account,
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
            profile.session_credential.clear();
            if let Some(token) =
                restore_session_credential_secret(&profile.authority, &profile.device_id)
            {
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

/// The verified identity, account-authority and current routing coordinates for
/// the foreground account.
///
/// Equality is deliberately not implemented for the aggregate. Callers must
/// choose either principal equality (`principal_id`) or account equality
/// (`authority`) explicitly; route and resolution changes do not create a new
/// account.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveAccountContext {
    pub profile_id: String,
    pub authority: PrincipalAuthorityKey,
    pub resolution: PrincipalResolutionProjection,
    pub device_id: DeviceId,
    pub server_url: Url,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SerializedActiveAccountContext {
    profile_id: String,
    authority: PrincipalAuthorityKey,
    resolution: PrincipalResolutionProjection,
    device_id: DeviceId,
    server_url: Url,
}

impl<'de> Deserialize<'de> for ActiveAccountContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = SerializedActiveAccountContext::deserialize(deserializer)?;
        Self::new(
            value.profile_id,
            value.authority,
            value.resolution,
            value.device_id,
            value.server_url,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum ActiveAccountContextError {
    #[error("profile_id must be non-empty")]
    EmptyProfileId,
    #[error("invalid principal authority: {0}")]
    InvalidAuthority(String),
    #[error("resolution full_id does not project to the authority principal_id")]
    PrincipalResolutionMismatch,
    #[error("route refresh service id does not match the account authority")]
    PrincipalServerMismatch,
    #[error("resolution update does not continue the active projection")]
    ResolutionPredecessorMismatch,
    #[error("invalid Principal Server route: {0}")]
    InvalidServerUrl(String),
}

impl ActiveAccountContext {
    pub(crate) fn new(
        profile_id: String,
        authority: PrincipalAuthorityKey,
        resolution: PrincipalResolutionProjection,
        device_id: DeviceId,
        server_url: Url,
    ) -> Result<Self, ActiveAccountContextError> {
        if profile_id.trim().is_empty() {
            return Err(ActiveAccountContextError::EmptyProfileId);
        }
        authority
            .validate()
            .map_err(|error| ActiveAccountContextError::InvalidAuthority(error.to_string()))?;
        validate_resolution_binding(&authority, &resolution)?;
        let server_url = validate_server_url(server_url.as_str())
            .map_err(|error| ActiveAccountContextError::InvalidServerUrl(error.to_string()))?;
        Ok(Self {
            profile_id,
            authority,
            resolution,
            device_id,
            server_url,
        })
    }

    #[must_use]
    pub fn principal_id(&self) -> &DidCoreId {
        &self.authority.principal_id
    }

    #[must_use]
    pub fn full_id(&self) -> &DidFullId {
        &self.resolution.full_id
    }

    #[must_use]
    pub fn is_same_account(&self, authority: &PrincipalAuthorityKey) -> bool {
        &self.authority == authority
    }

    /// Atomically replace the complete accepted resolution projection.
    pub fn update_resolution(
        &mut self,
        resolution: PrincipalResolutionProjection,
        previous_resolution_event_ref: &str,
        previous_method_history_head: &str,
    ) -> Result<(), ActiveAccountContextError> {
        validate_resolution_binding(&self.authority, &resolution)?;
        if previous_resolution_event_ref != self.resolution.resolution_event_ref
            || previous_method_history_head != self.resolution.method_history_head
            || resolution.updated_at < self.resolution.updated_at
        {
            return Err(ActiveAccountContextError::ResolutionPredecessorMismatch);
        }
        self.resolution = resolution;
        Ok(())
    }

    /// Refresh only the HTTP route after the caller has verified the service
    /// identity behind it.
    pub fn update_server_route(
        &mut self,
        principal_server_id: &DidCoreId,
        server_url: Url,
    ) -> Result<(), ActiveAccountContextError> {
        if &self.authority.principal_server_id != principal_server_id {
            return Err(ActiveAccountContextError::PrincipalServerMismatch);
        }
        self.server_url = validate_server_url(server_url.as_str())
            .map_err(|error| ActiveAccountContextError::InvalidServerUrl(error.to_string()))?;
        Ok(())
    }
}

fn validate_resolution_binding(
    authority: &PrincipalAuthorityKey,
    resolution: &PrincipalResolutionProjection,
) -> Result<(), ActiveAccountContextError> {
    let projected = project_full_id_to_core_id(&resolution.full_id)
        .map_err(|_| ActiveAccountContextError::PrincipalResolutionMismatch)?;
    if projected != authority.principal_id {
        return Err(ActiveAccountContextError::PrincipalResolutionMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod active_account_tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use chrono::{DateTime, Utc};

    use super::*;

    fn projection(full_id: &str, coordinate: &str) -> PrincipalResolutionProjection {
        PrincipalResolutionProjection {
            full_id: DidFullId::new(full_id).expect("full DID"),
            method_history_head: format!("head-{coordinate}"),
            version_id: format!("version-{coordinate}"),
            resolution_event_ref: format!("event-{coordinate}"),
            updated_at: "2026-08-22T00:00:00Z"
                .parse::<DateTime<Utc>>()
                .expect("timestamp"),
        }
    }

    fn authority(full_id: &str, server_id: &str) -> PrincipalAuthorityKey {
        let full_id = DidFullId::new(full_id).expect("full DID");
        PrincipalAuthorityKey::new(
            project_full_id_to_core_id(&full_id).expect("principal core"),
            DidCoreId::new(server_id).expect("server core"),
        )
    }

    fn device(suffix: &str) -> DeviceId {
        DeviceId::new(format!("ak:device:01964137-0000-7000-8000-{suffix:0>12}"))
            .expect("device id")
    }

    fn context(
        full_id: &str,
        server_id: &str,
        route: &str,
        coordinate: &str,
    ) -> ActiveAccountContext {
        ActiveAccountContext::new(
            format!("ak:profile:{coordinate}"),
            authority(full_id, server_id),
            projection(full_id, coordinate),
            device(coordinate),
            Url::parse(route).expect("route"),
        )
        .expect("active context")
    }

    #[test]
    fn default_config_is_explicitly_signed_out() {
        let config = ClientConfig::default();
        assert!(config.active_account.is_none());
        assert!(config.session_credential.is_empty());
        assert_eq!(config.principal_servers, vec!["https://local.host"]);
    }

    #[test]
    fn context_rejects_resolution_for_another_principal() {
        let result = ActiveAccountContext::new(
            "ak:profile:mismatch".to_owned(),
            authority(
                "did:webvh:z6mkalice:old.example:alice",
                "ak:did_core:web:server.example",
            ),
            projection("did:webvh:z6mkbob:bob.example:bob", "mismatch"),
            device("1"),
            Url::parse("https://server.example").unwrap(),
        );
        assert_eq!(
            result.unwrap_err(),
            ActiveAccountContextError::PrincipalResolutionMismatch
        );
    }

    #[test]
    fn same_core_resolution_update_replaces_projection_atomically() {
        let mut active = context(
            "did:webvh:z6mkalice:old.example:alice",
            "ak:did_core:web:server.example",
            "https://route-a.example",
            "1",
        );
        let profile_id = active.profile_id.clone();
        let authority = active.authority.clone();
        let device_id = active.device_id.clone();
        let route = active.server_url.clone();
        let previous_event_ref = active.resolution.resolution_event_ref.clone();
        let previous_history_head = active.resolution.method_history_head.clone();
        let next = projection("did:webvh:z6mkalice:new.example:users:alice", "2");

        active
            .update_resolution(next.clone(), &previous_event_ref, &previous_history_head)
            .unwrap();

        assert_eq!(active.resolution, next);
        assert_eq!(active.profile_id, profile_id);
        assert_eq!(active.authority, authority);
        assert_eq!(active.device_id, device_id);
        assert_eq!(active.server_url, route);
    }

    #[test]
    fn resolution_update_rejects_a_stale_predecessor() {
        let mut active = context(
            "did:webvh:z6mkalice:old.example:alice",
            "ak:did_core:web:server.example",
            "https://route-a.example",
            "1",
        );
        let next = projection("did:webvh:z6mkalice:new.example:users:alice", "2");

        assert_eq!(
            active
                .update_resolution(next, "ak:event:stale", "sha256:stale")
                .unwrap_err(),
            ActiveAccountContextError::ResolutionPredecessorMismatch
        );
    }

    #[test]
    fn route_refresh_requires_same_principal_server() {
        let mut active = context(
            "did:webvh:z6mkalice:old.example:alice",
            "ak:did_core:web:server.example",
            "https://route-a.example",
            "1",
        );
        let other = DidCoreId::new("ak:did_core:web:other.example").unwrap();
        assert_eq!(
            active
                .update_server_route(&other, Url::parse("https://route-b.example").unwrap())
                .unwrap_err(),
            ActiveAccountContextError::PrincipalServerMismatch
        );
        assert_eq!(active.server_url.as_str(), "https://route-a.example/");

        let server = active.authority.principal_server_id.clone();
        active
            .update_server_route(&server, Url::parse("https://route-b.example").unwrap())
            .unwrap();
        assert_eq!(active.server_url.as_str(), "https://route-b.example/");
    }

    #[test]
    fn profile_upsert_uses_authority_not_resolution_or_route() {
        let first_context = context(
            "did:webvh:z6mkalice:old.example:alice",
            "ak:did_core:web:server.example",
            "https://route-a.example",
            "1",
        );
        let mut first = AccountProfile {
            profile_id: first_context.profile_id.clone(),
            label: "Personal".to_owned(),
            authority: first_context.authority.clone(),
            resolution: first_context.resolution.clone(),
            device_id: first_context.device_id.clone(),
            server_url: first_context.server_url.clone(),
            session_credential: "token-a".to_owned(),
        };
        let mut profiles = MultiProfileConfig::default();
        let profile_id = profiles.upsert_and_activate(first.clone()).unwrap();

        first.profile_id = "ak:profile:must-not-replace-stable-id".to_owned();
        first.resolution = projection("did:webvh:z6mkalice:new.example:alice", "2");
        first.server_url = Url::parse("https://route-b.example").unwrap();
        first.device_id = device("2");
        first.session_credential = "token-b".to_owned();
        let refreshed_id = profiles.upsert_and_activate(first.clone()).unwrap();

        assert_eq!(profiles.profiles.len(), 1);
        assert_eq!(refreshed_id, profile_id);
        let refreshed = profiles.active().unwrap();
        assert_eq!(refreshed.profile_id, profile_id);
        assert_eq!(refreshed.resolution, first.resolution);
        assert_eq!(refreshed.server_url, first.server_url);
        assert_eq!(refreshed.session_credential, "token-b");
    }

    #[test]
    fn same_principal_on_different_servers_creates_distinct_profiles_and_secret_keys() {
        let full_id = "did:webvh:z6mkalice:alice.example:alice";
        let first = context(
            full_id,
            "ak:did_core:web:server-a.example",
            "https://route.example",
            "1",
        );
        let second = context(
            full_id,
            "ak:did_core:web:server-b.example",
            "https://route.example",
            "2",
        );
        assert_ne!(
            session_credential_secret_key(&first.authority, &first.device_id).unwrap(),
            session_credential_secret_key(&second.authority, &second.device_id).unwrap()
        );

        let mut profiles = MultiProfileConfig::default();
        for active in [first, second] {
            profiles
                .upsert_and_activate(AccountProfile {
                    profile_id: active.profile_id,
                    label: String::new(),
                    authority: active.authority,
                    resolution: active.resolution,
                    device_id: active.device_id,
                    server_url: active.server_url,
                    session_credential: String::new(),
                })
                .unwrap();
        }
        assert_eq!(profiles.profiles.len(), 2);
    }

    #[test]
    fn persisted_config_redacts_and_rehydrates_authority_device_scoped_credential() {
        let path = temp_config_path("typed-redaction");
        let active = context(
            "did:webvh:z6mkalice:alice.example:alice",
            "ak:did_core:web:server.example",
            "https://route.example",
            "1",
        );
        let mut writer = LocalConfigStore::with_path(path.clone());
        writer.save(ClientConfig::from_fields(
            Some(active.clone()),
            "sx_secret_credential",
        ));

        let raw = fs::read_to_string(&path).expect("config blob");
        assert!(!raw.contains("sx_secret_credential"));
        let loaded = LocalConfigStore::with_path(path).load();
        assert_eq!(loaded.session_credential, "sx_secret_credential");
        let loaded_active = loaded.active_account.unwrap();
        assert_eq!(loaded_active.authority, active.authority);
        assert_eq!(loaded_active.resolution, active.resolution);
    }

    #[test]
    fn legacy_ambiguous_identity_fields_fail_closed() {
        let mut value = serde_json::Map::new();
        value.insert(
            "principal_servers".to_owned(),
            serde_json::json!(["https://route.example"]),
        );
        value.insert(
            ["account_", "did"].concat(),
            serde_json::json!("did:web:alice.example"),
        );
        assert!(serde_json::from_value::<ClientConfig>(serde_json::Value::Object(value)).is_err());
    }

    #[test]
    fn validate_server_url_allows_https_and_loopback_only() {
        assert!(validate_server_url("https://arkret.example").is_ok());
        assert!(validate_server_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_server_url("http://arkret.example").is_err());
    }

    fn temp_config_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("inkson-{name}-{stamp}.json"))
    }
}
