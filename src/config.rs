#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use arkret_sdk::DeviceId;
use serde::{Deserialize, Serialize};
use url::Url;

pub use crate::identity::active_account::ActiveAccountContext;
use crate::identity::active_account::authority_namespace;
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
    pub principal_servers: Vec<Url>,
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
    pub fn authenticated(active_account: ActiveAccountContext, session_credential: String) -> Self {
        Self {
            principal_servers: default_principal_servers(),
            active_account: Some(active_account),
            session_credential,
        }
    }

    fn normalized(mut self) -> Self {
        self.principal_servers = normalize_principal_server_presets(&self.principal_servers);
        if self.active_account.is_none() {
            self.session_credential.clear();
        }
        self
    }

    pub fn server_url(&self) -> Option<&Url> {
        self.active_account
            .as_ref()
            .map(|account| &account.server_url)
    }

    pub fn active_account(&self) -> Option<&ActiveAccountContext> {
        self.active_account.as_ref()
    }

    pub fn principal_id(&self) -> Option<&arkret_sdk::DidCoreId> {
        self.active_account
            .as_ref()
            .map(ActiveAccountContext::principal_id)
    }

    pub fn device_id(&self) -> Option<&DeviceId> {
        self.active_account
            .as_ref()
            .map(|account| &account.device_id)
    }

    pub fn same_runtime_state(&self, other: &Self) -> bool {
        self.principal_servers == other.principal_servers
            && self.session_credential == other.session_credential
            && match (&self.active_account, &other.active_account) {
                (None, None) => true,
                (Some(left), Some(right)) => {
                    left.authority == right.authority
                        && left.profile_id == right.profile_id
                        && left.resolution == right.resolution
                        && left.device_id == right.device_id
                        && left.server_url == right.server_url
                }
                _ => false,
            }
    }
}

fn default_principal_servers() -> Vec<Url> {
    DEFAULT_PRINCIPAL_SERVERS
        .iter()
        .map(|server| Url::parse(server).expect("default Principal Server URL"))
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

fn push_unique_principal_server(options: &mut Vec<Url>, server_url: &Url) {
    if options.iter().any(|existing| existing == server_url) {
        return;
    }
    options.push(server_url.clone());
}

pub fn normalize_principal_server_presets(principal_servers: &[Url]) -> Vec<Url> {
    let mut options = Vec::<Url>::new();
    for server_url in principal_servers {
        push_unique_principal_server(&mut options, server_url);
    }
    if options.is_empty() {
        for server_url in default_principal_servers() {
            push_unique_principal_server(&mut options, &server_url);
        }
    }
    options
}

pub fn principal_server_options_for(
    current_server_url: &str,
    configured_principal_servers: &[Url],
) -> Vec<String> {
    let mut options = Vec::<String>::new();
    let mut push = |candidate: &str| {
        let normalized = normalize_server_url(candidate);
        if !normalized.is_empty()
            && !options
                .iter()
                .any(|existing| same_server_url(existing, &normalized))
        {
            options.push(normalized);
        }
    };
    push(current_server_url);
    for server_url in configured_principal_servers {
        push(server_url.as_str());
    }
    for server_url in DEFAULT_PRINCIPAL_SERVERS {
        push(server_url);
    }
    options
}

/// AKP-0007 P3B.4 — multi-account profile primitive. A profile is the
/// (server_url, principal_id, device_id, session_credential) tuple that the
/// existing single-profile `ClientConfig` already carries, plus a
/// stable `profile_id` so the switcher UI can address profiles by a
/// non-secret handle (principal_id + device_id could rotate; profile_id
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
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountProfile {
    #[serde(flatten)]
    pub account: ActiveAccountContext,
    /// Optional human label (e.g. "Work", "Personal"). Falls back to
    /// the stable principal identifier's last segment when empty.
    #[serde(default)]
    pub label: String,
    #[serde(default, skip_serializing)]
    pub session_credential: String,
}

impl AccountProfile {
    pub fn new(account: ActiveAccountContext, session_credential: String) -> Self {
        Self {
            account,
            label: String::new(),
            session_credential,
        }
    }

    /// Human label used by the avatar dropdown switcher. Falls back to the
    /// stable principal identifier's last `:` segment when no label is set.
    pub fn display_label(&self) -> &str {
        if !self.label.is_empty() {
            return self.label.as_str();
        }
        self.account
            .principal_id()
            .as_str()
            .rsplit(':')
            .next()
            .unwrap_or(self.account.principal_id().as_str())
    }
}

/// Multi-profile config. Persisted under `PROFILES_STORAGE_KEY` on
/// wasm and `app_data_dir()/profiles.json` on native.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
        self.profiles
            .iter()
            .find(|profile| profile.account.profile_id == id)
    }

    /// Add or replace a profile (matched by `principal_id + server_url`)
    /// and mark it active. Returns the active profile id.
    pub fn upsert_and_activate(&mut self, profile: AccountProfile) -> anyhow::Result<String> {
        if let Some(existing) = self
            .profiles
            .iter_mut()
            .find(|candidate| candidate.account.authority == profile.account.authority)
        {
            existing
                .account
                .update_resolution(profile.account.resolution)?;
            existing.account.device_id = profile.account.device_id;
            existing.account.update_route(
                &profile.account.authority.principal_server_id,
                profile.account.server_url,
            )?;
            existing.session_credential = profile.session_credential;
            if !profile.label.is_empty() {
                existing.label = profile.label;
            }
            let id = existing.account.profile_id.clone();
            self.active_profile_id = Some(id.clone());
            return Ok(id);
        }
        let id = profile.account.profile_id.clone();
        self.profiles.push(profile);
        self.active_profile_id = Some(id.clone());
        Ok(id)
    }

    /// Switch the active profile. Returns `false` if the requested
    /// profile_id is not in the store.
    pub fn activate(&mut self, profile_id: &str) -> bool {
        if self
            .profiles
            .iter()
            .any(|profile| profile.account.profile_id == profile_id)
        {
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
        self.profiles
            .retain(|profile| profile.account.profile_id != profile_id);
        if self.active_profile_id.as_deref() == Some(profile_id) {
            self.active_profile_id = self
                .profiles
                .first()
                .map(|profile| profile.account.profile_id.clone());
        }
    }
}

/// SecureKeyStore key for the current session credential of `principal_id`.
/// The namespace is per-DID — two profiles for the same DID on different
/// servers share one slot, matching the existing single-active-profile model.
fn session_credential_secret_key(account: &ActiveAccountContext) -> anyhow::Result<String> {
    Ok(format!(
        "coauth.session_credential.v1.{}.{}",
        authority_namespace(&account.authority)?,
        account.device_id.as_str()
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
    account: &ActiveAccountContext,
    session_credential: &str,
) -> anyhow::Result<()> {
    let store = config_secure_store();
    let key = session_credential_secret_key(account)?;
    if session_credential.is_empty() {
        // Empty config writes also happen during first-paint restore and
        // profile/bootstrap churn. Do not treat them as logout; explicit
        // session invalidation calls `clear_session_credential_secret`.
        return Ok(());
    }
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
    Ok(())
}

pub(crate) fn clear_session_credential_secret(account: &ActiveAccountContext) {
    let Ok(key) = session_credential_secret_key(account) else {
        return;
    };
    let store = config_secure_store();
    let _ = store.delete_secret(&key);
    if let Ok(mut cache) = session_credential_cache().lock() {
        cache.insert(key, None);
    }
}

/// Companion read: the session credential for `principal_id`, from the
/// in-process cache first, then the SecureKeyStore.
fn restore_session_credential_secret_from_store(
    account: &ActiveAccountContext,
    store: &dyn crate::secure_key_store::SecureKeyStore,
) -> Option<String> {
    let key = session_credential_secret_key(account).ok()?;
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

fn restore_session_credential_secret(account: &ActiveAccountContext) -> Option<String> {
    let store = config_secure_store();
    restore_session_credential_secret_from_store(account, store.as_ref())
}

/// Build the copy of `config` that is allowed to touch the plaintext
/// persistence layer: the `session_credential` is moved into the
/// SecureKeyStore and blanked.
fn redact_config_for_disk(config: &ClientConfig) -> ClientConfig {
    let mut redacted = config.clone();
    if let Some(account) = redacted.active_account.as_ref()
        && let Err(error) = persist_session_credential_secret(account, &redacted.session_credential)
    {
        tracing::warn!(?error, "session credential namespace construction failed");
    }
    redacted.session_credential.clear();
    redacted
}

/// Profile-store analogue of [`redact_config_for_disk`].
fn redact_profiles_for_disk(profiles: &MultiProfileConfig) -> MultiProfileConfig {
    let mut redacted = profiles.clone();
    for profile in &mut redacted.profiles {
        if let Err(error) =
            persist_session_credential_secret(&profile.account, &profile.session_credential)
        {
            tracing::warn!(?error, "profile credential namespace construction failed");
        }
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
        if let Some(account) = config.active_account.as_ref()
            && let Some(token) = restore_session_credential_secret_from_store(account, store)
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
        if let Some(profiles) = self.read_persisted_profiles()
            && !profiles.profiles.is_empty()
        {
            return self.rehydrate_profiles(profiles);
        }
        MultiProfileConfig::default()
    }

    /// Profile-store analogue of [`Self::rehydrate_config`]: reattach
    /// each profile's credential from the SecureKeyStore.
    fn rehydrate_profiles(&self, mut profiles: MultiProfileConfig) -> MultiProfileConfig {
        for profile in &mut profiles.profiles {
            profile.session_credential.clear();
            if let Some(token) = restore_session_credential_secret(&profile.account) {
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
    use chrono::{DateTime, TimeZone as _, Utc};

    use super::*;

    fn account(
        profile: &str,
        principal: &str,
        service: &str,
        full_id: &str,
        device: &str,
        route: &str,
    ) -> ActiveAccountContext {
        ActiveAccountContext::new(
            profile.to_owned(),
            arkret_sdk::PrincipalAuthorityKey::new(
                arkret_sdk::DidCoreId::new(principal.to_owned()).unwrap(),
                arkret_sdk::DidCoreId::new(service.to_owned()).unwrap(),
            ),
            arkret_sdk::PrincipalResolutionProjection {
                full_id: arkret_sdk::DidFullId::new(full_id.to_owned()).unwrap(),
                method_history_head: "head-1".to_owned(),
                version_id: "1".to_owned(),
                resolution_event_ref: format!("ak:event:{}", "A".repeat(44)),
                updated_at: Utc.with_ymd_and_hms(2026, 8, 22, 12, 0, 0).unwrap(),
            },
            arkret_sdk::DeviceId::new(device.to_owned()).unwrap(),
            Url::parse(route).unwrap(),
        )
        .unwrap()
    }

    fn alice(service: &str, route: &str) -> ActiveAccountContext {
        account(
            "ak:profile:019b0000-0000-7000-8000-000000000001",
            "ak:did_core:webvh:zAlice",
            service,
            "did:webvh:zAlice:users.example:alice",
            "ak:device:019b0000-0000-7000-8000-000000000001",
            route,
        )
    }

    #[test]
    fn default_config_is_signed_out_without_placeholder_identity() {
        let config = ClientConfig::default();
        assert!(config.active_account.is_none());
        assert!(config.session_credential.is_empty());
        assert_eq!(
            config.principal_servers,
            vec![Url::parse("https://local.host").unwrap()]
        );
    }

    #[test]
    fn profile_upsert_keys_only_by_authority_pair() {
        let mut profiles = MultiProfileConfig::default();
        let first = alice("ak:did_core:webvh:zServerA", "https://principal-a.example/");
        let stable_profile_id = profiles
            .upsert_and_activate(AccountProfile::new(first.clone(), "token-a".to_owned()))
            .unwrap();

        let mut relocated = first;
        relocated.resolution = arkret_sdk::PrincipalResolutionProjection {
            full_id: arkret_sdk::DidFullId::new(
                "did:webvh:zAlice:new.example:people:alice".to_owned(),
            )
            .unwrap(),
            method_history_head: "head-2".to_owned(),
            version_id: "2".to_owned(),
            resolution_event_ref: format!("ak:event:{}", "B".repeat(44)),
            updated_at: Utc.with_ymd_and_hms(2026, 8, 22, 12, 1, 0).unwrap(),
        };
        relocated.server_url = Url::parse("https://principal-a-mirror.example/").unwrap();
        let updated_profile_id = profiles
            .upsert_and_activate(AccountProfile::new(relocated, "token-b".to_owned()))
            .unwrap();

        assert_eq!(profiles.profiles.len(), 1);
        assert_eq!(stable_profile_id, updated_profile_id);
        assert_eq!(
            profiles.active().unwrap().account.resolution.version_id,
            "2"
        );
        assert_eq!(
            profiles.active().unwrap().account.server_url.as_str(),
            "https://principal-a-mirror.example/"
        );
    }

    #[test]
    fn same_principal_on_different_authority_is_a_distinct_profile_and_secret() {
        let first = alice("ak:did_core:webvh:zServerA", "https://principal-a.example/");
        let second = alice("ak:did_core:webvh:zServerB", "https://principal-b.example/");
        let mut profiles = MultiProfileConfig::default();
        profiles
            .upsert_and_activate(AccountProfile::new(first.clone(), "token-a".to_owned()))
            .unwrap();
        profiles
            .upsert_and_activate(AccountProfile::new(second.clone(), "token-b".to_owned()))
            .unwrap();

        assert_eq!(profiles.profiles.len(), 2);
        assert_ne!(
            session_credential_secret_key(&first).unwrap(),
            session_credential_secret_key(&second).unwrap()
        );
    }

    #[test]
    fn persisted_config_and_profile_reject_unknown_or_old_identity_shapes() {
        assert!(
            serde_json::from_value::<ClientConfig>(serde_json::json!({
                "server_url": "https://principal.example",
                "principal_servers": ["https://principal.example"],
                "principal_id": "ak:did_core:web:alice.example",
                "device_id": "ak:device:019b0000-0000-7000-8000-000000000001",
                "session_credential": ""
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<MultiProfileConfig>(serde_json::json!({
                "active_profile_id": null,
                "profiles": [],
                "active_principal": "ak:did_core:web:shadow.example"
            }))
            .is_err()
        );
    }

    #[test]
    fn validate_server_url_allows_https_and_loopback_http() {
        assert!(validate_server_url("https://arkret.example").is_ok());
        assert!(validate_server_url("http://127.0.0.1:8787").is_ok());
        assert!(validate_server_url("http://arkret.example").is_err());
    }
}
