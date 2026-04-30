#[cfg(not(target_arch = "wasm32"))]
use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use url::Url;

const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8787";
const DEFAULT_ACCOUNT_DID: &str = "did:web:alice.example";
const DEFAULT_DEVICE_ID: &str = "dev_yougen";
#[cfg(target_arch = "wasm32")]
const CONFIG_STORAGE_KEY: &str = "yougen.config.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    pub server_url: String,
    pub account_did: String,
    pub device_id: String,
    pub session_token: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_SERVER_URL.to_owned(),
            account_did: DEFAULT_ACCOUNT_DID.to_owned(),
            device_id: DEFAULT_DEVICE_ID.to_owned(),
            session_token: String::new(),
        }
    }
}

impl ClientConfig {
    pub fn from_fields(
        server_url: impl Into<String>,
        account_did: impl Into<String>,
        device_id: impl Into<String>,
        session_token: impl Into<String>,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            account_did: account_did.into(),
            device_id: device_id.into(),
            session_token: session_token.into(),
        }
    }
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
    #[cfg(not(target_arch = "wasm32"))]
    path: PathBuf,
}

impl Default for LocalConfigStore {
    fn default() -> Self {
        Self {
            cached: None,
            #[cfg(not(target_arch = "wasm32"))]
            path: default_config_path(),
        }
    }
}

impl LocalConfigStore {
    pub fn load(&self) -> ClientConfig {
        self.cached
            .clone()
            .or_else(|| self.read_persisted_config())
            .unwrap_or_default()
    }

    pub fn save(&mut self, config: ClientConfig) {
        self.cached = Some(config);
        let _ = self.flush();
    }

    pub fn flush(&self) -> anyhow::Result<()> {
        if let Some(config) = &self.cached {
            self.write_persisted_config(config)?;
        }
        Ok(())
    }

    pub fn save_fields(
        &mut self,
        server_url: String,
        account_did: String,
        device_id: String,
        session_token: String,
    ) {
        self.save(ClientConfig::from_fields(
            server_url,
            account_did,
            device_id,
            session_token,
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub fn with_path(path: impl Into<PathBuf>) -> Self {
        Self {
            cached: None,
            path: path.into(),
        }
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

    #[cfg(not(target_arch = "wasm32"))]
    fn write_persisted_config(&self, config: &ClientConfig) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.path, serde_json::to_vec_pretty(config)?)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_persisted_config(&self, config: &ClientConfig) -> anyhow::Result<()> {
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
    std::env::var_os("CLIENTX_CONFIG_PATH")
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
        .join("yougen")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn default_config_matches_dev_server_bootstrap() {
        let config = ClientConfig::default();
        assert_eq!(config.server_url, "http://127.0.0.1:8787");
        assert_eq!(config.account_did, "did:web:alice.example");
        assert_eq!(config.device_id, "dev_yougen");
        assert!(config.session_token.is_empty());
    }

    #[test]
    fn validate_server_url_allows_https_and_loopback_http() {
        assert_eq!(
            validate_server_url("https://contrix.example")
                .unwrap()
                .as_str(),
            "https://contrix.example/"
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
        let error = validate_server_url("http://contrix.example").unwrap_err();
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
            "http://serverx.local".to_owned(),
            "did:web:bob.example".to_owned(),
            "dev_bob".to_owned(),
            "sx_token".to_owned(),
        );

        assert_eq!(
            store.load(),
            ClientConfig::from_fields(
                "http://serverx.local",
                "did:web:bob.example",
                "dev_bob",
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
            "dev_persisted".to_owned(),
            "sx_persisted".to_owned(),
        );

        let reader = LocalConfigStore::with_path(path);
        assert_eq!(
            reader.load(),
            ClientConfig::from_fields(
                "http://persisted.local",
                "did:web:persisted.example",
                "dev_persisted",
                "sx_persisted",
            )
        );
    }

    fn temp_config_path(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("yougen-{name}-{stamp}.json"))
    }
}
