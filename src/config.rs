use serde::{Deserialize, Serialize};

const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8787";
const DEFAULT_ACCOUNT_DID: &str = "did:web:alice.example";
const DEFAULT_DEVICE_ID: &str = "dev_clientx";

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

#[derive(Clone, Debug, Default)]
pub struct LocalConfigStore {
    cached: Option<ClientConfig>,
}

impl LocalConfigStore {
    pub fn load(&self) -> ClientConfig {
        self.cached.clone().unwrap_or_default()
    }

    pub fn save(&mut self, config: ClientConfig) {
        self.cached = Some(config);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_dev_server_bootstrap() {
        let config = ClientConfig::default();
        assert_eq!(config.server_url, "http://127.0.0.1:8787");
        assert_eq!(config.account_did, "did:web:alice.example");
        assert_eq!(config.device_id, "dev_clientx");
        assert!(config.session_token.is_empty());
    }

    #[test]
    fn local_config_store_round_trips_latest_config() {
        let mut store = LocalConfigStore::default();
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
}
