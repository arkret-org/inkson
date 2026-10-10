use super::*;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeDiscoveryProgress {
    pub cursor: Option<String>,
    pub pending: Vec<arkret_sdk::EventId>,
    pub next_cursor: Option<String>,
    pub exhausted: bool,
    pub observed_frontier: Vec<String>,
    pub key_material_hint: String,
}

impl MlsWelcomeDiscoveryProgress {
    #[cfg(test)]
    pub(crate) fn observe_inputs(&mut self, frontier: Vec<String>, key_material_hint: String) {
        if self.key_material_hint != key_material_hint
            || (self.exhausted && self.observed_frontier != frontier)
        {
            *self = Self::default();
        }
        self.observed_frontier = frontier;
        self.key_material_hint = key_material_hint;
    }
}

impl LocalStateStore {
    #[cfg(test)]
    pub(crate) fn welcome_discovery_progress(&self, key: &str) -> MlsWelcomeDiscoveryProgress {
        self.cached
            .mls_welcome_discovery
            .get(key)
            .cloned()
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn save_welcome_discovery_progress(
        &mut self,
        key: String,
        value: Option<MlsWelcomeDiscoveryProgress>,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        match value {
            Some(value) => {
                self.cached.mls_welcome_discovery.insert(key, value);
            }
            None => {
                self.cached.mls_welcome_discovery.remove(&key);
            }
        }
        self.flush()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn restored_private_key_reopens_exhausted_window_without_frontier_change() {
        let mut progress = MlsWelcomeDiscoveryProgress {
            exhausted: true,
            observed_frontier: vec!["same-head".into()],
            key_material_hint: "missing-private-key".into(),
            ..Default::default()
        };
        progress.observe_inputs(vec!["same-head".into()], "missing-private-key".into());
        assert!(progress.exhausted);
        progress.observe_inputs(vec!["same-head".into()], "restored-private-key".into());
        assert!(!progress.exhausted);
        assert!(progress.cursor.is_none());
        progress.cursor = Some("resume".into());
        progress.observe_inputs(vec!["new-head".into()], "restored-private-key".into());
        assert_eq!(progress.cursor.as_deref(), Some("resume"));
    }

    #[tokio::test]
    async fn welcome_continuation_survives_restart_and_resets_only_one_scope() {
        let path = std::env::temp_dir().join(format!(
            "inkson-welcome-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = LocalStateStore::with_path(&path);
        let progress = MlsWelcomeDiscoveryProgress {
            cursor: Some("opaque-next".into()),
            ..Default::default()
        };
        store
            .save_welcome_discovery_progress("scope-a".into(), Some(progress.clone()))
            .unwrap();
        store
            .save_welcome_discovery_progress("scope-b".into(), Some(progress))
            .unwrap();
        store.begin_durable_flush().unwrap().wait().await.unwrap();
        let mut restored = LocalStateStore::with_path(&path);
        restored.ensure_cached_loaded();
        assert_eq!(
            restored
                .welcome_discovery_progress("scope-a")
                .cursor
                .as_deref(),
            Some("opaque-next")
        );
        restored
            .save_welcome_discovery_progress("scope-a".into(), None)
            .unwrap();
        restored
            .begin_durable_flush()
            .unwrap()
            .wait()
            .await
            .unwrap();
        assert!(
            restored
                .welcome_discovery_progress("scope-a")
                .cursor
                .is_none()
        );
        assert_eq!(
            restored
                .welcome_discovery_progress("scope-b")
                .cursor
                .as_deref(),
            Some("opaque-next")
        );
    }
}
