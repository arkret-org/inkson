//! Account-private Applet intents share the existing durable outbound vault.

use arkret_models_integration::{
    AppletConfigurationAdmissionStatus as Status, AppletConfigurationCommand,
    AppletConfigurationIntent, AppletConfigurationRequestBody, AppletConfigurationResponseBody,
};

use super::*;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigurationRecord {
    pub authority: arkret_sdk::AccountId,
    pub applet_id: arkret_sdk::AppletId,
    pub intent: AppletConfigurationIntent,
    pub outcome: Option<AppletConfigurationResponseBody>,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    fn original() -> ConfigurationRecord {
        ConfigurationRecord {
            authority: arkret_sdk::AccountId::new(
                "ak:did_core:web:admin.example".parse().unwrap(),
                "ak:did_core:web:account.example".parse().unwrap(),
            ),
            applet_id: "ak:applet:01904100-0000-7000-8000-000000000011"
                .parse()
                .unwrap(),
            intent: AppletConfigurationIntent {
                request_id: arkret_wire::new_prefixed_uuid7("ak:request:")
                    .parse()
                    .unwrap(),
                service_id: "ak:did_core:web:applet.example".parse().unwrap(),
                effective_scope: arkret_sdk::ScopeRef::realm(arkret_sdk::RealmId::from_event_id(
                    &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [71; 32]),
                )),
                selection: arkret_models_integration::AppletConfigurationSelection::NewBot {
                    display_name: Some("Helper".into()),
                },
            },
            outcome: None,
        }
    }

    #[tokio::test]
    async fn cold_retry_retains_original_and_other_service_has_independent_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("outbound.json");
        let candidate = original();
        let store = InksonOutboundStore::for_test_path(path.clone());
        let frozen = store
            .freeze_applet_configuration(candidate.clone())
            .await
            .unwrap();
        drop(store);
        let store = InksonOutboundStore::for_test_path(path);
        let retry = store.freeze_applet_configuration(original()).await.unwrap();
        assert_eq!(retry.intent.request_id, frozen.intent.request_id);
        let mut conflict = original();
        conflict.intent.selection =
            arkret_models_integration::AppletConfigurationSelection::NewBot {
                display_name: Some("Another".into()),
            };
        assert!(store.freeze_applet_configuration(conflict).await.is_err());
        let mut other = original();
        other.intent.service_id = "ak:did_core:web:other-applet.example".parse().unwrap();
        store.freeze_applet_configuration(other).await.unwrap();
        assert_eq!(
            store
                .pending_applet_configurations(&candidate.authority)
                .await
                .unwrap()
                .len(),
            2
        );
        let outcome = AppletConfigurationResponseBody {
            request_id: frozen.intent.request_id.clone(),
            intent_digest: format!("sha256:{}", "7".repeat(64)).parse().unwrap(),
            source_response_body: None,
            admission_status: Status::Cancelled,
            review_request_id: None,
        };
        let final_record = store
            .retain_applet_configuration_outcome(&frozen, outcome.clone())
            .await
            .unwrap();
        assert!(!final_record.pending());
        let mut stale = outcome;
        stale.admission_status = Status::Pending;
        assert!(
            !store
                .retain_applet_configuration_outcome(&frozen, stale)
                .await
                .unwrap()
                .pending()
        );
        let mut wrong_account = candidate.authority.clone();
        wrong_account.station_id = "ak:did_core:web:wrong.example".parse().unwrap();
        assert!(
            store
                .pending_applet_configurations(&wrong_account)
                .await
                .is_err()
        );
    }
}

impl ConfigurationRecord {
    pub fn pending(&self) -> bool {
        self.outcome.as_ref().is_none_or(|outcome| {
            matches!(
                outcome.admission_status,
                Status::NotStarted | Status::Pending
            )
        })
    }

    pub fn request(&self, command: AppletConfigurationCommand) -> AppletConfigurationRequestBody {
        AppletConfigurationRequestBody {
            command,
            intent: self.intent.clone(),
            approval_signatures: None,
        }
    }

    pub(super) fn validate(&self) -> garth::Result<()> {
        self.request(AppletConfigurationCommand::Configure)
            .validate()
            .map_err(|error| garth::Error::Storage(error.to_string()))?;
        if let Some(outcome) = &self.outcome
            && (outcome.request_id != self.intent.request_id
                || outcome.source_response_body.as_ref().is_some_and(|source| {
                    source.request_id != self.intent.request_id
                        || source.service_id != self.intent.service_id
                        || source.intent_digest != outcome.intent_digest
                }))
        {
            return Err(garth::Error::Storage(
                "Applet result differs from its frozen intent".into(),
            ));
        }
        Ok(())
    }
}

impl InksonOutboundStore {
    fn check_configuration_owner(&self, authority: &arkret_sdk::AccountId) -> garth::Result<()> {
        if self.account_id().is_some_and(|owner| owner != authority) {
            return Err(garth::Error::Storage(
                "Applet intent belongs to another Account vault".into(),
            ));
        }
        Ok(())
    }

    pub(crate) async fn pending_applet_configurations(
        &self,
        authority: &arkret_sdk::AccountId,
    ) -> garth::Result<Vec<ConfigurationRecord>> {
        self.check_configuration_owner(authority)?;
        self.mutate_state(|state| {
            if state
                .applet_configurations
                .iter()
                .any(|record| &record.authority != authority)
            {
                return Err(garth::Error::Storage(
                    "Applet intent belongs to another Account vault".into(),
                ));
            }
            Ok(state
                .applet_configurations
                .iter()
                .filter(|record| record.pending())
                .cloned()
                .collect())
        })
        .await
    }

    pub(crate) async fn freeze_applet_configuration(
        &self,
        candidate: ConfigurationRecord,
    ) -> garth::Result<ConfigurationRecord> {
        self.check_configuration_owner(&candidate.authority)?;
        candidate.validate()?;
        self.mutate_state(|state| {
            if let Some(original) = state.applet_configurations.iter().find(|record| {
                record.authority == candidate.authority
                    && record.applet_id == candidate.applet_id
                    && record.intent.service_id == candidate.intent.service_id
                    && record.intent.effective_scope.realm_id()
                        == candidate.intent.effective_scope.realm_id()
                    && record.pending()
            }) {
                if original.intent.effective_scope != candidate.intent.effective_scope
                    || original.intent.selection != candidate.intent.selection
                {
                    return Err(garth::Error::Storage(
                        "resolve the existing Applet intent before starting another".into(),
                    ));
                }
                return Ok(original.clone());
            }
            if state
                .applet_configurations
                .iter()
                .any(|record| record.intent.request_id == candidate.intent.request_id)
            {
                return Err(garth::Error::Storage(
                    "Applet request id already has an original".into(),
                ));
            }
            state.applet_configurations.push(candidate.clone());
            Ok(candidate)
        })
        .await
    }

    pub(crate) async fn retain_applet_configuration_outcome(
        &self,
        original: &ConfigurationRecord,
        outcome: AppletConfigurationResponseBody,
    ) -> garth::Result<ConfigurationRecord> {
        self.check_configuration_owner(&original.authority)?;
        let mut next = original.clone();
        next.outcome = Some(outcome);
        next.validate()?;
        self.mutate_state(|state| {
            let saved = state
                .applet_configurations
                .iter_mut()
                .find(|record| record.intent.request_id == original.intent.request_id)
                .ok_or_else(|| {
                    garth::Error::Storage("Applet intent original is unavailable".into())
                })?;
            if saved.authority != original.authority
                || saved.applet_id != original.applet_id
                || saved.intent != original.intent
            {
                return Err(garth::Error::Storage(
                    "Applet intent changed before result persistence".into(),
                ));
            }
            if !saved.pending() {
                return Ok(saved.clone());
            }
            if let Some(previous) = &saved.outcome
                && next
                    .outcome
                    .as_ref()
                    .is_some_and(|outcome| outcome.intent_digest != previous.intent_digest)
            {
                return Err(garth::Error::Storage(
                    "Applet execution intent changed across retries".into(),
                ));
            }
            *saved = next.clone();
            Ok(next)
        })
        .await
    }
}
