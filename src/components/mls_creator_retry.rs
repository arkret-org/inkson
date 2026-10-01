//! Explicit retry of a durable rejected creator attempt.

use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};

#[component]
pub(crate) fn CreatorMlsRetry(
    realm_id: ReadSignal<String>,
    refresh_hint: ReadSignal<String>,
    token: Signal<String>,
) -> Element {
    let context = crate::app::SessionContext::get();
    let mut busy = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut revision = use_signal(|| 0u64);
    use_effect(move || {
        let _ = realm_id();
        status.set(String::new());
    });
    let retryable = use_resource(move || {
        let realm = realm_id();
        let _ = refresh_hint();
        let _ = revision();
        let account = context.active_account();
        let base = (context.base_url)();
        let credential = token();
        async move {
            let Some(account) = account else {
                return false;
            };
            let Ok(scope_id) = arkret_sdk::RealmId::new(realm) else {
                return false;
            };
            let Ok(api) = crate::transport::auth::authed_api_ready(&base, credential).await else {
                return false;
            };
            let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                .with_authority(account.authority.clone());
            matches!(submitter.creator_bootstrap_record(&arkret_sdk::ScopeRef::Realm { realm_id: scope_id }).await,
                Ok(Some(record)) if record.rejection().is_some()
                    && record.intent().creator_device_id() == &account.device_id)
        }
    });
    if !retryable().unwrap_or(false) && !busy() && status().is_empty() {
        return rsx! {};
    }
    let pending = crate::i18n::tr("setup.action.finishing");
    let success = crate::i18n::tr("setup.progress.mls_ready_local");
    rsx! {
        div { class: "actions", "data-testid": "creator-mls-retry",
            if retryable().unwrap_or(false) || busy() {
                Button {
                    variant: ButtonVariant::Secondary,
                    disabled: busy(),
                    "data-testid": "creator-mls-retry-button",
                    onclick: move |_| {
                        let Some(account) = context.active_account() else { return; };
                        let realm = realm_id();
                        let base = (context.base_url)();
                        let credential = token();
                        let state_store = crate::app::runtime_adapter::state_store_handle(context.state_store);
                        let success = success.clone();
                        busy.set(true);
                        status.set(pending.clone());
                        spawn(async move {
                            let result = async {
                                let scope_id = arkret_sdk::RealmId::new(realm.clone())?;
                                let api = crate::transport::auth::authed_api_ready(&base, credential).await?;
                                let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                                    .with_authority(account.authority.clone());
                                let record = submitter.creator_bootstrap_record(&arkret_sdk::ScopeRef::Realm { realm_id: scope_id }).await?
                                    .ok_or_else(|| anyhow::anyhow!("creator retry lost its durable record"))?;
                                anyhow::ensure!(record.rejection().is_some(), "creator attempt is no longer rejected");
                                anyhow::ensure!(record.intent().creator_device_id() == &account.device_id,
                                    "creator retry requires the original device");
                                crate::mls::creator_bootstrap::start_creator_realm_mls_genesis(
                                    &api, &state_store, &realm, &account.authority, &account.device_id,
                                ).await.map_err(anyhow::Error::msg)
                            }.await;
                            if realm_id.peek().as_str() == realm {
                                status.set(match result { Ok(()) => success, Err(error) => error.to_string() });
                            }
                            busy.set(false);
                            revision.set(revision() + 1);
                        });
                    },
                    {crate::i18n::tr("setup.action.retry_mls")}
                }
            }
            if !status().is_empty() { span { class: "muted", "{status}" } }
        }
    }
}
