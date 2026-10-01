//! Durable creator recovery status and explicit rejected-attempt retry.

use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};

fn creator_scope(realm: String, circle: Option<String>) -> anyhow::Result<arkret_sdk::ScopeRef> {
    let realm_id = arkret_sdk::RealmId::new(realm)?;
    Ok(match circle {
        Some(circle) => arkret_sdk::ScopeRef::Circle {
            realm_id,
            circle_id: arkret_sdk::CircleId::new(circle)?,
        },
        None => arkret_sdk::ScopeRef::Realm { realm_id },
    })
}

#[component]
pub(crate) fn CreatorMlsRetry(
    realm_id: ReadSignal<String>,
    circle_id: Option<String>,
    refresh_hint: ReadSignal<String>,
    token: Signal<String>,
) -> Element {
    let context = crate::app::SessionContext::get();
    let mut busy = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut revision = use_signal(|| 0u64);
    use_future(move || async move {
        let mut changes = crate::outbound_store::subscribe_committed_changes();
        while changes.changed().await.is_ok() {
            let next = (*revision.peek()).wrapping_add(1);
            revision.set(next);
        }
    });
    use_effect(move || {
        let _ = realm_id();
        status.set(String::new());
    });
    let recovery_circle = circle_id.clone();
    let recovery = use_resource(move || {
        let realm = realm_id();
        let circle = recovery_circle.clone();
        let _ = refresh_hint();
        let _ = revision();
        let account = context.active_account();
        let base = (context.base_url)();
        let credential = token();
        async move {
            let Some(account) = account else {
                return (false, false);
            };
            let Ok(scope) = creator_scope(realm, circle) else {
                return (false, false);
            };
            let Ok(api) = crate::transport::auth::authed_api_ready(&base, credential).await else {
                return (false, false);
            };
            let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                .with_authority(account.authority.clone());
            let record = match submitter.creator_bootstrap_record(&scope).await {
                Ok(record) => record,
                // Detection commits quarantine then stops that caller. Re-read
                // committed state for presentation without retrying authoring.
                Err(_) => submitter
                    .creator_bootstrap_record(&scope)
                    .await
                    .ok()
                    .flatten(),
            };
            match record {
                Some(record) => (
                    record.rejection().is_some()
                        && record.intent().creator_device_id() == &account.device_id,
                    record.quarantine_diagnostic().is_some(),
                ),
                None => (false, false),
            }
        }
    });
    let (retryable, quarantined) = recovery().unwrap_or((false, false));
    if quarantined {
        return rsx! {
            div { class: "muted", role: "status", "data-testid": "creator-mls-quarantined",
                {crate::i18n::tr("setup.progress.mls_quarantined")}
            }
        };
    }
    if !retryable && !busy() && status().is_empty() {
        return rsx! {};
    }
    let pending = crate::i18n::tr("setup.action.finishing");
    let success = crate::i18n::tr("setup.progress.mls_ready_local");
    rsx! {
        div { class: "actions", "data-testid": "creator-mls-retry",
            if retryable || busy() {
                Button {
                    variant: ButtonVariant::Secondary,
                    disabled: busy(),
                    "data-testid": "creator-mls-retry-button",
                    onclick: move |_| {
                        let Some(account) = context.active_account() else { return; };
                        let realm = realm_id();
                        let circle = circle_id.clone();
                        let base = (context.base_url)();
                        let credential = token();
                        let state_store = crate::app::runtime_adapter::state_store_handle(context.state_store);
                        let success = success.clone();
                        busy.set(true);
                        status.set(pending.clone());
                        spawn(async move {
                            let result = async {
                                let scope = creator_scope(realm.clone(), circle)?;
                                let api = crate::transport::auth::authed_api_ready(&base, credential).await?;
                                let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                                    .with_authority(account.authority.clone());
                                let record = submitter.creator_bootstrap_record(&scope).await?
                                    .ok_or_else(|| anyhow::anyhow!("creator retry lost its durable record"))?;
                                anyhow::ensure!(record.rejection().is_some(), "creator attempt is no longer rejected");
                                anyhow::ensure!(record.intent().creator_device_id() == &account.device_id,
                                    "creator retry requires the original device");
                                if matches!(scope, arkret_sdk::ScopeRef::Circle { .. }) {
                                    crate::mls::creator_bootstrap::ensure_creator_circle_mls_genesis(
                                        &api, &state_store, &scope, &account.authority, &account.device_id, true,
                                    ).await.map_err(anyhow::Error::msg)
                                } else {
                                    crate::mls::creator_bootstrap::start_creator_realm_mls_genesis(
                                        &api, &state_store, &realm, &account.authority, &account.device_id,
                                    ).await.map_err(anyhow::Error::msg)
                                }
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
