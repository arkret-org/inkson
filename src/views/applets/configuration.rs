//! Administrator intent goes through the authenticated account Station.

use arkret_models_integration::{
    AppletConfigurationAdmissionStatus, AppletConfigurationCommand, AppletConfigurationIntent,
    AppletConfigurationSelection,
};

use super::*;
use crate::outbound_store::applet_configuration::ConfigurationRecord;
use crate::outbound_store::{InksonOutboundStore, OutboundLane};

async fn submit(
    base: &str,
    token: String,
    original: ConfigurationRecord,
    command: AppletConfigurationCommand,
) -> anyhow::Result<ConfigurationRecord> {
    with_event_submitter(base, token, |submitter| async move {
        anyhow::ensure!(
            submitter.authority()? == &original.authority,
            "active Account changed before Applet configuration"
        );
        let outcome = submitter
            .http()
            .applet_configuration_submit(&original.applet_id, &original.request(command))
            .await?;
        let store = InksonOutboundStore::open(&original.authority, OutboundLane::Standard)?;
        Ok(store
            .retain_applet_configuration_outcome(&original, outcome)
            .await?)
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

fn outcome_label(record: &ConfigurationRecord) -> String {
    let key = match record
        .outcome
        .as_ref()
        .map(|outcome| outcome.admission_status)
    {
        Some(AppletConfigurationAdmissionStatus::Accepted) => "applets.configure_accepted",
        Some(AppletConfigurationAdmissionStatus::Denied) => "applets.configure_denied",
        Some(AppletConfigurationAdmissionStatus::Cancelled) => "applets.configure_cancelled",
        _ => "applets.configure_pending",
    };
    tr(key)
}

#[component]
pub(super) fn ConfigurationPanel(
    token: Signal<String>,
    realm_id: String,
    applet_id: String,
    service_id: String,
) -> Element {
    let session = crate::app::SessionContext::get();
    let active_account = session.active_account;
    let base = crate::app::SessionContext::base_url_string();
    let mut name = use_signal(String::new);
    let mut circle = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut ready = use_signal(|| false);
    let mut pending = use_signal(|| None::<ConfigurationRecord>);
    let mut feedback = use_signal(String::new);
    let load_applet = applet_id.clone();
    let load_service = service_id.clone();
    let load_realm = crate::operation::trim_realm_id(&realm_id);
    use_effect(move || {
        let account = active_account().map(|account| account.authority);
        let applet = load_applet.clone();
        let service = load_service.clone();
        let realm = load_realm.clone();
        ready.set(false);
        busy.set(false);
        feedback.set(String::new());
        name.set(String::new());
        circle.set(String::new());
        pending.set(None);
        spawn(async move {
            let expected_account = account.clone();
            let result = async {
                let account =
                    account.ok_or_else(|| anyhow::anyhow!("active Account unavailable"))?;
                let store = InksonOutboundStore::open(&account, OutboundLane::Standard)?;
                let records = store.pending_applet_configurations(&account).await?;
                Ok::<_, anyhow::Error>(records.into_iter().find(|record| {
                    record.applet_id.as_str() == applet
                        && record.intent.service_id.as_str() == service
                        && record.intent.effective_scope.realm_id().as_str() == realm
                }))
            }
            .await;
            if active_account().map(|account| account.authority) != expected_account {
                return;
            }
            match result {
                Ok(record) => {
                    if let Some(record) = &record {
                        if let AppletConfigurationSelection::NewBot { display_name } =
                            &record.intent.selection
                        {
                            name.set(display_name.clone().unwrap_or_default());
                        }
                        circle.set(match &record.intent.effective_scope {
                            ScopeRef::Circle { circle_id, .. } => circle_id.to_string(),
                            _ => String::new(),
                        });
                    }
                    pending.set(record);
                    ready.set(true);
                }
                Err(error) => feedback.set(error.to_string()),
            }
        });
    });
    rsx! {
        div { class: "workflow-form", "data-testid": "applet-configuration-panel",
            Textarea {
                "data-testid": "applet-bot-name", placeholder: tr("applets.bot_name"),
                value: "{name}", disabled: busy() || pending().is_some(),
                oninput: move |event: FormEvent| name.set(event.value()),
            }
            Textarea {
                "data-testid": "applet-bot-circle", placeholder: tr("applets.circle_placeholder"),
                value: "{circle}", disabled: busy() || pending().is_some(),
                oninput: move |event: FormEvent| circle.set(event.value()),
            }
            Button {
                "data-testid": "applet-create-bot", disabled: !ready() || busy() || pending().is_some(),
                onclick: {
                    let base = base.clone();
                    move |_| {
                        let Some(account) = active_account().map(|account| account.authority) else { return };
                        let intent = (|| -> anyhow::Result<_> {
                            let scope = applet_effective_scope(&realm_id, Some(&circle())).map_err(anyhow::Error::msg)?;
                            let label = name().trim().to_owned();
                            Ok(ConfigurationRecord {
                                authority: account, applet_id: applet_id.parse()?,
                                intent: AppletConfigurationIntent {
                                    request_id: arkret_wire::new_prefixed_uuid7("ak:request:").parse()?,
                                    service_id: service_id.parse()?, effective_scope: scope,
                                    selection: AppletConfigurationSelection::NewBot { display_name: (!label.is_empty()).then_some(label) },
                                }, outcome: None,
                            })
                        })();
                        let record = match intent { Ok(record) => record, Err(error) => { feedback.set(error.to_string()); return; } };
                        let base = base.clone(); let credential = token();
                        busy.set(true);
                        spawn(async move {
                            let expected_account = record.authority.clone();
                            let result = async {
                                let store = InksonOutboundStore::open(&record.authority, OutboundLane::Standard)?;
                                let original = store.freeze_applet_configuration(record).await?;
                                if active_account().map(|account| account.authority).as_ref() != Some(&expected_account) {
                                    anyhow::bail!("active Account changed before configuration delivery");
                                }
                                pending.set(Some(original.clone()));
                                submit(&base, credential, original, AppletConfigurationCommand::Configure).await
                            }.await;
                            if active_account().map(|account| account.authority).as_ref() != Some(&expected_account) { return; }
                            match result {
                                Ok(record) => { feedback.set(outcome_label(&record)); pending.set(record.pending().then_some(record)); }
                                Err(error) => feedback.set(error.to_string()),
                            }
                            busy.set(false);
                        });
                    }
                },
                {tr("applets.create_bot")}
            }
            if let Some(original) = pending() {
                p { class: "muted", {tr("applets.configure_pending")} }
                for (command, label) in [
                    (AppletConfigurationCommand::Configure, "applets.configure_retry"),
                    (AppletConfigurationCommand::Recover, "applets.configure_recover"),
                    (AppletConfigurationCommand::Cancel, "applets.configure_cancel"),
                ] {
                    Button {
                        "data-testid": label,
                        disabled: busy(),
                        onclick: {
                            let base = base.clone(); let original = original.clone();
                            move |_| {
                                let base = base.clone(); let original = original.clone(); let credential = token();
                                busy.set(true);
                                spawn(async move {
                                    let expected_account = original.authority.clone();
                                    let result = submit(&base, credential, original, command).await;
                                    if active_account().map(|account| account.authority).as_ref() != Some(&expected_account) { return; }
                                    match result {
                                        Ok(record) => { feedback.set(outcome_label(&record)); pending.set(record.pending().then_some(record)); }
                                        Err(error) => feedback.set(error.to_string()),
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        {tr(label)}
                    }
                }
            }
            if !feedback().is_empty() {
                p { role: "status", "data-testid": "applet-configuration-status", "{feedback}" }
            }
        }
    }
}
