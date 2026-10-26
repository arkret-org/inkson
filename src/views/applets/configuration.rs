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

#[derive(Clone)]
struct ConfigurationState {
    context: Rc<InksonContext>,
    realm_id: String,
    applet_id: String,
    service_id: String,
    name: Cage<String>,
    circle: Cage<String>,
    busy: Cage<bool>,
    ready: Cage<bool>,
    pending: Cage<Option<ConfigurationRecord>>,
    feedback: Cage<String>,
}
impl ConfigurationState {
    fn create(self) {
        let context = self.context.clone();
        let active_account = context.active_account;
        let token = context.token;
        let base = context.base_url.get_untracked();
        let realm_id = self.realm_id.clone();
        let applet_id = self.applet_id.clone();
        let service_id = self.service_id.clone();
        let name = self.name;
        let circle = self.circle;
        let busy = self.busy;
        let _ready = self.ready;
        let pending = self.pending;
        let feedback = self.feedback;
        let handler = {
            let base = base.clone();
            move |_| {
                let Some(account) = active_account.get().map(|account| account.authority) else {
                    return;
                };
                let intent = (|| -> anyhow::Result<_> {
                    let scope = applet_effective_scope(&realm_id, Some(&circle.get()))
                        .map_err(anyhow::Error::msg)?;
                    let label = name.get().trim().to_owned();
                    Ok(ConfigurationRecord {
                        authority: account,
                        applet_id: applet_id.parse()?,
                        intent: AppletConfigurationIntent {
                            request_id: arkret_wire::new_prefixed_uuid7("ak:request:").parse()?,
                            service_id: service_id.parse()?,
                            effective_scope: scope,
                            selection: AppletConfigurationSelection::NewBot {
                                display_name: (!label.is_empty()).then_some(label),
                            },
                        },
                        outcome: None,
                    })
                })();
                let record = match intent {
                    Ok(record) => record,
                    Err(error) => {
                        feedback.revise(|value| {
                            *value = error.to_string();
                        });
                        return;
                    }
                };
                let base = base.clone();
                let credential = token.get();
                busy.revise(|value| {
                    *value = true;
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                        let expected_account = record.authority.clone();
                        let result = async {
                            let store = InksonOutboundStore::open(
                                &record.authority,
                                OutboundLane::Standard,
                            )?;
                            let original = store.freeze_applet_configuration(record).await?;
                            if active_account
                                .get()
                                .map(|account| account.authority)
                                .as_ref()
                                != Some(&expected_account)
                            {
                                anyhow::bail!(
                                    "active Account changed before configuration delivery"
                                );
                            }
                            pending.revise(|value| {
                                *value = Some(original.clone());
                            });
                            submit(
                                &base,
                                credential,
                                original,
                                AppletConfigurationCommand::Configure,
                            )
                            .await
                        }
                        .await;
                        if active_account
                            .get()
                            .map(|account| account.authority)
                            .as_ref()
                            != Some(&expected_account)
                        {
                            return;
                        }
                        match result {
                            Ok(record) => {
                                feedback.revise(|value| {
                                    *value = outcome_label(&record);
                                });
                                pending.revise(|value| {
                                    *value = record.pending().then_some(record);
                                });
                            }
                            Err(error) => feedback.revise(|value| {
                                *value = error.to_string();
                            }),
                        }
                        busy.revise(|value| {
                            *value = false;
                        });
                    });
                };
            }
        };
        handler(());
    }
    fn command(self, original: ConfigurationRecord, command: AppletConfigurationCommand) {
        let context = self.context.clone();
        let active_account = context.active_account;
        let token = context.token;
        let base = context.base_url.get_untracked();
        let _realm_id = self.realm_id.clone();
        let _applet_id = self.applet_id.clone();
        let _service_id = self.service_id.clone();
        let _name = self.name;
        let _circle = self.circle;
        let busy = self.busy;
        let _ready = self.ready;
        let pending = self.pending;
        let feedback = self.feedback;
        let handler = {
            let base = base.clone();
            let original = original.clone();
            move |_| {
                let base = base.clone();
                let original = original.clone();
                let credential = token.get();
                busy.revise(|value| {
                    *value = true;
                });
                {
                    let task_owner = context.clone();
                    let _ = task_owner.spawn(async move {
                        let expected_account = original.authority.clone();
                        let result = submit(&base, credential, original, command).await;
                        if active_account
                            .get()
                            .map(|account| account.authority)
                            .as_ref()
                            != Some(&expected_account)
                        {
                            return;
                        }
                        match result {
                            Ok(record) => {
                                feedback.revise(|value| {
                                    *value = outcome_label(&record);
                                });
                                pending.revise(|value| {
                                    *value = record.pending().then_some(record);
                                });
                            }
                            Err(error) => feedback.revise(|value| {
                                *value = error.to_string();
                            }),
                        }
                        busy.revise(|value| {
                            *value = false;
                        });
                    });
                };
            }
        };
        handler(());
    }
}
pub(super) fn page(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm_id: String,
    applet_id: String,
    service_id: String,
) -> View {
    let state = ConfigurationState {
        context: context.clone(),
        realm_id: realm_id.clone(),
        applet_id: applet_id.clone(),
        service_id: service_id.clone(),
        name: scope.cage(String::new()),
        circle: scope.cage(String::new()),
        busy: scope.cage(false),
        ready: scope.cage(false),
        pending: scope.cage(None),
        feedback: scope.cage(String::new()),
    };
    let name = state.name;
    let circle = state.circle;
    let busy = state.busy;
    let ready = state.ready;
    let pending = state.pending;
    let feedback = state.feedback;
    let active_account = context.active_account;
    let _token = context.token;
    let load_applet = applet_id.clone();
    let load_service = service_id.clone();
    let load_realm = crate::operation::trim_realm_id(&realm_id);
    let load_context = context.clone();
    scope.effect(move || {
        let account = active_account.get().map(|account| account.authority);
        let applet = load_applet.clone();
        let service = load_service.clone();
        let realm = load_realm.clone();
        ready.revise(|value| {
            *value = false;
        });
        busy.revise(|value| {
            *value = false;
        });
        feedback.revise(|value| {
            *value = String::new();
        });
        name.revise(|value| {
            *value = String::new();
        });
        circle.revise(|value| {
            *value = String::new();
        });
        pending.revise(|value| {
            *value = None;
        });
        {
            let task_owner = load_context.clone();
            let _ = task_owner.spawn(async move {
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
                if active_account.get().map(|account| account.authority) != expected_account {
                    return;
                }
                match result {
                    Ok(record) => {
                        if let Some(record) = &record {
                            if let AppletConfigurationSelection::NewBot { display_name } =
                                &record.intent.selection
                            {
                                name.revise(|value| {
                                    *value = display_name.clone().unwrap_or_default();
                                });
                            }
                            circle.revise(|value| {
                                *value = match &record.intent.effective_scope {
                                    ScopeRef::Circle { circle_id, .. } => circle_id.to_string(),
                                    _ => String::new(),
                                };
                            });
                        }
                        pending.revise(|value| {
                            *value = record;
                        });
                        ready.revise(|value| {
                            *value = true;
                        });
                    }
                    Err(error) => feedback.revise(|value| {
                        *value = error.to_string();
                    }),
                }
            });
        };
    });

    let editable = scope.bond(move || !busy.get() && pending.get().is_none());
    let create_enabled = scope.bond(move || ready.get() && !busy.get() && pending.get().is_none());
    let st = state.clone();
    let create = action(
        scope,
        context.clone(),
        "applet-create-bot",
        "applets.create_bot",
        "secondary",
        create_enabled,
        move || st.clone().create(),
    );
    let st = state.clone();
    let commands = reactive(pending, move |scope, record| {
        let Some(record) = record else {
            return empty();
        };
        let mut children = vec![paragraph("muted", tr("applets.configure_pending"))];
        for (command, label) in [
            (
                AppletConfigurationCommand::Configure,
                "applets.configure_retry",
            ),
            (
                AppletConfigurationCommand::Recover,
                "applets.configure_recover",
            ),
            (
                AppletConfigurationCommand::Cancel,
                "applets.configure_cancel",
            ),
        ] {
            let st = st.clone();
            let record = record.clone();
            children.push(action(
                scope,
                st.context.clone(),
                label,
                label,
                "secondary",
                scope.bond(move || !busy.get()),
                move || st.clone().command(record.clone(), command),
            ));
        }
        stack("applet-configuration-commands", children)
    });
    stack(
        "workflow-form applet-configuration-panel",
        vec![
            field(
                scope,
                context.clone(),
                "applet-bot-name",
                "applets.bot_name",
                name,
                editable,
                true,
                move |next| name.revise(|v| *v = next),
            ),
            field(
                scope,
                context.clone(),
                "applet-bot-circle",
                "applets.circle_placeholder",
                circle,
                editable,
                true,
                move |next| circle.revise(|v| *v = next),
            ),
            create,
            commands,
            paragraph("muted applet-configuration-status", feedback),
        ],
    )
}
