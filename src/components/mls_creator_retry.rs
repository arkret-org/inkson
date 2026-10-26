//! Durable creator recovery status and explicit rejected-attempt retry.
use std::rc::Rc;

use glory::prelude::*;

use super::mls_backup_prompt::try_set_state;
use crate::presentation::widgets::{line, paragraph, reactive, resource};
use crate::presentation::{InksonContext, View};
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

pub(crate) struct CreatorMlsRetryProps {
    pub realm_id: Lotus<String>,
    pub circle_id: Option<String>,
    pub refresh_hint: Lotus<String>,
    pub token: Cage<String>,
}
pub(crate) fn creator_mls_retry(
    scope: &Scope,
    context: Rc<InksonContext>,
    props: CreatorMlsRetryProps,
) -> View {
    let busy = scope.cage(false);
    let status = scope.cage(String::new());
    let revision = scope.cage(0_u64);
    let _ = scope.owner().spawn(async move {
        let mut changes = crate::outbound_store::subscribe_creator_committed_changes();
        while changes.changed().await.is_ok() {
            if revision
                .try_revise(|value| *value = value.wrapping_add(1))
                .is_err()
            {
                return;
            }
        }
    });
    let realm_id = props.realm_id;
    let refresh = props.refresh_hint;
    let token = props.token;
    let realm_reset = realm_id.clone();
    scope.effect(move || {
        let _ = realm_reset.get();
        try_set_state(status, String::new());
    });
    let ctx = context.clone();
    let realm = realm_id.clone();
    let circle = props.circle_id.clone();
    let recovery = resource(scope, move || {
        let realm = realm.get();
        let circle = circle.clone();
        let _ = refresh.get();
        let _ = revision.get();
        let _ = ctx.session_generation.get();
        let account = ctx.active_account.get();
        let base = ctx.base_url.get();
        let credential = token.get();
        async move {
            let Some(account) = account else {
                return Ok((false, false));
            };
            let Ok(scope) = creator_scope(realm, circle) else {
                return Ok((false, false));
            };
            let Ok(api) = crate::transport::auth::authed_api_ready(&base, credential).await else {
                return Ok((false, false));
            };
            let submitter = crate::event_submit::EventSubmitter::new(api.http().clone())
                .with_authority(account.authority.clone());
            let record = match submitter.creator_bootstrap_record(&scope).await {
                Ok(record) => record,
                Err(_) => submitter
                    .creator_bootstrap_record(&scope)
                    .await
                    .ok()
                    .flatten(),
            };
            Ok(match record {
                Some(record) => (
                    record.rejection().is_some()
                        && record.intent().creator_device_id() == &account.device_id,
                    record.quarantine_diagnostic().is_some(),
                ),
                None => (false, false),
            })
        }
    });
    let source = scope.bond(move || (recovery.data.get(), busy.get(), status.get()));
    reactive(source, move |scope, (data, is_busy, current_status)| {
        let (retryable, quarantined) = data.and_then(|value| value.ok()).unwrap_or((false, false));
        if quarantined {
            return paragraph(
                "muted creator-mls-quarantined",
                context.translated(scope, "setup.progress.mls_quarantined"),
            );
        }
        if !retryable && !is_busy && current_status.is_empty() {
            return Box::new(widget(|_| Ok(())));
        }
        let mut children = Vec::<View>::new();
        if retryable || is_busy {
            let context = context.clone();
            let realm_id = realm_id.clone();
            let circle = props.circle_id.clone();
            let owner = scope.downgrade();
            let ctx = context.clone();
            let label = context.translated(scope, "setup.action.retry_mls");
            children.push(Box::new(sapid::button().unstyled().class("secondary creator-mls-retry-button").label(label).enabled(!is_busy).on_press(move ||{
                if busy.get(){return}let Some(scope)=owner.upgrade()else{return};let Some(account)=ctx.active_account.get()else{return};let generation=ctx.session_generation.get();let active=ctx.active_account.get();
                let realm=realm_id.get();let realm_for_result=realm.clone();let circle=circle.clone();let base=ctx.base_url.get();let credential=token.get();let state_store=ctx.state_store.handle();let context=ctx.clone();let realm_id=realm_id.clone();let owner=scope.downgrade();
                try_set_state(busy,true);try_set_state(status,ctx.tr("setup.action.finishing"));
                let _=scope.owner().spawn(async move {
                    let result=async {
                        let scope=creator_scope(realm.clone(),circle)?;
                        let api=crate::transport::auth::authed_api_ready(&base,credential).await?;
                        let submitter=crate::event_submit::EventSubmitter::new(api.http().clone()).with_authority(account.authority.clone());
                        let record=submitter.creator_bootstrap_record(&scope).await?.ok_or_else(||anyhow::anyhow!("creator retry lost its durable record"))?;
                        anyhow::ensure!(record.rejection().is_some(),"creator attempt is no longer rejected");
                        anyhow::ensure!(record.intent().creator_device_id()==&account.device_id,"creator retry requires the original device");
                        if matches!(scope,arkret_sdk::ScopeRef::Circle{..}){crate::mls::creator_bootstrap::ensure_creator_circle_mls_genesis(&api,&state_store,&scope,&account.authority,&account.device_id,true).await.map_err(anyhow::Error::msg)}else{crate::mls::creator_bootstrap::retry_creator_realm_mls_genesis(&api,&state_store,&realm,&account.authority,&account.device_id).await.map_err(anyhow::Error::msg)}
                    }.await;
                    if owner.upgrade().is_none()||!context.session_matches(generation,&active){return}
                    if realm_id.get()==realm_for_result{try_set_state(status,match result{Ok(())=>context.tr("setup.progress.mls_ready_local"),Err(error)=>error.to_string()});}
                    try_set_state(busy,false);revision.revise(|value|*value=value.wrapping_add(1));
                });
            })));
        }
        if !current_status.is_empty() {
            children.push(paragraph("muted", current_status));
        }
        line("actions creator-mls-retry", children)
    })
}
