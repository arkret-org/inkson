//! Agent mode reads consume the original exact cut through the accepted own Station.
use arkret_sdk::exact_current_state::{ExactCurrentState, ExactCurrentStateReadResponseBody};
use arkret_sdk::{
    AccountId, AgentInteractionCurrentValue, AgentInteractionMode, AgentInteractionSetPayload,
    CurrentRevision, RealmId,
};

pub(crate) async fn read(
    http: &arkret_sdk::http_client::Client,
    realm: &RealmId,
    agent: &AccountId,
) -> anyhow::Result<(
    AgentInteractionMode,
    Option<CurrentRevision>,
    Option<AccountId>,
)> {
    let client = crate::transport::own_station_results::client_for_http(http).await?;
    let response =
        garth::own_station_results::read_own_station_agent_interaction(&client, realm, agent)
            .await?;
    let current = response.into_value()?;
    match current {
        ExactCurrentStateReadResponseBody::NeverWritten { .. } => {
            Ok((AgentInteractionMode::Private, None, None))
        }
        ExactCurrentStateReadResponseBody::Present {
            current_state: ExactCurrentState::AgentInteraction(entry),
            ..
        } => Ok((
            entry.value.interaction_mode,
            Some(entry.revision),
            Some(entry.value.controller_account_id),
        )),
        _ => anyhow::bail!("Agent mode read returned another current family"),
    }
}

pub(crate) async fn write(
    http: &arkret_sdk::http_client::Client,
    realm: RealmId,
    agent: AccountId,
    controller: AccountId,
    mode: AgentInteractionMode,
) -> anyhow::Result<AgentInteractionCurrentValue> {
    let (_, revision, owner) = read(http, &realm, &agent).await?;
    anyhow::ensure!(
        owner.as_ref().is_none_or(|owner| owner == &controller),
        "Agent mode controller differs from current binding"
    );
    let payload = AgentInteractionSetPayload {
        agent_account_id: agent.clone(),
        controller_account_id: controller.clone(),
        interaction_mode: mode,
        expected_commit_id: revision.map(|revision| revision.commit_id),
    };
    let operation = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::AgentInteractionSet,
    >(realm.as_str(), controller.principal_id.as_str(), payload)
    .build_sdk_event("inkson")?;
    anyhow::ensure!(
        operation.actor_id().as_account_id() == Some(&controller),
        "Agent mode producer changed account"
    );
    let accepted = crate::app::runtime_adapter::event_submitter(http.clone())
        .submit_sdk_event(&operation)
        .await?;
    anyhow::ensure!(
        accepted.is_committed(),
        "Agent mode submission was not committed"
    );
    let (actual, revision, owner) = read(http, &realm, &agent).await?;
    let commit = accepted
        .commit
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Agent mode submission omits Commit"))?;
    anyhow::ensure!(
        actual == mode
            && owner.as_ref() == Some(&controller)
            && revision
                .as_ref()
                .is_some_and(|r| r.commit_id == commit.commit_id
                    && r.stream_position == commit.stream_position),
        "Agent mode changed before confirmation"
    );
    Ok(AgentInteractionCurrentValue {
        controller_account_id: controller,
        interaction_mode: actual,
    })
}

/// Recheck selected shared Agent targets before uploads or encryption.
pub(crate) async fn require_public_targets(
    base: &str,
    credential: String,
    realm: &str,
    agents: Vec<AccountId>,
) -> anyhow::Result<()> {
    if agents.is_empty() {
        return Ok(());
    }
    let realm = RealmId::new(realm.to_owned())?;
    crate::transport::auth::with_authed_sdk_client(base, credential, |http| async move {
        for agent in agents {
            let (mode, ..) = read(&http, &realm, &agent).await?;
            anyhow::ensure!(
                mode == AgentInteractionMode::Public,
                "Agent mode changed; keep the draft and compose a new private request"
            );
        }
        Ok(())
    })
    .await
    .map_err(|error| anyhow::anyhow!(error.display()))
}

/// This is invoked only by the explicit per-Sidecar recipient action.
pub(crate) async fn enable_private_replies(
    http: &arkret_sdk::http_client::Client,
    selection: &crate::sidecar::PersonalSidecarEnrollment,
) -> anyhow::Result<()> {
    use arkret_models_collaboration::events_payloads::sidecar::{SidecarMemberStatePayload, SidecarMembership};
    let fence = crate::transport::auth::AuthoringSessionFence::capture()?;
    let actor = arkret_sdk::ActorId::account(selection.owner.clone());
    let scope = arkret_sdk::ScopeRef::Sidecar { realm_id: selection.realm.clone(), sidecar_id: selection.sidecar.clone() };
    let view = http.agent_sidecar_get(&selection.sidecar).await?;
    anyhow::ensure!(view.sidecar.controller_account_id == selection.owner && view.sidecar.realm_id == selection.realm
        && view.sidecar.source_realm_id.as_str() == selection.project, "private recipient selection changed");
    let submitter = crate::app::runtime_adapter::event_submitter(http.clone()).with_authority(selection.owner.clone());
    let mut latest = std::collections::BTreeMap::new();
    let mut before = None;
    loop {
        fence.check()?;
        let scan = arkret_sdk::StreamScanRequestBody { realm_id: selection.realm.clone(),
            stream_ref: arkret_sdk::CommitStreamRef::Sidecar { realm_id: selection.realm.clone(), sidecar_id: selection.sidecar.clone() },
            direction:arkret_sdk::StreamScanDirection::Before(before), limit:100 };
        let page=http.scan_commit_stream(&scan).await?;
        page.validate_for_request(&scan)?;
        for row in &page.committed_events {
            let event = row.reducer_input().ok_or_else(|| anyhow::anyhow!("private enrollment history is incomplete"))?;
            if event.kind != arkret_sdk::EventKind::SidecarMemberState {continue;}
            anyhow::ensure!(event.scope_ref==scope && event.actor_id==actor,"invalid private enrollment source");
            let value:SidecarMemberStatePayload=serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            if selection.agents.contains(&value.agent_account_id) {
                let account =value.agent_account_id.clone();
                let pos = row.commit().stream_position;
                let last=latest.entry(account).or_insert((pos,event.event_id.clone(),value.clone()));
                if pos>last.0 {*last=(pos,event.event_id.clone(),value);}
            }
        }
        if !page.truncated || latest.len()==selection.agents.len() {break;}
        let first=page.committed_events.iter().map(|row|row.commit().stream_position).min().ok_or_else(||anyhow::anyhow!("incomplete private enrollment page"))?;
        anyhow::ensure!(before.is_none_or(|p|first<p),"private history failed to advance");
        before=Some(first);
    }
    for agent in &selection.agents {
        fence.check()?;
        anyhow::ensure!(agent.station_id==selection.owner.station_id && agent!=&selection.owner,"invalid private recipient");
        let previous=latest.get(agent);
        if previous.is_some_and(|(_,_,value)|value.membership==SidecarMembership::Join && value.private_reply_allowed==Some(true)) {continue;}
        let payload=SidecarMemberStatePayload {agent_account_id:agent.clone(),membership:SidecarMembership::Join,
            predecessor_event_ref:previous.map(|(_,id,_)|id.clone()),private_reply_allowed:Some(true)};
        let operation=crate::operation::TypedOperationBuilder::new_for_actor::<arkret_sdk::event_spec::SidecarMemberState>(
            scope.clone(),actor.clone(),payload).build_sdk_event("inkson")?;
        let result=submitter.submit_sdk_event(&operation).await?;
        anyhow::ensure!(result.is_committed(),"private recipient change was not accepted");
    }
    Ok(())
}
