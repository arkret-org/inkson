//! Agent mode reads consume the original exact cut through the accepted own Station.
use arkret_sdk::exact_current_results::{ExactCurrentResultEntry, ExactCurrentResultsReadOutcome};
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
        ExactCurrentResultsReadOutcome::NeverWritten { .. } => {
            Ok((AgentInteractionMode::Private, None, None))
        }
        ExactCurrentResultsReadOutcome::Present {
            entry: ExactCurrentResultEntry::AgentInteraction(entry),
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
        expected_revision: revision,
    };
    let operation = crate::operation::TypedOperationBuilder::new::<
        arkret_sdk::event_spec::AgentInteractionSet,
    >(realm.as_str(), controller.principal_id.as_str(), payload)
    .build_sdk_event("inkson")?;
    anyhow::ensure!(
        operation.actor_id().as_account_id() == Some(&controller),
        "Agent mode producer changed account"
    );
    let accepted = crate::event_submit::EventSubmitter::from_current_session(http.clone())
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
