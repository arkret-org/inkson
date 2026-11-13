//! Close a consumed request before starting a later history window. A newer
//! missing source must not keep retrying an already completed smaller cut.

use super::*;

pub(super) async fn complete_covered_window(
    source: &OwnStationStateClient,
    state: &StateStoreHandle,
    vault: &HistoryExchangeVault<'_>,
    scope: &ScopeRef,
    originals: &[Event],
) -> anyhow::Result<()> {
    let Some(pending) = vault.request(scope).await? else {
        return Ok(());
    };
    if !pending.has_private_key() {
        return Ok(());
    }
    let request = pending.event().as_mls_history_request()?;
    let accepted = garth::own_station_results::read_window_dependency_by_event_id(
        source,
        &pending.event().event_id,
    )
    .await?;
    anyhow::ensure!(
        accepted.full()?.event == *pending.event(),
        "consumed history request differs from its accepted original"
    );
    let active = require_reader(source, state)?;
    for event in originals.iter().filter(|event| event.scope_ref == *scope) {
        let dependency =
            garth::own_station_results::read_window_dependency_by_event_id(source, &event.event_id)
                .await?;
        let full = dependency.full()?;
        anyhow::ensure!(
            full.event == *event && full.commit.stream_ref == request.history_cut.stream_ref,
            "history completion source differs from its accepted scope"
        );
        if full.commit.stream_position > request.history_cut.stream_position {
            continue;
        }
        for path in selected::paths(
            source,
            state,
            vault,
            &active.authority,
            &active.device_id,
            full,
        )
        .await?
        {
            if selected::held(
                source,
                state,
                vault,
                &active.authority,
                &active.device_id,
                full,
                &path,
            )
            .await
            .is_err()
            {
                return Ok(());
            }
        }
    }
    accepted.full()?;
    require_reader(source, state)?;
    vault
        .consume_request(scope, &pending.event().event_id)
        .await?;
    Ok(())
}
