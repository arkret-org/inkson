use crate::mls::governance_proof::GovernanceProofStateStore;

/// Fetch only the selected artifact's acceptance and exact MLS crypto dependencies.
pub(crate) async fn fetch<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state: S,
    event: &arkret_sdk::Event,
) -> Result<crate::state::CachedMlsAcceptedArtifact, String> {
    let authority = state
        .with_read(|store| store.active_authority())
        .ok_or_else(|| "MLS acceptance requires an active account".to_owned())?;
    let session_epoch = crate::identity::device_directory::cache_epoch();
    let observed_frontier =
        state.with_read(|store| store.seal_view_for_realm(event.realm_id.as_str()).frontier);
    let binding: arkret_sdk::MlsGovernanceBindingPayload = serde_json::from_value(
        event
            .payload
            .get("governance_binding")
            .cloned()
            .ok_or_else(|| "MLS artifact lacks its binding".to_owned())?,
    )
    .map_err(|error| error.to_string())?;
    let request = arkret_sdk::MlsAcceptedArtifactRequest {
        effective_scope: binding.effective_scope().clone(),
        mls_group_id: arkret_sdk::Base64UrlString::new(binding.mls_group_id().to_owned())
            .map_err(|error| error.to_string())?,
        artifact_ref: event.event_id.clone(),
    };
    let http = api.sdk_http_client().map_err(|error| error.to_string())?;
    let outcome = http
        .mls_accepted_artifact(&request)
        .await
        .map_err(|error| error.to_string())?;
    if outcome.governance_binding != binding {
        return Err(
            "MLS artifact binding differs from the Station's accepted transition".to_owned(),
        );
    }
    let transition = if outcome.transition_head.transition_ref == event.event_id {
        event.clone()
    } else {
        resolve_exact(&http, &outcome.transition_head.transition_ref).await?
    };
    let mut proposals = std::collections::BTreeMap::new();
    if transition.kind == arkret_sdk::EventKind::MlsCommit {
        let payload: arkret_sdk::MlsCommitPayload = serde_json::from_value(
            serde_json::to_value(&transition.payload).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let mut retained_bytes = 0usize;
        for reference in payload.proposal_refs() {
            let proposal = resolve_exact(&http, reference).await?;
            retained_bytes += serde_json::to_vec(&proposal)
                .map_err(|error| error.to_string())?
                .len();
            if retained_bytes > 16 * 1024 * 1024 {
                return Err("MLS exact proposal inputs exceed the local budget".to_owned());
            }
            proposals.insert(reference.clone(), proposal);
        }
    }
    let entry = crate::state::CachedMlsAcceptedArtifact {
        request,
        outcome,
        event: event.clone(),
        transition,
        proposals,
        authority,
        session_epoch,
        observed_frontier,
        received_at: chrono::Utc::now(),
    };
    state.with_write(|store| store.cache_mls_accepted_artifact(entry.clone()))?;
    Ok(entry)
}

async fn resolve_exact(
    http: &arkret_sdk::http_client::Client,
    reference: &arkret_sdk::EventId,
) -> Result<arkret_sdk::Event, String> {
    let result = http
        .events_resolve(&arkret_sdk::EventsResolveRequestBody {
            event_ids: vec![reference.clone()],
            event_digests: vec![],
            include_payload: Some(true),
            history_traversal_access: None,
            max_response_bytes: Some(8 * 1024 * 1024),
        })
        .await
        .map_err(|error| error.to_string())?;
    if result.events.len() != 1
        || !result.missing.is_empty()
        || !result.unauthorized.is_empty()
        || result.events[0].event_id != *reference
    {
        return Err("Station did not return the exact MLS crypto dependency".to_owned());
    }
    Ok(result.events.into_iter().next().expect("one exact Event"))
}

pub(crate) async fn fetch_ref<S: GovernanceProofStateStore>(
    api: &crate::transport::TransportClient,
    state: S,
    reference: &arkret_sdk::EventId,
) -> Result<crate::state::CachedMlsAcceptedArtifact, String> {
    let http = api.sdk_http_client().map_err(|error| error.to_string())?;
    let event = resolve_exact(&http, reference).await?;
    fetch(api, state, &event).await
}
