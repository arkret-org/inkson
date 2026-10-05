use super::*;

#[derive(Clone, PartialEq)]
pub(super) struct SidecarTimelineProjection {
    pub current: Result<Vec<arkret_sdk::AgentSidecarExchangeProjection>, String>,
    pub closes: Vec<(
        arkret_sdk::AgentSidecarExchangeProjection,
        arkret_sdk::AgentSidecarExchangeControl,
    )>,
    pub close_cut: Option<SidecarCloseCutFence>,
    pub private_event_ids: std::collections::BTreeSet<String>,
    pub messages: Vec<ChatMessage>,
    pub privacy_gate: crate::sidecar::SidecarPrivacyGate,
}

#[cfg(test)]
thread_local! {
    pub(super) static PROJECTION_BUILDS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One disposable read projection per store/evidence/context change. Composer,
/// panel and send-status repaints must not restore and verify private history.
pub(super) fn use_sidecar_timeline_projection(
    state_store: SyncSignal<LocalStateStore>,
    authority: arkret_sdk::AccountId,
    device: arkret_sdk::DeviceId,
    realm: String,
    evidence_epoch: u64,
) -> Memo<SidecarTimelineProjection> {
    use_memo(use_reactive(
        (&authority, &device, &realm, &evidence_epoch),
        move |(authority, device, realm, _)| {
            #[cfg(test)]
            PROJECTION_BUILDS.with(|count| count.set(count.get() + 1));
            let store = state_store.read();
            let (current, closes) =
                match crate::sidecar_fold::rebuild_with_closes(&store, &authority, &realm) {
                    Ok((projections, closes)) => (Ok(projections), closes),
                    Err(error) => (Err(format!("{error:#}")), Vec::new()),
                };
            let projections = current.as_deref().unwrap_or_default();
            let close_cut = current
                .is_ok()
                .then(|| SidecarCloseCutFence::capture(&store, &authority, &device, &realm))
                .flatten();
            let private_event_ids = projections
                .iter()
                .flat_map(|projection| {
                    std::iter::once(projection.private_request_event_id.to_string()).chain(
                        projection
                            .user_facing_response_event_ids
                            .iter()
                            .map(ToString::to_string),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>();
            let messages = if current.is_ok() {
                store
                    .verified_sidecar_inputs(&realm)
                    .ok()
                    .into_iter()
                    .flat_map(|(_, histories)| histories.into_values().flatten())
                    .filter(|full| private_event_ids.contains(full.event.event_id.as_str()))
                    .filter_map(|full| serde_json::to_value(&full.event).ok())
                    .filter_map(|event| {
                        chat_message_from_event_with_sidecar(
                            &realm,
                            &event,
                            Some(&store),
                            Some((&authority, authority.principal_id.as_str(), &device)),
                        )
                    })
                    .collect()
            } else {
                Vec::new()
            };
            let privacy_gate = crate::sidecar::SidecarPrivacyGate::from_store_with_projection(
                &store,
                authority.principal_id.as_str(),
                Some((&realm, projections)),
            );
            SidecarTimelineProjection {
                current,
                closes,
                close_cut,
                private_event_ids,
                messages,
                privacy_gate,
            }
        },
    ))
}
