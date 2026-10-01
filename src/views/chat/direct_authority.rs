use super::*;

pub(super) fn use_direct_authority(
    base_url: String,
    realm_id: String,
    authority: arkret_sdk::AccountId,
    token: Signal<String>,
    frontier_state: Signal<String>,
    realm_live_epoch: Signal<u64>,
    state_store: SyncSignal<LocalStateStore>,
) {
    let mut seen = use_signal(String::new);
    use_effect(use_reactive!(|(base_url, realm_id, authority)| {
        let credential = token();
        let cursor = frontier_state();
        let realm_epoch = realm_live_epoch();
        let peer = state_store.read().direct_conversation_peer(&realm_id);
        let Some(peer) = peer else { return };
        let epoch = crate::identity::device_directory::cache_epoch();
        let key = format!(
            "{base_url}|{realm_id}|{authority:?}|{peer:?}|{epoch}|{cursor}|{realm_epoch}|{credential}"
        );
        if credential.is_empty() || *seen.peek() == key {
            return;
        }
        seen.set(key);
        let Ok(query_sequence) = crate::mls::direct_binding::begin_query(&authority, &peer) else {
            return;
        };
        spawn(async move {
            let state = crate::app::runtime_adapter::state_store_handle(state_store);
            let result=crate::transport::auth::with_authed_sdk_client(&base_url,credential,|http|async move {
                let outcome=http.direct_conversation_resolve(&arkret_sdk::direct_conversation::DirectConversationResolveRequestBody{peer:peer.clone()}).await?;
                anyhow::ensure!(outcome.coordinates().is_none_or(|coordinates|coordinates.realm_id.as_str()==realm_id),"Direct Conversation query returned another Realm");
                crate::mls::direct_binding::install_resolved_message_context(&http,&state,&authority,epoch,query_sequence,peer,&outcome).await
            }).await;
            if let Err(error) = result {
                tracing::debug!(?error, "Direct Conversation authoring remains pending");
            }
        });
    }));
}
