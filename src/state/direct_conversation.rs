use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DirectMessageContext {
    pub account: arkret_sdk::AccountId,
    pub session_epoch: u64,
    pub query_sequence: u64,
    pub authority: crate::mls::direct_binding::MessageAuthority,
    pub group_state_ref: arkret_sdk::EventId,
    pub seal_ref: arkret_sdk::SealId,
}

impl LocalStateStore {
    pub(crate) fn direct_conversation_peer(
        &self,
        realm: &str,
    ) -> Option<arkret_sdk::contact_operations::ContactPeer> {
        self.cached.direct_conversation_peers.get(realm).cloned()
    }
    pub(crate) fn save_direct_conversation_peer(
        &mut self,
        realm: String,
        peer: arkret_sdk::contact_operations::ContactPeer,
    ) -> anyhow::Result<()> {
        self.ensure_cached_loaded();
        if self.cached.direct_conversation_peers.get(&realm) != Some(&peer) {
            self.cached.direct_conversation_peers.insert(realm, peer);
            self.flush()?;
        }
        Ok(())
    }
    pub(crate) fn set_direct_message_context(
        &mut self,
        realm: String,
        context: Option<DirectMessageContext>,
    ) {
        match context {
            Some(context) => {
                self.cached.direct_message_contexts.insert(realm, context);
            }
            None => {
                self.cached.direct_message_contexts.remove(&realm);
            }
        }
        while self.cached.direct_message_contexts.len() > 64 {
            let key = self
                .cached
                .direct_message_contexts
                .iter()
                .min_by_key(|(_, value)| value.query_sequence)
                .unwrap()
                .0
                .clone();
            self.cached.direct_message_contexts.remove(&key);
        }
    }
    pub(crate) fn direct_message_context(
        &self,
        realm: &str,
        actor: &arkret_sdk::ActorId,
    ) -> Option<DirectMessageContext> {
        let context = self.cached.direct_message_contexts.get(realm)?;
        if actor.as_account_id() != Some(&context.account)
            || self.active_authority().as_ref() != Some(&context.account)
            || context.session_epoch != crate::identity::device_directory::cache_epoch()
            || self
                .cached
                .direct_conversation_peers
                .get(realm)
                .is_none_or(|peer| {
                    !crate::mls::direct_binding::query_is_current(
                        &context.account,
                        peer,
                        context.query_sequence,
                    )
                })
            || self
                .cached
                .seal_views
                .get(realm)
                .is_none_or(|view| view.frontier != [context.seal_ref.to_string()])
        {
            return None;
        }
        Some(context.clone())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    fn account(station: &str) -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:direct-test.example").unwrap(),
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
        )
    }
    #[test]
    fn direct_result_is_scoped_to_account_query_and_observed_frontier() {
        let path = std::env::temp_dir().join(format!(
            "inkson-dc-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = LocalStateStore::with_path(path);
        let authority = account("station");
        store
            .write_root(&RootIndex {
                active_profile_id: Some("direct".into()),
                known_profiles: vec![AccountIndexEntry {
                    profile_id: "direct".into(),
                    authority: authority.clone(),
                }],
                ..Default::default()
            })
            .unwrap();
        store.ensure_cached_loaded();
        let peer = arkret_sdk::contact_operations::ContactPeer::Human {
            account_id: account("peer-station"),
        };
        let realm = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
        store
            .save_direct_conversation_peer(realm.into(), peer.clone())
            .unwrap();
        let sequence = crate::mls::direct_binding::begin_query(&authority, &peer).unwrap();
        let reference = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [7; 32]);
        let seal = arkret_sdk::SealId::new(format!("ak:seal:sha256:{}", "07".repeat(32))).unwrap();
        store.cached.seal_views.insert(
            realm.into(),
            LocalSealView {
                frontier: vec![seal.to_string()],
                ..Default::default()
            },
        );
        store.set_direct_message_context(
            realm.into(),
            Some(DirectMessageContext {
                account: authority.clone(),
                session_epoch: crate::identity::device_directory::cache_epoch(),
                query_sequence: sequence,
                authority: crate::mls::direct_binding::MessageAuthority::Participant(
                    reference.clone(),
                ),
                group_state_ref: reference,
                seal_ref: seal,
            }),
        );
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_some()
        );
        assert!(
            store
                .direct_message_context(
                    realm,
                    &arkret_sdk::ActorId::account(account("another-station"))
                )
                .is_none()
        );
        let json = serde_json::to_value(&store.cached).unwrap();
        assert!(json.get("direct_message_contexts").is_none());
        assert!(json["direct_conversation_peers"].get(realm).is_some());
        store
            .cached
            .seal_views
            .get_mut(realm)
            .unwrap()
            .frontier
            .clear();
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_none()
        );
        crate::mls::direct_binding::begin_query(&authority, &peer).unwrap();
        assert!(!crate::mls::direct_binding::query_is_current(
            &authority, &peer, sequence
        ));
    }
}
