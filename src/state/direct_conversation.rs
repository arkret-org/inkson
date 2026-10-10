use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DirectMessageContext {
    pub account: arkret_sdk::AccountId,
    pub session_epoch: u64,
    pub query_sequence: u64,
    pub authority_source: arkret_wire::AuthoritySourceId,
    pub authority_event_ref: arkret_sdk::EventId,
    pub group_state_ref: arkret_sdk::EventId,
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
            if let Some(account) = self.active_authority()
                && let Some(previous) = self.cached.direct_conversation_peers.get(&realm)
            {
                crate::mls::direct_binding::invalidate_query(&account, previous);
            }
            self.cached.direct_message_contexts.remove(&realm);
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
            let Some(key) = self
                .cached
                .direct_message_contexts
                .iter()
                .min_by_key(|(_, value)| value.query_sequence)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.cached.direct_message_contexts.remove(&key);
        }
    }
    pub(crate) fn invalidate_direct_message_peer(
        &mut self,
        account: &arkret_sdk::AccountId,
        peer: &arkret_sdk::contact_operations::ContactPeer,
    ) {
        let peers = &self.cached.direct_conversation_peers;
        self.cached
            .direct_message_contexts
            .retain(|realm, context| &context.account != account || peers.get(realm) != Some(peer));
    }
    pub(crate) fn direct_message_context(
        &self,
        realm: &str,
        actor: &arkret_sdk::ActorId,
    ) -> Option<DirectMessageContext> {
        let context = self.cached.direct_message_contexts.get(realm)?;
        if actor.as_account_id() != Some(&context.account)
            || self.active_authority().as_ref() != Some(&context.account)
            || context.session_epoch != crate::identity::device_directory::session_cache_epoch()
            || !self.cached.direct_conversation_peers.contains_key(realm)
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
    fn direct_result_survives_pending_refresh_but_not_account_or_peer_changes() {
        // Session cache mutations share the signer/scope tests' process-wide fence.
        let _scope = crate::secure_key_store::DeviceSeedScopeTestGuard::replace(None);
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
        store.set_direct_message_context(
            realm.into(),
            Some(DirectMessageContext {
                account: authority.clone(),
                session_epoch: crate::identity::device_directory::session_cache_epoch(),
                query_sequence: sequence,
                authority_source: arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
                authority_event_ref: reference.clone(),
                group_state_ref: reference,
            }),
        );
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_some()
        );
        crate::identity::device_directory::fence_device_refresh();
        let mut retained = store
            .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
            .expect("device directory refresh does not replace the Direct session");
        crate::identity::device_directory::reset_session_cache();
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_none(),
            "the same account cannot reuse a Direct context after session replacement"
        );
        retained.session_epoch = crate::identity::device_directory::session_cache_epoch();
        store.set_direct_message_context(realm.into(), Some(retained));
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
        let refresh_sequence = crate::mls::direct_binding::begin_query(&authority, &peer).unwrap();
        assert!(!crate::mls::direct_binding::query_is_current(
            &authority, &peer, sequence
        ));
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_some()
        );
        store.invalidate_direct_message_peer(&account("another-station"), &peer);
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_some()
        );
        store.invalidate_direct_message_peer(&authority, &peer);
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_none()
        );
        store.set_direct_message_context(
            realm.into(),
            Some(DirectMessageContext {
                account: authority.clone(),
                session_epoch: crate::identity::device_directory::session_cache_epoch(),
                query_sequence: sequence,
                authority_source: arkret_wire::AuthoritySourceId::DirectConversationParticipantV1,
                authority_event_ref: arkret_sdk::EventId::from_digest(
                    arkret_sdk::DigestSuite::Sha256,
                    [7; 32],
                ),
                group_state_ref: arkret_sdk::EventId::from_digest(
                    arkret_sdk::DigestSuite::Sha256,
                    [8; 32],
                ),
            }),
        );
        store
            .save_direct_conversation_peer(
                realm.into(),
                arkret_sdk::contact_operations::ContactPeer::Human {
                    account_id: account("replacement-peer"),
                },
            )
            .unwrap();
        assert!(!crate::mls::direct_binding::query_is_current(
            &authority,
            &peer,
            refresh_sequence
        ));
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority))
                .is_none()
        );
    }
}
