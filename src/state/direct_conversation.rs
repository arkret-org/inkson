use super::*;

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DirectMessageContext {
    pub account: arkret_sdk::AccountId,
    pub session_epoch: u64,
    pub query_sequence: u64,
    pub authority_source: arkret_wire::AuthoritySourceId,
    pub authority_event_ref: arkret_sdk::EventId,
    pub group_state_ref: arkret_sdk::EventId,
    pub structure_only: bool,
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
        self.direct_authoring_context(realm, actor)
            .filter(|context| !context.structure_only)
    }

    pub(crate) fn direct_structure_context(
        &self,
        realm: &str,
        actor: &arkret_sdk::ActorId,
    ) -> Option<DirectMessageContext> {
        let context = self.direct_authoring_context(realm, actor)?;
        let view = self.current_product_view()?;
        view.entries_for(realm)?;
        if context.authority_source
            != arkret_wire::AuthoritySourceId::DirectConversationParticipantV1
            || !self.current_product_view_ready(realm)
            || !view.complete_joined_members().ok()??.contains(actor)
        {
            return None;
        }
        Some(context)
    }

    fn direct_authoring_context(
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
                structure_only: false,
            }),
        );
        assert!(
            store
                .direct_message_context(realm, &arkret_sdk::ActorId::account(authority.clone()))
                .is_some()
        );
        let actor = arkret_sdk::ActorId::account(authority.clone());
        let mut normal = store.direct_message_context(realm, &actor).unwrap();
        let mut suspended = normal.clone();
        suspended.structure_only = true;
        store.set_direct_message_context(realm.into(), Some(suspended.clone()));
        assert!(store.direct_message_context(realm, &actor).is_none());
        assert!(store.direct_structure_context(realm, &actor).is_none());
        let row = |selector: serde_json::Value, value: serde_json::Value| {
            serde_json::from_value::<arkret_wire::TypedCurrentRow>(serde_json::json!({
                "selector": selector,
                "source_stream_ref": {"kind": "realm", "realm_id": realm},
                "revision": {"commit_id": "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq", "stream_position": 1},
                "value": value
            })).unwrap()
        };
        let rows = vec![
            row(
                serde_json::json!({"kind": "realm_profile"}),
                serde_json::json!({"title": "Direct"}),
            ),
            row(
                serde_json::json!({"kind": "realm_policy_bundle"}),
                serde_json::json!({"policy_revision": 1}),
            ),
            row(
                serde_json::json!({"kind": "member_state", "actor_id": actor}),
                serde_json::json!({"membership": "join"}),
            ),
            row(
                serde_json::json!({"kind": "member_state", "actor_id": arkret_sdk::ActorId::account(account("peer-station"))}),
                serde_json::json!({"membership": "leave"}),
            ),
        ];
        store
            .install_current_product_view(
                crate::current_projection::RealmCurrentView::new(realm, rows.clone(), false)
                    .unwrap(),
            )
            .unwrap();
        assert!(
            store.direct_structure_context(realm, &actor).is_none(),
            "a partial roster never grants structural authority"
        );
        store
            .install_current_product_view(
                crate::current_projection::RealmCurrentView::new(realm, rows.clone(), true)
                    .unwrap(),
            )
            .unwrap();
        assert!(
            store.direct_structure_context(realm, &actor).is_some(),
            "the joined actor retains structure when its peer leaves"
        );
        assert!(
            store.direct_message_context(realm, &actor).is_none(),
            "structural authority does not reopen Messages"
        );
        let mut left = rows.clone();
        let arkret_wire::TypedCurrentRow::Value { value, .. } = &mut left[2];
        *value = serde_json::json!({"membership": "leave"});
        store
            .install_current_product_view(
                crate::current_projection::RealmCurrentView::new(realm, left, true).unwrap(),
            )
            .unwrap();
        assert!(
            store.direct_structure_context(realm, &actor).is_none(),
            "the author that left cannot use the stable pair binding"
        );
        store
            .install_current_product_view(
                crate::current_projection::RealmCurrentView::new(realm, rows, true).unwrap(),
            )
            .unwrap();
        suspended.authority_source =
            arkret_wire::AuthoritySourceId::DirectConversationBootstrapParticipantV1;
        store.set_direct_message_context(realm.into(), Some(suspended));
        assert!(
            store.direct_structure_context(realm, &actor).is_none(),
            "bootstrap does not grant structure"
        );
        normal.structure_only = false;
        store.set_direct_message_context(realm.into(), Some(normal));
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
                structure_only: false,
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
