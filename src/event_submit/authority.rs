//! Realm founding-authority facts read from the Realm's own commit stream.
//!
//! The governance-authority protocol has no projected authority cell and no
//! producer-side authorization claim for a Realm owner: the owner authorizes
//! with its own actor identity and the current governance Station evaluates
//! that against the committed Realm projection. What remains here is the small
//! set of immutable facts the Realm genesis Event itself carries.

use super::*;

/// Authority facts pinned by a Realm's committed `ak.realm.create`.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum RealmCreateAuthority {
    Root { controller: arkret_sdk::ActorId },
    DirectConversation,
}

pub(super) fn realm_create_authority_cache()
-> &'static Mutex<BTreeMap<String, RealmCreateAuthority>> {
    static CACHE: SyncOnceLock<Mutex<BTreeMap<String, RealmCreateAuthority>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn realm_create_authority_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<RealmCreateAuthority> {
    events.iter().find_map(|event| {
        if event.realm_id.as_str() != realm_id || event.kind != arkret_sdk::EventKind::RealmCreate {
            return None;
        }
        if event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("direct_conversation")
        {
            return Some(RealmCreateAuthority::DirectConversation);
        }
        Some(RealmCreateAuthority::Root {
            controller: event.actor_id.clone(),
        })
    })
}

pub(super) fn realm_owner_covers_event_kind(kind: &str) -> bool {
    arkret_schema::capability_action(CapabilityActionId::REALM_OWNER)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&kind))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn realm_id() -> arkret_sdk::RealmId {
        arkret_sdk::RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned())
            .unwrap()
    }

    fn event(kind: arkret_sdk::EventKind, scope_ref: arkret_sdk::ScopeRef) -> arkret_sdk::Event {
        arkret_sdk::Event {
            event_id: arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [7; 32]),
            kind,
            realm_id: realm_id(),
            scope_ref,
            actor_id: arkret_sdk::ActorId::service(
                arkret_sdk::DidCoreId::new("ak:did_core:web:alice.example".to_owned()).unwrap(),
            ),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: chrono::Utc::now(),
            semantic_refs: Vec::new(),
            payload: BTreeMap::from([("object".to_owned(), json!({}))]),
            producer_proof: None,
        }
    }

    #[test]
    fn realm_create_authority_reads_the_founding_actor() {
        let realm_scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let create = event(arkret_sdk::EventKind::RealmCreate, realm_scope);
        let expected = create.actor_id.clone();

        assert_eq!(
            realm_create_authority_from_events(&[create], realm_id().as_str()),
            Some(RealmCreateAuthority::Root {
                controller: expected
            })
        );
    }

    #[test]
    fn direct_conversation_purpose_is_not_an_ordinary_realm_owner() {
        let realm_scope = arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id(),
        };
        let mut create = event(arkret_sdk::EventKind::RealmCreate, realm_scope);
        create.payload.insert(
            "object".to_owned(),
            json!({ "purpose": "direct_conversation" }),
        );

        assert_eq!(
            realm_create_authority_from_events(&[create], realm_id().as_str()),
            Some(RealmCreateAuthority::DirectConversation)
        );
    }
}
