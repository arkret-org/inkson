use super::admission::*;
use super::*;
use crate::test_support as fixture;

fn permission_checks(
    invite: anyhow::Result<bool>,
    cancel_invite: anyhow::Result<bool>,
    revoke_invite: anyhow::Result<bool>,
    remove: anyhow::Result<bool>,
) -> RealmMemberPermissionChecks {
    RealmMemberPermissionChecks {
        invite,
        cancel_invite,
        revoke_invite,
        remove,
    }
}

#[test]
fn member_permission_actions_preserve_protocol_probe_order() {
    assert_eq!(
        MEMBER_PERMISSION_ACTIONS,
        [
            CapabilityActionId::INVITE_CREATE,
            CapabilityActionId::INVITE_CANCEL,
            CapabilityActionId::INVITE_REVOKE,
            CapabilityActionId::REALM_ADMIN,
        ]
    );
}

#[test]
fn member_permission_aggregation_preserves_mixed_results_and_mapping() {
    let load = aggregate_realm_member_permissions(&permission_checks(
        Ok(true),
        Err(anyhow::anyhow!("cancel unavailable")),
        Ok(false),
        Ok(true),
    ));

    assert_eq!(
        load.capabilities,
        RealmMemberCapabilities {
            loaded: true,
            can_invite: true,
            can_cancel_invite: false,
            can_revoke_invite: false,
            can_remove: true,
        }
    );
    assert!(!load.all_checks_failed);
}

#[test]
fn member_permission_aggregation_marks_all_errors_fail_closed() {
    let load = aggregate_realm_member_permissions(&permission_checks(
        Err(anyhow::anyhow!("invite unavailable")),
        Err(anyhow::anyhow!("cancel unavailable")),
        Err(anyhow::anyhow!("revoke unavailable")),
        Err(anyhow::anyhow!("admin unavailable")),
    ));

    assert_eq!(
        load.capabilities,
        RealmMemberCapabilities {
            loaded: true,
            ..RealmMemberCapabilities::default()
        }
    );
    assert!(load.all_checks_failed);
}

/// Roster key for a test principal. Agent and human actors share the same
/// `ActorId::Account` shape — an agent is an account at the same Station, not
/// a different actor kind — so there is one branch, not two identical ones.
fn actor_key(id: &str) -> String {
    let principal = arkret_sdk::DidCoreId::new(id).unwrap();
    let station = arkret_sdk::DidCoreId::new("ak:did_core:web:principal.example").unwrap();
    arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(principal, station)).to_string()
}

fn member(id: &str) -> MemberProfile {
    MemberProfile::bare(actor_key(id))
}

fn agent(id: &str, controller: &str, name: &str) -> MemberAgentRow {
    MemberAgentRow {
        agent_id: id.to_owned(),
        controller_principal_id: controller.to_owned(),
        display_name: name.to_owned(),
        slug: "summary".to_owned(),
        status: "active".to_owned(),
        runtime_state: "ready".to_owned(),
        mention_policy: AgentMentionPolicy::Allowed,
        selection: ParticipationBits {
            reply_message: false,
            reaction_add: false,
            reaction_remove: false,
            accept_third_party_mention: true,
            act_on_behalf: false,
        },
    }
}

#[test]
fn my_agents_section_only_matches_the_current_account() {
    let own_group = MemberGroup {
        controller: member("ak:did_core:web:alice.example"),
        agents: Vec::new(),
    };
    let other_group = MemberGroup {
        controller: member("ak:did_core:web:bob.example"),
        agents: Vec::new(),
    };

    assert!(member_group_in_section(
        &own_group,
        MemberRosterSection::MyAgents,
        "ak:did_core:web:alice.example"
    ));
    assert!(!member_group_in_section(
        &other_group,
        MemberRosterSection::MyAgents,
        "ak:did_core:web:alice.example"
    ));
}

#[test]
fn my_agents_list_only_shows_joined_agents_and_picker_only_shows_available_active_agents() {
    let joined = agent(
        "ak:did_core:web:agent-joined.example",
        "ak:did_core:web:alice.example",
        "Joined",
    );
    let available = agent(
        "ak:did_core:web:agent-available.example",
        "ak:did_core:web:alice.example",
        "Available",
    );
    let mut paused = agent(
        "ak:did_core:web:agent-paused.example",
        "ak:did_core:web:alice.example",
        "Paused",
    );
    paused.status = "paused".to_owned();
    let members = BTreeSet::from([actor_key(&joined.agent_id)]);

    let (in_realm, candidates) =
        split_owned_agents_for_realm(&[joined.clone(), available.clone(), paused], &members);

    assert_eq!(in_realm, vec![joined]);
    assert_eq!(candidates, vec![available]);
}

fn temp_store(name: &str) -> LocalStateStore {
    let path = std::env::temp_dir().join(format!(
        "inkson-members-panel-{name}-{}.json",
        crate::operation::uuid_v7()
    ));
    LocalStateStore::with_path(path)
}

fn dummy_mls_checkpoint(realm_id: &str) -> crate::mls::persistence::MlsLocalCheckpointEnvelope {
    crate::mls::persistence::MlsLocalCheckpointEnvelope {
        realm_id: realm_id.to_owned(),
        group_id: "test-group".to_owned(),
        epoch: 0,
        admission_epoch: 0,
        group_state_event_id: None,
        salt_hex: String::new(),
        ciphertext_hex: String::new(),
        mac_hex: String::new(),
        recorded_at: chrono::Utc::now(),
        epoch_started_at: chrono::Utc::now(),
        app_messages_observed: 0,
        aead_version: crate::mls::persistence::AEAD_VERSION_CHACHA20_POLY1305,
    }
}

#[test]
fn splits_pending_invites_out_of_active_members() {
    let mut alice = member("ak:did_core:web:alice.example");
    alice.membership = Some("join".to_owned());
    let mut bob = member("ak:did_core:web:bob.example");
    bob.pending_invite = true;

    let (active, pending) = split_member_profiles(vec![alice, bob]);

    assert_eq!(active.len(), 1);
    assert_eq!(
        active[0].actor_id,
        actor_key("ak:did_core:web:alice.example")
    );
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].actor_id,
        actor_key("ak:did_core:web:bob.example")
    );
}

#[test]
fn optimistic_pending_invite_does_not_downgrade_joined_member() {
    let mut alice = member("ak:did_core:web:alice.example");
    alice.membership = Some("join".to_owned());
    let mut rows = vec![alice];

    upsert_pending_invite_profile(
        &mut rows,
        &actor_key("ak:did_core:web:alice.example"),
        Some("Alice"),
        None,
    );
    let (active, pending) = split_member_profiles(rows);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].membership.as_deref(), Some("join"));
    assert!(pending.is_empty());
}

#[test]
fn optimistic_pending_invite_records_display_handle() {
    let mut rows = Vec::new();

    upsert_pending_invite_profile(
        &mut rows,
        &actor_key("ak:did_core:web:bob.example"),
        Some("bob:example.com"),
        None,
    );

    assert_eq!(rows.len(), 1);
    assert!(rows[0].membership.is_none());
    assert!(rows[0].is_pending_invite());
    assert_eq!(rows[0].handles, vec!["bob:example.com"]);
}

#[test]
fn member_identity_lines_hide_handle_duplicates() {
    let handles = vec!["alice:local.host".to_owned()];

    assert!(!member_line_identity_visible(
        "alice:local.host",
        "alice:local.host",
        &handles
    ));
    assert!(member_line_identity_visible(
        "did:web:alice.local",
        "alice:local.host",
        &handles
    ));
}

#[test]
fn member_handle_line_keeps_all_handles_without_repeating_primary() {
    let single = vec!["alice:local.host".to_owned()];
    assert!(member_handles_for_line(&single, "alice:local.host").is_empty());

    let multiple = vec![
        "alice:local.host".to_owned(),
        "alice:work.local.host".to_owned(),
    ];
    let visible = member_handles_for_line(&multiple, "alice:local.host");
    assert_eq!(visible, vec!["alice:work.local.host"]);
    assert_eq!(
        member_handles_line_label(&multiple, &visible),
        "Other handles"
    );

    let display_title = member_handles_for_line(&multiple, "Alice");
    assert_eq!(display_title, multiple);
    assert_eq!(
        member_handles_line_label(&display_title, &display_title),
        "Handles"
    );
}

#[test]
fn groups_current_account_with_owned_agent_members() {
    let members = vec![
        member("ak:did_core:web:alice.example"),
        member("ak:did_core:web:bob.example"),
        member("ak:did_core:web:agent.example"),
    ];
    let groups = group_members_with_owned_agents(
        &members,
        &[agent(
            "ak:did_core:web:agent.example",
            "ak:did_core:web:alice.example",
            "Summary",
        )],
        "ak:did_core:web:alice.example",
    );

    let alice = groups
        .iter()
        .find(|group| group.controller.actor_id == actor_key("ak:did_core:web:alice.example"))
        .expect("alice group exists");
    assert_eq!(alice.agents.len(), 1);
    assert_eq!(alice.agents[0].agent_id, "ak:did_core:web:agent.example");
    assert_eq!(
        groups[0].controller.actor_id,
        actor_key("ak:did_core:web:alice.example")
    );
    assert!(
        groups
            .iter()
            .all(|group| group.controller.actor_id != actor_key("ak:did_core:web:agent.example"))
    );
}

#[test]
fn groups_agent_members_under_reported_controller() {
    let members = vec![
        member("ak:did_core:web:alice.example"),
        member("ak:did_core:web:bob.example"),
        member("ak:did_core:web:bob-agent.example"),
    ];
    let groups = group_members_with_owned_agents(
        &members,
        &[agent(
            "ak:did_core:web:bob-agent.example",
            "ak:did_core:web:bob.example",
            "Bob Summary",
        )],
        "ak:did_core:web:alice.example",
    );

    let bob = groups
        .iter()
        .find(|group| group.controller.actor_id == actor_key("ak:did_core:web:bob.example"))
        .expect("bob group exists");
    assert_eq!(bob.agents.len(), 1);
    assert_eq!(bob.agents[0].agent_id, "ak:did_core:web:bob-agent.example");
    assert!(
        groups.iter().all(
            |group| group.controller.actor_id != actor_key("ak:did_core:web:bob-agent.example")
        )
    );
}

const PANEL_ISSUER: &str = "ak:did_core:web:acme.example";

fn acme_policy_events() -> serde_json::Value {
    serde_json::json!({"events": [{
        "kind": "ak.realm.policy_bundle",
        "payload": {
            "policy_revision": 1,
            "handle_issuer_policies": [{
                "issuer_id": PANEL_ISSUER,
                "authorized_handle_domains": ["acme.example"],
                "issuer_class": "domain_authority"
            }]
        }
    }]})
}

#[test]
fn projected_member_profiles_use_only_verified_canonical_identity_fields() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("projected-profiles");
    let subject = fixture::authority("ak:did_core:web:acme.example:users:alice");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [{
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join",
                "subject_account_id": subject,
                "handle_claims": [crate::views::member_display::test_handle_claim(
                    &subject,
                    "alice:acme.example",
                    PANEL_ISSUER,
                    arkret_models_identity::HandleClaimStatus::Verified,
                )]
            }],
            "state": acme_policy_events(),
            "admins": ["did:web:alice.example"]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let alice = profiles
        .iter()
        .find(|profile| profile.actor_id == actor_key("ak:did_core:web:alice.example"))
        .expect("alice profile exists");
    assert_eq!(alice.display_name, None);
    assert_eq!(alice.handles, vec!["alice:acme.example"]);
    assert_eq!(alice.primary_label(), "alice:acme.example");
    assert_eq!(alice.avatar_blob_ref, None);
    assert!(!alice.is_admin);
}

#[test]
fn projected_member_profiles_reject_roster_rows_carrying_display_fields() {
    // The roster entry is a closed wire shape. A producer that decorates a
    // row with `display_name` / `display_profile` does not get those fields
    // ignored — the whole entry is rejected, so no unsigned display string
    // can reach a label.
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("projected-profiles-display-fields");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [{
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join",
                "display_name": "Alice",
                "display_profile": {
                    "avatar_blob_ref": "ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91"
                }
            }]
        }),
    );

    assert!(projected_member_profiles_for_realm(&store, realm_id).is_empty());
}

#[test]
fn projected_member_profiles_drop_handle_from_untrusted_issuer() {
    // §3.2.1 Step 0 issuer trust filter is mandatory: without a Realm
    // `handle_issuer_policies` entry authorizing the issuer for the handle
    // domain the claim is not a candidate, and the row degrades instead of
    // showing an unvetted handle.
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("projected-profiles-untrusted-issuer");
    let subject = fixture::authority("ak:did_core:web:acme.example:users:alice");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [{
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join",
                "subject_account_id": subject,
                "handle_claims": [crate::views::member_display::test_handle_claim(
                    &subject,
                    "alice:acme.example",
                    PANEL_ISSUER,
                    arkret_models_identity::HandleClaimStatus::Verified,
                )]
            }]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let alice = profiles
        .iter()
        .find(|profile| profile.actor_id == actor_key("ak:did_core:web:alice.example"))
        .expect("alice profile exists");
    assert!(alice.handles.is_empty());
}

#[test]
fn projected_member_profiles_classify_authority_root_controller_as_owner() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("authority-root-owner");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [{
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join"
            }],
            "state": {"events": [{
                "kind": "ak.realm.create",
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                "payload": {"object": {}}
            }]}
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let alice = profiles
        .iter()
        .find(|profile| profile.actor_id == actor_key("ak:did_core:web:alice.example"))
        .expect("authority-root controller is present");
    assert!(alice.is_owner);
    assert_eq!(alice.membership.as_deref(), Some("join"));
    assert_eq!(profiles.len(), 1);
}

#[test]
fn projected_member_profiles_reject_invite_as_roster_membership() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("pending-membership");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [
                {
                    "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}},
                    "membership": "join"
                },
                {
                    "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                    "membership": "invite"
                }
            ]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert_eq!(active.len(), 1);
    assert_eq!(
        active[0].actor_id,
        actor_key("ak:did_core:web:alice.example")
    );
    assert!(pending.is_empty());
}

#[test]
fn joined_member_signature_lists_only_joined_members_sorted() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("joined-signature");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:carol.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" },
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" },
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "invite" }
            ]
        }),
    );

    // Only `join` members, deduped and sorted — an `invite` roster row is not
    // valid. Invite lifecycle remains a separate projection.
    assert_eq!(
        joined_member_signature_for_realm(&store, realm_id),
        [
            actor_key("ak:did_core:web:alice.example"),
            actor_key("ak:did_core:web:carol.example")
        ]
        .join(",")
    );
}

#[test]
fn joined_member_signature_reads_raw_member_state_join() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("raw-member-state-join");
    store.append_raw_operation(
        "ak:event:Abfy0xl2jA1EqH9YZREVJu5uCrWp1osFkVmBnxuB1U88".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.member.state",
            "write_state": "synced",
            "payload": {
                "member_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join"
            }
        }),
    );
    assert_eq!(
        joined_member_signature_for_realm(&store, realm_id),
        actor_key("ak:did_core:web:bob.example")
    );
}

#[test]
fn accepted_invite_route_recovers_from_canonical_history_after_restart() {
    let realm = arkret_sdk::RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
        arkret_sdk::DigestSuite::Sha256,
        [0x42; 32],
    ));
    let realm_id = realm.as_str();
    let invitee = fixture::authority("ak:did_core:web:bob.example");
    let device_id = "ak:device:0196419b-0000-7000-8000-000000000002";
    let make_event = |kind: &str, principal: &str, payload: Value| {
        arkret_wire::test_support::raw_event(
            kind,
            arkret_sdk::ScopeRef::Realm {
                realm_id: fixture::realm_id(realm_id),
            },
            fixture::core_id(principal),
            invitee.station_id.clone(),
            1,
            arkret_sdk::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            payload,
        )
        .unwrap()
    };
    let create = make_event(
        "ak.invite.create",
        "ak:did_core:web:alice.example",
        serde_json::json!({
            "invitee_account_id": invitee,
            "introduction_evidence_digest": format!("sha256:{}", "1".repeat(64)),
            "expires_at": "2099-01-01T00:00:00.000Z"
        }),
    );
    let invite_id = arkret_sdk::InviteId::from_event_id(&create.event_id);
    let mut accept = make_event(
        "ak.invite.accept",
        invitee.principal_id.as_str(),
        serde_json::json!({
            "invite_id": invite_id,
            "invitee_account_id": invitee,
        }),
    );
    accept.proofs.push(
        arkret_sdk::ProducerEventProof {
            kind: arkret_sdk::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: arkret_sdk::DidUrl::new(format!(
                "did:web:bob.example#{device_id}"
            ))
            .unwrap(),
            event_digest: arkret_sdk::Hash::new(
                accept
                    .event_digest_with_digest_suite(arkret_sdk::DigestSuite::Sha256)
                    .unwrap(),
            )
            .unwrap(),
            signer_resolution_evidence_ref: None,
            created_at: accept.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "header..producer".to_owned(),
        }
        .into(),
    );
    // This is a projection test over already accepted Events; signature
    // verification belongs to the canonical ingest boundary. Start with no
    // locally authored invite hints, as on another device or after restart.
    for live_stream in [false, true] {
        let mut store = temp_store("accepted-invite-canonical-history");
        let events = [create.clone(), accept.clone()];
        let changed = if live_stream {
            crate::sync_engine::ingest_membership_events(
                &mut store,
                realm_id,
                &events
                    .into_iter()
                    .map(garth::ClientEvent::Event)
                    .collect::<Vec<_>>(),
            )
        } else {
            crate::sync_engine::ingest_membership_projection_events(&mut store, realm_id, &events)
        };
        assert_eq!(changed, 2);
        assert_eq!(
            accepted_invite_claim_route(
                &store,
                realm_id,
                &arkret_sdk::ActorId::account(invitee.clone()).to_string()
            ),
            Some(AcceptedInviteClaimRoute {
                destination_id: invitee.station_id.to_string(),
                target_device_id: Some(device_id.to_owned()),
            })
        );
        let other_station = fixture::authority_at_station(
            invitee.principal_id.as_str(),
            "ak:did_core:web:other.example",
        );
        assert!(
            accepted_invite_claim_route(
                &store,
                realm_id,
                &arkret_sdk::ActorId::account(other_station).to_string()
            )
            .is_none()
        );
        assert_eq!(
            crate::sync_engine::ingest_membership_projection_events(
                &mut store,
                realm_id,
                &[create.clone(), accept.clone()]
            ),
            0
        );
    }
}

#[test]
fn accepted_invite_route_binds_delivery_service_and_accepting_device() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let invitee = "ak:did_core:web:bob.example";
    let invite_id = "ak:invite:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA";
    let device_id = "ak:device:0196419b-0000-7000-8000-000000000002";
    let mut store = temp_store("accepted-invite-route");
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee_account_id": {
                "principal_id": invitee,
                "station_id": "ak:did_core:web:principal.example"
            },
            "event_id": "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA",
        }),
    );
    store.upsert_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee_account_id": {
                "principal_id": invitee,
                "station_id": "ak:did_core:web:principal.example"
            },
            "event_id": "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA"
        }),
    );
    store.append_raw_operation(
        "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.accept",
            "actor_id": {"kind":"account","account_id":{
                "principal_id": invitee,
                "station_id": "ak:did_core:web:principal.example"
            }},
            "signing_device_id": device_id,
            "event_id": "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM",
            "body": { "invite_id": invite_id }
        }),
    );

    assert_eq!(
        accepted_invite_claim_route(&store, realm_id, &actor_key(invitee)),
        Some(AcceptedInviteClaimRoute {
            destination_id: "ak:did_core:web:principal.example".to_owned(),
            target_device_id: Some(device_id.to_owned()),
        })
    );
    assert!(
        accepted_invite_claim_route(
            &store,
            "ak:realm:Ac4tyK_nwe4AYgJmR9A6pbiRrGZiDOx-i-EVWYUQabXC",
            &actor_key(invitee),
        )
        .is_none()
    );
}

#[test]
fn accepted_human_invite_route_fails_closed_without_exact_accepting_device() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let invitee = "ak:did_core:web:bob.example";
    let invite_id = "ak:invite:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA";
    let mut store = temp_store("accepted-invite-missing-device");
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee_account_id": {
                "principal_id": invitee,
                "station_id": "ak:did_core:web:principal.example"
            },
            "event_id": "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA",
        }),
    );
    store.append_raw_operation(
        "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.accept",
            "actor_id": {"kind":"account","account_id":{
                "principal_id": invitee,
                "station_id": "ak:did_core:web:principal.example"
            }},
            "event_id": "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM",
            "body": { "invite_id": invite_id }
        }),
    );

    assert_eq!(
        accepted_invite_claim_route(&store, realm_id, &actor_key(invitee)),
        Some(AcceptedInviteClaimRoute {
            destination_id: "ak:did_core:web:principal.example".to_owned(),
            target_device_id: None,
        })
    );
    let route = accepted_invite_claim_route(&store, realm_id, &actor_key(invitee)).unwrap();
    assert!(claim_target_device_id(&route, false).is_err());
    assert_eq!(claim_target_device_id(&route, true).unwrap(), None);
}

#[test]
fn pairwise_claim_selector_never_reuses_a_human_device_coordinate() {
    let route = AcceptedInviteClaimRoute {
        destination_id: "ak:did_core:web:principal.example".to_owned(),
        target_device_id: Some("ak:device:0196419b-0000-7000-8000-000000000002".to_owned()),
    };

    assert_eq!(claim_target_device_id(&route, true).unwrap(), None);
    assert_eq!(
        claim_target_device_id(&route, false).unwrap(),
        Some("ak:device:0196419b-0000-7000-8000-000000000002")
    );
}

#[test]
fn projected_duplicate_member_skips_invalid_invite_and_keeps_join() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("pending-then-joined-membership");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [
                {
                    "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                    "membership": "invite"
                },
                {
                    "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                    "membership": "join"
                }
            ]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_id, actor_key("ak:did_core:web:bob.example"));
    assert_eq!(active[0].membership.as_deref(), Some("join"));
    assert!(pending.is_empty());
}

#[test]
fn projected_member_profiles_restore_pending_invites_from_raw_operations() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("raw-pending-invite");
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invitee_account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            },
            "invitee_label": "bob:example.com",
            "state": "pending"
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert!(active.is_empty());
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].actor_id,
        actor_key("ak:did_core:web:bob.example")
    );
    assert_eq!(pending[0].handles, vec!["bob:example.com"]);
    assert_eq!(pending[0].invite_is_direct, Some(true));
}

#[test]
fn token_invite_profile_is_classified_for_high_risk_revoke() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let invite_id = "ak:invite:Ae5vV8Lwlft2Dp8x2y6Dv4NysvsHJwrADG-6PXdUz1Sl";
    let mut store = temp_store("raw-token-invite");
    store.append_raw_operation(
        "ak:event:AtAfWM99SbDRZ4kl3R0Z7xQ5sqkAav5jX_TdZt-o3Zg8".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "threepid": "email:masked@example.com",
            "state": "pending"
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (_, pending) = split_member_profiles(profiles);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].invite_id.as_deref(), Some(invite_id));
    assert_eq!(pending[0].invite_is_direct, Some(false));
}

#[test]
fn projected_member_profiles_promote_invite_accept_to_join_from_raw_operations() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let invite_id = "ak:invite:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH";
    let mut store = temp_store("raw-invite-accept-join");
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee_account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            },
            "invitee_label": "bob:example.com",
            "state": "pending"
        }),
    );
    store.append_raw_operation(
        "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.accept",
            "write_state": "synced",
            "body": {
                "invite_ref": invite_id
            }
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_id, actor_key("ak:did_core:web:bob.example"));
    assert_eq!(active[0].membership.as_deref(), Some("join"));
    assert!(pending.is_empty());
}

#[test]
fn queued_invite_accept_does_not_promote_join_but_realm_remains_reconcilable() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let invite_id = "ak:invite:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH";
    let mut store = temp_store("queued-invite-accept-reconcilable");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "encrypted": true,
            "member_roster_entries": [
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" },
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "invite" }
            ]
        }),
    );
    store
        .save_mls_checkpoint(realm_id.to_owned(), dummy_mls_checkpoint(realm_id))
        .unwrap();
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee_account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            },
            "invitee_label": "bob:example.com",
            "state": "pending"
        }),
    );
    store.append_raw_operation(
        "local-accept-queued".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.accept",
            "write_state": "queued",
            "body": {
                "invite_ref": invite_id
            }
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert!(
        active
            .iter()
            .all(|profile| profile.actor_id != actor_key("ak:did_core:web:bob.example"))
    );
    assert!(pending.iter().any(|profile| {
        profile.actor_id == actor_key("ak:did_core:web:bob.example")
            && profile.membership.is_none()
            && profile.is_pending_invite()
    }));
    let candidates = mls_admission_candidate_realms_for_actor(&store, "did:web:alice.example");
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].0, realm_id);
    assert_eq!(
        candidates[0].1,
        actor_key("ak:did_core:web:alice.example"),
        "queued local intent is not accepted membership, while the Realm is still inspected so canonical history can close the gap"
    );
}

#[test]
fn projected_member_profiles_drop_locally_cancelled_pending_invites() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let invite_id = "ak:invite:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH";
    let mut store = temp_store("raw-cancelled-pending-invite");
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee_account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            },
            "invitee_label": "bob:example.com",
            "state": "pending"
        }),
    );
    store.append_raw_operation(
        "ak:event:Au5pQ7O1BpiTtNqKCf8A3gJJBHV1wPamoxVLkyKlfFIc".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.cancel",
            "invite_id": invite_id,
            "state": "revoked"
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert!(active.is_empty());
    assert!(pending.is_empty());
}

#[test]
fn raw_pending_invite_does_not_override_join_projection() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("raw-pending-joined");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "member_roster_entries": [{
                "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}},
                "membership": "join"
            }]
        }),
    );
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invitee_account_id": {
                "principal_id": "ak:did_core:web:bob.example",
                "station_id": "ak:did_core:web:principal.example"
            },
            "state": "pending"
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_id, actor_key("ak:did_core:web:bob.example"));
    assert_eq!(active[0].membership.as_deref(), Some("join"));
    assert!(pending.is_empty());
}

#[test]
fn admission_candidates_exclude_direct_conversation_realms() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("admission-candidate-direct-conversation");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "encrypted": true,
            "member_roster_entries_limited": false,
            "member_roster_entries": [
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:alice.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" },
                { "actor_id": {"kind":"service","service_id":"ak:did_core:web:agent.example"}, "membership": "join" }
            ],
            "state_at_window_start": {
                "realm_metadata": {
                    "collaboration_role": "direct_conversation"
                }
            }
        }),
    );
    store.save_realm_collaboration_role(
        realm_id.to_owned(),
        Some(arkret_sdk::CollaborationRealmRole::DirectConversation),
    );
    store
        .save_mls_checkpoint(realm_id.to_owned(), dummy_mls_checkpoint(realm_id))
        .unwrap();

    assert!(
        mls_admission_candidate_realms_for_actor(&store, "did:web:alice.example").is_empty(),
        "the direct-conversation materializer owns its immutable MLS admission events"
    );
}

#[test]
fn projected_membership_uses_positive_limited_roster_without_claiming_completeness() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("accepted-membership-limited-roster");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "encrypted": true,
            "member_roster_entries_limited": true,
            "member_roster_entries": [
                { "actor_id": {"kind":"account","account_id":{"principal_id":"ak:did_core:web:bob.example","station_id":"ak:did_core:web:principal.example"}}, "membership": "join" }
            ]
        }),
    );

    let membership = projected_realm_membership_hint(&store, realm_id);
    assert_eq!(membership.completeness, MembershipCompleteness::Limited);
    assert_eq!(
        membership.joined,
        BTreeSet::from([actor_key("ak:did_core:web:bob.example")])
    );
}

#[test]
fn mention_policy_reads_realm_effective_bit() {
    let realm_id = arkret_sdk::RealmId::new(
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19".to_owned(),
    )
    .unwrap();
    let entries = vec![AgentParticipationEntry {
        scope: ParticipationScope::Realm { realm_id },
        selection: ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: false,
            accept_third_party_mention: true,
            act_on_behalf: false,
        },
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    }];

    let (policy, selection) = mention_state_from_entries(
        &entries,
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
    );
    assert_eq!(policy, AgentMentionPolicy::Allowed);
    assert!(selection.accept_third_party_mention);
}

#[test]
fn mention_state_uses_realm_participation_entry() {
    let realm = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
    let realm_id = arkret_sdk::RealmId::new(realm.to_owned()).unwrap();
    let entry = AgentParticipationEntry {
        scope: ParticipationScope::Realm { realm_id },
        selection: ParticipationBits {
            reply_message: true,
            reaction_add: true,
            reaction_remove: false,
            accept_third_party_mention: true,
            act_on_behalf: false,
        },
        version: 1,
        next_replace_input: ParticipationNextReplaceInput {
            expected_version: 1,
        },
    };

    let (policy, selection) = mention_state_from_entries(&[entry], realm);

    assert_eq!(policy, AgentMentionPolicy::Allowed);
    assert!(selection.accept_third_party_mention);
}

#[test]
fn mls_admission_authoring_locks_are_scoped_per_realm() {
    let realm_a = mls_admission_authoring_lock("ak:realm:a");
    let realm_a_again = mls_admission_authoring_lock("ak:realm:a");
    let realm_b = mls_admission_authoring_lock("ak:realm:b");

    assert!(Arc::ptr_eq(&realm_a, &realm_a_again));
    assert!(!Arc::ptr_eq(&realm_a, &realm_b));
}

// --- `build_realm_roster`: the derivation the panel used to inline ---------

const SELF_PRINCIPAL: &str = "ak:did_core:web:alice.example";

fn roster(
    members: Vec<MemberProfile>,
    owned_agents: Vec<MemberAgentRow>,
    section: MemberRosterSection,
    query: &str,
    visible_limit: usize,
) -> RealmRosterView {
    build_realm_roster(RealmRosterInput {
        members,
        owned_agents,
        principal_id: SELF_PRINCIPAL,
        section,
        query,
        visible_limit,
    })
}

fn pending_invite(id: &str) -> MemberProfile {
    let mut profile = member(id);
    profile.pending_invite = true;
    profile.invite_id = Some(format!("ak:invite:{id}"));
    profile
}

fn owner(id: &str) -> MemberProfile {
    let mut profile = member(id);
    profile.is_owner = true;
    profile
}

fn admin(id: &str) -> MemberProfile {
    let mut profile = member(id);
    profile.is_admin = true;
    profile
}

#[test]
fn roster_paging_caps_mounted_groups_and_reports_more() {
    let members: Vec<MemberProfile> = (0..5)
        .map(|index| member(&format!("ak:did_core:web:m{index}.example")))
        .collect();

    let capped = roster(
        members.clone(),
        Vec::new(),
        MemberRosterSection::Members,
        "",
        2,
    );
    assert_eq!(capped.filtered_count, 5, "the cap must not hide matches");
    assert_eq!(capped.visible, 2);
    assert_eq!(capped.visible_groups.len(), 2);
    assert!(capped.has_more);

    let complete = roster(members, Vec::new(), MemberRosterSection::Members, "", 50);
    assert_eq!(complete.visible, 5);
    assert!(!complete.has_more, "nothing left to reveal");
}

#[test]
fn pending_invites_never_offer_load_more() {
    // The pending section renders its rows from `visible_pending_invites`,
    // which the group paging window never touches. Offering "load more" there
    // would be a button that cannot change what is on screen.
    let members: Vec<MemberProfile> = (0..5)
        .map(|index| pending_invite(&format!("ak:did_core:web:p{index}.example")))
        .collect();
    let view = roster(
        members,
        Vec::new(),
        MemberRosterSection::PendingInvites,
        "",
        1,
    );
    assert!(!view.has_more);
    assert_eq!(view.visible_pending_invites.len(), 5);
    assert_eq!(view.pending_invite_match_count, 5);
}

#[test]
fn search_box_appears_only_past_the_threshold_and_never_for_my_agents() {
    let small: Vec<MemberProfile> = (0..3)
        .map(|index| member(&format!("ak:did_core:web:m{index}.example")))
        .collect();
    assert!(
        !roster(
            small,
            Vec::new(),
            MemberRosterSection::Members,
            "",
            MEMBER_PAGE_SIZE
        )
        .show_search
    );

    let large: Vec<MemberProfile> = (0..=MEMBER_SEARCH_THRESHOLD)
        .map(|index| member(&format!("ak:did_core:web:m{index}.example")))
        .collect();
    assert!(
        roster(
            large.clone(),
            Vec::new(),
            MemberRosterSection::Members,
            "",
            MEMBER_PAGE_SIZE
        )
        .show_search
    );
    assert!(
        !roster(
            large,
            Vec::new(),
            MemberRosterSection::MyAgents,
            "",
            MEMBER_PAGE_SIZE
        )
        .show_search,
        "the agent section is a fixed short list, not a searchable roster"
    );
}

#[test]
fn pending_invite_rows_narrow_with_the_query() {
    let mut bob = pending_invite("ak:did_core:web:bob.example");
    bob.handles = vec!["bob".to_owned()];
    let mut carol = pending_invite("ak:did_core:web:carol.example");
    carol.handles = vec!["carol".to_owned()];
    let members = vec![bob, carol];
    let view = roster(
        members,
        Vec::new(),
        MemberRosterSection::PendingInvites,
        "  CAROL  ",
        MEMBER_PAGE_SIZE,
    );
    assert_eq!(
        view.filter_query, "carol",
        "the query is trimmed and case-folded once, in the model"
    );
    assert_eq!(view.pending_invite_match_count, 1);
    assert_eq!(view.selected_section_visible_count, 1);
    assert!(!view.selected_section_empty);
}

#[test]
fn each_section_counts_its_own_population() {
    let members = vec![
        owner(SELF_PRINCIPAL),
        admin("ak:did_core:web:bob.example"),
        member("ak:did_core:web:carol.example"),
        member("ak:did_core:web:dave.example"),
        pending_invite("ak:did_core:web:erin.example"),
    ];
    let totals = |section| {
        roster(members.clone(), Vec::new(), section, "", MEMBER_PAGE_SIZE).selected_section_total
    };
    assert_eq!(totals(MemberRosterSection::Members), 2, "non-governance");
    assert_eq!(totals(MemberRosterSection::Owners), 1);
    assert_eq!(totals(MemberRosterSection::Admins), 1);
    assert_eq!(totals(MemberRosterSection::PendingInvites), 1);

    let view = roster(
        members,
        Vec::new(),
        MemberRosterSection::Members,
        "",
        MEMBER_PAGE_SIZE,
    );
    assert_eq!(view.total_members, 4, "pending invites are not members");
    assert_eq!(view.total_pending_invites, 1);
}

#[test]
fn the_authority_root_controller_is_told_to_transfer_ownership_not_to_add_an_admin() {
    // `capabilities.md` §10.4 L858: the root controller's only exit is
    // `ak.realm.owner.transfer`. A second admin satisfies the softer
    // last-admin guard but changes nothing for the root, so the owner reason
    // has to win.
    let members = vec![
        owner(SELF_PRINCIPAL),
        admin("ak:did_core:web:bob.example"),
        member("ak:did_core:web:carol.example"),
    ];
    let reason = roster(
        members,
        Vec::new(),
        MemberRosterSection::Members,
        "",
        MEMBER_PAGE_SIZE,
    )
    .self_leave_disabled_reason
    .expect("the root controller cannot leave");
    assert!(reason.contains("ak.realm.owner.transfer"), "{reason}");
}

#[test]
fn the_last_admin_is_asked_to_hand_over_authority_first() {
    let members = vec![admin(SELF_PRINCIPAL), member("ak:did_core:web:bob.example")];
    let reason = roster(
        members,
        Vec::new(),
        MemberRosterSection::Members,
        "",
        MEMBER_PAGE_SIZE,
    )
    .self_leave_disabled_reason
    .expect("the only governance principal cannot leave");
    assert!(reason.contains("Realm admin authority"), "{reason}");
}

#[test]
fn an_ordinary_member_may_leave() {
    let members = vec![owner("ak:did_core:web:bob.example"), member(SELF_PRINCIPAL)];
    assert!(
        roster(
            members,
            Vec::new(),
            MemberRosterSection::Members,
            "",
            MEMBER_PAGE_SIZE
        )
        .self_leave_disabled_reason
        .is_none()
    );
}

#[test]
fn one_of_two_admins_may_leave() {
    // The guard is about the Realm being left without governance, not about
    // the account holding authority.
    let members = vec![admin(SELF_PRINCIPAL), admin("ak:did_core:web:bob.example")];
    assert!(
        roster(
            members,
            Vec::new(),
            MemberRosterSection::Members,
            "",
            MEMBER_PAGE_SIZE
        )
        .self_leave_disabled_reason
        .is_none()
    );
}

#[test]
fn owned_agents_split_into_joined_and_addable_against_the_active_roster() {
    let joined_agent = agent(
        "ak:did_core:web:agent-joined.example",
        SELF_PRINCIPAL,
        "Joined",
    );
    let addable_agent = agent("ak:did_core:web:agent-free.example", SELF_PRINCIPAL, "Free");
    let other_controller_agent = agent(
        "ak:did_core:web:agent-bobs.example",
        "ak:did_core:web:bob.example",
        "Bob's",
    );
    let members = vec![
        member(SELF_PRINCIPAL),
        member(&joined_agent.agent_id),
        member(&other_controller_agent.agent_id),
    ];

    let view = roster(
        members,
        vec![
            joined_agent.clone(),
            addable_agent.clone(),
            other_controller_agent,
        ],
        MemberRosterSection::MyAgents,
        "",
        MEMBER_PAGE_SIZE,
    );
    assert_eq!(view.self_realm_agent_rows, vec![joined_agent]);
    assert_eq!(view.available_self_agent_rows, vec![addable_agent]);
    assert_eq!(
        view.selected_section_total, 1,
        "the agent section counts joined agents, not groups"
    );
    assert!(
        view.member_set.contains(&actor_key(SELF_PRINCIPAL)),
        "the active roster keys back the agent membership check"
    );
}

#[test]
fn the_section_menu_marks_exactly_the_selected_entry() {
    let selected = MemberRosterSection::Admins;
    assert_eq!(
        MemberRosterSection::Admins.menu_item_class(selected),
        "members-admin-menu-item active"
    );
    assert_eq!(
        MemberRosterSection::Members.menu_item_class(selected),
        "members-admin-menu-item"
    );
}
