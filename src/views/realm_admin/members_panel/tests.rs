use super::*;

fn member(id: &str) -> MemberProfile {
    MemberProfile::bare(id.to_owned())
}

fn agent(id: &str, controller: &str, name: &str) -> MemberAgentRow {
    MemberAgentRow {
        agent_id: id.to_owned(),
        controller_id: controller.to_owned(),
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
    let members = BTreeSet::from([joined.agent_id.clone()]);

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

fn dummy_mls_snapshot(realm_id: &str) -> crate::mls::persistence::MlsSnapshotEnvelope {
    crate::mls::persistence::MlsSnapshotEnvelope {
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
    bob.membership = Some("invite".to_owned());

    let (active, pending) = split_member_profiles(vec![alice, bob]);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_id, "ak:did_core:web:alice.example");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].actor_id, "ak:did_core:web:bob.example");
}

#[test]
fn optimistic_pending_invite_does_not_downgrade_joined_member() {
    let mut alice = member("ak:did_core:web:alice.example");
    alice.membership = Some("join".to_owned());
    let mut rows = vec![alice];

    upsert_pending_invite_profile(
        &mut rows,
        "ak:did_core:web:alice.example",
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
        "ak:did_core:web:bob.example",
        Some("bob:example.com"),
        None,
    );

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].membership.as_deref(), Some("invite"));
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
        .find(|group| group.controller.actor_id == "ak:did_core:web:alice.example")
        .expect("alice group exists");
    assert_eq!(alice.agents.len(), 1);
    assert_eq!(alice.agents[0].agent_id, "ak:did_core:web:agent.example");
    assert_eq!(
        groups[0].controller.actor_id,
        "ak:did_core:web:alice.example"
    );
    assert!(
        groups
            .iter()
            .all(|group| group.controller.actor_id != "ak:did_core:web:agent.example")
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
        .find(|group| group.controller.actor_id == "ak:did_core:web:bob.example")
        .expect("bob group exists");
    assert_eq!(bob.agents.len(), 1);
    assert_eq!(bob.agents[0].agent_id, "ak:did_core:web:bob-agent.example");
    assert!(
        groups
            .iter()
            .all(|group| group.controller.actor_id != "ak:did_core:web:bob-agent.example")
    );
}

#[test]
fn projected_member_profiles_use_only_verified_canonical_identity_fields() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("projected-profiles");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "members": [{
                "actor_id": "ak:did_core:web:alice.example",
                "display_name": "Alice",
                "subject_id": "ak:did_core:web:acme.example:users:alice",
                "handle_claims": [{
                    "subject": "ak:did_core:web:acme.example:users:alice",
                    "binding_state": "verified",
                    "handle": "alice:acme.example"
                }],
                "display_profile": {
                    "avatar_blob_ref": "ak:blob:sha256:01015dc8af66d01f557ea63f13538f1964848840a350c5311d1efc8ad138bb91"
                }
            }],
            "admins": ["did:web:alice.example"]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let alice = profiles
        .iter()
        .find(|profile| profile.actor_id == "ak:did_core:web:alice.example")
        .expect("alice profile exists");
    assert_eq!(alice.display_name, None);
    assert_eq!(alice.handles, vec!["alice:acme.example"]);
    assert_eq!(alice.avatar_blob_ref, None);
    assert!(!alice.is_admin);
}

#[test]
fn projected_member_profiles_classify_authority_root_controller_as_owner() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let mut store = temp_store("authority-root-owner");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "members": [{
                "actor_id": "ak:did_core:web:alice.example",
                "membership": "join"
            }],
            "state": {"events": [{
                "kind": "ak.realm.create",
                "actor_id": "ak:did_core:web:alice.example",
                "payload": {"object": {}}
            }]}
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let alice = profiles
        .iter()
        .find(|profile| profile.actor_id == "ak:did_core:web:alice.example")
        .expect("authority-root controller is present");
    assert!(alice.is_owner);
    assert_eq!(alice.membership.as_deref(), Some("join"));
    assert_eq!(profiles.len(), 1);
}

#[test]
fn projected_member_profiles_preserve_pending_invite_membership() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("pending-membership");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "members": [
                {
                    "actor_id": "ak:did_core:web:alice.example",
                    "membership": "join"
                },
                {
                    "actor_id": "ak:did_core:web:bob.example",
                    "membership": "invite"
                }
            ]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_id, "ak:did_core:web:alice.example");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].actor_id, "ak:did_core:web:bob.example");
    assert_eq!(pending[0].membership.as_deref(), Some("invite"));
}

#[test]
fn joined_member_signature_lists_only_joined_members_sorted() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("joined-signature");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "members": [
                { "actor_id": "ak:did_core:web:carol.example", "membership": "join" },
                { "actor_id": "ak:did_core:web:alice.example", "membership": "join" },
                { "actor_id": "ak:did_core:web:bob.example", "membership": "invite" }
            ]
        }),
    );

    // Only `join` members, deduped and sorted — `bob` (invite) is excluded
    // so an outstanding invite never triggers an admission attempt, and the
    // signature is stable regardless of projection ordering.
    assert_eq!(
        joined_member_signature_for_realm(&store, realm_id),
        "ak:did_core:web:alice.example,ak:did_core:web:carol.example"
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
            "body": {
                "actor_id": "ak:did_core:web:bob.example",
                "membership": "join"
            }
        }),
    );
    assert_eq!(
        joined_member_signature_for_realm(&store, realm_id),
        "ak:did_core:web:bob.example"
    );
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
            "invitee": invitee,
            "event_id": "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA",
            "recipient_service_id": "ak:did_core:web:principal.example"
        }),
    );
    store.upsert_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee": invitee,
            "event_id": "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA"
        }),
    );
    store.append_raw_operation(
        "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.accept",
            "actor_id": invitee,
            "signing_device_id": device_id,
            "event_id": "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM",
            "body": { "invite_id": invite_id }
        }),
    );

    assert_eq!(
        accepted_invite_claim_route(&store, realm_id, invitee),
        Some(AcceptedInviteClaimRoute {
            destination_service_id: "ak:did_core:web:principal.example".to_owned(),
            target_device_id: Some(device_id.to_owned()),
        })
    );
    assert!(
        accepted_invite_claim_route(
            &store,
            "ak:realm:Ac4tyK_nwe4AYgJmR9A6pbiRrGZiDOx-i-EVWYUQabXC",
            invitee,
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
            "invitee": invitee,
            "event_id": "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA",
            "recipient_service_id": "ak:did_core:web:principal.example"
        }),
    );
    store.append_raw_operation(
        "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.accept",
            "actor_id": invitee,
            "event_id": "ak:event:ACfHq_7preT7wHLHc3wh1uUqb9gWVTeJlk4olFvqggpM",
            "body": { "invite_id": invite_id }
        }),
    );

    assert_eq!(
        accepted_invite_claim_route(&store, realm_id, invitee),
        Some(AcceptedInviteClaimRoute {
            destination_service_id: "ak:did_core:web:principal.example".to_owned(),
            target_device_id: None,
        })
    );
    let route = accepted_invite_claim_route(&store, realm_id, invitee).unwrap();
    assert!(claim_target_device_id(&route, false).is_err());
    assert_eq!(claim_target_device_id(&route, true).unwrap(), None);
}

#[test]
fn pairwise_claim_selector_never_reuses_a_human_device_coordinate() {
    let route = AcceptedInviteClaimRoute {
        destination_service_id: "ak:did_core:web:principal.example".to_owned(),
        target_device_id: Some("ak:device:0196419b-0000-7000-8000-000000000002".to_owned()),
    };

    assert_eq!(claim_target_device_id(&route, true).unwrap(), None);
    assert_eq!(
        claim_target_device_id(&route, false).unwrap(),
        Some("ak:device:0196419b-0000-7000-8000-000000000002")
    );
}

#[test]
fn projected_duplicate_member_keeps_first_roster_entry() {
    let realm_id = "ak:realm:AKOOF3y2qB7XA-na-H-ZVZqMxf852TBtYhWuYm5iO_yw";
    let mut store = temp_store("pending-then-joined-membership");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "members": [
                {
                    "actor_id": "ak:did_core:web:bob.example",
                    "membership": "invite"
                },
                {
                    "actor_id": "ak:did_core:web:bob.example",
                    "membership": "join"
                }
            ]
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert!(active.is_empty());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].actor_id, "ak:did_core:web:bob.example");
    assert_eq!(pending[0].membership.as_deref(), Some("invite"));
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
            "invitee": "ak:did_core:web:bob.example",
            "invitee_label": "bob:example.com",
            "state": "pending"
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert!(active.is_empty());
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].actor_id, "ak:did_core:web:bob.example");
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
            "invitee": "ak:did_core:web:bob.example",
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
    assert_eq!(active[0].actor_id, "ak:did_core:web:bob.example");
    assert_eq!(active[0].membership.as_deref(), Some("join"));
    assert!(pending.is_empty());
}

#[test]
fn queued_invite_accept_does_not_promote_join_or_trigger_admission() {
    let realm_id = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    let invite_id = "ak:invite:AbrgMKK4KXMpRsGsFrsEQEsjo207metUd4zt8yjzB-UH";
    let mut store = temp_store("queued-invite-accept-no-admission");
    store.save_realm_tree_projection(
        realm_id.to_owned(),
        serde_json::json!({
            "encrypted": true,
            "members": [
                { "actor_id": "ak:did_core:web:alice.example", "membership": "join" },
                { "actor_id": "ak:did_core:web:bob.example", "membership": "invite" }
            ]
        }),
    );
    store
        .save_mls_snapshot(realm_id.to_owned(), dummy_mls_snapshot(realm_id))
        .unwrap();
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invite_id": invite_id,
            "invitee": "ak:did_core:web:bob.example",
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
            .all(|profile| profile.actor_id != "ak:did_core:web:bob.example")
    );
    assert!(pending.iter().any(|profile| {
        profile.actor_id == "ak:did_core:web:bob.example"
            && profile.membership.as_deref() == Some("invite")
    }));
    assert!(mls_admission_candidate_realms_for_actor(&store, "did:web:alice.example").is_empty());
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
            "invitee": "ak:did_core:web:bob.example",
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
            "members": [{
                "actor_id": "ak:did_core:web:bob.example",
                "membership": "join"
            }]
        }),
    );
    store.append_raw_operation(
        "ak:event:A4CYJzQmAt__oBoyRdn8Kbzp9uK8Qv1wxZwStS_7lUHA".to_owned(),
        Some(realm_id.to_owned()),
        serde_json::json!({
            "kind": "ak.invite.create",
            "invitee": "ak:did_core:web:bob.example",
            "state": "pending"
        }),
    );

    let profiles = projected_member_profiles_for_realm(&store, realm_id);
    let (active, pending) = split_member_profiles(profiles);

    assert_eq!(active.len(), 1);
    assert_eq!(active[0].actor_id, "ak:did_core:web:bob.example");
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
            "members_limited": false,
            "members": [
                { "actor_id": "ak:did_core:web:alice.example", "membership": "join" },
                { "actor_id": "ak:did_core:web:agent.example", "membership": "join" }
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
        .save_mls_snapshot(realm_id.to_owned(), dummy_mls_snapshot(realm_id))
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
            "members_limited": true,
            "members": [
                { "actor_id": "ak:did_core:web:bob.example", "membership": "join" }
            ]
        }),
    );

    let membership = projected_realm_membership_hint(&store, realm_id);
    assert_eq!(membership.completeness, MembershipCompleteness::Limited);
    assert_eq!(
        membership.joined,
        BTreeSet::from(["ak:did_core:web:bob.example".to_owned()])
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
