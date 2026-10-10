use super::*;

#[test]
fn newly_created_agent_selection_survives_directory_refresh_and_follows_filter_changes() {
    use std::cell::RefCell;
    use std::rc::Rc;

    type SelectionControl =
        Rc<RefCell<Option<(Signal<Vec<AgentView>>, Signal<String>, Signal<String>)>>>;
    fn agent(slug: &str, lifecycle: AgentLifecycleState) -> AgentView {
        let mut projection = test_agent_projection(lifecycle, AgentRuntimeState::PendingRuntimeKey);
        projection.agent_id =
            crate::mls_api_helpers::principal_core_id(&format!("did:web:agents.example:{slug}"))
                .unwrap();
        projection.slug = slug.to_owned();
        AgentView {
            agent: projection,
            grants: Vec::new(),
            key_state: None,
        }
    }
    fn harness(control: SelectionControl) -> Element {
        let agents = use_signal(|| vec![agent("old", AgentLifecycleState::Active)]);
        let selected = use_signal(|| agent_id(&agent("old", AgentLifecycleState::Active)));
        let filter = use_signal(|| "all".to_owned());
        *control.borrow_mut() = Some((agents, selected, filter));
        use_agent_selection(agents, selected, filter());
        let visible_selection = selected();
        rsx! { span { "{visible_selection}" } }
    }
    fn settle(dom: &mut VirtualDom) {
        // Drive the real effect/task queue as well as component renders.
        for _ in 0..4 {
            dom.render_immediate_to_vec();
            dom.process_events();
        }
    }
    let control = Rc::new(RefCell::new(None));
    let mut dom = VirtualDom::new_with_props(harness, control.clone());
    dom.rebuild_in_place();
    settle(&mut dom);
    let (mut agents, mut selected, mut filter) = *control.borrow().as_ref().unwrap();
    let new = agent("new", AgentLifecycleState::Active);
    let new_id = agent_id(&new);
    dom.in_runtime(|| selected.set(new_id.clone()));
    settle(&mut dom);
    assert_eq!(
        *selected.peek(),
        new_id,
        "creation selects the new Agent before its directory row arrives"
    );
    dom.in_runtime(|| agents.set(vec![agent("old", AgentLifecycleState::Active), new.clone()]));
    settle(&mut dom);
    assert_eq!(
        *selected.peek(),
        new_id,
        "a fresh directory retains the newly selected Agent"
    );
    let paused = agent("paused", AgentLifecycleState::Paused);
    let paused_id = agent_id(&paused);
    dom.in_runtime(|| agents.set(vec![paused, new.clone()]));
    settle(&mut dom);
    assert_eq!(*selected.peek(), new_id);
    dom.in_runtime(|| filter.set("paused".to_owned()));
    settle(&mut dom);
    assert_eq!(
        *selected.peek(),
        paused_id,
        "route filter changes still reconcile the visible selection"
    );
    dom.in_runtime(|| agents.set(vec![new]));
    settle(&mut dom);
    assert!(
        selected.peek().is_empty(),
        "directory removal clears a selection outside the current filter"
    );
    dom.in_runtime(|| filter.set("all".to_owned()));
    settle(&mut dom);
    assert_eq!(
        *selected.peek(),
        new_id,
        "returning to all selects the remaining Agent"
    );
}

#[test]
fn agent_slug_input_is_trimmed_and_lowercased() {
    assert_eq!(normalize_agent_slug(" AA "), "aa");
    assert_eq!(normalize_agent_slug("Summary_V2"), "summary_v2");
}

#[test]
fn directory_refresh_updates_status_without_dropping_loaded_details() {
    let mut rows = vec![AgentView {
        agent: test_agent_projection(
            AgentLifecycleState::Active,
            AgentRuntimeState::PendingRuntimeKey,
        ),
        grants: vec![
            serde_json::to_value(arkret_sdk::GrantSnapshot {
                grant_id: arkret_sdk::GrantId::new(
                    "ak:grant:AdIokNbDGo5OV8uIK_7oyEOrSIU423PwmxNVThDeiPwQ",
                )
                .unwrap(),
                realm_id: arkret_sdk::RealmId::new(
                    "ak:realm:AYzH43fmsgS6dn7noiHeYxAKUUdkhaJBnOGaWvu3MlBC",
                )
                .unwrap(),
                grant_digest: None,
                expires_at: None,
            })
            .unwrap(),
        ],
        key_state: None,
    }];
    let directory_rows = vec![AgentView {
        agent: test_agent_projection(AgentLifecycleState::Active, AgentRuntimeState::Ready),
        grants: Vec::new(),
        key_state: None,
    }];

    replace_agent_directory(&mut rows, directory_rows);

    assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Active);
    assert_eq!(
        crate::views::agents::model::agent_projection_runtime_state(&rows[0].agent),
        AgentRuntimeState::Ready
    );
    let grant: arkret_sdk::GrantSnapshot =
        serde_json::from_value(rows[0].grants[0].clone()).unwrap();
    assert_eq!(
        grant.grant_id.as_str(),
        "ak:grant:AdIokNbDGo5OV8uIK_7oyEOrSIU423PwmxNVThDeiPwQ"
    );
}

fn test_agent_projection(
    status: AgentLifecycleState,
    runtime_state: AgentRuntimeState,
) -> arkret_sdk::AgentProjection {
    arkret_sdk::AgentProjection {
        agent_id: crate::mls_api_helpers::principal_core_id("did:web:agents.example:summary")
            .unwrap(),
        display_name: None,
        slug: "summary".to_owned(),
        avatar_blob_ref: None,
        lifecycle: status,
        readiness: arkret_sdk::AgentReadiness {
            state: if runtime_state == AgentRuntimeState::Ready {
                arkret_sdk::AgentReadinessState::Ready
            } else {
                arkret_sdk::AgentReadinessState::NotReady
            },
            blockers: match runtime_state {
                AgentRuntimeState::Ready => Vec::new(),
                AgentRuntimeState::Replacing => {
                    vec![arkret_sdk::AgentReadinessBlocker::PairingOpen]
                }
                AgentRuntimeState::PendingRuntimeKey => vec![
                    arkret_sdk::AgentReadinessBlocker::RuntimeKeyMissing,
                    arkret_sdk::AgentReadinessBlocker::PairingOpen,
                ],
                AgentRuntimeState::PairingExpired => {
                    vec![arkret_sdk::AgentReadinessBlocker::RuntimeKeyMissing]
                }
            },
        },
        presence: arkret_sdk::AgentPresence {
            state: arkret_sdk::AgentPresenceState::Unknown,
            expires_at: crate::clock::now_utc(),
            refresh_after: crate::clock::now_utc(),
        },
        created_at: None,
        updated_at: None,
    }
}

fn keyed_authorizations()
-> Vec<arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState> {
    vec![
        arkret_models_collaboration::governance::agent_artifacts::AgentKeyAuthorizationState {
            key_id: arkret_sdk::NonEmptyString::new("runtime-key-1").unwrap(),
            verification_method: arkret_sdk::DidUrl::new(
                "did:web:agents.example:summary#runtime-key-1",
            )
            .unwrap(),
            authorized_event_ref: arkret_sdk::EventId::new(
                "ak:event:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5",
            )
            .unwrap(),
            expires_at: None,
        },
    ]
}

#[test]
fn requested_scope_restores_configured_content_capabilities() {
    let scope = requested_scope_for_presets(
        &[AgentGrantPreset::Read, AgentGrantPreset::ReplyAsAgent],
        &[AgentServiceScopePreset::SubscribeEvents],
    )
    .unwrap();

    assert!(requested_scope_matches_content_preset(
        Some(&scope),
        AgentGrantPreset::Read,
    ));
    assert!(requested_scope_matches_content_preset(
        Some(&scope),
        AgentGrantPreset::ReplyAsAgent,
    ));
    assert!(!requested_scope_matches_content_preset(
        Some(&scope),
        AgentGrantPreset::ActOnBehalf,
    ));
}

#[test]
fn live_pairing_detail_overrides_lossy_directory_runtime_summary() {
    let mut row = test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PendingRuntimeKey,
    );
    row.agent = test_agent_projection(
        AgentLifecycleState::Active,
        AgentRuntimeState::PairingExpired,
    );

    assert_eq!(
        agent_view_runtime_state(&row),
        AgentRuntimeState::PendingRuntimeKey
    );
}

#[test]
fn selected_agent_binding_compares_stable_core_ids_directly() {
    let row = test_pairing_view(AgentLifecycleState::Active, AgentRuntimeState::Ready);
    let key_state = row.key_state.as_ref().unwrap();

    assert!(selected_agent_binding_matches(
        key_state.agent_id.as_str(),
        &key_state.controller_account_id.principal_id,
        key_state,
    ));
    assert!(!selected_agent_binding_matches(
        "did:web:agents.example:summary",
        &key_state.controller_account_id.principal_id,
        key_state,
    ));
    assert!(!selected_agent_binding_matches(
        key_state.agent_id.as_str(),
        &arkret_sdk::DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        key_state,
    ));
}

fn test_pairing_view(status: AgentLifecycleState, runtime_state: AgentRuntimeState) -> AgentView {
    let agent_id = arkret_sdk::project_did_to_core_id(
        &arkret_sdk::Did::new("did:web:agents.example:summary").unwrap(),
    )
    .unwrap();
    let controller_principal_id =
        arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new("did:web:alice.example").unwrap())
            .unwrap();
    let scope = requested_scope_for_presets(
        &[AgentGrantPreset::Read],
        &AgentServiceScopePreset::DEFAULTS,
    )
    .unwrap();
    // Keyed agents (ready/replacing) carry an active authorization; never-keyed
    // agents (pending_runtime_key/pairing_expired) do not.
    let active_authorizations = match runtime_state {
        AgentRuntimeState::Ready | AgentRuntimeState::Replacing => keyed_authorizations(),
        AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::PairingExpired => Vec::new(),
    };
    AgentView {
        agent: test_agent_projection(status, runtime_state),
        grants: Vec::new(),
        key_state: Some(KeyState {
            agent_id,
            controller_account_id: arkret_sdk::AccountId::new(
                controller_principal_id,
                arkret_sdk::DidCoreId::new("ak:did_core:web:station.example".to_owned()).unwrap(),
            ),
            principal_control_realm_id: arkret_sdk::RealmId::new(
                "ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned(),
            )
            .unwrap(),
            controller_authorization_ref: arkret_sdk::DidUrl::new(
                "did:web:agents.example:summary#managed-controller",
            )
            .unwrap(),
            requested_scope: scope,
            pairing_request_id: matches!(
                runtime_state,
                AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
            )
            .then(|| arkret_sdk::OpaqueLocalId::new("pairing-request-1").unwrap()),
            pairing_code: matches!(
                runtime_state,
                AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
            )
            .then(|| "qL7m2nR4sT8vW0xY3zA5bQ".to_owned()),
            pairing_expires_at: matches!(
                runtime_state,
                AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
            )
            .then(|| crate::clock::now_utc() + chrono::Duration::hours(1)),
            approval_request_id: None,
            pending_runtime_key_request: None,
            approval_requested_at: None,
            authorized_event_ref: None,
            authorized_verification_method: None,
            authorized_public_key_digest: None,
            active_authorizations,
            signer_resolution_evidence_ref: None,
            current_signer_evidence: None,
        }),
    }
}

fn test_renew_outcome(replacement: bool) -> AgentRenewPairingOutcome {
    let row = match replacement {
        false => test_pairing_view(
            AgentLifecycleState::Active,
            AgentRuntimeState::PairingExpired,
        ),
        true => test_pairing_view(AgentLifecycleState::Paused, AgentRuntimeState::Ready),
    };
    let agent_did = row.agent.agent_id;
    let key_state = row.key_state.unwrap();
    let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &key_state.agent_id,
        &key_state.controller_account_id.principal_id,
        &key_state.requested_scope,
    )
    .unwrap();
    AgentRenewPairingOutcome {
        agent_id: agent_did,
        principal_control_realm_id: key_state.principal_control_realm_id,
        controller_authorization_ref: key_state.controller_authorization_ref,
        requested_scope_digest,
        pairing_request_id: arkret_sdk::OpaqueLocalId::new("pairing-request-2").unwrap(),
        pairing_code: "fresh-code".to_owned(),
        expires_at: chrono::DateTime::parse_from_rfc3339("2099-07-18T01:00:00.000Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    }
}

fn provision_complete_for_view(view: &AgentView) -> arkret_sdk::AgentProvisionComplete {
    let key_state = view.key_state.as_ref().unwrap();
    let did = arkret_sdk::Did::new("did:web:agents.example:unaddressed").unwrap();
    arkret_sdk::AgentProvisionComplete {
        status: arkret_sdk::AgentProvisionCompleteStatus::Complete,
        agent_id: view.agent.agent_id.clone(),
        did: did.clone(),
        initial_resolution: arkret_sdk::ResolutionCommitment {
            did,
            method_history_head:
                "sha256:0707070707070707070707070707070707070707070707070707070707070707".to_owned(),
            version_id: "1-fixture".to_owned(),
        },
        principal_control_realm_id: key_state.principal_control_realm_id.clone(),
        controller_authorization_ref: key_state.controller_authorization_ref.clone(),
        pairing_request_id: key_state.pairing_request_id.clone().unwrap(),
        pairing_code: key_state.pairing_code.clone(),
        expires_at: key_state.pairing_expires_at.unwrap(),
    }
}

#[test]
fn provisioning_second_agent_installs_its_pairing_before_selection() {
    let old = test_pairing_view(AgentLifecycleState::Active, AgentRuntimeState::Ready);
    let old_id = agent_id(&old);
    let mut created = test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PendingRuntimeKey,
    );
    let created_id =
        crate::mls_api_helpers::principal_core_id("did:web:agents.example:unaddressed").unwrap();
    created.agent.agent_id = created_id.clone();
    created.agent.slug = "unaddressed".to_owned();
    created.key_state.as_mut().unwrap().agent_id = created_id.clone();
    let outcome = provision_complete_for_view(&created);
    let mut stale_detail = created.clone();
    stale_detail.key_state = None;
    let controller = created
        .key_state
        .as_ref()
        .unwrap()
        .controller_account_id
        .clone();
    let mut rows = vec![old];
    let selected = apply_provisioned_agent_view(
        &mut rows,
        created,
        &outcome,
        &controller.principal_id,
        &controller.station_id,
    )
    .unwrap();

    // A detail request issued before the provision result owns an older epoch.
    apply_agent_detail_read(&mut rows, stale_detail, 1, 2);

    assert_ne!(selected, old_id);
    assert!(rows.iter().any(|row| agent_id(row) == selected));
    let panel = build_agent_admin_view(&rows, &selected, "all", &now_before_expiry());
    assert_eq!(panel.selected_slug, "unaddressed");
    assert!(panel.selected_should_show_pairing_card);
    assert_eq!(
        panel.selected_pairing_request_id,
        outcome.pairing_request_id.as_str()
    );
    assert_eq!(panel.selected_pairing_code, outcome.pairing_code.unwrap());
}

#[test]
fn provisioning_rejects_mismatched_authoritative_identity_and_pcr_without_upsert() {
    let created = test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PendingRuntimeKey,
    );
    let outcome = provision_complete_for_view(&created);
    let controller = created
        .key_state
        .as_ref()
        .unwrap()
        .controller_account_id
        .clone();
    for changed_coordinate in 0..7 {
        let mut wrong = created.clone();
        let other = arkret_sdk::DidCoreId::new("ak:did_core:web:other.example").unwrap();
        match changed_coordinate {
            0 => wrong.agent.agent_id = other,
            1 => wrong.key_state.as_mut().unwrap().agent_id = other,
            2 => {
                wrong
                    .key_state
                    .as_mut()
                    .unwrap()
                    .controller_account_id
                    .principal_id = other
            }
            3 => {
                wrong
                    .key_state
                    .as_mut()
                    .unwrap()
                    .controller_account_id
                    .station_id = other
            }
            4 => {
                wrong.key_state.as_mut().unwrap().principal_control_realm_id =
                    arkret_sdk::RealmId::new(
                        "ak:realm:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc",
                    )
                    .unwrap()
            }
            5 => {
                wrong
                    .key_state
                    .as_mut()
                    .unwrap()
                    .controller_authorization_ref =
                    arkret_sdk::DidUrl::new("did:web:other.example#controller").unwrap()
            }
            _ => wrong.key_state = None,
        }
        let mut rows = Vec::new();
        assert!(
            apply_provisioned_agent_view(
                &mut rows,
                wrong,
                &outcome,
                &controller.principal_id,
                &controller.station_id,
            )
            .is_err(),
            "changed coordinate {changed_coordinate}"
        );
        assert!(rows.is_empty(), "changed coordinate {changed_coordinate}");
    }
}

#[test]
fn provisioning_installs_authoritative_consumed_expired_and_renewed_pairing_states() {
    let created = test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PendingRuntimeKey,
    );
    let outcome = provision_complete_for_view(&created);
    let controller = created
        .key_state
        .as_ref()
        .unwrap()
        .controller_account_id
        .clone();
    for state in [
        AgentRuntimeState::Ready,
        AgentRuntimeState::PairingExpired,
        AgentRuntimeState::PendingRuntimeKey,
        AgentRuntimeState::Replacing,
    ] {
        let mut current = test_pairing_view(AgentLifecycleState::Active, state);
        if matches!(
            state,
            AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
        ) {
            let key_state = current.key_state.as_mut().unwrap();
            key_state.pairing_request_id =
                Some(arkret_sdk::OpaqueLocalId::new("renewed-pairing").unwrap());
            key_state.pairing_code = Some("renewed-code".to_owned());
            key_state.pairing_expires_at = Some(outcome.expires_at + chrono::Duration::hours(1));
        }
        // Exercise the SDK's serialized authoritative shape rather than filling
        // absent consumed/expired fields back from the provision response.
        let current: AgentView =
            serde_json::from_value(serde_json::to_value(&current).unwrap()).unwrap();
        let expected_key_state = serde_json::to_value(&current.key_state).unwrap();
        let mut rows = Vec::new();
        let selected = apply_provisioned_agent_view(
            &mut rows,
            current,
            &outcome,
            &controller.principal_id,
            &controller.station_id,
        )
        .unwrap();
        assert_eq!(selected, outcome.agent_id.as_str());
        assert_eq!(
            serde_json::to_value(&rows[0].key_state).unwrap(),
            expected_key_state
        );
        assert_eq!(agent_view_runtime_state(&rows[0]), state);
        let panel = build_agent_admin_view(&rows, &selected, "all", &now_before_expiry());
        assert_eq!(
            panel.selected_should_show_pairing_card,
            state != AgentRuntimeState::Ready
        );
        if matches!(
            state,
            AgentRuntimeState::PendingRuntimeKey | AgentRuntimeState::Replacing
        ) {
            assert_eq!(panel.selected_pairing_code, "renewed-code");
        } else {
            assert!(panel.selected_pairing_code.is_empty());
        }
    }
}

#[test]
fn bootstrap_renewal_reopens_expired_agent_and_exposes_fresh_material() {
    let mut rows = vec![test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PairingExpired,
    )];
    let outcome = test_renew_outcome(false);
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now).unwrap();

    // Bootstrap re-open preserves the lifecycle intent and moves only the
    // derived runtime_state back to pending_runtime_key.
    assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Active);
    let key_state = rows[0].key_state.as_ref().unwrap();
    assert_eq!(
        crate::views::agents::model::key_state_runtime_state(key_state),
        AgentRuntimeState::PendingRuntimeKey
    );
    assert_eq!(key_state.pairing_code.as_deref(), Some("fresh-code"));
}

#[test]
fn renewal_rejects_each_changed_controller_binding_without_publishing_pairing_code() {
    let baseline = test_renew_outcome(false);
    let mut wrong_realm = baseline.clone();
    wrong_realm.principal_control_realm_id = arkret_sdk::RealmId::new(
        "ak:realm:AYzH43fmsgS6dn7noiHeYxAKUUdkhaJBnOGaWvu3MlBC".to_owned(),
    )
    .unwrap();
    let mut wrong_authorization = baseline.clone();
    wrong_authorization.controller_authorization_ref =
        arkret_sdk::DidUrl::new("did:web:agents.example:summary#other-controller").unwrap();
    let mut wrong_scope = baseline.clone();
    wrong_scope.requested_scope_digest =
        arkret_sdk::Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap();
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    for outcome in [wrong_realm, wrong_authorization, wrong_scope] {
        let mut rows = vec![test_pairing_view(
            AgentLifecycleState::Active,
            AgentRuntimeState::PairingExpired,
        )];
        assert_eq!(
            apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now),
            Err("renewed pairing response does not match the loaded Agent binding")
        );
        assert_ne!(
            rows[0].key_state.as_ref().unwrap().pairing_code.as_deref(),
            Some("fresh-code")
        );
    }
}

#[test]
fn replacement_renewal_preserves_lifecycle_and_projects_replacing() {
    let mut rows = vec![test_pairing_view(
        AgentLifecycleState::Paused,
        AgentRuntimeState::Ready,
    )];
    let outcome = test_renew_outcome(true);
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now).unwrap();

    // Runtime replacement preserves the lifecycle intent (paused stays
    // paused; an active agent would stay active) and only projects the
    // derived runtime_state as replacing (key-management.md §3.6.1).
    assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Paused);
    let key_state = rows[0].key_state.as_ref().unwrap();
    assert_eq!(
        crate::views::agents::model::key_state_runtime_state(key_state),
        AgentRuntimeState::Replacing
    );
    assert_eq!(key_state.pairing_code.as_deref(), Some("fresh-code"));
}

#[test]
fn authoritative_pairing_reconcile_repairs_and_upserts_a_stale_local_row() {
    let authoritative = test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PairingExpired,
    );
    let outcome = test_renew_outcome(false);
    let mut stale = authoritative.clone();
    stale.key_state = None;
    let mut rows = vec![stale];
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    assert!(apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now,).is_err());
    reconcile_refreshed_pairing(
        &mut rows,
        authoritative,
        outcome.agent_id.as_str(),
        &outcome,
        now,
    )
    .unwrap();

    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]
            .key_state
            .as_ref()
            .and_then(|state| state.pairing_code.as_deref()),
        Some("fresh-code")
    );
}

#[test]
fn accepted_replacement_rejects_old_detail_but_allows_current_consumed_handle() {
    let ready = test_pairing_view(AgentLifecycleState::Active, AgentRuntimeState::Ready);
    let mut rows = vec![ready.clone()];
    let outcome = test_renew_outcome(true);
    let now = chrono::DateTime::parse_from_rfc3339("2026-07-18T00:00:00.000Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    apply_renewed_pairing(&mut rows, outcome.agent_id.as_str(), &outcome, now).unwrap();

    apply_agent_detail_read(&mut rows, ready.clone(), 1, 2);
    assert_eq!(
        agent_view_runtime_state(&rows[0]),
        AgentRuntimeState::Replacing
    );
    assert_eq!(
        rows[0]
            .key_state
            .as_ref()
            .unwrap()
            .pairing_request_id
            .as_deref(),
        Some(outcome.pairing_request_id.as_str())
    );
    assert_eq!(rows[0].agent.lifecycle, AgentLifecycleState::Active);

    apply_agent_detail_read(&mut rows, ready, 3, 3);
    assert_eq!(agent_view_runtime_state(&rows[0]), AgentRuntimeState::Ready);
    assert!(
        rows[0]
            .key_state
            .as_ref()
            .unwrap()
            .pairing_request_id
            .is_none()
    );
}

#[test]
fn pairing_renewal_is_available_before_an_open_request_expires() {
    assert!(should_offer_pairing_renewal(true, "pending_runtime_key"));
    assert!(should_offer_pairing_renewal(true, "pairing_expired"));
    assert!(!should_offer_pairing_renewal(false, "pending_runtime_key"));
    // Bootstrap renewal is offered only for the never-keyed runtime states;
    // ready/replacing (keyed) are not bootstrap-renewable.
    assert!(!should_offer_pairing_renewal(true, "ready"));
    assert!(!should_offer_pairing_renewal(true, "replacing"));
}

#[test]
fn pairing_credentials_require_bootstrap_or_explicit_replacement_state() {
    assert!(should_show_pairing_card(
        "pending_runtime_key",
        true,
        false,
        false
    ));
    assert!(should_show_pairing_card(
        "pairing_expired",
        true,
        true,
        false
    ));
    assert!(!should_show_pairing_card("ready", true, false, true));
    assert!(!should_show_pairing_card("replacing", true, false, false));
    assert!(should_show_pairing_card("replacing", true, false, true));
}

/// A far-future timestamp, so a live pairing handle is never read as expired.
fn now_before_expiry() -> String {
    crate::clock::now_timestamp()
}

#[test]
fn panel_view_picks_the_empty_state_copy_from_the_same_filter_the_list_uses() {
    // `has_any_agents` is what chooses between "No agents yet." and "No agents
    // match this filter.", so it is computed through `agent_matches_filter` with
    // the same `"all"` the list uses. "all" is not "every row": it excludes
    // deactivated Agents, which no default filter shows.
    let mut deactivated = test_pairing_view(
        AgentLifecycleState::Deactivated,
        AgentRuntimeState::PairingExpired,
    );
    deactivated.agent.slug = "retired".to_owned();
    let view = build_agent_admin_view(&[deactivated], "", "all", &now_before_expiry());
    assert!(view.visible_agents.is_empty());
    assert!(!view.has_any_agents);
    assert_eq!(view.selected_title, "No agent selected");

    // A row the account still holds but the active filter hides is the other
    // branch: the list is empty, yet the copy must not claim there are none.
    let paused = test_pairing_view(AgentLifecycleState::Paused, AgentRuntimeState::Ready);
    let view = build_agent_admin_view(&[paused], "", "active", &now_before_expiry());
    assert!(view.visible_agents.is_empty());
    assert!(view.has_any_agents);
}

#[test]
fn panel_view_drops_a_selection_the_active_filter_excludes() {
    let rows = vec![test_pairing_view(
        AgentLifecycleState::Paused,
        AgentRuntimeState::Ready,
    )];
    let selected = agent_id(&rows[0]);

    let matching = build_agent_admin_view(&rows, &selected, "paused", &now_before_expiry());
    assert_eq!(matching.selected_status, "paused");
    assert!(matching.selected_has_pcr_binding);

    // The list filter and the selection are independent inputs; a selection the
    // filter excludes renders the empty detail pane rather than a row the list
    // beside it is not showing.
    let excluded = build_agent_admin_view(&rows, &selected, "active", &now_before_expiry());
    assert!(excluded.selected_status.is_empty());
    assert!(!excluded.selected_has_pcr_binding);
}

#[test]
fn panel_view_offers_replacement_only_to_a_ready_runtime() {
    let ready = vec![test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::Ready,
    )];
    let view = build_agent_admin_view(&ready, &agent_id(&ready[0]), "all", &now_before_expiry());
    assert!(view.selected_can_replace_runtime);
    assert!(!view.selected_is_replacement_pairing);
    // A ready runtime has no live pairing handle, so no card and no renewal.
    assert!(!view.selected_should_show_pairing_card);
    assert!(!view.selected_can_renew_pairing);

    let replacing = vec![test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::Replacing,
    )];
    let view = build_agent_admin_view(
        &replacing,
        &agent_id(&replacing[0]),
        "all",
        &now_before_expiry(),
    );
    // A replacement already in flight must not offer a second one.
    assert!(!view.selected_can_replace_runtime);
    assert!(view.selected_is_replacement_pairing);
    assert!(view.selected_should_show_pairing_card);
    assert!(view.selected_can_renew_pairing);
}

#[test]
fn panel_view_reads_the_pairing_handle_from_the_key_state_not_the_readiness_summary() {
    let rows = vec![test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PendingRuntimeKey,
    )];
    let view = build_agent_admin_view(&rows, &agent_id(&rows[0]), "all", &now_before_expiry());

    assert_eq!(view.selected_runtime_state, "pending_runtime_key");
    assert_eq!(view.selected_pairing_code, "qL7m2nR4sT8vW0xY3zA5bQ");
    assert!(view.selected_has_pairing_handle);
    // The handle is live, so nothing here may report it expired.
    assert!(!view.selected_pairing_is_expired);
    assert!(view.selected_should_show_pairing_card);
    assert!(view.selected_can_renew_pairing);
}

#[test]
fn panel_view_expires_a_live_handle_once_the_clock_passes_its_deadline() {
    let rows = vec![test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::PendingRuntimeKey,
    )];
    let after_expiry = (crate::clock::now_utc() + chrono::Duration::hours(2)).to_rfc3339();

    let view = build_agent_admin_view(&rows, &agent_id(&rows[0]), "all", &after_expiry);

    // Expiry is read off the key state's own deadline, not off the readiness
    // blockers: the runtime axis still says `pending_runtime_key`.
    assert_eq!(view.selected_runtime_state, "pending_runtime_key");
    assert!(view.selected_pairing_is_expired);
    assert!(view.selected_should_show_pairing_card);
}

#[test]
fn panel_view_projects_the_configured_capability_ceiling_onto_the_preset_rows() {
    let rows = vec![test_pairing_view(
        AgentLifecycleState::Active,
        AgentRuntimeState::Ready,
    )];
    let view = build_agent_admin_view(&rows, &agent_id(&rows[0]), "all", &now_before_expiry());

    // `test_pairing_view` configures Read plus the default service scopes.
    let content: Vec<_> = view
        .selected_content_capabilities
        .iter()
        .filter(|(_, on)| *on)
        .map(|(preset, _)| *preset)
        .collect();
    assert_eq!(content, vec![AgentGrantPreset::Read]);
    let services: Vec<_> = view
        .selected_service_capabilities
        .iter()
        .filter(|(_, on)| *on)
        .map(|(preset, _)| *preset)
        .collect();
    assert_eq!(services, AgentServiceScopePreset::DEFAULTS.to_vec());

    // With nothing selected every row must read off, not stay stuck on the
    // previous Agent's ceiling.
    let empty = build_agent_admin_view(&rows, "", "all", &now_before_expiry());
    assert!(
        empty
            .selected_content_capabilities
            .iter()
            .all(|(_, on)| !on)
    );
    assert!(
        empty
            .selected_service_capabilities
            .iter()
            .all(|(_, on)| !on)
    );
}
