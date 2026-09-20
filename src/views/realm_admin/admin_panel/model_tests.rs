use super::*;

fn root() -> arkret_policy::realm_bootstrap::RealmAuthorityRootValue {
    arkret_policy::realm_bootstrap::RealmAuthorityRootValue {
        controller_actor_id: crate::mls_api_helpers::local_account_actor_id(
            "ak:did_core:web:alice.example",
        )
        .unwrap(),
        controller_epoch: 3,
        authority_generation: 1,
    }
}

const REALM: &str = "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM";

#[test]
fn owner_transfer_payload_pins_digest_and_new_controller() {
    let successor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        "ak:did_core:web:bob.example".parse().unwrap(),
        "ak:did_core:web:remote-station.example".parse().unwrap(),
    ));
    let payload =
        build_owner_transfer_payload(REALM, &root(), &successor.to_string(), "detached-proof")
            .unwrap();
    assert_eq!(payload.patch.controller_actor_id, successor);
    assert_eq!(
        payload.expected_state_digest.as_str(),
        crate::canonical::canonical_sha256(&root()).unwrap()
    );
    // The full builder chain accepts this payload (root authorization ref
    // stamped by the SDK intent builder).
    let intent = crate::event_builders::build_realm_owner_transfer_control_intent(
        "did:web:alice.example",
        payload,
    )
    .unwrap();
    assert_eq!(
        intent.kind().as_str(),
        arkret_wire::event_kind_str::REALM_OWNER_TRANSFER
    );
}

#[test]
fn owner_transfer_payload_rejects_an_empty_acceptance_proof() {
    let successor = root().controller_actor_id.to_string();
    assert!(build_owner_transfer_payload(REALM, &root(), &successor, "  ").is_err());
}

#[test]
fn owner_transfer_does_not_infer_a_station_from_a_principal() {
    assert!(
        build_owner_transfer_payload(
            REALM,
            &root(),
            "ak:did_core:web:bob.example",
            "detached-proof"
        )
        .is_err()
    );
    assert!(
        build_owner_transfer_payload(REALM, &root(), "did:web:bob.example", "detached-proof")
            .is_err()
    );
}

#[test]
fn authority_reset_payload_requires_local_destructive_confirmation() {
    let payload = build_authority_reset_payload(
        REALM,
        &root(),
        arkret_wire::event_kind_str::REALM_AUTHORITY_RESET,
    )
    .unwrap();
    assert_eq!(payload.realm_id.as_str(), REALM);
    assert!(build_authority_reset_payload(REALM, &root(), "yes really").is_err());
}

#[test]
fn governance_failure_hints_cover_the_reducer_rejection_reasons() {
    assert!(governance_failure_hint("submit failed: realm_authority_root_conflict").is_some());
    assert!(governance_failure_hint("rejected: realm_authority_controller_mismatch").is_some());
    assert!(governance_failure_hint("realm_authority_root_missing").is_some());
    assert_eq!(governance_failure_hint("network timeout"), None);
}

// --- security health ladder ------------------------------------------------

#[test]
fn a_paused_notary_outranks_every_other_alert() {
    let health = realm_security_health(true, true);
    assert_eq!(health.label, "Writes paused");
    assert_eq!(health.badge, "badge red");
    assert!(health.next_step.contains("Realm security service"));
    assert_eq!(health.alert_count, 2);
}

#[test]
fn a_pending_binding_is_reported() {
    let health = realm_security_health(false, true);
    assert_eq!(health.label, "Binding pending");
    assert_eq!(health.badge, "badge amber");
    assert_eq!(health.alert_count, 1);
}

#[test]
fn a_quiet_realm_reports_no_action_and_no_alerts() {
    let health = realm_security_health(false, false);
    assert_eq!(health.label, "No active alerts");
    assert_eq!(health.badge, "badge green");
    assert_eq!(health.alert_count, 0);
}

// --- seal diagnostics ------------------------------------------------------

#[test]
fn seal_diagnostics_name_the_reason_a_value_is_absent() {
    let empty = seal_diagnostics(&crate::state::LocalSealView::default());
    assert!(empty.frontier_label.contains("no Seal seen"));
    assert_eq!(empty.state_root_label, "(not published)");
    assert!(empty.mls_epoch_label.contains("no MLS epoch published"));
}

#[test]
fn seal_diagnostics_render_the_published_values() {
    let mut view = crate::state::LocalSealView {
        frontier: vec!["head-a".to_owned()],
        ..crate::state::LocalSealView::default()
    };
    view.state_root = Some("sha256:root".to_owned());
    view.mls_epoch = Some(7);
    let rendered = seal_diagnostics(&view);
    assert_eq!(rendered.frontier_label, "head-a");
    assert_eq!(rendered.state_root_label, "sha256:root");
    assert_eq!(rendered.mls_epoch_label, "7");
}

// --- owner-transfer candidates --------------------------------------------

#[test]
fn transfer_candidates_exclude_this_account_and_unparsable_members() {
    let alice = crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:alice.example")
        .expect("alice actor");
    let bob = crate::mls_api_helpers::local_account_actor_id("ak:did_core:web:bob.example")
        .expect("bob actor");
    let alice_wire = serde_json::to_string(&alice).expect("alice wire");
    let bob_wire = serde_json::to_string(&bob).expect("bob wire");
    let members = vec![
        alice_wire.clone(),
        bob_wire.clone(),
        "ak:did_core:web:carol.example".to_owned(),
    ];

    let candidates = governance_transfer_candidates(&members, Some(&alice));
    assert_eq!(
        candidates,
        vec![bob_wire.clone()],
        "the successor is addressed by exact ActorId, so a bare principal is not a candidate"
    );
    assert_eq!(
        governance_transfer_candidates(&members, None),
        vec![alice_wire, bob_wire],
        "with no signed-in actor nothing is excluded for being self"
    );
}

// --- metadata editor reconciliation ---------------------------------------

fn subject(title: &str, summary: &str, avatar: &str) -> MetadataSubject {
    MetadataSubject {
        kind: crate::models::RealmTreeNodeKind::Realm,
        home_realm_id: "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo".to_owned(),
        title: title.to_owned(),
        summary: summary.to_owned(),
        avatar_blob_ref: avatar.to_owned(),
    }
}

#[test]
fn a_new_subject_fills_every_editor_and_records_the_snapshot() {
    let incoming = subject("Realm A", "About A", "blob-a");
    let patch = reconcile_metadata_editors(
        "ak:realm:A",
        &incoming,
        MetadataEditorState {
            loaded_for: "ak:realm:B",
            loaded_subject: Some(&subject("Realm B", "About B", "blob-b")),
            title: "typed over",
            summary: "typed over",
            avatar_blob_ref: "typed over",
        },
    );
    assert_eq!(patch.title.as_deref(), Some("Realm A"));
    assert_eq!(patch.summary.as_deref(), Some("About A"));
    assert_eq!(patch.avatar_blob_ref.as_deref(), Some("blob-a"));
    assert_eq!(patch.loaded_for.as_deref(), Some("ak:realm:A"));
    assert_eq!(patch.loaded_subject, Some(incoming));
}

#[test]
fn an_unchanged_projection_asks_for_no_writes_at_all() {
    let current = subject("Realm A", "About A", "blob-a");
    assert_eq!(
        reconcile_metadata_editors(
            "ak:realm:A",
            &current,
            MetadataEditorState {
                loaded_for: "ak:realm:A",
                loaded_subject: Some(&current),
                title: "typed over",
                summary: "",
                avatar_blob_ref: "",
            },
        ),
        MetadataEditorPatch::default(),
        "a redundant Signal write on every render is what this guard prevents"
    );
}

#[test]
fn a_late_projection_fills_untouched_editors_and_leaves_edited_ones_alone() {
    // The Profile page rendered before the account projection arrived, so the
    // editors hold the empty previous snapshot — except the title, which the
    // operator has already typed over.
    let previous = subject("", "", "");
    let arrived = subject("Realm A", "About A", "blob-a");
    let patch = reconcile_metadata_editors(
        "ak:realm:A",
        &arrived,
        MetadataEditorState {
            loaded_for: "ak:realm:A",
            loaded_subject: Some(&previous),
            title: "operator's own title",
            summary: "",
            avatar_blob_ref: "",
        },
    );
    assert_eq!(patch.title, None, "typed input is never overwritten");
    assert_eq!(patch.summary.as_deref(), Some("About A"));
    assert_eq!(patch.avatar_blob_ref.as_deref(), Some("blob-a"));
    assert_eq!(patch.loaded_subject, Some(arrived));
}

#[test]
fn a_first_projection_with_no_previous_snapshot_only_records_it() {
    let arrived = subject("Realm A", "About A", "blob-a");
    let patch = reconcile_metadata_editors(
        "ak:realm:A",
        &arrived,
        MetadataEditorState {
            loaded_for: "ak:realm:A",
            loaded_subject: None,
            title: "typed",
            summary: "typed",
            avatar_blob_ref: "typed",
        },
    );
    assert_eq!(patch.title, None);
    assert_eq!(patch.summary, None);
    assert_eq!(patch.avatar_blob_ref, None);
    assert_eq!(patch.loaded_subject, Some(arrived));
}
