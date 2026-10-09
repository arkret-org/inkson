use super::*;

const REALM: &str = "ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM";

#[test]
fn governance_events_fail_closed_without_verified_authority_root_current() {
    assert_eq!(
        governance_authoring_gate(),
        Err(VERIFIED_AUTHORITY_ROOT_UNAVAILABLE),
    );
}

#[test]
fn capability_basis_requires_the_exact_verified_root_controller_and_generation() {
    let realm: arkret_sdk::RealmId = REALM.parse().unwrap();
    let issuer = arkret_sdk::AccountId {
        principal_id: "ak:did_core:web:alice.example".parse().unwrap(),
        station_id: "ak:did_core:web:station.example".parse().unwrap(),
    };
    let row = |controller: arkret_sdk::AccountId, generation| arkret_wire::TypedCurrentRow::Value {
        selector: arkret_wire::CurrentSelector::RealmAuthorityRoot,
        source_stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
        revision: arkret_wire::CurrentRevision {
            commit_id: arkret_wire::RealmCommitId::from_digest([1; 32]),
            stream_position: 9,
        },
        value: serde_json::json!({
            "controller_actor_id": arkret_sdk::ActorId::account(controller),
            "controller_epoch": 2,
            "authority_generation": generation,
            "authority_event_ref": arkret_sdk::EventId::from_token_bytes(realm.token_bytes()).unwrap(),
        }),
    };
    let current = row(issuer.clone(), 0);
    let basis = capability_issuer_basis(REALM, &[current.clone()], &issuer).unwrap();
    assert_eq!(basis.authority_generation, 0);
    assert_eq!(
        basis.authority_event_ref,
        arkret_sdk::EventId::from_token_bytes(realm.token_bytes()).unwrap()
    );
    assert!(capability_issuer_basis(REALM, &[], &issuer).is_none());
    assert!(capability_issuer_basis(REALM, &[current.clone(), current], &issuer).is_none());
    let reset_anchor = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [73; 32]);
    let mut reset = row(issuer.clone(), 1);
    let arkret_wire::TypedCurrentRow::Value { value, .. } = &mut reset;
    value["authority_event_ref"] = serde_json::json!(reset_anchor);
    let reset_basis = capability_issuer_basis(REALM, &[reset], &issuer).unwrap();
    assert_eq!(reset_basis.authority_generation, 1);
    assert_eq!(reset_basis.authority_event_ref, reset_anchor);
    let foreign_station = arkret_sdk::AccountId {
        station_id: "ak:did_core:web:other.example".parse().unwrap(),
        ..issuer.clone()
    };
    assert!(capability_issuer_basis(REALM, &[row(foreign_station, 0)], &issuer).is_none());
}
#[test]
fn governance_failure_hints_cover_the_reducer_rejection_reasons() {
    assert!(governance_failure_hint("submit failed: realm_authority_root_conflict").is_some());
    assert!(governance_failure_hint("rejected: realm_authority_controller_mismatch").is_some());
    assert!(governance_failure_hint("realm_authority_root_missing").is_some());
    assert_eq!(governance_failure_hint("network timeout"), None);
}

// --- security health -------------------------------------------------------

#[test]
fn a_pending_binding_is_reported() {
    let health = realm_security_health(true);
    assert_eq!(health.label, "Binding pending");
    assert_eq!(health.badge, "badge amber");
    assert_eq!(health.alert_count, 1);
}

#[test]
fn a_quiet_realm_reports_no_action_and_no_alerts() {
    let health = realm_security_health(false);
    assert_eq!(health.label, "No active alerts");
    assert_eq!(health.badge, "badge green");
    assert_eq!(health.alert_count, 0);
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
