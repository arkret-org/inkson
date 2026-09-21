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
fn capability_basis_uses_the_verified_generation_anchor() {
    let realm_id = arkret_sdk::RealmId::new(REALM).unwrap();
    let event_id =
        arkret_sdk::EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
    let basis = crate::state::PersistedRealmAuthorityBasis {
        realm_id: realm_id.clone(),
        current_service_id: "did:web:station.example".parse().unwrap(),
        current_generation: 4,
        genesis_ref: arkret_wire::CommittedEventRef {
            event_id: event_id.clone(),
            commit_id: arkret_wire::RealmCommitId::new(
                "ak:realm_commit:0196419b-0000-7000-8000-000000000001",
            )
            .unwrap(),
            stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id },
            stream_position: 0,
        },
        last_authority_change_ref: None,
        validated_at: chrono::Utc::now(),
    };
    let issuer = capability_issuer_basis(&basis);
    assert_eq!(issuer.authority_generation, 4);
    assert_eq!(issuer.authority_event_ref, event_id);
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
