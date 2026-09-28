use super::*;

fn node(id: &str, title: &str, parent: Option<&str>) -> RealmTreeNode {
    let kind = if id.starts_with("ak:space:") {
        RealmTreeNodeKind::Space
    } else {
        RealmTreeNodeKind::Realm
    };
    RealmTreeNode {
        id: id.to_owned(),
        title: title.to_owned(),
        description: None,
        tags: Default::default(),
        public: true,
        category: None,
        direct_conversation: false,
        parent_space_id: parent.map(ToOwned::to_owned),
        child_space_ids: Vec::new(),
        kind,
        realm_id: match kind {
            RealmTreeNodeKind::Realm => id.to_owned(),
            RealmTreeNodeKind::Space => parent
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| REALM_A.to_owned()),
        },
    }
}

const REALM_A: &str = "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo";
const REALM_B: &str = "ak:realm:AZQnaSleDidYaYIvfwYy3au5gnd_DSinxyUHEl7ewtxk";
const CONTROL_REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

fn navigation_input<'a>(
    loaded: &'a [RealmTreeNode],
    control: &'a BTreeSet<String>,
    pinned: &'a BTreeSet<String>,
    projections: &'a BTreeMap<String, Value>,
    local_mls: &'a BTreeSet<String>,
    remarks: &'a BTreeMap<String, RealmRemark>,
    active_realm_id: &'a str,
    query: &'a str,
) -> RealmNavigationInput<'a> {
    RealmNavigationInput {
        loaded_nodes: loaded,
        principal_control_realm_ids: control,
        context_realm_id: None,
        active_realm_id,
        pinned_realm_ids: pinned,
        realm_tree_projections: projections,
        current_product_view: None,
        realm_ids_with_local_mls: local_mls,
        realm_remarks: remarks,
        collaboration_query: query,
    }
}

#[test]
fn routed_product_realm_replaces_the_remembered_selection() {
    let control = BTreeSet::new();
    let selection = resolve_realm_selection(Some(REALM_B), REALM_A, &control);
    assert_eq!(selection.effective_realm_id.as_deref(), Some(REALM_B));
    assert_eq!(selection.remember.as_deref(), Some(REALM_B));
}

#[test]
fn routed_realm_already_remembered_writes_nothing_back() {
    let control = BTreeSet::new();
    let selection = resolve_realm_selection(Some(REALM_B), REALM_B, &control);
    assert_eq!(selection.effective_realm_id.as_deref(), Some(REALM_B));
    assert_eq!(selection.remember, None, "no redundant Signal write");
}

#[test]
fn control_realm_route_neither_selects_nor_is_remembered() {
    // A principal-control Realm reached by route must not become the product
    // selection, and must not overwrite the Realm the user last worked in.
    let control = BTreeSet::from([CONTROL_REALM.to_owned()]);
    let selection = resolve_realm_selection(Some(CONTROL_REALM), REALM_A, &control);
    assert_eq!(selection.effective_realm_id.as_deref(), Some(REALM_A));
    assert_eq!(selection.remember, None);
}

#[test]
fn blank_remembered_selection_without_a_route_stays_unset() {
    let control = BTreeSet::new();
    let selection = resolve_realm_selection(None, "   ", &control);
    assert_eq!(selection.effective_realm_id, None);
    assert_eq!(selection.remember, None);
}

#[test]
fn control_and_direct_conversation_realms_are_hidden_with_their_subtrees() {
    let mut direct = node(REALM_B, "Direct", None);
    direct.direct_conversation = true;
    let loaded = vec![
        node(REALM_A, "Acme", None),
        node(
            "ak:space:01964137-0000-7000-8000-0000000000a1",
            "Board",
            Some(REALM_A),
        ),
        direct,
        node(CONTROL_REALM, "Control", None),
    ];
    let control = BTreeSet::from([CONTROL_REALM.to_owned()]);
    let (pinned, projections, local_mls, remarks) = Default::default();
    let model = build_realm_navigation(navigation_input(
        &loaded,
        &control,
        &pinned,
        &projections,
        &local_mls,
        &remarks,
        REALM_A,
        "",
    ));
    let visible: Vec<&str> = model
        .collaboration_nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect();
    assert_eq!(
        visible,
        vec![REALM_A, "ak:space:01964137-0000-7000-8000-0000000000a1"]
    );
    assert_eq!(model.manage_realm_rows.len(), 1);
    assert_eq!(model.manage_realm_rows[0].space_count, 1);
}

#[test]
fn manage_rows_prefer_the_local_remark_over_the_public_title() {
    let loaded = vec![node(REALM_A, "Public title", None)];
    let control = BTreeSet::new();
    let (pinned, projections, local_mls) = Default::default();
    let mut remarks = BTreeMap::new();
    let mut remark = RealmRemark::new(
        crate::test_support::realm_id(REALM_A),
        "2026-06-01T00:00:00.000Z".parse().unwrap(),
    );
    remark.local_name = "My name".to_owned();
    remarks.insert(REALM_A.to_owned(), remark);
    let model = build_realm_navigation(navigation_input(
        &loaded,
        &control,
        &pinned,
        &projections,
        &local_mls,
        &remarks,
        REALM_A,
        "",
    ));
    assert_eq!(model.manage_realm_rows[0].display_name, "My name");
    assert_eq!(model.manage_realm_rows[0].title, "Public title");
    // Filtering matches the remark as well as the public title.
    for query in ["my name", "public"] {
        let filtered = build_realm_navigation(navigation_input(
            &loaded,
            &control,
            &pinned,
            &projections,
            &local_mls,
            &remarks,
            REALM_A,
            query,
        ));
        assert_eq!(filtered.filtered_realm_tree.len(), 1, "query {query}");
    }
}

#[test]
fn a_local_mls_snapshot_keeps_the_realm_encrypted_without_a_projection() {
    // Regression guard for the topbar/row disagreement: with no security state
    // in the projection the row must still read encrypted from local MLS
    // evidence rather than defaulting to unencrypted.
    let loaded = vec![node(REALM_A, "Acme", None)];
    let control = BTreeSet::new();
    let (pinned, remarks) = Default::default();
    let projections = BTreeMap::new();
    let local_mls = BTreeSet::from([REALM_A.to_owned()]);
    let model = build_realm_navigation(navigation_input(
        &loaded,
        &control,
        &pinned,
        &projections,
        &local_mls,
        &remarks,
        REALM_A,
        "",
    ));
    assert!(model.manage_realm_rows[0].encrypted);
    assert!(model.active_realm_security_encrypted);
}

#[test]
fn active_realm_security_falls_back_to_unencrypted_for_an_unknown_realm() {
    let loaded = vec![node(REALM_A, "Acme", None)];
    let control = BTreeSet::new();
    let (pinned, projections, local_mls, remarks) = Default::default();
    let model = build_realm_navigation(navigation_input(
        &loaded,
        &control,
        &pinned,
        &projections,
        &local_mls,
        &remarks,
        REALM_B,
        "",
    ));
    assert!(!model.active_realm_security_encrypted);
    assert!(model.active_projection_realm_id.is_empty());
}

#[test]
fn shell_chrome_carries_direction_and_sidebar_state_into_both_class_lists() {
    let ltr = shell_chrome("night", false, TextDirection::Ltr, false, false);
    assert_eq!(ltr.shell_class, "shell app");
    assert_eq!(ltr.auth_class, "auth-shell");
    assert_eq!(ltr.theme_toggle_icon, "sun");

    let rtl = shell_chrome("light", false, TextDirection::Rtl, true, true);
    assert_eq!(
        rtl.shell_class,
        "shell app rtl sidebar-collapsed sidebar-resizing"
    );
    assert_eq!(rtl.auth_class, "auth-shell rtl");
    assert_eq!(rtl.theme_toggle_icon, "moon");
}

#[test]
fn system_theme_decides_the_toggle_when_the_mode_is_system() {
    assert_eq!(
        shell_chrome("system", true, TextDirection::Ltr, false, false).theme_toggle_icon,
        "sun"
    );
    assert_eq!(
        shell_chrome("system", false, TextDirection::Ltr, false, false).theme_toggle_icon,
        "moon"
    );
}

#[test]
fn theme_toggle_title_stays_the_english_default_the_e2e_suite_asserts() {
    // `inkson.strands.account-settings.spec.ts` reads these exact titles.
    assert_eq!(
        shell_chrome("night", false, TextDirection::Ltr, false, false).theme_toggle_title,
        "Switch to light theme"
    );
    assert_eq!(
        shell_chrome("light", false, TextDirection::Ltr, false, false).theme_toggle_title,
        "Switch to night theme"
    );
}

#[test]
fn signed_out_identity_labels_do_not_leak_a_principal_id() {
    let store = crate::state::isolated_store_for_tests("shell-model-signed-out");
    let labels = account_identity_labels(AccountIdentityInput {
        has_session: false,
        personal_handles: &[],
        personal_handles_status: "unknown",
        account_display_name: "",
        device_display_name: "",
        device_id_label: "ak:dev…001",
        principal_id_value: "ak:did_core:web:alice.example",
        store: &store,
    });
    assert_eq!(labels.label, "Not signed in");
    assert_eq!(labels.detail, "Refresh server metadata, then sign in");
    assert!(!labels.label.contains("alice.example"));
}

#[test]
fn identity_labels_prefer_display_name_then_handle_then_protocol_id() {
    let store = crate::state::isolated_store_for_tests("shell-model-ladder");
    let handles = ["alice.example".to_owned()];
    let with_name = account_identity_labels(AccountIdentityInput {
        has_session: true,
        personal_handles: &handles,
        personal_handles_status: "verified",
        account_display_name: "Alice",
        device_display_name: "Laptop",
        device_id_label: "ak:dev…001",
        principal_id_value: "ak:did_core:web:alice.example",
        store: &store,
    });
    assert_eq!(with_name.label, "Alice");
    assert_eq!(with_name.detail, "@alice.example · Laptop");
    assert_eq!(with_name.handles_title, "alice.example");

    let without_name = account_identity_labels(AccountIdentityInput {
        has_session: true,
        personal_handles: &handles,
        personal_handles_status: "verified",
        account_display_name: "   ",
        device_display_name: "",
        device_id_label: "ak:dev…001",
        principal_id_value: "ak:did_core:web:alice.example",
        store: &store,
    });
    assert_eq!(without_name.label, "@alice.example");
    assert_eq!(without_name.detail, "@alice.example · ak:dev…001");

    let without_handle = account_identity_labels(AccountIdentityInput {
        has_session: true,
        personal_handles: &[],
        personal_handles_status: "none",
        account_display_name: "",
        device_display_name: "Laptop",
        device_id_label: "ak:dev…001",
        principal_id_value: "ak:did_core:web:alice.example",
        store: &store,
    });
    assert_eq!(without_handle.detail, "Laptop");
    assert_eq!(without_handle.handles_title, without_handle.handles_label);
}

fn contact_row(principal: &str) -> crate::models::ContactListRow {
    crate::models::ContactListRow {
        peer: arkret_sdk::contact_operations::ContactPeer::Human {
            account_id: crate::test_support::authority(principal),
        },
        state: arkret_sdk::ContactState::Accepted,
        request_event_ref: None,
        request_message: None,
        response_event_ref: None,
        tombstone_event_ref: None,
        next_prepare_input: None,
        granted_to_peer_scopes: Vec::new(),
        granted_by_peer_scopes: Vec::new(),
        bidirectional_scopes: vec![arkret_sdk::contact_operations::ContactScope::DirectMessage],
        effective_scopes: None,
        continuity_evidence: None,
        direct_conversation: None,
        contact_agent_projections: Vec::new(),
    }
}

#[test]
fn contact_inbox_badge_tracks_only_pending_incoming_requests() {
    use std::cell::Cell;
    use std::rc::Rc;

    use dioxus::prelude::*;
    let count = Rc::new(Cell::new(usize::MAX));
    let mut dom = dioxus::prelude::VirtualDom::new_with_props(
        |count: Rc<Cell<usize>>| {
            let rows = dioxus::prelude::use_signal(|| {
                [
                    arkret_sdk::ContactState::PendingIncoming,
                    arkret_sdk::ContactState::PendingOutgoing,
                    arkret_sdk::ContactState::Accepted,
                    arkret_sdk::ContactState::Rejected,
                ]
                .into_iter()
                .map(|state| {
                    let mut row = contact_row("ak:did_core:web:peer.example");
                    row.state = state;
                    row
                })
                .collect()
            });
            count.set(
                crate::app::ContactInbox(rows)
                    .pending_count(&crate::state::ClientLocalState::default()),
            );
            dioxus::prelude::rsx! {}
        },
        count.clone(),
    );
    dom.rebuild_in_place();
    assert_eq!(count.get(), 1);
}

#[test]
fn contact_inbox_uses_one_revision_for_visible_rows_and_attention() {
    use std::cell::RefCell;
    use std::rc::Rc;

    use arkret_models_collaboration::objects::productivity::{
        AccountBlocklistMode, AccountBlocklistSurface,
    };
    use dioxus::prelude::*;

    let result = Rc::new(RefCell::new(Vec::new()));
    let mut dom = VirtualDom::new_with_props(
        |result: Rc<RefCell<Vec<(u64, usize, Vec<String>)>>>| {
            let rows = use_signal(|| {
                [
                    "block.example",
                    "hide.example",
                    "mute.example",
                    "clear.example",
                ]
                .into_iter()
                .map(|station| {
                    let mut row = contact_row(&format!("ak:did_core:web:{station}"));
                    row.state = arkret_sdk::ContactState::PendingIncoming;
                    row
                })
                .collect()
            });
            let mut snapshot = crate::state::ClientLocalState::default();
            snapshot.client_blocklist_revision = 7;
            snapshot.client_blocklist = [
                ("block.example", AccountBlocklistMode::Block),
                ("hide.example", AccountBlocklistMode::Hide),
                ("mute.example", AccountBlocklistMode::Mute),
            ]
            .into_iter()
            .map(|(station, mode)| {
                let actor = contact_row(&format!("ak:did_core:web:{station}"))
                    .peer
                    .contact_actor_id();
                let mut entry = crate::account_data::new_blocklist_entry(
                    crate::account_data::BlocklistUiTargetKind::Actor,
                    &actor.to_string(),
                    None,
                    vec![AccountBlocklistSurface::Contacts],
                    None,
                    chrono::Utc::now(),
                )
                .unwrap();
                entry.mode = mode;
                entry
            })
            .collect();
            let inbox = crate::app::ContactInbox(rows);
            let visible = inbox
                .visible_pending(&snapshot)
                .into_iter()
                .map(|row| row.peer.contact_actor_id().to_string())
                .collect();
            result.borrow_mut().push((
                snapshot.client_blocklist_revision,
                inbox.pending_count(&snapshot),
                visible,
            ));
            rsx! {}
        },
        result.clone(),
    );
    dom.rebuild_in_place();
    let observed = result.borrow();
    let (revision, attention, visible) = &observed[0];
    assert_eq!(*revision, 7);
    assert_eq!(*attention, 1);
    assert_eq!(visible.len(), 2);
    assert!(visible.iter().any(|actor| actor.contains("mute.example")));
    assert!(visible.iter().any(|actor| actor.contains("clear.example")));
}

fn pinned_remark(principal: &str) -> ContactRemark {
    let mut remark = ContactRemark::new(
        crate::test_support::core_id(principal),
        String::new(),
        "2026-06-01T00:00:00.000Z".parse().unwrap(),
    );
    remark.pinned = true;
    remark
}

const CONTACT_A: &str = "ak:did_core:web:aaa.example";
const CONTACT_B: &str = "ak:did_core:web:bbb.example";
const CONTACT_C: &str = "ak:did_core:web:ccc.example";

#[test]
fn blocked_pending_contact_is_hidden_from_default_sidebar_without_removing_accepted_rows() {
    use arkret_models_collaboration::objects::productivity::AccountBlocklistSurface;

    let mut store = crate::state::isolated_store_for_tests("shell-model-blocked-pending-contact");
    let mut blocked_pending = contact_row(CONTACT_A);
    blocked_pending.state = arkret_sdk::ContactState::PendingIncoming;
    let mut visible_pending = contact_row(CONTACT_B);
    visible_pending.state = arkret_sdk::ContactState::PendingIncoming;
    let accepted = contact_row(CONTACT_C);
    let blocked_actor = blocked_pending.peer.contact_actor_id();
    let entry = crate::account_data::new_blocklist_entry(
        crate::account_data::BlocklistUiTargetKind::Actor,
        &blocked_actor.to_string(),
        None,
        vec![AccountBlocklistSurface::Contacts],
        None,
        chrono::Utc::now(),
    )
    .unwrap();
    let rows = [blocked_pending, visible_pending, accepted];
    let remarks = BTreeMap::new();
    store.set_client_blocklist(1, vec![entry]);
    let filtered = filter_and_sort_direct_contacts(&rows, "", &store, &remarks);
    assert_eq!(filtered.len(), 2);
    assert!(
        filtered
            .iter()
            .any(|row| row.peer.contact_actor_id() == rows[1].peer.contact_actor_id())
    );
    assert!(
        filtered
            .iter()
            .any(|row| row.peer.contact_actor_id() == rows[2].peer.contact_actor_id())
    );
    store.set_client_blocklist(2, Vec::new());
    assert_eq!(
        filter_and_sort_direct_contacts(&rows, "", &store, &remarks).len(),
        3
    );
}

#[test]
fn pinned_direct_contacts_sort_ahead_of_the_rest() {
    let store = crate::state::isolated_store_for_tests("shell-model-contacts-pin");
    let rows = vec![
        contact_row(CONTACT_A),
        contact_row(CONTACT_B),
        contact_row(CONTACT_C),
    ];
    let mut remarks = BTreeMap::new();
    remarks.insert(CONTACT_C.to_owned(), pinned_remark(CONTACT_C));
    let sorted = filter_and_sort_direct_contacts(&rows, "", &store, &remarks);
    let order: Vec<String> = sorted
        .iter()
        .map(|row| crate::models::contact_peer_id(row).as_str().to_owned())
        .collect();
    assert_eq!(order[0], CONTACT_C, "pinned contact leads");
    // The remaining two keep a stable label-then-peer-id order.
    assert_eq!(&order[1..], &[CONTACT_A.to_owned(), CONTACT_B.to_owned()]);
}

#[test]
fn direct_contact_query_matches_the_peer_id() {
    let store = crate::state::isolated_store_for_tests("shell-model-contacts-query");
    let rows = vec![contact_row(CONTACT_A), contact_row(CONTACT_B)];
    let remarks = BTreeMap::new();
    let matched = filter_and_sort_direct_contacts(&rows, "bbb.example", &store, &remarks);
    assert_eq!(matched.len(), 1);
    assert_eq!(
        crate::models::contact_peer_id(&matched[0]).as_str(),
        CONTACT_B
    );
    assert!(filter_and_sort_direct_contacts(&rows, "nobody", &store, &remarks).is_empty());
}

#[test]
fn direct_contact_query_matches_the_contact_state_wire_word() {
    // The sidebar search reaches the state word as well as the peer id; a
    // regression here silently narrows what the box can find.
    let store = crate::state::isolated_store_for_tests("shell-model-contacts-state");
    let rows = vec![contact_row(CONTACT_A)];
    let remarks = BTreeMap::new();
    let wire = crate::models::contact_state_wire(rows[0].state);
    assert_eq!(
        filter_and_sort_direct_contacts(&rows, wire, &store, &remarks).len(),
        1
    );
}
