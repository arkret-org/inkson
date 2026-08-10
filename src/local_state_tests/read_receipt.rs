//! Read-receipt defaults, override resolution, and server-policy locking.

use super::*;

#[test]
fn read_receipt_default_is_send_until_user_opts_out() {
    let path = temp_state_path("read-receipt-default");
    let mut store = LocalStateStore::with_path(path.clone());
    assert!(store.read_receipt_default_send());
    assert!(store.read_receipt_should_send(
        None,
        Some("ak:realm:ALrtDIsJ5j6bbQvqG1lN29Sl9zr0m0PNNkgrog0pQidE")
    ));

    store.set_read_receipt_default_send(false);
    let reader = LocalStateStore::with_path(path);
    assert!(!reader.read_receipt_default_send());
    assert!(!reader.read_receipt_should_send(
        None,
        Some("ak:realm:ALrtDIsJ5j6bbQvqG1lN29Sl9zr0m0PNNkgrog0pQidE")
    ));
}

#[test]
fn read_receipt_resolution_strand_overrides_realm_overrides_default() {
    let path = temp_state_path("read-receipt-resolve");
    let mut store = LocalStateStore::with_path(path.clone());
    // default = true (send)
    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(false),
    );
    store.set_read_receipt_strand_override(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        Some(true),
    );

    let reader = LocalStateStore::with_path(path);
    // Strand override wins.
    assert!(reader.read_receipt_should_send(
        Some("ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q"),
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    // Space override wins over default when no strand override.
    assert!(!reader.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    // Default applies when nothing matches.
    assert!(reader.read_receipt_should_send(
        None,
        Some("ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo")
    ));
}

#[test]
fn read_receipt_display_resolution_is_local_rendering_only() {
    let path = temp_state_path("read-receipt-display-resolve");
    let mut store = LocalStateStore::with_path(path.clone());
    assert!(store.read_receipt_default_display());
    assert!(store.read_receipt_should_display(
        None,
        Some("ak:realm:ALrtDIsJ5j6bbQvqG1lN29Sl9zr0m0PNNkgrog0pQidE")
    ));

    store.set_read_receipt_default_display(false);
    store.set_read_receipt_realm_display_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(true),
    );
    store.set_read_receipt_strand_display_override(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        Some(false),
    );

    let reader = LocalStateStore::with_path(path);
    assert!(!reader.read_receipt_default_display());
    assert!(!reader.read_receipt_should_display(
        Some("ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q"),
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    assert!(reader.read_receipt_should_display(
        Some("ak:strand:A4EpRDvQloG8EYOGEPnGhe1SLpxBiLQbOvlptwBvvPkA"),
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    assert!(!reader.read_receipt_should_display(
        None,
        Some("ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo")
    ));
}

#[test]
fn read_receipt_display_is_not_locked_by_server_disclosure_policy() {
    let path = temp_state_path("read-receipt-display-policy");
    let mut store = LocalStateStore::with_path(path);
    store.set_read_receipt_default_display(false);
    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("members".to_owned()),
        }),
    );
    assert!(store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    assert!(!store.read_receipt_should_display(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));

    store.set_read_receipt_default_display(true);
    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "disabled".to_owned(),
            visibility: Some("private".to_owned()),
        }),
    );
    assert!(!store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    assert!(store.read_receipt_should_display(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
}

#[test]
fn read_receipt_clearing_override_falls_back_to_default() {
    let path = temp_state_path("read-receipt-clear");
    let mut store = LocalStateStore::with_path(path);
    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(false),
    );
    assert!(!store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));

    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        None,
    );
    assert!(store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    assert!(
        store
            .read_receipt_realm_override("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
            .is_none()
    );
}

#[test]
fn server_policy_required_locks_user_choice_to_send() {
    let path = temp_state_path("read-receipt-policy-required");
    let mut store = LocalStateStore::with_path(path);
    // User opted out of the Space.
    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(false),
    );
    // But server publishes disclosure=required → must override to true.
    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    let snap = store
        .read_receipt_policy_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
        .unwrap();
    assert!(snap.locks_user_choice());
    assert!(!snap.lock_reason().is_empty());
}

#[test]
fn server_policy_disabled_locks_user_choice_to_skip() {
    let path = temp_state_path("read-receipt-policy-disabled");
    let mut store = LocalStateStore::with_path(path);
    // User opts in.
    store.set_read_receipt_default_send(true);
    // Server publishes disclosure=disabled → must override to false.
    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "disabled".to_owned(),
            visibility: Some("private".to_owned()),
        }),
    );
    assert!(!store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
}

#[test]
fn server_policy_optional_does_not_lock() {
    let path = temp_state_path("read-receipt-policy-optional");
    let mut store = LocalStateStore::with_path(path);
    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(false),
    );
    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(ReadReceiptPolicySnapshot {
            disclosure: "optional".to_owned(),
            visibility: None,
        }),
    );
    // optional → user override wins.
    assert!(!store.read_receipt_should_send(
        None,
        Some("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
    ));
    let snap = store
        .read_receipt_policy_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
        .unwrap();
    assert!(!snap.locks_user_choice());
    assert_eq!(snap.lock_reason(), "");
}

#[test]
fn read_receipt_policy_snapshot_persists_across_store_instances() {
    let path = temp_state_path("read-receipt-policy-persists");
    {
        let mut store = LocalStateStore::with_path(path.clone());
        store.set_read_receipt_policy_snapshot(
            "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            Some(ReadReceiptPolicySnapshot {
                disclosure: "required".to_owned(),
                visibility: Some("track_scoped".to_owned()),
            }),
        );
    }
    let reader = LocalStateStore::with_path(path);
    let snap = reader
        .read_receipt_policy_for_realm("ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE")
        .unwrap();
    assert_eq!(snap.disclosure, "required");
    assert_eq!(snap.visibility.as_deref(), Some("track_scoped"));
}
