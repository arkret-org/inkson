//! Visible read-receipt send and display preferences.

use super::*;

#[test]
fn chat_visible_read_receipt_send_respects_preferences() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-rr-pref-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_default_send(false);
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_realm_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(true),
    );
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:A4EpRDvQloG8EYOGEPnGhe1SLpxBiLQbOvlptwBvvPkA",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_strand_override(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        Some(false),
    );
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "disabled".to_owned(),
            visibility: Some("private".to_owned()),
        }),
    );
    assert!(!chat_visible_read_receipt_should_send(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));
}

#[test]
fn chat_visible_read_receipt_display_respects_local_preferences() {
    let temp = std::env::temp_dir().join(format!("inkson-chat-rr-display-{}", uuid_v7()));
    let mut store = LocalStateStore::with_path(temp);
    assert!(chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_default_display(false);
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_realm_display_override(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(true),
    );
    assert!(chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:A4EpRDvQloG8EYOGEPnGhe1SLpxBiLQbOvlptwBvvPkA",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_strand_display_override(
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        Some(false),
    );
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));

    store.set_read_receipt_policy_snapshot(
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
        Some(crate::state::ReadReceiptPolicySnapshot {
            disclosure: "required".to_owned(),
            visibility: Some("public".to_owned()),
        }),
    );
    assert!(!chat_visible_read_receipt_should_display(
        &store,
        "ak:strand:AC7ywGI8OKsg1D-rP9Zz8B2KmWgXxgfz6Sufdo7s5f1Q",
        "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
    ));
}
