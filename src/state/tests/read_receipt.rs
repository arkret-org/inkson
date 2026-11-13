//! User read-receipt preferences and their local default resolution.

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
}
