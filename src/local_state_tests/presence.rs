//! Presence visibility preference persistence.

use super::*;

#[test]
fn presence_visibility_defaults_to_public_and_persists() {
    let path = temp_state_path("presence-visibility");
    let mut store = LocalStateStore::with_path(path.clone());
    assert_eq!(store.presence_visibility(), PresenceVisibility::Public);
    assert!(store.presence_should_send());

    store.set_presence_visibility(PresenceVisibility::Nobody);
    assert!(!store.presence_should_send());

    let reader = LocalStateStore::with_path(path);
    assert_eq!(reader.presence_visibility(), PresenceVisibility::Nobody);
    assert!(!reader.presence_should_send());
}
