//! G3.Y3 — Personal blocklist settings page (`/settings/blocked-users`).
//!
//! Actor-private list of blocked DIDs. Spec
//! `governance/content-moderation.md` §4 — personal blocklist is a
//! client-side filter; spec `discovery/client-preferences.md` §2
//! defines the `ck.account.blocklist` account_data shape.
//!
//! Surfaces:
//! - `blocked-users-panel` wrapper
//! - `blocked-users-list` list wrapper
//! - `blocked-user-row[data-actor-did, data-blocked-at]` per entry
//! - `block-target-input`, `block-user-button`, `unblock-button`
//! - `write-status`
//!
//! The `block-actor-button` testid exposed elsewhere (directory rows,
//! space member rows) is owned by the respective view modules — this
//! file only owns the settings surface.

use dioxus::prelude::*;

use crate::components::{EmptyState, EmptyStateKind};
use crate::local_state::LocalStateStore;
use crate::views::helpers::short_protocol_id;

#[component]
pub fn BlocklistSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let _ = account_did;

    let initial = state_store.read().client_blocklist();
    let mut entries = use_signal(|| initial);
    let mut add_input = use_signal(String::new);
    let mut status = use_signal(String::new);

    rsx! {
        div { class: "event", "data-testid": "blocked-users-panel",
            div { class: "event-head",
                span { "Personal blocklist" }
            }
            div { class: "muted",
                "Blocked actors are hidden from your timeline and notifications on your devices."
            }

            div { class: "settings-list", "data-testid": "blocked-users-list",
                if entries.read().is_empty() {
                    EmptyState {
                        title: "Blocklist empty".to_owned(),
                        kind: EmptyStateKind::Empty,
                        message: Some("You haven't blocked any actors.".to_owned()),
                        test_id: None,
                    }
                } else {
                    for entry in entries.read().iter().cloned() {
                        {
                            let blocked_at = entry.blocked_at.clone().unwrap_or_default();
                            rsx! {
                                div {
                                    class: "event",
                                    "data-testid": "blocked-user-row",
                                    "data-actor-did": "{entry.did}",
                                    "data-blocked-at": "{blocked_at}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{entry.did}", "{entry.did}" }
                                        if !blocked_at.is_empty() {
                                            span { class: "muted", "{blocked_at}" }
                                        }
                                    }
                                    if let Some(reason) = &entry.reason {
                                        div { class: "muted", "{reason}" }
                                    }
                                    div { class: "actions",
                                        button {
                                            class: "secondary",
                                            "data-testid": "unblock-button",
                                            "data-actor-did": "{entry.did}",
                                            onclick: {
                                                let actor_did = entry.did.clone();
                                                let base = base_url;
                                                move |_| {
                                                    let changed = state_store.write().unblock_user(&actor_did);
                                                    let next = state_store.read().client_blocklist();
                                                    entries.set(next.clone());
                                                    if changed {
                                                        status.set(format!(
                                                            "Unblocked {}",
                                                            short_protocol_id(&actor_did)
                                                        ));
                                                        crate::views::settings::push_blocklist_account_data(
                                                            base(),
                                                            token(),
                                                            next,
                                                        );
                                                    }
                                                }
                                            },
                                            "Unblock"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div { class: "event",
                label { "Block another actor (DID)" }
                input {
                    "data-testid": "block-target-input",
                    value: "{add_input}",
                    placeholder: "did:web:peer.example",
                    oninput: move |evt| add_input.set(evt.value()),
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "block-user-button",
                        disabled: add_input.read().trim().is_empty(),
                        onclick: {
                            let base = base_url;
                            move |_| {
                                let target = add_input().trim().to_owned();
                                if target.is_empty() {
                                    return;
                                }
                                let changed = state_store.write().block_user(&target, None);
                                let next = state_store.read().client_blocklist();
                                entries.set(next.clone());
                                if changed {
                                    status.set(format!(
                                        "blocklist updated; added {}",
                                        short_protocol_id(&target)
                                    ));
                                    add_input.set(String::new());
                                    crate::views::settings::push_blocklist_account_data(
                                        base(),
                                        token(),
                                        next,
                                    );
                                } else {
                                    status.set(format!(
                                        "{} is already blocked",
                                        short_protocol_id(&target)
                                    ));
                                }
                            }
                        },
                        "Block actor"
                    }
                }
                if !status.read().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "write-status",
                        "{status}"
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_uses_client_blocklist_state_store_methods() {
        let mut store = LocalStateStore::default();
        assert!(store.client_blocklist().is_empty());

        assert!(store.block_user("did:web:bob.example", None));
        assert!(!store.block_user("did:web:bob.example", None));

        let entries = store.client_blocklist();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].did, "did:web:bob.example");
        assert!(entries[0].blocked_at.is_some());

        assert!(store.unblock_user("did:web:bob.example"));
        assert!(!store.unblock_user("did:web:bob.example"));
        assert!(store.client_blocklist().is_empty());
    }
}
