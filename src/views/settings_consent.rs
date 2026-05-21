//! G3.Y3 — Consent grants settings page (`/settings/consent`).
//!
//! Surface for reviewing active `cx.consent.grant` rows and revoking /
//! creating new ones. The reducer + projection backing these rows
//! lands in G3.S2 (soland); G3.S4 / G3.S6 own the cross-device fanout
//! tests. This view wires testids + a basic form so the cotest
//! `cotest/e2e/scenarios/identity/consent-grant` scenario has the
//! testids it expects (`consent-settings-panel`, `consent-grant-row`,
//! `consent-grant-revoke-button`, `consent-new-grant-*`).
//!
//! Spec anchors:
//! - `identity/consent-model.md` §2 — Consent cell or-set lattice.
//! - `identity/consent-model.md` §3 — `cx.consent.grant` /
//!   `cx.consent.revoke` Move shapes.
//! - `identity/consent-model.md` §4 — gate semantics.

use dioxus::prelude::*;

use crate::{
    components::{EmptyState, EmptyStateKind, HelpTip},
    local_state::LocalStateStore,
};

/// Local representation of a stored consent grant. Until the soland
/// projection lands (G3.S2), the panel reads from a placeholder
/// account_data key on [`LocalStateStore`] so the form is at least
/// round-trip testable.
///
/// TODO(G3.Y3-followup): replace this with the canonical projection
/// row from soland's `GET /api/v1/consent/grants` once that endpoint
/// exists; spec `identity/consent-model.md` §3.
#[derive(Clone, Debug, PartialEq)]
struct ConsentGrantRow {
    grant_id: String,
    scope: String,
    grantee_did: String,
    expires_at: String,
}

/// Account-data key used to stash the local-only grant list while the
/// soland projection is still being designed. The key is namespaced so
/// the eventual sync layer can migrate it.
const CONSENT_GRANTS_LOCAL_KEY: &str = "cx.consent.grants.local.v1";

/// Pull the placeholder grant list from the local state store. The
/// stored format is `grant_id\tscope\tgrantee\texpires_at` newline-
/// delimited so we don't need a JSON parser dep just for the stub.
fn load_local_grants(state_store: &LocalStateStore, account_did: &str) -> Vec<ConsentGrantRow> {
    let raw = match state_store.load_private_data(account_did, CONSENT_GRANTS_LOCAL_KEY) {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Vec::new(),
    };
    raw.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 4 {
                return None;
            }
            Some(ConsentGrantRow {
                grant_id: parts[0].to_owned(),
                scope: parts[1].to_owned(),
                grantee_did: parts[2].to_owned(),
                expires_at: parts[3].to_owned(),
            })
        })
        .collect()
}

fn save_local_grants(
    state_store: &mut LocalStateStore,
    account_did: &str,
    grants: &[ConsentGrantRow],
) {
    let serialized = grants
        .iter()
        .map(|g| {
            format!(
                "{}\t{}\t{}\t{}",
                g.grant_id, g.scope, g.grantee_did, g.expires_at
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    state_store.save_private_data(account_did, CONSENT_GRANTS_LOCAL_KEY, serialized);
}

#[component]
pub fn ConsentSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let _ = base_url;
    let _ = token;

    let initial_grants = load_local_grants(&state_store.read(), &account_did());
    let mut grants = use_signal(|| initial_grants);
    let mut show_form = use_signal(|| false);
    let mut new_scope = use_signal(|| "invite".to_owned());
    let mut new_grantee = use_signal(String::new);
    let mut new_ttl = use_signal(|| "30d".to_owned());
    let mut status = use_signal(String::new);

    rsx! {
        div { class: "event", "data-testid": "consent-settings-panel",
            div { class: "event-head",
                span { "Consent grants" }
                HelpTip { text: "Per-peer consent grants control which actors may contact you. Spec identity/consent-model.md §2 — or-set lattice with scope and time-window." }
            }
            div { class: "muted",
                "Each row is one active grant in your consent cell. Revoking a grant flips the or-set member to a tombstone; new grants append a fresh member."
            }

            if grants.read().is_empty() {
                EmptyState {
                    title: "No active consent grants".to_owned(),
                    kind: EmptyStateKind::Empty,
                    message: Some(
                        "Grant a peer permission to contact you, or wait for a pending request."
                            .to_owned(),
                    ),
                    test_id: Some("consent-grant-empty".to_owned()),
                }
            } else {
                ul { class: "settings-list",
                    for grant in grants.read().iter().cloned() {
                        li {
                            class: "event",
                            "data-testid": "consent-grant-row",
                            "data-grant-id": "{grant.grant_id}",
                            "data-scope": "{grant.scope}",
                            "data-grantee-did": "{grant.grantee_did}",
                            "data-expires-at": "{grant.expires_at}",
                            div { class: "event-head",
                                span { "{grant.scope}" }
                                span { class: "mono", "{grant.grantee_did}" }
                            }
                            div { class: "muted", "expires {grant.expires_at}" }
                            div { class: "actions",
                                button {
                                    class: "secondary",
                                    "data-testid": "consent-grant-revoke-button",
                                    "data-grant-id": "{grant.grant_id}",
                                    onclick: {
                                        let grant_id = grant.grant_id.clone();
                                        let account_did = account_did();
                                        move |_| {
                                            // TODO(G3.Y3-followup): wire to soland
                                            // `DELETE /api/v1/consent/grants/{id}` once the
                                            // reducer + projection land (G3.S2). Until then
                                            // the revoke is local-only so the cotest UI
                                            // assertion can still flip the row off.
                                            let updated: Vec<ConsentGrantRow> = grants
                                                .read()
                                                .iter()
                                                .filter(|g| g.grant_id != grant_id)
                                                .cloned()
                                                .collect();
                                            save_local_grants(
                                                &mut state_store.write(),
                                                &account_did,
                                                &updated,
                                            );
                                            grants.set(updated);
                                            status.set(format!("Revoked grant {grant_id}"));
                                        }
                                    },
                                    "Revoke"
                                }
                            }
                        }
                    }
                }
            }

            div { class: "actions",
                button {
                    class: "primary",
                    "data-testid": "consent-new-grant-button",
                    onclick: move |_| show_form.set(!show_form()),
                    if show_form() { "Cancel" } else { "New grant" }
                }
            }

            if show_form() {
                div { class: "event",
                    label { "Scope" }
                    input {
                        "data-testid": "consent-new-grant-scope-input",
                        value: "{new_scope}",
                        oninput: move |evt| new_scope.set(evt.value()),
                    }
                    label { "Grantee DID" }
                    input {
                        "data-testid": "consent-new-grant-grantee-input",
                        value: "{new_grantee}",
                        placeholder: "did:web:peer.example",
                        oninput: move |evt| new_grantee.set(evt.value()),
                    }
                    label { "TTL (e.g. 30d, 24h)" }
                    input {
                        "data-testid": "consent-new-grant-ttl-input",
                        value: "{new_ttl}",
                        oninput: move |evt| new_ttl.set(evt.value()),
                    }
                    div { class: "actions",
                        button {
                            class: "primary",
                            "data-testid": "consent-new-grant-submit-button",
                            disabled: new_grantee.read().trim().is_empty(),
                            onclick: {
                                let account_did = account_did();
                                move |_| {
                                    // TODO(G3.Y3-followup): wire to soland
                                    // `POST /api/v1/consent/grants` (request body
                                    // `{ scope, grantee, ttl }`) once the reducer +
                                    // schema land (G3.S2 / spec
                                    // identity/consent-model.md §3). For now we
                                    // optimistically append to local state so the
                                    // UI exercises the testids end-to-end.
                                    let grant = ConsentGrantRow {
                                        grant_id: format!(
                                            "local-{}",
                                            std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .map(|d| d.as_millis())
                                                .unwrap_or_default()
                                        ),
                                        scope: new_scope().trim().to_owned(),
                                        grantee_did: new_grantee().trim().to_owned(),
                                        expires_at: new_ttl().trim().to_owned(),
                                    };
                                    let mut next: Vec<ConsentGrantRow> =
                                        grants.read().iter().cloned().collect();
                                    next.push(grant.clone());
                                    save_local_grants(&mut state_store.write(), &account_did, &next);
                                    grants.set(next);
                                    status.set(format!(
                                        "Granted {} to {}",
                                        grant.scope, grant.grantee_did
                                    ));
                                    show_form.set(false);
                                    new_grantee.set(String::new());
                                }
                            },
                            "Submit grant"
                        }
                    }
                    if !status.read().is_empty() {
                        div {
                            class: "muted",
                            "data-testid": "consent-new-grant-status",
                            "{status}"
                        }
                    }
                }
            } else if !status.read().is_empty() {
                div {
                    class: "muted",
                    "data-testid": "consent-new-grant-status",
                    "{status}"
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_grants_round_trip_through_state_store() {
        let mut store = LocalStateStore::default();
        let did = "did:web:alice.example";
        let grants = vec![
            ConsentGrantRow {
                grant_id: "g1".to_owned(),
                scope: "invite".to_owned(),
                grantee_did: "did:web:bob.example".to_owned(),
                expires_at: "30d".to_owned(),
            },
            ConsentGrantRow {
                grant_id: "g2".to_owned(),
                scope: "message".to_owned(),
                grantee_did: "did:web:carol.example".to_owned(),
                expires_at: "1h".to_owned(),
            },
        ];
        save_local_grants(&mut store, did, &grants);
        let loaded = load_local_grants(&store, did);
        assert_eq!(loaded, grants);
    }

    #[test]
    fn empty_load_when_key_missing() {
        let store = LocalStateStore::default();
        let loaded = load_local_grants(&store, "did:web:nobody.example");
        assert!(loaded.is_empty());
    }
}
