//! TSP connections settings page (`/settings/connections`).
//!
//! Trust Spanning Protocol (TSP) is an interop *extension profile* (spec
//! `identity/tsp-integration.md` status header): v1 core defaults to HTTPS
//! JWE / MLS DM. This surface lets a user establish and review pairwise TSP
//! relationships with external VID endpoints (`did:web` / `did:webs` orgs
//! that publish a `ak.service.tsp` endpoint).
//!
//! Surfaces (referenced by `cotest/e2e/scenarios/identity/tsp-bootstrap.md`):
//! - `connections-panel` wrapper
//! - `establish-tsp-button`, `tsp-remote-vid-input`
//! - `tsp-relationship-list`, `tsp-relationship-row[data-remote-vid]`
//! - `tsp-trust-level-badge` (verified / degraded_no_witness)
//! - `connections-status`
//!
//! Relationships are stored as actor-private client state (the TSP transport
//! itself is a profile extension and not a v1-core durable Realm event), so
//! this view persists the relationship table through `LocalStateStore`
//! private data and does not assume the server materializes it.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::components::{EmptyState, EmptyStateKind};
use crate::local_state::LocalStateStore;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;

const TSP_RELATIONSHIPS_KEY: &str = "tsp_relationships";

/// One established TSP relationship as seen by the local client.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct TspRelationship {
    pub remote_vid: String,
    pub relationship_id: String,
    pub support_system: String,
    /// `verified` | `degraded_no_witness` — the VID trust assessment result
    /// (spec §8: record support system + trust assessment result).
    pub trust_level: String,
    pub established_at: String,
}

fn load_relationships(store: &LocalStateStore, account_key: &str) -> Vec<TspRelationship> {
    store
        .load_private_data(account_key, TSP_RELATIONSHIPS_KEY)
        .and_then(|raw| serde_json::from_str::<Vec<TspRelationship>>(&raw).ok())
        .unwrap_or_default()
}

fn save_relationships(
    store: &mut LocalStateStore,
    account_key: &str,
    relationships: &[TspRelationship],
) {
    if let Ok(raw) = serde_json::to_string(relationships) {
        store.save_private_data(account_key, TSP_RELATIONSHIPS_KEY, &raw);
    }
}

fn trust_level_label(trust_level: &str) -> &'static str {
    match trust_level {
        "degraded_no_witness" => "\u{26a0} Degraded (no witness)",
        "verified" => "Verified",
        _ => "Unknown",
    }
}

#[component]
pub fn ConnectionsSettingsCard(account_did: Signal<String>, token: Signal<String>) -> Element {
    // A4 — state_store from session context instead of a prop.
    let mut state_store = crate::app::SessionContext::get().state_store;
    let _ = token;

    let account_key = account_did();
    let initial = load_relationships(&state_store.read(), &account_key);
    let mut relationships = use_signal(|| initial);
    let mut remote_vid = use_signal(String::new);
    let mut status = use_signal(String::new);

    let establish = move |_| {
        let vid = remote_vid().trim().to_owned();
        if vid.is_empty() {
            status.set("Enter the remote VID (did:web / did:webs).".to_owned());
            return;
        }
        if !(vid.starts_with("did:") || vid.starts_with("tsp:")) {
            status.set("Remote VID must be a did:* or tsp:* identifier.".to_owned());
            return;
        }
        if relationships().iter().any(|item| item.remote_vid == vid) {
            status.set("A TSP relationship with that VID already exists.".to_owned());
            return;
        }
        // The real TSP relationship bootstrap against the remote
        // `ak.service.tsp` endpoint is not implemented yet; this preview
        // surface only records the intent locally. Until the live handshake
        // exists the row must not claim `verified` — it stays
        // `degraded_no_witness` so the badge reflects that no witness /
        // handshake evidence backs it (spec §8).
        let account_key = account_did();
        let record = TspRelationship {
            remote_vid: vid.clone(),
            relationship_id: format!("tsp:rel:{}", short_id(&vid)),
            support_system: "did:webvh / did:web".to_owned(),
            trust_level: "degraded_no_witness".to_owned(),
            established_at: String::new(),
        };
        let mut next = relationships();
        next.push(record);
        save_relationships(&mut state_store.write(), &account_key, &next);
        relationships.set(next);
        remote_vid.set(String::new());
        status.set(format!(
            "TSP relationship with {vid} recorded locally (preview; no remote bootstrap performed)."
        ));
    };

    rsx! {
        div {
            class: "settings-content-stack",
            "data-testid": "connections-panel",
            div { class: "event",
                div { class: "event-head",
                    span { "TSP connections" }
                    span { class: "badge amber", "preview — not yet connected" }
                }
                p { class: "muted",
                    "Establish pairwise Trust Spanning Protocol relationships with external "
                    "VID endpoints. v1 core uses HTTPS JWE / MLS DM by default; TSP is opt-in."
                }
                p { class: "muted", "data-testid": "connections-preview-warning",
                    "This surface is a local preview: entries are recorded on this device "
                    "only and no ak.service.tsp bootstrap is performed against the remote "
                    "endpoint yet."
                }
                div { class: "field",
                    Label { html_for: "tsp-remote-vid-input", "Remote VID" }
                    Input {
                        value: remote_vid(),
                        "data-testid": "tsp-remote-vid-input",
                        placeholder: "did:web:bob-extern.example",
                        oninput: move |event: FormEvent| remote_vid.set(event.value()),
                    }
                }
                div { class: "actions",
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "establish-tsp-button",
                        onclick: establish,
                        "Establish TSP channel"
                    }
                }
                if !status().is_empty() {
                    p { class: "status", "data-testid": "connections-status", "{status}" }
                }
            }

            if relationships().is_empty() {
                EmptyState {
                    kind: EmptyStateKind::Empty,
                    title: "No TSP relationships".to_owned(),
                    message: Some(
                        "Establish a TSP channel with an external VID endpoint to see it here."
                            .to_owned(),
                    ),
                    test_id: Some("tsp-relationships-empty".to_owned()),
                }
            } else {
                div {
                    class: "tsp-relationship-list",
                    "data-testid": "tsp-relationship-list",
                    for relationship in relationships() {
                        div {
                            key: "{relationship.relationship_id}",
                            class: "event tsp-relationship-row",
                            "data-testid": "tsp-relationship-row",
                            "data-remote-vid": "{relationship.remote_vid}",
                            "data-trust-level": "{relationship.trust_level}",
                            div { class: "event-head",
                                span { "{relationship.remote_vid}" }
                                span {
                                    class: "badge",
                                    "data-testid": "tsp-trust-level-badge",
                                    "data-trust-level": "{relationship.trust_level}",
                                    "{trust_level_label(&relationship.trust_level)}"
                                }
                            }
                            p { class: "muted",
                                "Relationship "
                                code { "{relationship.relationship_id}" }
                                " \u{00b7} support system "
                                "{relationship.support_system}"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Short, stable suffix derived from a VID for a relationship id.
fn short_id(vid: &str) -> String {
    vid.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .rev()
        .take(8)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}
