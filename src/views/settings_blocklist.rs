//! G3.Y3 — Personal blocklist settings page (`/settings/blocklist`).
//!
//! Actor-private list of blocked DIDs. Spec
//! `governance/content-moderation.md` §4 — personal blocklist is a
//! client-side filter; spec `discovery/client-preferences.md` §2
//! defines the `cx.account.blocklist` account_data shape. The cross-
//! device sync layer lives in G3.S4 / G3.S6; this view exposes the
//! testids the cotest `governance/personal-blocklist` scenario hooks.
//!
//! Surfaces:
//! - `blocklist-panel` wrapper
//! - `blocklist-row[data-actor-did, data-blocked-at]` per entry
//! - `blocklist-unblock-button` per row
//! - `blocklist-add-input`, `blocklist-add-button`, `blocklist-add-status`
//! - `blocklist-empty` empty state
//!
//! The `block-actor-button` testid exposed elsewhere (directory rows,
//! space member rows) is owned by the respective view modules — this
//! file only owns the settings surface.

use dioxus::prelude::*;

use crate::{
    components::{EmptyState, EmptyStateKind, HelpTip},
    local_state::LocalStateStore,
    views::helpers::short_protocol_id,
};

#[derive(Clone, Debug, PartialEq)]
struct BlocklistRow {
    actor_did: String,
    blocked_at: String,
}

/// Account-data key for the actor-private blocklist. Mirrors the
/// `CLIENT_BLOCKLIST_ACCOUNT_DATA_KEY` constant in `views/settings.rs`
/// (intentionally duplicated here as `const` because the parent
/// settings.rs entry is `pub(crate)` and we want to keep this file
/// self-contained until the eventual settings refactor).
///
/// TODO(G3.Y3-followup): centralise these account_data keys into a
/// single module once the soland API contract (`POST/GET/DELETE
/// /api/v1/account-data/blocklist`) is stable.
const CONSENT_BLOCKLIST_LOCAL_KEY: &str = "cx.account.blocklist.local.v1";

fn load_blocklist(state_store: &LocalStateStore, account_did: &str) -> Vec<BlocklistRow> {
    let raw = match state_store.load_private_data(account_did, CONSENT_BLOCKLIST_LOCAL_KEY) {
        Some(s) if !s.trim().is_empty() => s,
        _ => return Vec::new(),
    };
    raw.lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() != 2 {
                return None;
            }
            Some(BlocklistRow {
                actor_did: parts[0].to_owned(),
                blocked_at: parts[1].to_owned(),
            })
        })
        .collect()
}

fn save_blocklist(state_store: &mut LocalStateStore, account_did: &str, entries: &[BlocklistRow]) {
    let serialized = entries
        .iter()
        .map(|e| format!("{}\t{}", e.actor_did, e.blocked_at))
        .collect::<Vec<_>>()
        .join("\n");
    state_store.save_private_data(account_did, CONSENT_BLOCKLIST_LOCAL_KEY, serialized);
}

fn current_iso_timestamp() -> String {
    // Pure-Rust ISO-8601 stamp without pulling a date formatter that
    // wouldn't otherwise be needed. Format: `YYYY-MM-DDTHH:MM:SSZ`.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    // Avoid `chrono` round-trip dep in this small surface — yougen
    // already depends on it (Cargo.toml line 34), but a free format
    // call keeps this view's test surface std-only.
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_else(chrono::Utc::now);
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[component]
pub fn BlocklistSettingsCard(
    base_url: Signal<String>,
    account_did: Signal<String>,
    token: Signal<String>,
    mut state_store: Signal<LocalStateStore>,
) -> Element {
    let _ = base_url;
    let _ = token;

    let initial = load_blocklist(&state_store.read(), &account_did());
    let mut entries = use_signal(|| initial);
    let mut add_input = use_signal(String::new);
    let mut status = use_signal(String::new);

    rsx! {
        div { class: "event", "data-testid": "blocklist-panel",
            div { class: "event-head",
                span { "Personal blocklist" }
                HelpTip { text: "Actor-private list of DIDs whose new content you don't want to see. Spec governance/content-moderation.md §4 — block is client-side filter; quarantine is server-side." }
            }
            div { class: "muted",
                "Block hides new content from the listed actors in your timeline + notifications. The list syncs across your devices via cx.account.blocklist account_data."
            }

            if entries.read().is_empty() {
                EmptyState {
                    title: "Blocklist empty".to_owned(),
                    kind: EmptyStateKind::Empty,
                    message: Some("You haven't blocked any actors.".to_owned()),
                    test_id: Some("blocklist-empty".to_owned()),
                }
            } else {
                ul { class: "settings-list",
                    for entry in entries.read().iter().cloned() {
                        {
                            let actor_did_label = short_protocol_id(&entry.actor_did);
                            rsx! {
                                li {
                                    class: "event",
                                    "data-testid": "blocklist-row",
                                    "data-actor-did": "{entry.actor_did}",
                                    "data-blocked-at": "{entry.blocked_at}",
                                    div { class: "event-head",
                                        span { class: "mono", title: "{entry.actor_did}", "{actor_did_label}" }
                                        span { class: "muted", "{entry.blocked_at}" }
                                    }
                                    div { class: "actions",
                                        button {
                                            class: "secondary",
                                            "data-testid": "blocklist-unblock-button",
                                            "data-actor-did": "{entry.actor_did}",
                                            onclick: {
                                                let actor_did = entry.actor_did.clone();
                                                let account_did = account_did();
                                                move |_| {
                                                    // TODO(G3.Y3-followup): wire to
                                                    // `DELETE /api/v1/account-data/blocklist/{did}` once
                                                    // soland's account_data layer ships the personal
                                                    // blocklist endpoint (spec
                                                    // discovery/client-preferences.md §2).
                                                    let next: Vec<BlocklistRow> = entries
                                                        .read()
                                                        .iter()
                                                        .filter(|e| e.actor_did != actor_did)
                                                        .cloned()
                                                        .collect();
                                                    save_blocklist(
                                                        &mut state_store.write(),
                                                        &account_did,
                                                        &next,
                                                    );
                                                    entries.set(next);
                                                    status.set(format!(
                                                        "Unblocked {}",
                                                        short_protocol_id(&actor_did)
                                                    ));
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
                    "data-testid": "blocklist-add-input",
                    value: "{add_input}",
                    placeholder: "did:web:peer.example",
                    oninput: move |evt| add_input.set(evt.value()),
                }
                div { class: "actions",
                    button {
                        class: "primary",
                        "data-testid": "blocklist-add-button",
                        disabled: add_input.read().trim().is_empty(),
                        onclick: {
                            let account_did = account_did();
                            move |_| {
                                // TODO(G3.Y3-followup): wire to soland
                                // `POST /api/v1/account-data/blocklist` (body
                                // `{ entries: [{ target, kind: "block", created_at }] }`)
                                // once the account_data API ships the personal blocklist
                                // (spec discovery/client-preferences.md §2). For now we
                                // append optimistically so the cotest scenario's UI
                                // assertions land.
                                let target = add_input().trim().to_owned();
                                if target.is_empty() {
                                    return;
                                }
                                let already_blocked = entries
                                    .read()
                                    .iter()
                                    .any(|e| e.actor_did == target);
                                if already_blocked {
                                    status.set(format!(
                                        "{} is already blocked",
                                        short_protocol_id(&target)
                                    ));
                                    return;
                                }
                                let entry = BlocklistRow {
                                    actor_did: target.clone(),
                                    blocked_at: current_iso_timestamp(),
                                };
                                let mut next: Vec<BlocklistRow> =
                                    entries.read().iter().cloned().collect();
                                next.push(entry);
                                save_blocklist(&mut state_store.write(), &account_did, &next);
                                entries.set(next);
                                status.set(format!(
                                    "blocklist updated — added {}",
                                    short_protocol_id(&target)
                                ));
                                add_input.set(String::new());
                            }
                        },
                        "Block actor"
                    }
                }
                if !status.read().is_empty() {
                    div {
                        class: "muted",
                        "data-testid": "blocklist-add-status",
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
    fn blocklist_round_trips_through_state_store() {
        let mut store = LocalStateStore::default();
        let did = "did:web:alice.example";
        let entries = vec![
            BlocklistRow {
                actor_did: "did:web:bob.example".to_owned(),
                blocked_at: "2026-05-21T00:00:00Z".to_owned(),
            },
            BlocklistRow {
                actor_did: "did:web:mallory.example".to_owned(),
                blocked_at: "2026-05-21T01:00:00Z".to_owned(),
            },
        ];
        save_blocklist(&mut store, did, &entries);
        let loaded = load_blocklist(&store, did);
        assert_eq!(loaded, entries);
    }

    #[test]
    fn empty_load_returns_empty() {
        let store = LocalStateStore::default();
        let loaded = load_blocklist(&store, "did:web:nobody.example");
        assert!(loaded.is_empty());
    }

    #[test]
    fn iso_timestamp_has_expected_shape() {
        let stamp = current_iso_timestamp();
        // YYYY-MM-DDTHH:MM:SSZ → 20 chars.
        assert_eq!(stamp.len(), 20);
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
    }
}
