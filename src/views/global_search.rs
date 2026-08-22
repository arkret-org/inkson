//! A6.1 — global cross-Realm message search panel.
//!
//! Pressing
//! `Cmd+F` (or `Ctrl+F` off-mac), the `topbar-search-button`, or
//! navigating directly to `/search` opens this panel. The remote Arkret HTTP
//! catalog still has no spec-defined global plaintext search endpoint; this
//! panel searches only the local client index material the device can already
//! render from decrypted message projections.
//!
//! UI states surfaced:
//! - empty (no query typed yet) — `global-search-results-empty`
//! - loading — `global-search-results-loading`
//! - error — `global-search-results-error`
//! - no results — `global-search-results-no-results`
//! - hit list — `global-search-results` with per-row testids
//!
//! Each result row carries:
//! - `global-search-result-item` on the wrapper
//! - `global-search-result-realm` for the source Realm id
//! - `global-search-result-snippet` for the body excerpt

use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::i18n::tr;
use crate::models::IndexSearchView;
use crate::routes::Route;
use crate::state::LocalStateStore;
use crate::state::projection::projection_events_from_sync_realms;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// True when a `key` event should be treated as the global search
/// trigger (`Ctrl+F` on Win/Linux, `Cmd+F` on macOS). The `meta` flag
/// reflects the macOS Command modifier; `ctrl` reflects the Control
/// modifier. The browser's native page-find UI is suppressed at the
/// app level by the calling key handler (via `event.prevent_default`)
/// so the bound chord opens the in-app panel instead.
///
/// Pure function so the `app.rs` keydown handler can call this without
/// pulling in dioxus state.
pub fn key_event_is_search_trigger(key: &str, ctrl: bool, meta: bool) -> bool {
    matches!(key, "f" | "F") && (ctrl || meta)
}

/// Type alias for the panel's result list to keep the component
/// signature compact.
type ResultRows = Vec<Value>;

/// Extract a renderable snippet body from a soland search result row.
/// Falls back to `<no body>` so the UI still renders something even
/// when the row only carries metadata.
pub fn result_snippet(result: &Value) -> String {
    if let Some(body) = result
        .get("content")
        .and_then(|c| c.get("body"))
        .and_then(Value::as_str)
    {
        return body.to_owned();
    }
    if let Some(summary) = result.get("summary").and_then(Value::as_str) {
        return summary.to_owned();
    }
    if let Some(title) = result.get("title").and_then(Value::as_str) {
        return title.to_owned();
    }
    "<no body>".to_owned()
}

pub fn result_actor_id(result: &Value) -> String {
    string_field(result, &["actor_id", "source_actor_id"]).unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchDestination {
    pub route: Route,
    pub seal: Option<String>,
    pub label: String,
}

pub fn local_decrypted_index_search(
    realms: &std::collections::BTreeMap<String, Value>,
    store: &LocalStateStore,
    authority: &arkret_sdk::PrincipalAuthorityKey,
    device_id: &arkret_sdk::DeviceId,
    query: &str,
    realm_ids: &[String],
    object_kinds: Option<&[&str]>,
    limit: usize,
) -> IndexSearchView {
    let query_trimmed = query.trim();
    if query_trimmed.is_empty()
        || limit == 0
        || object_kinds.is_some_and(|kinds| !kinds.contains(&"message"))
    {
        return IndexSearchView {
            query: query_trimmed.to_owned(),
            results: Vec::new(),
            next_cursor: None,
        };
    }

    let query_lc = query_trimmed.to_lowercase();
    let realm_filter = realm_ids
        .iter()
        .filter(|realm_id| !realm_id.trim().is_empty())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let events =
        projection_events_from_sync_realms(realms, Some(store), Some((authority, device_id)));
    let sidecar_privacy =
        crate::sidecar::SidecarPrivacyGate::from_store(store, authority.principal_id.as_str());
    let mut results = Vec::new();
    for event in events {
        if results.len() >= limit {
            break;
        }
        let Some(realm_id) = event.realm_id.as_deref() else {
            continue;
        };
        if !realm_filter.is_empty() && !realm_filter.contains(realm_id) {
            continue;
        }
        let disclosure_probe = serde_json::json!({
            "event_id": event.event_id.as_deref(),
            "strand_id": event.strand_id.as_deref(),
            "body": event.body.as_str(),
        });
        if event.strand_id.as_ref().is_some_and(|strand_id| {
            !sidecar_privacy
                .allows_strand(crate::sidecar::SidecarDisclosureSurface::Search, strand_id)
        }) || !sidecar_privacy.allows_serialized(
            crate::sidecar::SidecarDisclosureSurface::Search,
            &disclosure_probe,
        ) {
            continue;
        }
        let Some(body) = searchable_message_body(&event.body, event.redacted) else {
            continue;
        };
        if !body.to_lowercase().contains(&query_lc) {
            continue;
        }
        let event_ref = event
            .event_id
            .as_deref()
            .or(Some(event.id.as_str()))
            .unwrap_or_default();
        results.push(json!({
            "realm_id": realm_id,
            "kind": "message",
            "surface": "message",
            "event_id": event_ref,
            "message_id": event_ref,
            "actor_id": event.sender,
            "content": { "body": body },
            "index_profile": arkret_sdk::ProfileId::SEARCH_CLIENT_INDEX_V1,
            "index_source": "local_decrypted_client_index"
        }));
    }

    IndexSearchView {
        query: query_trimmed.to_owned(),
        results,
        next_cursor: None,
    }
}

fn searchable_message_body(body: &str, redacted: bool) -> Option<&str> {
    let trimmed = body.trim();
    if redacted || trimmed.is_empty() || trimmed == "[message]" {
        None
    } else {
        Some(trimmed)
    }
}

/// Resolve a search result to the most specific local target we can
/// express. Newer soland rows may carry `message_id`, `event_id`,
/// `surface`, or `task_id`; otherwise rows degrade to the Realm overview.
pub fn result_destination(result: &Value) -> Option<SearchDestination> {
    let realm_id = result.get("realm_id").and_then(Value::as_str)?;
    if let Some(task_id) = string_field(result, &["task_id"]) {
        return Some(SearchDestination {
            route: Route::KanbanTask {
                realm_id: realm_id.to_owned(),
                task_id: task_id.clone(),
            },
            seal: Some(task_id),
            label: "Open task".to_owned(),
        });
    }

    if let Some(message_id) = string_field(result, &["message_id", "event_id", "object_id"]) {
        return Some(SearchDestination {
            // Carry the message id in the `?message=` query so ChatPanel
            // scrolls to and flashes the exact hit (design/route-view-ia.md
            // §3.2), mirroring the task deep-link above.
            route: Route::Chat {
                realm_id: realm_id.to_owned(),
                message: message_id.clone(),
            },
            seal: Some(message_id),
            label: "Open message".to_owned(),
        });
    }

    let surface = result
        .get("surface")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let route = match surface {
        "message" => Route::Chat {
            realm_id: realm_id.to_owned(),
            message: String::new(),
        },
        "kanban" | "board" => Route::KanbanRealm {
            realm_id: realm_id.to_owned(),
        },
        "chat" | "discussion" => Route::KanbanRealm {
            realm_id: realm_id.to_owned(),
        },
        _ => Route::Realm {
            realm_id: realm_id.to_owned(),
        },
    };
    Some(SearchDestination {
        route,
        seal: string_field(result, &["seal", "seal_id", "target_ref"]),
        label: "Open".to_owned(),
    })
}

// YOU-05-008: shared "first non-empty string under candidate keys" helper
// lives in `crate::realm_tree`.
use crate::realm_tree::string_field;

#[component]
pub fn GlobalSearchPanel(
    principal_id: Signal<String>,
    device_id: Signal<String>,
    initial_query: String,
) -> Element {
    // A4 — state_store from session context instead of a prop.
    let session = crate::app::SessionContext::get();
    let state_store = session.state_store;
    let active_account = session.active_account;
    let mut query = use_signal(|| initial_query.clone());
    let results = use_signal(ResultRows::new);
    let loading = use_signal(|| false);
    let error_msg = use_signal(String::new);
    let has_searched = use_signal(|| false);
    let navigator = use_navigator();

    // Auto-run the search when the panel is opened with a pre-filled
    // query (e.g. `/search?q=…`).
    let initial_query_for_effect = initial_query.clone();
    use_effect(move || {
        let q = initial_query_for_effect.clone();
        if !q.trim().is_empty() {
            run_search(
                q,
                state_store,
                principal_id(),
                device_id(),
                results,
                loading,
                error_msg,
                has_searched,
            );
        }
    });

    rsx! {
        div { class: "timeline", "data-testid": "global-search-panel", role: "region", "aria-label": tr("search.title"),
            div { class: "event",
                div { class: "event-head",
                    span { {tr("search.title")} }
                    span { class: "muted", "Search index" }
                }
                form {
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        let q = query();
                        if q.trim().is_empty() { return; }
                        run_search(
                            q,
                            state_store,
                            principal_id(),
                            device_id(),
                            results,
                            loading,
                            error_msg,
                            has_searched,
                        );
                    },
                    div { class: "actions", style: "gap: 8px;",
                        Input {
                            "data-testid": "global-search-input",
                            "aria-label": tr("search.title"),
                            r#type: "search",
                            placeholder: tr("search.placeholder"),
                            value: "{query}",
                            "autofocus": true,
                            oninput: move |event: FormEvent| query.set(event.value()),
                            style: "flex: 1; min-width: 280px;",
                        }
                        Button {
                            variant: ButtonVariant::Primary,
                            "data-testid": "global-search-submit",
                            r#type: "submit",
                            disabled: query().trim().is_empty() || loading(),
                            if loading() { {tr("search.results.loading")} } else { {tr("search.title")} }
                        }
                    }
                }
            }

            if !error_msg().is_empty() {
                div { class: "event", "data-testid": "global-search-results-error",
                    div { class: "event-head", span { {tr("search.results.error")} } }
                    div { class: "muted", "{error_msg}" }
                }
            } else if loading() {
                div { class: "event", "data-testid": "global-search-results-loading",
                    div { class: "muted", {tr("search.results.loading")} }
                }
            } else if !has_searched() {
                div { class: "event", "data-testid": "global-search-results-empty",
                    div { class: "muted", {tr("search.results.empty")} }
                }
            } else if results().is_empty() {
                div { class: "event", "data-testid": "global-search-results-no-results",
                    div { class: "muted", {tr("search.no_results")} }
                }
            } else {
                div { "data-testid": "global-search-results",
                    for (idx, result) in results().into_iter().enumerate() {
                        {
                            let snippet = result_snippet(&result);
                            let destination = result_destination(&result);
                            let realm_id_text = result
                                .get("realm_id")
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let sender = result_actor_id(&result);
                            let kind = result
                                .get("kind")
                                .and_then(Value::as_str)
                                .unwrap_or("message")
                                .to_owned();
                            let destination_for_button = destination.clone();
                            let realm_id_label = short_protocol_id(&realm_id_text);
                            let sender_label = actor_display_label(&state_store.read(), &sender);
                            rsx! {
                                div {
                                    key: "{idx}",
                                    class: "event",
                                    "data-testid": "global-search-result-item",
                                    div { class: "event-head",
                                        span { "{kind}" }
                                        span {
                                            class: "id mono",
                                            "data-testid": "global-search-result-realm",
                                            title: "{realm_id_text}",
                                            "{realm_id_label}"
                                        }
                                    }
                                    if !sender.is_empty() {
                                        div { class: "muted", title: "{sender}", "{sender_label}" }
                                    }
                                    div {
                                        "data-testid": "global-search-result-snippet",
                                        "{snippet}"
                                    }
                                    if let Some(target) = destination_for_button {
                                        div { class: "actions",
                                            Link {
                                                class: "secondary",
                                                "data-testid": "global-search-result-link",
                                                to: target.route,
                                                if let Some(seal) = target.seal {
                                                    span {
                                                        "data-testid": "global-search-result-seal",
                                                        "data-seal": "{seal}",
                                                        "{target.label}: {seal}"
                                                    }
                                                } else {
                                                    "{target.label}"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Convenience back-link so the panel doesn't trap users on
            // a dead-end route when no results show up.
            div { class: "actions",
                Button {
                    variant: ButtonVariant::Secondary,
                    "data-testid": "global-search-back",
                    onclick: move |_| {
                        let _ = navigator.push(Route::Dashboard);
                    },
                    "Back to dashboard"
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_search(
    q: String,
    state_store: SyncSignal<LocalStateStore>,
    authority: arkret_sdk::PrincipalAuthorityKey,
    device_id: arkret_sdk::DeviceId,
    mut results: Signal<ResultRows>,
    mut loading: Signal<bool>,
    mut error_msg: Signal<String>,
    mut has_searched: Signal<bool>,
) {
    let query_trimmed = q.trim().to_owned();
    if query_trimmed.is_empty() {
        return;
    }
    loading.set(true);
    error_msg.set(String::new());
    has_searched.set(true);
    let realm_ids: Vec<String> = Vec::new();
    let store = state_store.read();
    let state = store.load();
    let response = local_decrypted_index_search(
        &state.realm_tree_projections,
        &store,
        &authority,
        &device_id,
        &query_trimmed,
        &realm_ids,
        Some(&["message"]),
        50,
    );
    results.set(response.results);
    loading.set(false);
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn authority(actor: &str) -> arkret_sdk::PrincipalAuthorityKey {
        arkret_sdk::PrincipalAuthorityKey {
            principal_id: crate::mls_api_helpers::principal_core_id(actor).unwrap(),
            principal_server_id: arkret_sdk::DidCoreId::new("did:web:principal.example".to_owned())
                .unwrap(),
        }
    }

    fn device(value: &str) -> arkret_sdk::DeviceId {
        arkret_sdk::DeviceId::new(value.to_owned()).unwrap()
    }

    #[test]
    fn cmd_f_triggers_search() {
        assert!(key_event_is_search_trigger("f", false, true));
        assert!(key_event_is_search_trigger("F", false, true));
        assert!(key_event_is_search_trigger("f", true, false));
        assert!(key_event_is_search_trigger("F", true, false));
        // Plain `f` without a modifier MUST not trigger — otherwise we'd
        // collide with normal typing.
        assert!(!key_event_is_search_trigger("f", false, false));
        // Other keys, even with modifiers, MUST not trigger.
        assert!(!key_event_is_search_trigger("k", true, false));
        assert!(!key_event_is_search_trigger("Escape", true, true));
    }

    #[test]
    fn result_snippet_prefers_body_then_summary_then_title() {
        let with_body = json!({"content": {"body": "hello world"}});
        assert_eq!(result_snippet(&with_body), "hello world");

        let with_summary = json!({"summary": "matched query"});
        assert_eq!(result_snippet(&with_summary), "matched query");

        let with_title = json!({"title": "Demo Realm"});
        assert_eq!(result_snippet(&with_title), "Demo Realm");

        let empty = json!({});
        assert_eq!(result_snippet(&empty), "<no body>");
    }

    #[test]
    fn result_actor_id_ignores_deprecated_sender_field() {
        let row = json!({
            "sender": "did:web:removed.example",
            "actor_id": "ak:did_core:web:alice.example"
        });
        assert_eq!(result_actor_id(&row), "ak:did_core:web:alice.example");

        let removed_only = json!({"sender": "did:web:removed.example"});
        assert!(result_actor_id(&removed_only).is_empty());
    }

    #[test]
    fn result_destination_prefers_message_anchor() {
        let row = json!({
            "realm_id": "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE",
            "event_id": "ak:event:AMRFFcIrNlRzkEP8vLsl4eBWTFBOBX6eR89IhQWPENxE",
            "content": {"body": "hit"}
        });
        let destination = result_destination(&row).expect("destination");
        assert_eq!(
            destination.seal.as_deref(),
            Some("ak:event:AMRFFcIrNlRzkEP8vLsl4eBWTFBOBX6eR89IhQWPENxE")
        );
        match destination.route {
            Route::Chat { realm_id, message } => {
                assert_eq!(
                    realm_id,
                    "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE"
                );
                assert_eq!(
                    message,
                    "ak:event:AMRFFcIrNlRzkEP8vLsl4eBWTFBOBX6eR89IhQWPENxE"
                );
            }
            other => panic!("expected Chat, got {other:?}"),
        }
    }

    #[test]
    fn local_index_search_returns_decrypted_projection_message() {
        let realm_id = "ak:realm:AXvyk2cSPhfYUHVSaDoVqdjSO3t5IXRAqpG-6hQjjUAx".to_owned();
        let event_id = "ak:event:AR9_0Dn3PqKpHpxvh0C4oIGwx_MZWw6y7PjVc300c93v";
        let realms = std::collections::BTreeMap::from([(
            realm_id.clone(),
            json!({
                "summary": {"summary": "Searchable Realm"},
                "timeline": {"events": [{
                    "kind": "ak.message.create",
                    "event_id": event_id,
                    "actor_id": "ak:did_core:web:alice.example",
                    "created_at": "2026-06-19T00:00:00.000Z",
                    "content": {
                        "realm_id": realm_id,
                        "message_id": "ak:message:AW8-c0F9KfRq5YWdUYT1ilfjIDzjU3jCt-GT8KmVIeCA",
                        "body": "alpha local body"
                    }
                }]}
            }),
        )]);
        let store = LocalStateStore::default();

        let response = local_decrypted_index_search(
            &realms,
            &store,
            &authority("did:web:alice.example"),
            &device("ak:device:01904100-0000-7000-8000-000000000904"),
            "LOCAL",
            &[],
            Some(&["message"]),
            10,
        );

        assert_eq!(response.query, "LOCAL");
        assert_eq!(response.results.len(), 1);
        assert_eq!(
            response.results[0]["realm_id"].as_str(),
            realms.keys().next().map(String::as_str)
        );
        assert_eq!(response.results[0]["event_id"], event_id);
        assert_eq!(response.results[0]["content"]["body"], "alpha local body");
        assert_eq!(
            response.results[0]["index_profile"],
            arkret_sdk::ProfileId::SEARCH_CLIENT_INDEX_V1
        );
        assert_eq!(
            response.results[0]["index_source"],
            "local_decrypted_client_index"
        );
    }

    #[test]
    fn local_index_search_skips_encrypted_placeholders_without_plaintext() {
        let realm_id = "ak:realm:AUDoMj48Sty9R0GpFRg5qxBDzi-E7jGXZGe_mi0yHbpJ".to_owned();
        let realms = std::collections::BTreeMap::from([(
            realm_id.clone(),
            json!({
                "summary": {"summary": "Encrypted Realm"},
                "timeline": {"events": [{
                    "kind": "ak.message.create",
                    "event_id": "ak:event:AXJBg5RPw2O28Q_GeztGzhWf2jDciYN15ub4OYYpJ1tQ",
                    "actor_id": "ak:did_core:web:alice.example",
                    "created_at": "2026-06-19T00:00:00.000Z",
                    "content": {
                        "realm_id": realm_id,
                        "message_id": "ak:message:ATHkwzVL1fX0caFp7tHaPiGqpGaXLOTd3HKGEy34sduZ",
                        "encrypted_content": {"schema": "ak.schema.encrypted_envelope.v1"}
                    }
                }]}
            }),
        )]);
        let store = LocalStateStore::default();

        let response = local_decrypted_index_search(
            &realms,
            &store,
            &authority("did:web:alice.example"),
            &device("ak:device:01904100-0000-7000-8000-000000000914"),
            "message",
            &[],
            Some(&["message"]),
            10,
        );

        assert!(response.results.is_empty());
    }

    #[test]
    fn local_index_search_does_not_hide_a_native_sidecar_source_strand() {
        let actor_id = "did:web:alice.example";
        let realm_id = "ak:realm:Af2ZEitZ_Nla84KWtbRYoWWmZopTUKtZlKf7sz4QHbfy".to_owned();
        let source_strand_id = "ak:strand:AavbN9CgiOJRw5dWi7yMN2_jReUUAXLb-_EF2y2WL8lz".to_owned();
        let mut store = LocalStateStore::default();
        let pending = crate::sidecar::PendingSidecarSubmission {
            controller_id: actor_id.to_owned(),
            sidecar_id: arkret_sdk::SidecarId::new(
                "ak:sidecar:AW550jUB3z2wKhAvnsOXRVZTrs8UAJgTHWF5sxYI7TyI",
            )
            .unwrap(),
            source_strand_id: source_strand_id.clone(),
            exchange_id: arkret_sdk::AgentSidecarExchangeId::new("SearchPrivateStrand001").unwrap(),
            request_context: arkret_sdk::AgentSidecarExchangeRequestContext {
                source_track_ref: arkret_sdk::AgentSidecarSourceTrackRef {
                    realm_id: arkret_sdk::RealmId::new(realm_id.clone()).unwrap(),
                    strand_id: arkret_sdk::StrandId::new(source_strand_id.clone()).unwrap(),
                    track_name: "discussion".to_owned(),
                },
                source_hlc: arkret_sdk::Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
                client_order_key: arkret_sdk::NonEmptyString::new("device-1-1").unwrap(),
                addressed_agent_ids: vec![
                    crate::mls_api_helpers::principal_core_id("did:web:assistant.agents.example")
                        .unwrap(),
                ],
                completion_policy: arkret_sdk::AgentSidecarExchangeCompletionPolicy::Coordinator,
                coordinator_agent_id: None,
                source_event_id: None,
            },
            message_id: "ak:message:ASiSP84x2Juep0Q8j2fao1vAfdzqs8Y728RHY5FFyKDb".to_owned(),
            local_operation_id: "local-sidecar-search-test".to_owned(),
        };
        crate::sidecar::save_pending_sidecar_submission(&mut store, "search-test", &pending)
            .unwrap();
        let realms = std::collections::BTreeMap::from([(
            realm_id,
            json!({
                "summary": {"summary": "Search containment Realm"},
                "timeline": {"events": [{
                    "kind": "ak.message.create",
                    "event_id": "ak:event:AYE4Fy6EKDe_TOXKws3PPuPKjL-Qf6okkHXSc94b3s2b",
                    "actor_id": actor_id,
                    "created_at": "2026-07-29T00:00:00.000Z",
                    "content": {
                        "strand_id": source_strand_id,
                        "body": "sidecar-secret-search-needle"
                    }
                }]}
            }),
        )]);

        let response = local_decrypted_index_search(
            &realms,
            &store,
            &authority(actor_id),
            &device("ak:device:01904100-0000-7000-8000-000000000938"),
            "sidecar-secret-search-needle",
            &[],
            Some(&["message"]),
            10,
        );

        assert_eq!(response.results.len(), 1);
    }

    #[test]
    fn local_index_search_respects_realm_kind_and_limit_filters() {
        let first_realm_id = "ak:realm:AbPEQpgBpoYJaOBy6gq9_f6CcaazIEyAHgl0qdlWisCQ".to_owned();
        let second_realm_id = "ak:realm:ATGx6cCE_Pkzu-zRPgFdc43Tfv-MY96fKCW_fBBM3N1_".to_owned();
        let realms = std::collections::BTreeMap::from([
            (
                first_realm_id.clone(),
                json!({
                    "summary": {"summary": "First Realm"},
                    "timeline": {"events": [{
                        "kind": "ak.message.create",
                        "event_id": "ak:event:Ae8oasaCa8YvwE4_ULb5-ictCSzTCZoyn5KqQ81wpvDG",
                        "actor_id": "ak:did_core:web:alice.example",
                        "created_at": "2026-06-19T00:00:00.000Z",
                        "content": {"realm_id": first_realm_id, "body": "needle first"}
                    }]}
                }),
            ),
            (
                second_realm_id.clone(),
                json!({
                    "summary": {"summary": "Second Realm"},
                    "timeline": {"events": [{
                        "kind": "ak.message.create",
                        "event_id": "ak:event:AatXc8rOoiOfXgpJeRROJV9yNH3ydNHDDoc6VbiwNThT",
                        "actor_id": "ak:did_core:web:bob.example",
                        "created_at": "2026-06-19T00:00:00.000Z",
                        "content": {"realm_id": second_realm_id, "body": "needle second"}
                    }]}
                }),
            ),
        ]);
        let store = LocalStateStore::default();

        let not_messages = local_decrypted_index_search(
            &realms,
            &store,
            &authority("did:web:alice.example"),
            &device("ak:device:01904100-0000-7000-8000-000000000925"),
            "needle",
            &[],
            Some(&["realm"]),
            10,
        );
        assert!(not_messages.results.is_empty());

        let filtered = local_decrypted_index_search(
            &realms,
            &store,
            &authority("did:web:alice.example"),
            &device("ak:device:01904100-0000-7000-8000-000000000925"),
            "needle",
            std::slice::from_ref(&second_realm_id),
            Some(&["message"]),
            1,
        );
        assert_eq!(filtered.results.len(), 1);
        assert_eq!(filtered.results[0]["realm_id"], second_realm_id);
        assert_eq!(filtered.results[0]["content"]["body"], "needle second");
    }
}
