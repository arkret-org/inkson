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
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::views::helpers::{actor_display_label, short_protocol_id};

/// Type alias for the panel's result list to keep the component
/// signature compact.
type ResultRows = Vec<Value>;
type SearchRequest = (String, arkret_sdk::AccountId, arkret_sdk::DeviceId, u64);

/// Extract literal snippet text without interpreting it as a translation key.
/// `None` marks metadata-only rows; explicit empty text remains `Some`.
pub fn result_snippet(result: &Value) -> Option<String> {
    if let Some(body) = result
        .get("content")
        .and_then(|c| c.get("body"))
        .and_then(Value::as_str)
    {
        return Some(body.to_owned());
    }
    if let Some(summary) = result.get("summary").and_then(Value::as_str) {
        return Some(summary.to_owned());
    }
    if let Some(title) = result.get("title").and_then(Value::as_str) {
        return Some(title.to_owned());
    }
    None
}

// Resolve UI defaults only while rendering. Search projections remain literal.
fn render_result_snippet(result: &Value) -> String {
    result_snippet(result).unwrap_or_else(|| tr("search.no_body"))
}

fn render_result_kind(result: &Value) -> String {
    match result
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("message")
    {
        "message" => tr("search.kind.message"),
        kind => kind.to_owned(),
    }
}

pub fn result_actor_id(result: &Value) -> String {
    result
        .get("actor_id")
        .and_then(|actor| serde_json::from_value::<arkret_sdk::ActorId>(actor.clone()).ok())
        .map(|actor| actor.signing_principal_id().to_string())
        .or_else(|| string_field(result, &["actor_id", "source_actor_id"]))
        .unwrap_or_default()
}

#[derive(Clone, Debug, PartialEq)]
pub struct SearchDestination {
    pub route: Route,
    pub seal: Option<String>,
    pub label_key: &'static str,
}

enum SearchSource<'a> {
    #[allow(dead_code)]
    Borrowed(&'a LocalStateStore),
    Live(SyncSignal<LocalStateStore>),
}

impl SearchSource<'_> {
    fn with_store<R>(&self, read: impl FnOnce(&LocalStateStore) -> R) -> R {
        match self {
            Self::Borrowed(store) => read(store),
            Self::Live(store) => read(&store.peek()),
        }
    }
}

#[cfg(test)]
async fn local_decrypted_index_search(
    store: &LocalStateStore,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    query: &str,
    realm_ids: &[String],
    object_kinds: Option<&[&str]>,
    limit: usize,
) -> anyhow::Result<IndexSearchView> {
    search_local(
        SearchSource::Borrowed(store),
        authority,
        device_id,
        query,
        realm_ids,
        object_kinds,
        limit,
    )
    .await
}

async fn search_local(
    source: SearchSource<'_>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    query: &str,
    realm_ids: &[String],
    object_kinds: Option<&[&str]>,
    limit: usize,
) -> anyhow::Result<IndexSearchView> {
    let query = query.trim();
    let mut response = IndexSearchView {
        query: query.to_owned(),
        results: Vec::new(),
        next_cursor: None,
    };
    if query.is_empty()
        || limit == 0
        || object_kinds.is_some_and(|kinds| !kinds.contains(&"message"))
        || !source.with_store(|store| store.search_session_matches(authority, device_id))
    {
        return Ok(response);
    }
    let index = crate::state::CurrentIndex::open_committed(
        authority,
        source.with_store(|store| store.current_index_location()),
        || source.with_store(|store| Ok(store.current_generation())),
    )
    .await?;
    let generation = source.with_store(|store| store.current_generation());
    let needle = query.to_lowercase();
    let actor = arkret_sdk::ActorId::account(authority.clone());

    let mut after = None;
    loop {
        let page = index
            .read_search_page(&actor, after.as_deref(), chrono::Utc::now())
            .await?;
        if page.generation != generation
            || !source.with_store(|store| store.search_session_matches(authority, device_id))
        {
            response.results.clear();
            return Ok(response);
        }
        let (messages, privacy) = source.with_store(|store| {
            (
                crate::views::chat::model::chat_messages_from_search_originals(
                    &page.rows, store, authority, device_id,
                ),
                crate::sidecar::SidecarPrivacyGate::from_store(
                    store,
                    authority.principal_id.as_str(),
                ),
            )
        });
        for message in messages {
            if message.crypto_state != crate::views::chat::model::MessageCryptoState::Plaintext
                || message.pending
                || message.failed
                || message.redacted
                || (!realm_ids.is_empty() && !realm_ids.contains(&message.realm_id))
            {
                continue;
            }
            let Some(body) = searchable_message_body(&message.body, message.redacted) else {
                continue;
            };
            let probe =
                json!({"event_id": message.id, "strand_id": message.strand_id, "body": body});
            if !privacy.allows_strand(
                crate::sidecar::SidecarDisclosureSurface::Search,
                &message.strand_id,
            ) || !privacy
                .allows_serialized(crate::sidecar::SidecarDisclosureSurface::Search, &probe)
                || !body.to_lowercase().contains(&needle)
            {
                continue;
            }
            let Some(original) = page
                .rows
                .iter()
                .find(|full| full.event.event_id.as_str() == message.id)
            else {
                continue;
            };
            let body_source = message
                .protocol_content
                .as_ref()
                .and_then(|content| {
                    page.rows
                        .iter()
                        .find(|row| row.event.event_id == content.source)
                })
                .unwrap_or(original);
            response.results.push(json!({
                "realm_id": message.realm_id, "strand_id": message.strand_id,
                "kind": "message", "surface": "message", "event_id": message.id,
                "message_id": message.id, "actor_id": original.event.actor_id,
                "covering_commit": original.commit, "content": {"body": body},
                "source_event_id": body_source.event.event_id, "source_commit": body_source.commit,
                "index_profile": arkret_sdk::ProfileId::SEARCH_CLIENT_INDEX_V1,
                "index_source": "local_decrypted_client_index"
            }));
            if response.results.len() >= limit.min(100) {
                break;
            }
        }
        if response.results.len() >= limit.min(100) || page.next.is_none() {
            break;
        }
        after = page.next;
    }
    if source.with_store(|store| store.current_generation()) != generation
        || !source.with_store(|store| store.search_session_matches(authority, device_id))
    {
        response.results.clear()
    }
    Ok(response)
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
/// express. Newer coland rows may carry `message_id`, `event_id`,
/// `surface`, or `task_id`; otherwise rows degrade to the Realm overview.
pub fn result_destination(result: &Value) -> Option<SearchDestination> {
    let realm_id = result.get("realm_id").and_then(Value::as_str)?;
    if let Some(task_id) = string_field(result, &["task_id"]) {
        return Some(SearchDestination {
            route: Route::KanbanTask {
                realm_id: realm_id.to_owned(),
                task_id: task_id.clone(),
                tab: String::new(),
            },
            seal: Some(task_id),
            label_key: "search.open_task",
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
            label_key: "search.open_message",
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
        label_key: "search.open",
    })
}

// Shared "first non-empty string under candidate keys" helper
// lives in `crate::realm_tree`.
use crate::realm_tree::string_field;

#[derive(Clone, Copy)]
struct LocalSearchState {
    results: Signal<ResultRows>,
    loading: Signal<bool>,
    search_epoch: Signal<u64>,
    last_search: Signal<Option<SearchRequest>>,
    error_key: Signal<Option<&'static str>>,
    has_searched: Signal<bool>,
}

fn search_holder_ready(session: crate::app::SessionContext) -> bool {
    session
        .active_account
        .read()
        .as_ref()
        .is_some_and(|account| {
            session
                .state_store
                .read()
                .search_session_matches(&account.authority, &account.device_id)
        })
}

fn use_local_search(initial_query: String) -> LocalSearchState {
    // A4 — state_store from session context instead of a prop.
    let session = crate::app::SessionContext::get();
    let state_store = session.state_store;
    let active_account = session.active_account;
    let mut results = use_signal(ResultRows::new);
    let mut loading = use_signal(|| false);
    let mut search_epoch = use_signal(|| 0u64);
    let mut last_search = use_signal(|| None::<SearchRequest>);
    let mut error_key = use_signal(|| None::<&'static str>);
    let mut has_searched = use_signal(|| false);
    let mut clock_revision = use_signal(|| 0_u64);
    let security_fence = use_memo(move || {
        let _ = clock_revision.read();
        // A query after not_before must both release the now-valid result and
        // arm its expiry task, even when persisted evidence has not changed.
        let _ = search_epoch.read();
        let store = state_store.read();
        let account = active_account
            .read()
            .as_ref()
            .map(|account| (account.authority.clone(), account.device_id.clone()));
        let valid_until = account.as_ref().and_then(|(account, device)| {
            store.search_session_valid_until(account, device, chrono::Utc::now())
        });
        (
            account,
            *session.session_generation.read(),
            store.current_generation(),
            store.current_reset_required(),
            store.session_grant(),
            valid_until,
        )
    });
    // Resource dependencies cancel the previous timer when holder evidence is
    // renewed or replaced. Recheck wall time after waking, including suspend.
    let _expiry = use_resource(move || {
        let valid_until = security_fence.read().5;
        async move {
            if let Some(expiry) = valid_until {
                loop {
                    let remaining = expiry.signed_duration_since(chrono::Utc::now());
                    if remaining <= chrono::TimeDelta::zero() {
                        clock_revision.with_mut(|revision| *revision = revision.wrapping_add(1));
                        break;
                    }
                    crate::runtime_helpers::sleep_for(
                        remaining
                            .to_std()
                            .unwrap()
                            .min(std::time::Duration::from_secs(60)),
                    )
                    .await;
                }
            }
        }
    });
    use_effect(move || {
        let _ = security_fence.read();
        search_epoch.with_mut(|epoch| *epoch = epoch.wrapping_add(1));
        results.clear();
        loading.set(false);
        let retained_request = last_search.peek().clone();
        if let Some((q, owner, device, epoch)) = retained_request {
            let same_owner =
                active_account.peek().as_ref().is_some_and(|account| {
                    account.authority == owner && account.device_id == device
                }) && *session.session_generation.peek() == epoch;
            if same_owner {
                run_search(
                    q,
                    state_store,
                    owner,
                    device,
                    results,
                    loading,
                    error_key,
                    has_searched,
                    search_epoch,
                    last_search,
                );
            } else {
                last_search.set(None);
                has_searched.set(false);
            }
        }
    });

    // Auto-run the search when the panel is opened with a pre-filled
    // query (e.g. `/search?q=…`).
    let initial_query_for_effect = initial_query.clone();
    use_effect(move || {
        let q = initial_query_for_effect.clone();
        if !q.trim().is_empty() {
            let Some(account) = active_account.peek().clone() else {
                error_key.set(Some("search.account_unavailable"));
                return;
            };
            run_search(
                q,
                state_store,
                account.authority,
                account.device_id,
                results,
                loading,
                error_key,
                has_searched,
                search_epoch,
                last_search,
            );
        }
    });

    LocalSearchState {
        results,
        loading,
        search_epoch,
        last_search,
        error_key,
        has_searched,
    }
}

#[component]
pub fn GlobalSearchPanel(
    principal_id: Signal<Option<arkret_sdk::DidCoreId>>,
    device_id: Signal<String>,
    initial_query: String,
) -> Element {
    let session = crate::app::SessionContext::get();
    let state_store = session.state_store;
    let active_account = session.active_account;
    let mut query = use_signal(|| initial_query.clone());
    let navigator = use_navigator();
    let LocalSearchState {
        results,
        loading,
        search_epoch,
        last_search,
        mut error_key,
        has_searched,
    } = use_local_search(initial_query);
    // Rendering must use current wall time too: a new query can become valid
    // after not_before without changing any persisted holder evidence.
    let ready = search_holder_ready(session);

    rsx! {
        div { class: "timeline", "data-testid": "global-search-panel", role: "region", "aria-label": tr("search.title"),
            div { class: "event",
                div { class: "event-head",
                    span { {tr("search.title")} }
                    span { class: "muted", "data-testid": "global-search-index-label", {tr("search.index")} }
                }
                form {
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        let q = query();
                        if q.trim().is_empty() { return; }
                        let Some(account) = active_account.peek().clone() else {
                            error_key.set(Some("search.account_unavailable"));
                            return;
                        };
                        run_search(
                            q,
                            state_store,
                            account.authority,
                            account.device_id,
                            results,
                            loading,
                            error_key,
                            has_searched,
                            search_epoch,
                            last_search,
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

            if let Some(key) = error_key() {
                div { class: "event", "data-testid": "global-search-results-error",
                    div { class: "event-head", span { {tr("search.results.error")} } }
                    div { class: "muted", {tr(key)} }
                }
            } else if loading() {
                div { class: "event", "data-testid": "global-search-results-loading",
                    div { class: "muted", {tr("search.results.loading")} }
                }
            } else if !has_searched() {
                div { class: "event", "data-testid": "global-search-results-empty",
                    div { class: "muted", {tr("search.results.empty")} }
                }
            } else if !ready || results().is_empty() {
                div { class: "event", "data-testid": "global-search-results-no-results",
                    div { class: "muted", {tr("search.no_results")} }
                }
            } else {
                div { "data-testid": "global-search-results",
                    for (idx, result) in results().into_iter().enumerate() {
                        {
                            let snippet = render_result_snippet(&result);
                            let destination = result_destination(&result);
                            let realm_id_text = result
                                .get("realm_id")
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let sender = result_actor_id(&result);
                            let kind = render_result_kind(&result);
                            let destination_label = destination.as_ref().map(|target| tr(target.label_key)).unwrap_or_default();
                            let destination_for_button = destination.clone();
                            let realm_id_label = short_protocol_id(&realm_id_text);
                            let sender_label = actor_display_label(&state_store.read(), &sender);
                            rsx! {
                                div {
                                    key: "{idx}",
                                    class: "event",
                                    "data-testid": "global-search-result-item",
                                    "data-event-id": result.get("event_id").and_then(Value::as_str).unwrap_or_default(),
                                    "data-commit-id": result.pointer("/covering_commit/commit_id").and_then(Value::as_str).unwrap_or_default(),
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
                                                        "{destination_label}: {seal}"
                                                    }
                                                } else {
                                                    "{destination_label}"
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
                    {tr("search.back")}
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_search(
    q: String,
    state_store: SyncSignal<LocalStateStore>,
    authority: arkret_sdk::AccountId,
    device_id: arkret_sdk::DeviceId,
    mut results: Signal<ResultRows>,
    mut loading: Signal<bool>,
    mut error_key: Signal<Option<&'static str>>,
    mut has_searched: Signal<bool>,
    mut search_epoch: Signal<u64>,
    mut last_search: Signal<Option<SearchRequest>>,
) {
    let query_trimmed = q.trim().to_owned();
    if query_trimmed.is_empty() {
        return;
    }
    loading.set(true);
    error_key.set(None);
    has_searched.set(true);
    results.clear();
    let request_epoch = search_epoch.with_mut(|epoch| {
        *epoch = epoch.wrapping_add(1);
        *epoch
    });
    let generation = state_store.peek().current_generation();
    let session_generation = crate::app::SessionContext::get().session_generation;
    let session_epoch = *session_generation.peek();
    last_search.set(Some((
        q,
        authority.clone(),
        device_id.clone(),
        session_epoch,
    )));
    spawn(async move {
        let response = search_local(
            SearchSource::Live(state_store),
            &authority,
            &device_id,
            &query_trimmed,
            &[],
            Some(&["message"]),
            50,
        )
        .await;
        if *search_epoch.peek() != request_epoch {
            return;
        }
        let current = state_store.peek();
        if *session_generation.peek() != session_epoch
            || current.current_generation() != generation
            || !current.search_session_matches(&authority, &device_id)
        {
            results.clear();
        } else {
            match response {
                Ok(response) => results.set(response.results),
                Err(error) => {
                    tracing::warn!(%error, "local committed search failed closed");
                    error_key.set(Some("search.account_unavailable"));
                }
            }
        }
        loading.set(false);
    });
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support as fixture;

    #[test]
    fn result_snippet_prefers_body_then_summary_then_title() {
        let with_body = json!({"content": {"body": "hello world"}});
        assert_eq!(result_snippet(&with_body).as_deref(), Some("hello world"));

        let with_summary = json!({"summary": "matched query"});
        assert_eq!(
            result_snippet(&with_summary).as_deref(),
            Some("matched query")
        );

        let with_title = json!({"title": "Demo Realm"});
        assert_eq!(result_snippet(&with_title).as_deref(), Some("Demo Realm"));

        let empty = json!({});
        assert_eq!(result_snippet(&empty), None);
    }

    #[test]
    fn result_text_provenance_preserves_empty_keys_and_braces() {
        for literal in ["", "search.no_body", "{query} / 原文"] {
            let body =
                json!({"content": {"body": literal}, "summary": "ignored", "title": "ignored"});
            let summary = json!({"summary": literal, "title": "ignored"});
            let title = json!({"title": literal});
            for row in [body, summary, title] {
                assert_eq!(result_snippet(&row).as_deref(), Some(literal));
            }
        }
        assert_eq!(result_snippet(&json!({"content": {"body": null}})), None);

        let realm_id = "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";
        let task = result_destination(
            &json!({"realm_id": realm_id, "task_id": "task{seal}", "message_id": "ignored"}),
        )
        .unwrap();
        assert_eq!(task.label_key, "search.open_task");
        assert_eq!(task.seal.as_deref(), Some("task{seal}"));
        assert_eq!(
            task.route,
            Route::KanbanTask {
                realm_id: realm_id.to_owned(),
                task_id: "task{seal}".to_owned(),
                tab: String::new()
            }
        );
        let fallback = result_destination(
            &json!({"realm_id": realm_id, "surface": "unknown", "seal": "search.open"}),
        )
        .unwrap();
        assert_eq!(fallback.label_key, "search.open");
        assert_eq!(fallback.seal.as_deref(), Some("search.open"));
        assert_eq!(
            fallback.route,
            Route::Realm {
                realm_id: realm_id.to_owned()
            }
        );
        assert!(result_destination(&json!({"task_id": "missing-realm"})).is_none());
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

    #[tokio::test]
    async fn local_index_search_without_current_holder_evidence_is_empty() {
        let store = LocalStateStore::default();
        let response = local_decrypted_index_search(
            &store,
            &fixture::authority("did:web:alice.example"),
            &fixture::device_id("ak:device:01904100-0000-7000-8000-000000000904"),
            "needle",
            &[],
            Some(&["message"]),
            10,
        )
        .await
        .unwrap();
        assert!(response.results.is_empty());
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "global_search/session_tests.rs"]
mod session_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod locale_tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;
    use crate::i18n::{I18nSignal, UiLocale};

    type LocaleHandle = Rc<RefCell<Option<I18nSignal>>>;

    fn retained_search_surface((handle, rows): (LocaleHandle, ResultRows)) -> Element {
        let locale = use_context_provider(|| crate::i18n::init_i18n_with_locale(UiLocale::En));
        *handle.borrow_mut() = Some(locale);
        // Capture the result and feedback once. Locale updates alone must
        // schedule rendering; no query, projection, or route changes here.
        let rows = use_signal(move || rows);
        let error = use_signal(|| Some("search.account_unavailable"));
        let texts = rows
            .read()
            .iter()
            .map(|row| {
                let target = result_destination(row).unwrap();
                format!(
                    "{} | {} | {} | {}",
                    render_result_kind(row),
                    render_result_snippet(row),
                    tr(target.label_key),
                    target.seal.as_deref().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>();
        rsx! {
            div {
                for (index, text) in texts.into_iter().enumerate() {
                    p { key: "{index}", "{text}" }
                }
                if let Some(key) = error() {
                    p { {tr(key)} }
                }
            }
        }
    }

    fn text_edits(edits: dioxus::core::Mutations) -> Vec<String> {
        let mut text = edits
            .edits
            .into_iter()
            .filter_map(|edit| match edit {
                dioxus::core::Mutation::CreateTextNode { value, .. }
                | dioxus::core::Mutation::SetText { value, .. } => Some(value),
                _ => None,
            })
            .collect::<Vec<_>>();
        text.sort();
        text
    }

    #[test]
    fn retained_search_results_and_feedback_rerender_without_interpreting_literals() {
        let realm_id = "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";
        let rows = vec![
            json!({"realm_id": realm_id}),
            json!({"realm_id": realm_id, "task_id": "task{seal}", "content": {"body": "search.no_body"}}),
            json!({"realm_id": realm_id, "event_id": "message{seal}", "summary": "", "title": "ignored"}),
            json!({"realm_id": realm_id, "kind": "search.kind.message", "title": "{query} / 原文"}),
        ];
        let handle = Rc::new(RefCell::new(None));
        let mut dom = VirtualDom::new_with_props(retained_search_surface, (handle.clone(), rows));
        let english = [
            "Message | <no body> | Open | ",
            "Message | search.no_body | Open task | task{seal}",
            "Message |  | Open message | message{seal}",
            "search.kind.message | {query} / 原文 | Open | ",
            "The active account is unavailable. Sign in again to search.",
        ];
        let chinese = [
            "消息 | <无正文> | 打开 | ",
            "消息 | search.no_body | 打开任务 | task{seal}",
            "消息 |  | 打开消息 | message{seal}",
            "search.kind.message | {query} / 原文 | 打开 | ",
            "当前账号不可用。请重新登录后搜索。",
        ];
        let expected = |values: &[&str]| {
            let mut values = values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>();
            values.sort();
            values
        };
        assert_eq!(text_edits(dom.rebuild_to_vec()), expected(&english));
        let mut locale = handle.borrow().expect("surface provides locale");
        for (language, copy) in [(UiLocale::Zh, &chinese), (UiLocale::En, &english)] {
            dom.in_runtime(|| crate::i18n::set_locale(&mut locale, language));
            assert_eq!(text_edits(dom.render_immediate_to_vec()), expected(copy));
        }
    }
}
