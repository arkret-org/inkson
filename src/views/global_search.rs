//! A6.1 — global cross-Space message search panel.
//!
//! Spec: yougen UX backlog (see `_claude_todos.md` lane A). Pressing
//! `Cmd+F` (or `Ctrl+F` off-mac), the `topbar-search-button`, or
//! navigating directly to `/search` opens this panel. The query
//! round-trips through soland's `POST /api/v1/index/search` substring
//! scan (the only cross-space message search endpoint we have for v1);
//! cross-space coverage will improve once the durable projection
//! lands.
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
//! - `global-search-result-space` for the source Space id
//! - `global-search-result-snippet` for the body excerpt

use dioxus::prelude::*;
use dioxus_router::{Link, hooks::use_navigator};
use serde_json::Value;

use crate::api::ContrixApi;
use crate::i18n::tr;
use crate::routes::Route;
use crate::views::helpers::with_authed_api;

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

/// Format a result row's destination as a `Route::Space { space_id }`
/// link when the row carries a space_id, or `None` when it doesn't
/// (older soland responses or non-Space rows). Callers render the
/// destination as a Link or a plain text fallback.
pub fn result_space_route(result: &Value) -> Option<Route> {
    result
        .get("space_id")
        .and_then(Value::as_str)
        .map(|sid| Route::Space {
            space_id: sid.to_owned(),
        })
}

#[component]
pub fn GlobalSearchPanel(
    base_url: Signal<String>,
    token: Signal<String>,
    initial_query: String,
) -> Element {
    // `Signal` is `Copy`; the `mut` here is just so the closures below
    // can re-assign the bindings without explicit `let mut` shadowing
    // — `.set()` itself takes `&self`. The compiler suggests removing
    // `mut` but that breaks the closure capture for `query` which is
    // genuinely mutated below.
    #[allow(unused_mut)]
    let mut query = use_signal(|| initial_query.clone());
    #[allow(unused_mut)]
    let mut results = use_signal(ResultRows::new);
    #[allow(unused_mut)]
    let mut loading = use_signal(|| false);
    #[allow(unused_mut)]
    let mut error_msg = use_signal(String::new);
    #[allow(unused_mut)]
    let mut has_searched = use_signal(|| false);
    let navigator = use_navigator();

    // Auto-run the search when the panel is opened with a pre-filled
    // query (e.g. `/search?q=…`).
    let initial_query_for_effect = initial_query.clone();
    use_effect(move || {
        let q = initial_query_for_effect.clone();
        if !q.trim().is_empty() {
            run_search(
                q,
                base_url(),
                token(),
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
                    span { class: "muted", "cx.index.search" }
                }
                form {
                    onsubmit: move |evt| {
                        evt.prevent_default();
                        let q = query();
                        if q.trim().is_empty() { return; }
                        run_search(
                            q,
                            base_url(),
                            token(),
                            results,
                            loading,
                            error_msg,
                            has_searched,
                        );
                    },
                    div { class: "actions", style: "gap: 8px;",
                        input {
                            "data-testid": "global-search-input",
                            "aria-label": tr("search.title"),
                            r#type: "search",
                            placeholder: tr("search.placeholder"),
                            value: "{query}",
                            autofocus: true,
                            oninput: move |evt| query.set(evt.value()),
                            style: "flex: 1; min-width: 280px;",
                        }
                        button {
                            class: "primary",
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
                            let route = result_space_route(&result);
                            let space_id_text = result
                                .get("space_id")
                                .and_then(Value::as_str)
                                .unwrap_or("-")
                                .to_owned();
                            let sender = result
                                .get("sender")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let kind = result
                                .get("kind")
                                .and_then(Value::as_str)
                                .unwrap_or("message")
                                .to_owned();
                            let route_for_button = route.clone();
                            rsx! {
                                div {
                                    key: "{idx}",
                                    class: "event",
                                    "data-testid": "global-search-result-item",
                                    div { class: "event-head",
                                        span { "{kind}" }
                                        span {
                                            class: "id mono",
                                            "data-testid": "global-search-result-space",
                                            "{space_id_text}"
                                        }
                                    }
                                    if !sender.is_empty() {
                                        div { class: "muted", "{sender}" }
                                    }
                                    div {
                                        "data-testid": "global-search-result-snippet",
                                        "{snippet}"
                                    }
                                    if let Some(target) = route_for_button {
                                        div { class: "actions",
                                            Link {
                                                class: "secondary",
                                                "data-testid": "global-search-result-link",
                                                to: target,
                                                "Open Space"
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
                button {
                    class: "secondary",
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
    base_url: String,
    api_token: String,
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
    spawn(async move {
        let space_ids: Vec<String> = Vec::new();
        match with_authed_api(&base_url, api_token, move |api: ContrixApi| {
            let q = query_trimmed.clone();
            async move {
                api.index_search(&q, &space_ids, Some(&["message"]), 50)
                    .await
            }
        })
        .await
        {
            Ok(resp) => {
                results.set(resp.results);
                loading.set(false);
            }
            Err(err) => {
                error_msg.set(err.display());
                results.set(ResultRows::new());
                loading.set(false);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

        let with_title = json!({"title": "Demo Space"});
        assert_eq!(result_snippet(&with_title), "Demo Space");

        let empty = json!({});
        assert_eq!(result_snippet(&empty), "<no body>");
    }

    #[test]
    fn result_space_route_extracts_space_id() {
        let row = json!({"space_id": "cx:space:demo"});
        let route = result_space_route(&row).expect("should produce a route");
        match route {
            Route::Space { space_id } => assert_eq!(space_id, "cx:space:demo"),
            _ => panic!("expected Route::Space"),
        }

        let no_space = json!({"kind": "actor"});
        assert!(result_space_route(&no_space).is_none());
    }
}
