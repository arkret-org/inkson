use std::rc::Rc;

use glory::{Cage, Scope};
use serde_json::{Value, json};

use crate::i18n::tr;
use crate::models::IndexSearchView;
use crate::presentation::{InksonContext, View};
use crate::routes::Route;
use crate::state::LocalStateStore;
use crate::views::helpers::{actor_display_label, short_protocol_id};
use crate::views::settings::widgets::*;
/// Type alias for the panel's result list to keep the component
/// signature compact.
type ResultRows = Vec<Value>;
type SearchRequest = (String, arkret_sdk::AccountId, arkret_sdk::DeviceId, u64);
type SearchDeadline = Option<chrono::DateTime<chrono::Utc>>;

fn earliest_deadline(left: SearchDeadline, right: SearchDeadline) -> SearchDeadline {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

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
    Live(crate::presentation::SharedStateStore),
    #[cfg(not(target_arch = "wasm32"))]
    Host(
        crate::runtime::input::StateStoreHandle,
        &'a crate::state::PersistedSessionGrant,
    ),
}

impl SearchSource<'_> {
    fn with_store<R>(&self, read: impl FnOnce(&LocalStateStore) -> R) -> R {
        match self {
            Self::Borrowed(store) => read(store),
            Self::Live(store) => store.read(read),
            #[cfg(not(target_arch = "wasm32"))]
            Self::Host(store, _) => store.read(read),
        }
    }

    fn holder_deadline(
        &self,
        account: &arkret_sdk::AccountId,
        device: &arkret_sdk::DeviceId,
    ) -> SearchDeadline {
        #[cfg(not(target_arch = "wasm32"))]
        if let Self::Host(_, grant) = self {
            return self.with_store(|store| {
                store.search_valid_until_with_grant(
                    account,
                    device,
                    chrono::Utc::now(),
                    Some(grant),
                )
            });
        }
        self.with_store(|store| {
            store.search_session_valid_until(account, device, chrono::Utc::now())
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn search_native_index(
    store: crate::runtime::input::StateStoreHandle,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    grant: &crate::state::PersistedSessionGrant,
    query: &str,
    realm_ids: &[String],
    limit: usize,
) -> anyhow::Result<(IndexSearchView, SearchDeadline)> {
    let (mut view, policy_deadline) = search_local(
        SearchSource::Host(store.clone(), grant),
        authority,
        device_id,
        query,
        realm_ids,
        Some(&["message"]),
        limit,
    )
    .await?;
    let holder_deadline = SearchSource::Host(store, grant).holder_deadline(authority, device_id);
    let deadline = earliest_deadline(holder_deadline, policy_deadline);
    if holder_deadline.is_none() || deadline.is_some_and(|value| value <= chrono::Utc::now()) {
        view.results.clear();
    }
    Ok((view, deadline))
}

fn search_blocked_actors(store: &LocalStateStore) -> std::collections::BTreeSet<String> {
    crate::account_data::blocked_message_actor_ids(&store.client_blocklist())
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
    .map(|(view, _)| view)
}

async fn search_local(
    source: SearchSource<'_>,
    authority: &arkret_sdk::AccountId,
    device_id: &arkret_sdk::DeviceId,
    query: &str,
    realm_ids: &[String],
    object_kinds: Option<&[&str]>,
    limit: usize,
) -> anyhow::Result<(IndexSearchView, SearchDeadline)> {
    let query = query.trim();
    let mut response = IndexSearchView {
        query: query.to_owned(),
        results: Vec::new(),
        next_cursor: None,
    };
    if query.is_empty()
        || limit == 0
        || object_kinds.is_some_and(|kinds| !kinds.contains(&"message"))
        || source.holder_deadline(authority, device_id).is_none()
    {
        return Ok((response, None));
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
    let blocked = source.with_store(search_blocked_actors);

    let mut after = None;
    let mut recheck_at = None;
    loop {
        let page = index
            .read_search_page(&actor, after.as_deref(), chrono::Utc::now())
            .await?;
        if page.generation != generation
            || source.holder_deadline(authority, device_id).is_none()
            || source.with_store(search_blocked_actors) != blocked
        {
            response.results.clear();
            return Ok((response, None));
        }
        recheck_at = earliest_deadline(recheck_at, page.recheck_at);
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
            let Some(original) = page
                .rows
                .iter()
                .find(|full| full.event.event_id.as_str() == message.id)
            else {
                continue;
            };
            // Personal filtering uses the authenticated complete sender ActorId,
            // independently of membership and the shared Message lifecycle.
            if crate::account_data::message_actor_is_blocked(&original.event.actor_id, &blocked) {
                continue;
            }
            if message.crypto_state != crate::views::chat::model::MessageCryptoState::Plaintext
                || source.with_store(|store| store.account_scope_read_denied(&message.realm_id))
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
        || source.holder_deadline(authority, device_id).is_none()
        || source.with_store(search_blocked_actors) != blocked
        || recheck_at.is_some_and(|deadline| deadline <= chrono::Utc::now())
    {
        response.results.clear()
    }
    Ok((response, recheck_at))
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
    results: Cage<ResultRows>,
    loading: Cage<bool>,
    search_epoch: Cage<u64>,
    last_search: Cage<Option<SearchRequest>>,
    error_key: Cage<Option<&'static str>>,
    has_searched: Cage<bool>,
    recheck_at: Cage<SearchDeadline>,
    holder_deadline: Cage<SearchDeadline>,
    request_task: Cage<Option<glory::core::TaskToken>>,
}
fn search_holder_ready(context: &InksonContext) -> bool {
    context
        .active_account
        .get()
        .as_ref()
        .is_some_and(|account| {
            context
                .state_store
                .read(|store| store.search_session_matches(&account.authority, &account.device_id))
        })
}
fn local_search(
    scope: &Scope,
    context: Rc<InksonContext>,
    initial_query: String,
) -> LocalSearchState {
    let initial_request = context
        .active_account
        .get_untracked()
        .filter(|_| !initial_query.trim().is_empty())
        .map(|account| {
            (
                initial_query.clone(),
                account.authority,
                account.device_id,
                context.session_generation.get_untracked(),
            )
        });
    let missing_account = !initial_query.trim().is_empty() && initial_request.is_none();
    let state = LocalSearchState {
        results: scope.cage(Vec::new()),
        loading: scope.cage(false),
        search_epoch: scope.cage(0),
        last_search: scope.cage(initial_request),
        error_key: scope.cage(missing_account.then_some("search.account_unavailable")),
        has_searched: scope.cage(false),
        recheck_at: scope.cage(None),
        holder_deadline: scope.cage(None),
        request_task: scope.cage(None),
    };
    let clock = scope.cage(0_u64);
    let fence = {
        let ctx = context.clone();
        scope.bond(move || {
            let tick = clock.get();
            let _ = ctx.state_revision.get();
            let account = ctx
                .active_account
                .get()
                .map(|account| (account.authority, account.device_id));
            let generation = ctx.session_generation.get();
            ctx.state_store.read(|store| {
                let until = account.as_ref().and_then(|(account, device)| {
                    store.search_session_valid_until(account, device, chrono::Utc::now())
                });
                (
                    account,
                    generation,
                    store.current_generation(),
                    store.current_reset_required(),
                    store.session_grant(),
                    until,
                    search_blocked_actors(store),
                    tick,
                )
            })
        })
    };
    let _expiry = crate::presentation::widgets::resource(scope, move || {
        let _ = state.search_epoch.get();
        let until = earliest_deadline(
            earliest_deadline(fence.get().5, state.holder_deadline.get()),
            state.recheck_at.get(),
        );
        async move {
            if let Some(until) = until {
                loop {
                    let remaining = until.signed_duration_since(chrono::Utc::now());
                    if remaining <= chrono::TimeDelta::zero() {
                        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
                        tracing::warn!(
                            phase = "expiry_elapsed",
                            epoch = state.search_epoch.get_untracked(),
                            "local search lifecycle"
                        );
                        state.results.revise(|v| v.clear());
                        state.loading.revise(|v| *v = true);
                        state.recheck_at.revise(|v| *v = None);
                        state.holder_deadline.revise(|v| *v = None);
                        clock.revise(|v| *v = v.wrapping_add(1));
                        break;
                    }
                    crate::runtime_helpers::sleep_for(
                        remaining
                            .to_std()
                            .unwrap_or_default()
                            .min(std::time::Duration::from_secs(60)),
                    )
                    .await;
                }
            }
            Ok(())
        }
    });
    {
        let ctx = context.clone();
        let owner = scope.downgrade();
        scope.effect(move || {
            let current = fence.get();
            #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
            tracing::warn!(
                phase = "fence_changed",
                epoch = state.search_epoch.get_untracked(),
                holder_ready = current.5.is_some(),
                "local search lifecycle"
            );
            if let Some(task) = state.request_task.revise(Option::take) {
                task.cancel();
            }
            state
                .holder_deadline
                .revise(|deadline| *deadline = current.5);
            state.search_epoch.revise(|v| *v = v.wrapping_add(1));
            state.results.revise(|v| v.clear());
            state.recheck_at.revise(|v| *v = None);
            state.loading.revise(|v| *v = false);
            if let Some((query, account, device, generation)) = state.last_search.get_untracked() {
                if ctx
                    .active_account
                    .get_untracked()
                    .as_ref()
                    .is_some_and(|active| active.authority == account && active.device_id == device)
                    && ctx.session_generation.get_untracked() == generation
                {
                    run_search(ctx.clone(), owner.clone(), state, query);
                } else {
                    state.last_search.revise(|v| *v = None);
                    state.has_searched.revise(|v| *v = false);
                    state.recheck_at.revise(|v| *v = None);
                }
            }
        });
    }
    state
}
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
fn observe_search_holder(
    context: &InksonContext,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) {
    let now = chrono::Utc::now();
    context.state_store.read(|store| {
        let active_matches = store.active_authority().as_ref() == Some(account);
        let reset_required = store.current_reset_required();
        let persist_failed = store.persist_error().is_some();
        store.with_unoverlaid_account_fields(|state| {
            let grant = state.session_grant.as_ref();
            let authority = state.device_authoring_authority.as_ref();
            tracing::warn!(
                phase = "holder_gates",
                active_matches,
                reset_required,
                persist_failed,
                has_grant = grant.is_some(),
                has_authority = authority.is_some(),
                grant_owner_matches =
                    grant.is_some_and(
                        |grant| grant.account_id == *account && grant.device_id == *device
                    ),
                grant_unexpired = grant
                    .and_then(|grant| grant.grant_expires_at)
                    .is_some_and(|expiry| expiry > now),
                authority_owner_matches = authority
                    .is_some_and(|authority| authority.account_id == *account
                        && authority.device_id == *device),
                device_active = authority
                    .is_some_and(|authority| authority.device_projection.device_status.is_active()),
                attested_effective = authority
                    .is_some_and(|authority| authority.device_projection.attested_at <= now),
                authorization_effective = authority.is_some_and(|authority| authority
                    .device_projection
                    .authorization_window
                    .not_before
                    <= now),
                projection_unexpired =
                    authority.is_some_and(|authority| authority.device_projection.expires_at > now),
                window_unexpired = authority.is_some_and(|authority| authority
                    .device_projection
                    .authorization_window
                    .expires_at
                    .is_none_or(|expiry| expiry > now)),
                generation_matches = authority.is_some_and(|authority| {
                    crate::identity::authoring_generation::cached_principal_authoring_generation(
                        account,
                        device.as_str(),
                    )
                    .is_none_or(|generation| generation == authority.authoring_generation)
                }),
                "local search lifecycle"
            );
        });
    });
}

#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
struct SearchReadObservation {
    owner: glory::ui::WeakScope,
    epoch: Cage<u64>,
    serial: u64,
    complete: bool,
}
#[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
impl Drop for SearchReadObservation {
    fn drop(&mut self) {
        if !self.complete {
            tracing::warn!(phase="read_interrupted", owner_alive=self.owner.upgrade().is_some(), serial=self.serial,
                current_serial=?self.epoch.try_with_untracked(|value| *value).ok(), "local search lifecycle");
        }
    }
}

fn run_search(
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    state: LocalSearchState,
    q: String,
) {
    let query = q.trim().to_owned();
    if query.is_empty() {
        return;
    }
    let Some(scope) = owner.upgrade() else {
        return;
    };
    if let Some(task) = state.request_task.revise(Option::take) {
        task.cancel();
    }
    let serial = state.search_epoch.revise(|v| {
        *v = v.wrapping_add(1);
        *v
    });
    let Some(account) = context.active_account.get_untracked() else {
        state.results.revise(Vec::clear);
        state.loading.revise(|loading| *loading = false);
        state.holder_deadline.revise(|deadline| *deadline = None);
        state
            .error_key
            .revise(|v| *v = Some("search.account_unavailable"));
        return;
    };
    let authority = account.authority;
    let device = account.device_id;
    let session_generation = context.session_generation.get_untracked();
    let generation = context.state_store.read(|store| store.current_generation());
    let blocked = context.state_store.read(search_blocked_actors);
    state.recheck_at.revise(|v| *v = None);
    state.loading.revise(|v| *v = true);
    state.error_key.revise(|v| *v = None);
    state.has_searched.revise(|v| *v = true);
    state.results.revise(|v| v.clear());
    let holder_deadline = context
        .state_store
        .read(|store| store.search_session_valid_until(&authority, &device, chrono::Utc::now()));
    state
        .holder_deadline
        .revise(|deadline| *deadline = holder_deadline);
    state
        .last_search
        .revise(|v| *v = Some((q, authority.clone(), device.clone(), session_generation)));
    let task = scope.owner().spawn(async move {
        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
        let mut observation = {
            tracing::warn!(phase="read_started", serial, holder_ready=holder_deadline.is_some(), "local search lifecycle");
            SearchReadObservation { owner: owner.clone(), epoch: state.search_epoch, serial, complete:false }
        };
        #[cfg(all(test, not(target_arch = "wasm32")))]
        eprintln!(
            "[search-phase] request:start now={} serial={serial}",
            chrono::Utc::now()
        );
        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
        observe_search_holder(&context, &authority, &device);
        let response = search_local(
            SearchSource::Live(context.state_store.clone()),
            &authority,
            &device,
            &query,
            &[],
            Some(&["message"]),
            50,
        )
        .await;
        #[cfg(all(target_arch = "wasm32", feature = "spec-conformance"))]
        {
            observation.complete = true;
            tracing::warn!(phase="read_completed", serial, current_serial=state.search_epoch.get_untracked(), success=response.is_ok(), rows=?response.as_ref().ok().map(|(view,_)|view.results.len()), "local search lifecycle");
        }
        #[cfg(all(test, not(target_arch = "wasm32")))]
        eprintln!(
            "[search-phase] request:response now={} serial={serial} current_serial={} result={:?}",
            chrono::Utc::now(),
            state.search_epoch.get_untracked(),
            response
                .as_ref()
                .map(|(view, deadline)| (view.results.len(), deadline))
        );
        if owner.upgrade().is_none() || state.search_epoch.get_untracked() != serial {
            return;
        }
        state.request_task.revise(|task| *task = None);
        let current = context.session_generation.get_untracked() == session_generation
            && context.state_store.read(|store| {
                store.current_generation() == generation
                    && store.search_session_matches(&authority, &device)
                    && search_blocked_actors(store) == blocked
            });
        if !current {
            state.results.revise(|v| v.clear());
            state.recheck_at.revise(|v| *v = None);
        } else {
            match response {
                Ok((mut response, deadline)) => {
                    if deadline.is_some_and(|deadline| deadline <= chrono::Utc::now()) {
                        response.results.clear();
                    }
                    state.recheck_at.revise(|v| *v = deadline);
                    state.results.revise(|v| *v = response.results);
                }
                Err(error) => {
                    tracing::warn!(%error,"local committed search failed closed");
                    state.recheck_at.revise(|v| *v = None);
                    state
                        .error_key
                        .revise(|v| *v = Some("search.account_unavailable"));
                }
            }
        }
        state.loading.revise(|v| *v = false);
    });
    match task {
        Ok(task) if task.is_current() => {
            state.request_task.revise(|current| *current = Some(task));
        }
        Ok(_) => {}
        Err(error) => {
            state.loading.revise(|loading| *loading = false);
            state
                .error_key
                .revise(|key| *key = Some("search.account_unavailable"));
            scope.report_error(error);
        }
    }
}
pub fn page(scope: &Scope, context: Rc<InksonContext>, _route: Route) -> View {
    global_search_panel(scope, context, String::new())
}
pub fn global_search_panel(
    scope: &Scope,
    context: Rc<InksonContext>,
    initial_query: String,
) -> View {
    let query = scope.cage(initial_query.clone());
    let state = local_search(scope, context.clone(), initial_query);
    let ctx = context.clone();
    let owner = scope.downgrade();
    let enabled = scope.bond(move || !query.get().trim().is_empty() && !state.loading.get());
    let query_reference = scope.cage(None);
    let query_focused = scope.cage(false);
    let focus_owner = scope.downgrade();
    scope.effect(move || {
        if !query_focused.get_untracked()
            && let Some(node) = query_reference.get()
            && let Some(scope) = focus_owner.upgrade()
            && scope
                .capabilities()
                .is_ok_and(|capabilities| capabilities.focus)
        {
            match scope.action(glory::render::Action::Focus(node)) {
                Ok(()) => query_focused.revise(|focused| *focused = true),
                Err(error) => scope.report_error(error),
            }
        }
    });
    let query_context = context.clone();
    let query_owner = owner.clone();
    let form = line(
        "actions global-search-form",
        vec![
            input_prompt(
                scope,
                context.translated(scope, "search.placeholder").into(),
                query,
                Box::new(
                    sapid::text_field()
                        .unstyled()
                        .class("input global-search-input")
                        .name(context.translated(scope, "search.title"))
                        .purpose(glory::render::Purpose::Search)
                        .value(query)
                        .node_ref(query_reference)
                        .on_value_change(move |value| query.revise(|current| *current = value))
                        .on(glory::render::EventKind::Keyboard, move |event| {
                            if matches!(
                                event,
                                glory::render::Event::Keyboard {
                                    command: glory::render::KeyboardCommand::Submit,
                                    ..
                                }
                            ) && enabled.get_untracked()
                            {
                                run_search(
                                    query_context.clone(),
                                    query_owner.clone(),
                                    state,
                                    query.get_untracked(),
                                );
                            }
                        }),
                ),
            ),
            action(
                scope,
                context.clone(),
                "global-search-submit",
                "search.title",
                "primary",
                enabled,
                move || run_search(ctx.clone(), owner.clone(), state, query.get_untracked()),
            ),
        ],
    );
    let source = {
        let ctx = context.clone();
        scope.bond(move || {
            let _ = ctx.state_revision.get();
            let _ = ctx.active_account.get();
            let _ = ctx.session_generation.get();
            let _ = ctx.locale.get();
            (
                state.results.get(),
                state.loading.get(),
                state.error_key.get(),
                state.has_searched.get(),
                state.recheck_at.get(),
            )
        })
    };
    let ctx = context.clone();
    let results = reactive(
        source,
        move |scope, (rows, loading, error, searched, deadline)| {
            if let Some(key) = error {
                return stack(
                    "event global-search-results-error",
                    vec![
                        plain(ctx.translated(scope, "search.results.error")),
                        paragraph("muted", ctx.translated(scope, key)),
                    ],
                );
            }
            if loading {
                return stack(
                    "event global-search-results-loading",
                    vec![paragraph(
                        "muted",
                        ctx.translated(scope, "search.results.loading"),
                    )],
                );
            }
            if !searched {
                return stack(
                    "event global-search-results-empty",
                    vec![paragraph(
                        "muted",
                        ctx.translated(scope, "search.results.empty"),
                    )],
                );
            }
            let ready = search_holder_ready(&ctx)
                && deadline.is_none_or(|deadline| deadline > chrono::Utc::now());
            let blocked = ctx.state_store.read(search_blocked_actors);
            let rows = rows
                .into_iter()
                .filter(|row| {
                    ctx.state_store.read(|store| {
                        !row.get("realm_id")
                            .and_then(Value::as_str)
                            .is_none_or(|realm| store.account_scope_read_denied(realm))
                            && row
                                .get("actor_id")
                                .and_then(|actor| {
                                    serde_json::from_value::<arkret_sdk::ActorId>(actor.clone())
                                        .ok()
                                })
                                .is_some_and(|actor| {
                                    !crate::account_data::message_actor_is_blocked(&actor, &blocked)
                                })
                    })
                })
                .collect::<Vec<_>>();
            if !ready || rows.is_empty() {
                return stack(
                    "event global-search-results-no-results",
                    vec![paragraph(
                        "muted",
                        ctx.translated(scope, "search.no_results"),
                    )],
                );
            }
            stack(
                "global-search-results",
                rows.into_iter()
                    .enumerate()
                    .map(|(index, row)| {
                        let realm = string_field(&row, &["realm_id"]).unwrap_or_else(|| "-".into());
                        let actor = result_actor_id(&row);
                        let mut nodes = vec![line(
                            "event-head",
                            vec![
                                paragraph("global-search-result-kind", render_result_kind(&row)),
                                paragraph(
                                    "id mono global-search-result-realm",
                                    short_protocol_id(&realm),
                                ),
                            ],
                        )];
                        if !actor.is_empty() {
                            nodes.push(paragraph(
                                "muted",
                                ctx.state_store
                                    .read(|store| actor_display_label(store, &actor)),
                            ));
                        }
                        nodes.push(paragraph(
                            "global-search-result-snippet",
                            render_result_snippet(&row),
                        ));
                        if let Some(target) = result_destination(&row) {
                            let route = target.route;
                            let label = match target.seal {
                                Some(seal) => format!("{}: {seal}", tr(target.label_key)),
                                None => tr(target.label_key),
                            };
                            let ctx = ctx.clone();
                            nodes.push(Box::new(
                                crate::presentation::widgets::internal_link()
                                    .class("secondary global-search-result-link global-search-result-seal")
                                    .target(route.to_string())
                                    .name(label.clone())
                                    .fill(glory::ui::text().content(label))
                                    .on(glory::render::EventKind::Activate, move |_| {
                                        ctx.navigate(route.clone())
                                    }),
                            ));
                        }
                        // Preserve the source references previously exposed as HTML data
                        // attributes through a supported accessible description on both hosts.
                        let event = row
                            .get("event_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let commit = row
                            .pointer("/covering_commit/commit_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let relation = if !event.is_empty() || !commit.is_empty() {
                            use sha2::Digest;
                            let key = format!("{index}:{event}:{commit}");
                            let id = match glory::render::SemanticId::new(format!(
                                "search-source-{}",
                                hex::encode(sha2::Sha256::digest(key.as_bytes()))
                            )) {
                                Ok(id) => id,
                                Err(error) => {
                                    scope.report_error(error);
                                    return crate::presentation::widgets::empty();
                                }
                            };
                            nodes.push(Box::new(
                                glory::ui::view()
                                    .class("sr-only global-search-result-provenance")
                                    .semantics(Some(Box::new(glory::render::Semantics {
                                        id: Some(id.clone()),
                                        ..Default::default()
                                    })))
                                    .fill((
                                        glory::ui::text().content(format!(
                                            "{}: ",
                                            ctx.tr("search.source_event")
                                        )),
                                        glory::ui::text()
                                            .class("global-search-result-event-reference")
                                            .content(event.to_owned()),
                                        glory::ui::text().content(format!(
                                            " · {}: ",
                                            ctx.tr("search.source_commit")
                                        )),
                                        glory::ui::text()
                                            .class("global-search-result-commit-reference")
                                            .content(commit.to_owned()),
                                        glory::ui::text().content(" · Realm: "),
                                        glory::ui::text().class("global-search-result-realm-reference").content(realm.clone()),
                                    )),
                            ));
                            Some(Box::new(glory::render::Semantics {
                                described_by: Some(id),
                                ..Default::default()
                            }))
                        } else {
                            None
                        };
                        Box::new(
                            glory::ui::view()
                                .class("event global-search-result-item")
                                .role(glory::render::Role::Group)
                                .name(ctx.translated(scope, "search.result_source"))
                                .semantics(relation)
                                .fill(nodes),
                        ) as View
                    })
                    .collect(),
            )
        },
    );
    let ctx = context.clone();
    Box::new(
        glory::ui::view()
            .role(glory::render::Role::Section)
            .name(context.translated(scope, "search.title"))
            .class("timeline global-search-panel")
            .fill(vec![
                stack(
                    "event",
                    vec![
                        line(
                            "event-head",
                            vec![
                                plain(context.translated(scope, "search.title")),
                                paragraph(
                                    "muted global-search-index-label",
                                    context.translated(scope, "search.index"),
                                ),
                            ],
                        ),
                        form,
                    ],
                ),
                results,
                action(
                    scope,
                    context.clone(),
                    "global-search-back",
                    "search.back",
                    "secondary",
                    true,
                    move || ctx.navigate(Route::Dashboard),
                ),
            ]),
    )
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
    use super::*;
    #[test]
    fn retained_search_results_and_feedback_rerender_without_interpreting_literals() {
        let realm_id = "ak:realm:A_UALC69_WeDbu3WQ3suidUfmxa1MAW5tIIxjRS1C9yE";
        let rows = [
            json!({"realm_id": realm_id}),
            json!({"realm_id": realm_id, "task_id": "task{seal}", "content": {"body": "search.no_body"}}),
            json!({"realm_id": realm_id, "event_id": "message{seal}", "summary": "", "title": "ignored"}),
            json!({"realm_id": realm_id, "kind": "search.kind.message", "title": "{query} / 原文"}),
        ];
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
        for (locale, copy) in [
            (crate::i18n::UiLocale::En, &english),
            (crate::i18n::UiLocale::Zh, &chinese),
            (crate::i18n::UiLocale::En, &english),
        ] {
            crate::i18n::with_test_locale(locale, || {
                let mut actual = rows
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
                actual.push(tr("search.account_unavailable"));
                actual.sort();
                assert_eq!(actual, expected(copy));
            });
        }
    }
}
