pub use cokret_sdk::MentionNode;
use dioxus::prelude::*;

use crate::api::{
    CokretApi, is_auth_expired_error, is_terminal_session_grant_error,
    normalize_wait_for_sync_token,
};
use crate::config::{ClientConfig, LocalConfigStore};
use crate::ui::button::{Button, ButtonVariant};

/// Create an authenticated API client from a base URL and optional session credential.
pub fn authed_api(base_url: &str, session_credential: String) -> anyhow::Result<CokretApi> {
    authed_api_with_sync(base_url, session_credential, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
///
/// ②(A+②): `session_credential` is the `ck.session.grant` JWT.
/// The client also binds the device DPoP holder key so every `/_cokret/self/*`
/// request carries a per-request `DPoP` proof bound to the grant
/// (api-conventions.md §3.3). This is the centralized self-path credential
/// builder used across views.
pub fn authed_api_with_sync(
    base_url: &str,
    session_credential: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<CokretApi> {
    let mut api = CokretApi::new(base_url)?;
    if !session_credential.is_empty() {
        api = api.with_bearer(session_credential);
    }
    api = attach_device_dpop(api);
    if let Some(sync_token) = wait_for_sync_token {
        api = api.with_wait_for(sync_token);
    }
    Ok(api)
}

/// ②(A+②) — best-effort attach the device DPoP holder key to a client so its
/// `/_cokret/self/*` requests are sender-constrained (api-conventions.md §3.3).
/// In production the seed is read from the secure key store (independent of the
/// passed state store); in tests no key is present and the client stays
/// without device proof material.
pub fn attach_device_dpop(api: CokretApi) -> CokretApi {
    let store = crate::local_state::LocalStateStore::default();
    let Some(handle) = crate::auth_dpop::load_device_key(&store).ok().flatten() else {
        return api;
    };
    let mut api = api.with_dpop_device(handle.clone());
    // Attach the session-grant holder proof (minted from the persisted grant +
    // device key) so the Principal Server's grant introspection passes; without
    // it coauth answers `proof_required` and the grant reads inactive.
    if let Some(grant) = store.session_grant()
        && let Ok(proof) = handle.mint_session_grant_introspection_proof(
            &grant.grant_id,
            &grant.grant_jwt,
            &grant.audience,
        )
    {
        api = api.with_session_grant_proof(proof);
    }
    api
}

/// Derive a lowercase handle string from a DID, suitable for registration.
pub fn handle_from_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .unwrap_or("yougen")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

const SHORT_PROTOCOL_ID_THRESHOLD: usize = 32;

fn shorten_ascii_middle(value: &str, head: usize, tail: usize) -> String {
    let len = value.len();
    if len <= head + tail + 3 {
        return value.to_owned();
    }
    format!("{}...{}", &value[..head], &value[len - tail..])
}

/// Return a compact, display-only label for long protocol identifiers.
///
/// Storage, inputs, copy buttons, routes, and API payloads must keep the
/// canonical value. This helper is intentionally for read-only UI text such
/// as menus, badges, rows, and status labels.
pub fn short_protocol_id(value: impl AsRef<str>) -> String {
    let value = value.as_ref().trim();
    if value.len() <= SHORT_PROTOCOL_ID_THRESHOLD {
        return value.to_owned();
    }

    if let Some((prefix, tail)) = value.rsplit_once(':')
        && tail.len() >= 20
        && prefix.len() <= 20
    {
        return format!("{prefix}:{}", shorten_ascii_middle(tail, 8, 6));
    }

    shorten_ascii_middle(value, 16, 8)
}

/// Persist the current client configuration (server URL, DID, device ID, token).
pub fn persist_config(
    mut config_store: Signal<LocalConfigStore>,
    server_url: String,
    account_did: String,
    device_id: String,
    session_credential: String,
) {
    config_store.write().save(ClientConfig::from_fields(
        server_url,
        account_did,
        device_id,
        session_credential,
    ));
}

pub fn active_sync_token(sync_cursor: impl AsRef<str>) -> Option<String> {
    normalize_wait_for_sync_token(sync_cursor.as_ref())
}

/// Derive the canonical display handle from a DID produced by
/// [`crate::identity_handle::parse_user_handle`].
///
/// This is a display-only fallback for common materialized subject shapes:
/// `did:web:<domain>:users:<localpart>` and
/// `did:webvh:<scid>:<domain>:users:<localpart>`. Verified handle display
/// still comes from signed `ck.schema.handle_claim.v1` evidence or
/// `ck.find.directory.query.list_handles_for_subject`; this helper only keeps UI
/// rows readable while soland's roster handle-claim inline path is still
/// being wired.
pub fn handle_display_from_did(did: &str) -> Option<String> {
    let (without_prefix, method) = did
        .trim()
        .strip_prefix("did:web:")
        .map(|rest| (rest, "web"))
        .or_else(|| {
            did.trim()
                .strip_prefix("did:webvh:")
                .map(|rest| (rest, "webvh"))
        })?;
    let segments = without_prefix.split(':').collect::<Vec<_>>();
    let marker_index = segments
        .iter()
        .position(|segment| matches!(*segment, "users" | "user" | "principals" | "principal"))?;
    let authority_start = if method == "webvh" { 1 } else { 0 };
    if marker_index <= authority_start || marker_index + 2 != segments.len() {
        return None;
    }
    let localpart = segments[marker_index + 1].trim();
    if localpart.is_empty() {
        return None;
    }
    let authority = segments[authority_start..marker_index].join(":");
    let authority = authority.replace("%3A", ":").replace("%3a", ":");
    let candidate = format!("{localpart}:{authority}");
    crate::identity_handle::parse_user_handle(&candidate).map(|handle| handle.display)
}

/// F-REMARK-FANOUT-1: actor-private `local_name` lookup for a DID,
/// reused everywhere yougen would otherwise show a raw `did:web:...`.
///
/// The actor's `ContactRemark` rows arrive via account_data sync
/// (`ck.contacts.actor.<did>`) and live on `LocalStateStore`. Each
/// view used to fall back to the raw DID — this helper centralises the
/// "prefer the user's chosen alias, else the canonical DID" decision so
/// chat headers, @mention popovers, directory rows, verify-device peer
/// labels, and message-author lines stay consistent.
///
/// The `did` argument falls back to a handle-shaped display label when
/// the DID is the materialized form of a Cokret user handle, then to a
/// compact display-only protocol id. Use the original DID for inputs,
/// copies, routes, and protocol payloads.
pub fn display_name_for_did(
    state_store: &crate::local_state::LocalStateStore,
    did: &str,
) -> String {
    if let Some(handle) = handle_display_from_did(did) {
        return handle;
    }
    match state_store.contact_remark(did) {
        Some(remark) => remark.display_name(did).to_owned(),
        None => short_protocol_id(did),
    }
}

/// Reason a view-side API call failed. Roughly mirrors `connect()`'s
/// three-way error split:
///
/// * `Unavailable` — `CokretApi::new` rejected the base URL (bad scheme, parse error, etc.). The
///   session is intact; the user should fix the server URL.
/// * `AuthExpired` — the server returned a terminal session-grant code. The app-wide invalidator
///   has already cleared the session; callers should stop the current flow.
/// * `Failed` — every other error. Caller surfaces to status / last_error so the user sees a
///   retriable reason without losing the session.
#[derive(Debug)]
pub enum ApiCallError {
    Unavailable(anyhow::Error),
    AuthExpired(anyhow::Error),
    Failed(anyhow::Error),
}

impl ApiCallError {
    /// `true` when the error carries an explicit session-death signal
    /// from the server; the caller should wipe its session bundle.
    pub fn is_auth_expired(&self) -> bool {
        matches!(self, Self::AuthExpired(_))
    }

    /// The underlying error, regardless of classification, so callers can run
    /// wire-code predicates (e.g. [`crate::api::is_device_not_authorized_error`])
    /// against it.
    pub fn inner(&self) -> &anyhow::Error {
        match self {
            Self::Unavailable(err) | Self::AuthExpired(err) | Self::Failed(err) => err,
        }
    }

    /// Human-readable rendering suitable for `status` / `last_error`
    /// signals.
    pub fn display(&self) -> String {
        match self {
            Self::Unavailable(err) => format!("API unavailable: {err}"),
            Self::AuthExpired(err) => format!("Session expired: {err}"),
            Self::Failed(err) => format!("{err}"),
        }
    }
}

/// Build an authenticated [`CokretApi`] and pass it to the closure,
/// folding `CokretApi::new` errors + auth-expired errors + generic
/// API errors into a single [`ApiCallError`] so call sites can write:
///
/// ```ignore
/// match with_authed_api(&base, token, |api| async move {
///     api.list_key_backups().await
/// }).await {
///     Ok(value) => status.set(format!("{value}")),
///     Err(e) if e.is_auth_expired() => { /* stop current flow; invalidator owns cleanup */ }
///     Err(e) => last_error.set(Some(e.display())),
/// }
/// ```
///
/// instead of the three-deep nested `match`. Doesn't perform side
/// side effects of its own except terminal session invalidation through
/// `crate::session`, because lower-level helpers cannot own app signals.
pub async fn with_authed_api<F, Fut, T>(
    base_url: &str,
    mut session_credential: String,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(CokretApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    if let Some(refreshed) = crate::session::wait_for_current_session_credential_refresh().await
        && !refreshed.trim().is_empty()
    {
        session_credential = refreshed;
    }
    let api = authed_api(base_url, session_credential).map_err(ApiCallError::Unavailable)?;
    match f(api).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

/// Same as [`with_authed_api`] but also forwards a sync-cursor token to
/// the resulting `CokretApi` so any subsequent read is fenced behind
/// the latest write (read-your-writes consistency). Pass the result of
/// [`active_sync_token`] as `wait_for_sync_token`.
pub async fn with_authed_api_with_sync<F, Fut, T>(
    base_url: &str,
    mut session_credential: String,
    wait_for_sync_token: Option<String>,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(CokretApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if session_credential.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    if let Some(refreshed) = crate::session::wait_for_current_session_credential_refresh().await
        && !refreshed.trim().is_empty()
    {
        session_credential = refreshed;
    }
    let api = authed_api_with_sync(base_url, session_credential, wait_for_sync_token)
        .map_err(ApiCallError::Unavailable)?;
    match f(api).await {
        Ok(value) => Ok(value),
        Err(err) => Err(classify_api_call_error(err).await),
    }
}

async fn classify_api_call_error(err: anyhow::Error) -> ApiCallError {
    if is_terminal_session_grant_error(&err) {
        crate::session::invalidate_current_session("session grant is no longer active");
        return ApiCallError::AuthExpired(err);
    }
    if is_auth_expired_error(&err) {
        // Run the single-flight refresh path so views that ignore the
        // returned error still converge on a fresh token before their next
        // poll. Only the refresh path's terminal result clears the session.
        match crate::session::refresh_current_session().await {
            crate::session::CurrentSessionRefresh::Credential(_) => {
                ApiCallError::Failed(anyhow::anyhow!("session refreshed; retry the operation"))
            }
            crate::session::CurrentSessionRefresh::SignInRequired { reason } => {
                ApiCallError::Failed(anyhow::anyhow!(
                    "session refresh cannot continue locally: {reason}; {err}"
                ))
            }
            crate::session::CurrentSessionRefresh::LoginRequired { reason } => {
                ApiCallError::AuthExpired(anyhow::anyhow!(
                    "session refresh requires login: {reason}; {err}"
                ))
            }
            crate::session::CurrentSessionRefresh::RetryLater { reason } => {
                ApiCallError::Failed(anyhow::anyhow!("session refresh pending: {reason}; {err}"))
            }
        }
    } else {
        ApiCallError::Failed(err)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSelectorMentionToken {
    pub mention_text_original: String,
    pub controller_handle: String,
    pub agent_slug: String,
}

fn normalize_inline_token(token: &str) -> &str {
    token.trim_matches(|ch: char| {
        matches!(
            ch,
            ',' | '.' | '!' | '?' | ':' | ';' | ')' | '(' | '[' | ']' | '"' | '\''
        )
    })
}

pub fn parse_agent_selector_mention_tokens(input: &str) -> Vec<AgentSelectorMentionToken> {
    let mut tokens = Vec::new();
    for token in input.split_whitespace() {
        let normalized = normalize_inline_token(token);
        let Some(rest) = normalized.strip_prefix('@') else {
            continue;
        };
        let Some((controller_handle, agent_slug)) = rest.split_once('/') else {
            continue;
        };
        if controller_handle.is_empty()
            || cokret_sdk::models::validate_agent_slug(agent_slug).is_err()
        {
            continue;
        }
        let Some(parsed) = crate::identity_handle::parse_user_handle(controller_handle) else {
            continue;
        };
        tokens.push(AgentSelectorMentionToken {
            mention_text_original: normalized.to_owned(),
            controller_handle: parsed.handle,
            agent_slug: agent_slug.to_owned(),
        });
    }
    tokens.sort_by(|left, right| {
        left.controller_handle
            .cmp(&right.controller_handle)
            .then(left.agent_slug.cmp(&right.agent_slug))
            .then(left.mention_text_original.cmp(&right.mention_text_original))
    });
    tokens.dedup_by(|left, right| {
        left.controller_handle == right.controller_handle && left.agent_slug == right.agent_slug
    });
    tokens
}

pub fn parse_mention_nodes(input: &str) -> Vec<MentionNode> {
    let mut mentions = Vec::new();
    for token in input.split_whitespace() {
        let normalized = normalize_inline_token(token);
        if let Some(handle) = normalized.strip_prefix('@') {
            if let Some(audience) = cokret_sdk::AudienceMention::from_ui_token(normalized) {
                mentions.push(MentionNode::audience_mention(audience));
                continue;
            }
            if !handle.is_empty()
                && let Some(parsed) = crate::identity_handle::parse_user_handle(handle)
                && let Ok(subject_id) = cokret_sdk::Did::new(parsed.subject_did)
            {
                let mut mention = cokret_sdk::Mention::new(subject_id)
                    .with_display_name_at_time(parsed.display)
                    .with_mention_text_original(normalized.to_owned());
                if let Ok(handle) = cokret_sdk::Handle::parse(&parsed.handle) {
                    mention = mention.with_handle_at_time(handle);
                }
                mentions.push(MentionNode::mention(mention));
            }
        }
    }

    mentions.sort_by(|left, right| {
        left.target_id().cmp(right.target_id()).then(
            left.mention_text_original()
                .cmp(&right.mention_text_original()),
        )
    });
    mentions.dedup_by(|left, right| {
        left.as_mention().is_some() == right.as_mention().is_some()
            && left.target_id() == right.target_id()
    });
    mentions
}

/// R3.2 §3.8.2 — resolved render of an actor mention plus the visual
/// degradation tier the UI MUST surface. Wraps the SDK
/// [`cokret_sdk::MentionRender`] so the chat view can drive a distinct
/// CSS class / badge per fallback level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RenderedMention {
    /// The label to display (`@{localpart}:{domain}` for verified /
    /// cached, the captured display name for name-only, a truncated DID
    /// for unresolved).
    pub label: String,
    /// CSS class capturing the degradation tier — `mention-verified`,
    /// `mention-cached`, `mention-name-only`, `mention-unresolved`.
    pub tier_class: &'static str,
    /// `true` for any non-`Verified` tier — the UI MUST visually mark it
    /// as degraded.
    pub degraded: bool,
}

/// R3.2 §3.8.2 mention render path (YG-MENT-2).
///
/// Resolves the *current* display value for an actor mention by running
/// the shared SDK [`cokret_sdk::render_mention`] helper off the
/// authoritative `subject_id` — it MUST NOT use the audit-only
/// `handle_at_time` / `display_name_at_time` as the current value (those
/// are passed only as the degraded fallback inputs the SDK ladder steps
/// down to).
///
/// Step 1: Realm-scoped projection runs §3.2.1 primary handle selection
/// over `claim_set_snapshot` (the roster handle-claim evidence) +
/// `accepted_issuers` policy. When a verified primary handle wins it is
/// shown as `@{localpart}:{domain}`.
///
/// Step 2 (live `ck.find.directory.query.list_handles_for_subject` resolution) is
/// wired through [`crate::views::helpers::list_handles_for_subject_ui`] /
/// the "Why am I seeing this handle?" panel and feeds the same
/// `claim_set_snapshot` — `TODO(R3.2.1)`: plumb the live result back into
/// this synchronous render call once the directory cache lands.
///
/// Fallback ladder (each visually degraded): local cached verified handle
/// → `display_name_at_time` → truncated DID.
pub fn render_actor_mention(
    subject_id: &str,
    claim_set_snapshot: &[cokret_sdk::models::HandleClaim],
    accepted_issuers: &[String],
    context: Option<&str>,
    cached_handle: Option<&cokret_sdk::Handle>,
    display_name_at_time: Option<&str>,
) -> RenderedMention {
    use cokret_sdk::Did;
    use cokret_sdk::identity::{MentionRender, PrimaryHandleSelectInput, render_mention};

    // A malformed subject_id can't be resolved; fall straight to the
    // unresolved tier with a truncated form of the raw string.
    let Ok(subject) = Did::new(subject_id.to_owned()) else {
        return RenderedMention {
            label: short_protocol_id(subject_id),
            tier_class: "mention-unresolved",
            degraded: true,
        };
    };

    let selection = PrimaryHandleSelectInput {
        subject_id: subject.as_str(),
        context,
        claim_set_snapshot,
        accepted_issuers,
        // TODO(R3.2.1): resolve `metadata.primary_handle` at as_of via a
        // DID Document snapshot resolver (NoHolderPreferenceResolver
        // until the resolver is wired).
        holder_primary_handle_at_as_of: None,
        resolution_as_of: chrono::Utc::now(),
    };

    match render_mention(&subject, &selection, cached_handle, display_name_at_time) {
        MentionRender::Verified { handle } => RenderedMention {
            label: format!("@{}", handle.canonical()),
            tier_class: "mention-verified",
            degraded: false,
        },
        MentionRender::Cached { handle } => RenderedMention {
            label: format!("@{}", handle.canonical()),
            tier_class: "mention-cached",
            degraded: true,
        },
        MentionRender::NameOnly { name } => RenderedMention {
            label: name,
            tier_class: "mention-name-only",
            degraded: true,
        },
        MentionRender::Unresolved { truncated_did } => RenderedMention {
            label: truncated_did,
            tier_class: "mention-unresolved",
            degraded: true,
        },
    }
}

/// R3.2 (YG-DIR-1/2) — one row in the "Why am I seeing this handle?"
/// transparency panel. Flattens the audit-relevant fields of a signed
/// `ck.schema.handle_claim.v1` into display strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleClaimRow {
    pub handle: String,
    pub issuer: String,
    pub binding_state: String,
    pub created_at: String,
    pub expires_at: String,
    pub claim_digest: String,
    pub is_primary: bool,
}

/// Project a directory `list_handles_for_subject` response into display
/// rows (YG-DIR-2). The primary handle (per §3.2.1, computed server-side
/// and echoed in `primary_handle`) is flagged so the UI can mark it.
pub fn handle_claim_rows(
    res: &cokret_sdk::models::DirectorySubjectHandleList,
) -> Vec<HandleClaimRow> {
    let primary = res
        .primary_handle
        .as_ref()
        .map(|h| h.canonical().to_owned());
    res.claims
        .iter()
        .map(|claim| {
            let handle = claim
                .handle
                .as_ref()
                .map(|h| h.canonical().to_owned())
                .unwrap_or_default();
            let digest = cokret_sdk::identity::claim_digest(claim).unwrap_or_default();
            HandleClaimRow {
                is_primary: primary.as_deref() == Some(handle.as_str()) && !handle.is_empty(),
                handle,
                issuer: claim
                    .issuer
                    .clone()
                    .unwrap_or_else(|| "(unknown)".to_owned()),
                binding_state: claim
                    .binding_state
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_else(|| "(unset)".to_owned()),
                created_at: claim.created_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                expires_at: claim.expires_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                claim_digest: digest,
            }
        })
        .collect()
}

/// R3.2 (YG-DIR-1/2) — "Why am I seeing this handle?" transparency
/// panel. Given a subject (principal) DID it calls the directory
/// `ck.find.directory.query.list_handles_for_subject` op and renders the visible
/// signed handle claims (issuer / binding_state / created_at / expiry /
/// claim_digest) plus the §3.2.1 primary handle. This is the user-facing
/// disclosure surface mandated by §3.8 — handles are never authoritative
/// roster fields, so the user gets to see the signed evidence behind a
/// displayed handle.
#[component]
pub fn WhyThisHandlePanel(
    base_url: String,
    token: String,
    subject_id: String,
    /// Optional Realm id to scope disclosure policy.
    #[props(default)]
    realm_id: Option<String>,
) -> Element {
    let mut rows = use_signal(Vec::<HandleClaimRow>::new);
    let mut primary = use_signal(|| Option::<String>::None);
    let mut status = use_signal(String::new);
    let mut loaded = use_signal(|| false);

    let on_load = {
        let base_url = base_url.clone();
        let token = token.clone();
        let subject_id = subject_id.clone();
        let realm_id = realm_id.clone();
        move |_| {
            let base_url = base_url.clone();
            let token = token.clone();
            let subject_id = subject_id.clone();
            let realm_id = realm_id.clone();
            spawn(async move {
                status.set("Resolving visible handle claims…".to_owned());
                match with_authed_api(&base_url, token, move |api| async move {
                    api.list_handles_for_subject(&subject_id, realm_id.as_deref(), Some("display"))
                        .await
                })
                .await
                {
                    Ok(res) => {
                        primary.set(
                            res.primary_handle
                                .as_ref()
                                .map(|h| h.canonical().to_owned()),
                        );
                        let projected = handle_claim_rows(&res);
                        let count = projected.len();
                        rows.set(projected);
                        loaded.set(true);
                        status.set(format!("{count} visible handle claim(s)"));
                    }
                    Err(err) => status.set(err.display()),
                }
            });
        }
    };

    rsx! {
        div { class: "why-this-handle", "data-testid": "why-this-handle-panel",
            div { class: "why-this-handle-head",
                strong { "Why am I seeing this handle?" }
                span { class: "muted", "ck.find.directory.query.list_handles_for_subject" }
            }
            div { class: "muted",
                "Handles are not authoritative roster fields — they come from signed "
                code { "ck.schema.handle_claim.v1" }
                " evidence. This shows the claims visible to you and the §3.2.1 primary handle."
            }
            Button {
                variant: ButtonVariant::Secondary,
                "data-testid": "why-this-handle-load",
                onclick: on_load,
                "Show visible handle claims"
            }
            if let Some(p) = primary() {
                div { class: "why-this-handle-primary", "data-testid": "why-this-handle-primary",
                    strong { "Primary handle: " }
                    span { "@{p}" }
                }
            }
            if loaded() {
                ul { class: "handle-claim-list", "data-testid": "handle-claim-list",
                    for row in rows() {
                        li {
                            class: if row.is_primary { "handle-claim-row primary" } else { "handle-claim-row" },
                            "data-testid": "handle-claim-row",
                            div { class: "handle-claim-handle",
                                "@{row.handle}"
                                if row.is_primary {
                                    span { class: "badge", "primary" }
                                }
                            }
                            div { class: "muted",
                                "issuer: {row.issuer} · state: {row.binding_state}"
                            }
                            div { class: "muted",
                                "created: {row.created_at} · expires: {row.expires_at}"
                            }
                            div { class: "muted handle-claim-digest", "digest: {row.claim_digest}" }
                        }
                    }
                }
            }
            if !status().is_empty() {
                div { class: "muted", "data-testid": "why-this-handle-status", "{status}" }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actor_mentions_without_entity_references() {
        let mentions = parse_mention_nodes(
            "ping @did:web:bob.example and @Alice and @carol:example.com about #ck:task:123 and #topic-demo",
        );

        assert_eq!(mentions.len(), 1);
        assert!(
            !mentions
                .iter()
                .any(|mention| mention.mention_text_original() == Some("@Alice"))
        );
        assert!(
            !mentions
                .iter()
                .any(|mention| mention.mention_text_original() == Some("@did:web:bob.example"))
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target_id() == "did:web:example.com:users:carol")
        );
    }

    #[test]
    fn parses_audience_mentions_without_presence_online() {
        let mentions = parse_mention_nodes("notify @here and @all but never @online");

        assert!(mentions.iter().any(|mention| {
            mention.as_audience_mention().is_some_and(|mention| {
                mention.audience == cokret_sdk::AudienceMentionAudience::StrandEngaged
            })
        }));
        assert!(mentions.iter().any(|mention| {
            mention.as_audience_mention().is_some_and(|mention| {
                mention.audience == cokret_sdk::AudienceMentionAudience::EffectiveScopeMembers
            })
        }));
        assert!(
            !mentions
                .iter()
                .any(|mention| mention.mention_text_original() == Some("@online"))
        );
    }

    #[test]
    fn parses_agent_selector_tokens_without_materializing_mentions() {
        let tokens =
            parse_agent_selector_mention_tokens("ask @alice:example.com/summary, not @bob:Bad");
        assert_eq!(tokens.len(), 1);
        assert_eq!(
            tokens[0].mention_text_original,
            "@alice:example.com/summary"
        );
        assert_eq!(tokens[0].controller_handle, "alice:example.com");
        assert_eq!(tokens[0].agent_slug, "summary");

        let mentions = parse_mention_nodes("ask @alice:example.com/summary");
        assert!(mentions.is_empty());
    }

    #[test]
    fn render_actor_mention_runs_3_2_1_for_verified_handle() {
        use cokret_sdk::Handle;
        use cokret_sdk::models::{HandleBindingState, HandleClaim};
        let now = chrono::Utc::now();
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:acme.example").unwrap()),
            subject: Some(
                cokret_sdk::Did::new("did:web:acme.example:principals:alice".to_owned()).unwrap(),
            ),
            issuer: Some("did:web:issuer.acme.example".to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            created_at: Some(now - chrono::Duration::hours(1)),
            expires_at: Some(now + chrono::Duration::days(30)),
            ..Default::default()
        };
        let accepted = vec!["did:web:issuer.acme.example".to_owned()];
        let rendered = render_actor_mention(
            "did:web:acme.example:principals:alice",
            &[claim],
            &accepted,
            None,
            None,
            Some("Alice (stale)"),
        );
        // §3.2.1 wins → verified tier, NOT the audit display name.
        assert_eq!(rendered.label, "@alice:acme.example");
        assert_eq!(rendered.tier_class, "mention-verified");
        assert!(!rendered.degraded);
    }

    #[test]
    fn render_actor_mention_falls_back_to_name_then_did() {
        // No claims → degraded ladder. display_name_at_time is the
        // name-only fallback (audit metadata used ONLY as fallback).
        let name_only = render_actor_mention(
            "did:web:acme.example:principals:bob",
            &[],
            &[],
            None,
            None,
            Some("Bob"),
        );
        assert_eq!(name_only.label, "Bob");
        assert_eq!(name_only.tier_class, "mention-name-only");
        assert!(name_only.degraded);

        // Nothing at all → unresolved (truncated DID).
        let unresolved = render_actor_mention(
            "did:web:acme.example:principals:bob",
            &[],
            &[],
            None,
            None,
            None,
        );
        assert_eq!(unresolved.tier_class, "mention-unresolved");
        assert!(unresolved.degraded);
    }

    #[test]
    fn handle_claim_rows_flags_primary_and_projects_fields() {
        use cokret_sdk::Handle;
        use cokret_sdk::models::{DirectorySubjectHandleList, HandleBindingState, HandleClaim};
        let now = chrono::Utc::now();
        let subject =
            cokret_sdk::Did::new("did:web:acme.example:principals:alice".to_owned()).unwrap();
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:acme.example").unwrap()),
            subject: Some(subject.clone()),
            issuer: Some("did:web:issuer.acme.example".to_owned()),
            binding_state: Some(HandleBindingState::Verified),
            created_at: Some(now),
            expires_at: Some(now + chrono::Duration::days(30)),
            ..Default::default()
        };
        let res = DirectorySubjectHandleList {
            subject,
            claims: vec![claim],
            primary_handle: Some(Handle::parse("alice:acme.example").unwrap()),
            as_of: now,
            next_cursor: None,
            has_more: false,
        };
        // validator passes (claim.subject == response.subject).
        res.validate().unwrap();
        let rows = handle_claim_rows(&res);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].handle, "alice:acme.example");
        assert_eq!(rows[0].issuer, "did:web:issuer.acme.example");
        assert_eq!(rows[0].binding_state, "verified");
        assert!(rows[0].is_primary);
        assert!(rows[0].claim_digest.starts_with("sha256:"));
    }

    #[test]
    fn render_actor_mention_uses_local_cache_before_name() {
        use cokret_sdk::Handle;
        let cached = Handle::parse("bob:acme.example").unwrap();
        let rendered = render_actor_mention(
            "did:web:acme.example:principals:bob",
            &[],
            &[],
            None,
            Some(&cached),
            Some("Bob"),
        );
        assert_eq!(rendered.label, "@bob:acme.example");
        assert_eq!(rendered.tier_class, "mention-cached");
        assert!(rendered.degraded);
    }

    #[test]
    fn short_protocol_id_keeps_short_values_readable() {
        assert_eq!(
            short_protocol_id("did:web:alice.example"),
            "did:web:alice.example"
        );
    }

    #[test]
    fn short_protocol_id_compacts_typed_uuid_tail() {
        assert_eq!(
            short_protocol_id("ck:space:0196419b-0000-7000-8000-000000000000"),
            "ck:space:0196419b...000000"
        );
    }

    #[test]
    fn short_protocol_id_compacts_long_did_without_a_long_tail() {
        assert_eq!(
            short_protocol_id("did:web:auth.local.host:users:01KCANONICAL"),
            "did:web:auth.loc...ANONICAL"
        );
    }

    #[test]
    fn handle_display_from_did_recovers_materialized_user_handle() {
        assert_eq!(
            handle_display_from_did("did:web:acme.example:users:alice").as_deref(),
            Some("alice:acme.example")
        );
        assert_eq!(
            handle_display_from_did("did:web:acme.example%3A8443:users:bob").as_deref(),
            Some("bob:acme.example:8443")
        );
        assert_eq!(
            handle_display_from_did("did:webvh:zQmScid:acme.example:users:carol").as_deref(),
            Some("carol:acme.example")
        );
        assert!(handle_display_from_did("did:web:alice.example").is_none());
        assert!(handle_display_from_did("did:webvh:zQmScid:acme.example").is_none());
    }
}
