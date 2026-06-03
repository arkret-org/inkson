use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::api::{
    CokretApi, is_auth_expired_error, is_terminal_session_grant_error,
    normalize_wait_for_sync_token,
};
use crate::config::{ClientConfig, LocalConfigStore};

/// R3.2 (cokret-spec @ b56cab1) — composer/render-side mention node.
///
/// `target` carries the authoritative reference: for `kind == "actor"`
/// it is the principal DID (`subject_id` in spec terms — the ONLY field
/// used for actor attribution / resolution / render lookup); for entity
/// references it is the `ck:...` id. The remaining fields are compose-time
/// audit metadata ONLY and MUST NOT drive the current display value:
/// the render path runs §3.2.1 / the SDK `render_mention()` helper off
/// `target` instead. See [`crate::views::helpers::render_actor_mention`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMention {
    pub kind: String,
    /// Authoritative reference. For actor mentions this is the principal
    /// DID (`subject_id`); for entities the `ck:` id; for audience
    /// mentions the canonical audience token.
    #[serde(alias = "subject_id")]
    pub target: String,
    pub token: String,
    /// R3.2 audit-only: subject display name captured at compose time
    /// (`display_name_at_time`). Renamed from the pre-R3.2
    /// `display_snapshot`. NEVER the current display value. Empty when
    /// no snapshot was captured.
    #[serde(default)]
    pub display_name_at_time: String,
    /// R3.2 audit-only: canonical handle `<localpart>:<domain>` at compose
    /// time (`handle_at_time`). Renamed from the pre-R3.2 `handle`. NEVER
    /// the current display value — resolution runs §3.2.1 live. Empty when
    /// only a DID was supplied.
    #[serde(default)]
    pub handle_at_time: String,
    /// R3.2 audit-only: the original string the user typed
    /// (`mention_text_original`, e.g. `@alice:acme.com`).
    #[serde(default)]
    pub mention_text_original: String,
    /// Audit-only ISO-8601 timestamp the mention was resolved at compose
    /// time. Empty when the resolver didn't supply it.
    #[serde(default)]
    pub resolved_at: String,
}

fn audience_mention_audience_from_token(token: &str) -> Option<&'static str> {
    match token.trim().to_ascii_lowercase().as_str() {
        "@all" => Some("effective_scope_members"),
        "@participants" => Some("flow_participants"),
        "@watchers" => Some("flow_watchers"),
        "@here" => Some("flow_engaged"),
        "@assigned" | "@assignees" => Some("assigned_actors"),
        _ => None,
    }
}

/// Create an authenticated API client from a base URL and optional access token.
pub fn authed_api(base_url: &str, access_token: String) -> anyhow::Result<CokretApi> {
    authed_api_with_sync(base_url, access_token, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
pub fn authed_api_with_sync(
    base_url: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<CokretApi> {
    let mut api = CokretApi::new(base_url)?;
    if !access_token.is_empty() {
        api = api.with_bearer(access_token);
    }
    if let Some(sync_token) = wait_for_sync_token {
        api = api.with_wait_for(sync_token);
    }
    Ok(api)
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
    session_token: String,
) {
    config_store.write().save(ClientConfig::from_fields(
        server_url,
        account_did,
        device_id,
        session_token,
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
/// still comes from signed `cx.schema.handle_claim.v1` evidence or
/// `cx.directory.list_handles_for_subject`; this helper only keeps UI
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
/// (`cx.contacts.actor.<did>`) and live on `LocalStateStore`. Each
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
/// * `AuthExpired` — the server returned a definitive session-death code (per
///   [`is_auth_expired_error`]). The caller MUST clear the session and bounce to login, exactly as
///   the connect path does.
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
///     Err(e) if e.is_auth_expired() => { /* redirect_to_login */ }
///     Err(e) => last_error.set(Some(e.display())),
/// }
/// ```
///
/// instead of the three-deep nested `match`. Doesn't perform side
/// effects of its own — auth-expired cleanup (token reset, navigator
/// redirect) stays with the caller because those signals live in the
/// surrounding component scope.
pub async fn with_authed_api<F, Fut, T>(
    base_url: &str,
    access_token: String,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(CokretApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if access_token.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    let api = authed_api(base_url, access_token).map_err(ApiCallError::Unavailable)?;
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
    access_token: String,
    wait_for_sync_token: Option<String>,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(CokretApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    if access_token.trim().is_empty() {
        return Err(ApiCallError::AuthExpired(anyhow::anyhow!(
            "missing authenticated session"
        )));
    }
    let api = authed_api_with_sync(base_url, access_token, wait_for_sync_token)
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
        // Run the single-flight remint path so views that ignore the
        // returned AuthExpired error still converge on a fresh token (or
        // a cleared session on terminal failure) before their next poll.
        let _ = crate::session::refresh_current_bearer().await;
        ApiCallError::AuthExpired(err)
    } else {
        ApiCallError::Failed(err)
    }
}

pub fn parse_structured_mentions(input: &str) -> Vec<StructuredMention> {
    let mut mentions = Vec::new();
    for token in input.split_whitespace() {
        let normalized = token.trim_matches(|ch: char| {
            matches!(
                ch,
                ',' | '.' | '!' | '?' | ':' | ';' | ')' | '(' | '[' | ']' | '"' | '\''
            )
        });
        if let Some(handle) = normalized.strip_prefix('@') {
            if let Some(audience) = audience_mention_audience_from_token(normalized) {
                mentions.push(StructuredMention {
                    kind: "audience_mention".to_owned(),
                    target: audience.to_owned(),
                    token: normalized.to_owned(),
                    display_name_at_time: String::new(),
                    handle_at_time: String::new(),
                    mention_text_original: normalized.to_owned(),
                    resolved_at: String::new(),
                });
                continue;
            }
            if !handle.is_empty()
                && let Some(parsed) = crate::identity_handle::parse_user_handle(handle)
            {
                mentions.push(StructuredMention {
                    kind: "actor".to_owned(),
                    // Authoritative subject_id (principal DID).
                    target: parsed.subject_did,
                    token: normalized.to_owned(),
                    display_name_at_time: parsed.display,
                    handle_at_time: parsed.handle,
                    mention_text_original: normalized.to_owned(),
                    resolved_at: String::new(),
                });
            }
            continue;
        }
        if let Some(entity) = normalized.strip_prefix("#ck:") {
            mentions.push(StructuredMention {
                kind: "entity".to_owned(),
                target: format!("ck:{entity}"),
                token: normalized.to_owned(),
                display_name_at_time: String::new(),
                handle_at_time: String::new(),
                mention_text_original: normalized.to_owned(),
                resolved_at: String::new(),
            });
            continue;
        }
        if let Some(entity) = normalized.strip_prefix('#')
            && !entity.is_empty()
        {
            mentions.push(StructuredMention {
                kind: "entity".to_owned(),
                target: entity.to_owned(),
                token: normalized.to_owned(),
                display_name_at_time: String::new(),
                handle_at_time: String::new(),
                mention_text_original: normalized.to_owned(),
                resolved_at: String::new(),
            });
        }
    }

    mentions.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then(left.token.cmp(&right.token))
    });
    mentions.dedup_by(|left, right| left.kind == right.kind && left.target == right.target);
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
/// Step 2 (live `cx.directory.list_handles_for_subject` resolution) is
/// wired through [`crate::views::helpers::list_handles_for_subject_ui`] /
/// the "Why am I seeing this handle?" panel and feeds the same
/// `claim_set_snapshot` — `TODO(R3.2.1)`: plumb the live result back into
/// this synchronous render call once the directory cache lands.
///
/// Fallback ladder (each visually degraded): local cached verified handle
/// → `display_name_at_time` → truncated DID.
pub fn render_actor_mention(
    subject_id: &str,
    claim_set_snapshot: &[cokret_sdk::model::HandleClaim],
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
        subject_id: &subject,
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
/// `cx.schema.handle_claim.v1` into display strings.
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
    res: &cokret_sdk::model::DirectoryListHandlesForSubjectResBody,
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
/// `cx.directory.list_handles_for_subject` op and renders the visible
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
                span { class: "muted", "cx.directory.list_handles_for_subject" }
            }
            div { class: "muted",
                "Handles are not authoritative roster fields — they come from signed "
                code { "cx.schema.handle_claim.v1" }
                " evidence. This shows the claims visible to you and the §3.2.1 primary handle."
            }
            button {
                class: "secondary",
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
    fn parses_actor_and_entity_mentions() {
        let mentions = parse_structured_mentions(
            "ping @did:web:bob.example and @Alice and @carol:example.com about #ck:task:123 and #topic-demo",
        );

        assert_eq!(mentions.len(), 3);
        assert!(!mentions.iter().any(|mention| mention.token == "@Alice"));
        assert!(
            !mentions
                .iter()
                .any(|mention| mention.token == "@did:web:bob.example")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "did:web:example.com:users:carol")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "ck:task:123")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "topic-demo")
        );
    }

    #[test]
    fn parses_audience_mentions_without_presence_online() {
        let mentions = parse_structured_mentions("notify @here and @all but never @online");

        assert!(mentions.iter().any(|mention| {
            mention.kind == "audience_mention" && mention.target == "flow_engaged"
        }));
        assert!(mentions.iter().any(|mention| {
            mention.kind == "audience_mention" && mention.target == "effective_scope_members"
        }));
        assert!(!mentions.iter().any(|mention| mention.token == "@online"));
    }

    #[test]
    fn render_actor_mention_runs_3_2_1_for_verified_handle() {
        use cokret_sdk::Handle;
        use cokret_sdk::model::{HandleBindingState, HandleClaim};
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
        use cokret_sdk::model::{
            DirectoryListHandlesForSubjectResBody, HandleBindingState, HandleClaim,
        };
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
        let res = DirectoryListHandlesForSubjectResBody {
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
