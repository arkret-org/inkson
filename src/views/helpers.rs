use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    api::{ContrixApi, is_auth_expired_error, normalize_wait_for_sync_token},
    config::{ClientConfig, LocalConfigStore},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMention {
    pub kind: String,
    pub target: String,
    pub token: String,
    /// T7.3: compose-time label captured alongside the mention. Spec
    /// `flow-and-message.md §9.4`. Defaults to the empty string for
    /// mentions parsed from typed draft text where we don't yet have
    /// a resolved snapshot.
    #[serde(default)]
    pub display_snapshot: String,
    /// T7.3: original handle URI as typed by the author (e.g.
    /// `contrix://example.com/users/alice`). Empty when only a DID was supplied.
    #[serde(default)]
    pub handle_uri: String,
    /// T7.3: ISO-8601 timestamp the mention was resolved at compose
    /// time. Empty when the resolver didn't supply it.
    #[serde(default)]
    pub resolved_at: String,
}

/// Create an authenticated API client from a base URL and optional access token.
pub fn authed_api(base_url: &str, access_token: String) -> anyhow::Result<ContrixApi> {
    authed_api_with_sync(base_url, access_token, None)
}

/// Create an authenticated API client that also forwards the latest sync token
/// for read-your-writes consistency on subsequent reads.
pub fn authed_api_with_sync(
    base_url: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
) -> anyhow::Result<ContrixApi> {
    let mut api = ContrixApi::new(base_url)?;
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

    if let Some((prefix, tail)) = value.rsplit_once(':') {
        if tail.len() >= 20 && prefix.len() <= 20 {
            return format!("{prefix}:{}", shorten_ascii_middle(tail, 8, 6));
        }
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
/// The `did` argument falls back to a compact display-only label when no
/// remark / no `local_name` is set. Use the original DID for inputs, copies,
/// routes, and protocol payloads.
pub fn display_name_for_did(
    state_store: &crate::local_state::LocalStateStore,
    did: &str,
) -> String {
    match state_store.contact_remark(did) {
        Some(remark) => remark.display_name(did).to_owned(),
        None => short_protocol_id(did),
    }
}

/// Reason a view-side API call failed. Roughly mirrors `connect()`'s
/// three-way error split:
///
/// * `Unavailable` — `ContrixApi::new` rejected the base URL (bad
///   scheme, parse error, etc.). The session is intact; the user
///   should fix the server URL.
/// * `AuthExpired` — the server returned a definitive session-death
///   code (per [`is_auth_expired_error`]). The caller MUST clear the
///   session and bounce to login, exactly as the connect path does.
/// * `Failed` — every other error. Caller surfaces to status / last_error
///   so the user sees a retriable reason without losing the session.
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

/// Build an authenticated [`ContrixApi`] and pass it to the closure,
/// folding `ContrixApi::new` errors + auth-expired errors + generic
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
    F: FnOnce(ContrixApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let api = authed_api(base_url, access_token).map_err(ApiCallError::Unavailable)?;
    f(api).await.map_err(|err| {
        if is_auth_expired_error(&err) {
            ApiCallError::AuthExpired(err)
        } else {
            ApiCallError::Failed(err)
        }
    })
}

/// Same as [`with_authed_api`] but also forwards a sync-cursor token to
/// the resulting `ContrixApi` so any subsequent read is fenced behind
/// the latest write (read-your-writes consistency). Pass the result of
/// [`active_sync_token`] as `wait_for_sync_token`.
pub async fn with_authed_api_with_sync<F, Fut, T>(
    base_url: &str,
    access_token: String,
    wait_for_sync_token: Option<String>,
    f: F,
) -> Result<T, ApiCallError>
where
    F: FnOnce(ContrixApi) -> Fut,
    Fut: std::future::Future<Output = anyhow::Result<T>>,
{
    let api = authed_api_with_sync(base_url, access_token, wait_for_sync_token)
        .map_err(ApiCallError::Unavailable)?;
    f(api).await.map_err(|err| {
        if is_auth_expired_error(&err) {
            ApiCallError::AuthExpired(err)
        } else {
            ApiCallError::Failed(err)
        }
    })
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
            if !handle.is_empty() {
                if let Some(parsed) = crate::identity_handle::parse_user_handle(handle) {
                    mentions.push(StructuredMention {
                        kind: "actor".to_owned(),
                        target: parsed.subject_did,
                        token: normalized.to_owned(),
                        display_snapshot: parsed.display,
                        handle_uri: parsed.handle_uri,
                        resolved_at: String::new(),
                    });
                }
            }
            continue;
        }
        if let Some(entity) = normalized.strip_prefix("#cx:") {
            mentions.push(StructuredMention {
                kind: "entity".to_owned(),
                target: format!("cx:{entity}"),
                token: normalized.to_owned(),
                display_snapshot: String::new(),
                handle_uri: String::new(),
                resolved_at: String::new(),
            });
            continue;
        }
        if let Some(entity) = normalized.strip_prefix('#') {
            if !entity.is_empty() {
                mentions.push(StructuredMention {
                    kind: "entity".to_owned(),
                    target: entity.to_owned(),
                    token: normalized.to_owned(),
                    display_snapshot: String::new(),
                    handle_uri: String::new(),
                    resolved_at: String::new(),
                });
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actor_and_entity_mentions() {
        let mentions = parse_structured_mentions(
            "ping @did:web:bob.example and @Alice and @carol:example.com about #cx:task:123 and #topic-demo",
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
                .any(|mention| mention.target == "cx:task:123")
        );
        assert!(
            mentions
                .iter()
                .any(|mention| mention.target == "topic-demo")
        );
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
            short_protocol_id("cx:space:0196419b-0000-7000-8000-000000000000"),
            "cx:space:0196419b...000000"
        );
    }

    #[test]
    fn short_protocol_id_compacts_long_did_without_a_long_tail() {
        assert_eq!(
            short_protocol_id("did:web:auth.local.host:users:01KCANONICAL"),
            "did:web:auth.loc...ANONICAL"
        );
    }
}
