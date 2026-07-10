pub use arkret_sdk::MentionNode;
use dioxus::prelude::*;

use crate::api_error::normalize_wait_for_sync_token;
// YGN-ARCH-01 step 1: the authenticated-client builders (`authed_api*`,
// `with_authed_api*`, `ApiCallError`, DPoP attach) moved to
// `crate::api::authed` so the core layers (sync_engine / bootstrap / mls)
// no longer import a views module for their HTTP exit. Re-exported here so
// every existing `crate::views::helpers::…` call site keeps resolving.
pub use crate::authed_api::{
    ApiCallError, attach_device_dpop, authed_api, authed_api_with_sync, with_authed_api,
    with_authed_api_with_sync, with_authed_sdk_client, with_event_submitter,
};
use crate::config::{ClientConfig, LocalConfigStore};
use crate::ui::button::{Button, ButtonVariant};

/// Derive a lowercase handle string from a DID, suitable for registration.
pub fn handle_from_did(did: &str) -> String {
    did.rsplit(':')
        .next()
        .unwrap_or("inkson")
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

// Single source in yoface (YGN-ARCH-01 step 3: the projection layer needs
// this label formatter without importing a views module). Re-exported so all
// existing `views::helpers::short_protocol_id` call sites keep resolving.
pub use yoface::utils::text::short_protocol_id;

fn first_alphanumeric_upper(value: &str) -> Option<String> {
    value
        .chars()
        .find(|ch| ch.is_alphanumeric())
        .map(|ch| ch.to_uppercase().collect::<String>())
}

fn generic_avatar_seed(seed: &str) -> bool {
    matches!(
        seed.trim().to_ascii_lowercase().as_str(),
        "account"
            | "accounts"
            | "admin"
            | "auth"
            | "identity"
            | "issuer"
            | "oauth"
            | "operator"
            | "org"
            | "organization"
            | "realm"
            | "server"
            | "service"
            | "workspace"
    )
}

fn handle_avatar_seed(value: &str) -> Option<String> {
    if let Some(handle) = crate::identity_handle::parse_user_handle(value) {
        return Some(handle.localpart);
    }
    let trimmed = value.trim().trim_start_matches('@').trim();
    if trimmed.is_empty()
        || trimmed.starts_with("did:")
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.contains('/')
    {
        return None;
    }
    Some(
        trimmed
            .split([':', '@'])
            .next()
            .unwrap_or(trimmed)
            .to_owned(),
    )
}

/// Best-effort, **display-only** check of whether `handle` plausibly names the
/// same principal as the authoritative `identity` DID, used purely to pick a
/// stable avatar seed. This does NOT materialise the handle into a DID (that
/// would fabricate a non-attested `did:web` identifier — see
/// `identity_handle`): it compares the handle's localpart/domain against the
/// segments embedded in a materialised user DID (`…:users:<localpart>` under
/// `did:web:<domain>` / `did:webvh:<scid>:<domain>`). Identities whose DID does
/// not embed the handle shape simply don't match and fall through to the other
/// avatar-seed heuristics.
fn handle_matches_identity(handle: &str, identity: &str) -> bool {
    let Some(parsed) = crate::identity_handle::parse_user_handle(handle) else {
        return false;
    };
    let Some(display) = handle_display_from_did(identity) else {
        return false;
    };
    crate::identity_handle::parse_user_handle(&display)
        .is_some_and(|materialised| materialised.handle == parsed.handle)
}

fn materialized_did_avatar_seed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Some(display) = handle_display_from_did(trimmed) {
        return handle_avatar_seed(&display);
    }
    let without_prefix = trimmed
        .strip_prefix("did:web:")
        .or_else(|| trimmed.strip_prefix("did:webvh:"))?;
    let segments = without_prefix.split(':').collect::<Vec<_>>();
    let marker_index = segments
        .iter()
        .position(|segment| matches!(*segment, "users" | "user" | "principals" | "principal"))?;
    let localpart = segments.get(marker_index + 1)?.trim();
    (!localpart.is_empty()).then(|| localpart.to_owned())
}

fn protocol_tail_avatar_seed(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !trimmed.starts_with("did:") {
        return None;
    }
    trimmed
        .rsplit(':')
        .next()
        .map(str::trim)
        .filter(|tail| !tail.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn avatar_seed_from_identity_value(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_start_matches('@').trim();
    if trimmed.is_empty() {
        return None;
    }
    handle_avatar_seed(trimmed)
        .or_else(|| materialized_did_avatar_seed(trimmed))
        .or_else(|| protocol_tail_avatar_seed(trimmed))
        .or_else(|| Some(trimmed.to_owned()))
}

pub(crate) fn identity_avatar_seed(handles: &[String], identity_id: &str) -> String {
    let identity = identity_id.trim();
    for handle in handles {
        if handle_matches_identity(handle, identity)
            && let Some(seed) = handle_avatar_seed(handle)
        {
            return seed;
        }
    }
    if let Some(seed) = materialized_did_avatar_seed(identity) {
        return seed;
    }
    if let Some(seed) = handles
        .iter()
        .filter_map(|handle| handle_avatar_seed(handle))
        .find(|seed| !generic_avatar_seed(seed))
    {
        return seed;
    }
    if let Some(seed) = protocol_tail_avatar_seed(identity) {
        return seed;
    }
    if let Some(seed) = handles.iter().find_map(|handle| handle_avatar_seed(handle)) {
        return seed;
    }
    avatar_seed_from_identity_value(identity).unwrap_or_default()
}

pub(crate) fn identity_avatar_initial(handles: &[String], identity_id: &str) -> String {
    first_alphanumeric_upper(&identity_avatar_seed(handles, identity_id))
        .unwrap_or_else(|| "?".to_owned())
}

pub(crate) fn avatar_initial_from_identity_value(value: &str) -> Option<String> {
    avatar_seed_from_identity_value(value).and_then(|seed| first_alphanumeric_upper(&seed))
}

pub(crate) fn identity_avatar_tone(handles: &[String], identity_id: &str) -> usize {
    let seed = identity_avatar_seed(handles, identity_id);
    let hash_input = if seed.trim().is_empty() {
        identity_id.trim()
    } else {
        seed.trim()
    };
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in hash_input.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    (hash as usize % 6) + 1
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
/// reused everywhere inkson would otherwise show a raw `did:web:...`.
///
/// The actor's `ContactRemark` rows arrive via account_data sync
/// (`ck.contacts.actor.<did>`) and live on `LocalStateStore`. Each
/// view used to fall back to the raw DID — this helper centralises the
/// "prefer the user's chosen alias, else the canonical DID" decision so
/// chat headers, @mention popovers, directory rows, verify-device peer
/// labels, and message-author lines stay consistent.
///
/// The `did` argument falls back to a handle-shaped display label when
/// the DID is the materialized form of a Arkret user handle, then to a
/// compact display-only protocol id. Use the original DID for inputs,
/// copies, routes, and protocol payloads.
pub fn display_name_for_did(
    state_store: &crate::local_state::LocalStateStore,
    did: &str,
) -> String {
    if let Some(handle) = state_store
        .cached_member_handle_lookup(did, None, None)
        .and_then(|entry| entry.primary_handle)
        .and_then(|handle| crate::identity_handle::parse_user_handle(&handle).map(|h| h.display))
    {
        return handle;
    }
    if let Some(handle) = handle_display_from_did(did) {
        return handle;
    }
    match state_store.contact_remark(did) {
        Some(remark) => remark.display_name(did).to_owned(),
        None => short_protocol_id(did),
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
            || arkret_sdk::models::validate_agent_slug(agent_slug).is_err()
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

/// Parse audience tokens (`@here` / `@all` / …) from raw message text into
/// structured [`MentionNode::AudienceMention`] entries.
///
/// Typed actor handles (`@alice:example.com`) are intentionally NOT
/// materialised into [`MentionNode::Mention`] here: a `Mention`'s
/// authoritative `subject_id` MUST be a directory-attested principal DID
/// (`identity-handles.md §80`), which a synchronous text parser cannot
/// produce. Fabricating one client-side from the handle string would write a
/// non-verifiable `did:web` identifier into the wire `mentions[]` field. Actor
/// mentions therefore only enter the wire via the mention picker, whose chips
/// already carry a resolved `subject_id` (see `chat::mod` send path).
pub fn parse_mention_nodes(input: &str) -> Vec<MentionNode> {
    let mut mentions = Vec::new();
    for token in input.split_whitespace() {
        let normalized = normalize_inline_token(token);
        if normalized.strip_prefix('@').is_some()
            && let Some(audience) = arkret_sdk::AudienceMention::from_ui_token(normalized)
        {
            mentions.push(MentionNode::audience_mention(audience));
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
/// [`arkret_sdk::MentionRender`] so the chat view can drive a distinct
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
/// the shared SDK [`arkret_sdk::render_mention`] helper off the
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
    claim_set_snapshot: &[arkret_sdk::models::HandleClaim],
    accepted_issuers: &[String],
    context: Option<&str>,
    cached_handle: Option<&arkret_sdk::Handle>,
    display_name_at_time: Option<&str>,
) -> RenderedMention {
    use arkret_sdk::Did;
    use arkret_sdk::identity::{MentionRender, PrimaryHandleSelectInput, render_mention};

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
    res: &arkret_sdk::models::DirectorySubjectHandleList,
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
            let digest = arkret_sdk::identity::claim_digest(claim).unwrap_or_default();
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
    token: String,
    subject_id: String,
    /// Optional Realm id to scope disclosure policy.
    #[props(default)]
    realm_id: Option<String>,
) -> Element {
    // A4 — base_url from session context instead of a prop.
    let base_url = crate::app::SessionContext::base_url_string();
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
                match with_authed_sdk_client(&base_url, token, move |http| async move {
                    crate::directory_api::list_handles_for_subject(
                        &http,
                        &subject_id,
                        realm_id.as_deref(),
                        Some("display"),
                    )
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
                span { class: "muted", "ak.find.directory.query.list_handles_for_subject" }
            }
            div { class: "muted",
                "Handles are not authoritative roster fields — they come from signed "
                code { "ak.schema.handle_claim.v1" }
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
    fn typed_actor_handles_are_not_materialized_into_wire_mentions() {
        // A typed actor handle must NOT become a wire `Mention`: its
        // authoritative `subject_id` requires a directory-attested resolve,
        // not a client-fabricated `did:web` identifier. Only audience tokens
        // and (elsewhere) picker chips carry resolved subjects.
        let mentions = parse_mention_nodes(
            "ping @did:web:bob.example and @Alice and @carol:example.com about #ak:task:123 and #topic-demo",
        );
        assert!(
            mentions.is_empty(),
            "typed actor handles must not produce wire mentions"
        );
    }

    #[test]
    fn parses_audience_mentions_without_presence_online() {
        let mentions = parse_mention_nodes("notify @here and @all but never @online");

        assert!(mentions.iter().any(|mention| {
            mention.as_audience_mention().is_some_and(|mention| {
                mention.audience == arkret_sdk::AudienceMentionAudience::StrandEngaged
            })
        }));
        assert!(mentions.iter().any(|mention| {
            mention.as_audience_mention().is_some_and(|mention| {
                mention.audience == arkret_sdk::AudienceMentionAudience::EffectiveScopeMembers
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
        use arkret_sdk::Handle;
        use arkret_sdk::models::{HandleBindingState, HandleClaim};
        let now = chrono::Utc::now();
        let claim = HandleClaim {
            handle: Some(Handle::parse("alice:acme.example").unwrap()),
            subject: Some(
                arkret_sdk::Did::new("did:web:acme.example:principals:alice".to_owned()).unwrap(),
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
        use arkret_sdk::Handle;
        use arkret_sdk::models::{DirectorySubjectHandleList, HandleBindingState, HandleClaim};
        let now = chrono::Utc::now();
        let subject =
            arkret_sdk::Did::new("did:web:acme.example:principals:alice".to_owned()).unwrap();
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
        use arkret_sdk::Handle;
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
            short_protocol_id("ak:space:0196419b-0000-7000-8000-000000000000"),
            "ak:space:0196419b...000000"
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
