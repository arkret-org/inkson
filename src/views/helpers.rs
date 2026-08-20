pub use arkret_sdk::MentionNode;
use arkret_wire::{SchemaId, ServiceOperationId};
use dioxus::prelude::*;
// Single source in yoface (YGN-ARCH-01 step 3: the projection layer needs
// this label formatter without importing a views module). Re-exported so all
// existing `views::helpers::short_protocol_id` call sites keep resolving.
pub use yoface::utils::text::short_protocol_id;

pub(crate) use super::member_display::actor_display_label;
use crate::api_error::normalize_wait_for_sync_token;
use crate::config::{ClientConfig, LocalConfigStore};
use crate::transport::auth::with_endpoint_clients;
use crate::ui::button::{Button, ButtonVariant};

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
            || arkret_models_identity::validate_agent_slug(agent_slug).is_err()
        {
            continue;
        }
        let controller_handle = if controller_handle.eq_ignore_ascii_case("me") {
            "me".to_owned()
        } else {
            let Some(parsed) = crate::identity::handle::parse_user_handle(controller_handle) else {
                continue;
            };
            parsed.handle
        };
        tokens.push(AgentSelectorMentionToken {
            mention_text_original: normalized.to_owned(),
            controller_handle,
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
/// Step 2 (live `ak.find.directory.read.list_handles_for_subject` resolution) is
/// wired through [`crate::views::helpers::list_handles_for_subject_ui`] /
/// the "Why am I seeing this handle?" panel and feeds the same
/// `claim_set_snapshot` — `TODO(R3.2.1)`: plumb the live result back into
/// this synchronous render call once the directory cache lands.
///
/// Fallback ladder (each visually degraded): local cached verified handle
/// → `display_name_at_time` → truncated DID.
pub fn render_actor_mention(
    subject_id: &str,
    claim_set_snapshot: &[arkret_models_identity::HandleClaim],
    accepted_issuers: &[String],
    context: Option<&str>,
    cached_handle: Option<&arkret_sdk::Handle>,
    display_name_at_time: Option<&str>,
) -> RenderedMention {
    use arkret_sdk::identity::{MentionRender, PrimaryHandleSelectInput, render_mention};

    // A malformed subject_id can't be resolved; fall straight to the
    // unresolved tier with a truncated form of the raw string.
    let Ok(subject) = arkret_sdk::DidCoreId::new(subject_id.trim().to_owned()) else {
        return RenderedMention {
            label: short_protocol_id(subject_id),
            tier_class: "mention-unresolved",
            degraded: true,
        };
    };

    let accepted_issuers = accepted_issuers
        .iter()
        .filter_map(|issuer| arkret_sdk::DidCoreId::new(issuer.clone()).ok())
        .collect::<Vec<_>>();
    let selection = PrimaryHandleSelectInput {
        subject_id: subject.as_str(),
        context,
        claim_set_snapshot,
        accepted_issuers: &accepted_issuers,
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
/// `ak.schema.handle_claim.v1` into display strings.
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
    res: &arkret_models_discovery::DirectorySubjectHandleList,
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
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "(unknown)".to_owned()),
                binding_state: claim
                    .binding_state
                    .map(|s| format!("{s:?}").to_lowercase())
                    .unwrap_or_else(|| "(unset)".to_owned()),
                created_at: arkret_sdk::canonical::format_timestamp_canonical(claim.created_at),
                expires_at: claim
                    .expires_at
                    .map(arkret_sdk::canonical::format_timestamp_canonical)
                    .unwrap_or_default(),
                claim_digest: digest,
            }
        })
        .collect()
}

/// R3.2 (YG-DIR-1/2) — "Why am I seeing this handle?" transparency
/// panel. Given a subject (principal) DID it calls the directory
/// `ak.find.directory.read.list_handles_for_subject` op and renders the visible
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
                match with_endpoint_clients(&base_url, token, None, move |clients| async move {
                    clients
                        .directory()
                        .list_handles_for_subject(
                            &subject_id,
                            realm_id.as_deref(),
                            Some(arkret_models_discovery::DirectoryIntent::Lookup),
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
                span { class: "muted", {ServiceOperationId::FIND_DIRECTORY_READ_LIST_HANDLES_FOR_SUBJECT} }
            }
            div { class: "muted",
                "Handles are not authoritative roster fields — they come from signed "
                code { {SchemaId::HANDLE_CLAIM_V1} }
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
        let tokens = parse_agent_selector_mention_tokens(
            "ask @alice:example.com/summary, @me/digest, not @bob:Bad",
        );
        assert_eq!(tokens.len(), 2);
        assert_eq!(
            tokens[0].mention_text_original,
            "@alice:example.com/summary"
        );
        assert_eq!(tokens[0].controller_handle, "alice:example.com");
        assert_eq!(tokens[0].agent_slug, "summary");
        assert_eq!(tokens[1].mention_text_original, "@me/digest");
        assert_eq!(tokens[1].controller_handle, "me");
        assert_eq!(tokens[1].agent_slug, "digest");

        let mentions = parse_mention_nodes("ask @alice:example.com/summary");
        assert!(mentions.is_empty());
    }

    #[test]
    fn render_actor_mention_runs_3_2_1_for_verified_handle() {
        use arkret_models_identity::{HandleBindingState, HandleClaim};
        use arkret_sdk::Handle;
        let now = chrono::Utc::now();
        let claim = HandleClaim {
            schema: HandleClaim::SCHEMA.to_owned(),
            handle: Some(Handle::parse("alice:acme.example").unwrap()),
            handle_aliases: Vec::new(),
            subject: Some(
                crate::mls_api_helpers::principal_core_id("did:web:acme.example:principals:alice")
                    .unwrap(),
            ),
            issuer: Some(
                crate::mls_api_helpers::principal_core_id("did:web:issuer.acme.example").unwrap(),
            ),
            issuer_service_id: None,
            binding_state: Some(HandleBindingState::Verified),
            claim_kind: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: Default::default(),
            member_delivery_binding: None,
            claims: Vec::new(),
            created_at: now - chrono::Duration::hours(1),
            expires_at: Some(now + chrono::Duration::days(30)),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
        };
        let accepted = vec!["ak:did_core:web:issuer.acme.example".to_owned()];
        let rendered = render_actor_mention(
            "ak:did_core:web:acme.example:principals:alice",
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
            "ak:did_core:web:acme.example:principals:bob",
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
            "ak:did_core:web:acme.example:principals:bob",
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
        use arkret_models_discovery::DirectorySubjectHandleList;
        use arkret_models_identity::{HandleBindingState, HandleClaim};
        use arkret_sdk::Handle;
        let now = chrono::Utc::now();
        let subject =
            crate::mls_api_helpers::principal_core_id("did:web:acme.example:principals:alice")
                .unwrap();
        let claim = HandleClaim {
            schema: HandleClaim::SCHEMA.to_owned(),
            handle: Some(Handle::parse("alice:acme.example").unwrap()),
            handle_aliases: Vec::new(),
            subject: Some(subject.clone()),
            issuer: Some(
                crate::mls_api_helpers::principal_core_id("did:web:issuer.acme.example").unwrap(),
            ),
            issuer_service_id: None,
            binding_state: Some(HandleBindingState::Verified),
            claim_kind: None,
            visibility: None,
            audience: None,
            challenge: None,
            claim_scope: Default::default(),
            member_delivery_binding: None,
            claims: Vec::new(),
            created_at: now,
            expires_at: Some(now + chrono::Duration::days(30)),
            verified_at: None,
            source_refs: Vec::new(),
            proofs: Vec::new(),
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
        assert_eq!(rows[0].issuer, "ak:did_core:web:issuer.acme.example");
        assert_eq!(rows[0].binding_state, "verified");
        assert!(rows[0].is_primary);
        assert!(rows[0].claim_digest.starts_with("sha256:"));
    }

    #[test]
    fn render_actor_mention_uses_local_cache_before_name() {
        use arkret_sdk::Handle;
        let cached = Handle::parse("bob:acme.example").unwrap();
        let rendered = render_actor_mention(
            "ak:did_core:web:acme.example:principals:bob",
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
    fn short_protocol_id_compacts_typed_event_derived_token() {
        assert_eq!(
            short_protocol_id("ak:space:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j"),
            "ak:space:AcbFC8Ni...VQQ74j"
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
