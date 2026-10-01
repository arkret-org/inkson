pub use arkret_sdk::MentionNode;
use arkret_wire::{SchemaId, ServiceOperationId};
use dioxus::prelude::*;
// Single source in yoface (the projection layer needs
// this label formatter without importing a views module). Re-exported so all
// existing `views::helpers::short_protocol_id` call sites keep resolving.
pub use yoface::utils::text::short_protocol_id;

pub(crate) use super::member_display::{account_display_label, actor_display_label};

/// Display label for one Contact peer.
///
/// Contact rows carry the peer's exact `AccountId`, so this goes through
/// [`account_display_label`] and the Directory handle cache stays addressed by
/// the complete account. Only a `service` peer, which has no account subject,
/// falls back to the principal-only ladder.
pub(crate) fn contact_peer_label(
    store: &crate::state::LocalStateStore,
    contact: &crate::models::ContactListRow,
) -> String {
    match crate::models::contact_peer_account_id(contact) {
        Some(account_id) => account_display_label(store, &account_id),
        None => actor_display_label(store, crate::models::contact_peer_id(contact).as_str()),
    }
}

/// Render an account's canonical handles as one `a, b` label, or `fallback` when the
/// account has none.
///
/// Shared by the sidebar account row and the settings account section. They
/// used to hold byte-identical private copies, which is how the two surfaces
/// could have disagreed about the empty case.
pub(crate) fn account_handles_display(handles: &[String], fallback: &str) -> String {
    if handles.is_empty() {
        fallback.to_owned()
    } else {
        handles.join(", ")
    }
}
use crate::api_error::normalize_wait_for_sync_token;
use crate::config::{ClientConfig, LocalConfigStore};
use crate::transport::auth::with_endpoint_clients;
use crate::ui::button::{Button, ButtonVariant};

/// Persist the current authenticated configuration. Derived strings are
/// checked against the typed context and never used to manufacture identity or
/// resolution coordinates.
pub fn persist_config(
    mut config_store: Signal<LocalConfigStore>,
    server_url: String,
    principal_id: Option<arkret_sdk::DidCoreId>,
    device_id: String,
    session_credential: String,
) {
    let Some(account) = (crate::app::SessionContext::get().active_account)() else {
        tracing::warn!("authenticated config persist skipped without accepted account context");
        return;
    };
    if account.server_url.as_str().trim_end_matches('/') != server_url.trim_end_matches('/')
        || principal_id.as_ref() != Some(account.principal_id())
        || account.device_id.as_str() != device_id.trim()
    {
        tracing::error!(
            "authenticated config persist rejected because derived coordinates disagree with active context"
        );
        return;
    }
    config_store
        .write()
        .save(ClientConfig::authenticated(account, session_credential));
}

pub fn active_sync_token(sync_cursor: impl AsRef<str>) -> Option<String> {
    normalize_wait_for_sync_token(sync_cursor.as_ref())
}

fn normalize_inline_token(token: &str) -> &str {
    token.trim_matches(|ch: char| {
        matches!(
            ch,
            ',' | '.' | '!' | '?' | ':' | ';' | ')' | '(' | '[' | ']' | '"' | '\''
        )
    })
}

/// Parse audience tokens (`@here` / `@all` / …) from raw message text into
/// structured [`MentionNode::AudienceMention`] entries.
///
/// Typed actor handles (`@alice:example.com`) are intentionally NOT
/// materialised into [`MentionNode::Mention`] here: a `Mention`'s
/// authoritative `subject_account_id` MUST be a directory-attested complete
/// `AccountId` (`identity-handles.md §3.8`), which a synchronous text parser
/// cannot produce — it has neither the principal nor the Station component.
/// Fabricating one client-side from the handle string would write a
/// non-verifiable identity into the wire `mentions[]` field. Actor mentions
/// therefore only enter the wire via the mention picker, whose chips already
/// carry a resolved `subject_account_id` (see `chat::mod` send path).
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
        left.target().cmp(&right.target()).then(
            left.mention_text_original()
                .cmp(&right.mention_text_original()),
        )
    });
    mentions.dedup_by(|left, right| left.target() == right.target());
    mentions
}

/// §3.8.2 — resolved render of an actor mention plus the visual
/// degradation tier the UI MUST surface. Thin mention-flavoured wrapper
/// over [`crate::views::member_display::resolve_subject_display`], which is
/// the one place in this client that runs the render ladder.
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

/// §3.8.2 mention render path (YG-MENT-2).
///
/// Resolves the *current* display value for an actor mention from the
/// authoritative `subject_account_id` — it MUST NOT use the audit-only
/// `handle_at_time` / `display_name_at_time` as the current value (those
/// are passed only as the degraded fallback inputs the ladder steps down
/// to). The mention node already carries the Station component, so this path
/// never infers one.
///
/// Step 1: Realm-scoped projection runs §3.2.1 primary handle selection
/// over `claim_set_snapshot` (the roster handle-claim evidence) +
/// `handle_issuer_policy`. When a verified primary handle wins it is shown
/// as `@{localpart}:{domain}`.
///
/// Realm-scoped signed handle claims are the only Directory-adjacent input;
/// Directory itself no longer exposes account or handle lookup surfaces.
pub fn render_actor_mention(
    subject_account_id: &arkret_sdk::AccountId,
    claim_set_snapshot: &[arkret_models_identity::HandleClaim],
    handle_issuer_policy: &[arkret_sdk::identity::HandleIssuerPolicyEntry],
    context: Option<&str>,
    cached_handle: Option<&arkret_sdk::Handle>,
    display_name_at_time: Option<&str>,
) -> RenderedMention {
    use crate::views::member_display::{MemberDisplayTier, resolve_subject_display};

    // §3.2.1 Step 0 keys on the exact account, which the mention node carries
    // in full. Nothing here may fall back to a bare principal or manufacture a
    // Station.
    let rendered = resolve_subject_display(
        Some(subject_account_id),
        claim_set_snapshot,
        handle_issuer_policy,
        context,
        cached_handle,
        display_name_at_time,
        &short_protocol_id(subject_account_id.principal_id.as_str()),
    );
    let (label, tier_class) = match rendered.tier {
        MemberDisplayTier::Verified => (format!("@{}", rendered.label), "mention-verified"),
        MemberDisplayTier::Cached => (format!("@{}", rendered.label), "mention-cached"),
        MemberDisplayTier::NameOnly => (rendered.label, "mention-name-only"),
        MemberDisplayTier::Unresolved => (rendered.label, "mention-unresolved"),
    };
    RenderedMention {
        label,
        tier_class,
        degraded: !matches!(rendered.tier, MemberDisplayTier::Verified),
    }
}

#[cfg(test)]
pub(crate) fn verified_handle_claim(
    handle: &str,
    subject_account_id: arkret_sdk::AccountId,
    issuer_id: arkret_sdk::DidCoreId,
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> arkret_models_identity::HandleClaim {
    use arkret_models_identity::{
        HandleClaim, HandleClaimCore, HandleClaimStatus, HandleClaimVariant, HandleVisibility,
    };
    use arkret_sdk::{Hash, PayloadProof, PayloadProofPurpose};

    let method = arkret_sdk::DidUrl::new("did:web:issuer.acme.example#handle-claim").unwrap();
    let placeholder = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
    let proof = |purpose, payload_digest| PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: method.clone(),
        payload_digest,
        created_at: issued_at,
        domain: Some(arkret_models_identity::HANDLE_CLAIM_PROOF_DOMAIN.to_owned()),
        audience: None,
        proof_purpose: Some(purpose),
        jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
    };
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle: arkret_sdk::Handle::parse(handle).unwrap(),
        handle_aliases: Vec::new(),
        subject_account_id,
        issuer_id: issuer_id.clone(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: HandleVisibility::Public,
        audience: None,
        issued_at,
        expires_at: Some(expires_at),
        source_refs: Vec::new(),
        proofs: [
            proof(PayloadProofPurpose::IssuerAttestation, placeholder.clone()),
            proof(PayloadProofPurpose::HolderAcceptance, placeholder.clone()),
        ],
    };
    let digest = core.claim_digest().unwrap();
    core.proofs[0].payload_digest = digest.clone();
    core.proofs[1].payload_digest = digest.clone();
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        status: HandleClaimStatus::Verified,
        as_of: issued_at,
        verifier_id: issuer_id,
        verified_at: Some(issued_at),
        revocation: None,
        fresh_until: issued_at + chrono::Duration::minutes(5),
        status_proof: proof(PayloadProofPurpose::StatusAttestation, placeholder),
    };
    claim.status_proof.domain = Some(arkret_models_identity::HANDLE_CLAIM_STATUS_DOMAIN.to_owned());
    claim.status_proof.payload_digest = claim.status_digest().unwrap();
    claim.validate().unwrap();
    claim
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
    fn raw_agent_selector_text_does_not_materialize_mentions() {
        let mentions = parse_mention_nodes("ask @alice:example.com/summary or @me/digest");
        assert!(
            mentions.is_empty(),
            "0364 D2 keeps selector-like text inert"
        );
    }

    fn mention_test_account(principal: &str, station: &str) -> arkret_sdk::AccountId {
        arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(principal).unwrap(),
            arkret_sdk::DidCoreId::new(station.to_owned()).unwrap(),
        )
    }

    #[test]
    fn render_actor_mention_runs_3_2_1_for_verified_handle() {
        let now = chrono::Utc::now();
        let alice = mention_test_account(
            "did:web:acme.example:principals:alice",
            "ak:did_core:web:station.acme.example",
        );
        let claim = verified_handle_claim(
            "alice:acme.example",
            alice.clone(),
            crate::mls_api_helpers::principal_core_id("did:web:issuer.acme.example").unwrap(),
            // `verified_handle_claim` freezes `fresh_until` at issued_at + 5
            // minutes, and §3.2.1 rejects any candidate whose freshness window
            // has closed. An issued_at outside that window would test the
            // stale ladder, not the verified tier this case is about.
            now,
            now + chrono::Duration::days(30),
        );
        let accepted = vec![arkret_sdk::identity::HandleIssuerPolicyEntry {
            issuer_id: arkret_sdk::DidCoreId::new("ak:did_core:web:issuer.acme.example".to_owned())
                .unwrap(),
            authorized_handle_domains: vec!["acme.example".to_owned()],
            issuer_class: arkret_sdk::identity::HandleIssuerAuthorityClass::DomainAuthority,
        }];
        let rendered = render_actor_mention(
            &alice,
            std::slice::from_ref(&claim),
            &accepted,
            None,
            None,
            Some("Alice (stale)"),
        );
        // §3.2.1 wins → verified tier, NOT the audit display name.
        assert_eq!(rendered.label, "@alice:acme.example");
        assert_eq!(rendered.tier_class, "mention-verified");
        assert!(!rendered.degraded);

        // §3.8 — the same principal at another Station is a different account,
        // so Alice's claim MUST NOT be projected onto it.
        let alice_elsewhere = mention_test_account(
            "did:web:acme.example:principals:alice",
            "ak:did_core:web:other-station.acme.example",
        );
        let other = render_actor_mention(
            &alice_elsewhere,
            &[claim],
            &accepted,
            None,
            None,
            Some("Alice (stale)"),
        );
        assert_ne!(other.tier_class, "mention-verified");
        assert!(other.degraded);
    }

    #[test]
    fn render_actor_mention_falls_back_to_name_then_did() {
        let bob = mention_test_account(
            "did:web:acme.example:principals:bob",
            "ak:did_core:web:station.acme.example",
        );
        // No claims → degraded ladder. display_name_at_time is the
        // name-only fallback (audit metadata used ONLY as fallback).
        let name_only = render_actor_mention(&bob, &[], &[], None, None, Some("Bob"));
        assert_eq!(name_only.label, "Bob");
        assert_eq!(name_only.tier_class, "mention-name-only");
        assert!(name_only.degraded);

        // Nothing at all → unresolved (truncated DID).
        let unresolved = render_actor_mention(&bob, &[], &[], None, None, None);
        assert_eq!(unresolved.tier_class, "mention-unresolved");
        assert!(unresolved.degraded);
    }

    #[test]
    fn render_actor_mention_uses_local_cache_before_name() {
        use arkret_sdk::Handle;
        let cached = Handle::parse("bob:acme.example").unwrap();
        let bob = mention_test_account(
            "did:web:acme.example:principals:bob",
            "ak:did_core:web:station.acme.example",
        );
        let rendered = render_actor_mention(&bob, &[], &[], None, Some(&cached), Some("Bob"));
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

/// Home Realm of a stored projection body, falling back to the key it is
/// stored under.
fn projection_home_realm_id(projection: &serde_json::Value, stored_under: &str) -> String {
    projection
        .get("realm_id")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            projection
                .get("summary")
                .and_then(|summary| summary.get("realm_id"))
                .and_then(serde_json::Value::as_str)
        })
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .unwrap_or(stored_under)
        .to_owned()
}

/// The MLS activation of the Realm-default scope of `realm_id` as the
/// installed durable current view knows it.
///
/// `Some(true)` is the Station's accepted `mls_group`; `Some(false)` is a
/// complete verified cut without one. `None` means no complete cut of that
/// Realm is installed — never "plaintext"; gates that could leak plaintext
/// must fail closed on it.
pub(crate) fn realm_mls_activation(
    current: Option<&crate::current_projection::RealmCurrentView>,
    realm_id: &str,
) -> Option<bool> {
    let realm = arkret_sdk::RealmId::new(realm_id.trim().to_owned()).ok()?;
    current?
        .scope_mls_current(&arkret_sdk::ScopeRef::Realm { realm_id: realm })
        .activated()
}

/// [`realm_mls_activation`] for an id that may name a Realm or one of the
/// containers stored beside it.
///
/// Only Realm, Circle and Sidecar are security scopes, so a Space or board id
/// resolves through its stored body's home Realm rather than pretending to
/// carry a scope of its own.
pub(crate) fn scope_mls_activation(
    projections: &std::collections::BTreeMap<String, serde_json::Value>,
    current: Option<&crate::current_projection::RealmCurrentView>,
    scope_id: &str,
) -> Option<bool> {
    let scope_id = scope_id.trim();
    if scope_id.is_empty() {
        return None;
    }
    let projection = projections.get(scope_id)?;
    realm_mls_activation(current, &projection_home_realm_id(projection, scope_id))
}
