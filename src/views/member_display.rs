use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::HandleClaim;
use arkret_sdk::identity::{
    HandleIssuerPolicyEntry, MentionRender, PrimaryHandleSelectInput, render_mention,
};
use arkret_sdk::sync::MemberRosterMembership;
use arkret_sdk::{AccountId, Handle};
use serde_json::Value;

use super::helpers::short_protocol_id;
use crate::state::LocalStateStore;

/// Canonical Realm roster row from the root `member_roster_entries[]` projection.
///
/// This is the typed `ak` roster entry
/// (`account-subscribe-frame.schema.json#/$defs/member_roster_entry`) plus the
/// membership value the projection carried. Field parsing goes through the SDK
/// [`arkret_sdk::sync::MemberRosterEntry`] so a wire rename cannot silently degrade to "no
/// handle, no petname" the way hand-rolled `Value` field reads do.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RealmMemberRow {
    pub actor_id: arkret_sdk::ActorId,
    pub membership: Option<MemberRosterMembership>,
    pub identity_event_ids: Vec<String>,
    pub member_display_state_digest: Option<String>,
    pub subject_account_id: Option<AccountId>,
    pub handle_claims: Vec<HandleClaim>,
    pub handle_claims_limited: bool,
}

impl RealmMemberRow {
    /// Disclosed subject principal DID, when Realm policy disclosed the
    /// subject account for this row.
    pub(crate) fn subject_principal_id(&self) -> Option<&str> {
        self.subject_account_id
            .as_ref()
            .map(|account| account.principal_id.as_str())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ResolvedMemberDisplay {
    pub label: String,
    /// §3.8.2 render before the `client-preferences.md` §3.6 petname overlay.
    pub public_label: String,
    pub collision_public_display: String,
    pub primary_handle: Option<String>,
    /// §3.8.2 step 5 — which rung of the render ladder produced `label`.
    pub tier: MemberDisplayTier,
    pub display_name: Option<String>,
    pub avatar_blob_ref: Option<arkret_sdk::BlobRef>,
    pub subject_id: Option<String>,
}

/// Wire value of a roster membership state. `MemberRosterMembership` is closed to
/// the two roster-visible values; other membership words in this client come
/// from raw operations, not from the roster projection.
pub(crate) fn membership_wire_str(state: MemberRosterMembership) -> &'static str {
    match state {
        MemberRosterMembership::Join => "join",
        MemberRosterMembership::Knock => "knock",
    }
}

pub(crate) fn realm_member_roster(projection: Option<&Value>) -> Vec<RealmMemberRow> {
    let mut rows = BTreeMap::new();
    for entry in crate::state::realm_membership::validated_realm_roster_entries(projection) {
        let row = RealmMemberRow {
            actor_id: entry.actor_id,
            membership: Some(entry.membership),
            identity_event_ids: entry
                .identity_event_ids
                .into_iter()
                .map(|id| id.as_str().to_owned())
                .collect(),
            member_display_state_digest: entry
                .member_display_state_digest
                .map(|digest| digest.to_string()),
            subject_account_id: entry.subject_account_id,
            handle_claims: entry.handle_claims.unwrap_or_default(),
            handle_claims_limited: entry.handle_claims_limited.unwrap_or(false),
        };
        // `actor_id` is the roster key. Retain the first duplicate exactly as
        // required by the sync contract.
        rows.entry(row.actor_id.clone()).or_insert(row);
    }
    rows.into_values().collect()
}

/// Signed `ak.schema.handle_claim.v1` status-view fixture. The roster
/// carries the full SDK type, so tests build the real shape (both core
/// proofs and the status proof over the recomputed digests) instead of a
/// hand-written JSON subset that the wire would reject.
#[cfg(test)]
pub(crate) fn test_handle_claim(
    subject_account_id: &AccountId,
    handle: &str,
    issuer_did: &str,
    status: arkret_models_identity::HandleClaimStatus,
) -> HandleClaim {
    use arkret_models_identity::{
        HANDLE_CLAIM_PROOF_DOMAIN, HANDLE_CLAIM_STATUS_DOMAIN, HandleClaimCore, HandleClaimVariant,
        HandleVisibility,
    };
    use arkret_wire::{DidUrl, Hash, PayloadProof, PayloadProofPurpose};

    let now = chrono::Utc::now();
    let issued_at = now - chrono::Duration::minutes(5);
    let proof = |purpose: PayloadProofPurpose, domain: &str, created_at| {
        PayloadProof {
        kind: "detached_jws".to_owned(),
        verification_method: DidUrl::new("did:webvh:z6mkfixture:issuer.example#key-1").unwrap(),
        payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        created_at,
        domain: Some(domain.to_owned()),
        audience: None,
        proof_purpose: Some(purpose),
        jws: "eyJhbGciOiJFZDI1NTE5In0..AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
    }
    };
    let mut core = HandleClaimCore {
        schema: HandleClaimCore::SCHEMA.to_owned(),
        handle: Handle::parse(handle).unwrap(),
        handle_aliases: Vec::new(),
        subject_account_id: subject_account_id.clone(),
        issuer_id: arkret_sdk::DidCoreId::new(issuer_did.to_owned()).unwrap(),
        claim: HandleClaimVariant::HandleBinding,
        visibility: HandleVisibility::Public,
        audience: None,
        issued_at,
        expires_at: Some(now + chrono::Duration::days(30)),
        source_refs: Vec::new(),
        proofs: [
            proof(
                PayloadProofPurpose::IssuerAttestation,
                HANDLE_CLAIM_PROOF_DOMAIN,
                issued_at,
            ),
            proof(
                PayloadProofPurpose::HolderAcceptance,
                HANDLE_CLAIM_PROOF_DOMAIN,
                issued_at,
            ),
        ],
    };
    let digest = core.claim_digest().unwrap();
    for entry in &mut core.proofs {
        entry.payload_digest = digest.clone();
    }
    let mut claim = HandleClaim {
        schema: HandleClaim::SCHEMA.to_owned(),
        claim: core,
        status,
        as_of: now,
        verifier_id: arkret_sdk::DidCoreId::new(issuer_did.to_owned()).unwrap(),
        verified_at: matches!(status, arkret_models_identity::HandleClaimStatus::Verified)
            .then_some(now),
        revocation: None,
        fresh_until: now + chrono::Duration::minutes(5),
        status_proof: proof(
            PayloadProofPurpose::StatusAttestation,
            HANDLE_CLAIM_STATUS_DOMAIN,
            now,
        ),
    };
    claim.status_proof.payload_digest = claim.status_digest().unwrap();
    claim
}

/// Realm `handle_issuer_policies` fixture matching [`test_handle_claim`].
#[cfg(test)]
pub(crate) fn test_issuer_policy(issuer_did: &str, domain: &str) -> HandleIssuerPolicyEntry {
    HandleIssuerPolicyEntry {
        issuer_id: arkret_sdk::DidCoreId::new(issuer_did.to_owned()).unwrap(),
        authorized_handle_domains: vec![domain.to_owned()],
        issuer_class: arkret_sdk::identity::HandleIssuerAuthorityClass::DomainAuthority,
    }
}

/// `identity-handles.md` §3.2.1 issuer trust + domain-authority filter input:
/// the Realm's effective `handle_issuer_policies`, read from the Station's
/// current `ak.component.realm.policy_bundle.v1` value.
///
/// The bundle cell is sequenced state and the Station publishes exactly one
/// selected value for it, so the installed current result is the effective
/// policy; the client never re-picks a revision across projected Events. An
/// empty result is not "no constraint": §3.2.1 Step 0 makes the issuer filter
/// mandatory, so an empty policy makes the inline candidate set empty and the
/// renderer degrades instead of showing an unvetted handle.
pub(crate) fn realm_handle_issuer_policies(
    store: &LocalStateStore,
    realm_id: &str,
) -> Vec<HandleIssuerPolicyEntry> {
    let Some(value) = store
        .realm_current_view_entries(realm_id)
        .and_then(|entries| crate::current_projection::current_realm_policy_bundle_value(&entries))
    else {
        return Vec::new();
    };
    // The Station selects the current policy value; the published value is
    // either the bundle payload itself or the generic `{"value": ...}`
    // envelope it was committed in.
    let candidate = value.get("value").unwrap_or(&value);
    serde_json::from_value::<arkret_sdk::RealmPolicyBundlePayload>(candidate.clone())
        .ok()
        .and_then(|bundle| bundle.handle_issuer_policies)
        .unwrap_or_default()
}

/// §3.8.2 step 1c/1d — run the SDK §3.2.1 primary-handle selection over the
/// roster's inline signed handle-claim evidence.
///
/// The selection itself (issuer trust + domain-authority filter, audience
/// scope, validity window, priority layers and the deterministic tie-break)
/// lives in `arkret_sdk::identity`; this client only assembles the
/// deterministic input tuple.
#[cfg(test)]
pub(crate) fn inline_primary_handle(
    row: &RealmMemberRow,
    handle_issuer_policies: &[HandleIssuerPolicyEntry],
    context: Option<&str>,
) -> Option<Handle> {
    let account_id = row.subject_account_id.as_ref()?;
    if row.handle_claims.is_empty() {
        return None;
    }
    arkret_sdk::identity::select_primary_handle(&PrimaryHandleSelectInput {
        account_id,
        context,
        claim_set_snapshot: &row.handle_claims,
        handle_issuer_policies,
        // The DID Document `metadata.primary_handle` layer needs an as-of
        // DID Document snapshot resolver; until one is wired this client
        // runs the algorithm with the holder-preference layer empty, which
        // §3.2.1 permits (the layer is simply skipped).
        holder_primary_handle_at_as_of: None,
        resolution_as_of: chrono::Utc::now(),
    })
    .map(|claim| claim.claim.handle)
}

fn principal_core_subject(value: &str) -> Option<String> {
    let value = value.trim();
    arkret_sdk::DidCoreId::new(value.to_owned())
        .ok()
        .map(|id| id.as_str().to_owned())
}

pub(crate) fn member_lookup_subject(
    row: &RealmMemberRow,
    identity: Option<&arkret_sdk::MemberIdentity>,
) -> Option<String> {
    row.subject_principal_id()
        .and_then(principal_core_subject)
        .or_else(|| {
            identity.and_then(|identity| {
                principal_core_subject(identity.subject_actor_id.signing_principal_id().as_str())
            })
        })
}

/// The only admissible subject for a Directory handle query on a roster row.
///
/// `client-sync.md` §8.1: when the roster did not disclose
/// `subject_account_id` and the MemberIdentity `subject_actor_id` is absent or
/// on the `service` branch, there is no query input at all — the client MUST
/// wait for subject disclosure or use inline evidence, and MUST NOT fall back
/// to the Realm `actor_id`, a pairwise principal, or a locally assembled
/// account id. Returning `None` degrades the row to the §3.8.2 step 4 ladder.
pub(crate) fn member_handle_lookup_account(
    row: &RealmMemberRow,
    identity: Option<&arkret_sdk::MemberIdentity>,
) -> Option<AccountId> {
    row.subject_account_id.clone().or_else(|| {
        identity.and_then(|identity| identity.subject_actor_id.as_account_id().cloned())
    })
}

/// §3.8.2 step 5 — the visual-degradation tier a rendered member label sits
/// on. Every non-`Verified` tier MUST be visually marked as degraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemberDisplayTier {
    /// §3.2.1 selected a verified primary handle.
    Verified,
    /// Served from a locally cached verified handle (step 4a).
    Cached,
    /// Only a captured display name is available (step 4b).
    NameOnly,
    /// Nothing resolved; a truncated protocol id is shown (step 4c).
    Unresolved,
}

impl MemberDisplayTier {
    /// CSS class the surface applies so the degradation is visible.
    pub(crate) fn css_class(self) -> &'static str {
        match self {
            Self::Verified => "identity-verified",
            Self::Cached => "identity-cached",
            Self::NameOnly => "identity-name-only",
            Self::Unresolved => "identity-unresolved",
        }
    }

    /// Short badge text for a degraded tier, and the longer explanation the
    /// surface puts on its `title`. `None` for `Verified`.
    pub(crate) fn degraded_badge(self) -> Option<(String, String)> {
        let (badge, detail) = match self {
            Self::Verified => return None,
            Self::Cached => ("identity.tier.cached", "identity.tier.cached_detail"),
            Self::NameOnly => ("identity.tier.name_only", "identity.tier.name_only_detail"),
            Self::Unresolved => (
                "identity.tier.unresolved",
                "identity.tier.unresolved_detail",
            ),
        };
        Some((crate::i18n::tr(badge), crate::i18n::tr(detail)))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SubjectDisplay {
    pub label: String,
    pub handle: Option<String>,
    pub tier: MemberDisplayTier,
}

/// §3.8.2 — the single member/subject rendering entry point in this client.
///
/// When the exact `account_id` is known the whole ladder is the SDK's
/// [`render_mention`]: §3.2.1 primary-handle selection first, then the
/// cached-handle / display-name / unresolved fallbacks. Without an exact
/// account id §3.2.1 Step 0 cannot run at all, so the render starts at the
/// step 4 fallback ladder.
///
/// `unresolved_label` is this client's rendering of the step 4c "truncated
/// DID" rung; which rung applies is decided by the SDK, never here.
pub(crate) fn resolve_subject_display(
    account_id: Option<&AccountId>,
    claim_set_snapshot: &[HandleClaim],
    handle_issuer_policies: &[HandleIssuerPolicyEntry],
    context: Option<&str>,
    cached_handle: Option<&Handle>,
    display_name: Option<&str>,
    unresolved_label: &str,
) -> SubjectDisplay {
    let unresolved = || SubjectDisplay {
        label: unresolved_label.to_owned(),
        handle: None,
        tier: MemberDisplayTier::Unresolved,
    };
    if let Some(account_id) = account_id {
        let selection = PrimaryHandleSelectInput {
            account_id,
            context,
            claim_set_snapshot,
            handle_issuer_policies,
            // The holder-preference layer needs an as-of DID Document
            // snapshot resolver; until one is wired the layer stays empty,
            // which §3.2.1 permits.
            holder_primary_handle_at_as_of: None,
            resolution_as_of: chrono::Utc::now(),
        };
        return match render_mention(&selection, cached_handle, display_name) {
            MentionRender::Verified { handle } => SubjectDisplay {
                label: handle.canonical().to_owned(),
                handle: Some(handle.canonical().to_owned()),
                tier: MemberDisplayTier::Verified,
            },
            MentionRender::Cached { handle } => SubjectDisplay {
                label: handle.canonical().to_owned(),
                handle: Some(handle.canonical().to_owned()),
                tier: MemberDisplayTier::Cached,
            },
            MentionRender::NameOnly { name } => SubjectDisplay {
                label: name,
                handle: None,
                tier: MemberDisplayTier::NameOnly,
            },
            MentionRender::Unresolved { .. } => unresolved(),
        };
    }
    if let Some(handle) = cached_handle {
        return SubjectDisplay {
            label: handle.canonical().to_owned(),
            handle: Some(handle.canonical().to_owned()),
            tier: MemberDisplayTier::Cached,
        };
    }
    match display_name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => SubjectDisplay {
            label: name.to_owned(),
            handle: None,
            tier: MemberDisplayTier::NameOnly,
        },
        None => unresolved(),
    }
}

fn parse_handle(raw: &str) -> Option<Handle> {
    crate::identity::handle::parse_user_handle(raw)
        .and_then(|parsed| Handle::parse(&parsed.handle).ok())
}

pub(crate) fn resolve_member_display(
    store: &LocalStateStore,
    realm_id: &str,
    row: &RealmMemberRow,
) -> ResolvedMemberDisplay {
    let policies = realm_handle_issuer_policies(store, realm_id);
    resolve_member_display_with_policies(store, realm_id, row, &policies)
}

/// [`resolve_member_display`] with the Realm's §3.2.1 issuer policy already
/// resolved, so a roster loop reads the Realm projection once instead of once
/// per row.
pub(crate) fn resolve_member_display_with_policies(
    store: &LocalStateStore,
    realm_id: &str,
    row: &RealmMemberRow,
    handle_issuer_policies: &[HandleIssuerPolicyEntry],
) -> ResolvedMemberDisplay {
    let identity = store.resolved_member_identity(realm_id, &row.actor_id);
    let subject_id = member_lookup_subject(row, identity.as_ref());
    let handle_lookup_account = member_handle_lookup_account(row, identity.as_ref());
    // §3.8.2 step 4a input: the last verified primary handle this client saw
    // for the subject, either the active account's own persisted handle or a
    // signed handle evidence already carried by Realm state. The local cache
    // is addressed by the exact `AccountId` only; a row without a disclosed
    // subject has no cache key and degrades instead of borrowing another
    // Station's account.
    let cached_handle = [
        subject_id.as_deref(),
        Some(row.actor_id.signing_principal_id().as_str()),
    ]
    .into_iter()
    .flatten()
    .find_map(|principal_id| store.primary_handle_for_principal_id(principal_id))
    .or_else(|| {
        handle_lookup_account.as_ref().and_then(|subject| {
            store
                .cached_member_handle_lookup(
                    subject,
                    Some(realm_id),
                    row.member_display_state_digest.as_deref(),
                )
                .and_then(|entry| entry.primary_handle)
        })
    })
    .as_deref()
    .and_then(parse_handle);
    let display_name = identity.as_ref().and_then(|identity| {
        let name = identity.display_profile.display_name.trim();
        (!name.is_empty()).then(|| name.to_owned())
    });
    let account_id = row
        .subject_account_id
        .as_ref()
        .or_else(|| row.actor_id.as_account_id());
    let rendered = resolve_subject_display(
        account_id,
        &row.handle_claims,
        handle_issuer_policies,
        Some(realm_id),
        cached_handle.as_ref(),
        display_name.as_deref(),
        &short_protocol_id(row.actor_id.signing_principal_id().as_str()),
    );
    let collision_public_display = display_name
        .as_ref()
        .cloned()
        .unwrap_or_else(|| rendered.label.clone());
    let label = member_label_with_contact_petname(store, row, &rendered.label);
    ResolvedMemberDisplay {
        label,
        public_label: rendered.label,
        collision_public_display,
        primary_handle: rendered.handle,
        tier: rendered.tier,
        display_name,
        avatar_blob_ref: identity.and_then(|identity| identity.display_profile.avatar_blob_ref),
        subject_id,
    }
}

/// Canonical actor label for surfaces that only have a stable principal id and no Realm
/// roster row. An accepted human Contact's global petname wins; the rest of
/// the ladder is [`resolve_subject_display`] with no exact account id, so it
/// starts at the §3.8.2 step 4 fallbacks.
pub(crate) fn actor_display_label(store: &LocalStateStore, principal_id: &str) -> String {
    account_label_ladder(store, principal_id, None)
}

/// [`actor_display_label`] for a surface that holds the peer's exact
/// `AccountId`. Only this form may read the Directory handle cache: the cache
/// is keyed by the complete account, because `discovery-directory.md` forbids
/// answering for one Station's account with another Station's claims.
pub(crate) fn account_display_label(store: &LocalStateStore, account_id: &AccountId) -> String {
    account_label_ladder(store, account_id.principal_id.as_str(), Some(account_id))
}

fn account_label_ladder(
    store: &LocalStateStore,
    principal_id: &str,
    account_id: Option<&AccountId>,
) -> String {
    if let Some(petname) = store
        .active_contact_remark(principal_id)
        .and_then(|remark| {
            let petname = remark.petname.trim();
            (!petname.is_empty()).then(|| petname.to_owned())
        })
    {
        return petname;
    }
    let cached_handle = store
        .primary_handle_for_principal_id(principal_id)
        .or_else(|| {
            account_id.and_then(|account_id| {
                store
                    .cached_member_handle_lookup(account_id, None, None)
                    .and_then(|entry| entry.primary_handle)
            })
        })
        .as_deref()
        .and_then(parse_handle);
    resolve_subject_display(
        None,
        &[],
        &[],
        None,
        cached_handle.as_ref(),
        None,
        &short_protocol_id(principal_id),
    )
    .label
}

/// Realm roster variant. A petname is joined only through a unique verified
/// subject projection; actor ids and display strings are never guessed as
/// Contact principals.
pub(crate) fn member_label_with_contact_petname(
    store: &LocalStateStore,
    row: &RealmMemberRow,
    public_label: &str,
) -> String {
    row.subject_principal_id()
        .and_then(|principal_id| store.active_contact_remark(principal_id))
        .and_then(|remark| {
            let petname = remark.petname.trim();
            (!petname.is_empty()).then(|| petname.to_owned())
        })
        .unwrap_or_else(|| public_label.to_owned())
}

/// Build the bounded local anchor index used to warn when a visible public
/// display string collides with another accepted Contact's saved identity.
pub(crate) fn contact_petname_binding_index(
    remarks: &BTreeMap<String, crate::account_data::ContactRemark>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut index = BTreeMap::<String, BTreeSet<String>>::new();
    for (principal_id, remark) in remarks {
        for anchor in [
            Some(remark.petname.as_str()),
            remark.confirmed_display_name.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|anchor| !anchor.is_empty())
        {
            if let Ok(skeleton) = arkret_sdk::display_confusable_skeleton_v1(anchor) {
                index
                    .entry(skeleton)
                    .or_default()
                    .insert(principal_id.clone());
            }
        }
    }
    index
}

pub(crate) fn public_display_conflicts_with_other_contact(
    anchor_index: &BTreeMap<String, BTreeSet<String>>,
    subject_principal_id: Option<&str>,
    public_display: &str,
) -> bool {
    let Ok(skeleton) = arkret_sdk::display_confusable_skeleton_v1(public_display) else {
        return false;
    };
    anchor_index.get(&skeleton).is_some_and(|principals| {
        principals
            .iter()
            .any(|principal| Some(principal.as_str()) != subject_principal_id)
    })
}

pub(crate) fn owned_agent_slug<'a>(
    row: &RealmMemberRow,
    owned_agent_slugs: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    let arkret_sdk::ActorId::Account {
        account_id: arkret_sdk::AccountId { station_id, .. },
    } = &row.actor_id
    else {
        return None;
    };
    if !crate::operation::authoring_station_id().is_ok_and(|local| local == *station_id) {
        return None;
    }
    owned_agent_slugs
        .get(row.actor_id.signing_principal_id().as_str())
        .or_else(|| {
            row.subject_principal_id()
                .and_then(|subject| owned_agent_slugs.get(subject))
        })
        .map(String::as_str)
}

#[cfg(test)]
mod petname_tests {
    use super::*;

    #[test]
    fn roster_keeps_accounts_at_different_stations_distinct() {
        let principal =
            arkret_sdk::DidCoreId::new("ak:did_core:web:roster-isolation.example").unwrap();
        let actor = |station| {
            arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
                principal.clone(),
                arkret_sdk::DidCoreId::new(station).unwrap(),
            ))
        };
        let first = actor("ak:did_core:web:station-a.example");
        let second = actor("ak:did_core:web:station-b.example");
        let projection = serde_json::json!({"member_roster_entries": [
            {"actor_id": first, "membership": "join"},
            {"actor_id": second, "membership": "knock"},
            {"actor_id": first, "membership": "leave"},
            {"actor_id": principal, "membership": "join"}
        ]});
        let rows = realm_member_roster(Some(&projection));
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter()
                .find(|row| row.actor_id == first)
                .unwrap()
                .membership,
            Some(MemberRosterMembership::Join)
        );
        assert_eq!(
            rows.iter()
                .find(|row| row.actor_id == second)
                .unwrap()
                .membership,
            Some(MemberRosterMembership::Knock)
        );
    }

    fn remark(principal_id: &str, petname: &str) -> crate::account_data::ContactRemark {
        crate::account_data::ContactRemark::new(
            arkret_sdk::DidCoreId::new(principal_id).unwrap(),
            petname,
            chrono::Utc::now(),
        )
    }

    fn accepted_human(principal_id: &str) -> crate::models::ContactListRow {
        crate::models::ContactListRow {
            peer: arkret_sdk::contact_operations::ContactPeer::Human {
                account_id: arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new(principal_id).unwrap(),
                    arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                ),
            },
            state: arkret_sdk::ContactState::Accepted,
            request_event_ref: None,
            request_message: None,
            response_event_ref: None,
            tombstone_event_ref: None,
            next_prepare_input: None,
            granted_to_peer_scopes: Vec::new(),
            granted_by_peer_scopes: Vec::new(),
            bidirectional_scopes: Vec::new(),
            effective_scopes: None,
            continuity_evidence: None,
            direct_conversation: None,
            contact_agent_projections: Vec::new(),
            peer_endpoint: None,
        }
    }

    fn realm_row(actor_id: &str, subject_id: Option<&str>) -> RealmMemberRow {
        RealmMemberRow {
            actor_id: crate::mls_api_helpers::local_account_actor_id(actor_id).unwrap(),
            membership: Some(MemberRosterMembership::Join),
            identity_event_ids: Vec::new(),
            member_display_state_digest: None,
            subject_account_id: subject_id.map(|subject| {
                arkret_sdk::AccountId::new(
                    arkret_sdk::DidCoreId::new(subject.to_owned()).unwrap(),
                    crate::operation::authoring_station_id().unwrap(),
                )
            }),
            handle_claims: Vec::new(),
            handle_claims_limited: false,
        }
    }

    #[test]
    fn realm_petname_requires_both_accepted_contact_and_verified_subject_join() {
        let principal = "ak:did_core:web:alice.example";
        let mut store = LocalStateStore::default();
        store.set_contact_remark(principal, remark(principal, "Alice from Ops"));
        store.replace_accepted_human_contacts(&[accepted_human(principal)]);

        assert_eq!(
            member_label_with_contact_petname(
                &store,
                &realm_row("ak:did_core:key:realm-actor", None),
                "Public Alice",
            ),
            "Public Alice"
        );
        assert_eq!(
            member_label_with_contact_petname(
                &store,
                &realm_row("ak:did_core:key:realm-actor", Some(principal)),
                "Public Alice",
            ),
            "Alice from Ops"
        );

        store.replace_accepted_human_contacts(&[]);
        assert_eq!(
            member_label_with_contact_petname(
                &store,
                &realm_row("ak:did_core:key:realm-actor", Some(principal)),
                "Public Alice",
            ),
            "Public Alice"
        );
    }

    #[test]
    fn contact_anchor_index_excludes_the_visible_subjects_own_anchor() {
        let alice = "ak:did_core:web:alice.example";
        let bob = "ak:did_core:web:bob.example";
        let remarks = BTreeMap::from([
            (alice.to_owned(), remark(alice, "Alice")),
            (bob.to_owned(), remark(bob, "Bob")),
        ]);
        let index = contact_petname_binding_index(&remarks);

        assert!(!public_display_conflicts_with_other_contact(
            &index,
            Some(alice),
            "Ａlice"
        ));
        assert!(public_display_conflicts_with_other_contact(
            &index,
            Some(bob),
            "Ａlice"
        ));
        assert!(public_display_conflicts_with_other_contact(
            &index, None, "Ａlice"
        ));
    }
}
