//! Typed Realm write functions.
//!
//! These are the realm / space / member / governance event-building
//! submitters that formerly lived as inherent methods on
//! `crate::transport::TransportClient`. Each takes an
//! [`crate::event_submit::EventSubmitter`] as its first argument and
//! submits through it, so call sites can drop the `TransportClient` facade in
//! favour of `with_event_submitter`. `accept_realm_invite` stays inherent
//! on `TransportClient` because its cross-endpoint join routing needs the
//! facade's base-url / credential / sync-token state.

use serde_json::{Value, json};

use crate::event_builders::{
    build_capability_relinquish_control_event, build_member_state_transition_event,
    build_plaintext_visible_services_event, build_realm_archive_event,
    build_realm_authority_basis_update_control_event, build_realm_authority_reset_control_event,
    build_realm_bootstrap_events, build_realm_destroy_event,
    build_realm_history_sharing_policy_event, build_realm_owner_transfer_control_event,
    build_realm_state_event, build_space_create_event, build_space_lifecycle_event,
    parse_realm_bootstrap_members, recommended_history_sharing_policy_for_visibility,
    recommended_realm_policy_bundle_value,
};
use crate::event_submit::EventSubmitter;
use crate::models::{RealmCreateResult, RealmPolicyResult, SpaceCreateResult, SubmitEventResult};
use crate::operation::{EventKind, ak_ops};
use crate::realm_helpers::validate_join_rule_v1;

/// Build + submit the spec-canonical `ak.realm.create` event bundle
/// (and its facet follow-ups) via `ak.self.events.command.submit`
/// (`POST /_arkret/self/events`).
///
/// Per spec realm-and-space.md §2.5, create carries only identity/security
/// genesis state. Profile and policy are signed facets, and creator membership
/// is the final explicit slot; the complete ordered unit is admitted through
/// the staged authority root before any normal member-based authorization.
/// Seed invitees are submitted afterwards as ordinary directed
/// `ak.invite.create` Control Moves because membership may only enter
/// `invite` through that lifecycle.
///
/// Create-locked identity/security fields are sent in the closed genesis
/// payload; mutable policy such as federation policy is carried by its
/// registered bootstrap facet — no field is dropped at the wire, unlike a REST wrapper that
/// might only accept a subset.
#[allow(clippy::too_many_arguments)]
pub async fn create_realm(
    submitter: &EventSubmitter,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    join_rule: &str,
    history_visibility: &str,
    encryption_profile: &str,
    security_class: &str,
    federation_policy: &str,
    notary_profile: &str,
    digest_algorithm: &str,
    trust_domain: &str,
    invitees: Vec<String>,
    plaintext_visible_services: Vec<String>,
    alias: Option<&str>,
    content_scheme: Option<&str>,
) -> anyhow::Result<RealmCreateResult> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for canonical ak.realm.create"
        ));
    }
    let title = title.trim();
    if title.is_empty() {
        return Err(anyhow::anyhow!("title is required for ak.realm.profile"));
    }

    let join_rule = validate_join_rule_v1(join_rule)?;
    let notary_did = submitter.service_id().await?;
    let resolved_invitees = parse_realm_bootstrap_members(&invitees)?;
    // One CSPRNG salt belongs to this creation intent. The complete unsigned
    // unit is durably queued before prepare/sign; Garth then persists the
    // exact signed unit before the first HTTP write.
    let genesis_salt = arkret_sdk::GenesisSalt::generate()?;
    // The Realm id is not minted here: it is derived from the genesis Event
    // the builder produces (spec realm-and-space.md section 2.5.0).
    let (_draft_realm_id, events) = build_realm_bootstrap_events(
        genesis_salt,
        actor_id,
        &notary_did,
        title,
        summary,
        discoverability,
        join_rule,
        history_visibility,
        encryption_profile,
        security_class,
        federation_policy,
        notary_profile,
        digest_algorithm,
        trust_domain,
        &invitees,
        &plaintext_visible_services,
        alias,
        content_scheme,
    )?;
    // Genesis Realm bootstrap has no prior snapshot head. All follow-up
    // facets use the staged authority root, and creator membership is the
    // final explicit slot in the same atomic unit.
    let idempotency_key =
        arkret_sdk::OperationId::new_v7_at(crate::clock::now_unix_ms()).into_string();
    let realm_id = submitter
        .submit_realm_bootstrap_durable(events, idempotency_key)
        .await?
        .to_string();

    let introduction_evidence_digest =
        crate::canonical::canonical_sha256(&json!({"kind": "explicit_address"}))?;
    for invitee in &resolved_invitees {
        if invitee.actor_id == actor_id {
            continue;
        }
        let delivery_target = arkret_sdk::InviteDeliveryTarget::principal_server(
            arkret_sdk::Did::new(notary_did.clone())
                .map_err(|error| anyhow::anyhow!("invalid notary service DID: {error}"))?,
        );
        let event = ak_ops::invite_create_structured(
            &realm_id,
            actor_id,
            &invitee.actor_id,
            None,
            delivery_target,
            &introduction_evidence_digest,
        )?
        .build_sdk_event("inkson")?;
        submitter.submit_sdk_event(&event).await?;
    }

    let mut members = Vec::new();
    members.push(actor_id.to_owned());
    for invitee in resolved_invitees {
        if !members.iter().any(|member| member == &invitee.actor_id) {
            members.push(invitee.actor_id);
        }
    }

    Ok(RealmCreateResult {
        ok: true,
        realm_id,
        owner: actor_id.to_owned(),
        members,
        state: "active".to_owned(),
    })
}

/// Create a Space (product-structure container) inside an existing
/// Realm. Emits `ak.space.create` per spec realm-and-space.md §3.
/// Unlike `create_realm`, this does NOT bootstrap MLS / membership
/// / federation — those live on the Realm and Space inherits them.
#[allow(clippy::too_many_arguments)]
pub async fn create_space_under_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    kind: &str,
    parent_space_id: Option<&str>,
    default_realm_id: Option<&str>,
) -> anyhow::Result<SpaceCreateResult> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!("actor_id is required for ak.space.create"));
    }
    let title = title.trim();
    if title.is_empty() {
        return Err(anyhow::anyhow!("title is required for ak.space.create"));
    }
    let realm_id = realm_id.trim();
    if realm_id.is_empty() {
        return Err(anyhow::anyhow!(
            "realm_id is required for ak.space.create — Space must live inside a Realm"
        ));
    }
    let event = build_space_create_event(
        realm_id,
        actor_id,
        title,
        summary,
        kind,
        parent_space_id,
        default_realm_id,
    )?;
    // The Space is named by its create Event, not by this call site.
    let space_id = arkret_sdk::SpaceId::from_event_id(&event.event_id).into_string();
    submitter.submit_sdk_event(&event).await?;

    Ok(SpaceCreateResult {
        ok: true,
        space_id,
        owner: actor_id.to_owned(),
        members: vec![actor_id.to_owned()],
        state: "active".to_owned(),
    })
}

/// Send a Space lifecycle action (`archive` / `restore` /
/// `tombstone`) per spec realm-and-space.md §3.4. Caller MUST
/// pass the home Realm id — the event is authorized + written
/// inside that Realm. Server validates the state-machine
/// (active → archived → active, any → tombstoned) and rejects
/// invalid transitions with `space_not_active` /
/// `space_not_archived` / `realm_already_terminal`.
pub async fn change_space_lifecycle(
    submitter: &EventSubmitter,
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    kind: EventKind,
) -> anyhow::Result<()> {
    let actor_id = actor_id.trim();
    let space_id = space_id.trim();
    let realm_id = realm_id.trim();
    if actor_id.is_empty() || space_id.is_empty() || realm_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id, space_id and realm_id are all required for {kind}"
        ));
    }
    let event = build_space_lifecycle_event(space_id, realm_id, actor_id, kind)?;
    submitter.submit_sdk_event(&event).await?;
    Ok(())
}

/// Member-state FSM transition (kick / ban / unban / leave) on the
/// Realm's `ak.component.member.state.v1` cell. Submits a `ak.member.state`
/// event via `ak.self.events.command.submit`; deployment-local member REST shims are
/// intentionally not used.
pub async fn transition_member_state(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    member: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
) -> anyhow::Result<SubmitEventResult> {
    let mut event = build_member_state_transition_event(
        realm_id, actor_id, member, from_state, to_state, reason,
    )?;
    // `ak.member.state` is CBA-exempt in the shared stamper only because the
    // Realm-bootstrap batch submits it pre-signed without a seal frontier.
    // Post-bootstrap transitions (ban / kick / leave / unban) carry effects,
    // and the server rejects effects-carrying Control Moves without
    // `seal_basis.leaves` (envelope validation). Every caller of this helper
    // is an already-joined actor, so the realm seal frontier is readable.
    let seal_view = submitter.events_frontier_realm_seal_view(realm_id).await?;
    event.seal_basis = Some(seal_view.seal_basis());
    event.seal_ref = None;
    event.auth_context = None;
    submitter.submit_sdk_event(&event).await
}

// ── Space / Realm Management (all writes go through ak.self.events.command.submit) ─

/// Replace the Realm display profile through its dedicated singleton facet.
/// Generic Realm patches are intentionally unsupported: title, summary and
/// avatar have exactly one wire carrier, `ak.realm.profile`.
pub async fn update_realm_metadata(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    patch: Value,
) -> anyhow::Result<SubmitEventResult> {
    let fields = patch
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("Realm profile update must be an object"))?;
    if let Some(field) = fields
        .keys()
        .find(|field| !matches!(field.as_str(), "title" | "summary" | "avatar_blob_ref"))
    {
        anyhow::bail!("{field} is not carried by ak.realm.profile");
    }
    let title = fields
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Realm profile title is required"))?;
    let mut profile = arkret_sdk::RealmProfile::new(title)?;
    profile.summary = optional_profile_string(fields.get("summary"), "summary")?;
    profile.avatar_blob_ref =
        optional_profile_string(fields.get("avatar_blob_ref"), "avatar_blob_ref")?
            .map(arkret_sdk::BlobRef::new)
            .transpose()?;
    let mut event = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
        realm_id, actor_id, profile,
    )?;
    // The bootstrap builder uses a null-head guard. A later replacement is
    // authorized against the current Realm Seal frontier instead.
    event.preconditions.clear();
    let seal_view = submitter.events_frontier_realm_seal_view(realm_id).await?;
    event.seal_basis = Some(seal_view.seal_basis());
    event.seal_ref = None;
    event.auth_context = None;
    submitter.submit_sdk_event(&event).await
}

fn optional_profile_string(value: Option<&Value>, field: &str) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value
        .as_object()
        .and_then(|object| object.get("$op"))
        .and_then(Value::as_str)
        == Some("unset")
    {
        return Ok(None);
    }
    let value = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Realm profile {field} must be a string or unset"))?
        .trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

/// Update the Realm plaintext-visible service facet through the
/// dedicated `ak.realm.plaintext_visible_services` event. This is not a
/// The profile Event cannot change this policy: servers enforce plaintext
/// access from the typed facet projection.
pub async fn update_realm_plaintext_visible_services(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    services: Vec<String>,
) -> anyhow::Result<SubmitEventResult> {
    let Some(mut event) = build_plaintext_visible_services_event(realm_id, actor_id, &services)?
    else {
        anyhow::bail!("plaintext_visible_services update requires at least one service DID");
    };
    let seal_view = submitter.events_frontier_realm_seal_view(realm_id).await?;
    event.seal_basis = Some(seal_view.seal_basis());
    event.seal_ref = None;
    event.auth_context = None;
    submitter.submit_sdk_event(&event).await
}

/// Update a structural Space object's metadata via `ak.space.update`.
/// The event is submitted to the Space's home Realm (`realm_id`), while
/// `space_id` identifies the Space object being patched.
pub async fn update_space_metadata(
    submitter: &EventSubmitter,
    realm_id: &str,
    space_id: &str,
    actor_id: &str,
    patch: Value,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::space_update_patch(realm_id, actor_id, space_id, patch)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Set Realm join_rule + history_visibility policy, optionally also
/// emitting `ak.realm.policy_bundle` for Join Policy gates.
pub async fn set_realm_policy_events(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    join_rule: &str,
    history_visibility: &str,
    join_policy: Option<Value>,
    preserve_recommended_encryption_floor: bool,
) -> anyhow::Result<RealmPolicyResult> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for canonical Realm policy events"
        ));
    }
    if history_visibility.trim() == "restricted" {
        return Err(anyhow::anyhow!(
            "restricted history_visibility requires ak.realm.history_sharing_policy; use build_realm_history_sharing_policy_event before emitting the visibility change"
        ));
    }
    let join_rule = validate_join_rule_v1(join_rule)?;
    let mut events = vec![
        build_realm_state_event::<arkret_sdk::event_spec::RealmJoinRule>(
            realm_id,
            actor_id,
            arkret_sdk::RealmJoinRulePayload::new(serde_json::from_value(json!(join_rule))?),
        )?,
        build_realm_state_event::<arkret_sdk::event_spec::RealmHistoryVisibility>(
            realm_id,
            actor_id,
            arkret_sdk::HistoryVisibilityPayload::new(serde_json::from_value(json!(
                history_visibility
            ))?),
        )?,
    ];
    if let Some(policy) = recommended_history_sharing_policy_for_visibility(history_visibility) {
        events.push(build_realm_history_sharing_policy_event(
            realm_id, actor_id, policy,
        )?);
    }
    if let Some(join_policy) = join_policy {
        // `join_policy` is now a declared component of the closed bundle def,
        // so this write is a legal policy_bundle revision rather than an
        // unregistered extra key.
        //
        // The cell is a `cas_register`: this revision restates the COMPLETE
        // enabled component set, and anything omitted is cleared. Starting from
        // the recommended genesis bundle keeps `content_scheme` (whose one-way
        // ratchet would otherwise reject the write), the encryption floors and
        // the `aad_visibility` ceiling — dropping that last one would lower the
        // ceiling to `hidden` and start rejecting every `routing_digest`
        // envelope, which presents as "dedupe suddenly broke", not as a policy
        // edit.
        let mut policy_bundle = recommended_realm_policy_bundle_value(None);
        if !preserve_recommended_encryption_floor {
            policy_bundle.content_scheme = None;
            policy_bundle.content_encryption_floor = None;
            policy_bundle.metadata_encryption_floor = None;
        }
        policy_bundle.join_policy = Some(
            serde_json::from_value(join_policy)
                .map_err(|error| anyhow::anyhow!("invalid Realm join_policy: {error}"))?,
        );
        events.push(build_realm_state_event::<
            arkret_sdk::event_spec::RealmPolicyBundle,
        >(realm_id, actor_id, policy_bundle)?);
    }
    for event in events {
        submitter.submit_sdk_event(&event).await?;
    }
    Ok(RealmPolicyResult {
        ok: true,
        realm_id: realm_id.to_owned(),
        join_rule: join_rule.to_owned(),
        history_visibility: history_visibility.to_owned(),
    })
}

/// Set (or clear) the Realm Recovery Key (RRK) `durability_policy` via a
/// `ak.realm.policy_bundle` event (realm-and-space.md §2.3.1 write path —
/// no new event kind; durability is a policy component).
///
/// `policy` is the SDK-typed [`arkret_models_collaboration::objects::realm::DurabilityPolicy`]
/// so the client never re-defines the spec shape. `policy_revision` MUST be a
/// monotonic increment of the Realm's current policy revision (the reducer
/// rejects a stale revision). After this lands, a subsequent `ak.mls.commit`
/// covering the membership frontier activates the new epoch's sealing
/// obligation and triggers re-disclosure (§2.10.8) — the caller SHOULD prompt
/// an MLS commit / self-update afterward.
///
/// Pre-condition (caller-enforced): RRK durability is only effective when the
/// Realm uses `content_scheme=mls_exporter_aead_v1`; declaring `mode != none`
/// on a plain `mls_rfc9420` Realm is rejected server-side
/// (`durability_scheme_incompatible`).
pub async fn set_realm_durability_policy(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    policy: &arkret_models_collaboration::objects::realm::DurabilityPolicy,
    policy_revision: u64,
) -> anyhow::Result<()> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for ak.realm.policy_bundle"
        ));
    }
    // Same `cas_register` restatement rule as the join-policy write: begin from
    // the recommended component set so this revision does not clear
    // `content_scheme`, the encryption floors or the `aad_visibility` ceiling
    // on its way to setting one component.
    let mut policy_bundle = recommended_realm_policy_bundle_value(None);
    policy_bundle.policy_revision = policy_revision;
    policy_bundle.durability_policy = Some(policy.clone());
    let event = build_realm_state_event::<arkret_sdk::event_spec::RealmPolicyBundle>(
        realm_id,
        actor_id,
        policy_bundle,
    )?;
    submitter.submit_sdk_event(&event).await?;
    Ok(())
}

/// Close an open invite via `ak.invite.cancel` (spec-canonical).
///
/// `target_state` names which closed state the lifecycle FSM lands in and is
/// part of the signed payload: `rejected` when the invitee declines,
/// `revoked` when the inviter or an admin withdraws.
pub async fn cancel_realm_invite(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    invite_id: &str,
    invitee: &str,
    target_state: &str,
    reason: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event =
        ak_ops::invite_cancel(realm_id, actor_id, invite_id, invitee, target_state, reason)?
            .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

pub async fn revoke_realm_invite(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    invite_id: &str,
    invitee: Option<&str>,
    target_state: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::invite_revoke(
        realm_id,
        actor_id,
        invite_id,
        invitee,
        target_state,
        reason_code,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Leave a Realm via `ak.member.state` event (`join → leave` FSM).
pub async fn leave_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
) -> anyhow::Result<SubmitEventResult> {
    transition_member_state(
        submitter,
        realm_id,
        actor_id,
        actor_id,
        Some("join"),
        "leave",
        "self_leave",
    )
    .await
}

/// Archive a Realm via the reversible `ak.realm.archive` lifecycle facet.
pub async fn archive_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_archive_event(realm_id, actor_id, true, Some("operator_request"))?;
    submitter.submit_sdk_event(&event).await
}

/// Permanently retire a Realm via `ak.realm.destroy`.
pub async fn destroy_realm(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    reason: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_destroy_event(realm_id, actor_id, reason)?;
    submitter.submit_sdk_event(&event).await
}

/// Submit a two-party Realm owner transfer. `successor_acceptance` is already
/// embedded in the typed payload and is never synthesized by the service.
pub async fn transfer_realm_owner(
    submitter: &EventSubmitter,
    actor_id: &str,
    payload: arkret_sdk::RealmOwnerTransferPayload,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_owner_transfer_control_event(actor_id, payload)?;
    submitter.submit_sdk_event(&event).await
}

/// Submit an independently confirmed authority-generation reset.
pub async fn reset_realm_authority(
    submitter: &EventSubmitter,
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityResetPayload,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_authority_reset_control_event(actor_id, payload)?;
    submitter.submit_sdk_event(&event).await
}

/// Submit an explicit capability registry basis adoption.
pub async fn update_realm_authority_basis(
    submitter: &EventSubmitter,
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityBasisUpdatePayload,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_realm_authority_basis_update_control_event(actor_id, payload)?;
    submitter.submit_sdk_event(&event).await
}

/// Relinquish one grant held by the current subject. This path intentionally
/// does not request or attach `ak.capability.revoke` authority.
pub async fn relinquish_capability(
    submitter: &EventSubmitter,
    realm_id: arkret_sdk::RealmId,
    subject_id: &str,
    payload: arkret_sdk::CapabilityRelinquishPayload,
) -> anyhow::Result<SubmitEventResult> {
    let event = build_capability_relinquish_control_event(realm_id, subject_id, payload)?;
    submitter.submit_sdk_event(&event).await
}

/// Ban a member via `ak.member.state` event (`join → ban` FSM).
pub async fn ban_member(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    member: &str,
) -> anyhow::Result<SubmitEventResult> {
    transition_member_state(
        submitter,
        realm_id,
        actor_id,
        member,
        Some("join"),
        "ban",
        "admin_ban",
    )
    .await
}

// ── Daily governance — protocol-event pipeline (P3) ───────────────
//
// Setting / revoking Realm admins, sealing moderation decisions, and
// running the appeal loop are now self-authored protocol Moves submitted
// via `ak.self.events.command.submit` (`POST /_arkret/self/events`) —
// mirroring `transition_member_state` / `ban_member`. P1 (capability)
// and P2 (moderation) projected the matching reducers in soland and the
// sodmin-side admin write paths were retired; these are the inkson-side
// submitters that drive them.

/// Grant Realm admin authority to `subject` by emitting a
/// `ak.capability.grant{actions:[ak.realm.admin], subject}` event.
/// The Grant id is derived from the accepted Event id. P1's
/// `apply_capability` folds this into the soland authz index, so subsequent
/// `ak.realm.admin` checks for `subject` pass.
pub async fn grant_realm_admin(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    subject: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::capability_grant_actions(
        realm_id,
        actor_id,
        subject,
        &["ak.realm.admin"],
        None,
        Value::Null,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Revoke a Realm-admin grant via `ak.capability.revoke`. `grant_id`
/// MUST be the id of the grant established by [`grant_realm_admin`]
/// (the soland reducer locates the cell by `grant_id`).
pub async fn revoke_realm_admin(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    grant_id: &str,
    reason: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::capability_revoke(realm_id, actor_id, grant_id, reason)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Seal a moderation disposition via `ak.moderation.decision`. The cell
/// subject is the moderated `target_ref`; the sealed decision Event's own
/// id is the reference later lift / appeal events resolve. `decision` is
/// the closed-enum runtime verb (`hard_deny` / `soft_deny` / `quarantine`
/// / `require_review`).
pub async fn moderation_decide(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    target_ref: &str,
    decision: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::moderation_decision(realm_id, actor_id, target_ref, decision, reason_code)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Lift a previously sealed moderation decision via
/// `ak.moderation.decision.lift`. `target_ref` is the moderated target
/// (the cell subject shared with the original decision); `decision_ref`
/// is the `ak:event:` id of the decision being lifted.
pub async fn moderation_lift(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::moderation_decision_lift(
        realm_id,
        actor_id,
        target_ref,
        decision_ref,
        reason_code,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Take an appeal under review (`ak.moderation.appeal.review`).
pub async fn appeal_review(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    notes_ref: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::moderation_appeal_review(realm_id, actor_id, appeal_id, notes_ref)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// Decide an appeal (`ak.moderation.appeal.decision`). For an
/// `overturn` verdict the caller MUST also submit a matching
/// [`moderation_lift`] in the same ordered batch; for `modify`,
/// pass the replacement decision id as `modify_decision_ref` and submit
/// that new [`moderation_decide`] in the same batch. This single
/// call only mints the appeal-decision event.
pub async fn appeal_decide(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    verdict: &str,
    reason_text_ref: &str,
    modify_decision_ref: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        verdict,
        reason_text_ref,
        modify_decision_ref,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

/// `governance/content-moderation.md` §5.5.1.1 — atomically decide an
/// appeal `verdict=overturn`. The reducer rejects an overturn whose
/// matching `ak.moderation.decision.lift` (target = `decision_ref`) is not
/// in the SAME ordered submit batch (`appeal_overturn_missing_lift`), so
/// this helper builds BOTH events, signs them, and submits them via
/// [`EventSubmitter::submit_signed_sdk_events_batch`] as one transaction.
///
/// Order matters: the appeal-decision precedes the lift it authorizes.
pub async fn appeal_overturn_atomic(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_text_ref: &str,
    lift_reason_code: &str,
) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
    let appeal_event = ak_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        "overturn",
        reason_text_ref,
        None,
    )?
    .build_sdk_event("inkson")?;
    let lift_event = ak_ops::moderation_decision_lift(
        realm_id,
        actor_id,
        target_ref,
        decision_ref,
        lift_reason_code,
    )?
    .build_sdk_event("inkson")?;
    sign_and_submit_moderation_batch(submitter, realm_id, vec![appeal_event, lift_event]).await
}

/// `governance/content-moderation.md` §5.5.1.1 — atomically decide an
/// appeal `verdict=modify`. The reducer rejects a modify whose
/// replacement `ak.moderation.decision` (target = original target) is not
/// in the same batch, and cross-checks that the appeal-decision's
/// `modify_decision_ref` equals that new decision's event id. This helper
/// completes the replacement decision first, stamps its content-bound id as
/// `modify_decision_ref`, and submits the replacement, appeal decision, and
/// original-decision lift as one transaction.
///
/// Returns the minted replacement `decision_id` alongside the batch result
/// so the caller can surface it.
pub async fn appeal_modify_atomic(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    target_ref: &str,
    decision_ref: &str,
    new_verdict: &str,
    new_reason_code: &str,
    appeal_reason_text_ref: &str,
) -> anyhow::Result<(String, arkret_sdk::EventsSubmitOutcome)> {
    let new_decision =
        ak_ops::moderation_decision(realm_id, actor_id, target_ref, new_verdict, new_reason_code)?
            .build_sdk_event("inkson")?;
    let new_decision_id = new_decision.event_id.to_string();
    let appeal_event = ak_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        "modify",
        appeal_reason_text_ref,
        Some(&new_decision_id),
    )?
    .build_sdk_event("inkson")?;
    let lift_event = ak_ops::moderation_decision_lift(
        realm_id,
        actor_id,
        target_ref,
        decision_ref,
        "appeal_modify",
    )?
    .build_sdk_event("inkson")?;
    let result = sign_and_submit_moderation_batch(
        submitter,
        realm_id,
        vec![new_decision, appeal_event, lift_event],
    )
    .await?;
    Ok((new_decision_id, result))
}

/// Seal-stamp + sign each event in a moderation control transaction, then
/// submit them atomically via [`EventSubmitter::submit_signed_sdk_events_batch`].
/// Shared by [`appeal_overturn_atomic`] / [`appeal_modify_atomic`].
/// All envelopes ride the same Realm seal head so the batch is one
/// consistent control view.
async fn sign_and_submit_moderation_batch(
    submitter: &EventSubmitter,
    _realm_id: &str,
    events: Vec<arkret_sdk::Event>,
) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
    submitter
        .submit_sdk_events_batch(_realm_id, events, None)
        .await
}

/// Close an appeal (`ak.moderation.appeal.close`). Reviewer close or
/// appellant withdrawal (the reducer authorizes withdrawal via
/// `closer == appellant`).
pub async fn appeal_close(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    appeal_id: &str,
    close_reason: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::moderation_appeal_close(realm_id, actor_id, appeal_id, close_reason)?
        .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}
