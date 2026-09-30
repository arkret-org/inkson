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

use arkret_wire::CapabilityActionId;
use serde_json::Value;

#[cfg(test)]
use crate::event_builders::build_realm_profile_replacement_event;
use crate::event_builders::{
    build_capability_relinquish_control_intent, build_member_state_transition_event,
    build_realm_alias_event, build_realm_alias_rename_event, build_realm_alias_tombstone_event,
    build_realm_archive_event, build_realm_authority_reset_control_intent,
    build_realm_bootstrap_steps_for_station, build_realm_destroy_event,
    build_realm_owner_transfer_control_intent, build_realm_profile_update_event,
    build_realm_state_event_for_station, build_space_create_event, build_space_lifecycle_event,
    parse_wire_enum, recommended_realm_policy_bundle_value,
};
use crate::event_submit::EventSubmitter;
use crate::models::{RealmCreateResult, RealmPolicyResult, SpaceCreateResult, SubmitEventResult};
use crate::operation::{EventKind, LocalOperation, ak_ops};
use crate::realm_helpers::validate_join_rule_v1;

/// Build + submit the spec-canonical `ak.realm.create` event bundle
/// (and its facet follow-ups) via `ak.self.events.command.submit.v1`
/// (`POST /_arkret/self/events`).
///
/// Per spec realm-and-space.md §2.5, create carries only identity/security
/// genesis state. Profile and policy are signed facets, and creator membership
/// is the final explicit slot; the complete ordered unit is admitted through
/// the staged authority root before any normal member-based authorization.
/// Additional members are invited afterwards through the ordinary directed
/// `ak.invite.create` lifecycle, where each target carries verified resolution.
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
    history_access: &str,
    security_class: &str,
    federation_policy: &str,
    digest_algorithm: &str,
    trust_domain: &str,
    plaintext_visible_services: Vec<String>,
    alias: Option<&str>,
    mls_creator_device: Option<&arkret_sdk::DeviceId>,
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
    let station_id = submitter.authority()?.station_id.clone();
    let notary_did = submitter.service_did().await?;
    let described_server_id =
        arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(notary_did.clone())?)?;
    if described_server_id != station_id {
        anyhow::bail!(
            "authenticated Station authority does not match the current service description"
        );
    }
    let notary_service_origin = submitter.http().base_url().origin().ascii_serialization();
    // One CSPRNG salt belongs to this creation intent. The signed unit and an
    // explicitly selected MLS intent are committed before the first create write.
    let genesis_salt = arkret_sdk::GenesisSalt::generate()?;
    // The Realm id is not minted here: it is derived from the genesis Event
    // the builder produces (spec realm-and-space.md section 2.5.0).
    let steps = build_realm_bootstrap_steps_for_station(
        station_id,
        genesis_salt,
        actor_id,
        &notary_did,
        &notary_service_origin,
        title,
        summary,
        discoverability,
        join_rule,
        history_access,
        security_class,
        federation_policy,
        digest_algorithm,
        trust_domain,
        &plaintext_visible_services,
        alias,
    )?;
    // Genesis Realm bootstrap has no prior snapshot head. All follow-up
    // facets use the staged authority root, and creator membership is the
    // final explicit slot in the same atomic unit.
    let idempotency_key =
        arkret_sdk::OperationId::new_v7_at(crate::clock::now_unix_ms()).into_string();
    let committed = submitter
        .submit_realm_bootstrap_durable(steps, idempotency_key, mls_creator_device)
        .await?;
    let realm_id = committed.realm_id.to_string();

    Ok(RealmCreateResult {
        ok: true,
        realm_id,
        first_commit: committed.first_commit,
        owner: actor_id.to_owned(),
        members: vec![actor_id.to_owned()],
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
    let event =
        build_space_create_event(realm_id, actor_id, title, summary, kind, parent_space_id)?;
    // The Space is named by its create Event, so its id exists only once that
    // Event has been authored and accepted. Reading it from the receipt is the
    // difference between naming the Space that was created and naming one that
    // never existed.
    let accepted = submitter.submit_sdk_event(&event).await?;
    let space_id =
        arkret_sdk::SpaceId::from_event_id(&arkret_sdk::EventId::new(accepted.event_id.clone())?)
            .into_string();

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
/// event via `ak.self.events.command.submit.v1`; deployment-local member REST shims are
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
    let member: arkret_sdk::ActorId = serde_json::from_str(member).map_err(|error| {
        anyhow::anyhow!("membership target must be a complete ActorId: {error}")
    })?;
    let event = build_member_state_transition_event(
        realm_id, actor_id, &member, from_state, to_state, reason,
    )?;
    // The CBS basis is resolved once, at the authoring boundary, from the Realm
    // Seal frontier. Post-bootstrap transitions (ban / kick / leave / unban)
    // carry effects and the server rejects effects-carrying Control Moves
    // without `seal_basis.leaves`; every caller here is an already-joined actor,
    // so that frontier is readable when the write is authored.
    submitter.submit_sdk_event(&event).await
}

// ── Space / Realm Management (all writes go through ak.self.events.command.submit.v1) ─

/// Replace the Realm display profile through its dedicated singleton facet.
/// Generic Realm patches are intentionally unsupported: title, summary and
/// avatar have exactly one wire carrier, `ak.realm.profile`.
pub async fn update_realm_metadata(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
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
    let event = build_realm_profile_update_event(realm_id, actor_id, digest_suite, profile)?;
    submitter.submit_sdk_event(&event).await
}

fn latest_realm_alias_payload(
    rows: &[arkret_wire::CommittedEventView],
) -> anyhow::Result<Option<Value>> {
    let mut latest = None;
    for row in rows {
        let Some(event) = row.reducer_input() else {
            continue;
        };
        if event.kind == arkret_sdk::EventKind::RealmAlias {
            let payload = serde_json::to_value(&event.payload)?;
            serde_json::from_value::<arkret_sdk::RealmAliasPayload>(payload.clone())?.validate()?;
            latest = Some(payload);
        }
    }
    Ok(latest)
}

/// Declare, rename, or tombstone the Realm alias with an exact CAS head.
///
/// The current value is folded from the accepted Realm Event log immediately
/// before authoring. The builder places that complete value in `head_eq`, so a
/// concurrent alias edit is rejected instead of overwriting a newer claim.
pub async fn set_realm_alias(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    alias: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let realm_id = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let rows = submitter
        .http()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            arkret_wire::CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            100,
        )
        .await?
        .committed_events;
    let current = latest_realm_alias_payload(&rows)?;
    let requested = alias.map(str::trim).filter(|alias| !alias.is_empty());
    let event = match (requested, current) {
        (Some(alias), Some(expected)) => {
            let service_id = submitter.service_did().await?;
            build_realm_alias_rename_event(
                realm_id.as_str(),
                actor_id,
                &service_id,
                alias,
                expected,
            )?
        }
        (Some(alias), None) => {
            let service_id = submitter.service_did().await?;
            build_realm_alias_event(realm_id.as_str(), actor_id, &service_id, alias)?
        }
        (None, Some(expected)) => {
            let payload =
                serde_json::from_value::<arkret_sdk::RealmAliasPayload>(expected.clone())?
                    .validate()?;
            if payload.alias().is_none() {
                anyhow::bail!("Realm alias is already absent");
            }
            build_realm_alias_tombstone_event(realm_id.as_str(), actor_id, expected)?
        }
        (None, None) => anyhow::bail!("Realm alias is already absent"),
    };
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

/// Set Realm join_rule, optionally tighten history_access, and optionally emit
/// `ak.realm.policy_bundle` for Join Policy gates.
pub async fn set_realm_policy_events(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
    join_rule: &str,
    tighten_history_access: bool,
    join_policy: Option<Value>,
) -> anyhow::Result<RealmPolicyResult> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for canonical Realm policy events"
        ));
    }
    let join_rule = validate_join_rule_v1(join_rule)?;
    // The facet writes are authored by the authenticated account, whose closed
    // AccountId the submitter captured; its Station is named explicitly.
    let station_id = submitter.authority()?.station_id.clone();
    let mut events = vec![build_realm_state_event_for_station::<
        arkret_sdk::event_spec::RealmJoinRule,
    >(
        station_id.clone(),
        realm_id,
        actor_id,
        digest_suite,
        arkret_sdk::RealmJoinRulePayload::new(parse_wire_enum::<arkret_sdk::RealmJoinRuleValue>(
            "join_rule",
            join_rule,
        )?),
    )?];
    if tighten_history_access {
        events.push(build_realm_state_event_for_station::<
            arkret_sdk::event_spec::RealmHistoryAccess,
        >(
            station_id.clone(),
            realm_id,
            actor_id,
            digest_suite,
            arkret_sdk::HistoryAccessPayload::tighten(),
        )?);
    }
    if let Some(join_policy) = join_policy {
        // `join_policy` is now a declared component of the closed bundle def,
        // so this write is a legal policy_bundle revision rather than an
        // unregistered extra key.
        //
        // The cell is sequenced state: this revision restates the complete
        // enabled component set, and anything omitted is cleared.
        let mut policy_bundle = recommended_realm_policy_bundle_value();
        policy_bundle.join_policy = Some(
            serde_json::from_value(join_policy)
                .map_err(|error| anyhow::anyhow!("invalid Realm join_policy: {error}"))?,
        );
        events.push(build_realm_state_event_for_station::<
            arkret_sdk::event_spec::RealmPolicyBundle,
        >(
            station_id,
            realm_id,
            actor_id,
            digest_suite,
            policy_bundle,
        )?);
    }
    for event in events {
        submitter.submit_sdk_event(&event).await?;
    }
    Ok(RealmPolicyResult {
        ok: true,
        realm_id: realm_id.to_owned(),
        join_rule: join_rule.to_owned(),
        history_access_tightened: tighten_history_access,
    })
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
    invitee: &arkret_sdk::AccountId,
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
    invitee: Option<&arkret_sdk::AccountId>,
    target_state: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::invite_revoke(
        realm_id,
        actor_id,
        invite_id,
        invitee,
        arkret_sdk::InviteRevokePreviousState::Pending,
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
        &arkret_sdk::ActorId::account(submitter.authority()?.clone()).to_string(),
        Some("join"),
        "leave",
        "self_leave",
    )
    .await
}

/// Rejoin the caller to the same Direct Conversation Realm through the narrow
/// `ak.member.rejoin.own` authority profile. MLS recovery then uses the normal
/// same-group Add/Welcome path; there is no dedicated repair carrier.
pub async fn rejoin_direct_conversation(
    submitter: &EventSubmitter,
    realm_id: &arkret_sdk::RealmId,
    actor_did: &arkret_sdk::Did,
) -> anyhow::Result<SubmitEventResult> {
    let actor_id = arkret_sdk::project_did_to_core_id(actor_did)?;
    transition_member_state(
        submitter,
        realm_id.as_str(),
        actor_id.as_str(),
        &arkret_sdk::ActorId::account(submitter.authority()?.clone()).to_string(),
        Some("leave"),
        "join",
        "direct_conversation_self_rejoin",
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
    let event = LocalOperation::new(build_realm_owner_transfer_control_intent(
        actor_id, payload,
    )?);
    submitter.submit_sdk_event(&event).await
}

/// Submit an independently confirmed authority-generation reset.
pub async fn reset_realm_authority(
    submitter: &EventSubmitter,
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityResetPayload,
) -> anyhow::Result<SubmitEventResult> {
    let event = LocalOperation::new(build_realm_authority_reset_control_intent(
        actor_id, payload,
    )?);
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
    let event = LocalOperation::new(build_capability_relinquish_control_intent(
        realm_id, subject_id, payload,
    )?);
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
// Setting / revoking Realm admins and sealing moderation decisions are
// self-authored protocol Moves submitted
// via `ak.self.events.command.submit.v1` (`POST /_arkret/self/events`) —
// mirroring `transition_member_state` / `ban_member`. P1 (capability)
// and P2 (moderation) projected the matching reducers in soland and the
// sodmin-side admin write paths were retired; these are the inkson-side
// submitters that drive them.

/// Grant Realm admin authority to `subject` by emitting a
/// `ak.capability.grant{actions:[ak.realm.admin], subject}` event.
/// The Grant id is derived from the accepted Event id. P1's
/// `apply_capability` folds this into the soland authz index, so subsequent
/// `ak.realm.admin` checks for `subject` pass. `root_basis` must come from the
/// verified authority-root current result, not the governance Station's
/// handoff bundle: those two generations have different lifecycles.
pub async fn grant_realm_admin(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    subject: &arkret_sdk::AccountId,
    root_basis: &ak_ops::IssuerRealmAuthorityBasis,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::capability_grant_actions(
        realm_id,
        actor_id,
        subject,
        &[CapabilityActionId::REALM_ADMIN],
        None,
        Value::Null,
        root_basis,
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
/// id is the reference later lift events resolve. `decision` is
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
/// `ak.moderation.decision.lift`. `target_ref` is the moderated target shared
/// with the original decision; `decision_ref` is the `ak:event:` id of the
/// decision being lifted. The lift names the decision Event directly: the
/// or_set observed-remove dot set it used to carry no longer exists.
pub async fn moderation_lift(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    target_ref: &str,
    decision_ref: &str,
    reason_code: &str,
) -> anyhow::Result<SubmitEventResult> {
    let realm = arkret_sdk::RealmId::new(realm_id.to_owned())?;
    let current = submitter.read_moderation_current(realm, target_ref).await?;
    let event = ak_ops::moderation_decision_lift(
        realm_id,
        actor_id,
        target_ref,
        decision_ref,
        reason_code,
        &current,
    )?
    .build_sdk_event("inkson")?;
    submitter.submit_sdk_event(&event).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    const ACTOR_ID: &str = "ak:did_core:web:alice.example";
    const SERVICE_DID: &str = "did:web:server.example";

    fn committed_row(event: arkret_sdk::Event) -> arkret_wire::CommittedEventView {
        let commit = arkret_wire::RealmCommit {
            commit_id: arkret_wire::RealmCommitId::from_digest([1; 32]),
            realm_id: event.realm_id.clone(),
            stream_ref: arkret_wire::CommitStreamRef::from_scope(
                &event.scope_ref,
                Some(event.realm_id.clone()),
            )
            .unwrap(),
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: arkret_wire::RealmCommitAuthorityRef::GenesisOrChangeEvent(
                arkret_wire::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [9; 32]),
            ),
            committed_at: chrono::DateTime::parse_from_rfc3339("2026-09-20T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            signature: arkret_wire::DetachedObjectSignature {
                context: arkret_wire::DetachedSignatureContext::RealmCommit,
                signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
                verification_method: arkret_wire::DidUrl::new("did:web:authority.example#key-1")
                    .unwrap(),
                signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "a".repeat(64)))
                    .unwrap(),
                created_at: chrono::DateTime::parse_from_rfc3339("2026-09-20T00:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                sig: arkret_wire::Base64UrlString::new("AA").unwrap(),
            },
        };
        arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView { commit, event })
    }

    #[test]
    fn latest_alias_payload_folds_accepted_declaration_and_tombstone() {
        let declaration =
            build_realm_alias_event(REALM_ID, ACTOR_ID, SERVICE_DID, "engineering").unwrap();
        let declaration_value = serde_json::to_value(declaration.payload()).unwrap();
        let tombstone =
            build_realm_alias_tombstone_event(REALM_ID, ACTOR_ID, declaration_value).unwrap();
        let rows = vec![
            committed_row(crate::operation::author_for_test(&declaration).into_event()),
            committed_row(crate::operation::author_for_test(&tombstone).into_event()),
        ];
        let latest = latest_realm_alias_payload(&rows)
            .unwrap()
            .expect("alias history has a current value");
        let payload = serde_json::from_value::<arkret_sdk::RealmAliasPayload>(latest).unwrap();
        assert!(payload.alias().is_none());
    }

    #[test]
    fn latest_alias_payload_ignores_unrelated_events() {
        let alias =
            build_realm_alias_event(REALM_ID, ACTOR_ID, SERVICE_DID, "engineering").unwrap();
        let unrelated =
            build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmProfile>(
                crate::test_support::core_id(crate::test_support::STATION_ID),
                REALM_ID,
                ACTOR_ID,
                arkret_sdk::DigestSuite::Sha256,
                arkret_sdk::RealmProfile::new("Engineering").unwrap(),
            )
            .unwrap();
        let latest = latest_realm_alias_payload(&[
            committed_row(crate::operation::author_for_test(&alias).into_event()),
            committed_row(crate::operation::author_for_test(&unrelated).into_event()),
        ])
        .unwrap()
        .expect("alias remains current");
        let payload = serde_json::from_value::<arkret_sdk::RealmAliasPayload>(latest).unwrap();
        assert_eq!(
            payload.alias().map(arkret_sdk::RealmAlias::canonical),
            Some("engineering:server.example")
        );
    }

    #[test]
    fn realm_profile_replacement_is_a_closed_typed_event_without_producer_ordering() {
        let replacement = build_realm_profile_replacement_event(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Platform").unwrap(),
        )
        .unwrap();
        let authored = crate::operation::author_for_test(&replacement);
        assert_eq!(authored.kind, arkret_sdk::EventKind::RealmProfile);
        let profile = serde_json::from_value::<arkret_sdk::RealmProfile>(Value::Object(
            authored.payload.clone().into_iter().collect(),
        ))
        .unwrap();
        assert_eq!(profile.title, "Platform");

        let envelope = serde_json::to_value(authored.event()).unwrap();
        assert!(
            arkret_wire::forbidden_wire::forbidden_wire_violation(
                "event_envelope",
                "*",
                &envelope,
            )
            .is_none(),
            "profile producer Event must not carry retired ordering coordinates"
        );
    }

    #[test]
    fn realm_profile_update_ui_emits_the_same_closed_replacement_carrier() {
        let update = build_realm_profile_update_event(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Product").unwrap(),
        )
        .unwrap();
        let event = crate::operation::author_for_test(&update);
        assert_eq!(event.kind, arkret_sdk::EventKind::RealmProfile);
        assert_eq!(event.payload["title"], serde_json::json!("Product"));
    }
}
