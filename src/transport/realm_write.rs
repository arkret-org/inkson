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

use crate::event_builders::{
    build_capability_relinquish_control_intent, build_member_state_transition_event,
    build_plaintext_visible_services_event, build_realm_alias_event,
    build_realm_alias_rename_event, build_realm_alias_tombstone_event, build_realm_archive_event,
    build_realm_authority_reset_control_intent, build_realm_bootstrap_steps_for_principal_server,
    build_realm_destroy_event, build_realm_owner_transfer_control_intent,
    build_realm_profile_replacement_event, build_realm_state_event, build_space_create_event,
    build_space_lifecycle_event, parse_wire_enum, recommended_realm_policy_bundle_value,
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
    encryption_profile: &str,
    security_class: &str,
    federation_policy: &str,
    digest_algorithm: &str,
    trust_domain: &str,
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
    let principal_server_id = submitter.authority()?.principal_server_id.clone();
    let notary_did = submitter.service_did().await?;
    let described_server_id =
        arkret_sdk::project_did_to_core_id(&arkret_sdk::Did::new(notary_did.clone())?)?;
    if described_server_id != principal_server_id {
        anyhow::bail!(
            "authenticated Principal Server authority does not match the current service description"
        );
    }
    let notary = submitter.current_service_notary().await?;
    let notary_service_origin = submitter.http().base_url().origin().ascii_serialization();
    // One CSPRNG salt belongs to this creation intent. The complete unsigned
    // unit is durably queued before prepare/sign; Garth then persists the
    // exact signed unit before the first HTTP write.
    let genesis_salt = arkret_sdk::GenesisSalt::generate()?;
    // The Realm id is not minted here: it is derived from the genesis Event
    // the builder produces (spec realm-and-space.md section 2.5.0).
    let steps = build_realm_bootstrap_steps_for_principal_server(
        principal_server_id,
        genesis_salt,
        actor_id,
        &notary_did,
        notary,
        &notary_service_origin,
        title,
        summary,
        discoverability,
        join_rule,
        history_access,
        encryption_profile,
        security_class,
        federation_policy,
        digest_algorithm,
        trust_domain,
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
        .submit_realm_bootstrap_durable(steps, idempotency_key)
        .await?
        .to_string();

    Ok(RealmCreateResult {
        ok: true,
        realm_id,
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
    let event = build_member_state_transition_event(
        realm_id, actor_id, member, from_state, to_state, reason,
    )?;
    // The CBA basis is resolved once, at the authoring boundary, from the Realm
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
    let rows = submitter
        .http()
        .events_read_all_pages(realm_id)
        .await?
        .events;
    let expected_head = settled_realm_profile_payload(&rows)?;
    let event = build_realm_profile_replacement_event(
        realm_id,
        actor_id,
        digest_suite,
        profile,
        expected_head,
    )?;
    submitter.submit_sdk_event(&event).await
}

fn settled_realm_profile_payload(rows: &[arkret_sdk::EventReadRow]) -> anyhow::Result<Value> {
    let cell = arkret_wire::REALM_PROFILE_CELL;
    let mut current = Value::Null;
    let mut found = false;

    for row in rows {
        let event = match row {
            arkret_sdk::EventReadRow::Event(event) => event,
            arkret_sdk::EventReadRow::Redacted(view)
                if view.kind == arkret_sdk::EventKind::RealmProfile =>
            {
                anyhow::bail!(
                    "Realm profile Event {} is redacted; an exact CAS head cannot be authored",
                    view.event_id
                );
            }
            arkret_sdk::EventReadRow::ReferenceLocked(stub)
                if stub.kind == Some(arkret_sdk::EventKind::RealmProfile) =>
            {
                anyhow::bail!(
                    "a Realm profile Event is reference-locked; an exact CAS head cannot be authored"
                );
            }
            arkret_sdk::EventReadRow::Redacted(_)
            | arkret_sdk::EventReadRow::ReferenceLocked(_) => continue,
        };
        if event.kind != arkret_sdk::EventKind::RealmProfile {
            continue;
        }
        let payload = serde_json::to_value(&event.payload)?;
        let typed = serde_json::from_value::<arkret_sdk::RealmProfile>(payload.clone())?;
        if typed.schema != arkret_wire::SchemaId::REALM_PROFILE_V1 || typed.title.is_empty() {
            anyhow::bail!(
                "accepted Realm profile Event {} has an invalid payload",
                event.event_id
            );
        }
        let matching: Vec<_> = event
            .preconditions
            .iter()
            .filter(|guard| guard.cell.as_str() == cell)
            .collect();
        let [guard] = matching.as_slice() else {
            anyhow::bail!(
                "Realm profile Event {} must carry exactly one head_eq guard for {cell}",
                event.event_id
            );
        };
        if guard.predicate.op != arkret_sdk::PredicateOp::HeadEq
            || guard.predicate.value.as_ref() != Some(&current)
        {
            anyhow::bail!(
                "Realm profile history is not a single CAS chain at Event {}; conflict recovery is required",
                event.event_id
            );
        }
        current = payload;
        found = true;
    }

    if !found {
        anyhow::bail!("Realm profile is missing from the accepted Realm history");
    }
    Ok(current)
}

fn latest_realm_alias_payload(rows: &[arkret_sdk::EventReadRow]) -> anyhow::Result<Option<Value>> {
    let mut latest = None;
    for row in rows {
        let Some(event) = row.event() else {
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
    let rows = submitter
        .http()
        .events_read_all_pages(realm_id)
        .await?
        .events;
    let current = latest_realm_alias_payload(&rows)?;
    let requested = alias.map(str::trim).filter(|alias| !alias.is_empty());
    let event = match (requested, current) {
        (Some(alias), Some(expected)) => {
            let service_id = submitter.service_did().await?;
            build_realm_alias_rename_event(realm_id, actor_id, &service_id, alias, expected)?
        }
        (Some(alias), None) => {
            let service_id = submitter.service_did().await?;
            build_realm_alias_event(realm_id, actor_id, &service_id, alias)?
        }
        (None, Some(expected)) => {
            let payload =
                serde_json::from_value::<arkret_sdk::RealmAliasPayload>(expected.clone())?
                    .validate()?;
            if payload.alias().is_none() {
                anyhow::bail!("Realm alias is already absent");
            }
            build_realm_alias_tombstone_event(realm_id, actor_id, expected)?
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
    let Some(event) = build_plaintext_visible_services_event(realm_id, actor_id, &services)? else {
        anyhow::bail!("plaintext_visible_services update requires at least one service DID");
    };
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
    preserve_recommended_encryption_floor: bool,
) -> anyhow::Result<RealmPolicyResult> {
    let actor_id = actor_id.trim();
    if actor_id.is_empty() {
        return Err(anyhow::anyhow!(
            "actor_id is required for canonical Realm policy events"
        ));
    }
    let join_rule = validate_join_rule_v1(join_rule)?;
    let mut events = vec![build_realm_state_event::<
        arkret_sdk::event_spec::RealmJoinRule,
    >(
        realm_id,
        actor_id,
        digest_suite,
        arkret_sdk::RealmJoinRulePayload::new(parse_wire_enum::<arkret_sdk::RealmJoinRuleValue>(
            "join_rule",
            join_rule,
        )?),
    )?];
    if tighten_history_access {
        events.push(build_realm_state_event::<
            arkret_sdk::event_spec::RealmHistoryAccess,
        >(
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
        // The cell is a `cas_register`: this revision restates the COMPLETE
        // enabled component set, and anything omitted is cleared. Starting from
        // the recommended genesis bundle keeps the encryption floors.
        let mut policy_bundle = recommended_realm_policy_bundle_value();
        if !preserve_recommended_encryption_floor {
            policy_bundle.content_encryption_floor = None;
            policy_bundle.metadata_encryption_floor = None;
        }
        policy_bundle.join_policy = Some(
            serde_json::from_value(join_policy)
                .map_err(|error| anyhow::anyhow!("invalid Realm join_policy: {error}"))?,
        );
        events.push(build_realm_state_event::<
            arkret_sdk::event_spec::RealmPolicyBundle,
        >(realm_id, actor_id, digest_suite, policy_bundle)?);
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
        actor_id.as_str(),
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
// Setting / revoking Realm admins, sealing moderation decisions, and
// running the appeal loop are now self-authored protocol Moves submitted
// via `ak.self.events.command.submit.v1` (`POST /_arkret/self/events`) —
// mirroring `transition_member_state` / `ban_member`. P1 (capability)
// and P2 (moderation) projected the matching reducers in soland and the
// sodmin-side admin write paths were retired; these are the inkson-side
// submitters that drive them.

/// Grant Realm admin authority to `subject` by emitting a
/// `ak.capability.grant{actions:[ak.realm.admin], subject}` event.
/// The Grant id is derived from the accepted Event id. P1's
/// `apply_capability` folds this into the soland authz index, so subsequent
/// `ak.realm.admin` checks for `subject` pass. `root_basis` is the caller's
/// resolved authority-root coordinates
/// (`IssuerRootBasis::from_resolved_root`) the grant's `realm_root` issuer
/// authority binds to.
pub async fn grant_realm_admin(
    submitter: &EventSubmitter,
    realm_id: &str,
    actor_id: &str,
    subject: &str,
    root_basis: ak_ops::IssuerRootBasis,
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
    decision: &str,
    reason_text_ref: &str,
    modify_decision_ref: Option<&str>,
) -> anyhow::Result<SubmitEventResult> {
    let event = ak_ops::moderation_appeal_decision(
        realm_id,
        actor_id,
        appeal_id,
        decision,
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
            .build_sdk_event("inkson")?
            .into_intent();
    let (realm_id_owned, actor_id_owned) = (realm_id.to_owned(), actor_id.to_owned());
    let (appeal_id, target_ref_owned, decision_ref_owned, appeal_reason_text_ref) = (
        appeal_id.to_owned(),
        target_ref.to_owned(),
        decision_ref.to_owned(),
        appeal_reason_text_ref.to_owned(),
    );
    let authored = submitter
        .author_event_unit(vec![
            Box::new(move |_| Ok(vec![new_decision])),
            Box::new(move |authored| {
                // `modify_decision_ref` is the replacement decision's own Event
                // id; the reducer cross-checks it, so it can only be read after
                // that Event is authored.
                let new_decision_id = authored
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("appeal modify needs its replacement decision"))?
                    .event_id()
                    .to_string();
                Ok(vec![
                    ak_ops::moderation_appeal_decision(
                        &realm_id_owned,
                        &actor_id_owned,
                        &appeal_id,
                        "modify",
                        &appeal_reason_text_ref,
                        Some(&new_decision_id),
                    )?
                    .build_sdk_event("inkson")?
                    .into_intent(),
                    ak_ops::moderation_decision_lift(
                        &realm_id_owned,
                        &actor_id_owned,
                        &target_ref_owned,
                        &decision_ref_owned,
                        "appeal_modify",
                    )?
                    .build_sdk_event("inkson")?
                    .into_intent(),
                ])
            }),
        ])
        .await?;
    let new_decision_id = authored[0].event_id().to_string();
    let result = submitter
        .submit_signed_sdk_events_batch(&authored, None)
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
    events: Vec<crate::operation::LocalOperation>,
) -> anyhow::Result<arkret_sdk::EventsSubmitOutcome> {
    submitter
        .submit_sdk_events_batch(
            _realm_id,
            events
                .into_iter()
                .map(crate::operation::LocalOperation::into_intent)
                .collect(),
            None,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    const REALM_ID: &str = "ak:realm:AT3p9polsnQ_WOix32QZimMdE2zPe62HptJu2PaO3V1h";
    const ACTOR_ID: &str = "ak:did_core:web:alice.example";
    const SERVICE_DID: &str = "did:web:server.example";

    #[test]
    fn latest_alias_payload_folds_accepted_declaration_and_tombstone() {
        let declaration =
            build_realm_alias_event(REALM_ID, ACTOR_ID, SERVICE_DID, "engineering").unwrap();
        let declaration_value = serde_json::to_value(declaration.payload()).unwrap();
        let tombstone =
            build_realm_alias_tombstone_event(REALM_ID, ACTOR_ID, declaration_value).unwrap();
        let rows = vec![
            arkret_sdk::EventReadRow::Event(
                crate::operation::author_for_test(&declaration).into_event(),
            ),
            arkret_sdk::EventReadRow::Event(
                crate::operation::author_for_test(&tombstone).into_event(),
            ),
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
        let unrelated = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Engineering").unwrap(),
        )
        .unwrap();
        let latest = latest_realm_alias_payload(&[
            arkret_sdk::EventReadRow::Event(crate::operation::author_for_test(&alias).into_event()),
            arkret_sdk::EventReadRow::Event(
                crate::operation::author_for_test(&unrelated).into_event(),
            ),
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
    fn realm_profile_replacement_chains_from_the_complete_current_value() {
        let initial = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Engineering").unwrap(),
        )
        .unwrap();
        let initial_row = arkret_sdk::EventReadRow::Event(
            crate::operation::author_for_test(&initial).into_event(),
        );
        let expected = settled_realm_profile_payload(std::slice::from_ref(&initial_row)).unwrap();

        let replacement = build_realm_profile_replacement_event(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Platform").unwrap(),
            expected.clone(),
        )
        .unwrap();

        let [guard] = replacement.intent().preconditions() else {
            panic!("profile replacement must carry one exact CAS guard");
        };
        assert_eq!(guard.cell.as_str(), arkret_wire::REALM_PROFILE_CELL);
        assert_eq!(guard.predicate.op, arkret_sdk::PredicateOp::HeadEq);
        assert_eq!(guard.predicate.value.as_ref(), Some(&expected));

        let rows = vec![
            initial_row,
            arkret_sdk::EventReadRow::Event(
                crate::operation::author_for_test(&replacement).into_event(),
            ),
        ];
        assert_eq!(
            settled_realm_profile_payload(&rows).unwrap()["title"],
            serde_json::json!("Platform")
        );
    }

    #[test]
    fn realm_profile_history_rejects_a_replacement_without_a_cas_guard() {
        let initial = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Engineering").unwrap(),
        )
        .unwrap();
        let unguarded = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::DigestSuite::Sha256,
            arkret_sdk::RealmProfile::new("Platform").unwrap(),
        )
        .unwrap();
        let mut unguarded_event = crate::operation::author_for_test(&unguarded).into_event();
        unguarded_event.preconditions.clear();
        let rows = vec![
            arkret_sdk::EventReadRow::Event(
                crate::operation::author_for_test(&initial).into_event(),
            ),
            arkret_sdk::EventReadRow::Event(unguarded_event),
        ];

        let error = settled_realm_profile_payload(&rows).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("must carry exactly one head_eq guard"),
            "{error:#}"
        );
    }
}
