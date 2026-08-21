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
use serde_json::{Value, json};

use crate::event_builders::{
    build_capability_relinquish_control_intent, build_member_state_transition_event,
    build_plaintext_visible_services_event, build_realm_alias_event,
    build_realm_alias_rename_event, build_realm_alias_tombstone_event, build_realm_archive_event,
    build_realm_authority_basis_update_control_intent, build_realm_authority_reset_control_intent,
    build_realm_bootstrap_steps, build_realm_destroy_event,
    build_realm_history_sharing_policy_event, build_realm_owner_transfer_control_intent,
    build_realm_state_event, build_space_create_event, build_space_lifecycle_event,
    parse_realm_bootstrap_members, recommended_history_sharing_policy_for_visibility,
    recommended_realm_policy_bundle_value,
};
use crate::event_submit::EventSubmitter;
use crate::models::{RealmCreateResult, RealmPolicyResult, SpaceCreateResult, SubmitEventResult};
use crate::operation::{EventKind, LocalOperation, ak_ops};
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
    let notary_did = submitter.service_full_id().await?;
    let notary_service_origin = submitter.http().base_url().origin().ascii_serialization();
    let resolved_invitees = parse_realm_bootstrap_members(&invitees)?;
    if resolved_invitees
        .iter()
        .any(|invitee| invitee.actor_id != actor_id)
    {
        anyhow::bail!(
            "Realm bootstrap invitees omit service_resolution; create the Realm first, then invite with a principal locator"
        );
    }
    // One CSPRNG salt belongs to this creation intent. The complete unsigned
    // unit is durably queued before prepare/sign; Garth then persists the
    // exact signed unit before the first HTTP write.
    let genesis_salt = arkret_sdk::GenesisSalt::generate()?;
    // The Realm id is not minted here: it is derived from the genesis Event
    // the builder produces (spec realm-and-space.md section 2.5.0).
    let steps = build_realm_bootstrap_steps(
        genesis_salt,
        actor_id,
        &notary_did,
        &notary_service_origin,
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
        .submit_realm_bootstrap_durable(steps, idempotency_key)
        .await?
        .to_string();

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
    let event = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
        realm_id, actor_id, profile,
    )?
    // The bootstrap builder uses a null-head guard. A later replacement is
    // authorized against the current Realm Seal frontier instead, which the
    // authoring boundary resolves.
    .without_preconditions();
    submitter.submit_sdk_event(&event).await
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
            let service_id = submitter.service_full_id().await?;
            build_realm_alias_rename_event(realm_id, actor_id, &service_id, alias, expected)?
        }
        (Some(alias), None) => {
            let service_id = submitter.service_full_id().await?;
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
            arkret_sdk::StatePayload {
                value: Some(serde_json::to_value(join_rule)?),
                state: None,
                reason: None,
            },
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

/// Build the exact repair route from the resolver coordinates and the peer's
/// delivery binding. `peer_service_id` is the accepted Contact record's
/// `peer_service_id` — the same delivery-binding source the source Principal
/// Server resolves the relay destination from, so the planner can verify the
/// returned `destination_service_id` against it. A pair whose Contact does not
/// expose the peer Principal Server fails closed here: the client never
/// invents a destination route.
pub(crate) fn direct_conversation_repair_route(
    resolve: &arkret_sdk::DirectConversationResolveOutcome,
    source_service_id: arkret_sdk::DidCoreId,
    peer_service_id: Option<arkret_sdk::DidCoreId>,
    target_keypackage_ref: arkret_sdk::NonEmptyString,
) -> anyhow::Result<garth::DirectConversationRepairRoute> {
    let coordinates = resolve.coordinates().cloned().ok_or_else(|| {
        anyhow::anyhow!("Direct Conversation repair requires resolved coordinates")
    })?;
    if coordinates.binding_event_ref.is_none() {
        anyhow::bail!("Direct Conversation repair requires an accepted binding coordinate");
    }
    let target_service_id = peer_service_id.ok_or_else(|| {
        anyhow::anyhow!(
            "Direct Conversation repair requires the accepted Contact's peer delivery binding \
             to expose the peer Principal Server (target_service_id); refusing to invent a route"
        )
    })?;
    Ok(garth::DirectConversationRepairRoute {
        source_service_id,
        target_service_id,
        coordinates,
        target_keypackage_ref,
    })
}

/// Persist the Garth repair snapshot and wait for the durable-state barrier.
async fn persist_direct_conversation_repair(
    mut state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    planner: &garth::DirectConversationRepairPlanner,
) -> anyhow::Result<String> {
    use dioxus::prelude::{ReadableExt, WritableExt};
    let request_id = state_store
        .write()
        .save_direct_conversation_repair(planner)?;
    let barrier = state_store.read().begin_durable_flush()?;
    barrier.wait().await?;
    Ok(request_id)
}

/// Run the requester side of replacement repair through durable target
/// enqueue. The accepted self-rejoin Event and the resolver's current
/// whole-value digest author the exact request; every ambiguous retry reuses
/// the Garth-retained canonical bytes. No remote endpoint or resolution record
/// is persisted by the client.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_direct_conversation_repair(
    submitter: &EventSubmitter,
    http: &arkret_sdk::http_client::Client,
    state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    resolve: &arkret_sdk::DirectConversationResolveOutcome,
    requester_principal_id: arkret_sdk::DidCoreId,
    requester_full_id: &arkret_sdk::DidFullId,
    requester_device_id: arkret_sdk::DeviceId,
    source_service_id: arkret_sdk::DidCoreId,
    peer_service_id: Option<arkret_sdk::DidCoreId>,
    target_keypackage_ref: arkret_sdk::NonEmptyString,
) -> anyhow::Result<String> {
    let requester_full = arkret_sdk::DidFullId::new(requester_full_id.as_str().to_owned())?;
    if arkret_sdk::project_full_id_to_core_id(&requester_full)? != requester_principal_id {
        anyhow::bail!("repair requester full_id does not project to requester principal core_id");
    }
    // Fail closed on a missing peer Principal Server before anything is
    // authored or persisted.
    let route = direct_conversation_repair_route(
        resolve,
        source_service_id,
        peer_service_id,
        target_keypackage_ref.clone(),
    )?;
    let coordinates = route.coordinates.clone();
    let active_value_digest =
        crate::transport::account::direct_conversation_current_generation_value_digest(resolve)?;
    crate::transport::account::direct_conversation_history_sharing_policy()?;

    let rejoin = build_member_state_transition_event(
        coordinates.realm_id.as_str(),
        requester_principal_id.as_str(),
        requester_principal_id.as_str(),
        Some("leave"),
        "join",
        "direct_conversation_self_rejoin",
    )?;
    let rejoin = rejoin.with_authorization_ref(
        arkret_sdk::AuthorizationRef::new(
            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_REPAIR_V1.to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
    );
    // Resolve every fallible/remote signing prerequisite before authoring the
    // self-rejoin. Once that Event is accepted, freezing and persisting the
    // request is a synchronous local critical section with no network await.
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("Direct Conversation repair requires an active signer"))?;
    if signer.device_id() != Some(requester_device_id.as_str()) {
        anyhow::bail!("active signer is not bound to the repair requester device");
    }
    let verification_method = signer.verification_method_for_principal(requester_full_id)?;
    let device_authorize_event_id =
        crate::mls::admission::current_requester_device_authorize_event_id(
            http,
            requester_device_id.as_str(),
        )
        .await
        .map_err(anyhow::Error::msg)?;
    let request_id = arkret_sdk::Base64UrlString::new(crate::random::base64url_token(
        32,
        "generate Direct Conversation repair request id",
    )?)
    .map_err(anyhow::Error::msg)?;
    let accepted = submitter.submit_sdk_event(&rejoin).await?;
    let rejoin_event_id = arkret_sdk::EventId::new(accepted.event_id)?;
    let created_at = crate::clock::now_utc_canonical();
    let acceptance = garth::SelfRejoinAcceptance {
        realm_id: coordinates.realm_id.clone(),
        requester_principal_id: requester_principal_id.clone(),
        rejoin_event_id: rejoin_event_id.clone(),
        accepted_at: created_at,
    };
    let content = arkret_sdk::MemberRepairRequestPayload {
        realm_id: coordinates.realm_id.clone(),
        requester_principal_id: requester_principal_id.clone(),
        requester: arkret_sdk::MemberRepairRequester::Device {
            requester_device_id: requester_device_id.clone(),
        },
        requester_keypackage_ref: target_keypackage_ref.clone(),
        observed_active_generation_value_digest: active_value_digest,
        rejoin_event_id,
        created_at,
    };
    let mut planner = garth::DirectConversationRepairPlanner::new(route)?;
    planner.observe_self_rejoin_accepted(acceptance, content.clone())?;

    let signed_at = crate::clock::now_utc_canonical();
    let mut request = arkret_sdk::DirectConversationRepairDispatchRequest {
        request_id,
        content,
        requester_authorization: arkret_sdk::DirectConversationRepairAuthorization::Device {
            requester_device_id,
            verification_method: verification_method.clone(),
            device_authorize_event_id,
            signed_at,
            signature: arkret_sdk::ProtocolSignature {
                verification_method: verification_method.clone(),
                created_at: signed_at,
                jws: arkret_sdk::Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
            },
        },
    };
    let signing_input = request.signing_input()?;
    let signature = arkret_sdk::Base64UrlString::new(arkret_sdk::base64url_encode(
        signer.sign_raw(&signing_input)?,
    ))
    .map_err(anyhow::Error::msg)?;
    if let arkret_sdk::DirectConversationRepairAuthorization::Device {
        signature: proof, ..
    } = &mut request.requester_authorization
    {
        proof.jws = signature;
    }
    planner.freeze_signed_request(request.clone())?;
    let request_id = persist_direct_conversation_repair(state_store, &planner).await?;

    let outcome = match crate::transport::account::direct_conversation_repair_dispatch(
        http, &request,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            planner.record_dispatch_failure(error.to_string())?;
            persist_direct_conversation_repair(state_store, &planner).await?;
            return Err(error);
        }
    };
    planner.record_enqueue_outcome(outcome)?;
    persist_direct_conversation_repair(state_store, &planner).await?;
    planner.confirm_enqueue_outcome_durable()?;
    persist_direct_conversation_repair(state_store, &planner).await?;
    Ok(request_id)
}

/// Resume a frozen dispatch after restart or an ambiguous transport failure.
/// The request is loaded from durable state; callers cannot supply rebuilt
/// fields, and the planner rechecks the retained canonical bytes before send.
pub async fn retry_direct_conversation_repair_dispatch(
    http: &arkret_sdk::http_client::Client,
    state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    request_id: &str,
) -> anyhow::Result<()> {
    use dioxus::prelude::ReadableExt;
    let mut planner = state_store
        .read()
        .direct_conversation_repair(request_id)?
        .ok_or_else(|| anyhow::anyhow!("unknown Direct Conversation repair request"))?;
    if !matches!(
        planner.stage(),
        garth::DirectConversationRepairStage::DispatchFrozen
            | garth::DirectConversationRepairStage::DispatchRetryable
    ) {
        anyhow::bail!("Direct Conversation repair is not awaiting dispatch retry");
    }
    let request = planner
        .snapshot()
        .frozen_dispatch
        .ok_or_else(|| anyhow::anyhow!("repair retry has no frozen dispatch"))?
        .request;
    planner.exact_retry_bytes(&request)?;
    let outcome = match crate::transport::account::direct_conversation_repair_dispatch(
        http, &request,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            planner.record_dispatch_failure(error.to_string())?;
            persist_direct_conversation_repair(state_store, &planner).await?;
            return Err(error);
        }
    };
    planner.record_enqueue_outcome(outcome)?;
    persist_direct_conversation_repair(state_store, &planner).await?;
    planner.confirm_enqueue_outcome_durable()?;
    persist_direct_conversation_repair(state_store, &planner).await?;
    Ok(())
}

/// Assemble the replacement-generation activation payload for a repair whose
/// exact Welcome is durably consumed. Every member comes from an accepted
/// authority: the frozen resolver digest is the CAS predecessor, the current
/// generation number is read from the accepted activation Event the resolver
/// names, and the replacement group's genesis / selected state refs come from
/// the accepted Event log plus the locally joined MLS snapshot. Any missing or
/// ambiguous input fails closed — nothing is reconstructed from coordinates.
pub async fn prepare_direct_conversation_repair_activation(
    submitter: &EventSubmitter,
    state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    request_id: &str,
    resolve: &arkret_sdk::DirectConversationResolveOutcome,
) -> anyhow::Result<arkret_sdk::DirectConversationMlsGenerationActivatePayload> {
    use dioxus::prelude::ReadableExt;
    let (coordinates, frozen_digest, group_id, selected_group_state_ref) = {
        let store = state_store.read();
        let planner = store
            .direct_conversation_repair(request_id)?
            .ok_or_else(|| anyhow::anyhow!("unknown Direct Conversation repair request"))?;
        if planner.stage() != garth::DirectConversationRepairStage::WelcomeDurable {
            anyhow::bail!(
                "replacement activation requires the exact repair Welcome to be durably consumed"
            );
        }
        let snapshot = planner.snapshot();
        let frozen_digest = snapshot
            .expected_content
            .as_ref()
            .map(|content| content.observed_active_generation_value_digest.clone())
            .ok_or_else(|| anyhow::anyhow!("repair snapshot lost its frozen request content"))?;
        let coordinates = snapshot.route.coordinates.clone();
        let mls = store
            .mls_snapshot_for(coordinates.realm_id.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "replacement activation requires the locally joined replacement MLS group snapshot"
                )
            })?;
        let selected = store
            .mls_group_state_ref_for_effective_scope(
                coordinates.realm_id.as_str(),
                None,
                &mls.group_id,
                mls.epoch,
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        (coordinates, frozen_digest, mls.group_id, selected)
    };
    // The current cell value must still be the one the request froze;
    // otherwise the repair is stale and the payload must not be authored.
    let current_digest =
        crate::transport::account::direct_conversation_current_generation_value_digest(resolve)?;
    if current_digest != frozen_digest {
        anyhow::bail!(
            "current active-generation digest differs from the frozen repair predecessor; the repair observation is stale"
        );
    }
    let active_generation_ref =
        crate::transport::account::direct_conversation_current_generation_ref(resolve)?;
    let events = submitter
        .backfill(coordinates.realm_id.as_str())
        .await?
        .complete_events("Direct Conversation repair activation")?;
    direct_conversation_repair_activation_from_events(
        &events,
        &coordinates,
        &active_generation_ref,
        frozen_digest,
        &group_id,
        selected_group_state_ref,
    )
}

/// Pure assembly half of [`prepare_direct_conversation_repair_activation`]:
/// derive the replacement activation payload from the accepted Event log.
fn direct_conversation_repair_activation_from_events(
    events: &[arkret_sdk::Event],
    coordinates: &arkret_sdk::DirectConversationCoordinates,
    active_generation_ref: &arkret_sdk::EventId,
    predecessor_active_value_digest: arkret_sdk::Hash,
    replacement_group_id: &str,
    selected_group_state_ref: arkret_sdk::EventId,
) -> anyhow::Result<arkret_sdk::DirectConversationMlsGenerationActivatePayload> {
    let current = events
        .iter()
        .find(|event| &event.event_id == active_generation_ref)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "resolver active-generation Event {active_generation_ref} is not in the accepted Realm event log"
            )
        })?;
    if current.kind != arkret_sdk::EventKind::DirectConversationMlsGenerationActivate
        || current.realm_id != coordinates.realm_id
    {
        anyhow::bail!(
            "resolver active-generation ref does not name an accepted activation Event of this Realm"
        );
    }
    let current_payload = serde_json::from_value::<
        arkret_sdk::DirectConversationMlsGenerationActivatePayload,
    >(serde_json::to_value(&current.payload)?)
    .map_err(|error| anyhow::anyhow!("accepted active-generation payload is invalid: {error}"))?;
    if current_payload.pair_key != coordinates.pair_key
        || current_payload.main_strand_id != coordinates.main_strand_id
    {
        anyhow::bail!("accepted active-generation Event does not match the repair coordinates");
    }
    if current_payload.mls_group_id.as_str() == replacement_group_id {
        anyhow::bail!(
            "local MLS group is still the current active generation's group; there is no replacement to activate"
        );
    }
    let mls_generation = current_payload
        .mls_generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("replacement generation number overflows"))?;
    let genesis_ids = events
        .iter()
        .filter(|event| {
            event.kind == arkret_sdk::EventKind::MlsGenesis
                && event.realm_id == coordinates.realm_id
                && event.payload.get("mls_group_id").and_then(Value::as_str)
                    == Some(replacement_group_id)
        })
        .map(|event| event.event_id.clone())
        .collect::<Vec<_>>();
    let [genesis_event_ref] = genesis_ids.as_slice() else {
        anyhow::bail!(
            "replacement group requires exactly one accepted ak.mls.genesis in the Realm log; found {}",
            genesis_ids.len()
        );
    };
    let payload = arkret_sdk::DirectConversationMlsGenerationActivatePayload {
        pair_key: coordinates.pair_key.clone(),
        mls_generation,
        phase: arkret_sdk::DirectConversationMlsGenerationPhase::ExactPair,
        mls_group_id: arkret_sdk::MlsGroupId::new(replacement_group_id.to_owned())
            .map_err(anyhow::Error::msg)?,
        genesis_event_ref: genesis_event_ref.clone(),
        selected_group_state_ref: arkret_sdk::NonEmptyString::new(
            selected_group_state_ref.as_str().to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        main_strand_id: coordinates.main_strand_id.clone(),
        predecessor_active_value_digest: Some(predecessor_active_value_digest),
    };
    payload.validate()?;
    Ok(payload)
}

/// Author replacement-generation activation only after the exact repair
/// Welcome was consumed and durably recorded. The predecessor remains the
/// resolver-provided whole current-cell value digest frozen in the request.
pub async fn activate_direct_conversation_repair(
    submitter: &EventSubmitter,
    state_store: dioxus::prelude::SyncSignal<crate::state::LocalStateStore>,
    request_id: &str,
    actor_id: &arkret_sdk::DidCoreId,
    payload: arkret_sdk::DirectConversationMlsGenerationActivatePayload,
) -> anyhow::Result<SubmitEventResult> {
    use dioxus::prelude::{ReadableExt, WritableExt};
    let planner = state_store
        .read()
        .direct_conversation_repair(request_id)?
        .ok_or_else(|| anyhow::anyhow!("unknown Direct Conversation repair request"))?;
    if planner.stage() != garth::DirectConversationRepairStage::WelcomeDurable {
        anyhow::bail!("replacement generation cannot activate before exact Welcome consumption");
    }
    let snapshot = planner.snapshot();
    if snapshot
        .expected_content
        .as_ref()
        .is_none_or(|content| &content.requester_principal_id != actor_id)
    {
        anyhow::bail!("replacement activation actor differs from the frozen repair requester");
    }
    let expected = snapshot
        .expected_content
        .as_ref()
        .map(|content| &content.observed_active_generation_value_digest);
    if payload.pair_key != snapshot.route.coordinates.pair_key
        || payload.main_strand_id != snapshot.route.coordinates.main_strand_id
        || payload.predecessor_active_value_digest.as_ref() != expected
    {
        anyhow::bail!(
            "replacement activation differs from frozen repair coordinates or CAS digest"
        );
    }
    payload.validate()?;
    let event =
        build_realm_state_event::<arkret_sdk::event_spec::DirectConversationMlsGenerationActivate>(
            snapshot.route.coordinates.realm_id.as_str(),
            actor_id.as_str(),
            payload,
        )?;
    let event = event.with_authorization_ref(
        arkret_sdk::AuthorizationRef::new(
            arkret_wire::AuthoritySourceId::DIRECT_CONVERSATION_REPAIR_V1.to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
    );
    let result = submitter.submit_sdk_event(&event).await?;
    {
        let mut state_store = state_store;
        state_store
            .write()
            .record_direct_conversation_repair_activation(
                request_id,
                arkret_sdk::EventId::new(result.event_id.clone())?,
            )?;
    }
    let barrier = state_store.read().begin_durable_flush()?;
    barrier.wait().await?;
    Ok(result)
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

/// Submit an explicit capability registry basis adoption.
pub async fn update_realm_authority_basis(
    submitter: &EventSubmitter,
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityBasisUpdatePayload,
) -> anyhow::Result<SubmitEventResult> {
    let event = LocalOperation::new(build_realm_authority_basis_update_control_intent(
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
// via `ak.self.events.command.submit` (`POST /_arkret/self/events`) —
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
    const ACTOR_ID: &str = "did:web:alice.example";
    const SERVICE_ID: &str = "did:web:server.example";
    const STRAND_ID: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
    const BINDING_EVENT: &str = "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6";
    const OLD_GENESIS_EVENT: &str = "ak:event:ASJHfB5f-5oCgYCWweVEcwgoqhJVEz5hiSbZjYXGGYiB";
    const SELECTED_STATE_EVENT: &str = "ak:event:AXmtMMsFCgaqoViWB_h9mzuZPtig7XaopkKVmS4FA0C_";

    fn repair_hash(byte: char) -> arkret_sdk::Hash {
        arkret_sdk::Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn repair_coordinates() -> arkret_sdk::DirectConversationCoordinates {
        arkret_sdk::DirectConversationCoordinates {
            pair_key: repair_hash('a'),
            realm_id: arkret_sdk::RealmId::new(REALM_ID).unwrap(),
            main_strand_id: arkret_sdk::StrandId::new(STRAND_ID).unwrap(),
            binding_event_ref: Some(arkret_sdk::EventId::new(BINDING_EVENT).unwrap()),
        }
    }

    fn repair_resolve_suspended(
        coordinates: arkret_sdk::DirectConversationCoordinates,
    ) -> arkret_sdk::DirectConversationResolveOutcome {
        arkret_sdk::DirectConversationResolveOutcome::Suspended {
            coordinates,
            blockers: Vec::new(),
            active_mls_generation_ref: Some(
                arkret_sdk::EventId::new(SELECTED_STATE_EVENT).unwrap(),
            ),
            active_mls_generation_value_digest: Some(repair_hash('b')),
        }
    }

    fn source_service() -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new("ak:did_core:web:source.example").unwrap()
    }

    fn target_service() -> arkret_sdk::DidCoreId {
        arkret_sdk::DidCoreId::new("ak:did_core:web:target.example").unwrap()
    }

    fn repair_keypackage_ref() -> arkret_sdk::NonEmptyString {
        arkret_sdk::NonEmptyString::new("kp-exact-repair-target").unwrap()
    }

    /// Route construction fails closed when the accepted Contact does not
    /// expose the peer Principal Server; no route may be invented.
    #[test]
    fn repair_route_fails_closed_without_peer_service_id() {
        let resolve = repair_resolve_suspended(repair_coordinates());
        let error = direct_conversation_repair_route(
            &resolve,
            source_service(),
            None,
            repair_keypackage_ref(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("refusing to invent a route"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn repair_route_requires_coordinates_and_binding() {
        let no_coordinates = arkret_sdk::DirectConversationResolveOutcome::TemporarilyUnavailable {
            retry_after_ms: None,
        };
        assert!(
            direct_conversation_repair_route(
                &no_coordinates,
                source_service(),
                Some(target_service()),
                repair_keypackage_ref(),
            )
            .is_err()
        );

        let mut unbound = repair_coordinates();
        unbound.binding_event_ref = None;
        // An unbound pair is `provisional`; repair requires the accepted
        // binding coordinate regardless of resolver state.
        let resolve = arkret_sdk::DirectConversationResolveOutcome::Provisional {
            coordinates: unbound,
            active_mls_generation_ref: None,
            active_mls_generation_value_digest: None,
        };
        assert!(
            direct_conversation_repair_route(
                &resolve,
                source_service(),
                Some(target_service()),
                repair_keypackage_ref(),
            )
            .is_err()
        );
    }

    #[test]
    fn repair_route_uses_the_peer_delivery_binding_service() {
        let resolve = repair_resolve_suspended(repair_coordinates());
        let route = direct_conversation_repair_route(
            &resolve,
            source_service(),
            Some(target_service()),
            repair_keypackage_ref(),
        )
        .unwrap();
        assert_eq!(route.source_service_id, source_service());
        assert_eq!(route.target_service_id, target_service());
        assert_eq!(route.coordinates, repair_coordinates());
    }

    fn synthetic_realm_event(
        kind: arkret_sdk::EventKind,
        payload: serde_json::Value,
    ) -> arkret_sdk::Event {
        let base = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
            REALM_ID,
            ACTOR_ID,
            arkret_sdk::RealmProfile::new("Repair").unwrap(),
        )
        .unwrap();
        let mut event = crate::operation::author_for_test(&base).into_event();
        event.kind = kind;
        event.payload = serde_json::from_value(payload).unwrap();
        event
    }

    fn current_activation_event() -> arkret_sdk::Event {
        synthetic_realm_event(
            arkret_sdk::EventKind::DirectConversationMlsGenerationActivate,
            serde_json::json!({
                "pair_key": repair_hash('a').as_str(),
                "mls_generation": 1,
                "phase": "exact_pair",
                "mls_group_id": "group-old",
                "genesis_event_ref": OLD_GENESIS_EVENT,
                "selected_group_state_ref": OLD_GENESIS_EVENT,
                "main_strand_id": STRAND_ID,
                "predecessor_active_value_digest": repair_hash('c').as_str(),
            }),
        )
    }

    fn replacement_genesis_event() -> arkret_sdk::Event {
        synthetic_realm_event(
            arkret_sdk::EventKind::MlsGenesis,
            serde_json::json!({
                "mls_group_id": "group-new",
                "epoch": 0,
            }),
        )
    }

    #[test]
    fn repair_activation_payload_derives_next_generation_from_accepted_log() {
        let current = current_activation_event();
        let genesis = replacement_genesis_event();
        let active_ref = current.event_id.clone();
        let genesis_ref = genesis.event_id.clone();
        let payload = direct_conversation_repair_activation_from_events(
            &[current, genesis],
            &repair_coordinates(),
            &active_ref,
            repair_hash('b'),
            "group-new",
            arkret_sdk::EventId::new(SELECTED_STATE_EVENT).unwrap(),
        )
        .unwrap();
        assert_eq!(payload.mls_generation, 2);
        assert_eq!(
            payload.phase,
            arkret_sdk::DirectConversationMlsGenerationPhase::ExactPair
        );
        assert_eq!(payload.mls_group_id.as_str(), "group-new");
        assert_eq!(payload.genesis_event_ref, genesis_ref);
        assert_eq!(
            payload.selected_group_state_ref.as_str(),
            SELECTED_STATE_EVENT
        );
        assert_eq!(
            payload.predecessor_active_value_digest,
            Some(repair_hash('b'))
        );
    }

    #[test]
    fn repair_activation_payload_fails_closed_on_missing_or_contested_inputs() {
        let current = current_activation_event();
        let genesis = replacement_genesis_event();
        let active_ref = current.event_id.clone();
        let selected = arkret_sdk::EventId::new(SELECTED_STATE_EVENT).unwrap();

        // The resolver-named activation Event must be in the accepted log.
        assert!(
            direct_conversation_repair_activation_from_events(
                &[genesis.clone()],
                &repair_coordinates(),
                &active_ref,
                repair_hash('b'),
                "group-new",
                selected.clone(),
            )
            .is_err()
        );

        // A contested replacement genesis (two accepted genesis Events for the
        // same group) must not be resolved locally.
        assert!(
            direct_conversation_repair_activation_from_events(
                &[
                    current.clone(),
                    genesis.clone(),
                    replacement_genesis_event()
                ],
                &repair_coordinates(),
                &active_ref,
                repair_hash('b'),
                "group-new",
                selected.clone(),
            )
            .is_err()
        );

        // The local group still being the active generation's group means
        // there is no replacement to activate.
        assert!(
            direct_conversation_repair_activation_from_events(
                &[current, genesis],
                &repair_coordinates(),
                &active_ref,
                repair_hash('b'),
                "group-old",
                selected,
            )
            .is_err()
        );
    }

    #[test]
    fn latest_alias_payload_folds_accepted_declaration_and_tombstone() {
        let declaration =
            build_realm_alias_event(REALM_ID, ACTOR_ID, SERVICE_ID, "engineering").unwrap();
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
        let alias = build_realm_alias_event(REALM_ID, ACTOR_ID, SERVICE_ID, "engineering").unwrap();
        let unrelated = build_realm_state_event::<arkret_sdk::event_spec::RealmProfile>(
            REALM_ID,
            ACTOR_ID,
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
}
