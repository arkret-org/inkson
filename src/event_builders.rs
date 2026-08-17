//! Realm event and device envelope builders.
//!
//! These helpers are transport-neutral and independent of the API transport.

use std::collections::BTreeSet;

use arkret_wire::SchemaId;
use serde_json::Value;

use crate::operation::{
    EventKind, EventRequirements, Precondition, Predicate, PredicateOp, TypedOperationBuilder,
    trim_realm_id,
};
use crate::realm_defaults::{
    RECOMMENDED_REALM_ENCRYPTION_FLOOR_TYPED, RECOMMENDED_REALM_ENCRYPTION_PROFILE,
};

/// Event authoring instant normalized to the protocol's millisecond profile.
fn event_timestamp() -> chrono::DateTime<chrono::Utc> {
    crate::clock::now_utc_millis()
}

/// Canonical timestamp for payload/object fields that bind an Event instant.
///
/// Create payloads must carry `payload.object.created_at == Event.created_at`.
/// Both values therefore use the Event profile's fixed three-digit millisecond
/// representation.
fn payload_timestamp_wire(created_at: chrono::DateTime<chrono::Utc>) -> String {
    arkret_sdk::canonical::format_timestamp_canonical(created_at)
}

fn cell_ref(cell: &str) -> anyhow::Result<arkret_sdk::CellRef> {
    arkret_sdk::CellRef::new(cell.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid cell ref {cell:?}: {err}"))
}

fn head_eq_precondition(cell: &str, value: Value) -> anyhow::Result<Precondition> {
    Ok(Precondition {
        cell: cell_ref(cell)?,
        predicate: Predicate {
            op: PredicateOp::HeadEq,
            value: Some(value),
            values: None,
            predicate_id: None,
        },
    })
}

fn event_requirements_with_schema(schema_ref: &str) -> EventRequirements {
    EventRequirements {
        schema_profile_refs: vec![
            arkret_sdk::ProfileRef::new(schema_ref.to_owned())
                .expect("event builder schema profile ref must be valid"),
        ],
        required_features: Vec::new(),
        critical_extensions: Vec::new(),
    }
}

/// R3.1: `handle` is the canonical `<localpart>:<domain>` wire form
/// (renamed from `handle_uri` @ arkret-spec 7157ee8 — the `arkret://`
/// URI handle form has been retired).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealmBootstrapMember {
    pub(crate) actor_id: String,
}

impl RealmBootstrapMember {
    fn from_did(did: &str) -> Self {
        Self {
            actor_id: did.trim().to_owned(),
        }
    }
}

fn parse_realm_bootstrap_member(input: &str) -> anyhow::Result<RealmBootstrapMember> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("seed member is empty"));
    }
    if arkret_sdk::DidCoreId::new(trimmed.to_owned()).is_ok() {
        return Ok(RealmBootstrapMember::from_did(trimmed));
    }
    Err(anyhow::anyhow!(
        "seed member must be a did_core_id; handle bootstrap requires a Directory-resolved invite address"
    ))
}

pub(crate) fn parse_realm_bootstrap_members(
    inputs: &[String],
) -> anyhow::Result<Vec<RealmBootstrapMember>> {
    let mut members = Vec::new();
    for input in inputs {
        let member = parse_realm_bootstrap_member(input)?;
        if !members
            .iter()
            .any(|existing: &RealmBootstrapMember| existing.actor_id == member.actor_id)
        {
            members.push(member);
        }
    }
    Ok(members)
}

#[allow(clippy::too_many_arguments)]
/// Build the ordered Realm genesis batch.
///
/// The Realm id is **not** an input: spec realm-and-space.md section 2.5.0
/// derives it from the genesis Event, so this builds `ak.realm.create` first,
/// reads the id off the built envelope, and only then builds the follow-ups
/// that must name it. The derived id is returned alongside the batch.
pub fn build_realm_bootstrap_events(
    genesis_salt: arkret_sdk::GenesisSalt,
    actor_id: &str,
    notary_did: &str,
    notary_service_origin: &str,
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
    invitees: &[String],
    plaintext_visible_services: &[String],
    alias: Option<&str>,
    content_scheme: Option<&str>,
) -> anyhow::Result<(String, Vec<arkret_sdk::Event>)> {
    // The creator membership is the registry's final explicit bootstrap slot;
    // `ak.realm.create` never synthesizes membership.
    let mut events: Vec<arkret_sdk::Event> = Vec::new();
    validate_realm_history_content_scheme_for_profile(
        encryption_profile,
        history_visibility,
        content_scheme,
    )?;
    // Validate seed invitees here, but do not include their membership
    // transitions in the atomic genesis unit. Realm invite state can only be
    // entered through an ordinary `ak.invite.create` Control Move after the
    // creator's bootstrap has been accepted.
    let _invitees = parse_realm_bootstrap_members(invitees)?;
    let create_event = build_realm_create_event(
        genesis_salt,
        actor_id,
        notary_did,
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
        content_scheme,
    )?;
    // The genesis envelope carries no realm_id; the SDK resolved it from the
    // Event itself, and every follow-up in this batch must name that value.
    let realm_id_owned = create_event.realm_id.to_string();
    let realm_id = realm_id_owned.as_str();
    events.push(create_event);
    let mut profile = arkret_sdk::RealmProfile::new(title.trim())?;
    profile.summary = summary
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .map(ToOwned::to_owned);
    events.push(build_realm_state_event::<
        arkret_sdk::event_spec::RealmProfile,
    >(realm_id, actor_id, profile)?);
    // realm-and-space.md §2.5: an ordinary Realm is one genesis transaction of
    // `ak.realm.create` plus the closed follow-up facet whitelist. The creator's
    // root authority is the `ak.component.realm.authority_root.v1` cell the
    // create Event's registered reducer contract writes, so there is no
    // wire slot for a self-issued genesis grant.
    let mut policy_bundle =
        recommended_realm_policy_bundle_for_profile(encryption_profile, content_scheme)
            .unwrap_or_else(|| arkret_sdk::RealmPolicyBundlePayload {
                content_encryption_floor: Some(arkret_sdk::EncryptionFloor::AllowPlaintext),
                ..arkret_sdk::RealmPolicyBundlePayload::new(1)
            });
    policy_bundle.federation_policy =
        Some(parse_wire_enum("federation_policy", federation_policy)?);
    events.push(build_realm_state_event::<
        arkret_sdk::event_spec::RealmPolicyBundle,
    >(realm_id, actor_id, policy_bundle)?);
    events.push(build_realm_state_event::<
        arkret_sdk::event_spec::RealmJoinRule,
    >(
        realm_id,
        actor_id,
        arkret_sdk::StatePayload {
            value: Some(serde_json::to_value(parse_wire_enum::<
                arkret_sdk::RealmJoinRuleValue,
            >("join_rule", join_rule)?)?),
            state: None,
            reason: None,
        },
    )?);
    let history_sharing_policy =
        recommended_history_sharing_policy_for_profile(encryption_profile, history_visibility);
    let history_visibility_payload = if history_visibility.trim() == "restricted" {
        let policy = history_sharing_policy.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "restricted history_visibility requires a history sharing policy in the bootstrap unit"
            )
        })?;
        let digest = crate::canonical::canonical_sha256(policy)?;
        arkret_sdk::HistoryVisibilityPayload::restricted(digest)
    } else {
        arkret_sdk::HistoryVisibilityPayload::new(parse_wire_enum(
            "history_visibility",
            history_visibility,
        )?)
    };
    events.push(build_realm_state_event::<
        arkret_sdk::event_spec::RealmHistoryVisibility,
    >(realm_id, actor_id, history_visibility_payload)?);
    if let Some(policy) = history_sharing_policy {
        events.push(build_realm_history_sharing_policy_event(
            realm_id, actor_id, policy,
        )?);
    }
    events.push(build_realm_state_event::<
        arkret_sdk::event_spec::RealmDiscovery,
    >(
        realm_id,
        actor_id,
        arkret_sdk::StatePayload {
            value: Some(serde_json::to_value(parse_wire_enum::<
                arkret_sdk::RealmDiscoveryValue,
            >(
                "discoverability", discoverability
            )?)?),
            state: None,
            reason: None,
        },
    )?);
    // object-addressing.md §3.3: `ak.realm.alias` is the ONLY wire carrier of a
    // Realm alias, and §2.5 lists it among the seal_basis-exempt bootstrap
    // follow-ups, so naming a Realm at creation happens here rather than on the
    // closed Realm object. The alias domain is the deployment that issues it.
    //
    // Emptiness is judged AFTER stripping the `#` share sigil: the sigil is a
    // display affordance that never reaches the wire, so a sigil-only input is
    // "no alias" and must claim nothing, not fail preparation.
    if let Some(alias) = alias
        .map(|alias| alias.trim().trim_start_matches('#').trim())
        .filter(|alias| !alias.is_empty())
    {
        events.push(build_realm_alias_event(
            realm_id, actor_id, notary_did, alias,
        )?);
    }

    if let Some(event) =
        build_plaintext_visible_services_event(realm_id, actor_id, plaintext_visible_services)?
    {
        events.push(event);
    }

    let delivery_binding_policy = build_realm_delivery_binding_policy(realm_id, notary_did)?;
    let delivery_binding_policy_event = build_realm_state_event::<
        arkret_sdk::event_spec::RealmDeliveryBindingPolicy,
    >(realm_id, actor_id, delivery_binding_policy)?;
    let delivery_binding_policy_event_id = delivery_binding_policy_event.event_id.clone();
    events.push(delivery_binding_policy_event);

    use arkret_sdk::{
        BindingScope, BindingSource, DeliveryMode, MemberDeliveryBinding, RecipientServiceKind,
        ServiceResolutionCarrier,
    };
    let recipient_service_id = arkret_sdk::DidCoreId::from(arkret_sdk::project_full_id_to_core_id(
        &arkret_sdk::DidFullId::new(notary_did.to_owned())
            .map_err(|err| anyhow::anyhow!("invalid creator service DID: {err}"))?,
    )?);
    let mut service_origin = url::Url::parse(notary_service_origin)
        .map_err(|err| anyhow::anyhow!("invalid creator service origin: {err}"))?;
    if service_origin.scheme() == "http"
        && service_origin.host_str().is_some_and(|host| {
            host == "localhost"
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
        })
    {
        service_origin
            .set_scheme("https")
            .map_err(|()| anyhow::anyhow!("cannot normalize loopback creator service origin"))?;
    }
    if service_origin.scheme() != "https"
        || service_origin.host_str().is_none()
        || !service_origin.username().is_empty()
        || service_origin.password().is_some()
        || service_origin.query().is_some()
        || service_origin.fragment().is_some()
    {
        anyhow::bail!("creator service origin must be an absolute HTTPS origin");
    }
    let current_record_url = format!(
        "{}{}",
        service_origin.origin().ascii_serialization(),
        arkret_sdk::canonical_service_current_record_path(&recipient_service_id)
    );
    let service_resolution = ServiceResolutionCarrier::CurrentRecordUrl {
        current_record_url,
        pinned_record_digest: None,
    };
    service_resolution.validate_shape(&recipient_service_id)?;
    let creator_delivery_binding = MemberDeliveryBinding {
        recipient_service_id,
        recipient_service_kind: RecipientServiceKind::PrincipalServer,
        binding_scope: BindingScope::Realm,
        binding_source: BindingSource::RealmPolicy,
        delivery_modes: [
            DeliveryMode::Events,
            DeliveryMode::Sync,
            DeliveryMode::ToDevice,
            DeliveryMode::Push,
            DeliveryMode::KeyPackages,
        ]
        .into_iter()
        .collect(),
        service_resolution,
        did_document_digest: None,
        resolved_at: event_timestamp(),
        service_acceptance_ref: None,
        holder_proof_ref: None,
        policy_event_ref: Some(delivery_binding_policy_event_id),
        expires_at: None,
    };
    events.push(build_member_state_transition_event_with_binding(
        realm_id,
        actor_id,
        actor_id,
        None,
        "join",
        "creator_delivery_binding",
        Some(creator_delivery_binding),
    )?);

    // Every follow-up in the genesis transaction is checked against its
    // registered contract, not just the single-target cas_register facets the
    // deleted `validate_single_target_set_event_contract*` helper knew about.
    // `OrdinaryRealmBootstrap` is the one context in which a control write may
    // carry no CBA basis: there is no accepted Seal yet.
    for followup in &events[1..] {
        arkret_sdk::schema::validate_registered_cell_writes_in_context(
            followup,
            arkret_sdk::schema::EventCellContractContext::OrdinaryRealmBootstrap,
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "bootstrap Event {} ({}) violates its registry cell contract: {error}",
                followup.event_id,
                followup.kind.as_str()
            )
        })?;
    }
    arkret_policy::realm_bootstrap::validate_realm_bootstrap_unit(&events).map_err(|error| {
        let sequence = events
            .iter()
            .map(|event| {
                format!(
                    "{}[actor={},realm={}]",
                    event.kind.as_str(),
                    event.actor_id,
                    event.realm_id
                )
            })
            .collect::<Vec<_>>()
            .join(" -> ");
        anyhow::anyhow!(
            "{}: {error}; authored sequence: {sequence}",
            error.reason_code()
        )
    })?;
    Ok((realm_id_owned, events))
}

fn recommended_history_sharing_policy_for_profile(
    _encryption_profile: &str,
    history_visibility: &str,
) -> Option<arkret_sdk::HistorySharingPolicyPayloadValue> {
    if history_visibility.trim() == "restricted" {
        use arkret_sdk::{
            HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayloadValue,
            HistorySharingPolicyPayloadValueAudit, HistorySharingRange,
            HistorySharingReceiverClass, HistorySharingRestrictedRule,
            HistorySharingRestrictedRuleHistoryScope, HistorySharingScopeKind, HistoryVisibility,
        };
        return Some(HistorySharingPolicyPayloadValue {
            version: 1,
            default_key_share: HistoryKeyShareDefault::Deny,
            pre_join_history: None,
            post_removal_recovery: None,
            allowed_key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
            allowed_receiver_states: Some(vec![HistorySharingReceiverClass::ActiveMember]),
            audit: HistorySharingPolicyPayloadValueAudit {
                share_audit_event_required: true,
                access_audit_required: true,
            },
            restricted_rules: Some(vec![HistorySharingRestrictedRule {
                rule_id: "bootstrap_active_member_history".to_owned(),
                history_scope: Some(HistorySharingRestrictedRuleHistoryScope {
                    kind: HistorySharingScopeKind::Realm,
                    circle_id: None,
                }),
                receiver_classes: vec![HistorySharingReceiverClass::ActiveMember],
                allowed_history_visibility_values: vec![HistoryVisibility::Restricted],
                range: HistorySharingRange::SinceJoin,
                max_epoch_span: None,
                key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
                audit_required: Some(true),
            }]),
        });
    }
    None
}

/// Recommended `history_sharing_policy_payload.value` for a pre-join-visible
/// Realm, authored through the SDK strong type so every member is a declared
/// property of the closed `history_sharing_policy_payload` schema.
pub(crate) fn recommended_history_sharing_policy_for_visibility(
    history_visibility: &str,
) -> Option<arkret_sdk::HistorySharingPolicyPayloadValue> {
    use arkret_sdk::{
        HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayloadValue,
        HistorySharingPolicyPayloadValueAudit, HistorySharingPreJoinPolicy,
        HistorySharingReceiverClass,
    };
    let pre_join_visible = matches!(
        history_visibility.trim().to_ascii_lowercase().as_str(),
        "world_readable" | "shared" | "invited"
    );
    if !pre_join_visible {
        return None;
    }
    Some(HistorySharingPolicyPayloadValue {
        version: 1,
        default_key_share: HistoryKeyShareDefault::EventTimeVisibility,
        pre_join_history: Some(HistorySharingPreJoinPolicy::AllowIfVisibilityAllows),
        post_removal_recovery: None,
        allowed_key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
        allowed_receiver_states: Some(vec![HistorySharingReceiverClass::ActiveMember]),
        audit: HistorySharingPolicyPayloadValueAudit {
            share_audit_event_required: false,
            access_audit_required: false,
        },
        restricted_rules: None,
    })
}

/// Parse a wire enum token through its SDK strong type, so an unregistered
/// value fails here instead of on the receiver's schema gate.
fn parse_wire_enum<T: serde::de::DeserializeOwned>(field: &str, value: &str) -> anyhow::Result<T> {
    serde_json::from_value(Value::String(value.trim().to_owned()))
        .map_err(|err| anyhow::anyhow!("invalid {field} {value:?}: {err}"))
}

/// Build the closed `ak.schema.realm_genesis.v1` object as the SDK strong type.
///
/// Every member is a declared field of [`arkret_sdk::RealmGenesis`]
/// (`deny_unknown_fields`), so a member the
/// schema does not carry cannot be authored at all — the previous hand-built
/// `serde_json::Value` accepted any key and only failed at the receiver's
/// candidate gate.
#[allow(clippy::too_many_arguments)]
fn build_realm_genesis_object(
    genesis_salt: arkret_sdk::GenesisSalt,
    _actor_id: &str,
    notary_did: &str,
    _title: &str,
    _summary: Option<&str>,
    _discoverability: &str,
    _join_rule: &str,
    _history_visibility: &str,
    encryption_profile: &str,
    security_class: &str,
    _federation_policy: &str,
    notary_profile: &str,
    digest_algorithm: &str,
    trust_domain: &str,
    _content_scheme: Option<&str>,
) -> anyhow::Result<arkret_sdk::RealmGenesis> {
    let trust_domain_typed = arkret_sdk::TrustDomainId::new(trust_domain.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid trust_domain for realm.create: {err:?}"))?;
    let notary_profile_typed: arkret_sdk::NotaryProfile =
        parse_wire_enum("notary_profile", notary_profile)?;
    let notary = realm_genesis_notary(notary_profile_typed, notary_did)?;
    // realm-and-space.md §2.5: the create-locked registry digest is the basis
    // the Realm's authority-root cell is seeded with, so the owner ceiling is
    // pinned to the snapshot this client actually authored against.
    let capability_action_registry_digest = arkret_sdk::current_capability_action_registry_digest()
        .map_err(|err| {
            anyhow::anyhow!(
                "embedded capability-action registry unavailable for realm.create: {err}"
            )
        })?;

    let digest_algorithm = arkret_sdk::canonical::digest_suite(digest_algorithm.trim())
        .map_err(|err| anyhow::anyhow!("invalid digest_algorithm {digest_algorithm:?}: {err}"))?;
    arkret_sdk::RealmGenesis::event_derived(
        arkret_sdk::RealmPurpose::Collaboration,
        genesis_salt,
        trust_domain_typed,
        vec![arkret_wire::SchemaId::REALM_V1.to_owned()],
        arkret_sdk::CORE_REDUCER_PROFILE,
        digest_algorithm,
        parse_wire_enum("security_class", security_class)?,
        parse_wire_enum("encryption_profile", encryption_profile)?,
        notary_profile_typed,
        notary,
        capability_action_registry_digest,
    )
    .map_err(anyhow::Error::from)
}

/// Wrap a genesis Realm object into the `ak.realm.create` Event.
///
/// `object.created_at` is the single source for the envelope timestamp:
/// `realm_create_payload` semantic validation requires
/// `payload.object.created_at == Event.created_at`.
fn build_realm_create_event_from_object(
    actor_id: &str,
    object: arkret_sdk::RealmGenesis,
) -> anyhow::Result<arkret_sdk::Event> {
    let created_at = event_timestamp();
    // ak.component.realm.create.v1 is an ordered-log genesis singleton;
    // the bootstrap write asserts head_eq null and sets the realm metadata.
    let cell = arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_CREATE_V1);
    let preconditions = vec![head_eq_precondition(&cell, Value::Null)?];
    let realm_body = arkret_sdk::RealmCreatePayload::new(object);
    // The builder emits the closed `realm_genesis` scope for this kind, so the
    // realm id passed here is a placeholder the envelope never carries.
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmCreate>(
        arkret_sdk::RealmId::new("ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR")
            .expect("placeholder realm id is canonical")
            .into_string(),
        actor_id,
        realm_body,
    )
    .preconditions(preconditions)
    .requirements(event_requirements_with_schema(SchemaId::REALM_GENESIS_V1))
    .created_at(created_at)
    .build_sdk_event("inkson")
}

#[allow(clippy::too_many_arguments)]
pub fn build_realm_create_event(
    genesis_salt: arkret_sdk::GenesisSalt,
    actor_id: &str,
    notary_did: &str,
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
    content_scheme: Option<&str>,
) -> anyhow::Result<arkret_sdk::Event> {
    let object = build_realm_genesis_object(
        genesis_salt,
        actor_id,
        notary_did,
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
        content_scheme,
    )?;
    build_realm_create_event_from_object(actor_id, object)
}

/// Build the create-locked Principal Control Realm genesis for a managed
/// Native Personal Agent. The control facts belong to `agent_id`; the active
/// controller only executes the Event under the DID delegation returned by
/// provisioning.
pub fn build_managed_agent_pcr_create_event(
    agent_id: &str,
    initial_resolution: arkret_sdk::ResolutionCommitment,
    controller_id: &str,
    controller_authorization_ref: &str,
    trust_domain: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let created_at = event_timestamp();
    let payload = arkret_bootstrap::build_managed_agent_pcr_create_payload(
        arkret_bootstrap::ManagedAgentPcrCreatePayloadInput {
            agent_id: crate::mls_api_helpers::principal_core_id(agent_id)?,
            initial_resolution,
            controller_id: crate::mls_api_helpers::principal_core_id(controller_id)?,
            genesis_salt: arkret_sdk::GenesisSalt::generate()?,
            trust_domain: arkret_sdk::TrustDomainId::new(trust_domain.to_owned())?,
            capability_action_registry_digest:
                arkret_sdk::current_capability_action_registry_digest()?,
            created_at,
        },
    )?;
    let cell = arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_CREATE_V1);
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmCreate>(
        // `RealmCreate` serializes `realm_genesis`; this placeholder is never
        // carried and is replaced by retype(the finalized EventId).
        "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR",
        agent_id,
        payload,
    )
    .executed_by(controller_id)
    .authorization_ref(controller_authorization_ref)
    .preconditions(vec![head_eq_precondition(&cell, Value::Null)?])
    .requirements(event_requirements_with_schema(SchemaId::REALM_GENESIS_V1))
    .created_at(created_at)
    .build_sdk_event("inkson")
}

pub fn build_managed_agent_pcr_bootstrap_events(
    agent_id: &str,
    initial_resolution: arkret_sdk::ResolutionCommitment,
    controller_id: &str,
    controller_authorization_ref: &str,
    trust_domain: &str,
) -> anyhow::Result<Vec<arkret_sdk::Event>> {
    let create = build_managed_agent_pcr_create_event(
        agent_id,
        initial_resolution,
        controller_id,
        controller_authorization_ref,
        trust_domain,
    )?;
    let events = vec![create];
    arkret_bootstrap::materialize_managed_agent_pcr_control(
        &events,
        &crate::operation::cell_write_projector,
    )
    .map_err(|error| anyhow::anyhow!("managed Agent PCR bootstrap is invalid: {error}"))?;
    Ok(events)
}

/// Build the closed four-Event Direct Conversation founding unit from the
/// resolver's verbatim authoring material.  All identifiers are derived from
/// the finalized Event bytes; no service allocation or local UUID participates.
pub fn build_direct_conversation_founding_events(
    founder_id: &arkret_sdk::DidFullId,
    peer_id: &arkret_sdk::DidFullId,
    trust_domain: arkret_sdk::TrustDomainId,
    _input: &arkret_sdk::DirectConversationFoundingInput,
) -> anyhow::Result<Vec<arkret_sdk::Event>> {
    let created_at = event_timestamp();
    let founder_actor =
        arkret_sdk::DidCoreId::from(arkret_sdk::project_full_id_to_core_id(founder_id)?);
    let create_payload = arkret_sdk::direct_conversation_realm_create_payload(
        arkret_sdk::GenesisSalt::generate()?,
        trust_domain,
        arkret_sdk::NotaryProfile::SingleDid,
        arkret_sdk::NotaryValue::single_did(founder_actor.clone()),
        arkret_sdk::current_capability_action_registry_digest()?,
        created_at,
    )?;
    let create_cell = arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_CREATE_V1);
    let create = TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmCreate>(
        "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR",
        founder_id.as_str(),
        create_payload,
    )
    .preconditions(vec![head_eq_precondition(&create_cell, Value::Null)?])
    .requirements(event_requirements_with_schema(SchemaId::REALM_GENESIS_V1))
    .created_at(created_at)
    .build_sdk_event("inkson")?;

    let realm_id = create.realm_id.clone();
    let peer_actor = arkret_sdk::DidCoreId::from(arkret_sdk::project_full_id_to_core_id(peer_id)?);
    let membership = arkret_sdk::direct_conversation_peer_membership_bootstrap(
        realm_id.clone(),
        &founder_actor,
        [founder_actor.clone(), peer_actor.clone()],
        arkret_sdk::DeliveryStatus::Unroutable,
    )?;
    let member_cell = format!("ak:cell:ak.component.member.state.v1:{peer_actor}");
    let mut member = TypedOperationBuilder::new::<arkret_sdk::event_spec::MemberState>(
        realm_id.to_string(),
        founder_id.as_str(),
        membership,
    )
    .target_ref(peer_id.as_str())
    .preconditions(vec![head_eq_precondition(&member_cell, Value::Null)?])
    .created_at(created_at)
    .build_sdk_event("inkson")?;
    member.prev_refs = vec![create.event_id.clone()];
    crate::operation::rederive_event_identity(&mut member)?;

    let strand_payload = arkret_sdk::direct_conversation_main_strand_create_payload(
        realm_id,
        arkret_sdk::DidCoreId::from(arkret_sdk::project_full_id_to_core_id(founder_id)?),
        created_at,
    );
    let mut strand = TypedOperationBuilder::new::<arkret_sdk::event_spec::StrandCreate>(
        create.realm_id.to_string(),
        founder_id.as_str(),
        strand_payload,
    )
    .created_at(created_at)
    .build_sdk_event("inkson")?;
    strand.prev_refs = vec![member.event_id.clone()];
    crate::operation::rederive_event_identity(&mut strand)?;

    let founder_membership = arkret_sdk::direct_conversation_member_join_payload(
        create.realm_id.clone(),
        founder_actor.clone(),
        arkret_sdk::DeliveryStatus::Unroutable,
    );
    let founder_member_cell = format!("ak:cell:ak.component.member.state.v1:{founder_actor}");
    let mut founder_member = TypedOperationBuilder::new::<arkret_sdk::event_spec::MemberState>(
        create.realm_id.to_string(),
        founder_id.as_str(),
        founder_membership,
    )
    .target_ref(founder_actor.as_str())
    .preconditions(vec![head_eq_precondition(
        &founder_member_cell,
        Value::Null,
    )?])
    .created_at(created_at)
    .build_sdk_event("inkson")?;
    founder_member.prev_refs = vec![strand.event_id.clone()];
    crate::operation::rederive_event_identity(&mut founder_member)?;

    let events = vec![create, member, strand, founder_member];
    arkret_sdk::DirectConversationFoundingPlan::from_events([
        &events[0], &events[1], &events[2], &events[3],
    ])?;
    Ok(events)
}

pub fn encryption_profile_uses_recommended_floor(profile: &str) -> bool {
    profile
        .trim()
        .eq_ignore_ascii_case(RECOMMENDED_REALM_ENCRYPTION_PROFILE)
}

/// Resolve the effective §2.10 content scheme (capability axis) from the
/// optional caller selection: `None` or any history-capable choice ⇒ the
/// history-shareable `mls_exporter_aead_v1` default; an explicit `mls_rfc9420`
/// pins the forward-secret-only scheme. See [[content-scheme-capability-vs-toggle]].
pub fn resolve_realm_content_scheme(content_scheme: Option<&str>) -> &'static str {
    match content_scheme.map(str::trim) {
        Some("mls_rfc9420") => "mls_rfc9420",
        _ => "mls_exporter_aead_v1",
    }
}

pub fn validate_realm_history_content_scheme_for_profile(
    encryption_profile: &str,
    history_visibility: &str,
    content_scheme: Option<&str>,
) -> anyhow::Result<()> {
    if encryption_profile_uses_recommended_floor(encryption_profile) {
        arkret_sdk::validate_history_visibility_content_scheme_values(
            history_visibility,
            Some(resolve_realm_content_scheme(content_scheme)),
        )
        .map_err(|reason| anyhow::anyhow!("{reason}"))?;
    }
    Ok(())
}

/// Genesis `ak.realm.delivery_binding_policy` value: the creator's own
/// Principal Server is the sole admissible recipient service, and the only
/// admissible binding source is the Realm policy this Event establishes.
/// Authored through the SDK strong type
/// (`event-payload.schema.json#/$defs/realm_delivery_binding_policy_payload`,
/// `additionalProperties:false`).
fn build_realm_delivery_binding_policy(
    realm_id: &str,
    notary_did: &str,
) -> anyhow::Result<arkret_sdk::RealmDeliveryBindingPolicyPayload> {
    let realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|err| anyhow::anyhow!("invalid realm_id for delivery_binding_policy: {err:?}"))?;
    let recipient_service = crate::mls_api_helpers::principal_core_id(notary_did)
        .map_err(|err| anyhow::anyhow!("invalid delivery binding recipient service DID: {err}"))?;
    Ok(arkret_sdk::RealmDeliveryBindingPolicyPayload {
        realm_id: Some(realm_id),
        allowed_binding_sources: Some(
            [arkret_sdk::BindingSource::RealmPolicy]
                .into_iter()
                .collect(),
        ),
        did_document_default_allowed: Some(false),
        allowed_recipient_services: Some(arkret_sdk::AllowedRecipientServices::Allowlist(vec![
            recipient_service,
        ])),
        required_endorsers: Some(BTreeSet::new()),
        unroutable_membership_allowed: Some(true),
        rebind_authorization: Some(arkret_sdk::RebindAuthorization::Member),
        expires_after_seconds: None,
    })
}

/// Genesis `ak.realm.policy_bundle` payload.
pub fn recommended_realm_policy_bundle_value(
    content_scheme: Option<&str>,
) -> arkret_sdk::RealmPolicyBundlePayload {
    arkret_sdk::RealmPolicyBundlePayload {
        policy_revision: 1,
        // §2.10 content scheme — soland projects the effective scheme from THIS
        // policy_bundle cell (`policy_floor_field(components, "content_scheme")`),
        // not from the realm.create object, and applies a one-way ratchet.
        content_scheme: Some(resolve_realm_content_scheme(content_scheme).to_owned()),
        content_encryption_floor: Some(RECOMMENDED_REALM_ENCRYPTION_FLOOR_TYPED),
        metadata_encryption_floor: Some(RECOMMENDED_REALM_ENCRYPTION_FLOOR_TYPED),
        // `encryption-and-audit.md` §2.8 — a genesis Realm that does not declare
        // `aad_visibility` gets the fail-closed `hidden` ceiling, and every
        // later `routing_digest` envelope is rejected with
        // `aad_visibility_policy_violation`. Declaring it here is what makes
        // the AAD event-ref digest reachable at all; the value is the narrowest
        // one that supports digest-based dedupe.
        aad_visibility: Some(arkret_sdk::RealmAadVisibilityPolicy {
            event_id_kind: arkret_sdk::EncryptedEnvelopeAadVisibility::RoutingDigest,
        }),
        ..arkret_sdk::RealmPolicyBundlePayload::new(1)
    }
}

pub fn recommended_realm_policy_bundle_for_profile(
    profile: &str,
    content_scheme: Option<&str>,
) -> Option<arkret_sdk::RealmPolicyBundlePayload> {
    encryption_profile_uses_recommended_floor(profile)
        .then(|| recommended_realm_policy_bundle_value(content_scheme))
}

/// Build the genesis notary cell value as the SDK-authoritative
/// [`arkret_sdk::NotaryValue`] (no hand-rolled JSON — zero schema drift).
fn realm_genesis_notary(
    notary_profile: arkret_sdk::NotaryProfile,
    notary_did: &str,
) -> anyhow::Result<arkret_sdk::NotaryValue> {
    use arkret_sdk::NotaryProfile;
    let notary_did = arkret_sdk::DidFullId::new(notary_did.to_owned())
        .map_err(|e| anyhow::anyhow!("Realm notary DID `{notary_did}` invalid: {e}"))?;
    let notary_core_id = crate::mls_api_helpers::principal_core_id(notary_did.as_str())?;
    // Exhaustive over the profile enum: `Realm::validate_kind_invariants`
    // rejects a `notary_profile` that disagrees with `notary.kind`, so the
    // mapping must not have a catch-all arm that silently lands on single_did.
    let notary = match notary_profile {
        NotaryProfile::Threshold => {
            // Single-operator genesis committee: 1-of-1. `2*1 > 1` so the
            // forensic-attribution mode is `quorum_intersection`.
            arkret_sdk::NotaryValue::Threshold {
                threshold: 1,
                members: vec![notary_core_id.clone()],
                forensic_attribution: arkret_sdk::ForensicAttribution::QuorumIntersection,
            }
        }
        NotaryProfile::OpenSet => arkret_sdk::NotaryValue::OpenSet {
            members: vec![notary_core_id],
        },
        NotaryProfile::Mixed => arkret_sdk::NotaryValue::Mixed {
            actor_id: notary_core_id.clone(),
            recovery_members: vec![parse_derived_did(&derived_recovery_member_did(
                notary_did.as_str(),
            ))?],
        },
        NotaryProfile::SingleDid => {
            // `controller_organization` / `recovery_controller_organizations`
            // are required only when an authoritative organization DID can be
            // derived from the actor DID (the `did:web` no-history service
            // profile, where the host *is* the org authority). For the default
            // `did:webvh` actor the org's webvh DID carries its own SCID that is
            // unknowable client-side, so we omit the org-scoped fields and emit
            // the orgless `{kind, actor_id}` single_did genesis (realm.schema.json
            // single_did allOf; decisions/0003 §7 — personal Realms fall back to
            // per-user recovery) rather than fabricate a malformed
            // `did:webvh:<host>` (no SCID) identifier.
            match inferred_controller_organization_did(notary_did.as_str()) {
                Some(controller) => arkret_sdk::NotaryValue::single_did_with_org(
                    notary_core_id.clone(),
                    vec![parse_derived_did(&derived_recovery_member_did(
                        &controller,
                    ))?],
                    parse_derived_did(&controller)?,
                    vec![parse_derived_did(
                        &derived_recovery_controller_organization_did(&controller),
                    )?],
                ),
                None => arkret_sdk::NotaryValue::single_did(notary_core_id),
            }
        }
    };
    notary
        .validate()
        .map_err(|e| anyhow::anyhow!("realm genesis notary invalid: {e}"))?;
    Ok(notary)
}

/// Parse a client-derived notary DID string into the SDK [`arkret_sdk::DidFullId`].
fn parse_derived_did(did: &str) -> anyhow::Result<arkret_sdk::DidCoreId> {
    crate::mls_api_helpers::principal_core_id(did)
        .map_err(|e| anyhow::anyhow!("derived notary DID `{did}` invalid: {e}"))
}

/// Infer the controlling organization (principal-server) DID for a member's
/// actor DID, returning `None` when no authoritative org DID can be derived.
///
/// Only the explicit no-history `did:web:<host>[:<path>…]` service profile lets
/// us reduce the actor to a valid org DID (`did:web:<host>`). v1 core defaults
/// principal/service to `did:webvh`, whose org DID is
/// `did:webvh:<org-scid>:<host>…` — the org's SCID is not derivable from the
/// member DID, so we MUST NOT fabricate one (a bare `strip_prefix("did:web:")`
/// silently missed every `did:webvh` actor and fell back to the whole actor DID
/// as the organization, poisoning recovery-notary / controller-org derivation).
fn inferred_controller_organization_did(actor_id: &str) -> Option<String> {
    let actor_id = actor_id.trim();
    // Default `did:webvh` actors: org webvh DID requires the org's own SCID,
    // which is not knowable client-side — fail closed.
    if let Ok(did) = arkret_sdk::DidFullId::new(actor_id.to_owned())
        && arkret_sdk::identity::did_webvh_parts(&did).is_some()
    {
        return None;
    }
    // Explicit `did:web:<host>[:<path>…]` no-history service profile.
    if let Some(web_specific_id) = actor_id.strip_prefix("did:web:")
        && let Some(host) = web_specific_id.split(':').next()
        && !host.is_empty()
    {
        return Some(format!("did:web:{host}"));
    }
    None
}

fn derived_recovery_controller_organization_did(controller: &str) -> String {
    format!("{}:recovery", controller.trim())
}

fn derived_recovery_member_did(controller_or_actor: &str) -> String {
    format!("{}:recovery:notary", controller_or_actor.trim())
}

/// Build a `ak.space.create` event per spec realm-and-space.md §3.2.
/// Space is the product-structure container (workspace / project /
/// folder / board / list); it lives inside a Realm (`realm_id`) and
/// has no membership / policy / E2EE of its own — all security
/// semantics inherit from the home Realm.
///
/// No Space id is taken: a create payload carries none, because the Space id is
/// derived from this create Event (spec `zh/models/common-fields.md` section
/// 6.0). The builder stamps the derived id as `unsigned.local_target_ref`.
#[allow(clippy::too_many_arguments)]
pub fn build_space_create_event(
    realm_id: &str,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    kind: &str,
    parent_space_id: Option<&str>,
    default_realm_id: Option<&str>,
) -> anyhow::Result<arkret_sdk::Event> {
    let created_at = event_timestamp();
    // Build the canonical Space object via the SDK strong type so that
    // field names / shape stay aligned with `space_create_payload`
    // (`object`, additionalProperties:false). `created_at` is overridden
    // below with the envelope timestamp to keep wire identity with the
    // effects copy.
    let space_realm_id = arkret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id for space.create: {e:?}"))?;
    let space_created_by = crate::mls_api_helpers::principal_core_id(actor_id)
        .map_err(|e| anyhow::anyhow!("invalid created_by core_id for space.create: {e:?}"))?;
    let mut space_object =
        arkret_sdk::Space::create_object(space_realm_id, kind, title, space_created_by);
    space_object.state = Some(arkret_sdk::SpaceState::Active);
    if let Some(summary) = summary
        && !summary.trim().is_empty()
    {
        space_object.summary = Some(summary.trim().to_owned());
    }
    if let Some(parent) = parent_space_id
        && !parent.trim().is_empty()
    {
        space_object.parent_space_id = Some(
            arkret_sdk::SpaceId::new(parent.trim().to_owned())
                .map_err(|e| anyhow::anyhow!("invalid parent_space_id: {e:?}"))?,
        );
    }
    if let Some(default_realm) = default_realm_id
        && !default_realm.trim().is_empty()
    {
        space_object.default_realm_id = Some(
            arkret_sdk::RealmId::new(trim_realm_id(default_realm.trim()))
                .map_err(|e| anyhow::anyhow!("invalid default_realm_id: {e:?}"))?,
        );
    }
    // Preserve the envelope timestamp on the wire object (SDK defaults
    // `created_at` to construction time).
    space_object.created_at = created_at;

    // No `preconditions`: `ak.space.create` is a DataEvent
    // (`contract-registry.json` plane `data`), and
    // `event-envelope.schema.json` forbids a DataEvent from carrying
    // `preconditions` alongside the `seal_ref` + `auth_context` pair the submit
    // gate attaches. The pre-v1 builder asserted `head_eq null` on
    // `ak.component.space.create.v1`, which is not even the cell this kind
    // writes — the registered contract sets `payload.object` into the
    // `mv_register` `ak.component.space.metadata.v1`.
    let space_body = arkret_sdk::SpaceCreatePayload::new(space_object);
    TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceCreate>(
        realm_id, actor_id, space_body,
    )
    .requirements(event_requirements_with_schema(SchemaId::SPACE_V1))
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// Build a Space lifecycle event (`ak.space.archive` /
/// `ak.space.restore` / `ak.space.tombstone`) per spec
/// realm-and-space.md §3.4. All three write the new `state` value
/// into the registered Space lifecycle cell on the home Realm via
/// an FSM transition.
pub fn build_space_lifecycle_event(
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    kind: EventKind,
) -> anyhow::Result<arkret_sdk::Event> {
    // Only the prior state is the producer's to assert. The next state is
    // derived by the receiver from the registered FSM contract for this kind,
    // so naming it here would just be a second, unsigned copy of the reducer's
    // own rule.
    let (prior_state, _) = match &kind {
        EventKind::SpaceArchive => ("active", "archived"),
        EventKind::SpaceRestore => ("archived", "active"),
        // For tombstone, prior state may be either active or archived.
        // We assert via head_in {active, archived}, but the typed
        // helper only knows head_eq — so we model the explicit head_eq
        // against the most common source state (active). Reducer-side
        // FSM logic accepts the transition regardless of head form.
        EventKind::SpaceTombstone => ("active", "tombstoned"),
        other => {
            return Err(anyhow::anyhow!(
                "unsupported Space lifecycle event kind {}",
                other.as_str()
            ));
        }
    };
    let space_id_typed = arkret_sdk::SpaceId::new(space_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid space id {space_id:?}: {err}"))?;
    let transition_payload = || arkret_sdk::SpaceStateTransitionPayload {
        space_id: space_id_typed.clone(),
        reason: None,
        effective_at: None,
    };
    let tombstone_payload = || arkret_sdk::SpaceObjectTombstonePayload {
        space_id: space_id_typed.clone(),
        reason: Some("user_requested".to_owned()),
        replacement_space: None,
        replacement_event: None,
        effective_at: None,
    };
    let created_at = event_timestamp();
    let cell = space_cell(arkret_wire::CellFamilyId::SPACE_LIFECYCLE_V1, space_id);
    let preconditions = vec![head_eq_precondition(
        &cell,
        Value::String(prior_state.to_owned()),
    )?];
    match kind {
        EventKind::SpaceArchive => {
            TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceArchive>(
                realm_id,
                actor_id,
                transition_payload(),
            )
        }
        EventKind::SpaceRestore => {
            TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceRestore>(
                realm_id,
                actor_id,
                transition_payload(),
            )
        }
        EventKind::SpaceTombstone => TypedOperationBuilder::new::<
            arkret_sdk::event_spec::SpaceTombstone,
        >(realm_id, actor_id, tombstone_payload()),
        _ => unreachable!("unsupported Space lifecycle kind was rejected above"),
    }
    .target_ref(space_id)
    .preconditions(preconditions)
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// Build a Realm facet state event (`ak.realm.join_rule`,
/// `ak.realm.history_visibility`, `ak.realm.discovery`, ...).
pub fn build_realm_state_event<K: arkret_sdk::EventSpec>(
    realm_id: &str,
    actor_id: &str,
    payload: K::Payload,
) -> anyhow::Result<arkret_sdk::Event> {
    let created_at = event_timestamp();
    let realm_id = arkret_sdk::RealmId::new(crate::operation::trim_realm_id(realm_id))?;
    let scope_ref = arkret_sdk::ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let actor_id = crate::mls_api_helpers::principal_core_id(actor_id)?;
    let principal_server_id = crate::operation::authoring_principal_server_id()?;
    let hlc = arkret_sdk::Hlc::new("000000000000-0000-00000000")?;
    let mut event =
        arkret_sdk::TypedEventDraft::<K>::new(scope_ref, actor_id, principal_server_id, payload)?
            .author(0, hlc, created_at)?;

    // event-kind-registry.json declares that `cell_writes[]` is the sole
    // authority for reducer targets; the old flattened descriptor fields are
    // deliberately absent. Project the complete contract so authoring and
    // admission resolve exactly the same target. These Realm facet builders
    // are intentionally single-target: if a future contract becomes
    // conditional or multi-target, fail closed and require a purpose-built
    // authoring path instead of silently putting CAS on the wrong cell.
    let writes = crate::operation::project_registered_cell_writes(&event)
        .map_err(|error| anyhow::anyhow!("{} cell-write projection failed: {error}", event.kind))?;
    let [write] = writes.as_slice() else {
        anyhow::bail!(
            "Realm state event kind {} must project exactly one cell write, got {}",
            event.kind.as_str(),
            writes.len()
        );
    };
    let arkret_sdk::ProjectedOp::Direct(op) = &write.op else {
        anyhow::bail!(
            "Realm state event kind {} does not have a direct state write",
            event.kind.as_str()
        );
    };
    if op.op_type != arkret_sdk::LatticeOpType::Set {
        anyhow::bail!(
            "Realm state event kind {} does not have a set contract",
            event.kind.as_str()
        );
    }
    event.preconditions = vec![head_eq_precondition(write.cell.as_str(), Value::Null)?];
    crate::operation::rederive_event_identity(&mut event)?;
    Ok(event)
}

/// Build a `ak.realm.archive` lifecycle facet event. Realm archive is a
/// reversible boolean register; there is no separate `ak.realm.restore`.
pub fn build_realm_archive_event(
    realm_id: &str,
    actor_id: &str,
    archived: bool,
    reason: Option<&str>,
) -> anyhow::Result<arkret_sdk::Event> {
    let created_at = event_timestamp();
    // Strong type: realm_archive_payload (additionalProperties:false).
    let mut typed = arkret_sdk::RealmArchivePayload::new(archived);
    if let Some(reason) = reason.map(str::trim).filter(|value| !value.is_empty()) {
        typed = typed.with_reason(reason);
    }
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmArchive>(realm_id, actor_id, typed)
        .created_at(created_at)
        .build_sdk_event("inkson")
}

/// Build a `ak.realm.destroy` terminal lifecycle event.
pub fn build_realm_destroy_event(
    realm_id: &str,
    actor_id: &str,
    reason: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(anyhow::anyhow!("reason is required for ak.realm.destroy"));
    }
    let created_at = event_timestamp();
    // Strong type: realm_destroy_payload (reason required; verification_stub
    // _required omitted so the reducer applies its default; additionalProperties
    // :false).
    let payload = arkret_sdk::RealmDestroyPayload::new(reason);
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmDestroy>(realm_id, actor_id, payload)
        .created_at(created_at)
        .build_sdk_event("inkson")
}

fn realm_authority_builder_context(
    realm_id: &arkret_sdk::RealmId,
    actor_id: &str,
) -> anyhow::Result<(arkret_sdk::ScopeRef, arkret_sdk::DidCoreId, arkret_sdk::Hlc)> {
    Ok((
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        crate::mls_api_helpers::principal_core_id(actor_id)
            .map_err(|error| anyhow::anyhow!("invalid Realm authority actor DID: {error}"))?,
        arkret_sdk::Hlc::new("000000000000-0000-00000000")
            .map_err(|error| anyhow::anyhow!("invalid authoring HLC placeholder: {error}"))?,
    ))
}

/// Build the current-controller half of a Realm owner transfer. The payload
/// already contains the successor's independent acceptance proof.
pub fn build_realm_owner_transfer_control_event(
    actor_id: &str,
    payload: arkret_sdk::RealmOwnerTransferPayload,
) -> anyhow::Result<arkret_sdk::Event> {
    let (scope_ref, actor_id, hlc) = realm_authority_builder_context(&payload.realm_id, actor_id)?;
    arkret_policy::realm_bootstrap::build_realm_owner_transfer_event(
        scope_ref, actor_id, 1, hlc, payload,
    )
    .map_err(Into::into)
}

/// Build a destructive authority-generation reset. The SDK validates the
/// exact confirmation token and stamps the root-cell authorization reference.
pub fn build_realm_authority_reset_control_event(
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityResetPayload,
) -> anyhow::Result<arkret_sdk::Event> {
    let (scope_ref, actor_id, hlc) = realm_authority_builder_context(&payload.realm_id, actor_id)?;
    arkret_policy::realm_bootstrap::build_realm_authority_reset_event(
        scope_ref, actor_id, 1, hlc, payload,
    )
    .map_err(Into::into)
}

/// Build an explicit capability-registry basis adoption Event.
pub fn build_realm_authority_basis_update_control_event(
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityBasisUpdatePayload,
) -> anyhow::Result<arkret_sdk::Event> {
    let (scope_ref, actor_id, hlc) = realm_authority_builder_context(&payload.realm_id, actor_id)?;
    arkret_policy::realm_bootstrap::build_realm_authority_basis_update_event(
        scope_ref, actor_id, 1, hlc, payload,
    )
    .map_err(Into::into)
}

/// Build a subject-only grant relinquish Event. No revoke capability or
/// `authorization_ref` is attached.
pub fn build_capability_relinquish_control_event(
    realm_id: arkret_sdk::RealmId,
    subject_id: &str,
    payload: arkret_sdk::CapabilityRelinquishPayload,
) -> anyhow::Result<arkret_sdk::Event> {
    let (scope_ref, subject_id, hlc) = realm_authority_builder_context(&realm_id, subject_id)?;
    arkret_policy::build_capability_relinquish_event(scope_ref, subject_id, 1, hlc, payload)
        .map_err(Into::into)
}

/// Build a `ak.realm.alias` declaration — the ONLY wire carrier of a Realm
/// alias (object-addressing.md §3.3). `authority_service_id` is the deployment
/// DID that issues the alias; the alias `<domain>` MUST be its authority
/// domain, so a bare localpart is bound to it here and a foreign-domain input
/// is rejected instead of being silently rebound.
pub fn build_realm_alias_event(
    realm_id: &str,
    actor_id: &str,
    authority_service_id: &str,
    alias: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    let authority = arkret_sdk::RealmAlias::authority_domain_for_service(authority_service_id)
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot derive realm alias authority from {authority_service_id}: {error}"
            )
        })?;
    let canonical = arkret_sdk::RealmAlias::prepare_under_authority(alias, &authority)
        .map_err(|error| anyhow::anyhow!("invalid realm alias {alias:?}: {error}"))?;
    // First claim: the cell is still empty.
    build_realm_alias_payload_event(
        realm_id,
        actor_id,
        arkret_sdk::RealmAliasPayload::declaration(canonical),
        Value::Null,
    )
}

/// Rename an already-claimed alias. `settled_payload` is the whole current cell
/// value; the `cas_register` head_eq precondition is what makes a concurrent
/// rename lose instead of silently overwriting a live address.
pub fn build_realm_alias_rename_event(
    realm_id: &str,
    actor_id: &str,
    authority_service_id: &str,
    alias: &str,
    settled_payload: Value,
) -> anyhow::Result<arkret_sdk::Event> {
    let authority = arkret_sdk::RealmAlias::authority_domain_for_service(authority_service_id)
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot derive realm alias authority from {authority_service_id}: {error}"
            )
        })?;
    let canonical = arkret_sdk::RealmAlias::prepare_under_authority(alias, &authority)
        .map_err(|error| anyhow::anyhow!("invalid realm alias {alias:?}: {error}"))?;
    build_realm_alias_payload_event(
        realm_id,
        actor_id,
        arkret_sdk::RealmAliasPayload::declaration(canonical),
        settled_payload,
    )
}

/// Build the `ak.realm.alias` value tombstone that releases the Realm's alias.
/// After it is accepted the Realm is addressable only by `realm_id`.
/// `settled_payload` is the whole current cell value for the head_eq guard.
pub fn build_realm_alias_tombstone_event(
    realm_id: &str,
    actor_id: &str,
    settled_payload: Value,
) -> anyhow::Result<arkret_sdk::Event> {
    build_realm_alias_payload_event(
        realm_id,
        actor_id,
        arkret_sdk::RealmAliasPayload::tombstone(),
        settled_payload,
    )
}

fn build_realm_alias_payload_event(
    realm_id: &str,
    actor_id: &str,
    payload: arkret_sdk::RealmAliasPayload,
    expected_head: Value,
) -> anyhow::Result<arkret_sdk::Event> {
    let cell = arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_ALIAS_V1);
    let created_at = event_timestamp();
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmAlias>(realm_id, actor_id, payload)
        .preconditions(vec![head_eq_precondition(&cell, expected_head)?])
        .created_at(created_at)
        .build_sdk_event("inkson")
}

/// Emit `ak.realm.history_sharing_policy` from an already-typed policy value.
///
/// The marker fixes the Event kind and the SDK payload wrapper keeps the
/// policy value inseparable from that kind.
pub fn build_realm_history_sharing_policy_event(
    realm_id: &str,
    actor_id: &str,
    policy: arkret_sdk::HistorySharingPolicyPayloadValue,
) -> anyhow::Result<arkret_sdk::Event> {
    build_realm_state_event::<arkret_sdk::event_spec::RealmHistorySharingPolicy>(
        realm_id,
        actor_id,
        arkret_sdk::HistorySharingPolicyPayload::new(policy),
    )
}

/// Build a `ak.realm.plaintext_visible_services` event when the caller
/// supplies at least one service DID. Returns `None` when the input
/// list is empty so the bootstrap chain can skip emission entirely.
pub fn build_plaintext_visible_services_event(
    realm_id: &str,
    actor_id: &str,
    service_ids: &[String],
) -> anyhow::Result<Option<arkret_sdk::Event>> {
    // Strong type: plaintext_visible_services_payload (top-level
    // additionalProperties:false; item required fields strongly typed via the
    // SDK PlaintextDataClassKind / PlaintextServiceVisibility enums).
    //
    // Spec rename (head 37ce729 / SDK 4d5a1af): privacy / service feature enums
    // renamed `strand_body / message_body / body_only` → `strand_content /
    // message_content / content_only`. No serde alias — aggressive migration.
    use arkret_sdk::{PlaintextDataClassKind, PlaintextServiceVisibility, PlaintextVisibleService};
    let services = service_ids
        .iter()
        .map(|service| service.trim())
        .filter(|service| !service.is_empty())
        .map(|service| -> anyhow::Result<PlaintextVisibleService> {
            // ServiceDescribe exposes the canonical DidCoreId, while manual
            // configuration may still supply a resolvable full DID. Accept
            // both wire-valid representations and normalize to DidCoreId.
            let service_id = arkret_sdk::DidCoreId::new(service.to_owned())
                .or_else(|_| crate::mls_api_helpers::principal_core_id(service))
                .map_err(|err| {
                    anyhow::anyhow!("invalid plaintext service DID {service:?}: {err}")
                })?;
            Ok(PlaintextVisibleService::new(
                service_id,
                "principal_server",
                vec![
                    PlaintextDataClassKind::MessageContent,
                    PlaintextDataClassKind::FullTextIndex,
                    PlaintextDataClassKind::NotificationSummary,
                    PlaintextDataClassKind::InboxPreview,
                ],
                vec!["message_index".to_owned(), "notification_fanout".to_owned()],
                PlaintextServiceVisibility::PrivatePlaintext,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if services.is_empty() {
        return Ok(None);
    }
    let created_at = event_timestamp();
    let cell = arkret_wire::null_subject_cell(
        arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1,
    );
    let preconditions = vec![head_eq_precondition(&cell, Value::Null)?];
    let body_value = arkret_sdk::PlaintextVisibleServicesPayload::new(services);
    let event =
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmPlaintextVisibleServices>(
            realm_id, actor_id, body_value,
        )
        .preconditions(preconditions)
        .created_at(created_at)
        .build_sdk_event("inkson")?;
    Ok(Some(event))
}

/// Build a generic `ak.member.state` event on `ak.component.member.state.v1`,
/// modeling a single FSM transition (e.g. `join → leave` kick, `join → ban`
/// member ban, `leave → join` direct admission). `reason` shows up in the audit
/// trail.
pub fn build_member_state_transition_event(
    realm_id: &str,
    actor_id: &str,
    member_actor_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
) -> anyhow::Result<arkret_sdk::Event> {
    build_member_state_transition_event_with_binding(
        realm_id,
        actor_id,
        member_actor_id,
        from_state,
        to_state,
        reason,
        None,
    )
}

fn build_member_state_transition_event_with_binding(
    realm_id: &str,
    actor_id: &str,
    member_actor_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
    delivery_binding: Option<arkret_sdk::MemberDeliveryBinding>,
) -> anyhow::Result<arkret_sdk::Event> {
    use arkret_models_collaboration::governance::membership_invite::{
        MembershipPayload, MembershipPayloadState,
    };
    use arkret_models_identity::DeliveryStatus;
    let realm_id_wire = trim_realm_id(realm_id);
    let membership = match to_state {
        "join" => MembershipPayloadState::Join,
        "invite" => MembershipPayloadState::Invite,
        "knock" => MembershipPayloadState::Knock,
        "leave" => MembershipPayloadState::Leave,
        "ban" => MembershipPayloadState::Ban,
        other => return Err(anyhow::anyhow!("unknown membership state {other}")),
    };
    let member_did = crate::mls_api_helpers::principal_core_id(member_actor_id)
        .map_err(|err| anyhow::anyhow!("member actor_id not a valid core_id: {err}"))?;
    let member_cell_subject = member_did.as_str().to_owned();
    // Strong `membership_payload` (`event-payload.schema.json`). The schema's
    // `allOf` if/then makes `realm_id` + `actor_id` + `delivery_status`
    // REQUIRED whenever `membership == "join"`; we carry `realm_id` for every
    // transition (it is a valid property). Omitting it had made soland reject
    // invite-accept with `schema_violation … requires field 'realm_id'`.
    //
    // NOTE: membership_payload is `additionalProperties:false` and has NO
    // `handle` property — the prior `handle` write was an illegal field that
    // soland's schema validator rejects. The member identity is carried by
    // `actor_id`; handle evidence lives in signed HandleClaim objects on the
    // roster, not the durable membership event. The `handle` param has been
    // dropped accordingly (spec is the source of truth).
    let realm_value = arkret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("realm_id not canonical: {err}"))?;
    let mut membership_payload = if membership == MembershipPayloadState::Join {
        let delivery_status = if delivery_binding.is_some() {
            DeliveryStatus::Routable
        } else {
            DeliveryStatus::Unroutable
        };
        MembershipPayload::join(realm_value, member_did, delivery_status, reason)
    } else {
        MembershipPayload::transition(membership, member_did, reason).with_realm_id(realm_value)
    };
    if let Some(delivery_binding) = delivery_binding {
        membership_payload = membership_payload.with_delivery_binding(delivery_binding);
    }
    let cell = format!("ak:cell:ak.component.member.state.v1:{member_cell_subject}");
    let preconditions = if let Some(prior) = from_state {
        vec![head_eq_precondition(
            &cell,
            Value::String(prior.to_owned()),
        )?]
    } else {
        vec![head_eq_precondition(&cell, Value::Null)?]
    };
    TypedOperationBuilder::new::<arkret_sdk::event_spec::MemberState>(
        realm_id,
        actor_id,
        membership_payload,
    )
    .target_ref(member_cell_subject)
    .preconditions(preconditions)
    .build_sdk_event("inkson")
}

fn space_cell(cell_family: &str, space_id: &str) -> String {
    format!("ak:cell:{cell_family}:{space_id}")
}

/// Wire name of the device verification transcript this module signs.
pub const DEVICE_VERIFICATION_PROOF_TYPE: &str = "org.arkret.inkson.device_verification.proof.v1";

/// The bytes a device signs when it confirms a SAS / key verification.
///
/// This shape is deliberately **local** rather than an SDK type. `arkret-spec`
/// leaves `device-message.schema.json#/properties/content` open and registers
/// no verification-transcript `$defs`, so an SDK type would invent a wire shape
/// the spec does not define. This differs from `ak.realm.policy_bundle`, whose
/// normative payload is now represented by the SDK-owned
/// [`arkret_sdk::RealmPolicyBundlePayload`].
///
/// What the struct does buy is the property this task is about: the transcript
/// can no longer gain or lose a member by accident, because the bytes handed to
/// the signer are produced from these fields and nothing else. The member set
/// and the `skip_serializing_if` choices reproduce the previous hand-built
/// object byte-for-byte under canonical JSON — pinned by
/// `device_verification_transcript_canonical_bytes_are_unchanged`, which exists
/// so that already-signed proofs keep verifying.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceVerificationTranscript {
    #[serde(rename = "type")]
    pub transcript_type: String,
    pub from_actor: String,
    pub from_device: String,
    pub target_device: String,
    pub method: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sas_decimal: Option<[u16; 3]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_public_key: Option<String>,
}

/// A [`DeviceVerificationTranscript`] plus the detached JWS over its canonical
/// bytes. Rides inside the open part of a `ak.key.verification.*` device
/// message content (see [`build_sas_key_verification_content`]).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedDeviceVerificationProof {
    pub device_envelope: DeviceVerificationTranscript,
    pub signature: arkret_sdk::Proof,
}

impl SignedDeviceVerificationProof {
    /// JSON form used where an untyped block is required (device-message
    /// `content`, UI state, test assertions).
    pub fn to_value(&self) -> anyhow::Result<Value> {
        serde_json::to_value(self)
            .map_err(|error| anyhow::anyhow!("serialize device verification proof: {error}"))
    }
}

pub fn build_signed_device_verification_proof(
    from_actor: &str,
    from_device: &str,
    target_device: &str,
    method: &str,
    sas_decimal: Option<[u16; 3]>,
    local_public_key: Option<&str>,
    peer_public_key: Option<&str>,
    signing_key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<SignedDeviceVerificationProof> {
    let body = DeviceVerificationTranscript {
        transcript_type: DEVICE_VERIFICATION_PROOF_TYPE.to_owned(),
        from_actor: from_actor.to_owned(),
        from_device: from_device.to_owned(),
        target_device: target_device.to_owned(),
        method: method.to_owned(),
        created_at: payload_timestamp_wire(event_timestamp()),
        sas_decimal,
        local_public_key: local_public_key.map(str::to_owned),
        peer_public_key: peer_public_key.map(str::to_owned),
    };
    let transcript = serde_json::to_value(&body)
        .map_err(|error| anyhow::anyhow!("serialize device verification proof: {error}"))?;
    let canonical = arkret_sdk::canonical::canonical_json_bytes(&transcript)
        .map_err(|error| anyhow::anyhow!("canonicalize device verification proof: {error}"))?;
    // §2.2: a verification method is a DID URL rooted at the *signer's DID*.
    //
    // This used to emit `{from_device}#inkson-device`, i.e. an `ak:device:…`
    // typed id in the DID position — structurally not a DID URL, and something
    // no receiver could ever resolve. The `DidUrl` migration turned that into a
    // hard error, which is the correct outcome: the fixture/producer is fixed
    // rather than the type loosened. The replacement is the actor-scoped device
    // reference every other inkson proof already uses (`<actor DID>#<device
    // id>`); the `ak:device:` colons are inside the fragment, which the
    // `[A-Za-z0-9._:-]` fragment charset permits.
    let verification_method = arkret_sdk::DidUrl::new(format!("{from_actor}#{from_device}"))
        .map_err(|error| anyhow::anyhow!("device verification method is invalid: {error}"))?;
    let signer = arkret_sdk::signatures::proof::Ed25519DetachedJwsSigner::new(
        signing_key.clone(),
        verification_method.as_str().to_owned(),
    );
    let payload_digest = arkret_sdk::Hash::new(arkret_sdk::canonical::sha256_digest(&canonical))
        .map_err(|error| anyhow::anyhow!("hash device verification proof: {error}"))?;
    let signature = arkret_sdk::signatures::proof::build_proof_envelope(
        arkret_sdk::signatures::proof::detached_jws_kind(),
        verification_method,
        payload_digest,
        None,
        None,
        signer.sign_detached_jws(&canonical),
    );
    Ok(SignedDeviceVerificationProof {
        device_envelope: body,
        signature,
    })
}

/// `ak.key.verification.key` device-message content carrying the sender's
/// public key and the signed verification transcript.
///
/// `device-message.schema.json` requires `transaction_id` + `from_device` on
/// every `ak.key.verification.*` content and additionally `key` on
/// `ak.key.verification.key`. Inkson used to send only
/// `{device_envelope, signature}`, so the message satisfied none of the three
/// and any receiver validating against the schema had to reject it; the proof
/// block itself is legal because that content object is
/// `additionalProperties: true`.
///
/// `transaction_id` is a bare UUIDv7 rather than `arkret_sdk::TransactionId`:
/// the spec's `transaction_id` pattern is `^[A-Za-z0-9._~=-]{1,128}$`, which
/// the SDK type's `ak:transaction:` prefix cannot match.
pub fn build_sas_key_verification_content(
    transaction_id: &str,
    public_key_b64: &str,
    proof: SignedDeviceVerificationProof,
) -> anyhow::Result<arkret_sdk::KeyVerificationContent> {
    // `device-message.schema.json#/$defs/transaction_id`.
    if transaction_id.is_empty()
        || transaction_id.len() > 128
        || !transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~=-".contains(&byte))
    {
        anyhow::bail!(
            "key verification transaction_id must match ^[A-Za-z0-9._~=-]{{1,128}}$, got {transaction_id:?}"
        )
    }
    if public_key_b64.trim().is_empty() {
        anyhow::bail!("ak.key.verification.key content requires a non-empty key")
    }
    let mut content = arkret_sdk::KeyVerificationContent::new(
        arkret_sdk::DeviceMessageTransactionId::new(transaction_id.to_owned())
            .map_err(anyhow::Error::msg)?,
        arkret_sdk::DeviceId::new(proof.device_envelope.from_device.clone())?,
    );
    content.key = Some(
        arkret_sdk::NonEmptyString::new(public_key_b64.trim().to_owned())
            .map_err(anyhow::Error::msg)?,
    );
    content.extra.insert(
        "device_envelope".to_owned(),
        serde_json::to_value(proof.device_envelope)?,
    );
    content.extra.insert(
        "signature".to_owned(),
        serde_json::to_value(proof.signature)?,
    );
    Ok(content)
}

pub fn ensure_device_verification_proof_is_signed(proof: &Value) -> anyhow::Result<()> {
    let Some(signature) = proof.get("signature") else {
        anyhow::bail!("device verification proof must include a signed device envelope")
    };
    let jws = signature
        .get("jws")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if arkret_sdk::signatures::proof::validate_ed25519_detached_jws_shape(jws).is_err() {
        anyhow::bail!("device verification proof must carry an Ed25519 compact JWS")
    }
    if proof.get("device_envelope").is_none() {
        anyhow::bail!("device verification proof missing device_envelope")
    }
    Ok(())
}

#[cfg(test)]
mod notary_derivation_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn realm_bootstrap_members_require_stable_core_ids() {
        let members = parse_realm_bootstrap_members(&[
            " ak:did_core:web:alice.example ".to_owned(),
            "ak:did_core:web:alice.example".to_owned(),
        ])
        .expect("canonical did_core_id seed members are accepted");
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].actor_id, "ak:did_core:web:alice.example");

        let error = parse_realm_bootstrap_members(&["did:web:alice.example".to_owned()])
            .expect_err("full DID values are not stable Realm member identities");
        assert!(error.to_string().contains("did_core_id"));
    }

    fn agent_resolution() -> arkret_sdk::ResolutionCommitment {
        arkret_sdk::ResolutionCommitment {
            full_id: arkret_sdk::DidFullId::new("did:web:agent.example").unwrap(),
            method_history_head: format!("sha256:{}", "8".repeat(64)),
            version_id: "1-Qmfixture".to_owned(),
        }
    }

    #[test]
    fn managed_agent_pcr_prepare_freezes_an_exact_create_draft() {
        let event = build_managed_agent_pcr_create_event(
            "did:web:agent.example",
            agent_resolution(),
            "did:web:alice.example",
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
        )
        .expect("controller must freeze an exact event-derived PCR create");
        assert_eq!(event.kind, arkret_sdk::EventKind::RealmCreate);
        assert!(event.refs.is_empty());
    }

    #[test]
    fn managed_agent_pcr_bootstrap_contains_only_the_ref_free_create() {
        let events = build_managed_agent_pcr_bootstrap_events(
            "did:web:agent.example",
            agent_resolution(),
            "did:web:alice.example",
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
        )
        .expect("bootstrap create is locally authorable before provision commit");
        assert_eq!(events.len(), 1);
        assert!(events[0].refs.is_empty());
    }

    #[test]
    fn web_no_history_actor_derives_org_and_recovery_fields() {
        assert_eq!(
            inferred_controller_organization_did("did:web:alice.example"),
            Some("did:web:alice.example".to_owned())
        );
        // Multi-segment did:web path still reduces to the host authority.
        assert_eq!(
            inferred_controller_organization_did("did:web:alice.example:users:bob"),
            Some("did:web:alice.example".to_owned())
        );
        let notary = serde_json::to_value(
            realm_genesis_notary(
                arkret_sdk::NotaryProfile::SingleDid,
                "did:web:alice.example",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(notary["kind"], "single_did");
        assert_eq!(notary["actor_id"], "ak:did_core:web:alice.example");
        assert_eq!(
            notary["controller_organization"],
            "ak:did_core:web:alice.example"
        );
        assert_eq!(
            notary["recovery_members"][0],
            "ak:did_core:web:alice.example:recovery:notary"
        );
        assert_eq!(
            notary["recovery_controller_organizations"][0],
            "ak:did_core:web:alice.example:recovery"
        );
    }

    #[test]
    fn webvh_actor_fails_closed_without_fabricating_org_did() {
        // The org's webvh DID carries its own SCID, unknowable client-side —
        // so no controller_organization is derivable and none is fabricated.
        assert_eq!(
            inferred_controller_organization_did(
                "did:webvh:z2dmjBobScidVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:bob.example"
            ),
            None
        );
        let actor = "did:webvh:z2dmjBobScidVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn:bob.example";
        let notary = serde_json::to_value(
            realm_genesis_notary(arkret_sdk::NotaryProfile::SingleDid, actor).unwrap(),
        )
        .unwrap();
        // Orgless personal Realm emits the minimal `{kind, actor_id}` single_did
        // genesis (relaxed realm.schema.json single_did allOf); the notary
        // recovery path / org-scoped fields are omitted (personal Realms fall
        // back to per-user recovery, decisions/0003 §7) rather than fabricated
        // into a malformed did:webvh:<host>.
        assert_eq!(notary["kind"], "single_did");
        assert_eq!(
            notary["actor_id"],
            "ak:did_core:webvh:z2dmjBobScidVnosYTzHAMbzYDRZkVrD32ea9Sr2XNs8NkgMB5mn"
        );
        assert!(notary.get("recovery_members").is_none());
        assert!(notary.get("controller_organization").is_none());
        assert!(notary.get("recovery_controller_organizations").is_none());
    }

    /// Mirror of the Principal Server's `ak.realm.create` candidate gate
    /// (`validate_realm_proposal_policy` — soland
    /// `routing/events/operations/semantics.rs`): the authored
    /// `payload.object` MUST deserialize into the closed
    /// `ak.schema.realm_genesis.v1` model. `deny_unknown_fields` means any member
    /// the closed schema does not declare is rejected with
    /// `Realm genesis object violates ak.schema.realm_genesis.v1`, so authoring
    /// MUST NOT double-write facet state (`plaintext_visible_services`,
    /// `history_sharing_policy`, …) into the Realm object.
    fn assert_realm_candidate_matches_closed_schema(event: &arkret_sdk::Event) {
        let mut candidate = event
            .payload
            .get("object")
            .cloned()
            .expect("ak.realm.create payload carries object");
        if let Some(object) = candidate.as_object_mut() {
            object.remove("operation_id");
        }
        let realm: arkret_sdk::RealmGenesis =
            serde_json::from_value(candidate).unwrap_or_else(|error| {
                panic!("Realm genesis violates ak.schema.realm_genesis.v1: {error}")
            });
        realm
            .validate()
            .unwrap_or_else(|error| panic!("Realm genesis invariants: {error}"));
    }

    #[test]
    fn ordinary_realm_create_candidate_matches_closed_schema() {
        let (_realm_id, events) = build_realm_bootstrap_events(
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            "did:web:alice.example",
            "did:web:alice.example",
            "https://alice.example",
            "Ordinary Realm",
            Some("summary"),
            "invite_only",
            "invite",
            "shared",
            "mls_rfc9420",
            "standard",
            "closed",
            "single_did",
            "sha256",
            "ak:trust_domain:did.web.example",
            &[],
            &["did:web:media.example".to_owned()],
            // A non-empty alias, so the closed-schema gate actually sees the
            // create-time alias path. Passing `None` here is what let an
            // `object.alias` survive unnoticed in the first place.
            Some("general"),
            None,
        )
        .unwrap();
        assert_realm_candidate_matches_closed_schema(&events[0]);
        // The alias is its own facet Control Move too, never a Realm object
        // member; `ak.realm.alias` is the only carrier the spec registers.
        assert!(
            events
                .iter()
                .any(|event| event.kind.as_str() == "ak.realm.alias")
        );
        // The plaintext-visible service surface stays a dedicated facet
        // Control Move in the same genesis batch — never a Realm object member.
        assert!(
            events
                .iter()
                .any(|event| event.kind.as_str() == "ak.realm.plaintext_visible_services")
        );

        // The bundle is a flat SDK-typed payload, and both its target and its
        // genesis CAS guard come from the canonical registry contract. This is
        // the regression for clients that still read the removed flattened
        // EventKindDescriptor fields and rejected `ak.realm.policy_bundle`.
        let bundle = events
            .iter()
            .find(|event| event.kind == arkret_sdk::EventKind::RealmPolicyBundle)
            .expect("encrypted Realm bootstrap carries policy_bundle");
        let typed: arkret_sdk::RealmPolicyBundlePayload =
            serde_json::from_value(serde_json::to_value(&bundle.payload).unwrap()).unwrap();
        assert_eq!(typed.policy_revision, 1);
        assert!(!bundle.payload.contains_key("value"));
        let writes = crate::operation::project_registered_cell_writes(bundle).unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].cell.as_str(),
            "ak:cell:ak.component.realm.policy_bundle.v1:null"
        );
        assert_eq!(bundle.preconditions.len(), 1);
        assert_eq!(bundle.preconditions[0].cell, writes[0].cell);
        assert_eq!(
            bundle.preconditions[0].predicate.op,
            arkret_sdk::PredicateOp::HeadEq
        );
        assert_eq!(bundle.preconditions[0].predicate.value, Some(Value::Null));
    }

    #[test]
    fn managed_agent_pcr_create_candidate_is_event_derived_and_ref_free() {
        let event = build_managed_agent_pcr_create_event(
            "did:web:agent.example",
            agent_resolution(),
            "did:web:alice.example",
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
        )
        .expect("managed Agent create is authorable from closed protocol inputs");
        assert_eq!(
            event.realm_id,
            arkret_sdk::derive_genesis_realm_id(&event.event_id)
        );
        assert!(event.refs.is_empty());
    }

    #[test]
    fn realm_authority_and_relinquish_builders_preserve_distinct_authorization_modes() {
        let realm = "ak:realm:ASxFeEp6tO9V7cjI3A4hL2nyI_lMtmbnR6TzaYTi-EgH";
        let transfer: arkret_sdk::RealmOwnerTransferPayload = serde_json::from_value(json!({
            "realm_id": realm,
            "expected_state_digest": format!("sha256:{}", "1".repeat(64)),
            "patch": {
                "controller_id": "ak:did_core:web:bob.example",
                "controller_epoch": 1
            },
            "successor_acceptance": "successor-detached-proof"
        }))
        .unwrap();
        let event =
            build_realm_owner_transfer_control_event("did:web:alice.example", transfer).unwrap();
        assert_eq!(event.kind.as_str(), "ak.realm.owner.transfer");
        assert_eq!(
            event.authorization_ref.as_deref(),
            Some(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
        );

        let relinquish = build_capability_relinquish_control_event(
            arkret_sdk::RealmId::new(realm).unwrap(),
            "did:web:bob.example",
            arkret_sdk::CapabilityRelinquishPayload {
                grant_id: arkret_sdk::GrantId::new(
                    "ak:grant:Abgeuy84qDvMqHgAWAilTc0qrZ-TjiR81uM8oQbSyu9o",
                )
                .unwrap(),
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(relinquish.kind.as_str(), "ak.capability.relinquish");
        assert!(relinquish.authorization_ref.is_none());
    }

    #[test]
    fn plaintext_service_builder_accepts_canonical_core_service_id() {
        let event = build_plaintext_visible_services_event(
            "ak:realm:ASxFeEp6tO9V7cjI3A4hL2nyI_lMtmbnR6TzaYTi-EgH",
            "did:web:alice.example",
            &["ak:did_core:web:server.local".to_owned()],
        )
        .unwrap()
        .expect("a non-empty service list emits the policy event");

        assert_eq!(
            event.payload["services"][0]["service_id"],
            "ak:did_core:web:server.local"
        );
    }
}
