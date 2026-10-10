//! Realm event and device envelope builders.
//!
//! These helpers are transport-neutral and independent of the API transport.

use serde_json::Value;

use crate::operation::{EventKind, TypedOperationBuilder, trim_realm_id};

/// Event authoring instant normalized to the protocol's millisecond profile.
fn event_timestamp() -> chrono::DateTime<chrono::Utc> {
    crate::clock::now_utc_millis()
}

/// Build a Realm bootstrap against the exact Station captured by the
/// authenticated submitter. Production create flows use this entry point so a
/// transient reconnect cannot clear a process-global selection between UI
/// readiness and Event construction.
#[allow(clippy::too_many_arguments)]
pub fn build_realm_bootstrap_steps_for_station(
    station_id: arkret_sdk::DidCoreId,
    genesis_salt: arkret_sdk::GenesisSalt,
    actor_id: &str,
    notary_did: &str,
    notary_service_origin: &str,
    title: &str,
    summary: Option<&str>,
    discoverability: &str,
    join_rule: &str,
    history_access: &str,
    security_class: &str,
    federation_policy: &str,
    _digest_algorithm: &str,
    trust_domain: &str,
    plaintext_visible_services: &[String],
    alias: Option<&str>,
) -> anyhow::Result<Vec<crate::event_submit::EventUnitStep>> {
    let create_event = build_realm_create_event_for_station(
        station_id.clone(),
        genesis_salt,
        actor_id,
        discoverability,
        join_rule,
        history_access,
        security_class,
        trust_domain,
    )?;

    let facets = RealmBootstrapFacets {
        station_id,
        actor_id: actor_id.to_owned(),
        notary_did: notary_did.to_owned(),
        notary_service_origin: notary_service_origin.to_owned(),
        title: title.to_owned(),
        summary: summary.map(ToOwned::to_owned),
        discoverability: discoverability.to_owned(),
        join_rule: join_rule.to_owned(),
        history_access: history_access.to_owned(),
        federation_policy: federation_policy.to_owned(),
        alias: alias.map(ToOwned::to_owned),
        plaintext_visible_services: plaintext_visible_services.to_vec(),
    };
    let membership_facets = facets.clone();

    let create_step: crate::event_submit::EventUnitStep =
        Box::new(move |_authored| Ok(vec![create_event.into_intent()]));
    let facets_step: crate::event_submit::EventUnitStep = Box::new(move |authored| {
        let create = authored
            .first()
            .ok_or_else(|| anyhow::anyhow!("Realm bootstrap follow-ups need the create Event"))?;
        build_realm_bootstrap_facet_intents(
            &facets,
            create.realm_id.as_str(),
            create.digest_suite(),
        )
    });
    let membership_step: crate::event_submit::EventUnitStep = Box::new(move |authored| {
        let create = authored
            .first()
            .ok_or_else(|| anyhow::anyhow!("creator membership needs the create Event"))?;
        build_realm_bootstrap_membership_intent(&membership_facets, create.realm_id.as_str())
            .map(|intent| vec![intent])
    });
    Ok(vec![create_step, facets_step, membership_step])
}

/// The caller-chosen Realm facts every genesis follow-up is built from.
///
/// Held as owned values because the follow-ups are built later, from inside the
/// authoring chain, once the create Event has named the Realm.
#[derive(Clone)]
pub struct RealmBootstrapFacets {
    pub station_id: arkret_sdk::DidCoreId,
    pub actor_id: String,
    pub notary_did: String,
    pub notary_service_origin: String,
    pub title: String,
    pub summary: Option<String>,
    pub discoverability: String,
    pub join_rule: String,
    pub history_access: String,
    pub federation_policy: String,
    pub alias: Option<String>,
    pub plaintext_visible_services: Vec<String>,
}

/// The closed follow-up facet whitelist, scoped to the Realm the create named.
pub fn build_realm_bootstrap_facet_intents(
    facets: &RealmBootstrapFacets,
    realm_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
) -> anyhow::Result<Vec<crate::operation::EventIntent>> {
    let actor_id = facets.actor_id.as_str();
    let history_access = parse_wire_enum::<arkret_sdk::HistoryAccess>(
        "history_access",
        facets.history_access.as_str(),
    )?;
    let mut events: Vec<crate::operation::EventIntent> = Vec::new();

    let mut profile = arkret_sdk::RealmProfile::new(facets.title.trim())?;
    profile.summary = facets
        .summary
        .as_deref()
        .map(str::trim)
        .filter(|summary| !summary.is_empty())
        .map(ToOwned::to_owned);
    events.push(
        build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmProfile>(
            facets.station_id.clone(),
            realm_id,
            actor_id,
            digest_suite,
            profile,
        )?
        .into_intent(),
    );
    // realm-and-space.md §2.5: an ordinary Realm is one genesis transaction of
    // `ak.realm.create` plus the closed follow-up facet whitelist. The creator's
    // authority is the Realm genesis itself, admitted by the governance Station
    // named in that genesis, so there is no wire slot for a self-issued
    // genesis grant.
    let mut policy_bundle = arkret_sdk::RealmPolicyBundlePayload::new(1);
    policy_bundle.federation_policy = Some(parse_wire_enum(
        "federation_policy",
        &facets.federation_policy,
    )?);
    events.push(
        build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmPolicyBundle>(
            facets.station_id.clone(),
            realm_id,
            actor_id,
            digest_suite,
            policy_bundle,
        )?
        .into_intent(),
    );
    events.push(
        build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmJoinRule>(
            facets.station_id.clone(),
            realm_id,
            actor_id,
            digest_suite,
            arkret_sdk::RealmJoinRulePayload::new(
                parse_wire_enum::<arkret_sdk::RealmJoinRuleValue>("join_rule", &facets.join_rule)?,
            ),
        )?
        .into_intent(),
    );
    events.push(
        build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmHistoryAccess>(
            facets.station_id.clone(),
            realm_id,
            actor_id,
            digest_suite,
            arkret_sdk::HistoryAccessPayload::initialize(history_access),
        )?
        .into_intent(),
    );
    events.push(
        build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmDiscovery>(
            facets.station_id.clone(),
            realm_id,
            actor_id,
            digest_suite,
            arkret_sdk::RealmDiscoveryPayload::new(parse_wire_enum::<
                arkret_sdk::RealmDiscoverability,
            >(
                "discoverability", &facets.discoverability
            )?),
        )?
        .into_intent(),
    );
    // object-addressing.md §3.3: `ak.realm.alias` is the ONLY wire carrier of a
    // Realm alias, and §2.5 lists it among the seal_basis-exempt bootstrap
    // follow-ups, so naming a Realm at creation happens here rather than on the
    // closed Realm object. The alias domain is the deployment that issues it.
    //
    // Emptiness is judged AFTER stripping the `#` share sigil: the sigil is a
    // display affordance that never reaches the wire, so a sigil-only input is
    // "no alias" and must claim nothing, not fail preparation.
    if let Some(alias) = facets
        .alias
        .as_deref()
        .map(|alias| alias.trim().trim_start_matches('#').trim())
        .filter(|alias| !alias.is_empty())
    {
        events.push(
            build_realm_alias_event_for_station(
                facets.station_id.clone(),
                realm_id,
                actor_id,
                &facets.notary_did,
                alias,
            )?
            .into_intent(),
        );
    }

    if let Some(event) = build_plaintext_visible_services_event_for_station(
        facets.station_id.clone(),
        realm_id,
        actor_id,
        &facets.plaintext_visible_services,
    )? {
        events.push(event.into_intent());
    }

    Ok(events)
}

/// The creator membership. The complete ActorId carries its Station route.
/// Build the creator-membership member of the registered Realm bootstrap unit.
///
/// This is public for protocol fixture producers that author the same closed
/// unit without the application's submit queue. Normal product flows should
/// use [`build_realm_bootstrap_steps_for_station`].
pub fn build_realm_bootstrap_membership_intent(
    facets: &RealmBootstrapFacets,
    realm_id: &str,
) -> anyhow::Result<crate::operation::EventIntent> {
    let actor_id = facets.actor_id.as_str();
    Ok(build_member_state_transition_event_for_station(
        &facets.station_id,
        realm_id,
        actor_id,
        &arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(&facets.actor_id)?,
            facets.station_id.clone(),
        )),
        None,
        "join",
        "creator_membership",
        None,
    )?
    .into_intent())
}

/// Parse a wire enum token through its SDK strong type, so an unregistered
/// value fails here instead of on the receiver's schema gate.
pub(crate) fn parse_wire_enum<T: serde::de::DeserializeOwned>(
    field: &str,
    value: &str,
) -> anyhow::Result<T> {
    serde_json::from_value(Value::String(value.trim().to_owned()))
        .map_err(|err| anyhow::anyhow!("invalid {field} {value:?}: {err}"))
}

/// Build the closed `ak.schema.realm_genesis.v1` object as the SDK strong type.
///
/// Every member is a declared field of [`arkret_sdk::RealmGenesis`]
/// (`deny_unknown_fields`), so a member the schema does not carry cannot be
/// authored at all. The genesis names the initial governance Station and the
/// initial join rule, history access and discoverability; everything else the
/// creator chose is carried by the closed follow-up facet whitelist.
#[allow(clippy::too_many_arguments)]
fn build_realm_genesis_object(
    genesis_salt: arkret_sdk::GenesisSalt,
    governance_station_id: arkret_sdk::DidCoreId,
    discoverability: &str,
    join_rule: &str,
    history_access: &str,
    security_class: &str,
    trust_domain: &str,
) -> anyhow::Result<arkret_sdk::RealmGenesis> {
    let trust_domain_typed = arkret_sdk::TrustDomainId::new(trust_domain.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid trust_domain for realm.create: {err:?}"))?;
    arkret_sdk::RealmGenesis::new(
        arkret_sdk::RealmPurpose::Collaboration,
        genesis_salt,
        trust_domain_typed,
        parse_wire_enum("security_class", security_class)?,
        governance_station_id,
        parse_wire_enum("join_rule", join_rule)?,
        parse_wire_enum("history_access", history_access)?,
        parse_wire_enum("discoverability", discoverability)?,
        None,
        None,
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
) -> anyhow::Result<crate::operation::LocalOperation> {
    let created_at = event_timestamp();
    // ak.component.realm.create.v1 is an ordered-log genesis singleton;
    // the bootstrap write asserts head_eq null and sets the realm metadata.
    let realm_body = arkret_sdk::RealmCreatePayload::new(object);
    // The builder emits the closed `realm_genesis` scope for this kind, so the
    // realm id passed here is a placeholder the envelope never carries.
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmCreate>(
        arkret_sdk::RealmId::new("ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR")?
            .into_string(),
        actor_id,
        realm_body,
    )
    .created_at(created_at)
    .build_sdk_event("inkson")
}

fn build_realm_create_event_from_object_for_station(
    station_id: arkret_sdk::DidCoreId,
    actor_id: &str,
    object: arkret_sdk::RealmGenesis,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let created_at = event_timestamp();
    let realm_body = arkret_sdk::RealmCreatePayload::new(object);
    TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::RealmCreate>(
        arkret_sdk::RealmId::new("ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR")?
            .into_string(),
        actor_id,
        station_id,
        realm_body,
    )
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// Build a standalone `ak.realm.create` against the process-selected Station.
///
/// The genesis names the initial governance Station, join rule, history access
/// and discoverability. Everything else the creator chose is carried by the
/// closed follow-up facet whitelist of the bootstrap unit.
pub fn build_realm_create_event(
    genesis_salt: arkret_sdk::GenesisSalt,
    actor_id: &str,
    discoverability: &str,
    join_rule: &str,
    history_access: &str,
    security_class: &str,
    trust_domain: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let object = build_realm_genesis_object(
        genesis_salt,
        crate::operation::authoring_station_id()?,
        discoverability,
        join_rule,
        history_access,
        security_class,
        trust_domain,
    )?;
    build_realm_create_event_from_object(actor_id, object)
}

fn build_realm_create_event_for_station(
    station_id: arkret_sdk::DidCoreId,
    genesis_salt: arkret_sdk::GenesisSalt,
    actor_id: &str,
    discoverability: &str,
    join_rule: &str,
    history_access: &str,
    security_class: &str,
    trust_domain: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let object = build_realm_genesis_object(
        genesis_salt,
        station_id.clone(),
        discoverability,
        join_rule,
        history_access,
        security_class,
        trust_domain,
    )?;
    build_realm_create_event_from_object_for_station(station_id, actor_id, object)
}

/// The closed initial policy every Principal Control Realm genesis carries.
///
/// A PCR is not joinable and not discoverable: it exists to hold one
/// principal's own control facts. `history_access` is pinned by
/// `identity/key-management.md` §4.1 (`history_access=since_join`); the other
/// two are the fail-closed ends of their enums, because no `ak.realm.join_rule`
/// or `ak.realm.discovery` follow-up is in the PCR profile's event-kind
/// allowlist to widen them later.
const PCR_INITIAL_JOIN_RULE: arkret_sdk::JoinRule = arkret_sdk::JoinRule::Closed;
const PCR_INITIAL_HISTORY_ACCESS: arkret_sdk::HistoryAccess = arkret_sdk::HistoryAccess::SinceJoin;
const PCR_INITIAL_DISCOVERABILITY: arkret_sdk::Discoverability =
    arkret_sdk::Discoverability::Secret;

/// Build the create-locked Principal Control Realm genesis for a managed
/// Agent. The control facts belong to `agent_id`; the active controller only
/// executes the Event under the DID delegation returned by provisioning.
///
/// `governance_station_id` is the generation-0 governance Station the genesis
/// names (`identity/key-management.md` §4.1). It is passed in rather than read
/// from the process-global selection so a reconnect between UI readiness and
/// Event construction cannot move the frozen genesis to another Station.
pub fn build_agent_pcr_create_event(
    agent_id: &str,
    initial_resolution: arkret_sdk::ResolutionCommitment,
    governance_station_id: arkret_sdk::DidCoreId,
    controller_principal_id: &str,
    controller_authorization_ref: &str,
    trust_domain: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let created_at = event_timestamp();
    let payload = arkret_bootstrap::build_agent_pcr_create_payload(
        arkret_bootstrap::AgentPcrCreatePayloadInput {
            agent_id: crate::mls_api_helpers::principal_core_id(agent_id)?,
            governance_station_id: governance_station_id.clone(),
            initial_resolution,
            genesis_salt: arkret_sdk::GenesisSalt::generate()?,
            trust_domain: arkret_sdk::TrustDomainId::new(trust_domain.to_owned())?,
            initial_join_rule: PCR_INITIAL_JOIN_RULE,
            initial_history_access: PCR_INITIAL_HISTORY_ACCESS,
            initial_discoverability: PCR_INITIAL_DISCOVERABILITY,
        },
    )?;
    TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::RealmCreate>(
        // `RealmCreate` serializes `realm_genesis`; this placeholder is never
        // carried and is replaced by retype(the finalized EventId).
        "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR",
        agent_id,
        governance_station_id,
        payload,
    )
    .executed_by(controller_principal_id)
    .authorization_ref(controller_authorization_ref)
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// The Agent PCR genesis unit: exactly one create Event.
///
/// The unit shape is proven on the authored result, because
/// `materialize_agent_pcr_control` reads the Realm the create derives.
pub fn build_agent_pcr_bootstrap_steps(
    agent_id: &str,
    initial_resolution: arkret_sdk::ResolutionCommitment,
    governance_station_id: arkret_sdk::DidCoreId,
    controller_principal_id: &str,
    controller_authorization_ref: &str,
    trust_domain: &str,
) -> anyhow::Result<Vec<crate::event_submit::EventUnitStep>> {
    let create = build_agent_pcr_create_event(
        agent_id,
        initial_resolution,
        governance_station_id,
        controller_principal_id,
        controller_authorization_ref,
        trust_domain,
    )?
    .into_intent();
    Ok(vec![Box::new(move |_authored| Ok(vec![create]))])
}

/// Build the four-Event Direct Conversation founding chain. Authority evidence
/// belongs to the submission carrier; these Events contain only their own
/// creation and membership data. Identifiers derive from finalized Event bytes.
///
/// Only the genesis carries the branch-selecting critical founding ref
/// (contact-and-direct-conversation.md 6.1). No unit Event names another: the
/// relative order is the wire order alone. Every follow-up is scoped to the
/// Realm the create Event derives, so the unit can only be built forward from
/// real identities. Returning steps rather than Events is what enforces that:
/// there is no point at which a member exists carrying an id that the next
/// authoring pass would have to rewrite.
pub fn build_direct_conversation_founding_steps(
    founder_actor: &arkret_sdk::AccountId,
    peer_actor: &arkret_sdk::AccountId,
    trust_domain: arkret_sdk::TrustDomainId,
    evidence: &arkret_sdk::DirectConversationFoundingAuthorityEvidence,
) -> anyhow::Result<Vec<crate::event_submit::EventUnitStep>> {
    let created_at = event_timestamp();
    let founding_ref = evidence.founding_ref();
    let owned_agent = matches!(
        evidence,
        arkret_sdk::DirectConversationFoundingAuthorityEvidence::ControllerAgent { .. }
    );
    let founder_actor = founder_actor.clone();
    let peer_actor = peer_actor.clone();
    // The genesis names the governance Station the founder is authenticated
    // to: it is the Station that will commit every Event of this unit, and the
    // create Event below is routed through that same Station.
    let create_payload = arkret_sdk::direct_conversation_realm_create_payload(
        arkret_sdk::GenesisSalt::generate()?,
        trust_domain,
        founder_actor.station_id.clone(),
        created_at,
    )?;

    let founder = founder_actor.clone();
    let create_step: crate::event_submit::EventUnitStep = {
        let founder = founder.clone();
        let founding_ref = founding_ref.clone();
        Box::new(move |_authored| {
            // A genesis scope carries no Realm id; the SDK derives it from this
            // Event. The value passed here only names the scope constructor and
            // is discarded for `ak.realm.create`.
            Ok(vec![
                TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::RealmCreate>(
                    DIRECT_CONVERSATION_GENESIS_SCOPE_PLACEHOLDER,
                    founder.principal_id.as_str(),
                    founder.station_id.clone(),
                    create_payload,
                )
                .semantic_refs(vec![founding_ref.clone()])
                .created_at(created_at)
                .build_sdk_event("inkson")?
                .into_intent(),
            ])
        })
    };

    let member_step: crate::event_submit::EventUnitStep = {
        let founder = founder.clone();
        let founder_actor = founder_actor.clone();
        let peer_actor = peer_actor.clone();
        Box::new(move |authored| {
            let create = &authored[0];
            let mut membership = arkret_sdk::direct_conversation_peer_membership_bootstrap(
                create.realm_id.clone(),
                &founder_actor,
                [founder_actor.clone(), peer_actor.clone()],
            )?;
            if owned_agent {
                membership.agent_controller_binding =
                    Some(arkret_sdk::AgentControllerMembershipBinding {
                        controller_account_id: founder_actor.clone(),
                        controller_membership_generation_ref: authored[1].event_id.clone(),
                        controller_terminal_event_ref: None,
                    });
            }
            let peer_actor_id = arkret_sdk::ActorId::account(peer_actor.clone());
            let peer_actor_key = peer_actor_id.canonical_key()?;
            let member_cell_subject = peer_actor_key.to_owned();
            Ok(vec![
                TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::MemberState>(
                    create.realm_id.to_string(),
                    founder.principal_id.as_str(),
                    founder.station_id.clone(),
                    membership,
                )
                .target_ref(member_cell_subject)
                .created_at(created_at)
                .build_sdk_event("inkson")?
                .into_intent(),
            ])
        })
    };

    let strand_step: crate::event_submit::EventUnitStep = {
        let founder = founder.clone();
        let founder_actor = founder_actor.clone();
        Box::new(move |authored| {
            let create = &authored[0];
            let strand_payload = arkret_sdk::direct_conversation_main_strand_create_payload(
                create.realm_id.clone(),
                arkret_sdk::ActorId::account(founder_actor.clone()),
                created_at,
            );
            Ok(vec![
                TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::StrandCreate>(
                    create.realm_id.to_string(),
                    founder.principal_id.as_str(),
                    founder.station_id.clone(),
                    strand_payload,
                )
                .created_at(created_at)
                .build_sdk_event("inkson")?
                .into_intent(),
            ])
        })
    };

    let founder_member_step: crate::event_submit::EventUnitStep = {
        let founder = founder.clone();
        let founder_actor = founder_actor.clone();
        Box::new(move |authored| {
            let create = &authored[0];
            let founder_membership = arkret_sdk::direct_conversation_member_join_payload(
                create.realm_id.clone(),
                founder_actor.clone(),
            );
            let founder_actor_id = arkret_sdk::ActorId::account(founder_actor.clone());
            let founder_actor_key = founder_actor_id.canonical_key()?;
            let founder_member_cell_subject = founder_actor_key.to_owned();
            Ok(vec![
                TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::MemberState>(
                    create.realm_id.to_string(),
                    founder.principal_id.as_str(),
                    founder.station_id.clone(),
                    founder_membership,
                )
                .target_ref(founder_member_cell_subject)
                .created_at(created_at)
                .build_sdk_event("inkson")?
                .into_intent(),
            ])
        })
    };

    Ok(vec![
        create_step,
        founder_member_step,
        member_step,
        strand_step,
    ])
}

/// `ak.realm.create` is scoped `RealmGenesis`, so the Realm id handed to the
/// builder is parsed for validity and then discarded. This constant makes that
/// explicit instead of leaving a real-looking Realm id in a genesis call.
const DIRECT_CONVERSATION_GENESIS_SCOPE_PLACEHOLDER: &str =
    "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR";

/// Genesis `ak.realm.policy_bundle` payload. Realm creation has no content
/// scheme or encryption-profile branch; the Station admits the same closed
/// policy facet regardless of later MLS activation.
pub fn recommended_realm_policy_bundle_value() -> arkret_sdk::RealmPolicyBundlePayload {
    arkret_sdk::RealmPolicyBundlePayload::new(1)
}

/// Build a `ak.space.create` event per spec realm-and-space.md §3.2.
/// Space is the product-structure container (project / folder / board /
/// list); it lives inside a Realm (`realm_id`) and
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
) -> anyhow::Result<crate::operation::LocalOperation> {
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
    let space_created_by = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
        space_created_by,
        crate::operation::authoring_station_id()?,
    ));
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
    // Preserve the envelope timestamp on the wire object (SDK defaults
    // `created_at` to construction time).
    space_object.created_at = created_at;

    // This create has no domain precondition. The submit gate attaches its
    // AuthContext authority evidence; the registered contract projects
    // `payload.object` into the space metadata causal register.
    let space_body = arkret_sdk::SpaceCreatePayload::new(space_object);
    TypedOperationBuilder::new::<arkret_sdk::event_spec::SpaceCreate>(
        realm_id, actor_id, space_body,
    )
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
) -> anyhow::Result<crate::operation::LocalOperation> {
    // Only the prior state is the producer's to assert. The next state is
    // derived by the receiver from the registered FSM contract for this kind,
    // so naming it here would just be a second, unsigned copy of the reducer's
    // own rule.
    let (_prior_state, _) = match &kind {
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
        replacement_space_id: None,
        replacement_event_id: None,
        effective_at: None,
    };
    let created_at = event_timestamp();
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
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// Build a complete replacement for the Realm profile.
///
/// `ak.realm.profile` is a closed, typed whole-value payload. The governing
/// Station orders accepted replacements through `RealmCommit`; producers do
/// not attach a local causal head or a generic precondition to the Event.
pub fn build_realm_profile_replacement_event(
    realm_id: &str,
    actor_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
    payload: arkret_sdk::RealmProfile,
) -> anyhow::Result<crate::operation::LocalOperation> {
    build_realm_state_event_for_station::<arkret_sdk::event_spec::RealmProfile>(
        crate::operation::authoring_station_id()?,
        realm_id,
        actor_id,
        digest_suite,
        payload,
    )
}

/// Build a complete Realm profile value from the update UI.
///
/// The UI may call this an update, but the formal carrier is still the closed
/// `ak.realm.profile` replacement payload; commit order supplies authority.
pub fn build_realm_profile_update_event(
    realm_id: &str,
    actor_id: &str,
    digest_suite: arkret_sdk::DigestSuite,
    payload: arkret_sdk::RealmProfile,
) -> anyhow::Result<crate::operation::LocalOperation> {
    build_realm_profile_replacement_event(realm_id, actor_id, digest_suite, payload)
}

/// Build a Realm facet state event (`ak.realm.join_rule`,
/// `ak.realm.history_access`, `ak.realm.discovery`, ...) for the author's
/// explicit Station. Production callers take the Station from the submitter's
/// captured authority; there is no ambient variant.
pub fn build_realm_state_event_for_station<K: arkret_sdk::EventSpec>(
    station_id: arkret_sdk::DidCoreId,
    realm_id: &str,
    actor_id: &str,
    _digest_suite: arkret_sdk::DigestSuite,
    payload: K::Payload,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let realm_id = arkret_sdk::RealmId::new(crate::operation::trim_realm_id(realm_id))?;
    let builder = TypedOperationBuilder::new_for_station::<K>(
        realm_id.as_str(),
        actor_id,
        station_id,
        payload,
    )
    .created_at(event_timestamp());

    builder.build_sdk_event("inkson")
}

/// Build the explicit archive or restore Event selected by the user intent.
pub fn build_realm_archive_event(
    realm_id: &str,
    actor_id: &str,
    archived: bool,
    reason: Option<&str>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let created_at = event_timestamp();
    // Strong type: realm_archive_payload (additionalProperties:false).
    let mut typed = arkret_sdk::RealmArchivePayload::new();
    if let Some(reason) = reason.map(str::trim).filter(|value| !value.is_empty()) {
        typed = typed.with_reason(reason);
    }
    if archived {
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmArchive>(
            realm_id, actor_id, typed,
        )
        .created_at(created_at)
        .build_sdk_event("inkson")
    } else {
        TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmRestore>(
            realm_id, actor_id, typed,
        )
        .created_at(created_at)
        .build_sdk_event("inkson")
    }
}

/// Build a `ak.realm.destroy` terminal lifecycle event.
pub fn build_realm_destroy_event(
    realm_id: &str,
    actor_id: &str,
    reason: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
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
) -> anyhow::Result<(arkret_sdk::ScopeRef, arkret_sdk::ActorId)> {
    Ok((
        arkret_sdk::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            crate::mls_api_helpers::principal_core_id(actor_id)
                .map_err(|error| anyhow::anyhow!("invalid Realm authority actor DID: {error}"))?,
            crate::operation::authoring_station_id()?,
        )),
    ))
}

/// Build the current-controller half of a Realm owner transfer. The payload
/// already contains the successor's independent acceptance proof.
pub fn build_realm_owner_transfer_control_intent(
    actor_id: &str,
    payload: arkret_sdk::RealmOwnerTransferPayload,
) -> anyhow::Result<crate::operation::EventIntent> {
    let (scope_ref, actor_id) = realm_authority_builder_context(&payload.realm_id, actor_id)?;
    arkret_policy::realm_bootstrap::build_realm_owner_transfer_intent(
        scope_ref,
        actor_id,
        event_timestamp(),
        payload,
    )
    .map_err(Into::into)
}

/// Build a destructive authority-generation reset after the caller's local
/// exact-phrase confirmation. The governing Station checks the typed current
/// `expected_state_digest`; the Event carries no retired root-cell reference.
pub fn build_realm_authority_reset_control_intent(
    actor_id: &str,
    payload: arkret_sdk::RealmAuthorityResetPayload,
) -> anyhow::Result<crate::operation::EventIntent> {
    let (scope_ref, actor_id) = realm_authority_builder_context(&payload.realm_id, actor_id)?;
    arkret_event_draft::TypedEventDraft::<arkret_sdk::event_spec::RealmAuthorityReset>::new(
        scope_ref, actor_id, payload,
    )?
    .into_intent(event_timestamp())
    .map_err(Into::into)
}

/// Build a subject-only grant relinquish Event. No revoke capability or
/// `authorization_ref` is attached.
pub fn build_capability_relinquish_control_intent(
    realm_id: arkret_sdk::RealmId,
    subject_id: &str,
    payload: arkret_sdk::CapabilityRelinquishPayload,
) -> anyhow::Result<crate::operation::EventIntent> {
    let (scope_ref, subject_id) = realm_authority_builder_context(&realm_id, subject_id)?;
    arkret_policy::build_capability_relinquish_intent(
        scope_ref,
        subject_id,
        event_timestamp(),
        payload,
    )
    .map_err(Into::into)
}

/// Build a `ak.realm.alias` declaration — the ONLY wire carrier of a Realm
/// alias (object-addressing.md §3.3). `authority_service_did` is the deployment
/// DID that issues the alias; the alias `<domain>` MUST be its authority
/// domain, so a bare localpart is bound to it here and a foreign-domain input
/// is rejected instead of being silently rebound.
pub fn build_realm_alias_event(
    realm_id: &str,
    actor_id: &str,
    authority_service_did: &str,
    alias: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let authority = arkret_sdk::RealmAlias::authority_domain_for_service(authority_service_did)
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot derive realm alias authority from {authority_service_did}: {error}"
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

fn build_realm_alias_event_for_station(
    station_id: arkret_sdk::DidCoreId,
    realm_id: &str,
    actor_id: &str,
    authority_service_did: &str,
    alias: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let authority = arkret_sdk::RealmAlias::authority_domain_for_service(authority_service_did)
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot derive realm alias authority from {authority_service_did}: {error}"
            )
        })?;
    let canonical = arkret_sdk::RealmAlias::prepare_under_authority(alias, &authority)
        .map_err(|error| anyhow::anyhow!("invalid realm alias {alias:?}: {error}"))?;
    build_realm_alias_payload_event_for_station(
        station_id,
        realm_id,
        actor_id,
        arkret_sdk::RealmAliasPayload::declaration(canonical),
        Value::Null,
    )
}

/// Rename an already-claimed alias. `settled_payload` is the whole current
/// sequenced value, so a concurrent rename returns the current result instead
/// of silently overwriting a live address.
pub fn build_realm_alias_rename_event(
    realm_id: &str,
    actor_id: &str,
    authority_service_did: &str,
    alias: &str,
    settled_payload: Value,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let authority = arkret_sdk::RealmAlias::authority_domain_for_service(authority_service_did)
        .map_err(|error| {
            anyhow::anyhow!(
                "cannot derive realm alias authority from {authority_service_did}: {error}"
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
) -> anyhow::Result<crate::operation::LocalOperation> {
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
    _expected_head: Value,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let created_at = event_timestamp();
    TypedOperationBuilder::new::<arkret_sdk::event_spec::RealmAlias>(realm_id, actor_id, payload)
        .created_at(created_at)
        .build_sdk_event("inkson")
}

fn build_realm_alias_payload_event_for_station(
    station_id: arkret_sdk::DidCoreId,
    realm_id: &str,
    actor_id: &str,
    payload: arkret_sdk::RealmAliasPayload,
    _expected_head: Value,
) -> anyhow::Result<crate::operation::LocalOperation> {
    let created_at = event_timestamp();
    TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::RealmAlias>(
        realm_id, actor_id, station_id, payload,
    )
    .created_at(created_at)
    .build_sdk_event("inkson")
}

/// Build a `ak.realm.plaintext_visible_services` event when the caller
/// supplies at least one service DID. Returns `None` when the input
/// list is empty so the bootstrap chain can skip emission entirely.
pub fn build_plaintext_visible_services_event(
    realm_id: &str,
    actor_id: &str,
    service_ids: &[String],
) -> anyhow::Result<Option<crate::operation::LocalOperation>> {
    build_plaintext_visible_services_event_for_station(
        crate::operation::authoring_station_id()?,
        realm_id,
        actor_id,
        service_ids,
    )
}

fn build_plaintext_visible_services_event_for_station(
    station_id: arkret_sdk::DidCoreId,
    realm_id: &str,
    actor_id: &str,
    service_ids: &[String],
) -> anyhow::Result<Option<crate::operation::LocalOperation>> {
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
            // configuration may still supply a resolvable DID. Accept
            // both wire-valid representations and normalize to DidCoreId.
            let service_id = arkret_sdk::DidCoreId::new(service.to_owned())
                .or_else(|_| crate::mls_api_helpers::principal_core_id(service))
                .map_err(|err| {
                    anyhow::anyhow!("invalid plaintext service DID {service:?}: {err}")
                })?;
            Ok(PlaintextVisibleService::new(
                service_id,
                "station",
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
    let body_value = arkret_sdk::PlaintextVisibleServicesPayload::new(services);
    let event = TypedOperationBuilder::new_for_station::<
        arkret_sdk::event_spec::RealmPlaintextVisibleServices,
    >(realm_id, actor_id, station_id, body_value)
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
    member_actor_id: &arkret_sdk::ActorId,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
) -> anyhow::Result<crate::operation::LocalOperation> {
    build_member_state_transition_event_for_station(
        &crate::operation::authoring_station_id()?,
        realm_id,
        actor_id,
        member_actor_id,
        from_state,
        to_state,
        reason,
        None,
    )
}

/// A controller explicitly joins its own Agent, bound to the exact accepted
/// controller membership generation (`actor.md` section 3.3).
pub fn build_owned_agent_join_event(
    realm_id: &str,
    actor_id: &str,
    member: &arkret_sdk::ActorId,
    binding: arkret_sdk::AgentControllerMembershipBinding,
) -> anyhow::Result<crate::operation::LocalOperation> {
    binding.validate()?;
    anyhow::ensure!(
        crate::mls_api_helpers::principal_core_id(actor_id)?
            == binding.controller_account_id.principal_id,
        "Agent join writer differs from its controller Account"
    );
    anyhow::ensure!(
        binding.controller_terminal_event_ref.is_none(),
        "an Agent join cannot bind a terminal controller Event"
    );
    build_member_state_transition_event_for_station(
        &binding.controller_account_id.station_id.clone(),
        realm_id,
        actor_id,
        member,
        Some("leave"),
        "join",
        "controller_add_agent",
        Some(binding),
    )
}

fn build_member_state_transition_event_for_station(
    station_id: &arkret_sdk::DidCoreId,
    realm_id: &str,
    actor_id: &str,
    member_actor_id: &arkret_sdk::ActorId,
    _from_state: Option<&str>,
    to_state: &str,
    reason: &str,
    agent_controller_binding: Option<arkret_sdk::AgentControllerMembershipBinding>,
) -> anyhow::Result<crate::operation::LocalOperation> {
    use arkret_models_collaboration::governance::membership_invite::{
        MembershipPayload, MembershipPayloadState,
    };
    let realm_id_wire = trim_realm_id(realm_id);
    let membership = match to_state {
        "join" => MembershipPayloadState::Join,
        "knock" => MembershipPayloadState::Knock,
        "leave" => MembershipPayloadState::Leave,
        "ban" => MembershipPayloadState::Ban,
        other => return Err(anyhow::anyhow!("unknown membership state {other}")),
    };
    let station_id = station_id.clone();
    let member_id = member_actor_id.clone();
    // `member.state` is keyed by the complete ActorId. ActorId is structured
    // canonical JSON, so the registry's canonical_json composite rule hashes
    // that JSON string into the single safe CellRef subject segment.
    let member_actor_key = member_id.canonical_key()?;
    let member_cell_subject = member_actor_key.to_owned();
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
        MembershipPayload::join(realm_value, member_id, reason)
    } else {
        MembershipPayload::transition(membership, member_id, reason).with_realm_id(realm_value)
    };
    membership_payload.agent_controller_binding = agent_controller_binding;
    let builder = TypedOperationBuilder::new_for_station::<arkret_sdk::event_spec::MemberState>(
        realm_id,
        actor_id,
        station_id,
        membership_payload,
    );
    builder
        .target_ref(member_cell_subject)
        .build_sdk_event("inkson")
}

#[cfg(test)]
mod genesis_authority_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn owned_agent_join_carries_exact_controller_generation_and_rejects_terminal_binding() {
        let controller = arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:controller.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let member = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            controller.station_id.clone(),
        ));
        let generation =
            arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [57; 32]);
        let binding = arkret_sdk::AgentControllerMembershipBinding {
            controller_account_id: controller.clone(),
            controller_membership_generation_ref: generation.clone(),
            controller_terminal_event_ref: None,
        };
        let realm = arkret_sdk::RealmId::from_event_id(&generation);
        let intent = build_owned_agent_join_event(
            realm.as_str(),
            controller.principal_id.as_str(),
            &member,
            binding.clone(),
        )
        .unwrap()
        .into_intent();
        let payload: arkret_sdk::MembershipPayload =
            serde_json::from_value(serde_json::to_value(intent.payload()).unwrap()).unwrap();
        assert_eq!(payload.agent_controller_binding, Some(binding.clone()));
        assert_eq!(payload.member_id, member);
        assert_eq!(payload.membership, arkret_sdk::MembershipPayloadState::Join);
        assert!(payload.invite_ref.is_none());
        assert!(
            build_owned_agent_join_event(
                realm.as_str(),
                "ak:did_core:web:foreign.example",
                &member,
                binding.clone()
            )
            .is_err()
        );
        let mut terminal = binding;
        terminal.controller_terminal_event_ref = Some(arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [58; 32],
        ));
        assert!(
            build_owned_agent_join_event(
                realm.as_str(),
                controller.principal_id.as_str(),
                &member,
                terminal
            )
            .is_err()
        );
    }

    fn agent_resolution() -> arkret_sdk::ResolutionCommitment {
        arkret_sdk::ResolutionCommitment {
            did: arkret_sdk::Did::new("did:web:agent.example").unwrap(),
            method_history_head: format!("sha256:{}", "8".repeat(64)),
            version_id: "1-Qmfixture".to_owned(),
        }
    }

    /// The governance Station an Agent PCR genesis names. It is the Station
    /// the controller is authenticated to, not anything derived from the
    /// Agent's own keys.
    fn agent_governance_station() -> arkret_sdk::DidCoreId {
        crate::operation::authoring_station_id().unwrap()
    }

    #[test]
    fn agent_pcr_prepare_freezes_an_exact_create_draft() {
        let event = build_agent_pcr_create_event(
            "did:web:agent.example",
            agent_resolution(),
            agent_governance_station(),
            "did:web:alice.example",
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
        )
        .expect("controller must freeze an exact event-derived PCR create");
        assert_eq!(event.kind(), &arkret_sdk::EventKind::RealmCreate);
        assert!(event.intent().semantic_refs().is_empty());
    }

    #[test]
    fn agent_pcr_bootstrap_contains_only_the_ref_free_create() {
        let events = crate::event_submit::author_event_unit_for_test(
            build_agent_pcr_bootstrap_steps(
                "did:web:agent.example",
                agent_resolution(),
                agent_governance_station(),
                "did:web:alice.example",
                "did:web:agent.example#managed-controller",
                "ak:trust_domain:did.web.example",
            )
            .expect("bootstrap create is locally authorable before provision commit"),
        )
        .expect("the PCR bootstrap unit authors");
        assert_eq!(events.len(), 1);
        assert!(events[0].semantic_refs.is_empty());
    }

    /// Mirror of the Station's `ak.realm.create` candidate gate
    /// (`validate_realm_proposal_policy` — soland
    /// `routing/events/operations/semantics.rs`): the authored
    /// `payload.object` MUST deserialize into the closed
    /// `ak.schema.realm_genesis.v1` model. `deny_unknown_fields` means any member
    /// the closed schema does not declare is rejected with
    /// `Realm genesis object violates ak.schema.realm_genesis.v1`, so authoring
    /// MUST NOT double-write facet state (`plaintext_visible_services`,
    /// `history_access`, …) into the Realm object.
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
        let events = crate::event_submit::author_event_unit_for_test(
            build_realm_bootstrap_steps_for_station(
                crate::test_support::core_id(crate::test_support::STATION_ID),
                arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                "did:web:alice.example",
                "did:web:alice.example",
                "https://alice.example",
                "Ordinary Realm",
                Some("summary"),
                "invite_only",
                "invite",
                "since_join",
                "standard",
                "closed",
                "sha256",
                "ak:trust_domain:did.web.example",
                &["did:web:media.example".to_owned()],
                // A non-empty alias, so the closed-schema gate actually sees the
                // create-time alias path. Passing `None` here is what let an
                // `object.alias` survive unnoticed in the first place.
                Some("general"),
            )
            .unwrap(),
        )
        .expect("the Realm bootstrap unit authors");
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

        // The bundle is a flat SDK-typed payload. This is the regression for
        // clients that still read the removed flattened EventKindDescriptor
        // fields and rejected `ak.realm.policy_bundle`.
        let bundle = events
            .iter()
            .find(|event| event.kind == arkret_sdk::EventKind::RealmPolicyBundle)
            .expect("encrypted Realm bootstrap carries policy_bundle");
        let typed: arkret_sdk::RealmPolicyBundlePayload =
            serde_json::from_value(serde_json::to_value(&bundle.payload).unwrap()).unwrap();
        assert_eq!(typed.policy_revision, 1);
        assert!(!bundle.payload.contains_key("value"));

        // A producer Event carries no guard against prior state: no
        // precondition, no predecessor, no position. The authority decides
        // placement when it signs the RealmCommit, so the whole class of
        // removed coordinates is checked against the SDK's own forbidden-field
        // registry rather than a list copied into this crate.
        // `AuthoredEvent` serializes as a `{digest_suite, event}` record, so
        // the registry check has to be handed the Event envelope itself.
        let envelope =
            serde_json::to_value(bundle.event()).expect("the authored envelope serializes");
        if let Some(entry) =
            arkret_wire::forbidden_wire::forbidden_wire_violation("event_envelope", "*", &envelope)
        {
            panic!(
                "authored policy_bundle envelope carries forbidden field {}",
                entry.id
            );
        }
        for removed in ["preconditions", "cell_writes", "basis", "seal", "frontier"] {
            assert!(
                envelope.get(removed).is_none(),
                "producer Event must not carry {removed}"
            );
        }
    }

    #[test]
    fn realm_bootstrap_uses_the_explicit_authenticated_station() {
        let station_id =
            arkret_sdk::DidCoreId::new("ak:did_core:web:explicit-principal.example").unwrap();
        let events = crate::event_submit::author_event_unit_for_test(
            build_realm_bootstrap_steps_for_station(
                station_id.clone(),
                arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                    .unwrap(),
                "did:web:alice.example",
                "did:web:alice.example",
                "https://alice.example",
                "Explicit Station Realm",
                None,
                "invite_only",
                "invite",
                "since_join",
                "standard",
                "closed",
                "sha256",
                "ak:trust_domain:did.web.example",
                &[],
                None,
            )
            .unwrap(),
        )
        .expect("the Realm bootstrap unit authors");

        assert!(!events.is_empty());
        assert!(
            events
                .iter()
                .all(|event| event.actor_id.route_service_id() == &station_id)
        );
    }

    #[test]
    fn agent_pcr_create_candidate_is_event_derived_and_ref_free() {
        let event = build_agent_pcr_create_event(
            "did:web:agent.example",
            agent_resolution(),
            agent_governance_station(),
            "did:web:alice.example",
            "did:web:agent.example#managed-controller",
            "ak:trust_domain:did.web.example",
        )
        .expect("Agent create is authorable from closed protocol inputs");
        // A PCR Realm is named by its own create Event, so the binding only
        // exists once that Event is finalized.
        let authored = crate::operation::author_for_test(&event);
        assert_eq!(
            authored.realm_id,
            arkret_sdk::derive_genesis_realm_id(authored.event_id())
        );
        assert!(event.intent().semantic_refs().is_empty());
    }

    #[test]
    fn realm_owner_transfer_and_relinquish_builders_keep_distinct_payload_commitments() {
        let realm = "ak:realm:ASxFeEp6tO9V7cjI3A4hL2nyI_lMtmbnR6TzaYTi-EgH";
        let transfer: arkret_sdk::RealmOwnerTransferPayload = serde_json::from_value(json!({
            "realm_id": realm,
            "expected_state_digest": format!("sha256:{}", "1".repeat(64)),
            "patch": {
                "controller_actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:web:bob.example",
                        "station_id": "ak:did_core:web:principal.example"
                    }
                }
            },
            "successor_acceptance": "successor-detached-proof"
        }))
        .unwrap();
        let intent =
            build_realm_owner_transfer_control_intent("did:web:alice.example", transfer).unwrap();
        assert_eq!(intent.kind().as_str(), "ak.realm.owner.transfer");
        // Neither builder embeds an authorization reference any more: a
        // producer Event never names the projection state it is authorized
        // against, and the current governance Station evaluates authority
        // against the committed projection when it admits the Event.
        assert!(intent.authorization_ref().is_none());
        // What still separates the two is what each payload commits to. The
        // owner transfer names the exact authority-root state it replaces and
        // carries the successor's independent acceptance.
        assert!(intent.payload().contains_key("expected_state_digest"));
        assert!(intent.payload().contains_key("successor_acceptance"));

        let relinquish = build_capability_relinquish_control_intent(
            arkret_sdk::RealmId::new(realm).unwrap(),
            "did:web:bob.example",
            arkret_sdk::CapabilityRelinquishPayload {
                grant_id: arkret_sdk::GrantId::new(
                    "ak:grant:Abgeuy84qDvMqHgAWAilTc0qrZ-TjiR81uM8oQbSyu9o",
                )
                .unwrap(),
                expected_revision: arkret_wire::CurrentRevision {
                    commit_id: arkret_sdk::RealmCommitId::from_digest([41; 32]),
                    stream_position: 41,
                },
                reason: None,
            },
        )
        .unwrap();
        assert_eq!(relinquish.kind().as_str(), "ak.capability.relinquish");
        assert!(relinquish.authorization_ref().is_none());
        // Relinquish is subject-only: it names the grant it gives up and
        // nothing about the authority root.
        assert!(!relinquish.payload().contains_key("expected_state_digest"));
        assert!(relinquish.payload().contains_key("grant_id"));
        assert_eq!(
            relinquish.payload()["expected_revision"]["stream_position"],
            41
        );
    }

    #[test]
    fn realm_authority_reset_authors_only_the_formal_current_digest() {
        let payload: arkret_sdk::RealmAuthorityResetPayload = serde_json::from_value(json!({
            "realm_id": "ak:realm:ASxFeEp6tO9V7cjI3A4hL2nyI_lMtmbnR6TzaYTi-EgH",
            "expected_state_digest": format!("sha256:{}", "1".repeat(64)),
        }))
        .unwrap();
        let intent =
            build_realm_authority_reset_control_intent("did:web:alice.example", payload).unwrap();
        assert_eq!(intent.kind().as_str(), "ak.realm.authority.reset");
        assert_eq!(intent.payload().len(), 2);
        assert!(intent.payload().contains_key("expected_state_digest"));
        assert!(intent.authorization_ref().is_none());
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
            event.payload()["services"][0]["service_id"],
            "ak:did_core:web:server.local"
        );
    }
}
