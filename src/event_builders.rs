//! Realm event and device envelope builders.
//!
//! These helpers are transport-neutral and live outside the legacy API facade.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::operation::{
    Effect, EventKind, EventRequirements, LatticeOp, LatticeOpType, OperationBuilder, Precondition,
    Predicate, PredicateOp, trim_realm_id,
};
use crate::realm_defaults::{
    RECOMMENDED_REALM_ENCRYPTION_FLOOR, RECOMMENDED_REALM_ENCRYPTION_PROFILE,
};

/// RFC3339 timestamp in the canonical wire form soland's
/// `canonical::validate_timestamp_canonical` accepts: exactly
/// `YYYY-MM-DDTHH:MM:SSZ` (20 chars, UTC `Z` suffix, NO fractional
/// seconds - spec encoding.md section 3.5).
fn event_timestamp() -> String {
    crate::clock::now_rfc3339_secs()
}

fn set_sdk_event_created_at(event: &mut cokret_sdk::Event, created_at: &str) -> anyhow::Result<()> {
    event.created_at = chrono::DateTime::parse_from_rfc3339(created_at)
        .map_err(|err| anyhow::anyhow!("event timestamp is not canonical RFC3339: {err}"))?
        .with_timezone(&chrono::Utc);
    Ok(())
}

fn cell_ref(cell: &str) -> anyhow::Result<cokret_sdk::CellRef> {
    cokret_sdk::CellRef::new(cell.to_owned())
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

fn set_effect(cell: &str, value: Value) -> anyhow::Result<Effect> {
    Ok(Effect {
        cell: cell_ref(cell)?,
        op: LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    })
}

fn transition_effect(
    cell: &str,
    from: Value,
    to: Value,
    reason: Option<String>,
) -> anyhow::Result<Effect> {
    Ok(Effect {
        cell: cell_ref(cell)?,
        op: LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(from),
            to: Some(to),
            reason,
            issuer_seq: None,
        },
    })
}

fn event_requirements_with_schema(schema_ref: &str) -> EventRequirements {
    EventRequirements {
        schema_profile_refs: vec![schema_ref.to_owned()],
        reducer_profile_ref: None,
        required_features: Vec::new(),
        critical_extensions: Vec::new(),
    }
}

/// R3.1: `handle` is the canonical `<localpart>:<domain>` wire form
/// (renamed from `handle_uri` @ cokret-spec 7157ee8 — the `cokret://`
/// URI handle form has been retired).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealmBootstrapMember {
    pub(crate) actor_id: String,
    // Bootstrap membership accepts only already-authoritative DID input.
    // Handle evidence belongs on signed HandleClaim / Directory resolution
    // paths, not on a locally synthesized membership event.
    delivery_binding: Option<Value>,
}

impl RealmBootstrapMember {
    fn from_did(did: &str) -> Self {
        Self {
            actor_id: did.trim().to_owned(),
            delivery_binding: None,
        }
    }
}

fn parse_realm_bootstrap_member(input: &str) -> anyhow::Result<RealmBootstrapMember> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("seed member is empty"));
    }
    if trimmed.starts_with("did:") {
        return Ok(RealmBootstrapMember::from_did(trimmed));
    }
    Err(anyhow::anyhow!(
        "seed member must be a DID; handle bootstrap requires a Directory-resolved invite address"
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
pub fn build_realm_bootstrap_events(
    realm_id: &str,
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
    invitees: &[String],
    plaintext_visible_services: &[String],
    alias: Option<&str>,
    content_scheme: Option<&str>,
) -> anyhow::Result<Vec<cokret_sdk::Event>> {
    // Spec realm-and-space.md §2.6: creator membership is auto-derived
    // by the reducer from `ck.realm.create`'s `created_by == actor_id`
    // (renamed from `created_by_principal` at spec head 37ce729).
    // The bootstrap MUST NOT emit an explicit `ck.member.state{join}` for
    // the creator — the reducer writes that cell atomically with the
    // create event.
    let mut events: Vec<cokret_sdk::Event> = Vec::new();
    if history_visibility.trim() == "restricted" {
        return Err(anyhow::anyhow!(
            "restricted history_visibility requires a ck.realm.history_sharing_policy event in the same ordered batch"
        ));
    }
    validate_realm_history_content_scheme_for_profile(
        encryption_profile,
        history_visibility,
        content_scheme,
    )?;
    let invitees = parse_realm_bootstrap_members(invitees)?;
    events.push(build_realm_create_event(
        realm_id,
        actor_id,
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
        plaintext_visible_services,
        alias,
        content_scheme,
    )?);
    if let Some(policy_components) =
        recommended_realm_policy_components_for_profile(encryption_profile, content_scheme)
    {
        events.push(build_realm_state_event(
            realm_id,
            actor_id,
            EventKind::RealmPolicyComponents,
            policy_components,
        )?);
    }
    events.push(build_realm_state_event(
        realm_id,
        actor_id,
        EventKind::RealmJoinRule,
        json!(join_rule),
    )?);
    events.push(build_realm_state_event(
        realm_id,
        actor_id,
        EventKind::RealmHistoryVisibility,
        json!(history_visibility),
    )?);
    if let Some(policy) =
        recommended_history_sharing_policy_for_profile(encryption_profile, history_visibility)
    {
        events.push(build_realm_history_sharing_policy_event(
            realm_id, actor_id, policy,
        )?);
    }
    events.push(build_realm_state_event(
        realm_id,
        actor_id,
        EventKind::RealmDiscovery,
        json!(discoverability),
    )?);

    if let Some(event) =
        build_plaintext_visible_services_event(realm_id, actor_id, plaintext_visible_services)?
    {
        events.push(event);
    }

    for invitee in invitees.iter() {
        if invitee.actor_id != actor_id {
            events.push(build_member_state_event(
                realm_id, actor_id, invitee, "invite",
            )?);
        }
    }
    Ok(events)
}

fn recommended_history_sharing_policy_for_profile(
    encryption_profile: &str,
    history_visibility: &str,
) -> Option<Value> {
    let encrypted = encryption_profile.trim() == RECOMMENDED_REALM_ENCRYPTION_PROFILE;
    if !encrypted {
        return None;
    }
    recommended_history_sharing_policy_for_visibility(history_visibility)
}

pub(crate) fn recommended_history_sharing_policy_for_visibility(
    history_visibility: &str,
) -> Option<Value> {
    let pre_join_visible = matches!(
        history_visibility.trim().to_ascii_lowercase().as_str(),
        "world_readable" | "shared" | "invited"
    );
    if !pre_join_visible {
        return None;
    }
    Some(json!({
        "version": 1,
        "default_key_share": "event_time_visibility",
        "pre_join_history": "allow_if_visibility_allows",
        "allowed_key_sources": ["verified_member_device"],
        "allowed_receiver_states": ["active_member"],
        "audit": {
            "share_audit_event_required": false,
            "access_audit_required": false
        }
    }))
}

#[allow(clippy::too_many_arguments)]
pub fn build_realm_create_event(
    realm_id: &str,
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
    plaintext_visible_services: &[String],
    alias: Option<&str>,
    content_scheme: Option<&str>,
) -> anyhow::Result<cokret_sdk::Event> {
    // Per spec realm-and-space.md §2.3: high_assurance security_class
    // MUST satisfy federation_policy ∈ {closed, restricted, quarantine}.
    let effective_federation_policy =
        if security_class == "high_assurance" && federation_policy == "open" {
            "restricted"
        } else {
            federation_policy
        };
    let realm_object_id = trim_realm_id(realm_id);
    let envelope_realm_id = trim_realm_id(realm_id);
    let cell = space_cell("ck.component.realm.create.v1", &envelope_realm_id);
    let created_at_for_object = event_timestamp();
    let notary = realm_genesis_notary(notary_profile, actor_id)?;
    let mut object = json!({
        "id": realm_object_id,
        "schema": "ck.schema.realm.v1",
        "title": title,
        "trust_domain": trust_domain,
        // Spec rename (head 37ce729 / SDK 4d5a1af): realm.schema.json
        // `created_by_principal` → `created_by`. No serde alias —
        // aggressive migration.
        "created_by": actor_id,
        "schema_refs": ["ck.schema.realm.v1"],
        "default_discoverability": discoverability,
        "default_join_rule": join_rule,
        "history_visibility": history_visibility,
        "encryption_profile": encryption_profile,
        "security_class": security_class,
        "federation_policy": effective_federation_policy,
        "notary_profile": notary_profile,
        "digest_algorithm": digest_algorithm,
        "notary": notary,
        "created_at": created_at_for_object,
    });
    // §2.10 content scheme (capability axis): MLS-backed realms default to the
    // history-shareable `mls-exporter-aead-v1` scheme so a late joiner CAN be
    // granted pre-join content (forward secrecy degrades to per-epoch, §2.10.5).
    // Orthogonal to `history_visibility` (the runtime delivery toggle); plaintext
    // realms carry no content scheme. An extreme-confidentiality realm may
    // instead pin `mls-rfc9420` (per-message FS, history structurally
    // unshareable) by passing `content_scheme=Some("mls-rfc9420")` — see
    // [[content-scheme-capability-vs-toggle]].
    if encryption_profile.trim() == RECOMMENDED_REALM_ENCRYPTION_PROFILE {
        // Informational declaration on the realm object; soland's *authoritative*
        // projection reads content_scheme from the policy_components cell, but
        // the object field keeps realm.schema.json self-describing.
        object["content_scheme"] =
            Value::String(resolve_realm_content_scheme(content_scheme).to_owned());
    }
    if let Some(summary) = summary
        && !summary.trim().is_empty()
    {
        object["summary"] = Value::String(summary.trim().to_owned());
    }
    // Realm alias localpart (object-addressing.md §3.3). soland binds it to the
    // deployment authority domain, then validates / uniques it on projection;
    // here we just carry the raw user input (localpart or canonical) under
    // `object.alias`. The `#` share sigil is display-only and never sent.
    if let Some(alias) = alias
        && !alias.trim().is_empty()
    {
        object["alias"] = Value::String(alias.trim().trim_start_matches('#').to_owned());
    }
    let plaintext_services = plaintext_visible_services
        .iter()
        .map(|service| service.trim())
        .filter(|service| !service.is_empty())
        .map(|service| Value::String(service.to_owned()))
        .collect::<Vec<_>>();
    if !plaintext_services.is_empty() {
        object["plaintext_visible_services"] = Value::Array(plaintext_services);
    }

    // ck.component.realm.create.v1 is an ordered-log genesis singleton;
    // the bootstrap write asserts head_eq null and sets the realm metadata.
    let preconditions = vec![head_eq_precondition(&cell, Value::Null)?];
    let effects = vec![set_effect(&cell, object.clone())?];
    // The Realm entity itself has no SDK `*CreateObject` strong type yet
    // (the realm schema is large / lives outside the operation_payloads
    // module); the `object` Value above is hand-built. But the `{object}`
    // create-payload envelope is shared, so wrap it through the SDK
    // `ObjectCreatePayload` to align the envelope shape with
    // `realm_create_payload` (object, additionalProperties:false).
    let realm_body = cokret_sdk::ObjectCreatePayload::new(object.clone())
        .to_value()
        .map_err(|e| anyhow::anyhow!("ck.realm.create payload serialize: {e}"))?;
    let mut event = OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::RealmCreate,
    )
    .target_ref(realm_id)
    .body(realm_body)
    .preconditions(preconditions)
    .effects(effects)
    .requirements(event_requirements_with_schema("ck.schema.realm.v1"))
    .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at_for_object)?;
    Ok(event)
}

pub fn encryption_profile_uses_recommended_floor(profile: &str) -> bool {
    profile
        .trim()
        .eq_ignore_ascii_case(RECOMMENDED_REALM_ENCRYPTION_PROFILE)
}

/// Resolve the effective §2.10 content scheme (capability axis) from the
/// optional caller selection: `None` or any history-capable choice ⇒ the
/// history-shareable `mls-exporter-aead-v1` default; an explicit `mls-rfc9420`
/// pins the forward-secret-only scheme. See [[content-scheme-capability-vs-toggle]].
pub fn resolve_realm_content_scheme(content_scheme: Option<&str>) -> &'static str {
    match content_scheme.map(str::trim) {
        Some("mls-rfc9420") => "mls-rfc9420",
        _ => "mls-exporter-aead-v1",
    }
}

pub fn validate_realm_history_content_scheme_for_profile(
    encryption_profile: &str,
    history_visibility: &str,
    content_scheme: Option<&str>,
) -> anyhow::Result<()> {
    if encryption_profile_uses_recommended_floor(encryption_profile) {
        cokret_sdk::validate_history_visibility_content_scheme_values(
            history_visibility,
            Some(resolve_realm_content_scheme(content_scheme)),
        )
        .map_err(|reason| anyhow::anyhow!("{reason}"))?;
    }
    Ok(())
}

pub fn recommended_realm_policy_components_value(content_scheme: Option<&str>) -> Value {
    json!({
        "policy_revision": 1,
        "content_encryption_floor": RECOMMENDED_REALM_ENCRYPTION_FLOOR,
        "metadata_encryption_floor": RECOMMENDED_REALM_ENCRYPTION_FLOOR,
        // §2.10 content scheme — soland projects the effective scheme from THIS
        // policy_components cell (`policy_floor_field(components, "content_scheme")`),
        // not from the realm.create object, and applies a one-way ratchet.
        "content_scheme": resolve_realm_content_scheme(content_scheme),
    })
}

pub fn recommended_realm_policy_components_for_profile(
    profile: &str,
    content_scheme: Option<&str>,
) -> Option<Value> {
    encryption_profile_uses_recommended_floor(profile)
        .then(|| recommended_realm_policy_components_value(content_scheme))
}

/// Build the genesis notary cell value via the SDK-authoritative
/// [`cokret_sdk::NotaryValue`] type (no hand-rolled JSON — zero schema drift),
/// then serialize it to the wire `notary` object.
fn realm_genesis_notary(notary_profile: &str, actor_id: &str) -> anyhow::Result<Value> {
    let actor_did = cokret_sdk::Did::new(actor_id.to_owned())
        .map_err(|e| anyhow::anyhow!("realm notary actor DID `{actor_id}` invalid: {e}"))?;
    let notary = match notary_profile {
        "threshold" => {
            // Single-operator genesis committee: 1-of-1. `2*1 > 1` so the
            // forensic-attribution mode is `quorum_intersection`.
            cokret_sdk::NotaryValue::Threshold {
                threshold: 1,
                members: vec![actor_did],
                forensic_attribution: cokret_sdk::ForensicAttribution::QuorumIntersection,
            }
        }
        "open_set" => cokret_sdk::NotaryValue::OpenSet {
            members: vec![actor_did],
        },
        "mixed" => cokret_sdk::NotaryValue::Mixed {
            did: actor_did,
            recovery_members: vec![parse_derived_did(&derived_recovery_member_did(actor_id))?],
        },
        _ => {
            // `controller_organization` / `recovery_controller_organizations`
            // are required only when an authoritative organization DID can be
            // derived from the actor DID (the `did:web` no-history service
            // profile, where the host *is* the org authority). For the default
            // `did:webvh` actor the org's webvh DID carries its own SCID that is
            // unknowable client-side, so we omit the org-scoped fields and emit
            // the orgless `{type, did}` single_did genesis (realm.schema.json
            // single_did allOf; decisions/0003 §7 — personal Realms fall back to
            // per-user recovery) rather than fabricate a malformed
            // `did:webvh:<host>` (no SCID) identifier.
            match inferred_controller_organization_did(actor_id) {
                Some(controller) => cokret_sdk::NotaryValue::single_did_with_org(
                    actor_did,
                    vec![parse_derived_did(&derived_recovery_member_did(
                        &controller,
                    ))?],
                    parse_derived_did(&controller)?,
                    vec![parse_derived_did(
                        &derived_recovery_controller_organization_did(&controller),
                    )?],
                ),
                None => cokret_sdk::NotaryValue::single_did(actor_did),
            }
        }
    };
    notary
        .validate()
        .map_err(|e| anyhow::anyhow!("realm genesis notary invalid: {e}"))?;
    serde_json::to_value(&notary)
        .map_err(|e| anyhow::anyhow!("serialize realm genesis notary: {e}"))
}

/// Parse a client-derived notary DID string into the SDK [`cokret_sdk::Did`].
fn parse_derived_did(did: &str) -> anyhow::Result<cokret_sdk::Did> {
    cokret_sdk::Did::new(did.to_owned())
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
    if let Ok(did) = cokret_sdk::Did::new(actor_id.to_owned())
        && cokret_sdk::identity::did_webvh_parts(&did).is_some()
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

/// Build a `ck.space.create` event per spec realm-and-space.md §3.2.
/// Space is the product-structure container (workspace / project /
/// folder / board / list); it lives inside a Realm (`realm_id`) and
/// has no membership / policy / E2EE of its own — all security
/// semantics inherit from the home Realm.
#[allow(clippy::too_many_arguments)]
pub fn build_space_create_event(
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    title: &str,
    summary: Option<&str>,
    kind: &str,
    parent_space_id: Option<&str>,
    default_realm_id: Option<&str>,
) -> anyhow::Result<cokret_sdk::Event> {
    let created_at = event_timestamp();
    // Build the canonical Space object via the SDK strong type so that
    // field names / shape stay aligned with `space_create_payload`
    // (`object`, additionalProperties:false). `created_at` is overridden
    // below with the envelope timestamp to keep wire identity with the
    // effects copy.
    let space_realm_id = cokret_sdk::RealmId::new(trim_realm_id(realm_id))
        .map_err(|e| anyhow::anyhow!("invalid realm_id for space.create: {e:?}"))?;
    let space_object_id = cokret_sdk::SpaceId::new(space_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid space_id for space.create: {e:?}"))?;
    let space_created_by = cokret_sdk::Did::new(actor_id.to_owned())
        .map_err(|e| anyhow::anyhow!("invalid created_by DID for space.create: {e:?}"))?;
    let mut space_object = cokret_sdk::SpaceCreateObject::new(
        space_object_id,
        space_realm_id,
        kind,
        title,
        space_created_by,
    );
    space_object.state = Some(cokret_sdk::SpaceState::Active);
    if let Some(summary) = summary
        && !summary.trim().is_empty()
    {
        space_object.summary = Some(summary.trim().to_owned());
    }
    if let Some(parent) = parent_space_id
        && !parent.trim().is_empty()
    {
        space_object.parent_space_id = Some(
            cokret_sdk::SpaceId::new(parent.trim().to_owned())
                .map_err(|e| anyhow::anyhow!("invalid parent_space_id: {e:?}"))?,
        );
    }
    if let Some(default_realm) = default_realm_id
        && !default_realm.trim().is_empty()
    {
        space_object.default_realm_id = Some(
            cokret_sdk::RealmId::new(trim_realm_id(default_realm.trim()))
                .map_err(|e| anyhow::anyhow!("invalid default_realm_id: {e:?}"))?,
        );
    }
    let mut object = serde_json::to_value(&space_object)
        .map_err(|e| anyhow::anyhow!("ck.space.create object serialize: {e}"))?;
    // Preserve the envelope timestamp on the wire object (SDK defaults
    // `created_at` to construction time).
    object["created_at"] = Value::String(created_at.clone());

    let cell = space_cell("ck.component.space.create.v1", space_id);
    let preconditions = vec![head_eq_precondition(&cell, Value::Null)?];
    let effects = vec![set_effect(&cell, object.clone())?];
    let space_body = cokret_sdk::ObjectCreatePayload::new(object.clone())
        .to_value()
        .map_err(|e| anyhow::anyhow!("ck.space.create payload serialize: {e}"))?;
    let mut event = OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::SpaceCreate,
    )
    .target_ref(space_id)
    .body(space_body)
    .preconditions(preconditions)
    .effects(effects)
    .requirements(event_requirements_with_schema("ck.schema.space.v1"))
    .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at)?;
    Ok(event)
}

/// Build a Space lifecycle event (`ck.space.archive` /
/// `ck.space.restore` / `ck.space.tombstone`) per spec
/// realm-and-space.md §3.4. All three write the new `state` value
/// into the `ck.component.space.state.v1` cell on the home Realm via
/// an FSM transition.
pub fn build_space_lifecycle_event(
    space_id: &str,
    realm_id: &str,
    actor_id: &str,
    kind: EventKind,
) -> anyhow::Result<cokret_sdk::Event> {
    let (prior_state, next_state) = match &kind {
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
    let space_id_typed = cokret_sdk::SpaceId::new(space_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid space id {space_id:?}: {err}"))?;
    let body = match &kind {
        EventKind::SpaceArchive | EventKind::SpaceRestore => {
            serde_json::to_value(cokret_sdk::SpaceStateTransitionPayload {
                space_id: space_id_typed.clone(),
                reason: None,
                effective_at: None,
            })
            .map_err(|err| anyhow::anyhow!("space state transition payload: {err}"))?
        }
        EventKind::SpaceTombstone => {
            serde_json::to_value(cokret_sdk::SpaceObjectTombstonePayload {
                space_id: space_id_typed,
                reason: Some("user_requested".to_owned()),
                replacement_space: None,
                replacement_event: None,
                effective_at: None,
            })
            .map_err(|err| anyhow::anyhow!("space object tombstone payload: {err}"))?
        }
        _ => unreachable!("unsupported Space lifecycle kind was rejected above"),
    };
    let created_at = event_timestamp();
    let cell = space_cell("ck.component.space.state.v1", space_id);
    let preconditions = vec![head_eq_precondition(
        &cell,
        Value::String(prior_state.to_owned()),
    )?];
    let effects = vec![transition_effect(
        &cell,
        Value::String(prior_state.to_owned()),
        Value::String(next_state.to_owned()),
        None,
    )?];
    let mut event = OperationBuilder::new(realm_id, actor_id, kind)
        .target_ref(space_id)
        .body(body)
        .preconditions(preconditions)
        .effects(effects)
        .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at)?;
    Ok(event)
}

/// Build a Realm facet state event (`ck.realm.join_rule`,
/// `ck.realm.history_visibility`, `ck.realm.discovery`, ...).
pub fn build_realm_state_event(
    realm_id: &str,
    actor_id: &str,
    kind: EventKind,
    value: Value,
) -> anyhow::Result<cokret_sdk::Event> {
    let cell_family = match &kind {
        EventKind::RealmJoinRule => "ck.component.realm.join_rule.v1",
        EventKind::RealmHistoryVisibility => "ck.component.realm.history_visibility.v1",
        EventKind::RealmHistorySharingPolicy => "ck.component.realm.history_sharing_policy.v1",
        EventKind::RealmPreviewPolicy => "ck.component.realm.preview_policy.v1",
        EventKind::RealmDiscovery => "ck.component.realm.discovery.v1",
        EventKind::RealmSchema => "ck.component.realm.schema.v1",
        EventKind::RealmPolicyComponents => "ck.component.realm.policy_components.v1",
        other => {
            return Err(anyhow::anyhow!(
                "unsupported Realm state event kind {}",
                other.as_str()
            ));
        }
    };
    let created_at = event_timestamp();
    let realm_id_wire = trim_realm_id(realm_id);
    let cell = space_cell(cell_family, &realm_id_wire);
    let preconditions = vec![head_eq_precondition(&cell, Value::Null)?];
    let effects = vec![set_effect(&cell, value.clone())?];
    // For `ck.realm.history_visibility` the body is the spec
    // `history_visibility_payload` (`{value, restricted_policy_digest?,
    // reason?}`, additionalProperties:false). Route it through the SDK strong
    // type so the enum value + the `restricted ⇒ restricted_policy_digest`
    // conditional are checked at construction; the cell effect keeps the bare
    // enum string. Other facets (`join_rule`/`discovery`/...) have no dedicated
    // spec payload def and keep the generic `{value}` body.
    let body = if kind == EventKind::RealmHistoryVisibility {
        let visibility = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("history_visibility value must be a string"))?;
        let typed: cokret_sdk::HistoryVisibility =
            serde_json::from_value(Value::String(visibility.to_owned())).map_err(|err| {
                anyhow::anyhow!("invalid history_visibility {visibility:?}: {err}")
            })?;
        cokret_sdk::HistoryVisibilityPayload::new(typed).to_value()?
    } else {
        json!({ "value": value })
    };
    let mut event = OperationBuilder::new(realm_id, actor_id, kind)
        .body(body)
        .preconditions(preconditions)
        .effects(effects)
        .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at)?;
    Ok(event)
}

/// Build a `ck.realm.archive` lifecycle facet event. Realm archive is a
/// reversible boolean register; there is no separate `ck.realm.restore`.
pub fn build_realm_archive_event(
    realm_id: &str,
    actor_id: &str,
    archived: bool,
    reason: Option<&str>,
) -> anyhow::Result<cokret_sdk::Event> {
    let created_at = event_timestamp();
    let realm_id_wire = trim_realm_id(realm_id);
    let cell = space_cell("ck.component.realm.archive.v1", &realm_id_wire);
    // Strong type: realm_archive_payload (additionalProperties:false).
    let mut typed = cokret_sdk::RealmArchivePayload::new(archived);
    if let Some(reason) = reason.map(str::trim).filter(|value| !value.is_empty()) {
        typed = typed.with_reason(reason);
    }
    let payload = typed.to_value()?;
    let effects = vec![set_effect(&cell, payload.clone())?];
    let mut event = OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::RealmArchive,
    )
    .body(payload)
    .effects(effects)
    .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at)?;
    Ok(event)
}

/// Build a `ck.realm.destroy` terminal lifecycle event.
pub fn build_realm_destroy_event(
    realm_id: &str,
    actor_id: &str,
    reason: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    let reason = reason.trim();
    if reason.is_empty() {
        return Err(anyhow::anyhow!("reason is required for ck.realm.destroy"));
    }
    let created_at = event_timestamp();
    let realm_id_wire = trim_realm_id(realm_id);
    let cell = space_cell("ck.component.realm.destroy.v1", &realm_id_wire);
    // Strong type: realm_destroy_payload (reason required; verification_stub
    // _required omitted so the reducer applies its default; additionalProperties
    // :false).
    let payload = cokret_sdk::RealmDestroyPayload::new(reason).to_value()?;
    let effects = vec![set_effect(&cell, payload.clone())?];
    let mut event = OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::RealmDestroy,
    )
    .body(payload)
    .effects(effects)
    .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at)?;
    Ok(event)
}

pub fn build_realm_history_sharing_policy_event(
    realm_id: &str,
    actor_id: &str,
    policy: Value,
) -> anyhow::Result<cokret_sdk::Event> {
    build_realm_state_event(
        realm_id,
        actor_id,
        EventKind::RealmHistorySharingPolicy,
        policy,
    )
}

/// Build a `ck.realm.plaintext_visible_services` event when the caller
/// supplies at least one service DID. Returns `None` when the input
/// list is empty so the bootstrap chain can skip emission entirely.
pub fn build_plaintext_visible_services_event(
    realm_id: &str,
    actor_id: &str,
    service_dids: &[String],
) -> anyhow::Result<Option<cokret_sdk::Event>> {
    // Strong type: plaintext_visible_services_payload (top-level
    // additionalProperties:false; item required fields strongly typed via the
    // SDK PlaintextDataClassKind / PlaintextServiceVisibility enums).
    //
    // Spec rename (head 37ce729 / SDK 4d5a1af): privacy / service feature enums
    // renamed `strand_body / message_body / body_only` → `strand_content /
    // message_content / content_only`. No serde alias — aggressive migration.
    use cokret_sdk::{PlaintextDataClassKind, PlaintextServiceVisibility, PlaintextVisibleService};
    let services = service_dids
        .iter()
        .map(|service| service.trim())
        .filter(|service| !service.is_empty())
        .map(|service| -> anyhow::Result<PlaintextVisibleService> {
            let service_did = cokret_sdk::Did::new(service.to_owned()).map_err(|err| {
                anyhow::anyhow!("invalid plaintext service DID {service:?}: {err}")
            })?;
            Ok(PlaintextVisibleService::new(
                service_did,
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
    let realm_id_wire = trim_realm_id(realm_id);
    let cell = space_cell(
        "ck.component.realm.plaintext_visible_services.v1",
        &realm_id_wire,
    );
    let preconditions = vec![head_eq_precondition(&cell, Value::Null)?];
    let body_value = cokret_sdk::PlaintextVisibleServicesPayload::new(services).to_value()?;
    let effects = vec![set_effect(&cell, body_value.clone())?];
    // Builder takes `Value` by move; reuse the value we already built for
    // the effect rather than cloning `services` a second time.
    let mut event = OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::RealmPlaintextVisibleServices,
    )
    .body(body_value)
    .preconditions(preconditions)
    .effects(effects)
    .build_sdk_event("inkson")?;
    set_sdk_event_created_at(&mut event, &created_at)?;
    Ok(Some(event))
}

fn build_member_state_event(
    realm_id: &str,
    actor_id: &str,
    member: &RealmBootstrapMember,
    membership: &str,
) -> anyhow::Result<cokret_sdk::Event> {
    build_member_state_transition_event_with_binding(
        realm_id,
        actor_id,
        &member.actor_id,
        None,
        membership,
        "space_create",
        member.delivery_binding.clone(),
    )
}

/// Build a generic `ck.member.state` event on `ck.component.member.state.v1`,
/// modeling a single FSM transition (e.g. `join → leave` kick, `join → ban`
/// member ban, `null → join` invite-accept). `reason` shows up in the audit
/// trail.
pub fn build_member_state_transition_event(
    realm_id: &str,
    actor_id: &str,
    member_actor_id: &str,
    from_state: Option<&str>,
    to_state: &str,
    reason: &str,
) -> anyhow::Result<cokret_sdk::Event> {
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
    delivery_binding: Option<Value>,
) -> anyhow::Result<cokret_sdk::Event> {
    use cokret_sdk::models::{DeliveryStatus, MembershipPayload, MembershipPayloadState};
    let realm_id_wire = trim_realm_id(realm_id);
    let membership = match to_state {
        "join" => MembershipPayloadState::Join,
        "invite" => MembershipPayloadState::Invite,
        "knock" => MembershipPayloadState::Knock,
        "leave" => MembershipPayloadState::Leave,
        "ban" => MembershipPayloadState::Ban,
        other => return Err(anyhow::anyhow!("unknown membership state {other}")),
    };
    let member_did = cokret_sdk::Did::new(member_actor_id.to_owned())
        .map_err(|err| anyhow::anyhow!("member actor_id not a valid DID: {err}"))?;
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
    let realm_value = cokret_sdk::RealmId::new(realm_id_wire.clone())
        .map_err(|err| anyhow::anyhow!("realm_id not canonical: {err}"))?;
    let mut membership_payload = if membership == MembershipPayloadState::Join {
        MembershipPayload::join(realm_value, member_did, DeliveryStatus::Unroutable, reason)
    } else {
        MembershipPayload::transition(membership, member_did, reason).with_realm_id(realm_value)
    };
    if let Some(delivery_binding) = delivery_binding {
        membership_payload = membership_payload.with_delivery_binding(delivery_binding);
    }
    let payload = membership_payload.to_value()?;
    let cell = format!("ck:cell:ck.component.member.state.v1:{member_actor_id}");
    let preconditions = if let Some(prior) = from_state {
        vec![head_eq_precondition(
            &cell,
            Value::String(prior.to_owned()),
        )?]
    } else {
        vec![head_eq_precondition(&cell, Value::Null)?]
    };
    let from_value = from_state
        .map(|s| Value::String(s.to_owned()))
        .unwrap_or(Value::Null);
    let effects = vec![transition_effect(
        &cell,
        from_value,
        Value::String(to_state.to_owned()),
        Some(reason.to_owned()),
    )?];
    OperationBuilder::new(
        realm_id,
        actor_id,
        cokret_sdk::events::kinds::EventKind::MemberState,
    )
    .target_ref(member_actor_id)
    .body(payload)
    .preconditions(preconditions)
    .effects(effects)
    .build_sdk_event("inkson")
}

fn space_cell(cell_family: &str, space_id: &str) -> String {
    format!("ck:cell:{cell_family}:{space_id}")
}

/// Build the canonical `ck.schema.device_message.v1` send envelope:
///
/// ```json
/// {
///   "messages": {
///     "<target_actor_id>": {
///       "<target_device_id>": {
///         "kind": "<kind>",
///         "expires_at": "<rfc3339>",
///         "content": <content>
///       }
///     }
///   }
/// }
/// ```
///
/// The per-target object MUST match the SDK `DeviceMessageTarget`
/// (`kind` + `content` + `expires_at`) and `device-lifecycle.md` §7,
/// which both make `kind` and `expires_at` required — the older
/// `{type, content}` shape dropped `expires_at` and mislabelled `kind`
/// as `type`, so soland had to fall back to defaults.
///
/// Pure function so the wire shape is testable without a live HTTP
/// client; used by [`CokretApi::send_device_message_envelope`] (R3).
pub fn build_device_message_envelope(
    target_actor: &str,
    target_device_id: &str,
    kind: &str,
    expires_at: &str,
    content: serde_json::Value,
) -> anyhow::Result<cokret_sdk::models::DeviceMessagesSendRequestBody> {
    let target_actor = cokret_sdk::Did::new(target_actor.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid device-message target actor: {err}"))?;
    let target_device_id = cokret_sdk::DeviceId::new(target_device_id.to_owned())
        .map_err(|err| anyhow::anyhow!("invalid device-message target device_id: {err}"))?;
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_at)
        .map_err(|err| anyhow::anyhow!("invalid device-message expires_at: {err}"))?
        .with_timezone(&chrono::Utc);

    let target = cokret_sdk::models::DeviceMessageTarget {
        kind: kind.to_owned(),
        content,
        expires_at,
    };
    let mut by_device = BTreeMap::new();
    by_device.insert(target_device_id, target);
    let mut messages = BTreeMap::new();
    messages.insert(target_actor, by_device);
    Ok(cokret_sdk::models::DeviceMessagesSendRequestBody { messages })
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
) -> anyhow::Result<Value> {
    let mut body = json!({
        "type": "ck.device.verification.proof.v1",
        "from_actor": from_actor,
        "from_device": from_device,
        "target_device": target_device,
        "method": method,
        "created_at": event_timestamp(),
    });
    if let Some(sas_decimal) = sas_decimal {
        body["sas_decimal"] = json!(sas_decimal);
    }
    if let Some(local_public_key) = local_public_key {
        body["local_public_key"] = Value::String(local_public_key.to_owned());
    }
    if let Some(peer_public_key) = peer_public_key {
        body["peer_public_key"] = Value::String(peer_public_key.to_owned());
    }
    let canonical = cokret_sdk::canonical::canonical_json_bytes(&body)
        .map_err(|error| anyhow::anyhow!("canonicalize device verification proof: {error}"))?;
    let verification_method = format!("{}#inkson-device", from_device);
    let signer = cokret_sdk::signatures::proof::Ed25519DetachedJwsSigner::new(
        signing_key.clone(),
        verification_method,
    );
    let proof = signer
        .build_proof(&canonical, None, None)
        .map_err(|error| anyhow::anyhow!("sign device verification proof: {error}"))?;
    Ok(json!({
        "device_envelope": body,
        "signature": {
            "kind": proof.kind,
            "alg": proof.alg,
            "verification_method": proof.verification_method,
            "event_digest": proof.event_digest.as_str(),
            "jws": proof.jws,
        }
    }))
}

pub fn ensure_device_verification_proof_is_signed(proof: &Value) -> anyhow::Result<()> {
    let Some(signature) = proof.get("signature") else {
        anyhow::bail!("device verification proof must include a signed device envelope")
    };
    let alg = signature
        .get("alg")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let jws = signature
        .get("jws")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if alg != "EdDSA" || jws.split('.').count() != 3 {
        anyhow::bail!("device verification proof must carry an EdDSA compact JWS")
    }
    if proof.get("device_envelope").is_none() {
        anyhow::bail!("device verification proof missing device_envelope")
    }
    Ok(())
}

#[cfg(test)]
mod notary_derivation_tests {
    use super::*;

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
        let notary = realm_genesis_notary("single_did", "did:web:alice.example").unwrap();
        assert_eq!(notary["type"], "single_did");
        assert_eq!(notary["controller_organization"], "did:web:alice.example");
        assert_eq!(
            notary["recovery_members"][0],
            "did:web:alice.example:recovery:notary"
        );
        assert_eq!(
            notary["recovery_controller_organizations"][0],
            "did:web:alice.example:recovery"
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
        let notary = realm_genesis_notary("single_did", actor).unwrap();
        // Orgless personal Realm emits the minimal `{type, did}` single_did
        // genesis (relaxed realm.schema.json single_did allOf); the notary
        // recovery path / org-scoped fields are omitted (personal Realms fall
        // back to per-user recovery, decisions/0003 §7) rather than fabricated
        // into a malformed did:webvh:<host>.
        assert_eq!(notary["type"], "single_did");
        assert_eq!(notary["did"], actor);
        assert!(notary.get("recovery_members").is_none());
        assert!(notary.get("controller_organization").is_none());
        assert!(notary.get("recovery_controller_organizations").is_none());
    }
}
