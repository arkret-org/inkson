//! Realm authority-root and CBS authoring decisions.

use super::*;

/// Authority facts pinned by a Realm's accepted `ak.realm.create`.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum RealmCreateAuthority {
    Root { controller: arkret_sdk::ActorId },
    DirectConversation,
}

pub(super) fn realm_create_authority_cache()
-> &'static Mutex<BTreeMap<String, RealmCreateAuthority>> {
    static CACHE: SyncOnceLock<Mutex<BTreeMap<String, RealmCreateAuthority>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(super) fn realm_create_authority_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<RealmCreateAuthority> {
    events.iter().find_map(|event| {
        if event.realm_id.as_str() != realm_id || event.kind != arkret_sdk::EventKind::RealmCreate {
            return None;
        }
        if event
            .payload
            .get("object")
            .and_then(|object| object.get("purpose"))
            .and_then(serde_json::Value::as_str)
            == Some("direct_conversation")
        {
            return Some(RealmCreateAuthority::DirectConversation);
        }
        Some(RealmCreateAuthority::Root {
            controller: event.actor_id.clone(),
        })
    })
}

pub(super) fn realm_create_is_encrypted_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<bool> {
    events.iter().find_map(|event| {
        if event.realm_id.as_str() != realm_id || event.kind != arkret_sdk::EventKind::RealmCreate {
            return None;
        }
        event
            .payload
            .get("object")
            .and_then(|object| object.get("encryption_profile"))
            .and_then(serde_json::Value::as_str)
            .map(|profile| profile == "mls_rfc9420")
    })
}

/// Recover the creator proposal used by Inkson's legacy Realm wizard only
/// when the accepted founding unit makes it unambiguous. The wizard paired
/// `all_history_for_current_members` with exporter content and explicit
/// `durability_policy=none`; the protocol independently forbids that history
/// policy with standard RFC 9420 content. Multiple history facets or
/// `since_join` deliberately remain unresolved.
pub(super) fn legacy_creator_genesis_proposal_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<arkret_sdk::ProposedMlsGroupGenesisBinding> {
    if realm_create_is_encrypted_from_events(events, realm_id) != Some(true) {
        return None;
    }
    let history = events
        .iter()
        .filter(|event| {
            event.realm_id.as_str() == realm_id && event.kind.as_str() == "ak.realm.history_access"
        })
        .map(|event| event.payload.get("to").and_then(serde_json::Value::as_str))
        .collect::<Vec<_>>();
    if history.as_slice() != [Some("all_history_for_current_members")] {
        return None;
    }
    Some(arkret_sdk::ProposedMlsGroupGenesisBinding {
        content_scheme: arkret_wire::ContentScheme::MlsExporterAeadV1,
        durability_policy: Some(arkret_wire::DurabilityPolicy::None),
    })
}

pub(super) fn realm_owner_covers_event_kind(kind: &str) -> bool {
    arkret_schema::capability_action(CapabilityActionId::REALM_OWNER)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&kind))
}

/// Whether a direct controller-authored Event may claim the Realm authority
/// root. Root-control-only actions are intentionally absent from the ordinary
/// `ak.realm.owner` aggregate: the root cell is their sole authority, not one
/// possible owner capability. They still must be stamped with that root claim.
pub(super) fn realm_authority_root_covers_event_kind(kind: &str) -> bool {
    arkret_schema::capability_action(kind).is_some_and(|descriptor| descriptor.root_control_only)
        || realm_owner_covers_event_kind(kind)
}

/// Return the registered authority-root claim for direct Realm-root authoring.
#[allow(clippy::expect_used)]
pub(super) fn realm_authority_root_claim(
    intent: &EventIntent,
    authority: Option<&RealmCreateAuthority>,
) -> Option<arkret_sdk::AuthorizationRef> {
    if intent.authorization_ref().is_some()
        || intent.executed_by().is_some()
        || intent.applet_id().is_some()
        || !realm_authority_root_covers_event_kind(intent.kind().as_str())
    {
        return None;
    }
    match authority? {
        RealmCreateAuthority::Root { controller } if controller == intent.actor_id() => Some(
            arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
                .expect("realm authority-root constant must be valid"),
        ),
        _ => None,
    }
}

/// Execution lane selected by the intent's actual registered writes.
pub(super) fn cbs_effect_plane_for_intent(
    intent: &EventIntent,
) -> anyhow::Result<Option<CbsEffectPlane>> {
    arkret_sdk::classify_intent_execution(intent).map_err(anyhow::Error::from)
}

/// Producer-evidence family for one human-authored intent. Actor-private
/// Events have no CBS write plane, so the shared closed selector supplies only
/// their registry-defined Data exception.
pub(super) fn signer_evidence_plane_for_intent(
    intent: &EventIntent,
) -> anyhow::Result<CbsEffectPlane> {
    crate::event_signer::event_signer_evidence_plane(
        intent.kind(),
        cbs_effect_plane_for_intent(intent)?,
    )
    .map_err(anyhow::Error::from)
}

/// Check the projection's aggregate lane, retaining atomic mixed D/S commands.
pub(super) fn validate_projected_cbs_plane(
    event: &arkret_sdk::AuthoredEvent,
) -> anyhow::Result<()> {
    let Some(plane) = arkret_schema::classify_event_execution(event.event())? else {
        return Ok(());
    };
    let digest_suite = event.digest_suite();
    let event = event.event();
    // Inkson's Realm-owner grant surface authors direct `realm_root` grants.
    // The schema projector still requires an explicit resolver so that a
    // future grant-ref dependency cannot silently acquire invented ancestry;
    // an empty resolver derives direct roots and fails closed for grant refs.
    let mut projected_plane = None;
    for write in arkret_sdk::schema::project_registered_cell_writes_with_authority_resolver(
        event,
        digest_suite,
        &|_| None,
    )
    .map_err(|error| anyhow::anyhow!("cell-write projection failed: {error}"))?
    {
        let cell = arkret_sdk::CellId::from_ref(&write.cell_id)
            .map_err(|error| anyhow::anyhow!("projected cell is invalid: {error}"))?;
        let cell_plane = cbs_cell_family_plane(cell.component()).ok_or_else(|| {
            anyhow::anyhow!(
                "projected cell references unknown cell family {}",
                cell.component()
            )
        })?;
        if projected_plane.is_none() || cell_plane == CbsEffectPlane::Control {
            projected_plane = Some(cell_plane);
        }
    }
    if projected_plane != Some(plane) {
        anyhow::bail!(
            "event {} projects {projected_plane:?} writes but declares {plane:?} execution",
            event.event_id
        );
    }
    Ok(())
}

/// Freeze the authority references for an ordinary Event after checking the local signer identity.
pub(super) fn ordinary_event_auth_context(
    intent: &EventIntent,
    authority_refs: Vec<arkret_sdk::SealId>,
) -> anyhow::Result<arkret_sdk::AuthContext> {
    let actor_id = intent.executed_by().unwrap_or_else(|| intent.actor_id());
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active signer is required for ordinary Event authoring"))?;
    let did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_did_to_core_id(&did)? != *actor_id.signing_principal_id() {
        anyhow::bail!("active signer did does not project to the Event signing principal");
    }
    Ok(arkret_sdk::AuthContext { authority_refs })
}
