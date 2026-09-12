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

/// Build the signer/key-epoch context pinned by an ordinary Event.
pub(super) fn ordinary_event_auth_context(
    intent: &EventIntent,
    authority_refs: Vec<arkret_sdk::SealId>,
) -> anyhow::Result<arkret_sdk::AuthContext> {
    let actor_id = intent.executed_by().unwrap_or_else(|| intent.actor_id());
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active signer is required for AuthContext"))?;
    let did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_did_to_core_id(&did)? != *actor_id.signing_principal_id() {
        anyhow::bail!("active signer did does not project to AuthContext actor");
    }
    Ok(arkret_sdk::AuthContext {
        key_id: ordinary_event_key_id_for(intent),
        key_epoch: 0,
        credential_epoch: None,
        authority_refs,
    })
}

fn ordinary_event_key_id_for(intent: &EventIntent) -> arkret_sdk::OpaqueLocalId {
    let controller = intent
        .executed_by()
        .map(|actor| actor.signing_principal_id().as_str())
        .unwrap_or_else(|| intent.actor_id().signing_principal_id().as_str());
    let Some(signer) = crate::event_signer::active_signer() else {
        return fallback_key_id();
    };
    if let Some(device_id) = signer.device_id() {
        return opaque_key_id(device_id);
    }
    let method = signer.verification_method();
    let method_without_query = method
        .split_once('?')
        .map(|(head, _)| head)
        .unwrap_or(method);
    let Some((method_controller, fragment)) = method_without_query.split_once('#') else {
        return fallback_key_id();
    };
    if method_controller == controller && !fragment.is_empty() {
        opaque_key_id(fragment)
    } else {
        fallback_key_id()
    }
}

fn opaque_key_id(value: &str) -> arkret_sdk::OpaqueLocalId {
    arkret_sdk::OpaqueLocalId::new(value.strip_prefix("ak:").unwrap_or(value))
        .unwrap_or_else(|_| fallback_key_id())
}

#[allow(clippy::expect_used)]
fn fallback_key_id() -> arkret_sdk::OpaqueLocalId {
    arkret_sdk::OpaqueLocalId::new("device").expect("device is a valid opaque local id")
}
