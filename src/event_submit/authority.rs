//! Realm authority-root and CBA authoring decisions.

use super::*;

/// Authority facts pinned by a Realm's accepted `ak.realm.create`.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum RealmCreateAuthority {
    Root { controller_id: String },
}

pub(super) fn realm_create_authority_cache()
-> &'static Mutex<BTreeMap<String, RealmCreateAuthority>> {
    static CACHE: SyncOnceLock<Mutex<BTreeMap<String, RealmCreateAuthority>>> = SyncOnceLock::new();
    CACHE.get_or_init(|| Mutex::new(BTreeMap::new()))
}

/// The first ascending Realm page contains genesis; the margin covers only
/// interleaved bootstrap follow-ups, so the lookup never paginates.
pub(super) const REALM_CREATE_AUTHORITY_QUERY_LIMIT: u32 = 16;

pub(super) fn realm_create_authority_from_events(
    events: &[arkret_sdk::Event],
    realm_id: &str,
) -> Option<RealmCreateAuthority> {
    events.iter().find_map(|event| {
        if event.realm_id.as_str() != realm_id || event.kind != arkret_sdk::EventKind::RealmCreate {
            return None;
        }
        let controller_id = event.actor_id.as_str().trim();
        if controller_id.is_empty() {
            return None;
        }
        Some(RealmCreateAuthority::Root {
            controller_id: controller_id.to_owned(),
        })
    })
}

pub(super) fn realm_owner_covers_event_kind(kind: &str) -> bool {
    arkret_schema::capability_action(CapabilityActionId::REALM_OWNER)
        .is_some_and(|descriptor| descriptor.target_event_kinds.contains(&kind))
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
        || !realm_owner_covers_event_kind(intent.kind().as_str())
    {
        return None;
    }
    match authority? {
        RealmCreateAuthority::Root { controller_id }
            if controller_id == intent.actor_id().as_str() =>
        {
            Some(
                arkret_sdk::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
                    .expect("realm authority-root constant must be valid"),
            )
        }
        _ => None,
    }
}

/// CBA plane through which the registered event contract routes this intent.
pub(super) fn cba_effect_plane_for_intent(
    kind: &arkret_sdk::events::kinds::EventKind,
) -> anyhow::Result<Option<CbaEffectPlane>> {
    let plane = kind.cba_plane();
    if kind.is_reducer_input() && plane.is_none() {
        anyhow::bail!(
            "reducer-input kind {} declares no known CBA plane",
            kind.as_str()
        );
    }
    Ok(plane)
}

/// Prove the authored event's projected cells all sit on its declared plane.
pub(super) fn validate_projected_cba_plane(
    event: &arkret_sdk::AuthoredEvent,
) -> anyhow::Result<()> {
    let Some(plane) = cba_effect_plane_for_intent(&event.kind)? else {
        return Ok(());
    };
    let digest_suite = event.digest_suite();
    let event = event.event();
    for write in crate::operation::project_registered_cell_writes(event, digest_suite)
        .map_err(|error| anyhow::anyhow!("cell-write projection failed: {error}"))?
    {
        let cell = arkret_sdk::CellId::from_ref(&write.cell)
            .map_err(|error| anyhow::anyhow!("projected cell is invalid: {error}"))?;
        let cell_plane = cba_cell_family_plane(cell.component()).ok_or_else(|| {
            anyhow::anyhow!(
                "projected cell references unknown cell family {}",
                cell.component()
            )
        })?;
        if cell_plane != plane {
            anyhow::bail!(
                "event {} projects a {cell_plane:?} cell on the {plane:?} plane",
                event.event_id
            );
        }
    }
    Ok(())
}

/// Build the signer/key-epoch context pinned by a DataEvent.
pub(super) fn data_event_auth_context(
    intent: &EventIntent,
) -> anyhow::Result<arkret_sdk::AuthContext> {
    let actor_id = intent.executed_by().unwrap_or_else(|| intent.actor_id());
    let signer = crate::event_signer::active_signer()
        .ok_or_else(|| anyhow::anyhow!("active signer is required for AuthContext"))?;
    let did = arkret_sdk::Did::new(signer.signer_did().to_owned())?;
    if arkret_sdk::project_did_to_core_id(&did)? != *actor_id {
        anyhow::bail!("active signer did does not project to AuthContext actor");
    }
    Ok(arkret_sdk::AuthContext {
        key_id: data_event_key_id_for(intent),
        key_epoch: 0,
        credential_epoch: None,
    })
}

fn data_event_key_id_for(intent: &EventIntent) -> arkret_sdk::OpaqueLocalId {
    let controller = intent
        .executed_by()
        .map(|did| did.as_str())
        .unwrap_or_else(|| intent.actor_id().as_str());
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
