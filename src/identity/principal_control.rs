//! Event-derived Principal Control Realm helpers.

fn create_object_field<'a>(
    create: &'a arkret_sdk::Event,
    field: &str,
) -> Option<&'a serde_json::Value> {
    create
        .payload
        .get("object")
        .and_then(serde_json::Value::as_object)
        .and_then(|object| object.get(field))
}

pub fn realm_from_create(
    create: &arkret_sdk::Event,
    expected_principal: &arkret_sdk::DidCoreId,
) -> anyhow::Result<arkret_sdk::RealmId> {
    if create.kind != arkret_sdk::EventKind::RealmCreate
        || &create.actor_id != expected_principal
        || create_object_field(create, "purpose").and_then(serde_json::Value::as_str)
            != Some("principal_control")
        || create.realm_id.event_id() != create.event_id
    {
        anyhow::bail!("accepted Event is not this principal's event-derived PCR create");
    }
    Ok(create.realm_id.clone())
}

pub fn realm_from_registration(
    registration: &crate::state::PendingPrincipalRegistration,
) -> anyhow::Result<arkret_sdk::RealmId> {
    let unit = registration
        .pcr_genesis_unit
        .clone()
        .ok_or_else(|| anyhow::anyhow!("registration checkpoint omits PCR genesis unit"))?;
    realm_from_create(
        unit.create(),
        &arkret_sdk::DidCoreId::from(arkret_sdk::project_full_id_to_core_id(
            &arkret_sdk::DidFullId::new(registration.did.clone())?,
        )?),
    )
}

pub fn unavailable(context: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{context} requires an authoritative event-derived PCR id; no accepted create, receipt, or binding was supplied"
    )
}

pub(crate) trait PrincipalCoreInput: std::fmt::Display {
    fn principal_core_id(&self) -> anyhow::Result<arkret_sdk::DidCoreId>;
}

impl PrincipalCoreInput for arkret_sdk::DidCoreId {
    fn principal_core_id(&self) -> anyhow::Result<arkret_sdk::DidCoreId> {
        Ok(self.clone())
    }
}

impl PrincipalCoreInput for arkret_sdk::DidFullId {
    fn principal_core_id(&self) -> anyhow::Result<arkret_sdk::DidCoreId> {
        arkret_sdk::project_full_id_to_core_id(self).map_err(anyhow::Error::msg)
    }
}

pub(crate) async fn resolve_accepted<P: PrincipalCoreInput + ?Sized>(
    _http: &arkret_sdk::http_client::Client,
    _principal: &P,
) -> anyhow::Result<arkret_sdk::RealmId> {
    anyhow::bail!(
        "principal-control operation requires a frozen PCR authority context; current actor-history resolution is disabled"
    )
}
