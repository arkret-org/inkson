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
    expected_principal: &arkret_sdk::Did,
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
    let unit: arkret_wire::PcrGenesisUnit = serde_json::from_value(
        registration
            .pcr_genesis_unit
            .clone()
            .ok_or_else(|| anyhow::anyhow!("registration checkpoint omits PCR genesis unit"))?,
    )?;
    realm_from_create(
        unit.create(),
        &arkret_sdk::Did::new(registration.did.clone())?,
    )
}

pub fn unavailable(context: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{context} requires an authoritative event-derived PCR id; no accepted create, receipt, or binding was supplied"
    )
}

pub async fn resolve_accepted(
    http: &arkret_sdk::http_client::Client,
    principal: &arkret_sdk::Did,
) -> anyhow::Result<arkret_sdk::RealmId> {
    let page = http
        .events_read(&arkret_sdk::EventsQueryPostRequestBody {
            realms: Vec::new(),
            actors: vec![principal.clone()],
            before: None,
            after: None,
            order: Some("ascending".to_owned()),
            limit: Some(500),
            filters: None,
            include_completeness: Some(false),
        })
        .await?;
    if page.has_more || page.next_cursor.is_some() {
        anyhow::bail!("principal PCR actor history exceeds the bounded authoritative scan");
    }
    let mut creates = page
        .events
        .into_iter()
        .filter(|event| {
            event.kind == arkret_sdk::EventKind::RealmCreate
                && event.actor_id == *principal
                && create_object_field(event, "purpose").and_then(serde_json::Value::as_str)
                    == Some("principal_control")
        })
        .collect::<Vec<_>>();
    if creates.len() != 1 {
        anyhow::bail!(
            "principal {} has {} accepted PCR create Events; expected exactly one",
            principal,
            creates.len()
        );
    }
    let create = creates.remove(0);
    let realm_id = realm_from_create(&create, principal)?;
    let digest = arkret_sdk::Hash::new(create.event_digest()?)?;
    let resolved = http
        .events_resolve(&arkret_sdk::EventsResolveRequestBody {
            event_ids: vec![create.event_id.clone()],
            event_digests: vec![digest.clone()],
            seal_refs: Vec::new(),
            include_payload: Some(true),
        })
        .await?;
    if !resolved.events.iter().any(|event| event == &create)
        || !resolved.seals.iter().any(|seal| {
            seal.realm_id == realm_id
                && seal.delta.contains(&digest)
                && seal.covered_event_digests.contains(&digest)
        })
    {
        anyhow::bail!("principal PCR create is not covered by an accepted Seal");
    }
    Ok(realm_id)
}
