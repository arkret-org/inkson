//! Principal Control Realm authority boundary.

pub(crate) async fn resolve_accepted<P: std::fmt::Display + ?Sized>(
    http: &arkret_sdk::http_client::Client,
    principal: &P,
) -> anyhow::Result<arkret_sdk::RealmId> {
    let active = crate::secure_key_store::active_device_seed_scope()
        .ok_or_else(|| anyhow::anyhow!("principal-control operation has no active account"))?;
    let principal = principal.to_string();
    let principal_id = if principal.starts_with("did:") {
        let did = arkret_sdk::Did::new(principal)?;
        arkret_sdk::project_did_to_core_id(&did)?
    } else {
        arkret_sdk::DidCoreId::new(principal)?
    };
    anyhow::ensure!(
        principal_id == active.authority.principal_id,
        "principal-control operation does not target the active account"
    );

    let request = arkret_sdk::PrincipalResolutionAuditRequest::new(active.authority.clone());
    let evidence = http.principal_resolution_audit(&request).await?;
    anyhow::ensure!(
        evidence.principal_id == active.authority.principal_id
            && evidence.station_id == active.authority.station_id,
        "principal resolution audit changed the selected account authority"
    );
    anyhow::ensure!(
        evidence.principal_genesis_event.realm_id == evidence.principal_control_realm_id
            && evidence.current_resolution_event.realm_id == evidence.principal_control_realm_id
            && evidence.accepted_seal.realm_id == evidence.principal_control_realm_id,
        "principal resolution audit does not close over one PCR lineage"
    );
    Ok(evidence.principal_control_realm_id)
}
