//! Inkson adapter for Garth's durable event-signing stamp allocator.

#[cfg(not(test))]
use anyhow::Context as _;
use garth::StampScope;

pub(crate) fn issue_protocol_hlc(
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
) -> anyhow::Result<arkret_sdk::Hlc> {
    #[cfg(not(test))]
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    #[cfg(not(test))]
    let material = crate::secure_key_store::load_signing_seed(secure_store.as_ref())?
        .context("active event signing seed is unavailable")?;
    #[cfg(not(test))]
    let local_node_secret = material.seed;
    #[cfg(test)]
    let local_node_secret = [0x49; 32];
    issue_protocol_hlc_with_secret(actor_id, device_id, realm_id, &local_node_secret)
}

/// Allocate HLC metadata for account-data payloads before their transport
/// resolves the holder's event-derived PCR. The constant is only a local
/// allocator namespace and is never used as the account-data Event realm.
pub(crate) fn issue_account_data_hlc(
    actor_id: &str,
    device_id: &str,
) -> anyhow::Result<arkret_sdk::Hlc> {
    issue_protocol_hlc(
        actor_id,
        device_id,
        "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR",
    )
}

pub(crate) fn issue_protocol_hlc_with_secret(
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    local_node_secret: &[u8],
) -> anyhow::Result<arkret_sdk::Hlc> {
    let scope = StampScope {
        service_id: None,
        actor_id: crate::mls_api_helpers::principal_core_id(actor_id)?,
        device_id: arkret_sdk::DeviceId::new(device_id.to_owned())?,
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
    };
    let update = garth::StampFloorUpdate::IssueHlc {
        now_ms: crate::clock::now_unix_ms(),
    };
    #[cfg(all(not(target_arch = "wasm32"), not(test)))]
    let floor = native_stamp_store()?.advance_floor_sync(scope.clone(), update)?;
    #[cfg(any(target_arch = "wasm32", test))]
    let floor = memory_stamp_store().advance_floor_sync(scope.clone(), update)?;
    garth::hlc_from_floor(&scope, local_node_secret, floor).map_err(Into::into)
}

/// Allocate the first Realm-create HLC before the Event-derived Realm id
/// exists. This constant is only a local allocator namespace; it is never
/// written into the Event and does not predict or alias the resulting Realm.
pub(crate) fn issue_realm_genesis_hlc_with_secret(
    actor_id: &str,
    device_id: &str,
    local_node_secret: &[u8],
) -> anyhow::Result<arkret_sdk::Hlc> {
    issue_protocol_hlc_with_secret(
        actor_id,
        device_id,
        "ak:realm:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR",
        local_node_secret,
    )
}

#[cfg(all(not(target_arch = "wasm32"), not(test)))]
fn native_stamp_store() -> anyhow::Result<garth::FileStore> {
    garth::FileStore::open(crate::state::app_data_dir().join("signing-stamps-v1.json"))
        .map_err(Into::into)
}

#[cfg(any(target_arch = "wasm32", test))]
fn memory_stamp_store() -> garth::MemoryStore {
    thread_local! {
        static STORE: garth::MemoryStore = garth::MemoryStore::new();
    }
    STORE.with(Clone::clone)
}

#[cfg(test)]
mod tests {
    #[test]
    fn synchronous_local_hlc_issuance_is_monotonic() {
        let actor = "ak:did_core:web:sync-stamp-test.example";
        let device = "ak:device:01964137-0000-7000-8000-000000000021";
        let realm = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
        let first = super::issue_protocol_hlc_with_secret(actor, device, realm, &[7; 32]).unwrap();
        let second = super::issue_protocol_hlc_with_secret(actor, device, realm, &[7; 32]).unwrap();
        assert!(second.as_str() > first.as_str());
    }
}
