//! Inkson adapter for Garth's durable event-signing stamp allocator.

use anyhow::Context as _;
use garth::{HostClock, SigningStamp, SigningStampAllocator, StampScope};

#[derive(Clone, Copy, Debug)]
struct InksonClock;

impl HostClock for InksonClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        crate::clock::now_utc()
    }
}

pub(crate) async fn issue_event_stamp(
    event: &arkret_sdk::Event,
    observed_frontier: Option<u64>,
) -> anyhow::Result<SigningStamp> {
    let signer = crate::event_signer::active_signer().context("no active event signer")?;
    let device_id = signer
        .device_id()
        .context("active event signer is not bound to a device")?;
    let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
    let material = crate::secure_key_store::load_signing_seed(secure_store.as_ref())?
        .context("active event signing seed is unavailable")?;
    let scope = StampScope {
        service_id: None,
        actor_id: event.actor_id.clone(),
        device_id: arkret_sdk::DeviceId::new(device_id.to_owned())?,
        realm_id: event.realm_id.clone(),
    };

    #[cfg(all(not(target_arch = "wasm32"), not(test)))]
    let store = native_stamp_store()?;
    #[cfg(any(target_arch = "wasm32", test))]
    let store = memory_stamp_store();

    SigningStampAllocator::with_clock(store, scope, &material.seed, InksonClock)
        .issue(observed_frontier)
        .await
        .map_err(Into::into)
}

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

pub(crate) fn issue_protocol_hlc_for_active_device(
    actor_id: &str,
    realm_id: &str,
) -> anyhow::Result<arkret_sdk::Hlc> {
    let signer = crate::event_signer::active_signer().context("no active event signer")?;
    let device_id = signer
        .device_id()
        .context("active event signer is not bound to a device")?;
    issue_protocol_hlc(actor_id, device_id, realm_id)
}

pub(crate) fn issue_protocol_hlc_with_secret(
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    local_node_secret: &[u8],
) -> anyhow::Result<arkret_sdk::Hlc> {
    let scope = StampScope {
        service_id: None,
        actor_id: arkret_sdk::Did::new(actor_id.to_owned())?,
        device_id: arkret_sdk::DeviceId::new(device_id.to_owned())?,
        realm_id: arkret_sdk::RealmId::new(realm_id.to_owned())?,
    };
    let update = garth::StampFloorUpdate::IssueHlc {
        now_ms: crate::clock::now_unix_ms(),
    };
    #[cfg(all(not(target_arch = "wasm32"), not(test)))]
    let floor = native_stamp_store()?.advance_stamp_floor_blocking(scope.clone(), update)?;
    #[cfg(any(target_arch = "wasm32", test))]
    let floor = memory_stamp_store().advance_stamp_floor_blocking(scope.clone(), update)?;
    garth::hlc_from_floor(&scope, local_node_secret, floor).map_err(Into::into)
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
