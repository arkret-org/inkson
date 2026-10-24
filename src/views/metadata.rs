//! Personal display of authenticated standard Space and Strand metadata.

use serde_json::Value;

use crate::identity::metadata::open_metadata;
use crate::state::LocalStateStore;

pub(crate) fn current_metadata(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> Option<Value> {
    let entries = store.realm_current_state_entries(realm);
    let mut values = entries.iter().filter_map(|entry| {
        let arkret_sdk::CurrentState::Value {
            selector, value, ..
        } = entry;
        let target = match selector {
            arkret_sdk::CurrentSelector::Space { space_id } => space_id.as_str(),
            arkret_sdk::CurrentSelector::Strand { strand_id } => strand_id.as_str(),
            _ => return None,
        };
        (target == id).then_some(value)
    });
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let envelope = serde_json::from_value(value.get("encrypted_metadata")?.clone()).ok()?;
    let opened = open_metadata(store, realm, id, &envelope, account, device)?;
    if id.starts_with("ak:strand:") {
        let mut strand: arkret_sdk::Strand = serde_json::from_value(value.clone()).ok()?;
        strand.encrypted_metadata = None;
        strand.metadata = Some(serde_json::from_value(opened.clone()).ok()?);
        strand.validate_profile_activation().ok()?;
    }
    Some(opened)
}

pub(crate) fn current_title(
    store: &LocalStateStore,
    realm: &str,
    id: &str,
    account: &arkret_sdk::AccountId,
    device: &arkret_sdk::DeviceId,
) -> Option<String> {
    current_metadata(store, realm, id, account, device)?
        .get("title")?
        .as_str()
        .map(str::to_owned)
}
