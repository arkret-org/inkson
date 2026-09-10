//! Product reads over a bounded view of durably installed Station results.

use arkret_sdk::{CurrentEntries, CurrentResult, CurrentResultEntry, CurrentTarget};
use serde_json::Value;

pub(crate) const REQUIRED_REALM_CELLS: [&str; 4] = [
    "ak:cell:ak.component.realm.genesis.v1:null",
    "ak:cell:ak.component.realm.policy.v1:null",
    "ak:cell:ak.component.realm.policy_bundle.v1:null",
    "ak:cell:ak.component.realm.set_default_strand.v1:null",
];

fn realm_entry<'a>(
    entries: &'a [CurrentResultEntry],
    realm_id: &str,
    cell_id: &str,
) -> Option<&'a CurrentResultEntry> {
    entries.iter().find(|entry| {
        entry.selector().cell_id.as_str() == cell_id
            && matches!(&entry.selector().scope_ref,
                arkret_sdk::ScopeRef::Realm { realm_id: id } if id.as_str() == realm_id)
    })
}

pub(crate) fn required_realm_values_ready(entries: &[CurrentResultEntry], realm_id: &str) -> bool {
    REQUIRED_REALM_CELLS.iter().all(|cell| {
        realm_entry(entries, realm_id, cell)
            .is_some_and(|entry| matches!(entry.result(), CurrentResult::Value { .. }))
    })
}

/// Build presentation fields from complete current values, never from Event
/// ordering, effects or patches. All concurrent Strand heads remain in `current`.
pub(crate) fn install_bounded_view(
    projection: &mut Value,
    realm_id: &str,
    entries: Vec<CurrentResultEntry>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        entries.len() <= 512,
        "current view exceeds its in-memory budget"
    );
    anyhow::ensure!(
        arkret_sdk::canonical::canonical_json_bytes(&entries)?.len() <= 8 * 1024 * 1024,
        "current view exceeds its byte budget"
    );
    for entry in &entries {
        entry
            .selector()
            .validate_for_realm(&arkret_sdk::RealmId::new(realm_id.to_owned())?)?;
    }
    let default_strand =
        realm_entry(&entries, realm_id, REQUIRED_REALM_CELLS[3]).and_then(|entry| {
            match entry.result() {
                CurrentResult::Value { value } => value.as_json().as_str().map(ToOwned::to_owned),
                _ => None,
            }
        });
    let profile = realm_entry(
        &entries,
        realm_id,
        "ak:cell:ak.component.realm.profile.v1:null",
    )
    .and_then(|entry| match entry.result() {
        CurrentResult::Value { value } => {
            serde_json::from_value::<arkret_sdk::RealmProfile>(value.as_json().clone()).ok()
        }
        _ => None,
    });
    let object = projection
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Realm projection must be an object"))?;
    object.remove("default_strand_id");
    if let Some(strand_id) = default_strand {
        object.insert("default_strand_id".to_owned(), Value::String(strand_id));
    }
    if let Some(profile) = profile {
        let summary = object
            .entry("summary")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(summary) = summary.as_object_mut() {
            summary.insert("title".to_owned(), Value::String(profile.title));
            match profile.summary {
                Some(value) => {
                    summary.insert("summary".to_owned(), Value::String(value));
                }
                None => {
                    summary.remove("summary");
                }
            }
        }
    }
    object.insert(
        "current".to_owned(),
        serde_json::to_value(CurrentEntries { entries })?,
    );
    Ok(())
}

/// A single head can be displayed directly. Multiple heads are kept as a
/// conflict; this reader never chooses the last or largest Event id.
pub(crate) fn unique_strand_head(entry: &CurrentResultEntry) -> Option<arkret_sdk::Strand> {
    if !matches!(entry.target(), CurrentTarget::Strand { .. }) {
        return None;
    }
    let CurrentResult::Heads { heads } = entry.result() else {
        return None;
    };
    let [head] = heads.as_slice() else {
        return None;
    };
    head.value.as_strand().ok()
}
