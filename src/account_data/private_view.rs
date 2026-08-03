//! Actor-private View definitions carried as `ak.views.private.<view_id>`
//! encrypted account data.
//!
//! `visibility="private"` is refused by the `ak.view.create` / `ak.view.update`
//! reducers (`zh/models/views.md` §3.1), so this key is the only storage a
//! private View has. The server sees ciphertext and a key — every definition
//! rule is therefore enforced here, on the holder's device, before sealing.

use serde_json::Value;

/// One entry of the holder's private-View surface.
///
/// A View that fails to decrypt or validate is surfaced rather than dropped:
/// silently hiding one of the holder's own definitions is indistinguishable
/// from never having had it, which is exactly the failure a new device would
/// otherwise report as "my Views are gone".
#[derive(Clone, Debug)]
pub enum PrivateViewEntry {
    Loaded {
        account_data_key: String,
        revision: u64,
        view: Box<arkret_sdk::View>,
    },
    Unreadable {
        account_data_key: String,
        revision: u64,
        reason: String,
    },
}

impl PrivateViewEntry {
    pub fn account_data_key(&self) -> &str {
        match self {
            Self::Loaded {
                account_data_key, ..
            }
            | Self::Unreadable {
                account_data_key, ..
            } => account_data_key,
        }
    }

    pub fn revision(&self) -> u64 {
        match self {
            Self::Loaded { revision, .. } | Self::Unreadable { revision, .. } => *revision,
        }
    }

    pub fn view(&self) -> Option<&arkret_sdk::View> {
        match self {
            Self::Loaded { view, .. } => Some(view),
            Self::Unreadable { .. } => None,
        }
    }
}

/// Decode a decrypted private-View plaintext under `account_data_key`.
pub fn private_view_from_plaintext(
    account_data_key: &str,
    plaintext: &Value,
) -> anyhow::Result<arkret_sdk::View> {
    let view: arkret_sdk::View = serde_json::from_value(plaintext.clone())
        .map_err(|error| anyhow::anyhow!("private view plaintext: {error}"))?;
    view.validate_private_account_data(account_data_key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(view)
}

/// `(account_data_key, plaintext)` to seal for `view`.
///
/// Validating here rather than at the call site is the point: once
/// `seal_account_data_value` runs, nothing downstream — server or peer device
/// — can look inside again.
pub fn private_view_account_data_plaintext(
    view: &arkret_sdk::View,
) -> anyhow::Result<(String, Value)> {
    let account_data_key = arkret_sdk::private_view_account_data_key(&view.id);
    view.validate_private_account_data(&account_data_key)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let plaintext = serde_json::to_value(view)
        .map_err(|error| anyhow::anyhow!("private view JSON: {error}"))?;
    Ok((account_data_key, plaintext))
}

/// Private-View keys inside a full account-data listing.
///
/// `ak.self.account_data.query.list` returns every entry and takes no prefix
/// parameter, so the holder narrows the page locally.
pub fn private_view_account_data_keys<'a, I>(account_data_keys: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a str>,
{
    account_data_keys
        .into_iter()
        .filter(|key| arkret_sdk::private_view_account_data_key_view_id(key).is_some())
        .map(ToOwned::to_owned)
        .collect()
}

/// Decrypt and decode every private View in an account-data listing.
pub fn private_views_from_account_data(
    actor_id: &str,
    entries: &[arkret_sdk::AccountDataRow],
) -> Vec<PrivateViewEntry> {
    entries
        .iter()
        .filter(|entry| {
            arkret_sdk::private_view_account_data_key_view_id(&entry.account_data_key).is_some()
        })
        .map(|entry| {
            let account_data_key = entry.account_data_key.clone();
            let revision = entry.revision;
            let loaded = super::decrypt_account_data_entry(actor_id, &account_data_key, entry)
                .and_then(|plaintext| private_view_from_plaintext(&account_data_key, &plaintext));
            match loaded {
                Ok(view) => PrivateViewEntry::Loaded {
                    account_data_key,
                    revision,
                    view: Box::new(view),
                },
                Err(error) => PrivateViewEntry::Unreadable {
                    account_data_key,
                    revision,
                    reason: format!("{error:#}"),
                },
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::account_data::private_view_account_data_key;

    const VIEW_ID: &str = "ak:view:01904100-0000-7000-8000-848727f328fe";

    fn private_view_plaintext() -> Value {
        json!({
            "schema": "ak.schema.view.v1",
            "id": VIEW_ID,
            "realm_id": "ak:realm:01904100-0000-7000-8000-fd3637e8361f",
            "kind": "collection",
            "visibility": "private",
            "state": "active",
            "renderer": "board",
            "title": "Quarterly plan",
            "query": {"realm_ids": ["ak:realm:01904100-0000-7000-8000-fd3637e8361f"]},
            "collection": {},
            "created_by": "did:web:alice.example",
            "created_at": "2026-06-01T00:00:00.000Z"
        })
    }

    #[test]
    fn private_view_round_trips_through_its_own_key() {
        let key = private_view_account_data_key(VIEW_ID).unwrap();
        let view = private_view_from_plaintext(&key, &private_view_plaintext()).unwrap();
        assert_eq!(view.title.as_deref(), Some("Quarterly plan"));

        let (rebuilt_key, plaintext) = private_view_account_data_plaintext(&view).unwrap();
        assert_eq!(rebuilt_key, key);
        assert_eq!(plaintext["visibility"], "private");
        assert_eq!(plaintext["state"], "active");
    }

    #[test]
    fn private_view_requires_explicit_active_state() {
        let key = private_view_account_data_key(VIEW_ID).unwrap();
        let mut plaintext = private_view_plaintext();
        plaintext.as_object_mut().unwrap().remove("state");
        assert!(private_view_from_plaintext(&key, &plaintext).is_err());

        let mut tombstoned = private_view_plaintext();
        tombstoned["state"] = json!("tombstoned");
        tombstoned["state_changed_at"] = json!("2026-06-02T00:00:00.000Z");
        assert!(private_view_from_plaintext(&key, &tombstoned).is_err());
    }

    #[test]
    fn shared_visibility_never_loads_from_the_private_key() {
        let key = private_view_account_data_key(VIEW_ID).unwrap();
        let mut plaintext = private_view_plaintext();
        plaintext["visibility"] = json!("shared");
        assert!(private_view_from_plaintext(&key, &plaintext).is_err());

        plaintext.as_object_mut().unwrap().remove("visibility");
        assert!(private_view_from_plaintext(&key, &plaintext).is_err());
    }

    #[test]
    fn private_view_must_be_stored_under_its_own_view_id() {
        let foreign_key =
            private_view_account_data_key("ak:view:01904100-0000-7000-8000-848727f328ff").unwrap();
        assert!(private_view_from_plaintext(&foreign_key, &private_view_plaintext()).is_err());
    }

    #[test]
    fn enumeration_keeps_only_well_formed_private_view_keys() {
        let key = private_view_account_data_key(VIEW_ID).unwrap();
        let keys = private_view_account_data_keys([
            key.as_str(),
            "ak.client.ui_state",
            "ak.views.private.not-a-view-id",
            "ak.notifications.inbox.ak:notification:01904100-0000-7000-8000-848727f328fe",
        ]);
        assert_eq!(keys, vec![key]);
    }
}
