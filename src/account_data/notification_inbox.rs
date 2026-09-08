//! Cross-device Notification inbox state
//! (`ak.notifications.inbox.<notification_id>`).
//!
//! Per `zh/discovery/client-preferences.md` §3.2 this key carries only
//! `dismissed` / `archived`; `read` / `unread` stay derived from the read
//! cursor and MUST NOT be written here. The key is a `cas_register`, so the
//! merge below runs on plaintext inside the account-data CAS retry loop.

use std::cmp::Ordering;

use arkret_sdk::{NotificationInboxState, NotificationInboxValue};
use serde_json::Value;

/// Build the plaintext for one notification's inbox state.
pub fn notification_inbox_value(
    notification_id: &str,
    state: NotificationInboxState,
    updated_hlc: &str,
    origin_device_id: &str,
) -> anyhow::Result<NotificationInboxValue> {
    let value = NotificationInboxValue {
        notification_id: arkret_sdk::NotificationIdentity::new(notification_id.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        state,
        updated_hlc: arkret_sdk::Hlc::new(updated_hlc.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
        origin_device_id: arkret_sdk::DeviceId::new(origin_device_id.to_owned())
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    };
    Ok(value)
}

/// Decode the decrypted value stored under `account_data_key`.
pub fn notification_inbox_value_from_plaintext(
    account_data_key: &str,
    plaintext: &Value,
) -> anyhow::Result<NotificationInboxValue> {
    NotificationInboxValue::from_account_data(account_data_key, plaintext)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Elect the winner between the local intent and whatever the server holds.
///
/// This is the body of the CAS retry loop's merge closure: on a `cas_conflict`
/// the caller re-reads the authoritative value and calls this again, so every
/// device converges on the same plaintext without server-side ordering.
pub fn merge_notification_inbox_values(
    local: NotificationInboxValue,
    remote: Option<&NotificationInboxValue>,
) -> anyhow::Result<NotificationInboxValue> {
    let Some(remote) = remote else {
        return Ok(local);
    };
    let order = local
        .compare_precedence(remote)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(match order {
        Ordering::Greater => local,
        Ordering::Less | Ordering::Equal => remote.clone(),
    })
}

/// Merge body for the account-data CAS retry loop.
///
/// The stored value is ciphertext, so every attempt decrypts what the server
/// currently holds, elects a winner on plaintext, and re-seals. A stored value
/// that cannot be decrypted or does not bind this key is refused rather than
/// overwritten — losing another device's state to a decode bug is worse than
/// failing the write.
pub fn merge_notification_inbox_account_data(
    authority: &arkret_sdk::AccountId,
    account_data_key: &str,
    candidate: &NotificationInboxValue,
    current: Option<&arkret_sdk::AccountDataRow>,
) -> anyhow::Result<Value> {
    let remote = match current {
        Some(current) => {
            let plaintext =
                super::decrypt_account_data_entry(authority, account_data_key, current)?;
            Some(notification_inbox_value_from_plaintext(
                account_data_key,
                &plaintext,
            )?)
        }
        None => None,
    };
    let winner = merge_notification_inbox_values(candidate.clone(), remote.as_ref())?;
    super::encrypt_account_data_value(authority, account_data_key, &serde_json::to_value(&winner)?)
}

/// Inbox states carried by the `ak.account_data.set` Events in a sync frame.
///
/// Entries that do not decrypt or do not bind their own key are skipped: a
/// foreign or corrupt inbox record must never silently archive a notification.
pub fn notification_inbox_states_from_account_data_events(
    authority: &arkret_sdk::AccountId,
    events: &[arkret_sdk::Event],
) -> Vec<NotificationInboxValue> {
    events
        .iter()
        .filter_map(|event| {
            let account_data_key = event.payload.get("key")?.as_str()?;
            arkret_sdk::notification_inbox_account_data_key_notification_id(account_data_key)?;
            let plaintext =
                super::decrypt_account_data_entry(authority, account_data_key, &event.payload)
                    .ok()?;
            notification_inbox_value_from_plaintext(account_data_key, &plaintext).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const NOTIFICATION_ID: &str = "ak:notification:01904100-0000-7000-8000-848727f328fe";
    const DEVICE_A: &str = "ak:device:01904100-0000-7000-8000-000000000001";
    const DEVICE_B: &str = "ak:device:01904100-0000-7000-8000-000000000002";

    fn key() -> String {
        crate::account_data::notification_inbox_account_data_key(NOTIFICATION_ID).unwrap()
    }

    #[test]
    fn inbox_value_round_trips_through_its_own_key() {
        let value = notification_inbox_value(
            NOTIFICATION_ID,
            NotificationInboxState::Archived,
            "01970e589d21-0001-a13f9c2e",
            DEVICE_A,
        )
        .unwrap();
        assert_eq!(value.account_data_key(), key());

        let plaintext = serde_json::to_value(&value).unwrap();
        assert_eq!(
            notification_inbox_value_from_plaintext(&key(), &plaintext).unwrap(),
            value
        );
    }

    #[test]
    fn read_cursor_states_are_not_writable_here() {
        let plaintext = json!({
            "notification_id": NOTIFICATION_ID,
            "state": "read",
            "updated_hlc": "01970e589d21-0001-a13f9c2e",
            "origin_device_id": DEVICE_A
        });
        assert!(notification_inbox_value_from_plaintext(&key(), &plaintext).is_err());
    }

    #[test]
    fn merge_prefers_newer_hlc_then_higher_device_id() {
        let older = notification_inbox_value(
            NOTIFICATION_ID,
            NotificationInboxState::Dismissed,
            "01970e589d21-0001-a13f9c2e",
            DEVICE_B,
        )
        .unwrap();
        let newer = notification_inbox_value(
            NOTIFICATION_ID,
            NotificationInboxState::Archived,
            "01970e589d22-0000-a13f9c2e",
            DEVICE_A,
        )
        .unwrap();

        // First write of a key has nothing to merge against.
        assert_eq!(
            merge_notification_inbox_values(older.clone(), None).unwrap(),
            older
        );
        // Both arrival orders elect the same winner.
        assert_eq!(
            merge_notification_inbox_values(older.clone(), Some(&newer)).unwrap(),
            newer
        );
        assert_eq!(
            merge_notification_inbox_values(newer.clone(), Some(&older)).unwrap(),
            newer
        );

        let same_hlc_lower_device = notification_inbox_value(
            NOTIFICATION_ID,
            NotificationInboxState::Archived,
            "01970e589d21-0001-a13f9c2e",
            DEVICE_A,
        )
        .unwrap();
        assert_eq!(
            merge_notification_inbox_values(same_hlc_lower_device, Some(&older)).unwrap(),
            older
        );
    }

    #[test]
    fn merge_refuses_to_cross_notifications() {
        let local = notification_inbox_value(
            NOTIFICATION_ID,
            NotificationInboxState::Archived,
            "01970e589d21-0001-a13f9c2e",
            DEVICE_A,
        )
        .unwrap();
        let foreign = notification_inbox_value(
            "ak:notification:01904100-0000-7000-8000-848727f328ff",
            NotificationInboxState::Dismissed,
            "01970e589d21-0001-a13f9c2e",
            DEVICE_A,
        )
        .unwrap();
        assert!(merge_notification_inbox_values(local, Some(&foreign)).is_err());
    }
}
