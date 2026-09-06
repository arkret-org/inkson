//! Invite delivery credentials from the actor-private account-data carrier.
//!
//! `governance-objects.md` §5.3 forbids materializing private delivery
//! material on the Invite object, so the authz Invite read model never carries
//! an accept token. The Station delivers it on the holder-private
//! account-data cell `ak.account.invite_delivery` (the same carrier family
//! `consent-model.md` §6.1.1 defines for the quarantine inbox), persisted
//! server-side as a bounded CAS register and fanned out live as an
//! `ak.account_data.update` actor-private device update. This module is the
//! single ingestion and lookup point for both paths.

use arkret_models_collaboration::governance::invite_addressing::{
    InviteDelivery, InviteDeliveryEntry,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use super::{ClientLocalState, LocalStateStore, StoredInviteCredential};

/// Upper bound on locally retained invite credentials; writes evict expired
/// entries first, then the oldest by `received_at`.
pub(crate) const MAX_INVITE_CREDENTIALS: usize = 200;

fn validated_invite_delivery(content: &Value) -> Option<InviteDelivery> {
    let delivery = serde_json::from_value::<InviteDelivery>(content.clone()).ok()?;
    delivery.validate().ok()?;
    Some(delivery)
}

fn stored_invite_credential(entry: &InviteDeliveryEntry) -> StoredInviteCredential {
    StoredInviteCredential {
        realm_id: entry.realm_id.clone(),
        invite_token: entry.invite_token.clone(),
        expires_at: Some(entry.expires_at),
        received_at: entry.received_at,
    }
}

/// Parse the entries of an `ak.account.invite_delivery` cell payload
/// (`arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY`, wire schema
/// [`InviteDelivery::SCHEMA`]) into the SDK's strong
/// [`InviteDeliveryEntry`] type.
///
/// The complete cell must decode and validate as the canonical SDK wire type.
/// Malformed cells carry no credential anyone could rely on, so they fail
/// closed instead of being partially trusted.
pub(crate) fn invite_delivery_entries_from_cell(
    content: &Value,
) -> Vec<(String, StoredInviteCredential)> {
    let Some(delivery) = validated_invite_delivery(content) else {
        return Vec::new();
    };
    delivery
        .delivery_entries
        .into_iter()
        .map(|entry| {
            (
                entry.invite_id.as_str().to_owned(),
                stored_invite_credential(&entry),
            )
        })
        .collect()
}

fn credential_expired(credential: &StoredInviteCredential, now: DateTime<Utc>) -> bool {
    credential
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
}

impl ClientLocalState {
    /// The accept token the private delivery carried for `invite_id`, when it
    /// is still valid. Expired credentials are not returned.
    pub fn invite_credential_for(&self, invite_id: &str) -> Option<&StoredInviteCredential> {
        self.invite_credentials
            .get(invite_id)
            .filter(|credential| !credential_expired(credential, Utc::now()))
    }
}

impl LocalStateStore {
    pub(crate) fn apply_station_cas_account_data(
        &mut self,
        deltas: &[arkret_sdk::StationCasAccountDataContainer],
    ) {
        self.ensure_cached_loaded();
        let mut delivery_changed = false;
        for delta in deltas {
            if delta.complete {
                self.cached.station_cas_account_data.clear();
                delivery_changed = true;
            }
            for entry in &delta.upserts {
                delivery_changed |=
                    entry.account_data_key == arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY;
                self.cached
                    .station_cas_account_data
                    .insert(entry.account_data_key.clone(), entry.clone());
            }
            for removal in &delta.removals {
                delivery_changed |= removal.account_data_key
                    == arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY;
                self.cached
                    .station_cas_account_data
                    .remove(&removal.account_data_key);
            }
        }
        if delivery_changed {
            let delivery = self
                .cached
                .station_cas_account_data
                .get(arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY)
                .map(|entry| entry.content.clone());
            self.replace_invite_delivery_cell(delivery.as_ref());
        }
        if !deltas.is_empty() {
            let _ = self.flush();
        }
    }

    fn replace_invite_delivery_cell(&mut self, content: Option<&Value>) {
        let delivery = content.and_then(validated_invite_delivery);
        let retained_ids = delivery
            .as_ref()
            .map(|delivery| {
                delivery
                    .delivery_entries
                    .iter()
                    .map(|entry| entry.invite_id.as_str().to_owned())
                    .collect::<std::collections::BTreeSet<_>>()
            })
            .unwrap_or_default();
        self.cached.notification_projection.retain(|candidate| {
            candidate
                .invite()
                .is_none_or(|invite| retained_ids.contains(invite.invite_id.as_str()))
        });
        self.cached.invite_credentials.clear();
        if let Some(delivery) = delivery {
            let now = Utc::now();
            for entry in delivery.delivery_entries {
                let credential = stored_invite_credential(&entry);
                if credential_expired(&credential, now) {
                    continue;
                }
                self.cached
                    .invite_credentials
                    .insert(entry.invite_id.as_str().to_owned(), credential);
                crate::state::projection::notifications::upsert_invite_delivery_notification(
                    &mut self.cached.notification_projection,
                    &entry,
                );
            }
        }
    }

    /// Fold one server-written `ak.account.invite_delivery` cell into local
    /// private state. Per-entry latest `received_at` wins so a stale catch-up
    /// read cannot clobber a newer live fanout.
    pub fn save_invite_delivery_cell(&mut self, content: &Value) -> usize {
        let Some(delivery) = validated_invite_delivery(content) else {
            return 0;
        };
        self.ensure_cached_loaded();
        let mut merged = std::mem::take(&mut self.cached.invite_credentials);
        let now = Utc::now();
        merged.retain(|_, credential| !credential_expired(credential, now));
        let projection_before = self.cached.notification_projection.clone();
        let mut applied = 0;
        for entry in delivery.delivery_entries {
            let invite_id = entry.invite_id.as_str().to_owned();
            let credential = stored_invite_credential(&entry);
            if credential_expired(&credential, now) {
                continue;
            }
            match merged.get(&invite_id) {
                Some(existing) if existing.received_at >= credential.received_at => {}
                _ => {
                    merged.insert(invite_id, credential);
                    applied += 1;
                }
            }
            // The credential map and the notification projection are separate
            // durable stores, so "the credential is already current" is no
            // evidence that the notification survived: a joined-Realm prune or
            // a projection rewrite drops the notification without touching the
            // credential, and gating the upsert on the credential would then
            // leave the two permanently diverged with no path back. The upsert
            // is keyed by `invite:<invite_id>` and the read/archived overlay
            // lives outside the projection, so re-asserting it is idempotent.
            crate::state::projection::notifications::upsert_invite_delivery_notification(
                &mut self.cached.notification_projection,
                &entry,
            );
        }
        while merged.len() > MAX_INVITE_CREDENTIALS {
            let Some(oldest) = merged
                .iter()
                .min_by(|left, right| left.1.received_at.cmp(&right.1.received_at))
                .map(|(invite_id, _)| invite_id.clone())
            else {
                break;
            };
            merged.remove(&oldest);
        }
        self.cached.invite_credentials = merged;
        if applied > 0 || projection_before != self.cached.notification_projection {
            let _ = self.flush();
        }
        applied
    }

    /// Consume one `ak.account_data.update` actor-private device update
    /// carrying the invite delivery cell. Returns true when the local
    /// credential state changed.
    pub(crate) fn ingest_invite_delivery_update_message(&mut self, message: &Value) -> bool {
        if message
            .get("kind")
            .and_then(Value::as_str)
            != Some(arkret_wire::ActorPrivateUpdateKind::ACCOUNT_DATA_UPDATE)
        {
            return false;
        }
        let Some(update) = message.get("content") else {
            return false;
        };
        if update.get("account_data_key").and_then(Value::as_str)
            != Some(arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY)
            || update.get("operation").and_then(Value::as_str) != Some("put")
        {
            return false;
        }
        let Some(content) = update.get("content") else {
            return false;
        };
        self.save_invite_delivery_cell(content) > 0
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const REALM_ID: &str = "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1";
    const INVITE_ID: &str = "ak:invite:AZYDg8DDhw3K_txXc2FaKw9baWMbenl1vvUcRFfpjp3K";

    fn cell(entries: Value) -> Value {
        json!({
            "schema": InviteDelivery::SCHEMA,
            "updated_at": "2026-08-18T00:00:00.000Z",
            "delivery_entries": entries
        })
    }

    fn entry(invite_id: &str, token: &str, received_at: &str, expires_at: &str) -> Value {
        json!({
            "invite_id": invite_id,
            "realm_id": REALM_ID,
            "inviter_account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "invite_token": token,
            "received_at": received_at,
            "expires_at": expires_at
        })
    }

    #[test]
    fn canonical_account_data_snapshot_decodes_delivery_entries() {
        let entries = invite_delivery_entries_from_cell(&cell(json!([entry(
            INVITE_ID,
            "ak:invite-token:abc",
            "2026-08-18T00:00:00.000Z",
            "2099-08-25T00:00:00.000Z"
        )])));
        assert_eq!(entries.len(), 1);
        let (invite_id, credential) = &entries[0];
        assert_eq!(invite_id, INVITE_ID);
        assert_eq!(credential.invite_token, "ak:invite-token:abc");
        assert_eq!(credential.realm_id.as_str(), REALM_ID);
    }

    #[test]
    fn live_account_data_update_ingests_canonical_delivery_entries() {
        let path = std::env::temp_dir().join(format!(
            "inkson-invite-delivery-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = LocalStateStore::with_path(&path);
        let message = json!({
            "kind": arkret_wire::ActorPrivateUpdateKind::ACCOUNT_DATA_UPDATE,
            "content": {
                "operation": "put",
                "account_data_key": arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY,
                "revision": 1,
                "content": cell(json!([entry(
                    INVITE_ID,
                    "ak:invite-token:live",
                    "2026-08-18T00:00:00.000Z",
                    "2099-08-25T00:00:00.000Z"
                )])),
                "updated_at": "2026-08-18T00:00:00.000Z"
            },
            "created_at": "2026-08-18T00:00:00.000Z"
        });

        assert!(store.ingest_invite_delivery_update_message(&message));
        assert_eq!(
            store
                .load()
                .invite_credential_for(INVITE_ID)
                .map(|credential| credential.invite_token.as_str()),
            Some("ak:invite-token:live")
        );
        let projection = store.notification_projection();
        assert!(matches!(
            projection.as_slice(),
            [crate::state::StoredNotification::Invite { invite }]
                if invite.invite_id.as_str() == INVITE_ID
                    && invite.realm_id.as_str() == REALM_ID
                    && invite.created_at.to_rfc3339() == "2026-08-18T00:00:00+00:00"
        ));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn station_cas_baseline_and_removal_replace_invite_delivery_state() {
        let path = std::env::temp_dir().join(format!(
            "inkson-station-cas-invite-delivery-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut store = LocalStateStore::with_path(&path);
        let updated_at = DateTime::parse_from_rfc3339("2026-08-18T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.apply_station_cas_account_data(&[arkret_sdk::StationCasAccountDataContainer {
            complete: true,
            upserts: vec![arkret_sdk::AccountDataRow {
                account_data_key: arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
                revision: 3,
                content: cell(json!([entry(
                    INVITE_ID,
                    "ak:invite-token:baseline",
                    "2026-08-18T00:00:00.000Z",
                    "2099-08-25T00:00:00.000Z"
                )])),
                updated_at,
            }],
            removals: Vec::new(),
        }]);
        assert_eq!(
            store
                .load()
                .invite_credential_for(INVITE_ID)
                .map(|credential| credential.invite_token.as_str()),
            Some("ak:invite-token:baseline")
        );

        store.apply_station_cas_account_data(&[arkret_sdk::StationCasAccountDataContainer {
            complete: false,
            upserts: Vec::new(),
            removals: vec![arkret_sdk::StationCasAccountDataRemoval {
                account_data_key: arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY.to_owned(),
                revision: 4,
                updated_at,
            }],
        }]);
        let state = store.load();
        assert!(state.invite_credential_for(INVITE_ID).is_none());
        assert!(
            !state
                .station_cas_account_data
                .contains_key(arkret_wire::AccountDataKey::ACCOUNT_INVITE_DELIVERY)
        );
        assert!(store.notification_projection().is_empty());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lookup_drops_expired_credentials() {
        let mut state = ClientLocalState::default();
        state.invite_credentials.insert(
            INVITE_ID.to_owned(),
            StoredInviteCredential {
                realm_id: arkret_sdk::RealmId::new(REALM_ID.to_owned()).unwrap(),
                invite_token: "ak:invite-token:abc".to_owned(),
                expires_at: Some(
                    DateTime::parse_from_rfc3339("2020-01-01T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                ),
                received_at: Utc::now(),
            },
        );
        assert!(state.invite_credential_for(INVITE_ID).is_none());
        assert!(state.invite_credential_for("ak:invite:unknown").is_none());
    }
}
