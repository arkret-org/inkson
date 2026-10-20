//! Incremental account records shared by the native and browser transaction ports.
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Shared<T>(Arc<T>);
impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self(Arc::new(T::default()))
    }
}
impl<T> From<T> for Shared<T> {
    fn from(value: T) -> Self {
        Self(Arc::new(value))
    }
}
impl<T> Deref for Shared<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}
impl<T: Clone> DerefMut for Shared<T> {
    fn deref_mut(&mut self) -> &mut T {
        Arc::make_mut(&mut self.0)
    }
}
impl<T: PartialEq> PartialEq for Shared<T> {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0) || self.0 == other.0
    }
}
impl<T: Eq> Eq for Shared<T> {}
impl<T> Shared<T> {
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl<T: Clone> Shared<T> {
    pub fn into_inner(self) -> T {
        Arc::unwrap_or_clone(self.0)
    }
}
impl<A, T: FromIterator<A>> FromIterator<A> for Shared<T> {
    fn from_iter<I: IntoIterator<Item = A>>(iter: I) -> Self {
        T::from_iter(iter).into()
    }
}
impl<T: Clone + IntoIterator> IntoIterator for Shared<T> {
    type Item = T::Item;
    type IntoIter = T::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.into_inner().into_iter()
    }
}
impl<'a, T> IntoIterator for &'a Shared<T>
where
    &'a T: IntoIterator,
{
    type Item = <&'a T as IntoIterator>::Item;
    type IntoIter = <&'a T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&*self.0).into_iter()
    }
}

impl<'a, T: Clone> IntoIterator for &'a mut Shared<T>
where
    &'a mut T: IntoIterator,
{
    type Item = <&'a mut T as IntoIterator>::Item;
    type IntoIter = <&'a mut T as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        (&mut **self).into_iter()
    }
}

pub(super) trait MapExt<K, V> {
    fn retain(&mut self, keep: impl FnMut(&K, &mut V) -> bool);
    fn for_each_mut(&mut self, visit: impl FnMut(&K, &mut V));
    fn into_values(self) -> impl Iterator<Item = V>;
}
impl<K: Ord + Clone, V: Clone> MapExt<K, V> for imbl::OrdMap<K, V> {
    fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        let keys: Vec<_> = self.keys().cloned().collect();
        for key in keys {
            if !keep(&key, self.get_mut(&key).expect("existing key")) {
                self.remove(&key);
            }
        }
    }
    fn for_each_mut(&mut self, mut visit: impl FnMut(&K, &mut V)) {
        let keys: Vec<_> = self.keys().cloned().collect();
        for key in keys {
            visit(&key, self.get_mut(&key).expect("existing key"));
        }
    }
    fn into_values(self) -> impl Iterator<Item = V> {
        self.into_iter().map(|(_, value)| value)
    }
}

#[derive(Clone, Debug)]
pub(super) struct Change {
    pub path: Vec<String>,
    pub value: Option<Vec<u8>>,
}
#[derive(Default)]
pub(super) struct Changes(pub Vec<Change>);
impl Changes {
    pub fn scalar<T: Serialize + PartialEq>(
        &mut self,
        path: Vec<String>,
        old: Option<&T>,
        new: Option<&T>,
    ) -> anyhow::Result<()> {
        if old == new {
            return Ok(());
        }
        self.0.push(Change {
            path,
            value: new.map(serde_json::to_vec).transpose()?,
        });
        Ok(())
    }
    pub fn map<K: Ord + Clone + Serialize, V: Clone + PartialEq>(
        &mut self,
        path: Vec<String>,
        old: Option<&imbl::OrdMap<K, V>>,
        new: Option<&imbl::OrdMap<K, V>>,
        mut value: impl FnMut(&mut Self, Vec<String>, Option<&V>, Option<&V>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        if old.is_none() != new.is_none() {
            self.scalar(
                path.clone(),
                old.map(|_| &serde_json::Value::Null),
                new.map(|_| &serde_json::Value::Null),
            )?;
            // A present empty nested map must survive restart. The marker is
            // installed before child records during hydration.
            if new.is_some() {
                self.0.last_mut().expect("map marker").value = Some(b"{}".to_vec());
            }
        }
        // Constructing an empty persistent tree reserves nodes inline for V.
        // Large protocol values must not add that frame to every account commit.
        let mut emit = |key: &K, a: Option<&V>, b: Option<&V>| -> anyhow::Result<()> {
            let key = serde_json::to_value(key)?;
            let key = key
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("account map key is not a string"))?;
            let mut entry = path.clone();
            entry.push(key.to_owned());
            value(self, entry, a, b)
        };
        match (old, new) {
            (Some(old), Some(new)) => {
                for diff in old.diff(new) {
                    match diff {
                        imbl::ordmap::DiffItem::Add(key, value) => emit(key, None, Some(value))?,
                        imbl::ordmap::DiffItem::Remove(key, value) => emit(key, Some(value), None)?,
                        imbl::ordmap::DiffItem::Update {
                            old: (key, before),
                            new: (_, after),
                        } => emit(key, Some(before), Some(after))?,
                    }
                }
            }
            (Some(old), None) => {
                for (key, value) in old {
                    emit(key, Some(value), None)?;
                }
            }
            (None, Some(new)) => {
                for (key, value) in new {
                    emit(key, None, Some(value))?;
                }
            }
            (None, None) => {}
        }
        Ok(())
    }
    pub fn set<K: Ord + Clone + Serialize>(
        &mut self,
        path: Vec<String>,
        old: &imbl::OrdSet<K>,
        new: &imbl::OrdSet<K>,
    ) -> anyhow::Result<()> {
        self.set_optional(path, Some(old), Some(new))
    }
    pub fn set_optional<K: Ord + Clone + Serialize>(
        &mut self,
        path: Vec<String>,
        old: Option<&imbl::OrdSet<K>>,
        new: Option<&imbl::OrdSet<K>>,
    ) -> anyhow::Result<()> {
        if old.is_none() != new.is_none() {
            self.0.push(Change {
                path: path.clone(),
                value: new.map(|_| b"[]".to_vec()),
            });
        }
        let empty = imbl::OrdSet::new();
        let old = old.unwrap_or(&empty);
        let new = new.unwrap_or(&empty);
        if old.ptr_eq(new) {
            return Ok(());
        }
        for key in old.clone().symmetric_difference(new.clone()) {
            let mut entry = path.clone();
            entry.push(serde_json::to_string(&key)?);
            self.0.push(Change {
                path: entry,
                value: if new.contains(&key) {
                    Some(serde_json::to_vec(&key)?)
                } else {
                    None
                },
            });
        }
        Ok(())
    }
    pub fn seq<C: Sequence>(
        &mut self,
        path: Vec<String>,
        old: &Shared<C>,
        new: &Shared<C>,
    ) -> anyhow::Result<()> {
        self.seq_optional(path, Some(old), Some(new))
    }
    pub fn seq_optional<C: Sequence>(
        &mut self,
        path: Vec<String>,
        old: Option<&Shared<C>>,
        new: Option<&Shared<C>>,
    ) -> anyhow::Result<()> {
        if let (Some(a), Some(b)) = (old, new) {
            if a.ptr_eq(b) {
                return Ok(());
            }
        }
        if old.is_none() != new.is_none() {
            self.0.push(Change {
                path: path.clone(),
                value: new.map(|_| b"[]".to_vec()),
            });
        }
        for i in 0..old.map_or(0, |s| s.size()).max(new.map_or(0, |s| s.size())) {
            let mut row = path.clone();
            row.push(format!("{i:020}"));
            self.scalar(row, old.and_then(|s| s.at(i)), new.and_then(|s| s.at(i)))?;
        }
        Ok(())
    }
}

// Field recipes deliberately keep each collection out of the account root.
impl super::ClientLocalState {
    pub(super) fn durable_changes(&self, old: &Self) -> anyhow::Result<Changes> {
        let Self {
            sync_cursor: _,
            demand_sync: _,
            commit_stream_cursors: _,
            verified_commit_stream_cursors: _,
            verified_commit_stream_anchors: _,
            station_cas_projection: _,
            client_core_pending_deliveries: _,
            client_core_next_delivery_id: _,
            device_message_cursors: _,
            client_core_seen_event_ids: _,
            raw_operations: _,
            verified_message_commits: _,
            verified_poll_inputs: _,
            verified_reaction_assertions: _,
            verified_poll_prefixes: _,
            verified_sidecar_history: _,
            verified_sidecar_current: _,
            verified_sidecar_current_watermarks: _,
            realm_destroy_receipts: _,
            realm_tree_projections: _,
            realm_collaboration_roles: _,
            realm_state_snapshot_sync: _,
            saved_account_data: _,
            scheduled_send_account_data: _,
            scheduled_send_target_realms: _,
            notification_projection: _,
            presence_projection: _,
            presence_visibility: _,
            presence_preference: _,
            to_device_inbox: _,
            mls_welcome_inbox_index: _,
            to_device_receipts: _,
            notification_client_state: _,
            invite_credentials: _,
            station_cas_account_data: _,
            realm_watch_levels: _,
            muted_notification_kinds: _,
            notification_dnd_settings: _,
            read_receipt_default_send: _,
            read_receipt_default_display: _,
            read_receipt_realm_overrides: _,
            read_receipt_realm_display_overrides: _,
            read_receipt_strand_overrides: _,
            read_receipt_strand_display_overrides: _,
            stream_cursors: _,
            realm_authority_basis: _,
            push_registration: _,
            local_identity: _,
            device_authoring_authority: _,
            move_submissions: _,
            plain_local_data: _,
            read_cursors: _,
            session_grant: _,
            pending_account_handoff: _,
            pending_principal_registration: _,
            recovery_material_evidence: _,
            mls_local_checkpoints: _,
            mls_rejection_cleared_checkpoints: _,
            mls_receive_recovery_checkpoints: _,
            mls_genesis_emitted: _,
            mls_group_state_refs: _,
            mls_pending_keypackage_consumes: _,
            mls_historical_group_state_refs: _,
            mls_historical_checkpoints: _,
            historical_agent_event_candidates: _,
            historical_agent_signer_keys: _,
            mls_coverage_stale: _,
            direct_conversation_peers: _,
            direct_message_contexts: _,
            mls_welcome_discovery: _,
            current_generation: _,
            current_reset_required: _,
            local_device_refresh_pending: _,
            mls_private_plaintext: _,
            mls_decrypted_plaintext: _,
            authenticated_identity_links: _,
            composer_drafts: _,
            realm_remarks: _,
            contact_remarks: _,
            accepted_human_contact_principals: _,
            client_blocklist: _,
            client_blocklist_revision: _,
            pending_personal_block_sagas: _,
            committed_personal_block_sagas: _,
            personal_blocklist_write_pending: _,
            server_trust_domain: _,
            dpop_device_key: _,
            member_identity_events: _,
            member_handle_cache: _,
            primary_handle: _,
        } = self;
        let mut changes = Changes::default();
        changes.scalar(
            vec!["sync_cursor".into()],
            Some(&old.sync_cursor),
            Some(&self.sync_cursor),
        )?;
        self.demand_sync
            .durable_changes(&old.demand_sync, &mut changes)?;
        changes.map(
            vec!["commit_stream_cursors".into()],
            Some(&old.commit_stream_cursors),
            Some(&self.commit_stream_cursors),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["verified_commit_stream_cursors".into()],
            Some(&old.verified_commit_stream_cursors),
            Some(&self.verified_commit_stream_cursors),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["verified_commit_stream_anchors".into()],
            Some(&old.verified_commit_stream_anchors),
            Some(&self.verified_commit_stream_anchors),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        self.station_cas_projection
            .visit_checkpoint_changes(&old.station_cas_projection, |path, value| {
                let mut key = vec!["station_cas_projection".into()];
                key.extend(path);
                changes.0.push(Change {
                    path: key,
                    value: value.map(|v| serde_json::to_vec(&v)).transpose()?,
                });
                Ok(())
            })
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        changes.seq(
            vec!["client_core_pending_deliveries".into()],
            &old.client_core_pending_deliveries,
            &self.client_core_pending_deliveries,
        )?;
        changes.scalar(
            vec!["client_core_next_delivery_id".into()],
            Some(&old.client_core_next_delivery_id),
            Some(&self.client_core_next_delivery_id),
        )?;
        changes.map(
            vec!["device_message_cursors".into()],
            Some(&old.device_message_cursors),
            Some(&self.device_message_cursors),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.seq(
            vec!["client_core_seen_event_ids".into()],
            &old.client_core_seen_event_ids,
            &self.client_core_seen_event_ids,
        )?;
        changes.seq(
            vec!["raw_operations".into()],
            &old.raw_operations,
            &self.raw_operations,
        )?;
        changes.seq(
            vec!["verified_message_commits".into()],
            &old.verified_message_commits,
            &self.verified_message_commits,
        )?;
        changes.seq(
            vec!["verified_poll_inputs".into()],
            &old.verified_poll_inputs,
            &self.verified_poll_inputs,
        )?;
        changes.seq(
            vec!["verified_reaction_assertions".into()],
            &old.verified_reaction_assertions,
            &self.verified_reaction_assertions,
        )?;
        changes.map(
            vec!["verified_poll_prefixes".into()],
            Some(&old.verified_poll_prefixes),
            Some(&self.verified_poll_prefixes),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["verified_sidecar_history".into()],
            Some(&old.verified_sidecar_history),
            Some(&self.verified_sidecar_history),
            |changes, p, a, b| {
                changes.seq_optional(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["verified_sidecar_current".into()],
            Some(&old.verified_sidecar_current),
            Some(&self.verified_sidecar_current),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["verified_sidecar_current_watermarks".into()],
            Some(&old.verified_sidecar_current_watermarks),
            Some(&self.verified_sidecar_current_watermarks),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["realm_destroy_receipts".into()],
            Some(&old.realm_destroy_receipts),
            Some(&self.realm_destroy_receipts),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["realm_tree_projections".into()],
            Some(&old.realm_tree_projections),
            Some(&self.realm_tree_projections),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["realm_collaboration_roles".into()],
            Some(&old.realm_collaboration_roles),
            Some(&self.realm_collaboration_roles),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["snapshot_sync".into()],
            Some(&old.realm_state_snapshot_sync),
            Some(&self.realm_state_snapshot_sync),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["saved_account_data".into()],
            Some(&old.saved_account_data),
            Some(&self.saved_account_data),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["scheduled_send_account_data".into()],
            Some(&old.scheduled_send_account_data),
            Some(&self.scheduled_send_account_data),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["scheduled_send_target_realms".into()],
            Some(&old.scheduled_send_target_realms),
            Some(&self.scheduled_send_target_realms),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.seq(
            vec!["notification_projection".into()],
            &old.notification_projection,
            &self.notification_projection,
        )?;
        changes.seq(
            vec!["presence_projection".into()],
            &old.presence_projection,
            &self.presence_projection,
        )?;
        changes.scalar(
            vec!["presence_visibility".into()],
            Some(&old.presence_visibility),
            Some(&self.presence_visibility),
        )?;
        changes.scalar(
            vec!["presence_preference".into()],
            Some(&old.presence_preference),
            Some(&self.presence_preference),
        )?;
        changes.seq(
            vec!["to_device_inbox".into()],
            &old.to_device_inbox,
            &self.to_device_inbox,
        )?;
        changes.map(
            vec!["mls_welcome_inbox_index".into()],
            Some(&old.mls_welcome_inbox_index),
            Some(&self.mls_welcome_inbox_index),
            |changes, p, a, b| {
                changes.seq_optional(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["to_device_receipts".into()],
            Some(&old.to_device_receipts),
            Some(&self.to_device_receipts),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["notification_client_state".into()],
            Some(&old.notification_client_state),
            Some(&self.notification_client_state),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["invite_credentials".into()],
            Some(&old.invite_credentials),
            Some(&self.invite_credentials),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["station_cas_account_data".into()],
            Some(&old.station_cas_account_data),
            Some(&self.station_cas_account_data),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["realm_watch_levels".into()],
            Some(&old.realm_watch_levels),
            Some(&self.realm_watch_levels),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["muted_notification_kinds".into()],
            Some(&old.muted_notification_kinds),
            Some(&self.muted_notification_kinds),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.scalar(
            vec!["notification_dnd_settings".into()],
            Some(&old.notification_dnd_settings),
            Some(&self.notification_dnd_settings),
        )?;
        changes.scalar(
            vec!["read_receipt_default_send".into()],
            Some(&old.read_receipt_default_send),
            Some(&self.read_receipt_default_send),
        )?;
        changes.scalar(
            vec!["read_receipt_default_display".into()],
            Some(&old.read_receipt_default_display),
            Some(&self.read_receipt_default_display),
        )?;
        changes.map(
            vec!["read_receipt_realm_overrides".into()],
            Some(&old.read_receipt_realm_overrides),
            Some(&self.read_receipt_realm_overrides),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["read_receipt_realm_display_overrides".into()],
            Some(&old.read_receipt_realm_display_overrides),
            Some(&self.read_receipt_realm_display_overrides),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["read_receipt_strand_overrides".into()],
            Some(&old.read_receipt_strand_overrides),
            Some(&self.read_receipt_strand_overrides),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["read_receipt_strand_display_overrides".into()],
            Some(&old.read_receipt_strand_display_overrides),
            Some(&self.read_receipt_strand_display_overrides),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["stream_cursors".into()],
            Some(&old.stream_cursors),
            Some(&self.stream_cursors),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["realm_authority_basis".into()],
            Some(&old.realm_authority_basis),
            Some(&self.realm_authority_basis),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.scalar(
            vec!["push_registration".into()],
            Some(&old.push_registration),
            Some(&self.push_registration),
        )?;
        changes.scalar(
            vec!["local_identity".into()],
            Some(&old.local_identity),
            Some(&self.local_identity),
        )?;
        changes.scalar(
            vec!["device_authoring_authority".into()],
            Some(&old.device_authoring_authority),
            Some(&self.device_authoring_authority),
        )?;
        changes.map(
            vec!["move_submissions".into()],
            Some(&old.move_submissions),
            Some(&self.move_submissions),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["plain_local_data".into()],
            Some(&old.plain_local_data),
            Some(&self.plain_local_data),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["read_cursors".into()],
            Some(&old.read_cursors),
            Some(&self.read_cursors),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.scalar(
            vec!["session_grant".into()],
            Some(&old.session_grant),
            Some(&self.session_grant),
        )?;
        changes.scalar(
            vec!["pending_account_handoff".into()],
            Some(&old.pending_account_handoff),
            Some(&self.pending_account_handoff),
        )?;
        changes.scalar(
            vec!["pending_principal_registration".into()],
            Some(&old.pending_principal_registration),
            Some(&self.pending_principal_registration),
        )?;
        changes.scalar(
            vec!["recovery_material_evidence".into()],
            Some(&old.recovery_material_evidence),
            Some(&self.recovery_material_evidence),
        )?;
        changes.map(
            vec!["mls_snapshots".into()],
            Some(&old.mls_local_checkpoints),
            Some(&self.mls_local_checkpoints),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_rejection_cleared_checkpoints".into()],
            Some(&old.mls_rejection_cleared_checkpoints),
            Some(&self.mls_rejection_cleared_checkpoints),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_receive_recovery_snapshots".into()],
            Some(&old.mls_receive_recovery_checkpoints),
            Some(&self.mls_receive_recovery_checkpoints),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.set(
            vec!["mls_genesis_emitted".into()],
            &old.mls_genesis_emitted,
            &self.mls_genesis_emitted,
        )?;
        changes.map(
            vec!["mls_group_state_refs".into()],
            Some(&old.mls_group_state_refs),
            Some(&self.mls_group_state_refs),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_pending_keypackage_consumes".into()],
            Some(&old.mls_pending_keypackage_consumes),
            Some(&self.mls_pending_keypackage_consumes),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_historical_group_state_refs".into()],
            Some(&old.mls_historical_group_state_refs),
            Some(&self.mls_historical_group_state_refs),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_historical_snapshots".into()],
            Some(&old.mls_historical_checkpoints),
            Some(&self.mls_historical_checkpoints),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["historical_agent_event_candidates".into()],
            Some(&old.historical_agent_event_candidates),
            Some(&self.historical_agent_event_candidates),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["historical_agent_signer_keys".into()],
            Some(&old.historical_agent_signer_keys),
            Some(&self.historical_agent_signer_keys),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_coverage_stale".into()],
            Some(&old.mls_coverage_stale),
            Some(&self.mls_coverage_stale),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["direct_conversation_peers".into()],
            Some(&old.direct_conversation_peers),
            Some(&self.direct_conversation_peers),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["mls_welcome_discovery".into()],
            Some(&old.mls_welcome_discovery),
            Some(&self.mls_welcome_discovery),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.scalar(
            vec!["current_generation".into()],
            Some(&old.current_generation),
            Some(&self.current_generation),
        )?;
        changes.scalar(
            vec!["current_reset_required".into()],
            Some(&old.current_reset_required),
            Some(&self.current_reset_required),
        )?;
        changes.scalar(
            vec!["local_device_refresh_pending".into()],
            Some(&old.local_device_refresh_pending),
            Some(&self.local_device_refresh_pending),
        )?;
        changes.map(
            vec!["realm_remarks".into()],
            Some(&old.realm_remarks),
            Some(&self.realm_remarks),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.seq(
            vec!["client_blocklist".into()],
            &old.client_blocklist,
            &self.client_blocklist,
        )?;
        changes.scalar(
            vec!["client_blocklist_revision".into()],
            Some(&old.client_blocklist_revision),
            Some(&self.client_blocklist_revision),
        )?;
        changes.set(
            vec!["pending_personal_block_sagas".into()],
            &old.pending_personal_block_sagas,
            &self.pending_personal_block_sagas,
        )?;
        changes.set(
            vec!["committed_personal_block_sagas".into()],
            &old.committed_personal_block_sagas,
            &self.committed_personal_block_sagas,
        )?;
        changes.scalar(
            vec!["personal_blocklist_write_pending".into()],
            Some(&old.personal_blocklist_write_pending),
            Some(&self.personal_blocklist_write_pending),
        )?;
        changes.scalar(
            vec!["server_trust_domain".into()],
            Some(&old.server_trust_domain),
            Some(&self.server_trust_domain),
        )?;
        changes.scalar(
            vec!["dpop_device_key".into()],
            Some(&old.dpop_device_key),
            Some(&self.dpop_device_key),
        )?;
        changes.map(
            vec!["member_identity_events".into()],
            Some(&old.member_identity_events),
            Some(&self.member_identity_events),
            |changes, p, a, b| {
                changes.map(p, a, b, |changes, p, a, b| {
                    changes.seq_optional(p, a, b)?;
                    Ok(())
                })?;
                Ok(())
            },
        )?;
        changes.map(
            vec!["member_handle_cache".into()],
            Some(&old.member_handle_cache),
            Some(&self.member_handle_cache),
            |changes, p, a, b| {
                changes.scalar(p, a, b)?;
                Ok(())
            },
        )?;
        changes.scalar(
            vec!["primary_handle".into()],
            Some(&old.primary_handle),
            Some(&self.primary_handle),
        )?;
        Ok(changes)
    }
}
pub(super) const SET_FIELDS: &[&str] = &[
    "mls_genesis_emitted",
    "pending_personal_block_sagas",
    "committed_personal_block_sagas",
];

pub trait ReadMap<V: 'static>: Lookup<V> {
    fn iter(&self) -> impl Iterator<Item = (&String, &V)>;
}
impl<V: 'static> ReadMap<V> for std::collections::BTreeMap<String, V> {
    fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.iter()
    }
}
impl<V: Clone + 'static> ReadMap<V> for imbl::OrdMap<String, V> {
    fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.iter()
    }
}

pub(super) trait Sequence {
    type Item: Serialize + PartialEq;
    fn size(&self) -> usize;
    fn at(&self, index: usize) -> Option<&Self::Item>;
}
impl<T: Serialize + PartialEq> Sequence for Vec<T> {
    type Item = T;
    fn size(&self) -> usize {
        self.len()
    }
    fn at(&self, i: usize) -> Option<&T> {
        self.get(i)
    }
}
impl<T: Serialize + PartialEq> Sequence for std::collections::VecDeque<T> {
    type Item = T;
    fn size(&self) -> usize {
        self.len()
    }
    fn at(&self, i: usize) -> Option<&T> {
        self.get(i)
    }
}

pub trait Lookup<V> {
    fn get(&self, key: &str) -> Option<&V>;
}
impl<V> Lookup<V> for std::collections::BTreeMap<String, V> {
    fn get(&self, key: &str) -> Option<&V> {
        self.get(key)
    }
}
impl<V: Clone> Lookup<V> for imbl::OrdMap<String, V> {
    fn get(&self, key: &str) -> Option<&V> {
        self.get(key)
    }
}
impl<T: PartialEq, const N: usize> PartialEq<[T; N]> for Shared<Vec<T>> {
    fn eq(&self, other: &[T; N]) -> bool {
        self.as_slice() == other
    }
}
