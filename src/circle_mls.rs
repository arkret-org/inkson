//! Membership-removal rotation for one MLS scope.
//!
//! Removing members is entirely client-side MLS work: the Station orders the
//! resulting `ak.mls.commit` on the scope's own stream, but it never decides
//! which leaves come out. The removal set is derived from the group's own
//! verified leaf bindings, and the SDK refuses a target actor with no leaf, so
//! a partial rotation can never be committed.
//!
//! Proposals travel inside the Commit bytes, so a rotation produces exactly one
//! Event.

use crate::secure_key_store::SecureKeyStore;
use crate::state::LocalStateStore;

/// One exact local MLS group state frozen for a removal rotation.
///
/// Freezing matters because the group may advance between the moment the user
/// picks the members to remove and the moment the commit is authored: the
/// rotation must either apply to the state it was planned against or fail.
#[derive(Clone)]
pub(crate) struct MembershipRemovalSnapshot {
    pub effective_scope: arkret_sdk::ScopeRef,
    pub mls_group_id: String,
    pub epoch: u64,
    pub base_group_state_ref: arkret_sdk::EventId,
    /// The complete member identities whose every leaf this rotation removes.
    pub targets: Vec<arkret_sdk::ActorId>,
    checkpoint_bytes: Vec<u8>,
}

impl MembershipRemovalSnapshot {
    pub(crate) fn capture(
        store: &LocalStateStore,
        effective_scope: arkret_sdk::ScopeRef,
        targets: Vec<arkret_sdk::ActorId>,
    ) -> Result<Self, String> {
        if targets.is_empty() {
            return Err("MLS removal requires at least one target actor".to_owned());
        }
        let checkpoint = store
            .mls_checkpoint_for_scope(&effective_scope)
            .ok_or_else(|| "MLS removal requires a local group checkpoint".to_owned())?;
        let base_group_state_ref = store.mls_group_state_ref_for_scope(
            &effective_scope,
            &checkpoint.group_id,
            checkpoint.epoch,
        )?;
        let mut targets = targets;
        targets.sort();
        targets.dedup();
        Ok(Self {
            effective_scope,
            mls_group_id: checkpoint.group_id.clone(),
            epoch: checkpoint.epoch,
            base_group_state_ref,
            targets,
            checkpoint_bytes: serde_json::to_vec(&checkpoint).map_err(|e| e.to_string())?,
        })
    }

    /// Refuse the rotation when the local group is no longer byte-identical to
    /// the state it was planned against.
    pub(crate) fn ensure_current(&self, store: &LocalStateStore) -> Result<(), String> {
        let checkpoint = store
            .mls_checkpoint_for_scope(&self.effective_scope)
            .ok_or_else(|| "MLS removal checkpoint disappeared".to_owned())?;
        if serde_json::to_vec(&checkpoint).map_err(|e| e.to_string())? != self.checkpoint_bytes
            || checkpoint.group_id != self.mls_group_id
            || checkpoint.epoch != self.epoch
            || store.mls_group_state_ref_for_scope(
                &self.effective_scope,
                &self.mls_group_id,
                self.epoch,
            )? != self.base_group_state_ref
        {
            return Err("MLS removal base or local checkpoint changed".to_owned());
        }
        Ok(())
    }
}

/// The authored rotation: one `ak.mls.commit` plus the staged group state it
/// will install once the Station accepts it.
pub struct CircleScopeRotateDraft {
    pub commit_event: crate::operation::LocalOperation,
    pub staged_checkpoint: crate::mls::persistence::MlsLocalCheckpointEnvelope,
    pub removed_leaves: Vec<u32>,
    pub removed_actors: Vec<arkret_sdk::ActorId>,
}

pub(crate) fn build_remove_scope_rotate_draft(
    state_store: &LocalStateStore,
    secure_store: &dyn SecureKeyStore,
    authority: &arkret_sdk::AccountId,
    actor_id: &str,
    device_id: &arkret_sdk::DeviceId,
    frozen: &MembershipRemovalSnapshot,
) -> Result<CircleScopeRotateDraft, String> {
    let effective_scope = frozen.effective_scope.clone();
    let realm_id = effective_scope
        .realm_id_opt()
        .ok_or("MLS removal has no Realm")?
        .as_str()
        .to_owned();
    let circle_id = match &effective_scope {
        arkret_sdk::ScopeRef::Circle { circle_id, .. } => Some(circle_id.as_str().to_owned()),
        arkret_sdk::ScopeRef::Realm { .. } => None,
        _ => return Err("MLS membership rotation only accepts Realm/Circle".to_owned()),
    };
    let (remove, staged) = crate::mls::runtime::build_mls_remove_actors_commit_for_scope(
        state_store,
        secure_store,
        &effective_scope,
        authority,
        device_id,
        frozen,
    )
    .map_err(|err| err.user_message())?;
    if remove.removed_leaves.is_empty() {
        return Err("MLS removal produced no leaf removals".to_owned());
    }
    if remove.removed_leaves.len() != remove.removed_actors.len() {
        return Err("MLS removal leaves do not align with removed actors".to_owned());
    }
    let commit_event = crate::mls::group_events::mls_commit_event_from_store_for_effective_scope(
        state_store,
        &realm_id,
        circle_id.as_deref(),
        actor_id,
        &staged.envelope,
    )?;
    Ok(CircleScopeRotateDraft {
        commit_event,
        staged_checkpoint: staged.staged_checkpoint,
        removed_leaves: remove.removed_leaves,
        removed_actors: remove.removed_actors,
    })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod removal_snapshot_tests {
    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn target() -> arkret_sdk::ActorId {
        arkret_sdk::ActorId::account(crate::test_support::authority("did:web:bob.example"))
    }

    #[test]
    fn a_removal_snapshot_refuses_a_changed_checkpoint_base_or_epoch() {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
        };
        let group_id = scope.canonical_mls_group_id().unwrap();
        let base =
            arkret_sdk::EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml")
                .unwrap();
        let mut store = crate::state::isolated_store_for_tests("removal-snapshot-fence");
        let checkpoint = crate::mls::persistence::encrypt_state(
            REALM,
            &group_id,
            1,
            b"snapshot-bytes",
            "secret",
            &[1; 16],
        );
        store
            .save_mls_checkpoint_for_scope(&scope, checkpoint)
            .unwrap();
        store
            .record_mls_group_state_ref_for_scope(&scope, &group_id, 1, base.clone())
            .unwrap();
        let checkpoint = store.mls_checkpoint_for_scope(&scope).unwrap();

        let frozen =
            MembershipRemovalSnapshot::capture(&store, scope.clone(), vec![target()]).unwrap();
        assert_eq!(frozen.epoch, 1);
        assert_eq!(frozen.base_group_state_ref, base);
        frozen.ensure_current(&store).unwrap();

        let mut wrong_base = frozen.clone();
        wrong_base.base_group_state_ref =
            arkret_sdk::EventId::from_digest(arkret_sdk::canonical::DigestSuite::Sha256, [7; 32]);
        assert!(wrong_base.ensure_current(&store).is_err());

        let mut wrong_epoch = frozen.clone();
        wrong_epoch.epoch = 2;
        assert!(wrong_epoch.ensure_current(&store).is_err());

        let mut changed = checkpoint.clone();
        changed.ciphertext_hex.push_str("00");
        store
            .save_mls_checkpoint_for_scope(&scope, changed)
            .unwrap();
        assert!(frozen.ensure_current(&store).is_err());
    }

    #[test]
    fn a_removal_snapshot_needs_at_least_one_target() {
        let scope = arkret_sdk::ScopeRef::Realm {
            realm_id: arkret_sdk::RealmId::new(REALM).unwrap(),
        };
        let store = crate::state::isolated_store_for_tests("removal-snapshot-empty");
        assert!(MembershipRemovalSnapshot::capture(&store, scope, Vec::new()).is_err());
    }
}
