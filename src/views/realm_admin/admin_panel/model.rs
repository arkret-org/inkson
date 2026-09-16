//! Pure derivations behind the Realm admin panel.
//!
//! Governance payload builders and failure hints, the security-health ladder,
//! the Seal diagnostics labels and the metadata editor reconciliation. The
//! reconciliation in particular used to run inline between the panel's
//! `use_signal` declarations and its `rsx!`, writing Signals mid-render; it
//! now returns the writes it wants instead of performing them, which is what
//! makes it assertable.

use super::*;

/// `expected_state_digest` for the two authority-root transition payloads:
/// the canonical SHA-256 of the replayed root value, exactly what the soland
/// reducer recomputes before applying a `security_barrier` transition.
pub(super) fn expected_authority_root_digest(
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
) -> anyhow::Result<arkret_sdk::Hash> {
    arkret_sdk::Hash::new(crate::canonical::canonical_sha256(root)?).map_err(anyhow::Error::msg)
}

/// Build the `ak.realm.owner.transfer` payload. `successor_acceptance` is the
/// successor's independent proof pasted by the operator — the client never
/// synthesizes it (the wire type only requires non-empty signature material;
/// binding semantics live with the successor's tooling).
pub(super) fn build_owner_transfer_payload(
    realm_id: &str,
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
    successor: &str,
    successor_acceptance: &str,
) -> anyhow::Result<arkret_sdk::RealmOwnerTransferPayload> {
    Ok(arkret_sdk::RealmOwnerTransferPayload {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        expected_state_digest: expected_authority_root_digest(root)?,
        patch: arkret_sdk::RealmOwnerTransferPatch {
            controller_actor_id: serde_json::from_str(successor).map_err(|error| {
                anyhow::anyhow!("successor must be a complete ActorId: {error}")
            })?,
        },
        successor_acceptance: arkret_sdk::SignatureMaterial::NonEmptyString(
            arkret_sdk::NonEmptyString::new(successor_acceptance.trim().to_owned())
                .map_err(|reason| anyhow::anyhow!("successor acceptance: {reason}"))?,
        ),
    })
}

/// Build the destructive `ak.realm.authority.reset` payload.
/// `destructive_confirmation` is the operator-typed token; the SDK builder
/// (and the reducer) only accept the literal event-kind string, so the typed
/// text ships verbatim instead of being auto-filled.
pub(super) fn build_authority_reset_payload(
    realm_id: &str,
    root: &arkret_policy::realm_bootstrap::RealmAuthorityRootValue,
    destructive_confirmation: &str,
) -> anyhow::Result<arkret_sdk::RealmAuthorityResetPayload> {
    Ok(arkret_sdk::RealmAuthorityResetPayload {
        realm_id: arkret_sdk::RealmId::new(realm_id.trim().to_owned())?,
        expected_state_digest: expected_authority_root_digest(root)?,
        destructive_confirmation: destructive_confirmation.trim().to_owned(),
    })
}

/// Operator guidance for the known authority-root rejection reasons, appended
/// to the raw error in the status line. `None` for anything unrecognized.
pub(super) fn governance_failure_hint(error_text: &str) -> Option<&'static str> {
    if error_text.contains("realm_authority_root_conflict") {
        Some(
            "the authority root changed concurrently (security barrier) — wait for sync to \
             surface the new root and retry from the refreshed state",
        )
    } else if error_text.contains("realm_authority_controller_mismatch") {
        Some(
            "only the current root controller may submit this transition, and an owner-transfer \
             successor must be a joined member with a non-empty acceptance proof",
        )
    } else if error_text.contains("realm_authority_root_missing") {
        Some(
            "this Realm has no projected authority-root cell (it predates the contract); \
             governance transitions are unavailable",
        )
    } else {
        None
    }
}

/// The one alert line the Security section leads with.
///
/// The two conditions are not independent — a paused notary makes the
/// pending-binding advice wrong — so the
/// ladder has to be read in order. Keeping it here means the order is stated
/// once and can be asserted without mounting the panel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RealmSecurityHealth {
    pub(super) label: &'static str,
    pub(super) badge: &'static str,
    pub(super) next_step: &'static str,
    /// How many conditions are active, for the section badge.
    pub(super) alert_count: usize,
}

pub(super) fn realm_security_health(
    paused: bool,
    pending_mls_binding: bool,
) -> RealmSecurityHealth {
    let alert_count = usize::from(paused) + usize::from(pending_mls_binding);
    let (label, badge, next_step) = if paused {
        (
            "Writes paused",
            "badge red",
            "Restore the Realm security service before asking members to try again.",
        )
    } else if pending_mls_binding {
        (
            "Binding pending",
            "badge amber",
            "Wait for the encrypted update to finish, then retry if the alert remains.",
        )
    } else {
        ("No active alerts", "badge green", "No action needed.")
    };
    RealmSecurityHealth {
        label,
        badge,
        next_step,
        alert_count,
    }
}

/// Read-only Seal diagnostics, each with the sentinel text that says *why* a
/// value is absent rather than rendering an empty cell.
pub(super) struct SealDiagnostics {
    /// Move ids covered by the current Seal batch.
    pub(super) leaf_count: usize,
    pub(super) frontier_label: String,
    pub(super) state_root_label: String,
    pub(super) mls_epoch_label: String,
}

pub(super) fn seal_diagnostics(seal_view: &crate::state::LocalSealView) -> SealDiagnostics {
    SealDiagnostics {
        leaf_count: seal_view.leaves.len(),
        frontier_label: if seal_view.frontier.is_empty() {
            "(no verified Seal head)".to_owned()
        } else {
            seal_view.frontier.join(", ")
        },
        state_root_label: seal_view
            .state_root
            .clone()
            .unwrap_or_else(|| "(not published)".to_owned()),
        // MLS epoch from the sequenced state of ak.component.mls.epoch.v1.
        mls_epoch_label: seal_view
            .mls_epoch
            .map(|epoch| epoch.to_string())
            .unwrap_or_else(|| "(no MLS epoch published)".to_owned()),
    }
}

/// Owner-transfer candidates: every projected member that is not this account.
///
/// Members that do not parse as a complete `ActorId` are dropped rather than
/// offered, because the transfer payload addresses the successor by exact
/// `ActorId` and a partial coordinate cannot name one.
pub(super) fn governance_transfer_candidates(
    projected_members: &[String],
    account_actor: Option<&arkret_sdk::ActorId>,
) -> Vec<String> {
    projected_members
        .iter()
        .filter(|member| {
            serde_json::from_str::<arkret_sdk::ActorId>(member)
                .ok()
                .is_some_and(|candidate| Some(&candidate) != account_actor)
        })
        .cloned()
        .collect()
}

/// The metadata editor fields as the panel currently holds them.
pub(super) struct MetadataEditorState<'a> {
    /// Subject the editors were last filled for.
    pub(super) loaded_for: &'a str,
    /// Canonical snapshot the editors were last reconciled against.
    pub(super) loaded_subject: Option<&'a MetadataSubject>,
    pub(super) title: &'a str,
    pub(super) summary: &'a str,
    pub(super) avatar_blob_ref: &'a str,
}

/// Writes the metadata editors want, rather than the writes themselves.
///
/// `None` means "leave this Signal alone". Returning the intent instead of
/// calling `set` is the whole point: the panel performed these writes in the
/// middle of its render, so no test could observe the decision separately from
/// mounting the component.
#[derive(Default, Debug, PartialEq, Eq)]
pub(super) struct MetadataEditorPatch {
    pub(super) title: Option<String>,
    pub(super) summary: Option<String>,
    pub(super) avatar_blob_ref: Option<String>,
    pub(super) loaded_for: Option<String>,
    pub(super) loaded_subject: Option<MetadataSubject>,
}

/// Fill the editors on a subject change, and afterwards let a late-arriving
/// projection reach only the fields the operator has not touched.
///
/// A deep-linked Profile page can render before the account projection lands.
/// Reconciling each untouched editor against the *previous* canonical snapshot
/// is what lets the delayed value fill in without overwriting input already
/// typed over it.
pub(super) fn reconcile_metadata_editors(
    subject_id: &str,
    subject: &MetadataSubject,
    state: MetadataEditorState<'_>,
) -> MetadataEditorPatch {
    if state.loaded_for != subject_id {
        return MetadataEditorPatch {
            title: Some(subject.title.clone()),
            summary: Some(subject.summary.clone()),
            avatar_blob_ref: Some(subject.avatar_blob_ref.clone()),
            loaded_for: Some(subject_id.to_owned()),
            loaded_subject: Some(subject.clone()),
        };
    }
    if state.loaded_subject == Some(subject) {
        return MetadataEditorPatch::default();
    }
    let mut patch = MetadataEditorPatch {
        loaded_subject: Some(subject.clone()),
        ..MetadataEditorPatch::default()
    };
    let Some(previous) = state.loaded_subject else {
        return patch;
    };
    let reconciled_title = reconcile_editor_value(state.title, &previous.title, &subject.title);
    if reconciled_title != state.title {
        patch.title = Some(reconciled_title);
    }
    let reconciled_summary =
        reconcile_editor_value(state.summary, &previous.summary, &subject.summary);
    if reconciled_summary != state.summary {
        patch.summary = Some(reconciled_summary);
    }
    let reconciled_avatar = reconcile_editor_value(
        state.avatar_blob_ref,
        &previous.avatar_blob_ref,
        &subject.avatar_blob_ref,
    );
    if reconciled_avatar != state.avatar_blob_ref {
        patch.avatar_blob_ref = Some(reconciled_avatar);
    }
    patch
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
