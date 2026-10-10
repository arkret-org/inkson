//! Pure derivations behind the Realm admin panel.
//!
//! Governance failure hints, the security-health state, the verified Station
//! delegation-root basis used by capability grants, and metadata editor
//! reconciliation. The reconciliation in particular used to run inline between the panel's
//! `use_signal` declarations and its `rsx!`, writing Signals mid-render; it
//! now returns the writes it wants instead of performing them, which is what
//! makes it assertable.

use super::*;

pub(super) const VERIFIED_AUTHORITY_ROOT_UNAVAILABLE: &str = "verified governing Station authority-root current is unavailable; sync it before authoring this governance Event";

/// Owner transfer/reset still require their complete authoring and acceptance
/// proof flow. A root current row alone does not enable those transitions.
/// Keep the explicit gate until that flow is wired and verified.
pub(super) fn governance_authoring_gate() -> Result<(), &'static str> {
    Err(VERIFIED_AUTHORITY_ROOT_UNAVAILABLE)
}

/// Read the installed, authority-verified root rather than the unrelated
/// governing-Station tenure. The current value retains its exact delegation
/// anchor across owner transfer and Station handoff, including after reset.
pub(super) fn capability_issuer_basis(
    realm_id: &str,
    entries: &[arkret_wire::TypedCurrentRow],
    issuer: &arkret_sdk::AccountId,
) -> Option<crate::operation::ak_ops::IssuerRealmAuthorityBasis> {
    let realm: arkret_sdk::RealmId = realm_id.parse().ok()?;
    let mut roots = entries.iter().filter_map(|entry| {
        let arkret_wire::TypedCurrentRow::Value { selector, source_stream_ref, value, .. } = entry;
        (matches!(selector, arkret_wire::CurrentSelector::RealmAuthorityRoot)
            && matches!(source_stream_ref, arkret_wire::CommitStreamRef::Realm { realm_id: source } if source == &realm))
            .then_some(value)
    });
    let root: arkret_wire::RealmAuthorityRootValue =
        serde_json::from_value(roots.next()?.clone()).ok()?;
    if roots.next().is_some()
        || root.validate().is_err()
        || root.controller_actor_id != arkret_sdk::ActorId::account(issuer.clone())
    {
        return None;
    }
    Some(crate::operation::ak_ops::IssuerRealmAuthorityBasis {
        authority_generation: root.authority_generation,
        authority_event_ref: root.authority_event_ref,
    })
}

/// Operator guidance for the known authority-root rejection reasons, appended
/// to the raw error in the status line. `None` for anything unrecognized.
#[cfg(test)]
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
            "the governing Station has no current authority-root result for this Realm; \
             governance transitions are unavailable",
        )
    } else {
        None
    }
}

/// The one alert line the Security section leads with. A pending MLS binding
/// is the remaining local safety state; retired notary/Seal health is not
/// reconstructed from cache.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RealmSecurityHealth {
    pub(super) label: &'static str,
    pub(super) badge: &'static str,
    pub(super) next_step: &'static str,
    /// How many conditions are active, for the section badge.
    pub(super) alert_count: usize,
}

pub(super) fn realm_security_health(pending_mls_binding: bool) -> RealmSecurityHealth {
    let alert_count = usize::from(pending_mls_binding);
    let (label, badge, next_step) = if pending_mls_binding {
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
