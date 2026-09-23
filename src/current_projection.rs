//! Product reads over the typed current results of a Realm state snapshot.
//!
//! A current result is authority-signed: it carries the exact `RealmCommit`
//! revision it was computed at, so a presentation field derived from it never
//! has to be re-derived from Event ordering, and there is no Realm-global
//! position anywhere in this view.

use arkret_wire::{CurrentSelector, RealmId, TypedCurrentResult};
use serde_json::Value;

/// The current results a Realm view needs before it can render its own
/// identity and policy. Everything else is optional and rendered as it arrives.
pub(crate) const REQUIRED_REALM_SELECTORS: [CurrentSelector; 2] =
    [CurrentSelector::RealmProfile, CurrentSelector::RealmPolicy];

fn selector_of(entry: &TypedCurrentResult) -> &CurrentSelector {
    match entry {
        TypedCurrentResult::Value { selector, .. }
        | TypedCurrentResult::MessageReactions { selector, .. } => selector,
    }
}

fn value_of(entry: &TypedCurrentResult) -> Option<&Value> {
    match entry {
        TypedCurrentResult::Value { value, .. } => Some(value),
        TypedCurrentResult::MessageReactions { .. } => None,
    }
}

fn entry_for<'a>(
    entries: &'a [TypedCurrentResult],
    selector: &CurrentSelector,
) -> Option<&'a TypedCurrentResult> {
    entries.iter().find(|entry| selector_of(entry) == selector)
}

pub(crate) fn required_realm_values_ready(entries: &[TypedCurrentResult]) -> bool {
    REQUIRED_REALM_SELECTORS
        .iter()
        .all(|selector| entry_for(entries, selector).and_then(value_of).is_some())
}

/// Build presentation fields from the snapshot's typed current results.
///
/// The Station already selected each value and signed the snapshot that carries
/// it, so nothing here re-runs a reducer or reads Event order.
pub(crate) fn install_complete_view(
    projection: &mut Value,
    realm_id: &str,
    entries: Vec<TypedCurrentResult>,
) -> anyhow::Result<()> {
    // v1 carries one complete inline snapshot. Capacity is enforced atomically
    // by RealmCommit admission; a client must not impose an item-count dialect,
    // truncate entries, or invent a private paging protocol here.
    let realm = RealmId::new(realm_id.to_owned())?;
    for entry in &entries {
        // Only the scope-carrying selectors can name another Realm at all; the
        // rest are Realm-singletons of the snapshot they arrived in.
        if let CurrentSelector::MlsGroup { scope_ref } = selector_of(entry) {
            anyhow::ensure!(
                scope_ref.realm_id_opt() == Some(&realm),
                "current MLS group result belongs to another Realm"
            );
        }
    }

    let profile = entry_for(&entries, &CurrentSelector::RealmProfile)
        .and_then(value_of)
        .and_then(|value| serde_json::from_value::<arkret_sdk::RealmProfile>(value.clone()).ok());

    let object = projection
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Realm projection must be an object"))?;
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
    object.insert("current".to_owned(), serde_json::to_value(&entries)?);
    Ok(())
}

/// Decode the current Strand value the Station selected for `strand_id`.
pub(crate) fn current_strand(
    entries: &[TypedCurrentResult],
    strand_id: &arkret_sdk::StrandId,
) -> Option<arkret_sdk::Strand> {
    let selector = CurrentSelector::Strand {
        strand_id: strand_id.clone(),
    };
    entry_for(entries, &selector)
        .and_then(value_of)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
}

/// The current MLS group of `scope_ref`, i.e. the evidence that this scope has
/// an accepted `ak.mls.genesis` and is therefore irreversibly encrypted.
pub(crate) fn current_mls_group(
    entries: &[TypedCurrentResult],
    scope_ref: &arkret_sdk::ScopeRef,
) -> Option<arkret_wire::MlsGroupCurrent> {
    let selector = CurrentSelector::MlsGroup {
        scope_ref: scope_ref.clone(),
    };
    entry_for(entries, &selector)
        .and_then(value_of)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .filter(|group: &arkret_wire::MlsGroupCurrent| group.effective_scope == *scope_ref)
}

/// Whether `scope_ref` has activated MLS.
///
/// This is the single client-side judgement of "is this scope encrypted". A
/// scope is plaintext until its own accepted `ak.mls.genesis` and irreversibly
/// standard RFC 9420 afterwards; there is no create-locked encryption profile
/// or encryption floor to consult.
pub(crate) fn scope_has_accepted_mls_genesis(
    entries: &[TypedCurrentResult],
    scope_ref: &arkret_sdk::ScopeRef,
) -> bool {
    current_mls_group(entries, scope_ref).is_some()
}

/// The Station-selected current `ak.realm.policy` value carried by a stored
/// Realm projection, if that projection already holds a signed current view.
///
/// Callers hand in the whole locally stored projection (`realm_tree_projection`
/// output); the `current` member is the exact `Vec<TypedCurrentResult>` that
/// [`install_complete_view`] wrote, so nothing here re-derives state from Event
/// order or from a protocol-level component id.
pub(crate) fn current_realm_policy_value(projection: &Value) -> Option<Value> {
    let entries: Vec<TypedCurrentResult> =
        serde_json::from_value(projection.get("current")?.clone()).ok()?;
    entry_for(&entries, &CurrentSelector::RealmPolicy)
        .and_then(value_of)
        .cloned()
}

/// The authority revision the Station committed one selector's current value
/// at, for `expected_revision` CAS on the next write to that selector.
///
/// `None` means the selector has no committed current value yet, which is a
/// settled empty result rather than an unknown one: the first write supersedes
/// nothing.
pub(crate) fn current_revision_for(
    entries: &[TypedCurrentResult],
    selector: &CurrentSelector,
) -> Option<arkret_wire::CurrentRevision> {
    entry_for(entries, selector).map(|entry| match entry {
        TypedCurrentResult::Value { revision, .. }
        | TypedCurrentResult::MessageReactions { revision, .. } => revision.clone(),
    })
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CurrentRevision, RealmCommitId};

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn revision(position: u64) -> CurrentRevision {
        let mut digest = [0; 32];
        digest[..8].copy_from_slice(&position.to_be_bytes());
        CurrentRevision {
            commit_id: RealmCommitId::from_digest(digest),
            stream_position: position,
        }
    }

    fn entry(selector: CurrentSelector, position: u64, value: Value) -> TypedCurrentResult {
        TypedCurrentResult::Value {
            selector,
            revision: revision(position),
            value,
        }
    }

    fn realm_scope() -> arkret_sdk::ScopeRef {
        arkret_sdk::ScopeRef::Realm {
            realm_id: RealmId::new(REALM).unwrap(),
        }
    }

    fn mls_group_value() -> Value {
        serde_json::json!({
            "effective_scope": {"kind": "realm", "realm_id": REALM},
            "genesis_event_ref": "ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "current_mls_commit_event_ref":
                "ak:event:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL",
            "epoch": 4,
            "current_key_access_revision": 2,
            "covered_key_access_revision": 2,
            "public_tree_ref":
                "ak:blob:sha256:431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460"
        })
    }

    #[test]
    fn a_realm_view_is_ready_once_profile_and_policy_are_current() {
        let profile = entry(
            CurrentSelector::RealmProfile,
            3,
            serde_json::json!({"schema": "ak.schema.realm_profile.v1", "title": "Launch"}),
        );
        let policy = entry(
            CurrentSelector::RealmPolicy,
            4,
            serde_json::json!({"policy_revision": 1}),
        );
        assert!(!required_realm_values_ready(std::slice::from_ref(&profile)));
        assert!(required_realm_values_ready(&[profile, policy]));
    }

    #[test]
    fn a_scope_is_encrypted_exactly_when_it_has_an_accepted_mls_genesis() {
        let plaintext = [entry(
            CurrentSelector::RealmProfile,
            1,
            serde_json::json!({"schema": "ak.schema.realm_profile.v1", "title": "Open"}),
        )];
        assert!(!scope_has_accepted_mls_genesis(&plaintext, &realm_scope()));

        let activated = [entry(
            CurrentSelector::MlsGroup {
                scope_ref: realm_scope(),
            },
            9,
            mls_group_value(),
        )];
        assert!(scope_has_accepted_mls_genesis(&activated, &realm_scope()));
        let group = current_mls_group(&activated, &realm_scope()).expect("current MLS group");
        assert_eq!(group.epoch, 4);
    }

    #[test]
    fn a_mls_value_for_another_scope_cannot_activate_this_scope() {
        let mut wrong_scope = mls_group_value();
        wrong_scope["effective_scope"]["realm_id"] =
            serde_json::json!("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM");
        let entries = [entry(
            CurrentSelector::MlsGroup {
                scope_ref: realm_scope(),
            },
            9,
            wrong_scope,
        )];
        assert!(current_mls_group(&entries, &realm_scope()).is_none());
        assert!(!scope_has_accepted_mls_genesis(&entries, &realm_scope()));
    }

    #[test]
    fn a_current_mls_group_for_another_realm_is_refused_by_the_bounded_view() {
        let other = arkret_sdk::ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
                .unwrap(),
        };
        let entries = vec![entry(
            CurrentSelector::MlsGroup { scope_ref: other },
            2,
            mls_group_value(),
        )];
        let mut projection = serde_json::json!({});
        let error = install_complete_view(&mut projection, REALM, entries).unwrap_err();
        assert!(
            error.to_string().contains("belongs to another Realm"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_bounded_view_installs_the_current_profile_title() {
        let entries = vec![entry(
            CurrentSelector::RealmProfile,
            5,
            serde_json::json!({
                "schema": "ak.schema.realm_profile.v1",
                "title": "Launch planning",
                "summary": "Q4"
            }),
        )];
        let mut projection = serde_json::json!({});
        install_complete_view(&mut projection, REALM, entries).unwrap();
        assert_eq!(projection["summary"]["title"], "Launch planning");
        assert_eq!(projection["summary"]["summary"], "Q4");
        // The signed revision travels with the value, so a reader can tell which
        // commit it was computed at without consulting Event order.
        assert_eq!(projection["current"][0]["revision"]["stream_position"], 5);
    }

    #[test]
    fn a_complete_inline_view_is_not_cut_off_at_a_private_item_limit() {
        let entries = (0..513)
            .map(|position| {
                entry(
                    CurrentSelector::RealmProfile,
                    position,
                    serde_json::json!({
                        "schema": "ak.schema.realm_profile.v1",
                        "title": format!("Realm {position}")
                    }),
                )
            })
            .collect::<Vec<_>>();
        let mut projection = serde_json::json!({});

        install_complete_view(&mut projection, REALM, entries).unwrap();

        assert_eq!(projection["current"].as_array().unwrap().len(), 513);
    }
}
