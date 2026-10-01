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
pub(crate) const REQUIRED_REALM_SELECTORS: [CurrentSelector; 2] = [
    CurrentSelector::RealmProfile,
    CurrentSelector::RealmPolicyBundle,
];

fn selector_of(entry: &TypedCurrentResult) -> &CurrentSelector {
    let TypedCurrentResult::Value { selector, .. } = entry;
    selector
}

fn value_of(entry: &TypedCurrentResult) -> &Value {
    let TypedCurrentResult::Value { value, .. } = entry;
    value
}

fn entry_for<'a>(
    entries: &'a [TypedCurrentResult],
    selector: &CurrentSelector,
) -> Option<&'a TypedCurrentResult> {
    entries.iter().find(|entry| selector_of(entry) == selector)
}

pub(crate) fn required_realm_values_ready(entries: &[TypedCurrentResult]) -> bool {
    if let Some(genesis) = entry_for(entries, &CurrentSelector::RealmGenesis)
        .map(value_of)
        .and_then(|value| serde_json::from_value::<arkret_sdk::RealmGenesis>(value.clone()).ok())
        && genesis.purpose == arkret_sdk::RealmPurpose::DirectConversation
    {
        // Direct founding has four Events and no editable profile/policy
        // baseline. Its closed genesis supplies the fixed policy instead.
        return genesis.validate().is_ok()
            && genesis.initial_join_rule == arkret_sdk::JoinRule::Closed
            && genesis.initial_history_access == arkret_sdk::HistoryAccess::SinceJoin
            && genesis.initial_discoverability == arkret_sdk::Discoverability::InviteOnly;
    }
    REQUIRED_REALM_SELECTORS
        .iter()
        .all(|selector| entry_for(entries, selector).is_some())
}

/// The typed current results of one Realm as the product reads them.
///
/// Host view only: the rows are read page by page from the durable current
/// index for the selected Realm and held in memory. It never reaches the wire
/// and is never persisted in the account blob.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RealmCurrentView {
    pub realm_id: String,
    pub entries: Vec<TypedCurrentResult>,
    /// Whether the rows were read at one complete verified cut of the durable
    /// index (installed baseline, every authorized stream covered, no pending
    /// refresh). Only such a view may answer a selector's absence.
    pub complete_cut: bool,
}

/// What an installed current view says about one scope's MLS activation.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ScopeMlsCurrent {
    /// The view carries the scope's accepted `mls_group`: the scope is
    /// irreversibly standard RFC 9420.
    Activated(arkret_wire::MlsGroupCurrent),
    /// The view is a complete verified cut without an `mls_group` for the
    /// scope: it has no accepted Genesis.
    NotActivated,
    /// No complete cut of the scope's Realm is installed; nothing is known.
    Unknown,
}

impl ScopeMlsCurrent {
    /// `Some(activated)` once known, `None` while unknown.
    pub(crate) fn activated(&self) -> Option<bool> {
        match self {
            Self::Activated(_) => Some(true),
            Self::NotActivated => Some(false),
            Self::Unknown => None,
        }
    }
}

impl RealmCurrentView {
    pub(crate) fn ready(&self) -> bool {
        self.complete_cut && required_realm_values_ready(&self.entries)
    }

    /// Validate that every scope-carrying row belongs to `realm_id`.
    pub(crate) fn new(
        realm_id: &str,
        entries: Vec<TypedCurrentResult>,
        complete_cut: bool,
    ) -> anyhow::Result<Self> {
        let realm = RealmId::new(realm_id.to_owned())?;
        for entry in &entries {
            if let TypedCurrentResult::Value {
                selector: CurrentSelector::MemberState { .. },
                source_stream_ref,
                ..
            } = entry
            {
                anyhow::ensure!(
                    source_stream_ref
                        == &arkret_wire::CommitStreamRef::Realm {
                            realm_id: realm.clone()
                        },
                    "current member state belongs to another Realm stream"
                );
            }
            // Only the scope-carrying selectors can name another Realm at all;
            // the rest are Realm-singletons of the index region they came from.
            if let CurrentSelector::MlsGroup { scope_ref } = selector_of(entry) {
                anyhow::ensure!(
                    scope_ref.realm_id_opt() == Some(&realm),
                    "current MLS group result belongs to another Realm"
                );
            }
        }
        Ok(Self {
            realm_id: realm.as_str().to_owned(),
            entries,
            complete_cut,
        })
    }

    /// The MLS activation of `scope_ref` as this view knows it. An accepted
    /// row is positive evidence on its own, because activation is
    /// irreversible; its absence answers only on a complete cut.
    pub(crate) fn scope_mls_current(&self, scope_ref: &arkret_sdk::ScopeRef) -> ScopeMlsCurrent {
        let Some(entries) = scope_ref
            .realm_id_opt()
            .and_then(|realm_id| self.entries_for(realm_id.as_str()))
        else {
            return ScopeMlsCurrent::Unknown;
        };
        match current_mls_group(entries, scope_ref) {
            Some(group) => ScopeMlsCurrent::Activated(group),
            None if self.complete_cut => ScopeMlsCurrent::NotActivated,
            None => ScopeMlsCurrent::Unknown,
        }
    }

    /// The rows of `realm_id`, or `None` when this view belongs to another
    /// Realm. `None` is "not installed", never an empty current set.
    pub(crate) fn entries_for(&self, realm_id: &str) -> Option<&[TypedCurrentResult]> {
        (self.realm_id == realm_id.trim()).then_some(self.entries.as_slice())
    }

    /// Reconciliation may infer absent members only from the complete
    /// authority-verified cut, never from a partial roster display page.
    pub(crate) fn complete_joined_members(
        &self,
    ) -> anyhow::Result<Option<std::collections::BTreeSet<arkret_sdk::ActorId>>> {
        if !self.complete_cut {
            return Ok(None);
        }
        let mut joined = std::collections::BTreeSet::new();
        for entry in &self.entries {
            if let TypedCurrentResult::Value {
                selector: CurrentSelector::MemberState { actor_id },
                value,
                ..
            } = entry
            {
                let state: arkret_wire::MemberStateCurrent = serde_json::from_value(value.clone())?;
                if state.membership == arkret_wire::MembershipState::Join {
                    joined.insert(actor_id.clone());
                }
            }
        }
        Ok(Some(joined))
    }
}

/// Write the presentation fields derived from the current Realm profile into a
/// stored Realm projection. Only the title and summary are copied; the typed
/// rows themselves stay in the index.
pub(crate) fn apply_profile_summary(
    projection: &mut Value,
    entries: &[TypedCurrentResult],
) -> anyhow::Result<()> {
    let Some(profile) = entry_for(entries, &CurrentSelector::RealmProfile)
        .map(value_of)
        .and_then(|value| serde_json::from_value::<arkret_sdk::RealmProfile>(value.clone()).ok())
    else {
        return Ok(());
    };
    let object = projection
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Realm projection must be an object"))?;
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
        .map(value_of)
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
        .map(value_of)
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .filter(|group: &arkret_wire::MlsGroupCurrent| group.effective_scope == *scope_ref)
}

/// The Station-selected current `ak.realm.policy_bundle` value.
pub(crate) fn current_realm_policy_bundle_value(entries: &[TypedCurrentResult]) -> Option<Value> {
    entry_for(entries, &CurrentSelector::RealmPolicyBundle)
        .map(value_of)
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
    entry_for(entries, selector).map(|entry| {
        let TypedCurrentResult::Value { revision, .. } = entry;
        revision.clone()
    })
}

#[cfg(test)]
mod tests {
    use arkret_wire::{CurrentRevision, RealmCommitId};

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    #[test]
    fn membership_reconciliation_requires_a_complete_verified_cut() {
        let actor = arkret_sdk::ActorId::account(arkret_sdk::AccountId::new(
            arkret_sdk::DidCoreId::new("ak:did_core:web:member.example").unwrap(),
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let rows = vec![entry(
            CurrentSelector::MemberState {
                actor_id: actor.clone(),
            },
            1,
            serde_json::json!({"membership":"join","joined_at":"2026-09-27T00:00:00.000Z"}),
        )];
        assert_eq!(
            RealmCurrentView::new(REALM, rows.clone(), false)
                .unwrap()
                .complete_joined_members()
                .unwrap(),
            None,
        );
        assert_eq!(
            RealmCurrentView::new(REALM, rows.clone(), true)
                .unwrap()
                .complete_joined_members()
                .unwrap(),
            Some(std::collections::BTreeSet::from([actor])),
        );
        let mut stale = rows;
        let TypedCurrentResult::Value {
            source_stream_ref, ..
        } = &mut stale[0];
        *source_stream_ref = arkret_wire::CommitStreamRef::Realm {
            realm_id: RealmId::new("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
                .unwrap(),
        };
        assert!(RealmCurrentView::new(REALM, stale, true).is_err());
    }

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
            source_stream_ref: arkret_wire::CommitStreamRef::Realm {
                realm_id: RealmId::new(REALM).unwrap(),
            },
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
            CurrentSelector::RealmPolicyBundle,
            4,
            serde_json::json!({"policy_revision": 1}),
        );
        assert!(!required_realm_values_ready(std::slice::from_ref(&profile)));
        let entries = vec![profile, policy];
        assert!(required_realm_values_ready(&entries));
        assert!(
            RealmCurrentView::new(REALM, entries.clone(), true)
                .unwrap()
                .ready()
        );
        assert!(
            !RealmCurrentView::new(REALM, entries, false)
                .unwrap()
                .ready()
        );
    }

    #[test]
    fn direct_current_uses_fixed_genesis_policy_only_at_a_complete_cut() {
        let genesis = arkret_sdk::RealmGenesis::new(
            arkret_sdk::RealmPurpose::DirectConversation,
            arkret_sdk::GenesisSalt::new("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            arkret_sdk::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
            arkret_sdk::SecurityClass::Standard,
            arkret_sdk::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            arkret_sdk::JoinRule::Closed,
            arkret_sdk::HistoryAccess::SinceJoin,
            arkret_sdk::Discoverability::InviteOnly,
            None,
            None,
        )
        .unwrap();
        let value = serde_json::to_value(&genesis).unwrap();
        let entries = vec![entry(CurrentSelector::RealmGenesis, 0, value.clone())];
        assert!(
            RealmCurrentView::new(REALM, entries.clone(), true)
                .unwrap()
                .ready()
        );
        assert!(
            !RealmCurrentView::new(REALM, entries, false)
                .unwrap()
                .ready()
        );
        for (field, invalid) in [
            ("purpose", serde_json::json!("collaboration")),
            ("initial_join_rule", serde_json::json!("invite")),
            (
                "initial_history_access",
                serde_json::json!("all_history_for_current_members"),
            ),
            ("initial_discoverability", serde_json::json!("listed")),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut invalid_genesis = value.clone();
            invalid_genesis[field] = invalid;
            let entries = vec![entry(CurrentSelector::RealmGenesis, 0, invalid_genesis)];
            assert!(
                !RealmCurrentView::new(REALM, entries, true).unwrap().ready(),
                "{field}"
            );
        }
    }

    #[test]
    fn a_scope_is_encrypted_exactly_when_it_has_an_accepted_mls_genesis() {
        let plaintext = vec![entry(
            CurrentSelector::RealmProfile,
            1,
            serde_json::json!({"schema": "ak.schema.realm_profile.v1", "title": "Open"}),
        )];
        let complete = RealmCurrentView::new(REALM, plaintext.clone(), true).unwrap();
        assert_eq!(
            complete.scope_mls_current(&realm_scope()),
            ScopeMlsCurrent::NotActivated
        );

        let activated = vec![entry(
            CurrentSelector::MlsGroup {
                scope_ref: realm_scope(),
            },
            9,
            mls_group_value(),
        )];
        let group = current_mls_group(&activated, &realm_scope()).expect("current MLS group");
        assert_eq!(group.epoch, 4);
        let view = RealmCurrentView::new(REALM, activated, false).unwrap();
        assert_eq!(
            view.scope_mls_current(&realm_scope()),
            ScopeMlsCurrent::Activated(group)
        );
    }

    #[test]
    fn an_incomplete_cut_never_answers_plaintext() {
        let rows = vec![entry(
            CurrentSelector::RealmProfile,
            1,
            serde_json::json!({"schema": "ak.schema.realm_profile.v1", "title": "Open"}),
        )];
        let partial = RealmCurrentView::new(REALM, rows, false).unwrap();
        assert_eq!(
            partial.scope_mls_current(&realm_scope()),
            ScopeMlsCurrent::Unknown
        );
        assert_eq!(partial.scope_mls_current(&realm_scope()).activated(), None);
        let other = arkret_sdk::ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
                .unwrap(),
        };
        let complete = RealmCurrentView::new(REALM, Vec::new(), true).unwrap();
        assert_eq!(complete.scope_mls_current(&other), ScopeMlsCurrent::Unknown);
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
        let error = RealmCurrentView::new(REALM, entries, true).unwrap_err();
        assert!(
            error.to_string().contains("belongs to another Realm"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_profile_summary_is_copied_without_the_typed_rows() {
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
        apply_profile_summary(&mut projection, &entries).unwrap();
        assert_eq!(projection["summary"]["title"], "Launch planning");
        assert_eq!(projection["summary"]["summary"], "Q4");
        assert!(projection.get("current").is_none());
    }

    #[test]
    fn a_view_answers_only_for_its_own_realm() {
        let view = RealmCurrentView::new(REALM, Vec::new(), true).unwrap();
        assert_eq!(view.entries_for(REALM), Some(&[][..]));
        assert_eq!(
            view.entries_for("ak:realm:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM"),
            None
        );
    }
}
