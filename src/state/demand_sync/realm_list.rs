//! Account-list visibility changes invalidate retained current cuts. List
//! revisions remain account-local and are never compared with stream positions.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealmListReadFence {
    removal: Option<u64>,
}

fn read_fence(state: &DemandSyncState, realm: &str) -> RealmListReadFence {
    RealmListReadFence {
        removal: state.summary_removals.get(realm).copied(),
    }
}

fn read_denied(state: &DemandSyncState, realm: &str) -> bool {
    let row = state.summaries.get(realm);
    row.is_some_and(|row| row.membership != arkret_wire::MembershipState::Join)
        || state
            .summary_removals
            .get(realm)
            .is_some_and(|negative| row.is_none_or(|row| row.revision <= *negative))
}

enum Effect {
    Upsert(RealmRow),
    Remove(String),
}

struct Plan {
    next: DemandSyncState,
    effects: Vec<Effect>,
    resets: BTreeSet<String>,
}

impl Plan {
    fn upsert(&mut self, row: &RealmRow) -> anyhow::Result<()> {
        let id = row.realm_id.as_str();
        let old = self.next.summaries.get(id);
        if self
            .next
            .summary_removals
            .get(id)
            .is_some_and(|v| *v > row.revision || (*v == row.revision && old.is_none()))
            || old.is_some_and(|v| v.revision > row.revision)
        {
            return Ok(());
        }
        anyhow::ensure!(
            old.is_none_or(|v| v.revision != row.revision || v == row),
            "Realm summary changed at same revision"
        );
        if (old.is_none() && self.next.summary_removals.contains_key(id))
            || old.is_some_and(|v| v.membership != row.membership)
            || (old.is_none() && row.membership != arkret_wire::MembershipState::Join)
        {
            self.resets.insert(id.to_owned());
        }
        // Preserve the last negative list revision across rejoin. It is an
        // in-flight read fence, not a current denial of a newer joined row.
        if row.membership != arkret_wire::MembershipState::Join {
            self.next
                .summary_removals
                .insert(id.to_owned(), row.revision);
        }
        self.next.summaries.insert(id.to_owned(), row.clone());
        self.effects.push(Effect::Upsert(row.clone()));
        Ok(())
    }

    fn remove(&mut self, id: &str, revision: u64) {
        if self
            .next
            .summaries
            .get(id)
            .is_some_and(|v| v.revision > revision)
            || self
                .next
                .summary_removals
                .get(id)
                .is_some_and(|v| *v > revision)
        {
            return;
        }
        if self.next.summary_removals.get(id) != Some(&revision) {
            self.resets.insert(id.to_owned());
        }
        self.next.summaries.remove(id);
        self.next.summary_removals.insert(id.to_owned(), revision);
        self.effects.push(Effect::Remove(id.to_owned()));
    }
}

fn prepare(state: &DemandSyncState, views: &FrameViews) -> anyhow::Result<Plan> {
    // All growing collections are persistent roots. Clone only those roots;
    // copy rows solely for this bounded page/delta, never the account payloads.
    let mut plan = Plan {
        next: state.clone(),
        effects: Vec::new(),
        resets: BTreeSet::new(),
    };
    if let Some(page) = &views.realm_list {
        if plan.next.list_snapshot.as_ref() != Some(&page.snapshot_cursor) {
            plan.next.list_snapshot = Some(page.snapshot_cursor.clone());
            plan.next.list_revision = page.snapshot_revision;
            plan.next.list_seen.clear();
            plan.next.list_complete = false;
        }
        anyhow::ensure!(
            plan.next.list_revision == page.snapshot_revision,
            "Realm list snapshot changed revision"
        );
        for row in &page.items {
            plan.next.list_seen.insert(row.realm_id.to_string());
            plan.upsert(row)?;
        }
        plan.next.list_after = page.next_cursor.clone();
        plan.next.requested_list_after = None;
        plan.next.list_complete = page.complete;
        if page.complete {
            let stale = plan
                .next
                .summaries
                .iter()
                .filter(|(id, row)| {
                    row.revision <= page.snapshot_revision && !plan.next.list_seen.contains(*id)
                })
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in stale {
                plan.remove(&id, page.snapshot_revision);
            }
        }
    }
    if let Some(changes) = &views.realm_list_changes {
        for row in &changes.upserts {
            plan.upsert(row)?;
        }
        for row in &changes.removals {
            plan.remove(row.realm_id.as_str(), row.revision);
        }
    }
    Ok(plan)
}

#[cfg(any(test, target_arch = "wasm32"))]
pub(super) fn initial_resets(frame: &AccountSubscribeFrame) -> anyhow::Result<BTreeSet<String>> {
    Ok(prepare(&DemandSyncState::default(), &FrameViews::decode(frame)?)?.resets)
}

impl LocalStateStore {
    pub(crate) fn realm_list_read_fence(&self, realm: &str) -> RealmListReadFence {
        self.with_unoverlaid_account_fields(|state| read_fence(&state.demand_sync, realm))
    }

    pub(crate) fn require_realm_list_read_fence(
        &self,
        realm: &str,
        expected: Option<&RealmListReadFence>,
    ) -> anyhow::Result<()> {
        if expected.is_some_and(|expected| self.realm_list_read_fence(realm) != *expected) {
            return Err(crate::state::current_index::CurrentCutSuperseded.into());
        }
        Ok(())
    }

    /// Negative evidence only: neither an absent list page nor a joined summary
    /// grants access. The complete signed current cut still supplies authority.
    pub(crate) fn account_scope_read_denied(&self, realm: &str) -> bool {
        self.with_unoverlaid_account_fields(|state| read_denied(&state.demand_sync, realm))
    }

    pub(crate) fn account_scope_resets(
        &self,
        frame: &AccountSubscribeFrame,
    ) -> anyhow::Result<BTreeSet<String>> {
        if frame.realm_list.is_none() && frame.realm_list_changes.is_none() {
            return Ok(BTreeSet::new());
        }
        self.with_unoverlaid_account_fields(|state| {
            Ok(prepare(&state.demand_sync, &FrameViews::decode(frame)?)?.resets)
        })
    }

    pub(super) fn apply_realm_list_views(&mut self, views: &FrameViews) -> anyhow::Result<()> {
        if views.realm_list.is_none() && views.realm_list_changes.is_none() {
            return Ok(());
        }
        let plan = prepare(&self.cached.demand_sync, views)?;
        self.cached.demand_sync = plan.next;
        for effect in plan.effects {
            match effect {
                Effect::Upsert(row) => self.project_demand_summary(&row)?,
                Effect::Remove(id) => self.project_demand_removal(&id),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    const REALM: &str = "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI";
    const OTHER: &str = "ak:realm:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";
    fn apply(state: &DemandSyncState, value: Value) -> Plan {
        let frame: AccountSubscribeFrame = serde_json::from_value(value).unwrap();
        frame.validate().unwrap();
        prepare(state, &FrameViews::decode(&frame).unwrap()).unwrap()
    }
    fn join(realm: &str, revision: u64) -> Value {
        json!({"kind":"delta","cursor":"ak:cursor:YQ","realm_list_changes":{
            "upserts":[{"realm_id":realm,"revision":revision,"activity_position":1,"membership":"join"}],"removals":[]}})
    }

    #[test]
    fn list_removal_and_rejoin_fence_late_reads_without_resetting_activity_updates() {
        let first = apply(&DemandSyncState::default(), join(REALM, 10));
        assert!(first.resets.is_empty());
        assert_eq!(
            read_fence(&DemandSyncState::default(), REALM),
            read_fence(&first.next, REALM)
        );
        assert!(!read_denied(&first.next, REALM));
        let old_read = read_fence(&first.next, REALM);
        let removed = apply(
            &first.next,
            json!({"kind":"delta","cursor":"ak:cursor:Yg",
            "realm_list_changes":{"upserts":[],"removals":[{"realm_id":REALM,"revision":11}]}}),
        );
        assert_eq!(removed.resets, BTreeSet::from([REALM.to_owned()]));
        assert!(read_denied(&removed.next, REALM));
        assert_ne!(old_read, read_fence(&removed.next, REALM));
        let stale = apply(&removed.next, join(REALM, 10));
        assert!(stale.resets.is_empty());
        assert_eq!(stale.next.summary_removals.get(REALM), Some(&11));
        let rejoined = apply(&stale.next, join(REALM, 12));
        assert_eq!(rejoined.resets, BTreeSet::from([REALM.to_owned()]));
        assert_ne!(old_read, read_fence(&rejoined.next, REALM));
        let activity = apply(&rejoined.next, join(REALM, 13));
        assert!(activity.resets.is_empty());
        assert_eq!(activity.next.summary_removals.get(REALM), Some(&11));
        assert!(!read_denied(&activity.next, REALM));
        assert_eq!(
            read_fence(&rejoined.next, REALM),
            read_fence(&activity.next, REALM)
        );
        let cold: DemandSyncState =
            serde_json::from_value(serde_json::to_value(&activity.next).unwrap()).unwrap();
        assert_eq!(read_fence(&cold, REALM), read_fence(&activity.next, REALM));
        assert_ne!(old_read, read_fence(&cold, REALM));
    }

    #[test]
    fn knock_and_rejoin_keep_the_negative_boundary_without_rejecting_activity() {
        let first = apply(&DemandSyncState::default(), join(REALM, 10));
        let old_read = read_fence(&first.next, REALM);
        let mut knock = join(REALM, 11);
        knock["realm_list_changes"]["upserts"][0]["membership"] = json!("knock");
        let knocked = apply(&first.next, knock);
        assert!(read_denied(&knocked.next, REALM));
        let mut conflict = join(REALM, 11);
        conflict["realm_list_changes"]["upserts"][0]["membership"] = json!("knock");
        conflict["realm_list_changes"]["upserts"][0]["title"] = json!("conflicting same-cut title");
        let frame: AccountSubscribeFrame = serde_json::from_value(conflict).unwrap();
        assert!(prepare(&knocked.next, &FrameViews::decode(&frame).unwrap()).is_err());
        assert_eq!(knocked.resets, BTreeSet::from([REALM.to_owned()]));
        let rejoined = apply(&knocked.next, join(REALM, 12));
        assert_eq!(rejoined.resets, BTreeSet::from([REALM.to_owned()]));
        assert!(!read_denied(&rejoined.next, REALM));
        assert_ne!(old_read, read_fence(&rejoined.next, REALM));
        let activity = apply(&rejoined.next, join(REALM, 13));
        assert!(activity.resets.is_empty());
        assert_eq!(
            read_fence(&rejoined.next, REALM),
            read_fence(&activity.next, REALM)
        );
    }

    #[test]
    fn completed_list_omission_resets_only_rows_covered_by_that_list_cut() {
        let first = apply(&DemandSyncState::default(), join(REALM, 5));
        let newer = apply(&first.next, join(OTHER, 50));
        let complete = apply(
            &newer.next,
            json!({"kind":"delta","cursor":"ak:cursor:Yw",
            "realm_list":{"snapshot_cursor":"ak:cursor:Yg","snapshot_revision":10,"items":[]}}),
        );
        assert_eq!(complete.resets, BTreeSet::from([REALM.to_owned()]));
        assert!(complete.next.summaries.contains_key(OTHER));
        let restored = apply(&complete.next, join(REALM, 11));
        assert_eq!(restored.resets, BTreeSet::from([REALM.to_owned()]));
    }
}
