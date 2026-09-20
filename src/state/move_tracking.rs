use super::*;

impl LocalStateStore {
    // ── Move submission tracking ─────────────────────────────────────────

    /// Record a freshly-submitted Move and its initial state. The
    /// caller records local progress separately from verified effectiveness.
    /// `kind` is a free-form classifier (e.g. `ak.consent.grant`,
    /// `ak.message.create`, `mls_commit`) the UI uses to decorate
    /// pills + icons.
    pub fn record_move_submission(
        &mut self,
        move_id: impl Into<String>,
        realm_id: impl Into<String>,
        kind: impl Into<String>,
        state: MoveSubmissionState,
        reason: Option<String>,
        observed_stream_head: Option<String>,
    ) -> MoveSubmissionRecord {
        self.record_move_submission_with_event_id(
            move_id,
            None,
            realm_id,
            kind,
            state,
            reason,
            observed_stream_head,
        )
    }

    /// Record a submission and its signed Event id when available.
    /// Sync diagnostics are keyed only by that exact Event id.
    pub fn record_move_submission_with_event_id(
        &mut self,
        move_id: impl Into<String>,
        event_id: Option<String>,
        realm_id: impl Into<String>,
        kind: impl Into<String>,
        state: MoveSubmissionState,
        reason: Option<String>,
        observed_stream_head: Option<String>,
    ) -> MoveSubmissionRecord {
        self.ensure_cached_loaded();
        let move_id = move_id.into();
        let record = MoveSubmissionRecord {
            move_id: move_id.clone(),
            event_id,
            realm_id: realm_id.into(),
            kind: kind.into(),
            state,
            submitted_at: Utc::now(),
            reason,
            observed_stream_head,
        };
        self.cached.move_submissions.insert(move_id, record.clone());
        let _ = self.flush();
        record
    }

    fn move_submission_lookup_key(&self, event_id: &str) -> Option<String> {
        if self.cached.move_submissions.contains_key(event_id) {
            return Some(event_id.to_owned());
        }
        self.cached
            .move_submissions
            .iter()
            .find(|(_, record)| record.event_id.as_deref() == Some(event_id))
            .map(|(key, _)| key.clone())
    }

    /// Fold one authority submission outcome into the tracked Move.
    ///
    /// The governance Station's `RealmCommit` (or its typed rejection) is the
    /// only state source: there is no per-Event "state" field on a sync
    /// projection to read, and a Move that has not been committed stays
    /// pending. `PendingMlsBinding` is preserved because it is a local
    /// send-gate, not a submission verdict.
    pub fn apply_move_submission_result(
        &mut self,
        result: &crate::models::SubmitEventResult,
    ) -> bool {
        self.ensure_cached_loaded();
        let Some(record_key) = self.move_submission_lookup_key(&result.event_id) else {
            return false;
        };
        let Some(record) = self.cached.move_submissions.get_mut(&record_key) else {
            return false;
        };
        record
            .event_id
            .get_or_insert_with(|| result.event_id.clone());
        if let Some(commit) = &result.commit {
            record.observed_stream_head = crate::state::commit_stream_key(&commit.stream_ref)
                .map(|key| format!("{key}@{}", commit.stream_position));
        }
        let state = MoveSubmissionState::from_send_queue_status(result.status);
        if record.state == MoveSubmissionState::PendingMlsBinding
            && state == MoveSubmissionState::Effective
        {
            // The Event committed, but the local MLS gate is still open. Event
            // lifecycle and MLS epoch lifecycle are distinct.
            return false;
        }
        record.state = state;
        record.reason = result.rejection_reason_code.clone();
        let _ = self.flush();
        true
    }

    /// Read all tracked Moves for a specific Realm, sorted by submit
    /// time (newest first). Used by Board / realm_admin pills.
    pub fn move_submissions_for_realm(&self, realm_id: &str) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> = self
            .load()
            .move_submissions
            .into_values()
            .filter(|record| record.realm_id == realm_id)
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.submitted_at));
        out
    }

    /// Read all tracked Moves regardless of Space — used by the
    /// dashboard "everything failing" banner and the recovery flow.
    pub fn all_move_submissions(&self) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> =
            self.load().move_submissions.into_values().collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.submitted_at));
        out
    }

    /// True when at least one tracked Move targeting `realm_id` is
    /// stuck on `PendingMlsBinding`. Drives the M7 toast.
    pub fn realm_has_pending_mls_binding(&self, realm_id: &str) -> bool {
        self.move_submissions_for_realm(realm_id)
            .iter()
            .any(|record| record.state == MoveSubmissionState::PendingMlsBinding)
    }

    /// User-facing reason for the newest pending MLS binding in a Realm.
    ///
    /// The binding kind matters: an accepted membership Join requires an MLS
    /// Add, while a Leave/Ban requires an MLS Remove. Callers must not label
    /// the generic state as one proposal type without consulting the tracked
    /// canonical transition.
    pub fn realm_pending_mls_binding_reason(&self, realm_id: &str) -> Option<String> {
        self.move_submissions_for_realm(realm_id)
            .into_iter()
            .find(|record| record.state == MoveSubmissionState::PendingMlsBinding)
            .map(|record| {
                record.reason.unwrap_or_else(|| {
                    "epoch_update_required: membership frontier changed; MLS commit required"
                        .to_owned()
                })
            })
    }

    /// Resolve locally tracked membership transitions once the server reports
    /// no remaining Realm or Circle MLS Remove obligations.  Membership Event
    /// lifecycle and MLS epoch lifecycle are distinct, so the Event becoming
    /// effective alone must not clear the send gate; the reconciliation worker
    /// calls this only after the cryptographic frontier has caught up.
    pub fn resolve_member_remove_mls_bindings(&mut self, realm_id: &str) -> usize {
        self.ensure_cached_loaded();
        let mut updated = 0;
        for record in self.cached.move_submissions.values_mut() {
            if record.realm_id == realm_id
                && record.kind == "mls_member_remove"
                && record.state == MoveSubmissionState::PendingMlsBinding
            {
                record.state = MoveSubmissionState::Effective;
                record.reason = None;
                updated += 1;
            }
        }
        if updated > 0 {
            let _ = self.flush();
        }
        updated
    }

    /// Resolve tracked Join transitions after an accepted MLS Add commit has
    /// brought the local group roster into exact agreement with canonical
    /// Realm membership. The reconciliation caller is responsible for that
    /// cryptographic roster check; Event effectiveness alone is insufficient.
    pub fn resolve_member_add_mls_bindings(&mut self, realm_id: &str) -> usize {
        self.ensure_cached_loaded();
        let mut updated = 0;
        for record in self.cached.move_submissions.values_mut() {
            if record.realm_id == realm_id
                && record.kind == "mls_member_add"
                && record.state == MoveSubmissionState::PendingMlsBinding
            {
                record.state = MoveSubmissionState::Effective;
                record.reason = None;
                updated += 1;
            }
        }
        if updated > 0 {
            let _ = self.flush();
        }
        updated
    }
}
