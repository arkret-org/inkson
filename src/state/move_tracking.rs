use super::*;

impl LocalStateStore {
    // ── Move submission tracking ─────────────────────────────────────────

    /// Record a freshly-submitted Move and its initial state. The
    /// caller has just received soland's `SubmitMoveOutcome`; the
    /// state is mapped in via [`MoveSubmissionState::from_submit_state`].
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
        seal_ref: Option<String>,
    ) -> MoveSubmissionRecord {
        self.record_move_submission_with_event_id(
            move_id, None, realm_id, kind, state, reason, seal_ref,
        )
    }

    /// Record a freshly-submitted Move/Event and remember the server Event id
    /// when available. Sync `event_states[]` is keyed by server `event_id`,
    /// while older local queues used `move_id` / idempotency aliases.
    pub fn record_move_submission_with_event_id(
        &mut self,
        move_id: impl Into<String>,
        event_id: Option<String>,
        realm_id: impl Into<String>,
        kind: impl Into<String>,
        state: MoveSubmissionState,
        reason: Option<String>,
        seal_ref: Option<String>,
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
            seal_ref,
        };
        self.cached.move_submissions.insert(move_id, record.clone());
        let _ = self.flush();
        record
    }

    fn move_submission_lookup_key(
        &self,
        event_id: Option<&str>,
        move_id: Option<&str>,
    ) -> Option<String> {
        for id in [move_id, event_id].into_iter().flatten() {
            if self.cached.move_submissions.contains_key(id) {
                return Some(id.to_owned());
            }
        }
        self.cached
            .move_submissions
            .iter()
            .find(|(_, record)| {
                event_id.is_some_and(|id| record.event_id.as_deref() == Some(id))
                    || move_id.is_some_and(|id| record.move_id == id)
            })
            .map(|(key, _)| key.clone())
    }

    /// Apply per-event protocol states from a per-Realm sync projection.
    /// Spec source: `service-surface.md §5.3`, where each reducer-input
    /// Event may carry `event_id`, `event_state`, and an optional reason code.
    pub fn ingest_move_event_states(&mut self, realm_id: &str, body: &Value) -> usize {
        let Some(entries) = body.get("event_states").and_then(|v| v.as_array()) else {
            return 0;
        };
        self.ensure_cached_loaded();
        let mut updated = 0usize;
        for entry in entries {
            let event_id = entry.get("event_id").and_then(|v| v.as_str());
            let move_id = entry.get("move_id").and_then(|v| v.as_str());
            if event_id.is_none() && move_id.is_none() {
                continue;
            }
            let Some(state_label) = entry
                .get("event_state")
                .or_else(|| entry.get("state"))
                .and_then(|v| v.as_str())
            else {
                continue;
            };
            let reason = entry
                .get("event_state_reason_code")
                .or_else(|| entry.get("reason_code"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let state = MoveSubmissionState::from_submit_state(state_label, reason.as_deref());
            let Some(record_key) = self.move_submission_lookup_key(event_id, move_id) else {
                continue;
            };
            let Some(record) = self.cached.move_submissions.get_mut(&record_key) else {
                continue;
            };
            if record.realm_id != realm_id {
                continue;
            }
            if let Some(event_id) = event_id {
                record.event_id.get_or_insert_with(|| event_id.to_owned());
            }
            record.state = state;
            if reason.is_some() {
                record.reason = reason;
            }
            updated += 1;
        }
        if updated > 0 {
            let _ = self.flush();
        }
        updated
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
    /// dashboard "everything failing" banner and the recovery strand.
    pub fn all_move_submissions(&self) -> Vec<MoveSubmissionRecord> {
        let mut out: Vec<MoveSubmissionRecord> =
            self.load().move_submissions.into_values().collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.submitted_at));
        out
    }

    /// True when at least one tracked Move in `realm_id` is in
    /// `NotaryPaused`. Drives the Realm-wide "waiting for recovery notary"
    /// banner described in the M4 ticket.
    pub fn realm_has_paused_notary(&self, realm_id: &str) -> bool {
        self.move_submissions_for_realm(realm_id)
            .iter()
            .any(|record| record.state == MoveSubmissionState::NotaryPaused)
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
