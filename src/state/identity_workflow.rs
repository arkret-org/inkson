use super::*;

impl LocalStateStore {
    pub(crate) fn save_identity_inception_draft(
        &mut self,
        draft: crate::identity::identity_workflow::PublicPrincipalInceptionDraft,
    ) -> arkret_sdk::Result<()> {
        self.ensure_cached_loaded();
        if let Some(existing) = self.cached.identity_inception_drafts.get(&draft.draft_id)
            && existing != &draft
        {
            return Err(arkret_sdk::Error::IdempotencyConflict(
                draft.draft_id.clone(),
            ));
        }
        self.cached
            .identity_inception_drafts
            .insert(draft.draft_id.clone(), draft);
        self.flush().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("persist public inception draft: {error}"))
        })
    }

    pub(crate) fn identity_inception_draft(
        &self,
        draft_id: &str,
    ) -> Option<crate::identity::identity_workflow::PublicPrincipalInceptionDraft> {
        self.load().identity_inception_drafts.get(draft_id).cloned()
    }

    pub(crate) fn replace_identity_inception_draft(
        &mut self,
        draft: crate::identity::identity_workflow::PublicPrincipalInceptionDraft,
    ) -> arkret_sdk::Result<()> {
        self.ensure_cached_loaded();
        if !self
            .cached
            .identity_inception_drafts
            .contains_key(&draft.draft_id)
        {
            return Err(arkret_sdk::Error::Protocol(format!(
                "identity inception draft not found: {}",
                draft.draft_id
            )));
        }
        self.cached
            .identity_inception_drafts
            .insert(draft.draft_id.clone(), draft);
        self.flush().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("persist inception checkpoint: {error}"))
        })
    }

    pub(crate) fn save_identity_recovery_workflow(
        &mut self,
        principal_id: String,
        workflow: crate::identity::identity_workflow::RecoveryWorkflow,
    ) -> arkret_sdk::Result<()> {
        self.ensure_cached_loaded();
        if let Some(existing) = self.cached.identity_recovery_workflows.get(&principal_id) {
            let existing_model = match existing {
                crate::identity::identity_workflow::RecoveryWorkflow::CrossSigningReset { .. } => {
                    crate::identity::identity_workflow::PrincipalAuthorityModel::CrossSigning
                }
                crate::identity::identity_workflow::RecoveryWorkflow::EnrollmentAuthorityHandoff(
                    _,
                ) => crate::identity::identity_workflow::PrincipalAuthorityModel::EnrollmentAuthority,
            };
            workflow.ensure_model(existing_model).map_err(|error| {
                arkret_sdk::Error::Protocol(format!("replace recovery workflow: {error}"))
            })?;
        }
        self.cached
            .identity_recovery_workflows
            .insert(principal_id, workflow);
        self.flush().map_err(|error| {
            arkret_sdk::Error::Protocol(format!("persist recovery workflow checkpoint: {error}"))
        })
    }

    pub(crate) fn identity_recovery_workflow(
        &self,
        principal_id: &str,
    ) -> Option<crate::identity::identity_workflow::RecoveryWorkflow> {
        self.load()
            .identity_recovery_workflows
            .get(principal_id)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_identity_workflow_json_contains_no_secret_fields() {
        let state = ClientLocalState::default();
        let json = serde_json::to_string(&state).unwrap();
        for forbidden in [
            "recovery_mnemonic",
            "recovery_secret",
            "root_seed",
            "recovery_proof_seed",
            "backup_hpke_ikm",
            "private_key",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
}
