#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkflowStage {
    Supported,
    ClientReady,
    Blocked,
}

impl WorkflowStage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::ClientReady => "client-ready",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientWorkflow {
    pub id: &'static str,
    pub name: &'static str,
    pub stage: WorkflowStage,
    pub client_surface: &'static str,
    pub server_dependency: &'static str,
}

pub fn production_release_workflows() -> Vec<ClientWorkflow> {
    vec![
        ClientWorkflow {
            id: "account.dev_bootstrap",
            name: "Development account bootstrap",
            stage: WorkflowStage::Supported,
            client_surface: "Settings + Connect",
            server_dependency: "POST /api/v1/auth/dev-login",
        },
        ClientWorkflow {
            id: "account.registration",
            name: "Production registration",
            stage: WorkflowStage::Blocked,
            client_surface: "Onboarding identity bootstrap",
            server_dependency: "Needs DID proof challenge, recovery policy, and account/device verification before production",
        },
        ClientWorkflow {
            id: "account.password_passkey_login",
            name: "Password/passkey login",
            stage: WorkflowStage::Blocked,
            client_surface: "Release panel gap",
            server_dependency: "Needs coauth-owned OIDC/passkey challenge, code/token exchange, soland session-grant handoff, and chime push registration grant reuse",
        },
        ClientWorkflow {
            id: "identity.device_verification",
            name: "Device verification",
            stage: WorkflowStage::ClientReady,
            client_surface: "Devices panel + SDK device primitives + cross-signing plan",
            server_dependency: "Needs persisted device trust + SAS/QR verification + revocation + cross_signing publish/reset endpoints (SDK three-tier model and trust-chain verifier are now in place)",
        },
        ClientWorkflow {
            id: "recovery.key_backup_upload",
            name: "Encrypted Cloud Vault upload",
            stage: WorkflowStage::ClientReady,
            client_surface: "Recovery panel: passphrase + Argon2id KDF + XChaCha20-Poly1305 AEAD",
            server_dependency: "PUT /api/v1/keys/backups/{backup_id} (cx.schema.key_backup.v1 envelope)",
        },
        ClientWorkflow {
            id: "recovery.key_backup_restore",
            name: "Restore from encrypted backup",
            stage: WorkflowStage::ClientReady,
            client_surface: "Recovery panel: list + decrypt + delete the server-side vault ciphertext",
            server_dependency: "GET /api/v1/keys/backups, GET /api/v1/keys/backups/{id}, DELETE /api/v1/keys/backups/{id}",
        },
        ClientWorkflow {
            id: "identity.cross_signing_setup",
            name: "Cross-signing bootstrap and reset",
            stage: WorkflowStage::ClientReady,
            client_surface: "Verify Device panel: renders CrossSigningSetupPlan steps + canonical events",
            server_dependency: "Needs cx.cross_signing.publish / cx.cross_signing.reset / cx.device.authorized acceptance endpoints",
        },
        ClientWorkflow {
            id: "space.discovery",
            name: "Discover and resolve public spaces",
            stage: WorkflowStage::Supported,
            client_surface: "Directory panel",
            server_dependency: "POST /api/v1/directory/search-spaces and resolve-space",
        },
        ClientWorkflow {
            id: "space.create",
            name: "Create space",
            stage: WorkflowStage::Blocked,
            client_surface: "Workspace Setup space bootstrap",
            server_dependency: "Needs metadata edit, policy templates, signed operation templates, and retention rules",
        },
        ClientWorkflow {
            id: "space.membership",
            name: "Invite, add, remove, and kick members",
            stage: WorkflowStage::Blocked,
            client_surface: "Workspace Setup + Space Admin membership",
            server_dependency: "Missing invite/member state operations, authz checks, MLS Welcome/Commit delivery, and removal epoch rotation",
        },
        ClientWorkflow {
            id: "space.delete",
            name: "Leave, archive, and delete space",
            stage: WorkflowStage::Blocked,
            client_surface: "Workspace Setup + Space Admin destructive flows",
            server_dependency: "Needs leave/archive UX, tombstone policy, and history retention enforcement",
        },
        ClientWorkflow {
            id: "message.create",
            name: "Plaintext and local encrypted compose",
            stage: WorkflowStage::ClientReady,
            client_surface: "Space timeline composer",
            server_dependency: "Needs real web MLS crypto store and client-side signed commit path for offline queue",
        },
        ClientWorkflow {
            id: "moderation.report",
            name: "Moderation report",
            stage: WorkflowStage::Supported,
            client_surface: "Report / Queue",
            server_dependency: "POST /api/v1/moderation/report",
        },
        ClientWorkflow {
            id: "release.packaging",
            name: "Release packaging and upgrade",
            stage: WorkflowStage::Blocked,
            client_surface: "Release panel gap",
            server_dependency: "Missing signed builds, updater, crash telemetry, release channels, and production configuration",
        },
    ]
}

pub fn blocked_release_workflows() -> Vec<ClientWorkflow> {
    production_release_workflows()
        .into_iter()
        .filter(|workflow| workflow.stage == WorkflowStage::Blocked)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_workflow_inventory_keeps_major_client_gaps_visible() {
        let blocked = blocked_release_workflows();
        assert!(
            blocked
                .iter()
                .any(|workflow| workflow.id == "account.registration")
        );
        assert!(blocked.iter().any(|workflow| workflow.id == "space.create"));
        assert!(
            blocked
                .iter()
                .any(|workflow| workflow.id == "space.membership")
        );
        assert!(blocked.iter().any(|workflow| workflow.id == "space.delete"));
    }

    #[test]
    fn current_supported_workflows_are_explicit_not_inferred_as_release_ready() {
        let workflows = production_release_workflows();
        assert!(
            workflows
                .iter()
                .any(|workflow| workflow.id == "account.dev_bootstrap"
                    && workflow.stage == WorkflowStage::Supported)
        );
        assert!(
            workflows
                .iter()
                .any(|workflow| workflow.id == "message.create"
                    && workflow.stage == WorkflowStage::ClientReady)
        );
    }

    #[test]
    fn key_backup_flows_are_client_ready() {
        let workflows = production_release_workflows();
        for id in [
            "recovery.key_backup_upload",
            "recovery.key_backup_restore",
            "identity.cross_signing_setup",
        ] {
            assert!(
                workflows
                    .iter()
                    .any(|w| w.id == id && w.stage == WorkflowStage::ClientReady),
                "expected {id} to be client-ready"
            );
        }
    }
}
