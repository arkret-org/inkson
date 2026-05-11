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
pub struct ProductWorkflow {
    pub id: &'static str,
    pub name: &'static str,
    pub stage: WorkflowStage,
    pub client_surface: &'static str,
    pub server_dependency: &'static str,
}

pub fn production_release_workflows() -> Vec<ProductWorkflow> {
    vec![
        ProductWorkflow {
            id: "account.dev_bootstrap",
            name: "Development account bootstrap",
            stage: WorkflowStage::Supported,
            client_surface: "Settings + Connect",
            server_dependency: "POST /api/v1/auth/dev-login",
        },
        ProductWorkflow {
            id: "account.registration",
            name: "Production registration",
            stage: WorkflowStage::Blocked,
            client_surface: "Product panel basic registration",
            server_dependency: "Needs DID proof challenge, recovery policy, and account/device verification before production",
        },
        ProductWorkflow {
            id: "account.password_passkey_login",
            name: "Password/passkey login",
            stage: WorkflowStage::Blocked,
            client_surface: "Release panel gap",
            server_dependency: "Needs coauth-owned OIDC/passkey challenge, code/token exchange, soland session-grant handoff, and chime push registration grant reuse",
        },
        ProductWorkflow {
            id: "identity.device_verification",
            name: "Device verification",
            stage: WorkflowStage::ClientReady,
            client_surface: "Devices panel + SDK device primitives",
            server_dependency: "Needs persisted device trust, cross-signing, SAS/QR verification, and revocation endpoints",
        },
        ProductWorkflow {
            id: "space.discovery",
            name: "Discover and resolve public spaces",
            stage: WorkflowStage::Supported,
            client_surface: "Directory panel",
            server_dependency: "POST /api/v1/directory/search-spaces and resolve-space",
        },
        ProductWorkflow {
            id: "space.create",
            name: "Create space",
            stage: WorkflowStage::Blocked,
            client_surface: "Product panel basic create Space",
            server_dependency: "Needs metadata edit, policy templates, signed operation templates, and retention rules",
        },
        ProductWorkflow {
            id: "space.membership",
            name: "Invite, add, remove, and kick members",
            stage: WorkflowStage::Blocked,
            client_surface: "Product panel basic add/remove member",
            server_dependency: "Missing invite/member state operations, authz checks, MLS Welcome/Commit delivery, and removal epoch rotation",
        },
        ProductWorkflow {
            id: "space.delete",
            name: "Leave, archive, and delete space",
            stage: WorkflowStage::Blocked,
            client_surface: "Product panel basic delete Space",
            server_dependency: "Needs leave/archive UX, tombstone policy, and history retention enforcement",
        },
        ProductWorkflow {
            id: "message.create",
            name: "Plaintext and local encrypted compose",
            stage: WorkflowStage::ClientReady,
            client_surface: "Timeline composer + Product panel canonical send",
            server_dependency: "Needs real web MLS crypto store and client-side signed commit path for offline queue",
        },
        ProductWorkflow {
            id: "moderation.report",
            name: "Moderation report",
            stage: WorkflowStage::Supported,
            client_surface: "Report / Queue",
            server_dependency: "POST /api/v1/moderation/report",
        },
        ProductWorkflow {
            id: "release.packaging",
            name: "Release packaging and upgrade",
            stage: WorkflowStage::Blocked,
            client_surface: "Release panel gap",
            server_dependency: "Missing signed builds, updater, crash telemetry, release channels, and production configuration",
        },
    ]
}

pub fn blocked_release_workflows() -> Vec<ProductWorkflow> {
    production_release_workflows()
        .into_iter()
        .filter(|workflow| workflow.stage == WorkflowStage::Blocked)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_workflow_inventory_keeps_major_product_gaps_visible() {
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
}
