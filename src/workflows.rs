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
            server_dependency: "POST /_arkret/gate/account/session-grants",
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
            name: "Recovery Key (24 words) backup upload",
            stage: WorkflowStage::ClientReady,
            client_surface: "Recovery panel: 24-word Recovery Key + Argon2id KDF + XChaCha20-Poly1305 AEAD",
            server_dependency: "PUT /_arkret/self/keys/backups/{backup_id} (ck.schema.key_backup.v1 envelope)",
        },
        ClientWorkflow {
            id: "recovery.key_backup_restore",
            name: "Encrypted backup history",
            stage: WorkflowStage::ClientReady,
            client_surface: "Recovery panel: backup history timestamp summary and latest-backup status",
            server_dependency: "GET /_arkret/self/keys/backups",
        },
        ClientWorkflow {
            id: "identity.cross_signing_setup",
            name: "Cross-signing bootstrap and reset",
            stage: WorkflowStage::ClientReady,
            client_surface: "Verify Device panel: renders CrossSigningSetupPlan steps + canonical events",
            server_dependency: "Needs ck.cross_signing.publish / ck.cross_signing.reset / ck.device.authorize acceptance endpoints",
        },
        ClientWorkflow {
            id: "space.discovery",
            name: "Discover and resolve public realms",
            stage: WorkflowStage::Supported,
            client_surface: "Directory panel",
            server_dependency: "POST /_arkret/find/directory/search-realms and resolve-realm",
        },
        ClientWorkflow {
            id: "space.create",
            name: "Create space",
            stage: WorkflowStage::ClientReady,
            client_surface: "New Space setup (`views/setup.rs` → `api.create_space`)",
            server_dependency: "F-SPACE-LIFECYCLE-1 (2026-05-19): create-space form wired through views/setup.rs:605 (`api.create_space(actor, title, summary, discoverability, join_rule, history_visibility, invitees, plaintext_services)`). Server still owns policy template + retention rule defaults, but the client-side bootstrap path is complete and round-trips through `state_store.save_realm_tree_projection` on success.",
        },
        ClientWorkflow {
            id: "realm.membership",
            name: "Invite, add, remove, and kick members",
            stage: WorkflowStage::Blocked,
            client_surface: "Realm setup + Realm Admin membership",
            server_dependency: "Missing invite/member state operations, authz checks, MLS Welcome/Commit delivery, and removal epoch rotation",
        },
        ClientWorkflow {
            id: "realm.delete",
            name: "Leave, archive, and destroy Realm",
            stage: WorkflowStage::ClientReady,
            client_surface: "Realm setup + Realm Admin destructive strands (`views/realm_admin.rs` Leave + Destroy buttons)",
            server_dependency: "F-REALM-LIFECYCLE-1 (2026-05-19): leave-realm is wired through views/realm_admin.rs (`api.leave_realm(realm_id)` + local cache reset); destroy-realm is wired through views/realm_admin.rs (`api.destroy_realm(realm_id)`). Both surfaces report success/failure via `status_msg`; Realm destroy retention enforcement remains server-side.",
        },
        ClientWorkflow {
            id: "message.create",
            name: "Plaintext and local encrypted compose",
            stage: WorkflowStage::ClientReady,
            client_surface: "Chat composer",
            server_dependency: "Needs real web MLS crypto store and client-side signed commit path for offline queue",
        },
        ClientWorkflow {
            id: "moderation.report",
            name: "Moderation report",
            stage: WorkflowStage::Supported,
            client_surface: "Report / Queue",
            server_dependency: "POST /_arkret/self/moderation/report",
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
        // F-REALM-LIFECYCLE-1 (2026-05-19): realm.delete moved from
        // Blocked → ClientReady because the corresponding UI
        // wiring (`views/setup.rs` create strand + `views/realm_admin.rs`
        // Leave / Destroy buttons) was already shipped. Explicitly negate
        // it here so a future regression that reintroduces the gap fails
        // this test.
        assert!(
            !blocked.iter().any(|workflow| workflow.id == "space.create"),
            "space.create should be ClientReady — UI wired via views/setup.rs:605 (`api.create_space`)"
        );
        assert!(
            !blocked.iter().any(|workflow| workflow.id == "realm.delete"),
            "realm.delete should be ClientReady — UI wired via views/realm_admin.rs Leave + Destroy buttons"
        );
        // realm.membership remains Blocked: MLS Welcome / Commit
        // delivery + removal epoch rotation are still server gaps.
        assert!(
            blocked
                .iter()
                .any(|workflow| workflow.id == "realm.membership")
        );
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
    fn key_backup_strands_are_client_ready() {
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
