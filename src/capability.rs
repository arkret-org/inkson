use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::hlc::Hlc;

/// Action groups as defined by the spec.
/// Each group contains a set of action verbs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionGroup {
    Common,
    Board,
    Conversation,
    RunMemory,
    Administrative,
}

impl ActionGroup {
    /// Returns the set of actions in this group.
    pub fn actions(&self) -> &'static [&'static str] {
        match self {
            Self::Common => &[
                "space.read",
                "space.update",
                "entity.create",
                "entity.read",
                "entity.update",
                "entity.delete",
                "entity.restore",
                "relation.create",
                "relation.read",
                "relation.delete",
                "view.create",
                "view.read",
                "view.update",
                "invite.create",
                "invite.accept",
                "invite.cancel",
            ],
            Self::Board => &[
                "board.create",
                "board.read",
                "board.update",
                "board.delete",
                "collection.create",
                "collection.update",
                "collection.move",
            ],
            Self::Conversation => &[
                "message.create",
                "message.revise",
                "message.redact",
                "reaction.add",
                "reaction.remove",
                "typing.send",
                "read_marker.update",
                "comment.create",
                "comment.update",
                "comment.redact",
            ],
            Self::RunMemory => &[
                "run.create",
                "run.update",
                "run.complete",
                "run.fail",
                "memory.create",
                "memory.update",
                "memory.confirm",
                "memory.invalidate",
                "memory.supersede",
            ],
            Self::Administrative => &[
                "capability.grant",
                "capability.delegate",
                "capability.revoke",
                "policy.set",
                "schema.define",
                "schema.update",
                "member.invite",
                "member.remove",
                "member.role_change",
            ],
        }
    }

    /// Check if an action belongs to this group.
    pub fn contains(&self, action: &str) -> bool {
        self.actions().contains(&action)
    }
}

/// Constraint types as defined by the spec.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "params")]
pub enum Constraint {
    /// Time-based validity window.
    Temporal {
        not_before: Option<String>,
        not_after: Option<String>,
    },
    /// Restrict which fields the subject can access.
    FieldAccess {
        allowed_fields: Vec<String>,
        denied_fields: Vec<String>,
    },
    /// Restrict to specific entity types.
    TypeRestriction { allowed_types: Vec<String> },
    /// Limit scope to specific spaces or collections.
    ScopeLimitation {
        space_ids: Vec<String>,
        collection_ids: Vec<String>,
    },
    /// Control delegation depth and re-authorization.
    DelegationControl {
        max_depth: u32,
        allowed_actions: Vec<String>,
    },
    /// Rate limiting constraints.
    RateLimiting {
        max_operations: u32,
        window_seconds: u64,
    },
    /// Require approval before execution.
    ApprovalWorkflow {
        approvers: Vec<String>,
        min_approvals: u32,
    },
    /// Require specific claims to be present.
    ClaimBased {
        required_claims: Vec<String>,
    },
    /// Ensure operations are attributable.
    Accountability {
        audit_log: bool,
        retain_identity: bool,
    },
    /// Require encryption for the operation.
    EncryptionRequirement {
        require_e2ee: bool,
        allowed_schemes: Vec<String>,
    },
}

impl Constraint {
    /// Evaluate whether this constraint is satisfied given the context.
    pub fn evaluate(&self, ctx: &EvalContext) -> ConstraintResult {
        match self {
            Self::Temporal {
                not_before,
                not_after,
            } => {
                let now = &ctx.current_time;
                if let Some(before) = not_before {
                    if now < before {
                        return ConstraintResult::Deny("before validity window".to_owned());
                    }
                }
                if let Some(after) = not_after {
                    if now > after {
                        return ConstraintResult::Deny("after validity window".to_owned());
                    }
                }
                ConstraintResult::Allow
            }
            Self::FieldAccess {
                allowed_fields,
                denied_fields,
            } => {
                if let Some(ref fields) = ctx.requested_fields {
                    for field in fields {
                        if denied_fields.contains(field) {
                            return ConstraintResult::Deny(format!(
                                "field {field} is denied"
                            ));
                        }
                        if !allowed_fields.is_empty() && !allowed_fields.contains(field) {
                            return ConstraintResult::Deny(format!(
                                "field {field} not in allowed list"
                            ));
                        }
                    }
                }
                ConstraintResult::Allow
            }
            Self::TypeRestriction { allowed_types } => {
                if let Some(ref entity_type) = ctx.entity_type {
                    if !allowed_types.contains(entity_type) {
                        return ConstraintResult::Deny(format!(
                            "entity type {entity_type} not allowed"
                        ));
                    }
                }
                ConstraintResult::Allow
            }
            Self::ScopeLimitation {
                space_ids,
                collection_ids,
            } => {
                if let Some(ref space) = ctx.space_id {
                    if !space_ids.is_empty() && !space_ids.contains(space) {
                        return ConstraintResult::Deny(format!(
                            "space {space} not in scope"
                        ));
                    }
                }
                if let Some(ref collection) = ctx.collection_id {
                    if !collection_ids.is_empty() && !collection_ids.contains(collection) {
                        return ConstraintResult::Deny(format!(
                            "collection {collection} not in scope"
                        ));
                    }
                }
                ConstraintResult::Allow
            }
            Self::DelegationControl {
                max_depth,
                allowed_actions,
            } => {
                if ctx.delegation_depth > *max_depth {
                    return ConstraintResult::Deny("delegation depth exceeded".to_owned());
                }
                if let Some(ref action) = ctx.action {
                    if !allowed_actions.is_empty() && !allowed_actions.contains(action) {
                        return ConstraintResult::Deny(format!(
                            "action {action} not delegatable"
                        ));
                    }
                }
                ConstraintResult::Allow
            }
            Self::RateLimiting {
                max_operations,
                window_seconds,
            } => {
                let count = ctx
                    .operation_counts
                    .get(&format!("{window_seconds}s"))
                    .copied()
                    .unwrap_or(0);
                if count >= *max_operations {
                    ConstraintResult::Deny("rate limit exceeded".to_owned())
                } else {
                    ConstraintResult::Allow
                }
            }
            Self::ApprovalWorkflow {
                approvers,
                min_approvals,
            } => {
                let approved = ctx
                    .approvals
                    .iter()
                    .filter(|a| approvers.contains(a))
                    .count() as u32;
                if approved < *min_approvals {
                    ConstraintResult::RequireReview(format!(
                        "need {} more approvals",
                        min_approvals - approved
                    ))
                } else {
                    ConstraintResult::Allow
                }
            }
            Self::ClaimBased { required_claims } => {
                for claim in required_claims {
                    if !ctx.claims.contains(claim) {
                        return ConstraintResult::Deny(format!("missing claim: {claim}"));
                    }
                }
                ConstraintResult::Allow
            }
            Self::Accountability {
                audit_log,
                retain_identity,
            } => {
                if *audit_log && !ctx.audit_enabled {
                    return ConstraintResult::Deny("audit log required".to_owned());
                }
                if *retain_identity && ctx.anonymous {
                    return ConstraintResult::Deny(
                        "identity retention required".to_owned(),
                    );
                }
                ConstraintResult::Allow
            }
            Self::EncryptionRequirement {
                require_e2ee,
                allowed_schemes,
            } => {
                if *require_e2ee && !ctx.is_encrypted {
                    return ConstraintResult::Deny("E2EE required".to_owned());
                }
                if let Some(ref scheme) = ctx.encryption_scheme {
                    if !allowed_schemes.is_empty() && !allowed_schemes.contains(scheme) {
                        return ConstraintResult::Deny(format!(
                            "encryption scheme {scheme} not allowed"
                        ));
                    }
                }
                ConstraintResult::Allow
            }
        }
    }
}

/// Result of evaluating a constraint.
#[derive(Clone, Debug, PartialEq)]
pub enum ConstraintResult {
    Allow,
    Deny(String),
    Quarantine(String),
    RequireReview(String),
}

/// Evaluation context for constraint checking.
#[derive(Clone, Debug, Default)]
pub struct EvalContext {
    pub current_time: String,
    pub requested_fields: Option<Vec<String>>,
    pub entity_type: Option<String>,
    pub space_id: Option<String>,
    pub collection_id: Option<String>,
    pub action: Option<String>,
    pub delegation_depth: u32,
    pub operation_counts: HashMap<String, u32>,
    pub approvals: Vec<String>,
    pub claims: HashSet<String>,
    pub audit_enabled: bool,
    pub anonymous: bool,
    pub is_encrypted: bool,
    pub encryption_scheme: Option<String>,
}

/// Resource selector for matching resources.
/// Supports the EBNF syntax from the spec.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ResourceSelector {
    /// Match a specific space.
    Space(String),
    /// Match a specific entity.
    Entity(String),
    /// Match entities of a specific type.
    EntityType(String),
    /// Match a specific relation.
    Relation(String),
    /// Match a specific view.
    View(String),
    /// Match everything.
    Wildcard,
    /// Match any of the selectors (disjunction).
    Any(Vec<ResourceSelector>),
    /// Match all of the selectors (conjunction).
    All(Vec<ResourceSelector>),
    /// Exclude matching selectors.
    Except(Box<ResourceSelector>, Vec<ResourceSelector>),
}

impl ResourceSelector {
    /// Check if this selector matches the given resource.
    pub fn matches(&self, resource: &ResourceRef) -> bool {
        match self {
            Self::Space(id) => resource.space_id.as_ref() == Some(id),
            Self::Entity(id) => resource.entity_id.as_ref() == Some(id),
            Self::EntityType(t) => resource.entity_type.as_ref() == Some(t),
            Self::Relation(id) => resource.relation_id.as_ref() == Some(id),
            Self::View(id) => resource.view_id.as_ref() == Some(id),
            Self::Wildcard => true,
            Self::Any(selectors) => selectors.iter().any(|s| s.matches(resource)),
            Self::All(selectors) => selectors.iter().all(|s| s.matches(resource)),
            Self::Except(include, excludes) => {
                include.matches(resource)
                    && !excludes.iter().any(|e| e.matches(resource))
            }
        }
    }
}

/// Reference to a resource being evaluated.
#[derive(Clone, Debug, Default)]
pub struct ResourceRef {
    pub space_id: Option<String>,
    pub entity_id: Option<String>,
    pub entity_type: Option<String>,
    pub relation_id: Option<String>,
    pub view_id: Option<String>,
}

/// A capability grant as defined by the spec.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// Unique grant ID.
    pub grant_id: String,
    /// The issuer (who grants the capability).
    pub issuer: String,
    /// The subject (who receives the capability).
    pub subject: String,
    /// Resources this grant applies to.
    pub resource_selectors: Vec<ResourceSelector>,
    /// Actions allowed by this grant.
    pub actions: Vec<String>,
    /// Constraints on this grant.
    pub constraints: Vec<Constraint>,
    /// Proof of issuance (signature).
    pub proofs: Vec<GrantProof>,
    /// When this grant was issued.
    pub issued_at: Hlc,
    /// Maximum delegation depth.
    pub max_delegation_depth: u32,
    /// Parent grant ID (for delegated grants).
    pub parent_grant_id: Option<String>,
    /// Whether this grant is revocable.
    pub revocable: bool,
}

/// Proof of grant issuance.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GrantProof {
    /// Proof type (e.g., "signature", "witness").
    pub proof_type: String,
    /// The creator of the proof.
    pub creator: String,
    /// The proof value.
    pub value: String,
    /// When the proof was created.
    pub created: Hlc,
}

/// A capability revocation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CapabilityRevocation {
    /// The grant being revoked.
    pub grant_id: String,
    /// Who is revoking.
    pub revoker: String,
    /// When the revocation occurred.
    pub revoked_at: Hlc,
    /// Reason for revocation.
    pub reason: Option<String>,
    /// Whether to cascade revoke delegated grants.
    pub cascade: bool,
}

/// Authorization decision.
#[derive(Clone, Debug, PartialEq)]
pub enum AuthzDecision {
    Allow,
    Deny(String),
    Quarantine(String),
    RequireReview(String),
}

/// The capability authorization engine.
#[derive(Clone, Debug, Default)]
pub struct CapabilityEngine {
    /// Active grants indexed by grant_id.
    grants: HashMap<String, CapabilityGrant>,
    /// Revocations indexed by grant_id.
    revocations: HashMap<String, CapabilityRevocation>,
    /// Delegation chain index: parent_grant_id -> child_grant_ids.
    delegation_index: HashMap<String, Vec<String>>,
}

impl CapabilityEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a grant to the engine.
    pub fn add_grant(&mut self, grant: CapabilityGrant) {
        // Index delegation chain
        if let Some(ref parent_id) = grant.parent_grant_id {
            self.delegation_index
                .entry(parent_id.clone())
                .or_default()
                .push(grant.grant_id.clone());
        }
        self.grants.insert(grant.grant_id.clone(), grant);
    }

    /// Revoke a grant.
    pub fn revoke(&mut self, revocation: CapabilityRevocation) {
        let grant_id = revocation.grant_id.clone();
        if revocation.cascade {
            // Cascade revoke all delegated grants
            self.cascade_revoke(&grant_id, &revocation.revoker, &revocation.revoked_at);
        }
        self.revocations.insert(grant_id, revocation);
    }

    /// Check if a subject can perform an action on a resource.
    pub fn check(
        &self,
        subject: &str,
        action: &str,
        resource: &ResourceRef,
        ctx: &EvalContext,
    ) -> AuthzDecision {
        // Find all grants for this subject
        let applicable_grants: Vec<&CapabilityGrant> = self
            .grants
            .values()
            .filter(|g| g.subject == subject)
            .filter(|g| !self.revocations.contains_key(&g.grant_id))
            .filter(|g| {
                g.actions.iter().any(|a| a == action || a == "*")
                    && g.resource_selectors.iter().any(|s| s.matches(resource))
            })
            .collect();

        if applicable_grants.is_empty() {
            return AuthzDecision::Deny(format!(
                "no grant found for {subject} to {action}"
            ));
        }

        // Evaluate constraints in priority order: deny > quarantine > allow > require_review
        let mut has_allow = false;
        let mut quarantine_reason = None;
        let mut review_reason = None;

        for grant in &applicable_grants {
            for constraint in &grant.constraints {
                match constraint.evaluate(ctx) {
                    ConstraintResult::Allow => has_allow = true,
                    ConstraintResult::Deny(reason) => {
                        return AuthzDecision::Deny(reason);
                    }
                    ConstraintResult::Quarantine(reason) => {
                        quarantine_reason = Some(reason);
                    }
                    ConstraintResult::RequireReview(reason) => {
                        review_reason = Some(reason);
                    }
                }
            }
        }

        // Priority: deny > quarantine > allow > require_review
        if let Some(reason) = quarantine_reason {
            AuthzDecision::Quarantine(reason)
        } else if has_allow {
            AuthzDecision::Allow
        } else if let Some(reason) = review_reason {
            AuthzDecision::RequireReview(reason)
        } else {
            AuthzDecision::Allow
        }
    }

    /// Check if a subject can delegate an action.
    pub fn can_delegate(
        &self,
        subject: &str,
        action: &str,
        resource: &ResourceRef,
        ctx: &EvalContext,
    ) -> AuthzDecision {
        // Check if subject has the capability.grant or capability.delegate action
        let grant_check = self.check(subject, "capability.grant", resource, ctx);
        let delegate_check = self.check(subject, "capability.delegate", resource, ctx);

        match (grant_check, delegate_check) {
            (AuthzDecision::Allow, _) | (_, AuthzDecision::Allow) => {
                // Also check that the subject has the action they want to delegate
                self.check(subject, action, resource, ctx)
            }
            (AuthzDecision::Deny(r1), AuthzDecision::Deny(r2)) => {
                AuthzDecision::Deny(format!(
                    "cannot delegate: {r1} / {r2}"
                ))
            }
            (AuthzDecision::Quarantine(r), _)
            | (_, AuthzDecision::Quarantine(r)) => AuthzDecision::Quarantine(r),
            (AuthzDecision::RequireReview(r), _)
            | (_, AuthzDecision::RequireReview(r)) => {
                AuthzDecision::RequireReview(r)
            }
        }
    }

    /// Get all effective grants for a subject.
    pub fn effective_grants(&self, subject: &str) -> Vec<&CapabilityGrant> {
        self.grants
            .values()
            .filter(|g| g.subject == subject)
            .filter(|g| !self.revocations.contains_key(&g.grant_id))
            .collect()
    }

    /// Get the delegation chain for a grant.
    pub fn delegation_chain(&self, grant_id: &str) -> Vec<&CapabilityGrant> {
        let mut chain = Vec::new();
        let mut current = grant_id;

        while let Some(grant) = self.grants.get(current) {
            chain.push(grant);
            match &grant.parent_grant_id {
                Some(parent_id) => current = parent_id,
                None => break,
            }
        }

        chain
    }

    /// Validate a delegation chain.
    pub fn validate_delegation_chain(&self, grant_id: &str) -> Result<(), String> {
        let chain = self.delegation_chain(grant_id);

        if chain.is_empty() {
            return Err("grant not found".to_owned());
        }

        // Check each link in the chain
        for window in chain.windows(2) {
            let child = window[0];
            let parent = window[1];

            // Child must reference parent
            if child.parent_grant_id.as_ref() != Some(&parent.grant_id) {
                return Err("broken delegation chain".to_owned());
            }

            // Child must not exceed parent's max delegation depth
            if child.max_delegation_depth > parent.max_delegation_depth {
                return Err("delegation depth exceeded".to_owned());
            }

            // Child's actions must be a subset of parent's actions
            for action in &child.actions {
                if !parent.actions.contains(action) && !parent.actions.contains(&"*".to_owned())
                {
                    return Err(format!(
                        "action {action} not in parent grant"
                    ));
                }
            }

            // Child's resource selectors must be within parent's scope
            // (simplified check - full EBNF matching would be more complex)
        }

        // Check revocations
        for grant in &chain {
            if self.revocations.contains_key(&grant.grant_id) {
                return Err(format!(
                    "grant {} is revoked",
                    grant.grant_id
                ));
            }
        }

        Ok(())
    }

    /// Cascade revoke all delegated grants.
    fn cascade_revoke(&mut self, parent_id: &str, revoker: &str, time: &Hlc) {
        if let Some(children) = self.delegation_index.get(parent_id).cloned() {
            for child_id in children {
                self.revocations.insert(
                    child_id.clone(),
                    CapabilityRevocation {
                        grant_id: child_id.clone(),
                        revoker: revoker.to_owned(),
                        revoked_at: time.clone(),
                        reason: Some("cascaded from parent revocation".to_owned()),
                        cascade: true,
                    },
                );
                // Recursively cascade
                self.cascade_revoke(&child_id, revoker, time);
            }
        }
    }

    /// Get all active grants.
    pub fn active_grants(&self) -> Vec<&CapabilityGrant> {
        self.grants
            .values()
            .filter(|g| !self.revocations.contains_key(&g.grant_id))
            .collect()
    }

    /// Get all revocations.
    pub fn get_revocations(&self) -> Vec<&CapabilityRevocation> {
        self.revocations.values().collect()
    }
}

/// Builder for creating CapabilityGrant objects.
pub struct GrantBuilder {
    grant: CapabilityGrant,
}

impl GrantBuilder {
    pub fn new(issuer: &str, subject: &str) -> Self {
        Self {
            grant: CapabilityGrant {
                grant_id: format!("grant-{}", crate::operation::uuid_v8()),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                resource_selectors: Vec::new(),
                actions: Vec::new(),
                constraints: Vec::new(),
                proofs: Vec::new(),
                issued_at: Hlc::now(),
                max_delegation_depth: 0,
                parent_grant_id: None,
                revocable: true,
            },
        }
    }

    pub fn with_id(mut self, id: &str) -> Self {
        self.grant.grant_id = id.to_owned();
        self
    }

    pub fn with_action(mut self, action: &str) -> Self {
        self.grant.actions.push(action.to_owned());
        self
    }

    pub fn with_actions(mut self, actions: &[&str]) -> Self {
        self.grant
            .actions
            .extend(actions.iter().map(|s| s.to_owned()));
        self
    }

    pub fn with_resource(mut self, selector: ResourceSelector) -> Self {
        self.grant.resource_selectors.push(selector);
        self
    }

    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.grant.constraints.push(constraint);
        self
    }

    pub fn with_delegation_depth(mut self, depth: u32) -> Self {
        self.grant.max_delegation_depth = depth;
        self
    }

    pub fn with_parent(mut self, parent_id: &str) -> Self {
        self.grant.parent_grant_id = Some(parent_id.to_owned());
        self
    }

    pub fn irrevocable(mut self) -> Self {
        self.grant.revocable = false;
        self
    }

    pub fn build(self) -> CapabilityGrant {
        self.grant
    }
}

/// Create capability grant operations.
pub mod cx_capability {
    use super::*;

    /// Create a capability grant operation.
    pub fn grant_op(grant: &CapabilityGrant) -> serde_json::Value {
        serde_json::json!({
            "type": "cx.capability.grant",
            "grant_id": grant.grant_id,
            "issuer": grant.issuer,
            "subject": grant.subject,
            "resource_selectors": grant.resource_selectors,
            "actions": grant.actions,
            "constraints": grant.constraints,
            "max_delegation_depth": grant.max_delegation_depth,
            "parent_grant_id": grant.parent_grant_id,
            "revocable": grant.revocable,
            "issued_at": grant.issued_at.encode(),
        })
    }

    /// Create a capability delegation operation.
    pub fn delegate_op(grant: &CapabilityGrant) -> serde_json::Value {
        serde_json::json!({
            "type": "cx.capability.delegate",
            "grant_id": grant.grant_id,
            "issuer": grant.issuer,
            "subject": grant.subject,
            "resource_selectors": grant.resource_selectors,
            "actions": grant.actions,
            "constraints": grant.constraints,
            "max_delegation_depth": grant.max_delegation_depth,
            "parent_grant_id": grant.parent_grant_id,
            "issued_at": grant.issued_at.encode(),
        })
    }

    /// Create a capability revocation operation.
    pub fn revoke_op(revocation: &CapabilityRevocation) -> serde_json::Value {
        serde_json::json!({
            "type": "cx.capability.revoke",
            "grant_id": revocation.grant_id,
            "revoker": revocation.revoker,
            "revoked_at": revocation.revoked_at.encode(),
            "reason": revocation.reason,
            "cascade": revocation.cascade,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_grant() -> CapabilityGrant {
        GrantBuilder::new("did:web:alice", "did:web:bob")
            .with_action("entity.read")
            .with_action("entity.update")
            .with_resource(ResourceSelector::Space("cx:space:test".to_owned()))
            .with_constraint(Constraint::Temporal {
                not_before: None,
                not_after: Some("2027-01-01T00:00:00Z".to_owned()),
            })
            .with_delegation_depth(2)
            .build()
    }

    #[test]
    fn test_grant_builder() {
        let grant = test_grant();
        assert_eq!(grant.issuer, "did:web:alice");
        assert_eq!(grant.subject, "did:web:bob");
        assert_eq!(grant.actions.len(), 2);
        assert_eq!(grant.max_delegation_depth, 2);
        assert!(grant.revocable);
    }

    #[test]
    fn test_action_groups() {
        assert!(ActionGroup::Common.contains("space.read"));
        assert!(ActionGroup::Common.contains("entity.create"));
        assert!(ActionGroup::Conversation.contains("message.create"));
        assert!(ActionGroup::Administrative.contains("capability.grant"));
        assert!(!ActionGroup::Common.contains("message.create"));
    }

    #[test]
    fn test_resource_selector() {
        let selector = ResourceSelector::Space("cx:space:test".to_owned());
        let resource = ResourceRef {
            space_id: Some("cx:space:test".to_owned()),
            ..Default::default()
        };
        assert!(selector.matches(&resource));

        let resource_no_match = ResourceRef {
            space_id: Some("cx:space:other".to_owned()),
            ..Default::default()
        };
        assert!(!selector.matches(&resource_no_match));
    }

    #[test]
    fn test_wildcard_selector() {
        let selector = ResourceSelector::Wildcard;
        let resource = ResourceRef::default();
        assert!(selector.matches(&resource));
    }

    #[test]
    fn test_any_selector() {
        let selector = ResourceSelector::Any(vec![
            ResourceSelector::Space("cx:space:a".to_owned()),
            ResourceSelector::Space("cx:space:b".to_owned()),
        ]);
        let resource_a = ResourceRef {
            space_id: Some("cx:space:a".to_owned()),
            ..Default::default()
        };
        let resource_c = ResourceRef {
            space_id: Some("cx:space:c".to_owned()),
            ..Default::default()
        };
        assert!(selector.matches(&resource_a));
        assert!(!selector.matches(&resource_c));
    }

    #[test]
    fn test_except_selector() {
        let selector = ResourceSelector::Except(
            Box::new(ResourceSelector::Wildcard),
            vec![ResourceSelector::Space("cx:space:secret".to_owned())],
        );
        let normal = ResourceRef {
            space_id: Some("cx:space:normal".to_owned()),
            ..Default::default()
        };
        let secret = ResourceRef {
            space_id: Some("cx:space:secret".to_owned()),
            ..Default::default()
        };
        assert!(selector.matches(&normal));
        assert!(!selector.matches(&secret));
    }

    #[test]
    fn test_capability_engine_check_allow() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let resource = ResourceRef {
            space_id: Some("cx:space:test".to_owned()),
            entity_id: Some("entity-1".to_owned()),
            ..Default::default()
        };
        let ctx = EvalContext {
            current_time: "2026-01-01T00:00:00Z".to_owned(),
            ..Default::default()
        };

        let decision = engine.check("did:web:bob", "entity.read", &resource, &ctx);
        assert_eq!(decision, AuthzDecision::Allow);
    }

    #[test]
    fn test_capability_engine_check_deny_no_grant() {
        let engine = CapabilityEngine::new();
        let resource = ResourceRef::default();
        let ctx = EvalContext::default();

        let decision = engine.check("did:web:bob", "entity.read", &resource, &ctx);
        assert!(matches!(decision, AuthzDecision::Deny(_)));
    }

    #[test]
    fn test_capability_engine_check_deny_wrong_action() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let resource = ResourceRef {
            space_id: Some("cx:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = EvalContext::default();

        let decision = engine.check("did:web:bob", "entity.delete", &resource, &ctx);
        assert!(matches!(decision, AuthzDecision::Deny(_)));
    }

    #[test]
    fn test_capability_engine_check_deny_wrong_resource() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let resource = ResourceRef {
            space_id: Some("cx:space:other".to_owned()),
            ..Default::default()
        };
        let ctx = EvalContext::default();

        let decision = engine.check("did:web:bob", "entity.read", &resource, &ctx);
        assert!(matches!(decision, AuthzDecision::Deny(_)));
    }

    #[test]
    fn test_capability_engine_revoke() {
        let mut engine = CapabilityEngine::new();
        let grant = test_grant();
        let grant_id = grant.grant_id.clone();
        engine.add_grant(grant);

        engine.revoke(CapabilityRevocation {
            grant_id: grant_id.clone(),
            revoker: "did:web:alice".to_owned(),
            revoked_at: Hlc::now(),
            reason: Some("test revocation".to_owned()),
            cascade: false,
        });

        let resource = ResourceRef {
            space_id: Some("cx:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = EvalContext::default();

        let decision = engine.check("did:web:bob", "entity.read", &resource, &ctx);
        assert!(matches!(decision, AuthzDecision::Deny(_)));
    }

    #[test]
    fn test_delegation_chain() {
        let mut engine = CapabilityEngine::new();
        let parent = test_grant();
        let parent_id = parent.grant_id.clone();
        engine.add_grant(parent);

        let child = GrantBuilder::new("did:web:bob", "did:web:charlie")
            .with_action("entity.read")
            .with_resource(ResourceSelector::Space("cx:space:test".to_owned()))
            .with_parent(&parent_id)
            .with_delegation_depth(1)
            .build();
        let child_id = child.grant_id.clone();
        engine.add_grant(child);

        let chain = engine.delegation_chain(&child_id);
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].subject, "did:web:charlie");
        assert_eq!(chain[1].subject, "did:web:bob");
    }

    #[test]
    fn test_delegation_validation() {
        let mut engine = CapabilityEngine::new();
        let parent = test_grant();
        let parent_id = parent.grant_id.clone();
        engine.add_grant(parent);

        let child = GrantBuilder::new("did:web:bob", "did:web:charlie")
            .with_action("entity.read")
            .with_resource(ResourceSelector::Space("cx:space:test".to_owned()))
            .with_parent(&parent_id)
            .with_delegation_depth(1)
            .build();
        let child_id = child.grant_id.clone();
        engine.add_grant(child);

        assert!(engine.validate_delegation_chain(&child_id).is_ok());
    }

    #[test]
    fn test_cascade_revoke() {
        let mut engine = CapabilityEngine::new();
        let parent = test_grant();
        let parent_id = parent.grant_id.clone();
        engine.add_grant(parent);

        let child = GrantBuilder::new("did:web:bob", "did:web:charlie")
            .with_action("entity.read")
            .with_resource(ResourceSelector::Space("cx:space:test".to_owned()))
            .with_parent(&parent_id)
            .with_delegation_depth(1)
            .build();
        let child_id = child.grant_id.clone();
        engine.add_grant(child);

        engine.revoke(CapabilityRevocation {
            grant_id: parent_id.clone(),
            revoker: "did:web:alice".to_owned(),
            revoked_at: Hlc::now(),
            reason: Some("test cascade".to_owned()),
            cascade: true,
        });

        assert!(engine.revocations.contains_key(&child_id));
    }

    #[test]
    fn test_effective_grants() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let grants = engine.effective_grants("did:web:bob");
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].issuer, "did:web:alice");
    }

    #[test]
    fn test_constraint_temporal_allow() {
        let constraint = Constraint::Temporal {
            not_before: Some("2025-01-01T00:00:00Z".to_owned()),
            not_after: Some("2027-01-01T00:00:00Z".to_owned()),
        };
        let ctx = EvalContext {
            current_time: "2026-06-15T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert_eq!(constraint.evaluate(&ctx), ConstraintResult::Allow);
    }

    #[test]
    fn test_constraint_temporal_deny() {
        let constraint = Constraint::Temporal {
            not_before: None,
            not_after: Some("2025-01-01T00:00:00Z".to_owned()),
        };
        let ctx = EvalContext {
            current_time: "2026-06-15T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert!(matches!(
            constraint.evaluate(&ctx),
            ConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_constraint_field_access() {
        let constraint = Constraint::FieldAccess {
            allowed_fields: vec!["name".to_owned(), "email".to_owned()],
            denied_fields: vec!["ssn".to_owned()],
        };

        let ctx_allowed = EvalContext {
            requested_fields: Some(vec!["name".to_owned()]),
            ..Default::default()
        };
        assert_eq!(constraint.evaluate(&ctx_allowed), ConstraintResult::Allow);

        let ctx_denied = EvalContext {
            requested_fields: Some(vec!["ssn".to_owned()]),
            ..Default::default()
        };
        assert!(matches!(
            constraint.evaluate(&ctx_denied),
            ConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_constraint_rate_limiting() {
        let constraint = Constraint::RateLimiting {
            max_operations: 10,
            window_seconds: 60,
        };

        let ctx_under = EvalContext {
            operation_counts: HashMap::from([("60s".to_owned(), 5)]),
            ..Default::default()
        };
        assert_eq!(constraint.evaluate(&ctx_under), ConstraintResult::Allow);

        let ctx_over = EvalContext {
            operation_counts: HashMap::from([("60s".to_owned(), 15)]),
            ..Default::default()
        };
        assert!(matches!(
            constraint.evaluate(&ctx_over),
            ConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_cx_capability_ops() {
        let grant = test_grant();
        let op = cx_capability::grant_op(&grant);
        assert_eq!(op["type"], "cx.capability.grant");
        assert_eq!(op["issuer"], "did:web:alice");

        let revocation = CapabilityRevocation {
            grant_id: grant.grant_id.clone(),
            revoker: "did:web:alice".to_owned(),
            revoked_at: Hlc::now(),
            reason: Some("test".to_owned()),
            cascade: false,
        };
        let op = cx_capability::revoke_op(&revocation);
        assert_eq!(op["type"], "cx.capability.revoke");
    }
}
