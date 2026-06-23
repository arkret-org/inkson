use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Action groups as defined by the spec.
/// Each group contains a set of action verbs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionGroup {
    Common,
    SpaceStrand,
    Conversation,
    Morph,
    Administrative,
}

impl ActionGroup {
    /// Returns the set of actions in this group.
    ///
    /// Registered action names are the **canonical, fully-qualified** forms
    /// from the spec `capability-action-registry.json` (always `ck.`
    /// prefixed). Entries that are yougen-local UI grouping placeholders are
    /// marked inline and must not be written into capability grants.
    /// F-CAP-FIX-1 (2026-05-19) brought this table in line with spec
    /// fixtures, which write `actions: ["ck.strand.read", ...]` — under the
    /// previous bare-name table a wire-shaped grant from any conforming
    /// server would have failed `CapabilityEngine::check`'s string
    /// comparison and produced false denies.
    pub fn actions(&self) -> &'static [&'static str] {
        match self {
            Self::Common => &[
                "ck.realm.update",
                "ck.space.create",
                "ck.space.update",
                "ck.space.archive",
                "ck.space.restore",
                "ck.space.tombstone",
                "ck.strand.create",
                "ck.strand.read",
                "ck.strand.update",
                "ck.strand.archive",
                "ck.strand.restore",
                "ck.relation.create",
                "ck.relation.tombstone",
                "ck.view.create",
                "ck.view.update",
                "ck.invite.create",
                "ck.invite.accept",
                "ck.invite.cancel",
            ],
            Self::SpaceStrand => &[
                "ck.strand.move",
                "ck.strand.reorder",
                // Per cokret-spec dc01ad7 the four
                // `strand.track.{enable,disable,update,set_primary}`
                // verbs were unified into a single `ck.strand.tracks.update`
                // capability covering all track mutations via a
                // `ck.patch.v1` JSON Patch against `Strand.tracks`.
                "ck.strand.tracks.update",
            ],
            Self::Conversation => &[
                "ck.message.create",
                "ck.message.revise",
                "ck.message.redact",
                "ck.reaction.add",
                "ck.reaction.remove",
                "ck.typing.broadcast",
                "ck.read_cursor.advance",
                // R14: `ck.comment.*` are not in capability-action-registry.json
                // (the registry has no comment action family). These remain
                // yougen-local UI grouping placeholders only.
                "ck.comment.create",
                "ck.comment.update",
                "ck.comment.redact",
            ],
            Self::Morph => &[
                "ck.morph.create",
                "ck.morph.read",
                "ck.morph.update",
                "ck.morph.archive",
                "ck.morph.restore",
                // R14: `ck.morph.tombstone` is not in
                // capability-action-registry.json; yougen-local UI grouping
                // placeholder only.
                "ck.morph.tombstone",
            ],
            Self::Administrative => &[
                "ck.capability.grant",
                "ck.capability.delegate",
                "ck.capability.revoke",
                "ck.policy.set",
                "ck.schema.define",
                "ck.schema.update",
                // R14: `ck.member.{invite,remove,role_change}` are not in
                // capability-action-registry.json. Member lifecycle is driven
                // by the `ck.circle.member.*` / `ck.invite.*` registry actions
                // and the `ck.member.state` FSM; these three remain
                // yougen-local UI grouping placeholders only.
                "ck.member.invite",
                "ck.member.remove",
                "ck.member.role_change",
            ],
        }
    }

    /// Check if an action belongs to this group.
    pub fn contains(&self, action: &str) -> bool {
        self.actions().contains(&action)
    }
}

/// UI-side capability constraints hydrated for local pre-gating.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "params")]
pub enum UiCapabilityConstraint {
    /// Time-based validity window. Spec uses the `not_before` / `expires_at`
    /// pair; `not_after` is a forbidden field name on the capability
    /// UiCapabilityConstraint wire form.
    Temporal {
        not_before: Option<String>,
        expires_at: Option<String>,
    },
    /// Restrict which fields the subject can access.
    FieldAccess {
        allowed_fields: Vec<String>,
        denied_fields: Vec<String>,
    },
    /// Restrict to specific object types or facets.
    TypeRestriction {
        allowed_object_types: Vec<String>,
        #[serde(default)]
        allowed_facets: Vec<String>,
    },
    /// Limit scope to specific Realm-owned Space containers.
    ScopeLimitation {
        space_ids: Vec<String>,
        #[serde(default)]
        space_container_ids: Vec<String>,
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
    ClaimBased { required_claims: Vec<String> },
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

impl UiCapabilityConstraint {
    /// Evaluate whether this UiCapabilityConstraint is satisfied given the context.
    pub fn evaluate(&self, ctx: &UiCapabilityEvalContext) -> UiConstraintResult {
        match self {
            Self::Temporal {
                not_before,
                expires_at,
            } => {
                let now = &ctx.current_time;
                if let Some(before) = not_before
                    && now < before
                {
                    return UiConstraintResult::Deny("before validity window".to_owned());
                }
                if let Some(after) = expires_at
                    && now > after
                {
                    return UiConstraintResult::Deny("after validity window".to_owned());
                }
                UiConstraintResult::Allow
            }
            Self::FieldAccess {
                allowed_fields,
                denied_fields,
            } => {
                if let Some(ref fields) = ctx.requested_fields {
                    for field in fields {
                        if denied_fields.contains(field) {
                            return UiConstraintResult::Deny(format!("field {field} is denied"));
                        }
                        if !allowed_fields.is_empty() && !allowed_fields.contains(field) {
                            return UiConstraintResult::Deny(format!(
                                "field {field} not in allowed list"
                            ));
                        }
                    }
                }
                UiConstraintResult::Allow
            }
            Self::TypeRestriction {
                allowed_object_types,
                allowed_facets,
            } => {
                if let Some(ref object_type) = ctx.object_type
                    && !allowed_object_types.contains(object_type)
                {
                    return UiConstraintResult::Deny(format!(
                        "object type {object_type} not allowed"
                    ));
                }
                if !allowed_facets.is_empty() {
                    for facet in allowed_facets {
                        if !ctx.facets.contains(facet) {
                            return UiConstraintResult::Deny(format!(
                                "facet {facet} not allowed or unavailable"
                            ));
                        }
                    }
                }
                UiConstraintResult::Allow
            }
            Self::ScopeLimitation {
                space_ids,
                space_container_ids,
            } => {
                if let Some(ref space) = ctx.space_id
                    && !space_ids.is_empty()
                    && !space_ids.contains(space)
                {
                    return UiConstraintResult::Deny(format!("space {space} not in scope"));
                }
                if let Some(ref container) = ctx.space_container_id
                    && !space_container_ids.is_empty()
                    && !space_container_ids.contains(container)
                {
                    return UiConstraintResult::Deny(format!(
                        "space container {container} not in scope"
                    ));
                }
                UiConstraintResult::Allow
            }
            Self::DelegationControl {
                max_depth,
                allowed_actions,
            } => {
                if ctx.delegation_depth > *max_depth {
                    return UiConstraintResult::Deny("delegation depth exceeded".to_owned());
                }
                if let Some(ref action) = ctx.action
                    && !allowed_actions.is_empty()
                    && !allowed_actions.contains(action)
                {
                    return UiConstraintResult::Deny(format!("action {action} not delegatable"));
                }
                UiConstraintResult::Allow
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
                    UiConstraintResult::Deny("rate limit exceeded".to_owned())
                } else {
                    UiConstraintResult::Allow
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
                    UiConstraintResult::RequireReview(format!(
                        "need {} more approvals",
                        min_approvals - approved
                    ))
                } else {
                    UiConstraintResult::Allow
                }
            }
            Self::ClaimBased { required_claims } => {
                for claim in required_claims {
                    if !ctx.claims.contains(claim) {
                        return UiConstraintResult::Deny(format!("missing claim: {claim}"));
                    }
                }
                UiConstraintResult::Allow
            }
            Self::Accountability {
                audit_log,
                retain_identity,
            } => {
                if *audit_log && !ctx.audit_enabled {
                    return UiConstraintResult::Deny("audit log required".to_owned());
                }
                if *retain_identity && ctx.anonymous {
                    return UiConstraintResult::Deny("identity retention required".to_owned());
                }
                UiConstraintResult::Allow
            }
            Self::EncryptionRequirement {
                require_e2ee,
                allowed_schemes,
            } => {
                if *require_e2ee && !ctx.is_encrypted {
                    return UiConstraintResult::Deny("E2EE required".to_owned());
                }
                if let Some(ref scheme) = ctx.encryption_scheme
                    && !allowed_schemes.is_empty()
                    && !allowed_schemes.contains(scheme)
                {
                    return UiConstraintResult::Deny(format!(
                        "encryption scheme {scheme} not allowed"
                    ));
                }
                UiConstraintResult::Allow
            }
        }
    }
}

/// Result of evaluating a UiCapabilityConstraint.
#[derive(Clone, Debug, PartialEq)]
pub enum UiConstraintResult {
    Allow,
    Deny(String),
    Quarantine(String),
    RequireReview(String),
}

/// Evaluation context for UiCapabilityConstraint checking.
#[derive(Clone, Debug, Default)]
pub struct UiCapabilityEvalContext {
    pub current_time: String,
    pub requested_fields: Option<Vec<String>>,
    pub object_type: Option<String>,
    pub facets: Vec<String>,
    pub space_id: Option<String>,
    pub space_container_id: Option<String>,
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

/// UI-side resource selector for matching resources.
/// Supports the EBNF syntax from the spec but is not the wire type.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum UiResourceSelector {
    /// Match a specific space.
    Space(String),
    /// Match a specific canonical object.
    Object(String),
    /// Match canonical objects of a specific type.
    ObjectType(String),
    /// Match a specific relation.
    Relation(String),
    /// Match a specific view.
    View(String),
    /// Match everything.
    Wildcard,
    /// Match any of the selectors (disjunction).
    Any(Vec<UiResourceSelector>),
    /// Match all of the selectors (conjunction).
    All(Vec<UiResourceSelector>),
    /// Exclude matching selectors.
    Except(Box<UiResourceSelector>, Vec<UiResourceSelector>),
}

impl UiResourceSelector {
    /// Check if this selector matches the given resource.
    pub fn matches(&self, resource: &UiResourceRef) -> bool {
        match self {
            Self::Space(id) => resource.space_id.as_ref() == Some(id),
            Self::Object(id) => resource.object_ref.as_ref() == Some(id),
            Self::ObjectType(t) => resource.object_type.as_ref() == Some(t),
            Self::Relation(id) => resource.relation_id.as_ref() == Some(id),
            Self::View(id) => resource.view_id.as_ref() == Some(id),
            Self::Wildcard => true,
            Self::Any(selectors) => selectors.iter().any(|s| s.matches(resource)),
            Self::All(selectors) => selectors.iter().all(|s| s.matches(resource)),
            Self::Except(include, excludes) => {
                include.matches(resource) && !excludes.iter().any(|e| e.matches(resource))
            }
        }
    }
}

/// Reference to a resource being evaluated.
#[derive(Clone, Debug, Default)]
pub struct UiResourceRef {
    pub space_id: Option<String>,
    pub object_ref: Option<String>,
    pub object_type: Option<String>,
    pub facets: Vec<String>,
    pub relation_id: Option<String>,
    pub view_id: Option<String>,
}

/// A capability grant, reduced to the fields the UI pre-gate engine
/// actually reads.
///
/// R22 (2026-06-03): the original struct carried a full wire-construction
/// surface (issuer / proofs / issued_at / delegation depth / parent /
/// revocable) plus a `GrantBuilder`, `cx_capability` op factory,
/// `GrantProof` and `CapabilityRevocation`. None of that was ever wired
/// into yougen's production paths — the only consumers are the UI pre-gate
/// helpers in `kanban.rs`, which need `subject` / `actions` /
/// `resource_selectors` / `constraints` to answer "should this button be
/// enabled". Everything else was dead write-side scaffolding and has been
/// removed. The authoritative grant lifecycle (issuance, proofs,
/// delegation, revocation) lives on the server.
#[derive(Clone, Debug, PartialEq)]
pub struct UiCapabilityGrant {
    /// The subject (who receives the capability).
    pub subject: String,
    /// Resources this grant applies to.
    pub resource_selectors: Vec<UiResourceSelector>,
    /// Actions allowed by this grant.
    pub actions: Vec<String>,
    /// Constraints on this grant.
    pub constraints: Vec<UiCapabilityConstraint>,
}

/// Authorization decision.
#[derive(Clone, Debug, PartialEq)]
pub enum UiAuthzDecision {
    Allow,
    Deny(String),
    Quarantine(String),
    RequireReview(String),
}

/// The capability authorization engine.
///
/// **UI pre-gate only.** This engine exists purely to pre-disable controls
/// in yougen's UI so users get immediate feedback before hitting the
/// server. It is **not** a security boundary: the authoritative
/// authorization decision — including grant signature/proof verification,
/// delegation-chain validation, and revocation — is made by the server.
/// yougen never trusts a local Allow.
#[derive(Clone, Debug, Default)]
pub struct CapabilityEngine {
    /// Grants the UI has hydrated for pre-gating, indexed by subject.
    grants: Vec<UiCapabilityGrant>,
}

impl CapabilityEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed a grant into the UI pre-gate index.
    ///
    /// **Security note:** this is a UI hydrate hook only. It deliberately
    /// does **not** verify any proof/signature — the server is the sole
    /// authority for grant validity (R5). When the `ck.capability.grant`
    /// projection path is wired up, grants arrive already
    /// server-validated; yougen simply mirrors them to pre-gate buttons.
    /// Do not treat a grant present here as proof of authorization.
    pub fn add_grant(&mut self, grant: UiCapabilityGrant) {
        self.grants.push(grant);
    }

    /// Check whether a subject can perform an action on a resource.
    ///
    /// **Fail-closed (R5):** absent an explicit, UiCapabilityConstraint-satisfied
    /// Allow this returns `Deny`. yougen never derives an Allow from the
    /// lack of a matching deny. This decision is advisory for the UI only;
    /// the server makes the authoritative call.
    pub fn check(
        &self,
        subject: &str,
        action: &str,
        resource: &UiResourceRef,
        ctx: &UiCapabilityEvalContext,
    ) -> UiAuthzDecision {
        // Find all grants for this subject
        let applicable_grants: Vec<&UiCapabilityGrant> = self
            .grants
            .iter()
            .filter(|g| g.subject == subject)
            .filter(|g| {
                g.actions.iter().any(|a| a == action || a == "*")
                    && g.resource_selectors.iter().any(|s| s.matches(resource))
            })
            .collect();

        if applicable_grants.is_empty() {
            return UiAuthzDecision::Deny(format!("no grant found for {subject} to {action}"));
        }

        // Evaluate constraints in priority order: deny > quarantine > allow > require_review
        let mut has_allow = false;
        let mut quarantine_reason = None;
        let mut review_reason = None;

        for grant in &applicable_grants {
            // A grant with no constraints is unconditionally permissive for
            // the actions/resources it covers.
            if grant.constraints.is_empty() {
                has_allow = true;
            }
            for constraint in &grant.constraints {
                match constraint.evaluate(ctx) {
                    UiConstraintResult::Allow => has_allow = true,
                    UiConstraintResult::Deny(reason) => {
                        return UiAuthzDecision::Deny(reason);
                    }
                    UiConstraintResult::Quarantine(reason) => {
                        quarantine_reason = Some(reason);
                    }
                    UiConstraintResult::RequireReview(reason) => {
                        review_reason = Some(reason);
                    }
                }
            }
        }

        // Priority: deny > quarantine > allow > require_review. R5: any path
        // that does not produce an explicit Allow falls through to Deny
        // (fail-closed) rather than the previous fail-open default.
        if let Some(reason) = quarantine_reason {
            UiAuthzDecision::Quarantine(reason)
        } else if has_allow {
            UiAuthzDecision::Allow
        } else if let Some(reason) = review_reason {
            UiAuthzDecision::RequireReview(reason)
        } else {
            UiAuthzDecision::Deny(format!(
                "no UiCapabilityConstraint admitted {subject} to {action}"
            ))
        }
    }

    /// UI-side pre-gate for a button / control.
    ///
    /// Returns a [`CapabilityGate`] suitable for binding to a Dioxus
    /// button's `disabled` + `title` attributes. The contract: when the
    /// engine carries no grants for `subject` at all the gate stays open
    /// (yougen still trusts the server's authoritative check). Once the
    /// engine has been seeded with grants for the actor — typically by
    /// hydrating `ck.capability.grant` events on login — the gate
    /// disables the control whenever `check` returns anything other than
    /// `Allow`, so users get immediate feedback before they hit the
    /// server's 403.
    pub fn ui_gate(
        &self,
        subject: &str,
        action: &str,
        resource: &UiResourceRef,
        ctx: &UiCapabilityEvalContext,
    ) -> CapabilityGate {
        let has_any_grant_for_subject = self.grants.iter().any(|g| g.subject == subject);
        if !has_any_grant_for_subject {
            return CapabilityGate::open();
        }
        match self.check(subject, action, resource, ctx) {
            UiAuthzDecision::Allow => CapabilityGate::open(),
            UiAuthzDecision::Deny(reason) => CapabilityGate::denied(reason),
            UiAuthzDecision::Quarantine(reason) => {
                CapabilityGate::denied(format!("quarantine: {reason}"))
            }
            UiAuthzDecision::RequireReview(reason) => {
                CapabilityGate::denied(format!("review required: {reason}"))
            }
        }
    }
}

/// Result of a UI-side capability gate evaluation. See
/// [`CapabilityEngine::ui_gate`] for the contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityGate {
    /// True when the control should accept input; false when it should
    /// be rendered disabled.
    pub enabled: bool,
    /// Human-readable reason when `enabled = false`. Empty when the
    /// gate is open.
    pub reason: String,
}

impl CapabilityGate {
    pub fn open() -> Self {
        Self {
            enabled: true,
            reason: String::new(),
        }
    }

    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            enabled: false,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(
        subject: &str,
        actions: &[&str],
        constraints: Vec<UiCapabilityConstraint>,
    ) -> UiCapabilityGrant {
        UiCapabilityGrant {
            subject: subject.to_owned(),
            resource_selectors: vec![UiResourceSelector::Space("ck:space:test".to_owned())],
            actions: actions.iter().map(|s| (*s).to_owned()).collect(),
            constraints,
        }
    }

    fn test_grant() -> UiCapabilityGrant {
        grant(
            "did:web:bob",
            &["ck.strand.read", "ck.strand.update"],
            vec![UiCapabilityConstraint::Temporal {
                not_before: None,
                expires_at: Some("2027-01-01T00:00:00Z".to_owned()),
            }],
        )
    }

    #[test]
    fn test_action_groups() {
        // F-CAP-FIX-1: spec capability-action-registry.json uses the
        // fully-qualified `ck.<noun>.<verb>` form everywhere; the local
        // ActionGroup table mirrors that exactly. A bare-name lookup
        // (`strand.create`) is now an explicit miss so we catch any
        // regression that re-introduces the removed short form.
        // Realm security-boundary actions live in ck.realm.*; Space
        // container actions live in ck.space.*.
        assert!(ActionGroup::Common.contains("ck.realm.update"));
        assert!(ActionGroup::Common.contains("ck.strand.create"));
        assert!(ActionGroup::Conversation.contains("ck.message.create"));
        assert!(ActionGroup::Administrative.contains("ck.capability.grant"));
        assert!(!ActionGroup::Common.contains("ck.message.create"));
        assert!(!ActionGroup::Common.contains("strand.create"));
    }

    #[test]
    fn test_lifecycle_archive_restore_symmetry() {
        // Spec contract: every lifecycle family with `*.archive` MUST also
        // expose `*.restore` (canonical archived -> active transition).
        assert!(ActionGroup::Common.contains("ck.strand.archive"));
        assert!(ActionGroup::Common.contains("ck.strand.restore"));
        assert!(ActionGroup::Common.contains("ck.space.archive"));
        assert!(ActionGroup::Common.contains("ck.space.restore"));
        assert!(ActionGroup::Morph.contains("ck.morph.archive"));
        assert!(ActionGroup::Morph.contains("ck.morph.restore"));
    }

    #[test]
    fn test_ui_gate_open_when_no_grants_for_subject() {
        // Empty engine — yougen should keep the button enabled and let
        // the server make the final call. This is the "we haven't
        // hydrated capability state yet" path.
        let engine = CapabilityEngine::new();
        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();
        let gate = engine.ui_gate("did:web:alice.example", "ck.space.archive", &resource, &ctx);
        assert!(gate.enabled);
        assert!(gate.reason.is_empty());
    }

    #[test]
    fn test_ui_gate_denies_when_grant_present_but_action_missing() {
        // Engine carries an unrelated grant for the subject — gate is
        // now active and denies space.archive because the grant only
        // covers realm.update.
        let mut engine = CapabilityEngine::new();
        engine.add_grant(UiCapabilityGrant {
            subject: "did:web:alice.example".to_owned(),
            resource_selectors: vec![UiResourceSelector::Wildcard],
            actions: vec!["ck.realm.update".to_owned()],
            constraints: Vec::new(),
        });
        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();
        let gate = engine.ui_gate("did:web:alice.example", "ck.space.archive", &resource, &ctx);
        assert!(!gate.enabled);
        assert!(gate.reason.contains("ck.space.archive"));
    }

    #[test]
    fn test_ui_gate_allows_when_grant_covers_action() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(UiCapabilityGrant {
            subject: "did:web:alice.example".to_owned(),
            resource_selectors: vec![UiResourceSelector::Wildcard],
            actions: vec!["ck.space.archive".to_owned(), "ck.space.restore".to_owned()],
            constraints: Vec::new(),
        });
        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();
        let gate = engine.ui_gate("did:web:alice.example", "ck.space.archive", &resource, &ctx);
        assert!(gate.enabled);
        assert!(gate.reason.is_empty());
    }

    #[test]
    fn test_resource_selector() {
        let selector = UiResourceSelector::Space("ck:space:test".to_owned());
        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        assert!(selector.matches(&resource));

        let resource_no_match = UiResourceRef {
            space_id: Some("ck:space:other".to_owned()),
            ..Default::default()
        };
        assert!(!selector.matches(&resource_no_match));
    }

    #[test]
    fn test_wildcard_selector() {
        let selector = UiResourceSelector::Wildcard;
        let resource = UiResourceRef::default();
        assert!(selector.matches(&resource));
    }

    #[test]
    fn test_any_selector() {
        let selector = UiResourceSelector::Any(vec![
            UiResourceSelector::Space("ck:space:a".to_owned()),
            UiResourceSelector::Space("ck:space:b".to_owned()),
        ]);
        let resource_a = UiResourceRef {
            space_id: Some("ck:space:a".to_owned()),
            ..Default::default()
        };
        let resource_c = UiResourceRef {
            space_id: Some("ck:space:c".to_owned()),
            ..Default::default()
        };
        assert!(selector.matches(&resource_a));
        assert!(!selector.matches(&resource_c));
    }

    #[test]
    fn test_except_selector() {
        let selector = UiResourceSelector::Except(
            Box::new(UiResourceSelector::Wildcard),
            vec![UiResourceSelector::Space("ck:space:secret".to_owned())],
        );
        let normal = UiResourceRef {
            space_id: Some("ck:space:normal".to_owned()),
            ..Default::default()
        };
        let secret = UiResourceRef {
            space_id: Some("ck:space:secret".to_owned()),
            ..Default::default()
        };
        assert!(selector.matches(&normal));
        assert!(!selector.matches(&secret));
    }

    #[test]
    fn test_capability_engine_check_allow() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            object_ref: Some("ck:strand:0196419b-0000-7000-8000-000000000001".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext {
            current_time: "2026-01-01T00:00:00Z".to_owned(),
            ..Default::default()
        };

        let decision = engine.check("did:web:bob", "ck.strand.read", &resource, &ctx);
        assert_eq!(decision, UiAuthzDecision::Allow);
    }

    #[test]
    fn test_capability_engine_check_deny_no_grant() {
        let engine = CapabilityEngine::new();
        let resource = UiResourceRef::default();
        let ctx = UiCapabilityEvalContext::default();

        let decision = engine.check("did:web:bob", "ck.strand.read", &resource, &ctx);
        assert!(matches!(decision, UiAuthzDecision::Deny(_)));
    }

    #[test]
    fn test_capability_engine_check_deny_wrong_action() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();

        let decision = engine.check("did:web:bob", "ck.strand.archive", &resource, &ctx);
        assert!(matches!(decision, UiAuthzDecision::Deny(_)));
    }

    #[test]
    fn test_capability_engine_check_deny_wrong_resource() {
        let mut engine = CapabilityEngine::new();
        engine.add_grant(test_grant());

        let resource = UiResourceRef {
            space_id: Some("ck:space:other".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();

        let decision = engine.check("did:web:bob", "ck.strand.read", &resource, &ctx);
        assert!(matches!(decision, UiAuthzDecision::Deny(_)));
    }

    #[test]
    fn test_capability_engine_check_unconstrained_grant_allows() {
        // R5: an unconstrained grant covering the action/resource yields a
        // positive Allow (not a fail-open fallthrough).
        let mut engine = CapabilityEngine::new();
        engine.add_grant(grant("did:web:bob", &["ck.strand.read"], Vec::new()));

        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();
        let decision = engine.check("did:web:bob", "ck.strand.read", &resource, &ctx);
        assert_eq!(decision, UiAuthzDecision::Allow);
    }

    #[test]
    fn test_capability_engine_check_require_review_not_allow() {
        // R5 fail-closed: a grant whose only UiCapabilityConstraint resolves to
        // RequireReview must NOT silently become Allow.
        let mut engine = CapabilityEngine::new();
        engine.add_grant(grant(
            "did:web:bob",
            &["ck.strand.read"],
            vec![UiCapabilityConstraint::ApprovalWorkflow {
                approvers: vec!["did:web:alice".to_owned()],
                min_approvals: 1,
            }],
        ));

        let resource = UiResourceRef {
            space_id: Some("ck:space:test".to_owned()),
            ..Default::default()
        };
        let ctx = UiCapabilityEvalContext::default();
        let decision = engine.check("did:web:bob", "ck.strand.read", &resource, &ctx);
        assert!(matches!(decision, UiAuthzDecision::RequireReview(_)));
    }

    #[test]
    fn test_constraint_temporal_allow() {
        let UiCapabilityConstraint = UiCapabilityConstraint::Temporal {
            not_before: Some("2025-01-01T00:00:00Z".to_owned()),
            expires_at: Some("2027-01-01T00:00:00Z".to_owned()),
        };
        let ctx = UiCapabilityEvalContext {
            current_time: "2026-06-15T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            UiCapabilityConstraint.evaluate(&ctx),
            UiConstraintResult::Allow
        );
    }

    #[test]
    fn test_constraint_temporal_deny() {
        let UiCapabilityConstraint = UiCapabilityConstraint::Temporal {
            not_before: None,
            expires_at: Some("2025-01-01T00:00:00Z".to_owned()),
        };
        let ctx = UiCapabilityEvalContext {
            current_time: "2026-06-15T00:00:00Z".to_owned(),
            ..Default::default()
        };
        assert!(matches!(
            UiCapabilityConstraint.evaluate(&ctx),
            UiConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_constraint_field_access() {
        let UiCapabilityConstraint = UiCapabilityConstraint::FieldAccess {
            allowed_fields: vec!["name".to_owned(), "email".to_owned()],
            denied_fields: vec!["ssn".to_owned()],
        };

        let ctx_allowed = UiCapabilityEvalContext {
            requested_fields: Some(vec!["name".to_owned()]),
            ..Default::default()
        };
        assert_eq!(
            UiCapabilityConstraint.evaluate(&ctx_allowed),
            UiConstraintResult::Allow
        );

        let ctx_denied = UiCapabilityEvalContext {
            requested_fields: Some(vec!["ssn".to_owned()]),
            ..Default::default()
        };
        assert!(matches!(
            UiCapabilityConstraint.evaluate(&ctx_denied),
            UiConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_constraint_type_restriction_checks_facets() {
        let UiCapabilityConstraint = UiCapabilityConstraint::TypeRestriction {
            allowed_object_types: vec!["strand".to_owned()],
            allowed_facets: vec!["stateful".to_owned(), "rankable".to_owned()],
        };

        let ctx_allowed = UiCapabilityEvalContext {
            object_type: Some("strand".to_owned()),
            facets: vec!["stateful".to_owned(), "rankable".to_owned()],
            ..Default::default()
        };
        assert_eq!(
            UiCapabilityConstraint.evaluate(&ctx_allowed),
            UiConstraintResult::Allow
        );

        let ctx_denied = UiCapabilityEvalContext {
            object_type: Some("strand".to_owned()),
            facets: vec!["stateful".to_owned()],
            ..Default::default()
        };
        assert!(matches!(
            UiCapabilityConstraint.evaluate(&ctx_denied),
            UiConstraintResult::Deny(_)
        ));
    }

    #[test]
    fn test_constraint_rate_limiting() {
        let UiCapabilityConstraint = UiCapabilityConstraint::RateLimiting {
            max_operations: 10,
            window_seconds: 60,
        };

        let ctx_under = UiCapabilityEvalContext {
            operation_counts: HashMap::from([("60s".to_owned(), 5)]),
            ..Default::default()
        };
        assert_eq!(
            UiCapabilityConstraint.evaluate(&ctx_under),
            UiConstraintResult::Allow
        );

        let ctx_over = UiCapabilityEvalContext {
            operation_counts: HashMap::from([("60s".to_owned(), 15)]),
            ..Default::default()
        };
        assert!(matches!(
            UiCapabilityConstraint.evaluate(&ctx_over),
            UiConstraintResult::Deny(_)
        ));
    }
}
