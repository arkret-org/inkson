//! Form state only; all serialized policy and current records come from the SDK.
use arkret_models_collaboration::governance::operation_wire::{
    AgentPolicyOperation, AgentPolicyTarget, ManagementOperation, ManagementReviewRequirement,
    Policy, PolicyResourceKind, PolicyResourceSelector, PolicyRule, PolicyRuleKind,
    PolicySetStatePayload, PolicySetValue,
};
use arkret_sdk::{AccountId, ActorId, CurrentRevision, PolicyId, RealmId, ScopeRef};
use arkret_wire::{PolicyEffect, PolicyKind};

#[derive(Clone, Debug, Default)]
pub(super) struct ResourceDraft {
    pub kind: String,
    pub realm: String,
    pub reference: String,
}
#[derive(Clone, Debug)]
pub(super) struct RuleDraft {
    pub id: String,
    pub priority: String,
    pub effect: String,
    pub target: String,
    pub principal: String,
    pub station: String,
    pub operations: Vec<String>,
    pub actions: String,
    pub resources: Vec<ResourceDraft>,
    pub approvers: String,
    pub threshold: String,
    pub max_age: String,
}
impl Default for RuleDraft {
    fn default() -> Self {
        Self {
            id: format!("rule_{}", crate::operation::uuid_v7().replace('-', "_")),
            priority: "0".into(),
            effect: "deny".into(),
            target: "all".into(),
            principal: String::new(),
            station: String::new(),
            operations: vec!["join".into()],
            actions: String::new(),
            resources: Vec::new(),
            approvers: String::new(),
            threshold: "1".into(),
            max_age: "3600".into(),
        }
    }
}
#[derive(Clone, Debug)]
pub(super) struct Draft {
    pub policy_id: String,
    pub circle: String,
    pub default_effect: String,
    pub default_operations: Vec<String>,
    pub default_approvers: String,
    pub default_threshold: String,
    pub default_max_age: String,
    pub priority: String,
    pub not_before: String,
    pub expires_at: String,
    pub rules: Vec<RuleDraft>,
}
impl Default for Draft {
    fn default() -> Self {
        Self {
            policy_id: format!("ak:policy:{}", crate::operation::uuid_v7()),
            circle: String::new(),
            default_effect: "allow".into(),
            default_operations: vec!["join".into()],
            default_approvers: String::new(),
            default_threshold: "1".into(),
            default_max_age: "3600".into(),
            priority: String::new(),
            not_before: String::new(),
            expires_at: String::new(),
            rules: vec![RuleDraft::default()],
        }
    }
}
fn enum_value<T: serde::de::DeserializeOwned>(text: &str) -> anyhow::Result<T> {
    Ok(serde_json::from_value(serde_json::Value::String(
        text.into(),
    ))?)
}
fn optional_timestamp(text: &str) -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
    if text.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(
            chrono::DateTime::parse_from_rfc3339(text.trim())?.with_timezone(&chrono::Utc),
        ))
    }
}
fn review(
    approvers: &str,
    threshold: &str,
    max_age: &str,
) -> anyhow::Result<ManagementReviewRequirement> {
    let value = ManagementReviewRequirement {
        approver_actor_ids: serde_json::from_str(approvers)?,
        threshold: threshold.parse()?,
        max_age_seconds: max_age.parse()?,
    };
    value.validate()?;
    Ok(value)
}
fn words(text: &str) -> Option<Vec<String>> {
    let values: Vec<_> = text.split_whitespace().map(str::to_owned).collect();
    (!values.is_empty()).then_some(values)
}
impl RuleDraft {
    fn build(&self) -> anyhow::Result<PolicyRule> {
        let effect: PolicyEffect = enum_value(&self.effect)?;
        let target = match self.target.as_str() {
            "all" => AgentPolicyTarget::All {},
            "controller" | "agent" => {
                let account = AccountId::new(
                    arkret_sdk::DidCoreId::new(self.principal.trim())?,
                    arkret_sdk::DidCoreId::new(self.station.trim())?,
                );
                account.validate()?;
                if self.target == "controller" {
                    AgentPolicyTarget::Controller {
                        controller_account_id: account,
                    }
                } else {
                    AgentPolicyTarget::Agent {
                        agent_account_id: account,
                    }
                }
            }
            _ => anyhow::bail!("Choose a registered Agent target"),
        };
        let resources = self
            .resources
            .iter()
            .map(|r| {
                Ok(PolicyResourceSelector {
                    kind: enum_value(&r.kind)?,
                    realm_id: if r.realm.trim().is_empty() {
                        None
                    } else {
                        Some(RealmId::new(r.realm.trim())?)
                    },
                    resource_ref: (!r.reference.trim().is_empty())
                        .then(|| r.reference.trim().to_owned()),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let value = PolicyRule {
            rule_id: self.id.trim().into(),
            kind: PolicyRuleKind::Agent,
            effect: effect.clone(),
            agent_target: Some(target),
            agent_operations: Some(
                self.operations
                    .iter()
                    .map(|v| enum_value(v))
                    .collect::<anyhow::Result<_>>()?,
            ),
            applet_target: None,
            applet_operations: None,
            review_requirement: (effect == PolicyEffect::RequireReview)
                .then(|| review(&self.approvers, &self.threshold, &self.max_age))
                .transpose()?,
            priority: self.priority.parse()?,
            actions: words(&self.actions),
            resources: (!resources.is_empty()).then_some(resources),
            servers: None,
            conditions: None,
            schema_ref: None,
            profile_ref: None,
            params: None,
        };
        Ok(value)
    }
    fn from_rule(rule: &PolicyRule) -> anyhow::Result<Self> {
        anyhow::ensure!(
            rule.kind == PolicyRuleKind::Agent,
            "This editor cannot rewrite a different rule family"
        );
        let mut form = Self {
            id: rule.rule_id.clone(),
            priority: rule.priority.to_string(),
            effect: serialized_enum(&rule.effect)?,
            operations: rule
                .agent_operations
                .clone()
                .unwrap_or_default()
                .iter()
                .map(serialized_enum)
                .collect::<anyhow::Result<_>>()?,
            actions: rule.actions.clone().unwrap_or_default().join("\n"),
            resources: Vec::new(),
            ..Self::default()
        };
        match rule
            .agent_target
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Agent rule omits target"))?
        {
            AgentPolicyTarget::All {} => form.target = "all".into(),
            AgentPolicyTarget::Controller {
                controller_account_id: account,
            }
            | AgentPolicyTarget::Agent {
                agent_account_id: account,
            } => {
                form.target = if matches!(
                    rule.agent_target,
                    Some(AgentPolicyTarget::Controller { .. })
                ) {
                    "controller"
                } else {
                    "agent"
                }
                .into();
                form.principal = account.principal_id.to_string();
                form.station = account.station_id.to_string();
            }
        }
        for r in rule.resources.as_deref().unwrap_or_default() {
            form.resources.push(ResourceDraft {
                kind: serialized_enum(&r.kind)?,
                realm: r
                    .realm_id
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                reference: r.resource_ref.clone().unwrap_or_default(),
            });
        }
        if let Some(r) = &rule.review_requirement {
            form.approvers = serde_json::to_string_pretty(&r.approver_actor_ids)?;
            form.threshold = r.threshold.to_string();
            form.max_age = r.max_age_seconds.to_string();
        }
        Ok(form)
    }
}
fn serialized_enum(value: &impl serde::Serialize) -> anyhow::Result<String> {
    Ok(serde_json::to_value(value)?
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Expected SDK enum"))?
        .into())
}
impl Draft {
    pub fn scope(&self, realm: &RealmId) -> anyhow::Result<ScopeRef> {
        if self.circle.trim().is_empty() {
            Ok(ScopeRef::Realm {
                realm_id: realm.clone(),
            })
        } else {
            Ok(ScopeRef::Circle {
                realm_id: realm.clone(),
                circle_id: arkret_sdk::CircleId::new(self.circle.trim())?,
            })
        }
    }
    pub fn build(
        &self,
        realm: &RealmId,
        actor: &AccountId,
        previous: Option<&Policy>,
        revision: Option<CurrentRevision>,
    ) -> anyhow::Result<PolicySetStatePayload> {
        let effect: PolicyEffect = enum_value(&self.default_effect)?;
        let now = crate::clock::now_utc_millis();
        let id = PolicyId::new(self.policy_id.trim())?;
        if let Some(p) = previous {
            anyhow::ensure!(
                p.id == id && p.realm_id.as_ref() == Some(realm),
                "Policy id and Realm cannot be rebound"
            );
        }
        let value = Policy {
            schema: Policy::SCHEMA.into(),
            id: id.clone(),
            realm_id: Some(realm.clone()),
            policy_kind: PolicyKind::Agent,
            rules: self
                .rules
                .iter()
                .map(RuleDraft::build)
                .collect::<anyhow::Result<_>>()?,
            default_effect: effect.clone(),
            default_review_requirement: (effect == PolicyEffect::RequireReview)
                .then(|| {
                    review(
                        &self.default_approvers,
                        &self.default_threshold,
                        &self.default_max_age,
                    )
                })
                .transpose()?,
            default_operations: if effect == PolicyEffect::RequireReview {
                Some(
                    self.default_operations
                        .iter()
                        .map(|op| enum_value::<ManagementOperation>(op))
                        .collect::<anyhow::Result<_>>()?,
                )
            } else {
                None
            },
            priority: if self.priority.trim().is_empty() {
                None
            } else {
                Some(self.priority.parse()?)
            },
            not_before: optional_timestamp(&self.not_before)?,
            expires_at: optional_timestamp(&self.expires_at)?,
            created_by: previous
                .map(|p| p.created_by.clone())
                .unwrap_or_else(|| ActorId::account(actor.clone())),
            created_at: previous.map(|p| p.created_at).unwrap_or(now),
            updated_by: previous.map(|_| ActorId::account(actor.clone())),
            updated_at: previous.map(|_| now),
            extra: previous.map(|p| p.extra.clone()).unwrap_or_default(),
        };
        let payload = PolicySetStatePayload {
            policy_id: id,
            expected_revision: Some(revision),
            value: PolicySetValue::Governance(Box::new(value)),
        };
        payload.validate()?;
        Ok(payload)
    }
    pub fn from_policy(policy: &Policy, scope: &ScopeRef) -> anyhow::Result<Self> {
        anyhow::ensure!(
            policy.policy_kind == PolicyKind::Agent,
            "This is not an Agent policy"
        );
        let mut form = Self {
            policy_id: policy.id.to_string(),
            circle: match scope {
                ScopeRef::Circle { circle_id, .. } => circle_id.to_string(),
                _ => String::new(),
            },
            default_effect: serialized_enum(&policy.default_effect)?,
            priority: policy.priority.map(|p| p.to_string()).unwrap_or_default(),
            not_before: policy
                .not_before
                .map(|v| v.to_rfc3339())
                .unwrap_or_default(),
            expires_at: policy
                .expires_at
                .map(|v| v.to_rfc3339())
                .unwrap_or_default(),
            rules: policy
                .rules
                .iter()
                .map(RuleDraft::from_rule)
                .collect::<anyhow::Result<_>>()?,
            ..Self::default()
        };
        if let Some(r) = &policy.default_review_requirement {
            form.default_approvers = serde_json::to_string_pretty(&r.approver_actor_ids)?;
            form.default_threshold = r.threshold.to_string();
            form.default_max_age = r.max_age_seconds.to_string();
        }
        form.default_operations = policy
            .default_operations
            .clone()
            .unwrap_or_default()
            .iter()
            .map(serialized_enum)
            .collect::<anyhow::Result<_>>()?;
        Ok(form)
    }
}
/// Configuration compatibility only; the Station still checks current authority.
pub(super) fn supported_by_current_backend(
    payload: &PolicySetStatePayload,
    scope: &ScopeRef,
) -> bool {
    let PolicySetValue::Governance(document) = &payload.value else {
        return false;
    };
    if document.policy_kind != PolicyKind::Agent {
        return false;
    }
    if document.validate().is_err() {
        return false;
    }
    if !matches!(scope,
        arkret_wire::ScopeRef::Realm { realm_id }
        | arkret_wire::ScopeRef::Circle { realm_id, .. }
        if document.realm_id.as_ref() == Some(realm_id))
    {
        return false;
    }
    let circle = matches!(scope, arkret_wire::ScopeRef::Circle { .. });
    if (circle && document.default_effect == PolicyEffect::RequireReview)
        || document.rules.iter().any(|rule| {
            rule.kind != PolicyRuleKind::Agent
                || (circle && rule.effect == PolicyEffect::RequireReview)
                || rule.actions.as_ref().is_some_and(|actions| {
                    actions.iter().any(|action| {
                        arkret_schema::capability_action(action).is_none_or(|descriptor| {
                            descriptor.event_mapping_kind == "aggregate_admin"
                        }) || arkret_wire::ServiceOperationId::from_wire(action).is_some()
                    })
                })
                || (rule.actions.is_some()
                    && rule.agent_operations.as_ref().is_some_and(|ops| {
                        ops.iter().any(|op| {
                            matches!(
                                op,
                                AgentPolicyOperation::Join | AgentPolicyOperation::Publish
                            )
                        })
                    }))
                || rule.resources.as_ref().is_some_and(|resources| {
                    resources.iter().any(|resource| {
                        resource
                            .realm_id
                            .as_ref()
                            .is_some_and(|realm| document.realm_id.as_ref() != Some(realm))
                            || match resource.kind {
                                PolicyResourceKind::Realm => {
                                    resource.resource_ref.as_ref().is_some_and(|id| {
                                        document
                                            .realm_id
                                            .as_ref()
                                            .is_none_or(|realm| realm.as_str() != id)
                                    })
                                }
                                PolicyResourceKind::Strand => resource
                                    .resource_ref
                                    .as_ref()
                                    .is_some_and(|id| id.parse::<arkret_wire::StrandId>().is_err()),
                                PolicyResourceKind::Space => resource
                                    .resource_ref
                                    .as_ref()
                                    .is_some_and(|id| id.parse::<arkret_wire::SpaceId>().is_err()),
                                PolicyResourceKind::Object => resource
                                    .resource_ref
                                    .as_ref()
                                    .is_some_and(|id| !arkret_wire::is_object_ref(id)),
                                // Service scope cannot be used as a content-resource selector.
                                // No registered Agent management service matcher supplies its
                                // facts.
                                PolicyResourceKind::Service => true,
                            }
                    })
                })
        })
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    fn realm() -> RealmId {
        RealmId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [11; 32],
        ))
    }
    fn account(principal: &str, station: &str) -> AccountId {
        AccountId::new(
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{principal}.example")).unwrap(),
            arkret_sdk::DidCoreId::new(format!("ak:did_core:web:{station}.example")).unwrap(),
        )
    }
    fn revision() -> CurrentRevision {
        CurrentRevision {
            commit_id: arkret_sdk::RealmCommitId::from_digest([13; 32]),
            stream_position: 9,
        }
    }
    #[test]
    fn controller_rule_retains_full_account_without_enumerating_current_agents() {
        let controller = account("controller", "remote-station");
        let mut draft = Draft::default();
        draft.rules[0].target = "controller".into();
        draft.rules[0].principal = controller.principal_id.to_string();
        draft.rules[0].station = controller.station_id.to_string();
        let payload = draft
            .build(&realm(), &account("admin", "home"), None, None)
            .unwrap();
        let PolicySetValue::Governance(policy) = payload.value else {
            panic!()
        };
        assert_eq!(
            policy.rules[0].agent_target,
            Some(AgentPolicyTarget::Controller {
                controller_account_id: controller
            })
        );
        assert_eq!(policy.rules.len(), 1);
        assert!(supported_by_current_backend(
            &draft
                .build(&realm(), &account("admin", "home"), None, None)
                .unwrap(),
            &ScopeRef::Realm { realm_id: realm() }
        ));
    }
    #[test]
    fn exact_agent_selector_and_missing_station_never_borrow_admin_station() {
        let agent = account("agent", "remote-station");
        let mut draft = Draft::default();
        draft.rules[0].target = "agent".into();
        draft.rules[0].principal = agent.principal_id.to_string();
        assert!(
            draft
                .build(&realm(), &account("admin", "home"), None, None)
                .is_err()
        );
        draft.rules[0].station = agent.station_id.to_string();
        let PolicySetValue::Governance(policy) = draft
            .build(&realm(), &account("admin", "home"), None, None)
            .unwrap()
            .value
        else {
            panic!()
        };
        assert_eq!(
            policy.rules[0].agent_target,
            Some(AgentPolicyTarget::Agent {
                agent_account_id: agent
            })
        );
    }
    #[test]
    fn same_id_cas_preserves_creation_and_full_current_revision() {
        let mut draft = Draft::default();
        let creator = account("creator", "home");
        let PolicySetValue::Governance(old) =
            draft.build(&realm(), &creator, None, None).unwrap().value
        else {
            panic!()
        };
        draft.rules[0].priority = "12".into();
        let updater = account("updater", "other-station");
        let rev = revision();
        let payload = draft
            .build(&realm(), &updater, Some(&old), Some(rev.clone()))
            .unwrap();
        assert_eq!(payload.expected_revision, Some(Some(rev)));
        let PolicySetValue::Governance(policy) = payload.value else {
            panic!()
        };
        assert_eq!(policy.id, old.id);
        assert_eq!(policy.created_at, old.created_at);
        assert_eq!(policy.created_by, old.created_by);
        assert_eq!(policy.updated_by, Some(ActorId::account(updater)));
        draft.policy_id = format!("ak:policy:{}", crate::operation::uuid_v7());
        assert!(draft.build(&realm(), &creator, Some(&old), None).is_err());
    }
    #[test]
    fn all_registered_operations_and_default_deny_match_the_station_configuration_matrix() {
        let mut draft = Draft::default();
        let actor = account("admin", "home");
        let scope = ScopeRef::Realm { realm_id: realm() };
        for op in [
            "join",
            "authorize",
            "execute",
            "read",
            "deliver",
            "publish",
            "serve",
        ] {
            draft.rules[0].operations = vec![op.into()];
            for effect in ["allow", "deny", "quarantine"] {
                draft.rules[0].effect = effect.into();
                let p = draft.build(&realm(), &actor, None, None).unwrap();
                assert!(
                    supported_by_current_backend(&p, &scope),
                    "registered operation {op}, effect {effect}"
                );
                let circle = arkret_sdk::CircleId::from_event_id(
                    &arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [14; 32]),
                );
                assert!(supported_by_current_backend(
                    &p,
                    &ScopeRef::Circle {
                        realm_id: realm(),
                        circle_id: circle
                    }
                ));
            }
        }
        draft.rules[0].effect = "deny".into();
        draft.rules[0].operations = vec!["join".into()];
        draft.default_effect = "deny".into();
        assert!(supported_by_current_backend(
            &draft.build(&realm(), &actor, None, None).unwrap(),
            &scope
        ));
        draft.default_effect = "allow".into();
        draft.rules[0].actions = "ak.message.create".into();
        assert!(!supported_by_current_backend(
            &draft.build(&realm(), &actor, None, None).unwrap(),
            &scope
        ));
        draft.rules[0].operations = vec!["execute".into()];
        assert!(supported_by_current_backend(
            &draft.build(&realm(), &actor, None, None).unwrap(),
            &scope
        ));
        draft.rules[0].actions.clear();
        let event_id = arkret_sdk::EventId::from_digest(arkret_sdk::DigestSuite::Sha256, [15; 32]);
        for (kind, reference) in [
            ("realm", realm().to_string()),
            (
                "strand",
                arkret_sdk::StrandId::from_event_id(&event_id).to_string(),
            ),
            (
                "space",
                arkret_sdk::SpaceId::from_event_id(&event_id).to_string(),
            ),
            ("object", realm().to_string()),
        ] {
            draft.rules[0].resources = vec![ResourceDraft {
                kind: kind.into(),
                realm: realm().to_string(),
                reference,
            }];
            assert!(
                supported_by_current_backend(
                    &draft.build(&realm(), &actor, None, None).unwrap(),
                    &scope
                ),
                "registered resource {kind}"
            );
        }
        let mut payload = draft.build(&realm(), &actor, None, None).unwrap();
        let PolicySetValue::Governance(policy) = &mut payload.value else {
            panic!()
        };
        policy.rules[0].resources.as_mut().unwrap()[0].kind = PolicyResourceKind::Service;
        assert!(!supported_by_current_backend(&payload, &scope));
        let PolicySetValue::Governance(policy) = &mut payload.value else {
            panic!()
        };
        policy.rules[0].resources.as_mut().unwrap()[0].kind = PolicyResourceKind::Object;
        policy.rules[0].resources.as_mut().unwrap()[0].realm_id =
            Some(RealmId::from_event_id(&event_id));
        assert!(!supported_by_current_backend(&payload, &scope));
    }
    #[test]
    fn review_uses_sdk_requirements_and_rejects_unregistered_execute_review() {
        let actor = account("admin", "home");
        let approver = ActorId::account(account("reviewer", "home"));
        let mut draft = Draft::default();
        draft.rules[0].effect = "require_review".into();
        draft.rules[0].approvers = serde_json::to_string(&vec![approver]).unwrap();
        let p = draft.build(&realm(), &actor, None, None).unwrap();
        assert!(supported_by_current_backend(
            &p,
            &ScopeRef::Realm { realm_id: realm() }
        ));
        let circle = arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [14; 32],
        ));
        assert!(!supported_by_current_backend(
            &p,
            &ScopeRef::Circle {
                realm_id: realm(),
                circle_id: circle
            }
        ));
        draft.rules[0].operations = vec!["publish".into()];
        let publish = draft.build(&realm(), &actor, None, None).unwrap();
        assert!(supported_by_current_backend(
            &publish,
            &ScopeRef::Realm { realm_id: realm() }
        ));
        draft.rules[0].operations = vec!["execute".into()];
        assert!(draft.build(&realm(), &actor, None, None).is_err());
        draft.rules[0].operations = vec!["join".into()];
        draft.rules[0].threshold = "2".into();
        assert!(draft.build(&realm(), &actor, None, None).is_err());
    }
    #[test]
    fn form_roundtrip_preserves_selector_operations_priority_resources_and_validity() {
        let mut draft = Draft::default();
        draft.not_before = "2026-10-12T01:00:00Z".into();
        draft.expires_at = "2026-10-13T01:00:00Z".into();
        draft.rules[0].priority = "17".into();
        draft.priority = "3".into();
        draft.rules[0].resources.push(ResourceDraft {
            kind: "realm".into(),
            realm: realm().to_string(),
            reference: realm().to_string(),
        });
        let actor = account("admin", "home");
        let PolicySetValue::Governance(policy) =
            draft.build(&realm(), &actor, None, None).unwrap().value
        else {
            panic!()
        };
        let restored = Draft::from_policy(&policy, &ScopeRef::Realm { realm_id: realm() }).unwrap();
        let PolicySetValue::Governance(updated) = restored
            .build(&realm(), &actor, Some(&policy), Some(revision()))
            .unwrap()
            .value
        else {
            panic!()
        };
        assert_eq!(
            serde_json::to_value(policy.rules).unwrap(),
            serde_json::to_value(updated.rules).unwrap()
        );
        assert_eq!(policy.priority, updated.priority);
        assert_eq!(policy.not_before, updated.not_before);
        assert_eq!(policy.expires_at, updated.expires_at);
    }
    #[test]
    fn first_write_serializes_explicit_null_and_circle_uses_the_same_registered_matrix() {
        let form = Draft::default();
        let payload = form
            .build(&realm(), &account("admin", "home"), None, None)
            .unwrap();
        let value = serde_json::to_value(&payload).unwrap();
        assert!(value.as_object().unwrap().contains_key("expected_revision"));
        assert_eq!(value["expected_revision"], serde_json::Value::Null);
        let circle = arkret_sdk::CircleId::from_event_id(&arkret_sdk::EventId::from_digest(
            arkret_sdk::DigestSuite::Sha256,
            [14; 32],
        ));
        assert!(supported_by_current_backend(
            &payload,
            &ScopeRef::Circle {
                realm_id: realm(),
                circle_id: circle
            }
        ));
    }
}
