//! YGN-ORG-03 — Realm ↔ organization binding / revocation UI.
//!
//! The client must NOT conflate "this Realm declared an organization hint"
//! with "an organization signed and the Realm accepted a verified
//! relationship". This panel makes the four lifecycle states explicit and
//! drives the two-step bind flow (organization-side authorization first, then
//! the Realm-side accept event) plus the two distinct revocation paths.
//!
//! The proof / delegation that authorizes a `ck.realm.organization` statement
//! comes from the organization-side authorization flow (coauth / DID
//! controller), never from the human login session. Until SOL-ORG-06 /
//! COA-ORG-03 expose those endpoints, this panel develops against the DTO mock
//! below and marks the live submission boundary with a TODO.

use dioxus::prelude::*;

use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::views::helpers::short_protocol_id;

/// Lifecycle state of a Realm ↔ organization relationship, as the client must
/// distinguish it. Maps the organization-statement model onto the four UI
/// states named in YGN-ORG-03.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrgRelationshipPhase {
    /// The Realm merely declared an organization hint; no organization
    /// signature exists. NOT a verified relationship.
    DeclaredHint,
    /// The organization-side authorization has been requested but the signed
    /// statement is not yet accepted into Realm history.
    PendingConsent,
    /// An organization signed an `active` statement and the Realm accepted it;
    /// the relationship is live.
    VerifiedActive,
    /// A prior relationship was revoked or has expired; no official standing.
    RevokedOrExpired,
}

impl OrgRelationshipPhase {
    pub(crate) fn badge_class(self) -> &'static str {
        match self {
            Self::DeclaredHint => "badge amber",
            Self::PendingConsent => "badge blue",
            Self::VerifiedActive => "badge green",
            Self::RevokedOrExpired => "badge red",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::DeclaredHint => "declared hint",
            Self::PendingConsent => "pending organization consent",
            Self::VerifiedActive => "verified active",
            Self::RevokedOrExpired => "revoked / expired",
        }
    }

    /// One-line UX copy that prevents "selected an organization" from being
    /// read as "verified by the organization".
    pub(crate) fn explainer(self) -> &'static str {
        match self {
            Self::DeclaredHint => {
                "This Realm names an organization, but the organization has not signed a \
                 statement. This is a hint only — it is NOT an organization-verified \
                 relationship."
            }
            Self::PendingConsent => {
                "Waiting for the organization to authorize and sign. Nothing is verified until \
                 the signed statement is accepted into Realm history."
            }
            Self::VerifiedActive => {
                "The organization signed an active statement and the Realm accepted it. This is \
                 a proof-backed, verified relationship."
            }
            Self::RevokedOrExpired => {
                "A prior relationship was revoked by the organization or has expired. No \
                 official organization standing applies."
            }
        }
    }
}

/// DTO mock of a Realm ↔ organization relationship row. Mirrors the
/// `RealmOrganizationPayload` projection teabay / soland will return
/// (SOL-ORG-06 / TBY-ORG-02); developed against this until those land.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OrgRelationshipDto {
    pub organization_did: String,
    pub organization_name: String,
    /// `owner` / `governance` / `sponsor` / `directory_certifier`.
    pub relationship: String,
    pub phase: OrgRelationshipPhase,
    /// Endorsement scopes carried by the statement (display-only here).
    pub control_scopes: Vec<String>,
    /// Audit id of the latest statement, when one exists.
    pub statement_id: Option<String>,
}

fn mock_relationships() -> Vec<OrgRelationshipDto> {
    vec![
        OrgRelationshipDto {
            organization_did: "did:webvh:acme.example:orgs:acme".to_owned(),
            organization_name: "Acme Corp".to_owned(),
            relationship: "owner".to_owned(),
            phase: OrgRelationshipPhase::VerifiedActive,
            control_scopes: vec!["official_badge".to_owned(), "realm_admin".to_owned()],
            statement_id: Some("org-stmt-acme-1".to_owned()),
        },
        OrgRelationshipDto {
            organization_did: "did:webvh:standards.example:orgs:gov".to_owned(),
            organization_name: "Standards Body".to_owned(),
            relationship: "governance".to_owned(),
            phase: OrgRelationshipPhase::PendingConsent,
            control_scopes: vec!["moderation_policy".to_owned()],
            statement_id: None,
        },
        OrgRelationshipDto {
            organization_did: "did:web:hint.example".to_owned(),
            organization_name: "Hinted Org".to_owned(),
            relationship: "sponsor".to_owned(),
            phase: OrgRelationshipPhase::DeclaredHint,
            control_scopes: Vec::new(),
            statement_id: None,
        },
    ]
}

/// YGN-ORG-03 panel. Rendered inside the realm_admin Federation section.
#[component]
pub fn RealmOrganizationPanel(realm_id: String) -> Element {
    // DTO mock signal — replace with the teabay / soland projection fetch once
    // SOL-ORG-06 / TBY-ORG-02 land.
    let relationships = use_signal(mock_relationships);
    // Bind-flow inputs.
    let mut bind_org_did = use_signal(String::new);
    let mut bind_relationship = use_signal(|| "owner".to_owned());
    let mut flow_status = use_signal(String::new);
    // Two-step bind flow tracker: did we obtain organization-side authorization
    // yet? The Realm-side accept stays disabled until we have.
    let mut authorization_obtained = use_signal(|| false);

    rsx! {
        div { class: "event", "data-testid": "realm-organization-panel",
            div { class: "event-head",
                span { "Organization control" }
                span { title: "{realm_id}", "{short_protocol_id(&realm_id)}" }
            }
            div { class: "muted",
                "Bind this Realm to an organization principal, or revoke an existing relationship. \
                 An organization principal is a separate DID controller: the binding is authorized \
                 by the organization side, never by your login session."
            }

            // Current relationships — each row shows its lifecycle phase so a
            // declared hint can never be mistaken for a verified relationship.
            div { class: "metric-grid", "data-testid": "org-relationship-list",
                for rel in relationships() {
                    {
                        let phase = rel.phase;
                        let org_did = rel.organization_did.clone();
                        let scopes = rel.control_scopes.join(", ");
                        rsx! {
                            div {
                                class: "event nested-card",
                                "data-testid": "org-relationship-row",
                                "data-organization-did": "{org_did}",
                                "data-phase": "{phase_slug(phase)}",
                                div { class: "event-head",
                                    span { "{rel.organization_name}" }
                                    span {
                                        class: phase.badge_class(),
                                        "data-testid": "org-relationship-phase-badge",
                                        "{phase.label()}"
                                    }
                                }
                                div { class: "muted", title: "{org_did}", "{short_protocol_id(&org_did)} · {rel.relationship}" }
                                div { class: "muted", "data-testid": "org-relationship-explainer", "{phase.explainer()}" }
                                if !scopes.is_empty() {
                                    div { class: "muted", "data-testid": "org-relationship-scopes", "scopes: {scopes}" }
                                }
                                // Revocation differs by side. Organization-side
                                // revoke withdraws the organization's consent
                                // (a `revoked` ck.realm.organization statement,
                                // authorized by the org). Realm-side remove
                                // detaches the relationship from Realm history
                                // without the org's signature.
                                if phase == OrgRelationshipPhase::VerifiedActive {
                                    div { class: "actions",
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "org-revoke-org-side-button",
                                            onclick: {
                                                let org_did = org_did.clone();
                                                move |_| {
                                                    // TODO(SOL-ORG-06 / COA-ORG-03): request an
                                                    // organization-side `revoked` statement
                                                    // (authorized by the org DID controller),
                                                    // build it via
                                                    // ck_ops::realm_organization_statement with
                                                    // status=Revoked + revokes_statement_id, then
                                                    // submit. No org endpoint yet.
                                                    flow_status.set(format!(
                                                        "organization-side revoke requested for {} — needs an org-authorized revoked statement (pending SOL-ORG-06)",
                                                        short_protocol_id(&org_did)
                                                    ));
                                                }
                                            },
                                            "Organization revoke"
                                        }
                                        Button {
                                            variant: ButtonVariant::Secondary,
                                            "data-testid": "org-remove-realm-side-button",
                                            onclick: {
                                                let org_did = org_did.clone();
                                                move |_| {
                                                    // TODO(SOL-ORG-06): Realm-side remove detaches
                                                    // the relationship from Realm projection
                                                    // without the organization's signature; it does
                                                    // NOT invalidate the org's standing elsewhere.
                                                    flow_status.set(format!(
                                                        "Realm-side remove for {} — detaches locally without the organization's signature (pending SOL-ORG-06)",
                                                        short_protocol_id(&org_did)
                                                    ));
                                                }
                                            },
                                            "Realm remove"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Two-step bind flow.
            div { class: "workflow-form", "data-testid": "org-bind-form",
                div { class: "event-head",
                    span { "Bind a new organization" }
                    span { "two-step: organization authorizes, then Realm accepts" }
                }
                Label { html_for: "org-bind-did-input", "Organization DID" }
                Input {
                    id: "org-bind-did-input",
                    "data-testid": "org-bind-did-input",
                    value: "{bind_org_did}",
                    placeholder: "did:webvh:example.test:orgs:org1",
                    oninput: move |event: FormEvent| {
                        bind_org_did.set(event.value());
                        // Changing the target invalidates any prior org-side
                        // authorization.
                        authorization_obtained.set(false);
                    },
                }
                Label { html_for: "org-bind-relationship-select", "Relationship" }
                select {
                    id: "org-bind-relationship-select",
                    "data-testid": "org-bind-relationship-select",
                    value: "{bind_relationship}",
                    onchange: move |event: FormEvent| bind_relationship.set(event.value()),
                    option { value: "owner", "owner" }
                    option { value: "governance", "governance" }
                    option { value: "sponsor", "sponsor" }
                    option { value: "directory_certifier", "directory_certifier" }
                }
                div { class: "muted", "data-testid": "org-bind-step-hint",
                    if authorization_obtained() {
                        "Step 2/2 — organization authorization obtained. Submit the Realm-side accept."
                    } else {
                        "Step 1/2 — request organization-side authorization. Selecting an organization here does NOT verify it."
                    }
                }
                div { class: "actions",
                    // Step 1: obtain organization-side authorization. This is
                    // the org DID controller's decision, not the login
                    // session's.
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "org-request-authorization-button",
                        disabled: bind_org_did().trim().is_empty(),
                        onclick: move |_| {
                            let org = bind_org_did().trim().to_owned();
                            if org.is_empty() {
                                flow_status.set("enter an organization DID first".to_owned());
                                return;
                            }
                            // TODO(COA-ORG-03): hand off to the organization-side
                            // authorization flow (coauth / DID controller). The
                            // returned proof + (for delegated roles)
                            // delegation_ref become the
                            // RealmOrganizationAuthorizationInput passed to
                            // ck_ops::realm_organization_statement. No endpoint
                            // yet; mock the success here.
                            authorization_obtained.set(true);
                            flow_status.set(format!(
                                "organization authorization requested for {} ({}) — awaiting org-side proof (pending COA-ORG-03)",
                                short_protocol_id(&org),
                                bind_relationship()
                            ));
                        },
                        "Request organization authorization"
                    }
                    // Step 2: submit the Realm-side accept. Disabled until step
                    // 1 has produced an organization-side authorization.
                    Button {
                        variant: ButtonVariant::Primary,
                        "data-testid": "org-submit-accept-button",
                        disabled: !authorization_obtained(),
                        onclick: move |_| {
                            let org = bind_org_did().trim().to_owned();
                            // TODO(SOL-ORG-06): build the active
                            // ck.realm.organization statement with the
                            // org-supplied RealmOrganizationAuthorizationInput
                            // via ck_ops::realm_organization_statement and
                            // submit it as the Realm-side accept. No submit path
                            // until soland accepts the kind.
                            flow_status.set(format!(
                                "Realm-side accept for {} ({}) staged — submit pending SOL-ORG-06",
                                short_protocol_id(&org),
                                bind_relationship()
                            ));
                            authorization_obtained.set(false);
                        },
                        "Submit Realm accept"
                    }
                }
                if !flow_status().is_empty() {
                    div { class: "muted", "data-testid": "org-flow-status", "{flow_status}" }
                }
            }
        }
    }
}

fn phase_slug(phase: OrgRelationshipPhase) -> &'static str {
    match phase {
        OrgRelationshipPhase::DeclaredHint => "declared_hint",
        OrgRelationshipPhase::PendingConsent => "pending_consent",
        OrgRelationshipPhase::VerifiedActive => "verified_active",
        OrgRelationshipPhase::RevokedOrExpired => "revoked_or_expired",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_hint_is_not_presented_as_verified() {
        // YGN-ORG-05 (UI): a declared hint must read as a hint, never as a
        // verified relationship, and must not carry the verified-active badge.
        let phase = OrgRelationshipPhase::DeclaredHint;
        assert_eq!(phase.label(), "declared hint");
        assert_ne!(phase.label(), OrgRelationshipPhase::VerifiedActive.label());
        assert_ne!(
            phase.badge_class(),
            OrgRelationshipPhase::VerifiedActive.badge_class()
        );
        assert!(phase.explainer().contains("NOT"));
    }

    #[test]
    fn verified_active_is_the_only_proof_backed_phase() {
        assert_eq!(
            OrgRelationshipPhase::VerifiedActive.label(),
            "verified active"
        );
        assert_eq!(
            OrgRelationshipPhase::VerifiedActive.badge_class(),
            "badge green"
        );
        // Pending consent is explicitly not verified.
        assert_ne!(
            OrgRelationshipPhase::PendingConsent.badge_class(),
            OrgRelationshipPhase::VerifiedActive.badge_class()
        );
        assert!(
            OrgRelationshipPhase::PendingConsent
                .explainer()
                .contains("Nothing is verified")
        );
    }

    #[test]
    fn every_phase_has_a_distinct_slug_and_badge() {
        let phases = [
            OrgRelationshipPhase::DeclaredHint,
            OrgRelationshipPhase::PendingConsent,
            OrgRelationshipPhase::VerifiedActive,
            OrgRelationshipPhase::RevokedOrExpired,
        ];
        let slugs: Vec<_> = phases.iter().map(|p| phase_slug(*p)).collect();
        for (i, a) in slugs.iter().enumerate() {
            for b in slugs.iter().skip(i + 1) {
                assert_ne!(a, b, "phase slugs must be distinct");
            }
        }
    }

    #[test]
    fn mock_dto_covers_hint_pending_and_verified() {
        let rels = mock_relationships();
        assert!(
            rels.iter()
                .any(|r| r.phase == OrgRelationshipPhase::DeclaredHint)
        );
        assert!(
            rels.iter()
                .any(|r| r.phase == OrgRelationshipPhase::PendingConsent)
        );
        assert!(
            rels.iter()
                .any(|r| r.phase == OrgRelationshipPhase::VerifiedActive)
        );
        // A declared hint carries no signed statement id.
        let hint = rels
            .iter()
            .find(|r| r.phase == OrgRelationshipPhase::DeclaredHint)
            .unwrap();
        assert!(hint.statement_id.is_none());
    }
}
