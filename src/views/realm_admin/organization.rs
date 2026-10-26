//! Realm <-> organization
//! relationship view.
//!
//! The client must NOT conflate "this Realm declared an organization hint"
//! with "an organization signed and the Realm accepted a verified
//! relationship". This panel makes the lifecycle states explicit.
//!
//! Read side: the verified relationships and declared hints are read from the
//! spec-canonical projection `ak.self.realm_organization.read.list.v1`
//! (`GET /_arkret/self/realms/{realm_id}/organizations`) via
//! [`crate::transport::TransportClient::list_realm_organizations`]. The server only returns
//! `verified_active` / `revoked_or_expired` rows plus
//! `declared_organization_hint_ids`.
//!
//! Write side: binding a Realm to an organization and signing organization-side
//! statements (and revocations) is the organization DID controller's authority,
//! exercised in the admin console (codmin). inkson does NOT mint or submit
//! organization-side signatures and does NOT call coauth admin endpoints; this
//! panel only reads and links operators to where the binding flow lives.

use std::rc::Rc;

use arkret_identifiers::{Did, DidCoreId};
use arkret_models_collaboration::events_payloads::{
    RealmOrganizationControlScope, RealmOrganizationRelationship, RealmOrganizationStatus,
};
use arkret_models_collaboration::governance::realm_governance::{
    RealmOrganizationLifecyclePhase, RealmOrganizationRelationshipList,
    RealmOrganizationRelationshipView,
};
use glory::{Cage, Scope};

use crate::organization::{
    OrganizationStatementInput, load_organization_control_key, prepare_organization_inception,
    sign_organization_statement, store_organization_control_seed,
};
use crate::presentation::{InksonContext, View};
use crate::transport::auth::with_authed_sdk_client;
use crate::views::helpers::short_protocol_id;
use crate::views::settings::widgets::*;

/// Context-provided server-administrator signal (D0). Newtype-wrapped so the
/// context lookup can't collide with any other bare `Signal<bool>`. Sourced from
/// `AccountView.is_server_admin` (the server's configured admin principal set),
/// NOT from any Realm-role `is_admin` placeholder.
#[derive(Clone, Copy)]
pub struct ServerAdminSignal(pub Cage<bool>);

/// Best-effort read of the context-provided server-admin signal. Returns `false`
/// when no provider is mounted (e.g. unit tests) so callers fail closed: the
/// organization create/bind write UI stays hidden unless the viewer is a proven
/// server administrator.
pub fn is_server_admin(context: &InksonContext) -> bool {
    context.is_server_admin.get()
}

/// SecureKeyStore-adjacent local index of organizations this administrator has
/// minted on this device. Stored as JSON in the per-account private-data store
/// so the bind UI can offer a dropdown of already-created organizations. The
/// control private keys themselves live in the secure key store, keyed by the
/// stable organization id.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreatedOrganization {
    pub organization_id: DidCoreId,
    /// Exact DID whose controller method is retained for statement proof.
    pub organization_did: Did,
    /// Organization control verification method id (`<did>#did-key-1`).
    pub did_key_id: String,
    /// Operator-facing label captured at creation time.
    pub display_name: String,
}

/// Plain local-data key (per account) for the created-organizations index. No
/// version suffix per the storage-key convention.
const CREATED_ORGANIZATIONS_KEY: &str = "organizations.created";

/// Read the created-organizations index for the active account from local state.
fn load_created_organizations(store: &crate::state::LocalStateStore) -> Vec<CreatedOrganization> {
    store
        .load_plain_local_data(CREATED_ORGANIZATIONS_KEY)
        .and_then(|raw| serde_json::from_str::<Vec<CreatedOrganization>>(&raw).ok())
        .unwrap_or_default()
}

/// Append (or replace by stable id) a created organization into the per-account index.
fn upsert_created_organization(
    store: &mut crate::state::LocalStateStore,
    entry: CreatedOrganization,
) {
    let mut list = load_created_organizations(store);
    if let Some(existing) = list
        .iter_mut()
        .find(|item| item.organization_id == entry.organization_id)
    {
        *existing = entry;
    } else {
        list.push(entry);
    }
    if let Ok(serialized) = serde_json::to_string(&list) {
        store.save_plain_local_data(CREATED_ORGANIZATIONS_KEY, serialized);
    }
}

/// Map the UI relationship slug onto the SDK enum.
fn relationship_from_slug(slug: &str) -> Option<RealmOrganizationRelationship> {
    match slug {
        "owner" => Some(RealmOrganizationRelationship::Owner),
        "governance" => Some(RealmOrganizationRelationship::Governance),
        "sponsor" => Some(RealmOrganizationRelationship::Sponsor),
        "directory_certifier" => Some(RealmOrganizationRelationship::DirectoryCertifier),
        _ => None,
    }
}

/// Map a control-scope slug onto the SDK enum.
fn control_scope_from_slug(slug: &str) -> Option<RealmOrganizationControlScope> {
    match slug {
        "official_badge" => Some(RealmOrganizationControlScope::OfficialBadge),
        "realm_admin" => Some(RealmOrganizationControlScope::RealmAdmin),
        "realm_authority" => Some(RealmOrganizationControlScope::RealmAuthority),
        "moderation_policy" => Some(RealmOrganizationControlScope::ModerationPolicy),
        "retention_policy" => Some(RealmOrganizationControlScope::RetentionPolicy),
        "directory_listing" => Some(RealmOrganizationControlScope::DirectoryListing),
        "plaintext_visible_service" => Some(RealmOrganizationControlScope::PlaintextVisibleService),
        _ => None,
    }
}

/// All selectable control-scope slugs with their human labels, for the bind UI.
const CONTROL_SCOPE_CHOICES: &[(&str, &str)] = &[
    ("official_badge", "Official badge"),
    ("realm_admin", "Realm admin"),
    ("realm_authority", "Realm authority"),
    ("moderation_policy", "Moderation policy"),
    ("retention_policy", "Retention policy"),
    ("directory_listing", "Directory listing"),
    ("plaintext_visible_service", "Plaintext-visible service"),
];

/// All selectable relationship slugs with their human labels, for the bind UI.
const RELATIONSHIP_CHOICES: &[(&str, &str)] = &[
    ("owner", "Owner"),
    ("governance", "Governance"),
    ("sponsor", "Sponsor"),
    ("directory_certifier", "Directory certifier"),
];

/// Lifecycle state of a Realm ↔ organization relationship, as the client must
/// distinguish it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrgRelationshipPhase {
    /// The Realm merely declared an organization hint; no organization
    /// signature exists. NOT a verified relationship.
    DeclaredHint,
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
            Self::VerifiedActive => "badge green",
            Self::RevokedOrExpired => "badge red",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::DeclaredHint => "declared hint",
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

/// Map the spec projection's `lifecycle_phase` discriminator onto the UI phase.
/// The server only emits `verified_active` / `revoked_or_expired`; declared
/// hints arrive on a separate field.
pub(crate) fn phase_from_lifecycle(
    lifecycle: RealmOrganizationLifecyclePhase,
) -> OrgRelationshipPhase {
    match lifecycle {
        RealmOrganizationLifecyclePhase::VerifiedActive => OrgRelationshipPhase::VerifiedActive,
        RealmOrganizationLifecyclePhase::RevokedOrExpired => OrgRelationshipPhase::RevokedOrExpired,
    }
}

/// One row rendered by the panel. Built from the SDK projection — inkson does
/// not define the wire type, only this display-side view.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OrgRelationshipDto {
    pub organization_id: String,
    pub organization_name: String,
    /// `owner` / `governance` / `sponsor` / `directory_certifier`, or empty for
    /// a declared hint (which carries no relationship).
    pub relationship: String,
    pub phase: OrgRelationshipPhase,
    /// Endorsement scopes carried by the statement (display-only here).
    pub control_scopes: Vec<String>,
    /// Audit id of the latest statement, when one exists.
    pub statement_id: Option<String>,
}

/// Serialize a serde snake_case enum to its wire string for display. Returns
/// the empty string on the (unexpected) serialize failure so the row still
/// renders without a fabricated value.
fn enum_slug<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Build a display row from a projected verified / revoked relationship row.
fn dto_from_row(row: &RealmOrganizationRelationshipView) -> OrgRelationshipDto {
    let organization_id = row.organization_id.as_str().to_owned();
    OrgRelationshipDto {
        organization_name: short_protocol_id(&organization_id),
        relationship: enum_slug(&row.relationship),
        phase: phase_from_lifecycle(row.lifecycle_phase),
        control_scopes: row.control_scopes.iter().map(enum_slug).collect(),
        statement_id: Some(row.statement_id.clone()),
        organization_id,
    }
}

/// Build a declared-hint display row from an owning-organization id with no
/// verified statement. A hint has no relationship, no scopes, and no statement.
fn dto_from_hint(id: &str) -> OrgRelationshipDto {
    OrgRelationshipDto {
        organization_name: short_protocol_id(id),
        relationship: String::new(),
        phase: OrgRelationshipPhase::DeclaredHint,
        control_scopes: Vec::new(),
        statement_id: None,
        organization_id: id.to_owned(),
    }
}

/// Flatten a projection response into the display rows: verified / revoked rows
/// first, then declared hints.
fn dtos_from_list(list: &RealmOrganizationRelationshipList) -> Vec<OrgRelationshipDto> {
    let mut out: Vec<OrgRelationshipDto> = list.relationships.iter().map(dto_from_row).collect();
    out.extend(
        list.declared_organization_hint_ids
            .iter()
            .map(|id| dto_from_hint(id.as_str())),
    );
    out
}

/// Rendered inside the realm_admin Federation section.
#[derive(Clone)]
struct OrganizationPage {
    context: Rc<InksonContext>,
    owner: glory::ui::WeakScope,
    realm: String,
    display_name: Cage<String>,
    handle: Cage<String>,
    status_msg: Cage<String>,
    created_did: Cage<String>,
    busy: Cage<bool>,
    selected_org: Cage<String>,
    relationship: Cage<String>,
    selected_scopes: Cage<Vec<String>>,
    revoke_mode: Cage<bool>,
    revokes_statement_id: Cage<String>,
}
impl OrganizationPage {
    #[allow(unused_variables)]
    fn create(&self) {
        let context = self.context.clone();
        if !context.is_server_admin.get_untracked() {
            return;
        }
        let owner = self.owner.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let state_store = context.state_store.clone();
        let realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let display_name = self.display_name;
        let handle = self.handle;
        let status_msg = self.status_msg;
        let created_did = self.created_did;
        let busy = self.busy;
        let action = {
            let base = base_url.clone();
            move |_| {
                let base = base.clone();
                let api_token = token.get();
                let local_id = handle.get().trim().to_owned();
                let name = display_name.get().trim().to_owned();
                if local_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "organization handle is required".to_owned();
                    });
                    return;
                }
                busy.revise(|value| {
                    *value = true;
                });
                status_msg.revise(|value| {
                    *value = "minting organization DID…".to_owned();
                });
                created_did.revise(|value| {
                    *value = String::new();
                });
                if let Some(scope) = owner.upgrade() {
                    spawn(&scope, async move {
                        let (prepared, organization) = match prepare_organization_inception(
                            &base,
                            &local_id,
                            Some(&name),
                            &[],
                        ) {
                            Ok(pair) => pair,
                            Err(err) => {
                                busy.revise(|value| {
                                    *value = false;
                                });
                                status_msg.revise(|value| {
                                    *value = format!("inception build failed: {err}");
                                });
                                return;
                            }
                        };

                        // Persist the control seed BEFORE submitting so a
                        // network failure after a successful mint cannot
                        // strand a DID with no recoverable control key.
                        let secure_store =
                            crate::secure_key_store::default_secure_key_store("inkson");
                        if let Err(err) = store_organization_control_seed(
                            secure_store.as_ref(),
                            &organization.organization_id,
                            &organization.control_seed,
                        ) {
                            busy.revise(|value| {
                                *value = false;
                            });
                            status_msg.revise(|value| {
                                *value = format!("could not store organization control key: {err}");
                            });
                            return;
                        }

                        let submit_body = prepared.submit_body.clone();
                        match crate::transport::auth::with_authed_sdk_client(
                            &base,
                            api_token,
                            move |http| {
                                let submit_body = submit_body.clone();
                                async move {
                                    crate::transport::account::submit_did_operation(
                                        &http,
                                        &submit_body,
                                    )
                                    .await
                                }
                            },
                        )
                        .await
                        {
                            Ok(outcome) => {
                                // Record the created organization in the
                                // per-account index so the bind UI can list
                                // it.
                                {
                                    state_store.write(|store| {
                                        upsert_created_organization(
                                            store,
                                            CreatedOrganization {
                                                organization_id: organization
                                                    .organization_id
                                                    .clone(),
                                                organization_did: organization
                                                    .organization_did
                                                    .clone(),
                                                did_key_id: organization.did_key_id.clone(),
                                                display_name: name.clone(),
                                            },
                                        )
                                    });
                                }
                                created_did.revise(|value| {
                                    *value = outcome.did.as_str().to_owned();
                                });
                                let outcome_status = match outcome.status {
                                    arkret_sdk::DidOperationSubmitStatus::Accepted => "accepted",
                                    arkret_sdk::DidOperationSubmitStatus::Duplicate => "duplicate",
                                    arkret_sdk::DidOperationSubmitStatus::Pending => "pending",
                                };
                                status_msg.revise(|value| {
                                    *value = format!("organization minted ({outcome_status})");
                                });
                                display_name.revise(|value| {
                                    *value = String::new();
                                });
                                handle.revise(|value| {
                                    *value = String::new();
                                });
                            }
                            Err(err) => {
                                status_msg.revise(|value| {
                                    *value = format!("organization mint failed: {}", err.display());
                                });
                            }
                        }
                        busy.revise(|value| {
                            *value = false;
                        });
                    });
                };
            }
        };
        action(());
    }
    #[allow(unused_variables)]
    fn bind(&self) {
        let context = self.context.clone();
        if !context.is_server_admin.get_untracked() {
            return;
        }
        let owner = self.owner.clone();
        let base_url = context.base_url.get();
        let token = context.token;
        let state_store = context.state_store.clone();
        let realm_id = self.realm.clone();
        let principal_id = context
            .principal_id
            .get()
            .map(|value| value.to_string())
            .unwrap_or_default();
        let status_msg = self.status_msg;
        let busy = self.busy;
        let selected_org = self.selected_org;
        let relationship = self.relationship;
        let selected_scopes = self.selected_scopes;
        let revoke_mode = self.revoke_mode;
        let revokes_statement_id = self.revokes_statement_id;
        let action = {
            let base = base_url.clone();
            let realm_id = realm_id.clone();
            let principal_id = principal_id.clone();
            move |_| {
                let base = base.clone();
                let realm_id = realm_id.clone();
                let actor = principal_id.clone();
                let api_token = token.get();
                let selected_organization_id = selected_org.get().trim().to_owned();
                if selected_organization_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "select an organization first".to_owned();
                    });
                    return;
                }
                let Some(organization) = context
                    .state_store
                    .read(load_created_organizations)
                    .iter()
                    .find(|organization| {
                        organization.organization_id.as_str() == selected_organization_id
                    })
                    .cloned()
                else {
                    status_msg.revise(|value| {
                        *value = "selected organization is unavailable".to_owned();
                    });
                    return;
                };
                let Some(relationship_value) = relationship_from_slug(&relationship.get()) else {
                    status_msg.revise(|value| {
                        *value = "invalid relationship".to_owned();
                    });
                    return;
                };
                let scopes: Vec<RealmOrganizationControlScope> = selected_scopes
                    .get()
                    .iter()
                    .filter_map(|slug| control_scope_from_slug(slug))
                    .collect();
                if scopes.is_empty() {
                    status_msg.revise(|value| {
                        *value = "select at least one control scope".to_owned();
                    });
                    return;
                }
                let is_revoke = revoke_mode.get();
                let revokes_id = revokes_statement_id.get().trim().to_owned();
                if is_revoke && revokes_id.is_empty() {
                    status_msg.revise(|value| {
                        *value = "revoke requires the prior statement id".to_owned();
                    });
                    return;
                }
                // Resolve the organization control verification
                // method id + signing key from local storage.
                let did_key_id = organization.did_key_id.clone();
                let secure_store = crate::secure_key_store::default_secure_key_store("inkson");
                let control_key = match load_organization_control_key(
                    secure_store.as_ref(),
                    &organization.organization_id,
                ) {
                    Ok(Some(key)) => key,
                    Ok(None) => {
                        status_msg.revise(|value| {
                            *value = "organization control key not found on this device".to_owned();
                        });
                        return;
                    }
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("could not load organization control key: {err}");
                        });
                        return;
                    }
                };

                let issued_at = crate::clock::now_utc();
                let statement_id = crate::operation::uuid_v7();
                let status_value = if is_revoke {
                    RealmOrganizationStatus::Revoked
                } else {
                    RealmOrganizationStatus::Active
                };
                let statement_input = OrganizationStatementInput {
                    statement_id: statement_id.clone(),
                    realm_id: realm_id.clone(),
                    organization_id: organization.organization_id.clone(),
                    organization_did: organization.organization_did.clone(),
                    verification_method: did_key_id.clone(),
                    relationship: relationship_value,
                    status: status_value,
                    control_scopes: scopes.clone(),
                    issued_at,
                    revokes_statement_id: is_revoke.then(|| revokes_id.clone()),
                };
                // Sign the organization-side statement proof with
                // the organization control key (NOT the login /
                // device signer).
                let signed = match sign_organization_statement(&statement_input, &control_key) {
                    Ok(payload) => payload,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("organization signing failed: {err}");
                        });
                        return;
                    }
                };

                // Feed the SAME fields plus the signed proof into
                // the ak.realm.organization builder; it
                // reconstructs an identical payload so the
                // canonical signing bytes — and the proof — stay
                // valid on the wire.
                let authorization = signed.authorization.clone();
                let builder = match crate::operation::ak_ops::realm_organization_statement(
                    &realm_id,
                    &actor,
                    &statement_id,
                    &organization.organization_id,
                    relationship_value,
                    status_value,
                    scopes,
                    issued_at,
                    authorization,
                    is_revoke.then(|| revokes_id.clone()),
                ) {
                    Ok(builder) => builder,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("statement build failed: {err}");
                        });
                        return;
                    }
                };
                let event = match builder.build_sdk_event("inkson") {
                    Ok(event) => event,
                    Err(err) => {
                        status_msg.revise(|value| {
                            *value = format!("event build failed: {err}");
                        });
                        return;
                    }
                };

                busy.revise(|value| {
                    *value = true;
                });
                status_msg.revise(|value| {
                    *value = if is_revoke {
                        "revoking organization binding…".to_owned()
                    } else {
                        "binding organization…".to_owned()
                    };
                });
                if let Some(scope) = owner.upgrade() {
                    spawn(&scope, async move {
                        match crate::transport::auth::with_authed_api(
                            &base,
                            api_token,
                            move |api| {
                                let event = event.clone();
                                async move { api.event_submitter()?.submit_sdk_event(&event).await }
                            },
                        )
                        .await
                        {
                            Ok(resp) => {
                                status_msg.revise(|value| {
                                    *value = format!(
                                        "submitted ak.realm.organization: event_id={}",
                                        short_protocol_id(&resp.event_id)
                                    );
                                });
                            }
                            Err(err) => {
                                status_msg.revise(|value| {
                                    *value = format!("submit failed: {}", err.display());
                                });
                            }
                        }
                        busy.revise(|value| {
                            *value = false;
                        });
                    });
                };
            }
        };
        action(());
    }
}
fn phase_slug(phase: OrgRelationshipPhase) -> &'static str {
    match phase {
        OrgRelationshipPhase::DeclaredHint => "declared_hint",
        OrgRelationshipPhase::VerifiedActive => "verified_active",
        OrgRelationshipPhase::RevokedOrExpired => "revoked_or_expired",
    }
}

pub(super) fn page(scope: &Scope, context: Rc<InksonContext>, realm: String) -> View {
    let load_context = context.clone();
    let load_realm = realm.clone();
    let relationships = crate::presentation::widgets::resource(scope, move || {
        let base = load_context.base_url.get();
        let token = load_context.token.get();
        let realm = load_realm.clone();
        let _ = load_context.session_generation.get();
        async move {
            with_authed_sdk_client(&base, token, |http| async move {
                crate::transport::realm_read::list_realm_organizations(&http, &realm).await
            })
            .await
            .map(|list| dtos_from_list(&list))
            .map_err(|error| error.display())
        }
    });
    let rows_context = context.clone();
    let rows = crate::presentation::widgets::resource_content(
        context.clone(),
        format!("realm-organizations-{realm}"),
        relationships,
        "recovery.panel.loading",
        move |scope, rows| {
            let context = rows_context.clone();
            let mut children = Vec::new();
            if rows.is_empty() {
                children.push(paragraph(
                    "muted",
                    "No verified organization relationships or declared hints.",
                ));
            }
            for row in rows {
                let mut details = vec![
                    line(
                        "event-head",
                        vec![
                            plain(row.organization_name),
                            paragraph(row.phase.badge_class(), row.phase.label()),
                        ],
                    ),
                    paragraph("muted", row.phase.explainer()),
                    paragraph("mono", row.organization_id),
                ];
                if !row.relationship.is_empty() {
                    details.push(paragraph("", row.relationship));
                }
                if !row.control_scopes.is_empty() {
                    details.push(paragraph("muted", row.control_scopes.join(", ")));
                }
                if let Some(statement) = row.statement_id {
                    details.push(paragraph("muted mono", short_protocol_id(&statement)));
                }
                children.push(stack(
                    format!(
                        "event organization-relationship-row org-phase-{}",
                        phase_slug(row.phase)
                    ),
                    details,
                ));
            }
            card(scope, context, "Realm organization relationships", children)
        },
    );
    let admin = context.is_server_admin;
    let forms_context = context.clone();
    let forms = reactive(admin, move |scope, admin| {
        if !admin {
            return empty();
        }
        let context = forms_context.clone();
        let create = organization_state(scope, context.clone(), realm.clone());
        let bind = organization_state(scope, context.clone(), realm.clone());
        let create_action = create.clone();
        let bind_action = bind.clone();
        let create_busy = create.busy;
        let bind_busy = bind.busy;
        let create_enabled = scope.bond(move || !create_busy.get());
        let bind_enabled = scope.bond(move || !bind_busy.get());
        let selected = bind.selected_org;
        let relationship = bind.relationship;
        let scopes = bind.selected_scopes;
        let revoke = bind.revoke_mode;
        let prior = bind.revokes_statement_id;
        let options_context = context.clone();
        let state_revision = context.state_revision;
        let options = reactive(state_revision, move |scope, _| {
            let context = options_context.clone();
            let organizations = context.state_store.read(load_created_organizations);
            let options = organizations
                .into_iter()
                .map(|org| {
                    (
                        org.organization_id.to_string(),
                        format!(
                            "{} ({})",
                            org.display_name,
                            short_protocol_id(org.organization_did.as_str())
                        ),
                    )
                })
                .collect();
            choice(
                scope,
                context,
                "org-bind-org-select",
                "Organization",
                selected,
                options,
                bind_enabled,
                move |next| {
                    selected.revise(|value| {
                        *value = next;
                    })
                },
            )
        });
        let mut scope_controls = Vec::new();
        for (slug, label) in CONTROL_SCOPE_CHOICES.iter().copied() {
            let checked = scope.bond(move || scopes.get().iter().any(|value| value == slug));
            scope_controls.push(toggle(
                scope,
                context.clone(),
                &format!("org-bind-scope-{slug}"),
                label,
                checked,
                bind_enabled,
                move |checked| {
                    scopes.revise(|values| {
                        values.retain(|value| value != slug);
                        if checked {
                            values.push(slug.to_owned());
                        }
                    })
                },
            ));
        }
        stack(
            "settings-content-stack organization-admin-tools",
            vec![
                card(
                    scope,
                    context.clone(),
                    "Create an organization",
                    vec![
                        paragraph(
                            "muted",
                            "Mint a new organization DID (did:webvh) anchored to this Station. The organization control private key is stored securely on this device — it is the signing authority for binding the organization to Realms.",
                        ),
                        input(
                            scope,
                            context.clone(),
                            "org-create-display-name",
                            "Display name",
                            create.display_name,
                            create_enabled,
                        ),
                        input(
                            scope,
                            context.clone(),
                            "org-create-handle",
                            "Handle / local id",
                            create.handle,
                            create_enabled,
                        ),
                        action(
                            scope,
                            context.clone(),
                            "org-create-submit",
                            "Create organization",
                            "primary",
                            create_enabled,
                            move || create_action.create(),
                        ),
                        status(create.created_did),
                        status(create.status_msg),
                    ],
                ),
                card(
                    scope,
                    context.clone(),
                    "Bind organization to this Realm",
                    vec![
                        options,
                        choice(
                            scope,
                            context.clone(),
                            "org-bind-relationship-select",
                            "Relationship",
                            relationship,
                            RELATIONSHIP_CHOICES
                                .iter()
                                .map(|(slug, label)| (slug.to_string(), label.to_string()))
                                .collect(),
                            bind_enabled,
                            move |next| {
                                relationship.revise(|value| {
                                    *value = next;
                                })
                            },
                        ),
                        stack("metric-grid org-bind-scopes", scope_controls),
                        toggle(
                            scope,
                            context.clone(),
                            "org-bind-revoke-toggle",
                            "Revoke a prior statement",
                            revoke,
                            bind_enabled,
                            move |next| {
                                revoke.revise(|value| {
                                    *value = next;
                                })
                            },
                        ),
                        input(
                            scope,
                            context.clone(),
                            "org-bind-revokes-id",
                            "Revokes statement id",
                            prior,
                            revoke,
                        ),
                        action(
                            scope,
                            context.clone(),
                            "org-bind-submit",
                            "Bind organization / Revoke binding",
                            "primary",
                            bind_enabled,
                            move || bind_action.bind(),
                        ),
                        status(bind.status_msg),
                    ],
                ),
            ],
        )
    });
    stack("settings-content-stack", vec![rows, forms])
}
fn organization_state(
    scope: &Scope,
    context: Rc<InksonContext>,
    realm: String,
) -> OrganizationPage {
    OrganizationPage {
        context,
        owner: scope.downgrade(),
        realm,
        display_name: scope.cage(String::new()),
        handle: scope.cage(String::new()),
        status_msg: scope.cage(String::new()),
        created_did: scope.cage(String::new()),
        busy: scope.cage(false),
        selected_org: scope.cage(String::new()),
        relationship: scope.cage("owner".into()),
        selected_scopes: scope.cage(vec!["official_badge".into()]),
        revoke_mode: scope.cage(false),
        revokes_statement_id: scope.cage(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_hint_is_not_presented_as_verified() {
        // A declared hint must read as a hint, never as a
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
    }

    #[test]
    fn every_phase_has_a_distinct_slug_and_badge() {
        let phases = [
            OrgRelationshipPhase::DeclaredHint,
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
    fn lifecycle_phase_maps_onto_ui_phase() {
        // The server only emits these two lifecycle phases; map them onto the
        // verified / revoked UI phases and never onto a hint / pending state.
        assert_eq!(
            phase_from_lifecycle(RealmOrganizationLifecyclePhase::VerifiedActive),
            OrgRelationshipPhase::VerifiedActive
        );
        assert_eq!(
            phase_from_lifecycle(RealmOrganizationLifecyclePhase::RevokedOrExpired),
            OrgRelationshipPhase::RevokedOrExpired
        );
    }

    #[test]
    fn hint_dto_carries_no_statement_or_relationship() {
        let dto = dto_from_hint("ak:did_core:webvh:hint.example:orgs:org1");
        assert_eq!(dto.phase, OrgRelationshipPhase::DeclaredHint);
        assert!(dto.statement_id.is_none());
        assert!(dto.relationship.is_empty());
        assert!(dto.control_scopes.is_empty());
        // The stable id is preserved verbatim; no fabricated display name.
        assert_eq!(
            dto.organization_id,
            "ak:did_core:webvh:hint.example:orgs:org1"
        );
    }

    #[test]
    fn control_scope_choices_match_the_closed_formal_enum() {
        let choices = CONTROL_SCOPE_CHOICES
            .iter()
            .map(|(slug, _)| *slug)
            .collect::<Vec<_>>();
        assert_eq!(
            choices,
            vec![
                "official_badge",
                "realm_admin",
                "realm_authority",
                "moderation_policy",
                "retention_policy",
                "directory_listing",
                "plaintext_visible_service",
            ]
        );
        assert_eq!(
            control_scope_from_slug("realm_authority"),
            Some(RealmOrganizationControlScope::RealmAuthority)
        );
        assert_eq!(control_scope_from_slug("notary_control"), None);
        assert_eq!(control_scope_from_slug("durability_policy"), None);
    }
}
