//! YGN-ORG-03 / SOL-ORG-06 (client consumer) — Realm ↔ organization
//! relationship view.
//!
//! The client must NOT conflate "this Realm declared an organization hint"
//! with "an organization signed and the Realm accepted a verified
//! relationship". This panel makes the lifecycle states explicit.
//!
//! Read side: the verified relationships and declared hints are read from the
//! spec-canonical projection `ck.self.realm_organization.query.list`
//! (`GET /_cokret/self/realms/{realm_id}/organizations`) via
//! [`crate::api::CokretApi::list_realm_organizations`]. The server only returns
//! `verified_active` / `revoked_or_expired` rows plus
//! `declared_organization_hints`.
//!
//! Write side: binding a Realm to an organization and signing organization-side
//! statements (and revocations) is the organization DID controller's authority,
//! exercised in the admin console (sodmin). inkson does NOT mint or submit
//! organization-side signatures and does NOT call coauth admin endpoints; this
//! panel only reads and links operators to where the binding flow lives.

use cokret_sdk::models::{
    RealmOrganizationControlScope, RealmOrganizationLifecyclePhase, RealmOrganizationRelationship,
    RealmOrganizationRelationshipList, RealmOrganizationRelationshipRow, RealmOrganizationStatus,
};
use dioxus::prelude::*;

use crate::organization::{
    OrganizationStatementInput, load_organization_control_key, prepare_organization_inception,
    sign_organization_statement, store_organization_control_seed,
};
use crate::views::helpers::{short_protocol_id, with_authed_api};

/// Context-provided server-administrator signal (D0). Newtype-wrapped so the
/// context lookup can't collide with any other bare `Signal<bool>`. Sourced from
/// `AccountView.is_server_admin` (the server's configured admin principal set),
/// NOT from any Realm-role `is_admin` placeholder.
#[derive(Clone, Copy)]
pub struct ServerAdminSignal(pub Signal<bool>);

/// Best-effort read of the context-provided server-admin signal. Returns `false`
/// when no provider is mounted (e.g. unit tests) so callers fail closed: the
/// organization create/bind write UI stays hidden unless the viewer is a proven
/// server administrator.
pub fn is_server_admin() -> bool {
    try_consume_context::<ServerAdminSignal>()
        .map(|wrap| (wrap.0)())
        .unwrap_or(false)
}

/// SecureKeyStore-adjacent local index of organizations this administrator has
/// minted on this device. Stored as JSON in the per-account private-data store
/// so the bind UI can offer a dropdown of already-created organizations. The
/// control private keys themselves live in the secure key store, keyed by DID.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CreatedOrganization {
    pub did: String,
    /// Organization control verification method id (`<did>#did-key-1`).
    pub did_key_id: String,
    /// Operator-facing label captured at creation time.
    pub display_name: String,
}

/// Private-data key (per account) for the created-organizations index. No
/// version suffix per the storage-key convention.
const CREATED_ORGANIZATIONS_KEY: &str = "organizations.created";

/// Read the created-organizations index for `account_did` from local state.
fn load_created_organizations(
    store: &crate::local_state::LocalStateStore,
    account_did: &str,
) -> Vec<CreatedOrganization> {
    store
        .load_private_data(account_did, CREATED_ORGANIZATIONS_KEY)
        .and_then(|raw| serde_json::from_str::<Vec<CreatedOrganization>>(&raw).ok())
        .unwrap_or_default()
}

/// Append (or replace by DID) a created organization into the per-account index.
fn upsert_created_organization(
    store: &mut crate::local_state::LocalStateStore,
    account_did: &str,
    entry: CreatedOrganization,
) {
    let mut list = load_created_organizations(store, account_did);
    if let Some(existing) = list.iter_mut().find(|item| item.did == entry.did) {
        *existing = entry;
    } else {
        list.push(entry);
    }
    if let Ok(serialized) = serde_json::to_string(&list) {
        store.save_private_data(account_did, CREATED_ORGANIZATIONS_KEY, serialized);
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
        "notary_control" => Some(RealmOrganizationControlScope::NotaryControl),
        "policy_server" => Some(RealmOrganizationControlScope::PolicyServer),
        "delivery_binding_policy" => Some(RealmOrganizationControlScope::DeliveryBindingPolicy),
        "durability_policy" => Some(RealmOrganizationControlScope::DurabilityPolicy),
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
    ("notary_control", "Notary control"),
    ("policy_server", "Policy server"),
    ("delivery_binding_policy", "Delivery binding policy"),
    ("durability_policy", "Durability policy"),
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
    /// The organization-side authorization has been requested but the signed
    /// statement is not yet accepted into Realm history. Client-side bind-flow
    /// state only — the server never projects this, so the read-only panel never
    /// constructs it; retained as the lifecycle vocabulary the sodmin-coordinated
    /// bind flow uses.
    #[allow(dead_code)]
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

/// Map the spec projection's `lifecycle_phase` discriminator onto the UI phase.
/// The server only emits `verified_active` / `revoked_or_expired`; declared
/// hints arrive on a separate field and `pending_consent` is client-only.
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
    pub organization_did: String,
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
fn dto_from_row(row: &RealmOrganizationRelationshipRow) -> OrgRelationshipDto {
    let organization_did = row.organization_id.as_str().to_owned();
    OrgRelationshipDto {
        organization_name: short_protocol_id(&organization_did),
        relationship: enum_slug(&row.relationship),
        phase: phase_from_lifecycle(row.lifecycle_phase),
        control_scopes: row.control_scopes.iter().map(enum_slug).collect(),
        statement_id: Some(row.statement_id.clone()),
        organization_did,
    }
}

/// Build a declared-hint display row from an owning-organization DID with no
/// verified statement. A hint has no relationship, no scopes, and no statement.
fn dto_from_hint(did: &str) -> OrgRelationshipDto {
    OrgRelationshipDto {
        organization_name: short_protocol_id(did),
        relationship: String::new(),
        phase: OrgRelationshipPhase::DeclaredHint,
        control_scopes: Vec::new(),
        statement_id: None,
        organization_did: did.to_owned(),
    }
}

/// Flatten a projection response into the display rows: verified / revoked rows
/// first, then declared hints.
fn dtos_from_list(list: &RealmOrganizationRelationshipList) -> Vec<OrgRelationshipDto> {
    let mut out: Vec<OrgRelationshipDto> = list.relationships.iter().map(dto_from_row).collect();
    out.extend(
        list.declared_organization_hints
            .iter()
            .map(|did| dto_from_hint(did.as_str())),
    );
    out
}

/// YGN-ORG-03 panel. Rendered inside the realm_admin Federation section.
#[component]
pub fn RealmOrganizationPanel(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    /// Authenticated account DID (the operator). Used to scope the locally
    /// stored organization control keys + created-organization index, and as the
    /// outer event `actor`.
    account_did: String,
    state_store: Signal<crate::local_state::LocalStateStore>,
) -> Element {
    // D0/D4 gate: the organization create + bind/revoke write UI is rendered ONLY
    // for a proven server administrator (`AccountView.is_server_admin`). Read the
    // context signal here so the whole write surface can be conditionally
    // mounted; non-administrators keep the read-only relationship list below.
    let server_admin = is_server_admin();
    // Read the verified relationships + declared hints from the spec
    // projection. Read-only: no bind / sign happens here.
    let relationships = use_resource({
        let base_url = base_url.clone();
        let realm_id = realm_id.clone();
        move || {
            let base_url = base_url.clone();
            let realm_id = realm_id.clone();
            let session = token();
            async move {
                with_authed_api(&base_url, session, |api| async move {
                    api.list_realm_organizations(&realm_id).await
                })
                .await
                .map(|list| dtos_from_list(&list))
                .map_err(|err| format!("{err:?}"))
            }
        }
    });

    rsx! {
        div { class: "event", "data-testid": "realm-organization-panel",
            div { class: "event-head",
                span { "Organization control" }
                span { title: "{realm_id}", "{short_protocol_id(&realm_id)}" }
            }
            div { class: "muted",
                "View this Realm's verified organization relationships and declared hints. \
                 An organization principal is a separate DID controller: binding and \
                 organization-side signing are performed in the admin console (sodmin), \
                 never by your login session. This panel is read-only."
            }

            // Current relationships — each row shows its lifecycle phase so a
            // declared hint can never be mistaken for a verified relationship.
            match &*relationships.read_unchecked() {
                None => rsx! {
                    div { class: "muted", "data-testid": "org-relationship-loading",
                        "Loading organization relationships…"
                    }
                },
                Some(Err(err)) => rsx! {
                    div { class: "muted", "data-testid": "org-relationship-error",
                        "Could not load organization relationships: {err}"
                    }
                },
                Some(Ok(rows)) if rows.is_empty() => rsx! {
                    div { class: "metric-grid", "data-testid": "org-relationship-list",
                        div { class: "muted", "data-testid": "org-relationship-empty",
                            "No verified organization relationships or declared hints for this Realm."
                        }
                    }
                },
                Some(Ok(rows)) => rsx! {
                    div { class: "metric-grid", "data-testid": "org-relationship-list",
                        for rel in rows.clone() {
                            {
                                let phase = rel.phase;
                                let org_did = rel.organization_did.clone();
                                let scopes = rel.control_scopes.join(", ");
                                let relationship_suffix = if rel.relationship.is_empty() {
                                    String::new()
                                } else {
                                    format!(" · {}", rel.relationship)
                                };
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
                                        div { class: "muted", title: "{org_did}", "{short_protocol_id(&org_did)}{relationship_suffix}" }
                                        div { class: "muted", "data-testid": "org-relationship-explainer", "{phase.explainer()}" }
                                        if !scopes.is_empty() {
                                            div { class: "muted", "data-testid": "org-relationship-scopes", "scopes: {scopes}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
            }

            // D2 / D3 — server-administrator-only write surface. The
            // organization principal is a distinct `did:webvh` DID controller;
            // creating it and signing its relationship statements is an operator
            // authority, gated on `AccountView.is_server_admin`. Non-admins never
            // see these controls (D4) and keep only the read-only list above.
            if server_admin {
                OrganizationCreatePanel {
                    base_url: base_url.clone(),
                    token,
                    account_did: account_did.clone(),
                    state_store,
                }
                OrganizationBindPanel {
                    base_url: base_url.clone(),
                    token,
                    realm_id: realm_id.clone(),
                    account_did: account_did.clone(),
                    state_store,
                }
            } else {
                div { class: "muted", "data-testid": "org-bind-readonly-note",
                    "Binding a Realm to an organization, and revoking it, requires an \
                     organization-authorized signature from the organization DID controller, \
                     which only a server administrator can mint and sign here. This view is \
                     read-only for your account."
                }
            }
        }
    }
}

/// D2 — create a new organization: mint its `did:webvh`, persist the control
/// key locally, and display the minted DID. Server-administrator only (mounted
/// only when `is_server_admin()` is true).
#[component]
fn OrganizationCreatePanel(
    base_url: String,
    token: Signal<String>,
    account_did: String,
    state_store: Signal<crate::local_state::LocalStateStore>,
) -> Element {
    let mut display_name = use_signal(String::new);
    let mut handle = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut created_did = use_signal(String::new);
    let mut busy = use_signal(|| false);

    rsx! {
        div { class: "workflow-form", "data-testid": "org-create-form",
            div { class: "event-head",
                span { "Create an organization" }
                span { class: "badge green", "server admin" }
            }
            div { class: "muted",
                "Mint a new organization DID (did:webvh) anchored to this Principal Server. \
                 The organization control private key is stored securely on this device — it \
                 is the signing authority for binding the organization to Realms."
            }
            div { class: "field",
                label { "Display name" }
                input {
                    r#type: "text",
                    "data-testid": "org-create-display-name",
                    value: "{display_name}",
                    placeholder: "Acme Foundation",
                    oninput: move |evt| display_name.set(evt.value()),
                }
            }
            div { class: "field",
                label { "Handle / local id" }
                input {
                    r#type: "text",
                    "data-testid": "org-create-handle",
                    value: "{handle}",
                    placeholder: "acme",
                    oninput: move |evt| handle.set(evt.value()),
                }
            }
            div { class: "actions",
                button {
                    r#type: "button",
                    class: "primary",
                    "data-testid": "org-create-submit",
                    disabled: busy(),
                    onclick: {
                        let base = base_url.clone();
                        let account_did = account_did.clone();
                        move |_| {
                            let base = base.clone();
                            let account_did = account_did.clone();
                            let api_token = token();
                            let local_id = handle().trim().to_owned();
                            let name = display_name().trim().to_owned();
                            if local_id.is_empty() {
                                status_msg.set("organization handle is required".to_owned());
                                return;
                            }
                            busy.set(true);
                            status_msg.set("minting organization DID…".to_owned());
                            created_did.set(String::new());
                            spawn(async move {
                                // The organization document records the deployment's
                                // service DID as its device-enrollment-authority
                                // service entry (uniform embedded-webvh profile);
                                // the organization itself authorizes no end-user
                                // devices, and the relationship-binding verifier
                                // does not depend on this field.
                                let enrollment_authority = match crate::views::helpers::with_authed_sdk_client(
                                    &base,
                                    api_token.clone(),
                                    |http| async move { crate::account_api::identity_describe(&http).await },
                                )
                                .await
                                {
                                    Ok(describe) => describe.service_did.as_str().to_owned(),
                                    Err(err) => {
                                        busy.set(false);
                                        status_msg.set(format!(
                                            "could not resolve identity authority: {}",
                                            err.display()
                                        ));
                                        return;
                                    }
                                };

                                let (prepared, organization) = match prepare_organization_inception(
                                    &base,
                                    &local_id,
                                    Some(&name),
                                    &[],
                                    &enrollment_authority,
                                ) {
                                    Ok(pair) => pair,
                                    Err(err) => {
                                        busy.set(false);
                                        status_msg.set(format!("inception build failed: {err}"));
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
                                    &organization.did,
                                    &organization.control_seed,
                                ) {
                                    busy.set(false);
                                    status_msg.set(format!(
                                        "could not store organization control key: {err}"
                                    ));
                                    return;
                                }

                                let submit_body = prepared.submit_body.clone();
                                match crate::views::helpers::with_authed_api(
                                    &base,
                                    api_token,
                                    move |api| {
                                        let submit_body = submit_body.clone();
                                        async move { api.submit_did_operation(&submit_body).await }
                                    },
                                )
                                .await
                                {
                                    Ok(outcome) => {
                                        // Record the created organization in the
                                        // per-account index so the bind UI can list
                                        // it.
                                        {
                                            let mut store = state_store.write();
                                            upsert_created_organization(
                                                &mut store,
                                                &account_did,
                                                CreatedOrganization {
                                                    did: organization.did.clone(),
                                                    did_key_id: organization.did_key_id.clone(),
                                                    display_name: name.clone(),
                                                },
                                            );
                                        }
                                        created_did.set(outcome.did.as_str().to_owned());
                                        status_msg.set(format!(
                                            "organization minted ({})",
                                            outcome.status
                                        ));
                                        display_name.set(String::new());
                                        handle.set(String::new());
                                    }
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "organization mint failed: {}",
                                            err.display()
                                        ));
                                    }
                                }
                                busy.set(false);
                            });
                        }
                    },
                    "Create organization"
                }
            }
            if !created_did().is_empty() {
                div {
                    class: "muted",
                    "data-testid": "org-create-result",
                    "data-organization-did": "{created_did}",
                    title: "{created_did}",
                    "Created: {created_did}"
                }
            }
            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "org-create-status", "{status_msg}" }
            }
        }
    }
}

/// D3 — bind a created organization to this Realm (or revoke a prior binding).
/// The organization-side statement proof is signed with the organization control
/// key; the resulting `ck.realm.organization` event is submitted on the
/// operator's self plane. Server-administrator only.
#[component]
fn OrganizationBindPanel(
    base_url: String,
    token: Signal<String>,
    realm_id: String,
    account_did: String,
    state_store: Signal<crate::local_state::LocalStateStore>,
) -> Element {
    let created = use_memo({
        let account_did = account_did.clone();
        move || load_created_organizations(&state_store.read(), &account_did)
    });

    let mut selected_org = use_signal(String::new);
    let mut relationship = use_signal(|| "owner".to_owned());
    let mut selected_scopes = use_signal(|| vec!["official_badge".to_owned()]);
    let mut revoke_mode = use_signal(|| false);
    let mut revokes_statement_id = use_signal(String::new);
    let mut status_msg = use_signal(String::new);
    let mut busy = use_signal(|| false);

    rsx! {
        div { class: "workflow-form", "data-testid": "org-bind-form",
            div { class: "event-head",
                span { "Bind organization to this Realm" }
                span { class: "badge green", "server admin" }
            }
            if created().is_empty() {
                div { class: "muted", "data-testid": "org-bind-no-orgs",
                    "No organizations created on this device yet. Create one above, then bind it here."
                }
            } else {
                div { class: "field",
                    label { "Organization" }
                    select {
                        "data-testid": "org-bind-org-select",
                        value: "{selected_org}",
                        onchange: move |evt| selected_org.set(evt.value()),
                        option { value: "", "Select an organization…" }
                        for org in created() {
                            option {
                                value: "{org.did}",
                                "{org.display_name} ({short_protocol_id(&org.did)})"
                            }
                        }
                    }
                }
                div { class: "field",
                    label { "Relationship" }
                    select {
                        "data-testid": "org-bind-relationship-select",
                        value: "{relationship}",
                        onchange: move |evt| relationship.set(evt.value()),
                        for (slug , label) in RELATIONSHIP_CHOICES.iter() {
                            option { value: "{slug}", "{label}" }
                        }
                    }
                }
                div { class: "field",
                    label { "Control scopes" }
                    div { class: "metric-grid", "data-testid": "org-bind-scopes",
                        for (slug , label) in CONTROL_SCOPE_CHOICES.iter() {
                            {
                                let slug = (*slug).to_owned();
                                let checked = selected_scopes().iter().any(|s| s == &slug);
                                rsx! {
                                    label { class: "checkbox-row",
                                        input {
                                            r#type: "checkbox",
                                            "data-scope": "{slug}",
                                            checked,
                                            onchange: move |evt| {
                                                let mut scopes = selected_scopes();
                                                if evt.checked() {
                                                    if !scopes.iter().any(|s| s == &slug) {
                                                        scopes.push(slug.clone());
                                                    }
                                                } else {
                                                    scopes.retain(|s| s != &slug);
                                                }
                                                selected_scopes.set(scopes);
                                            },
                                        }
                                        "{label}"
                                    }
                                }
                            }
                        }
                    }
                }
                div { class: "field",
                    label { class: "checkbox-row",
                        input {
                            r#type: "checkbox",
                            "data-testid": "org-bind-revoke-toggle",
                            checked: revoke_mode(),
                            onchange: move |evt| revoke_mode.set(evt.checked()),
                        }
                        "Revoke a prior statement"
                    }
                }
                if revoke_mode() {
                    div { class: "field",
                        label { "Revokes statement id" }
                        input {
                            r#type: "text",
                            "data-testid": "org-bind-revokes-id",
                            value: "{revokes_statement_id}",
                            placeholder: "org-stmt-…",
                            oninput: move |evt| revokes_statement_id.set(evt.value()),
                        }
                    }
                }
                div { class: "actions",
                    button {
                        r#type: "button",
                        class: "primary",
                        "data-testid": "org-bind-submit",
                        disabled: busy(),
                        onclick: {
                            let base = base_url.clone();
                            let realm_id = realm_id.clone();
                            let account_did = account_did.clone();
                            move |_| {
                                let base = base.clone();
                                let realm_id = realm_id.clone();
                                let actor = account_did.clone();
                                let api_token = token();
                                let org_did = selected_org().trim().to_owned();
                                if org_did.is_empty() {
                                    status_msg.set("select an organization first".to_owned());
                                    return;
                                }
                                let Some(relationship_value) = relationship_from_slug(&relationship())
                                else {
                                    status_msg.set("invalid relationship".to_owned());
                                    return;
                                };
                                let scopes: Vec<RealmOrganizationControlScope> = selected_scopes()
                                    .iter()
                                    .filter_map(|slug| control_scope_from_slug(slug))
                                    .collect();
                                if scopes.is_empty() {
                                    status_msg.set("select at least one control scope".to_owned());
                                    return;
                                }
                                let is_revoke = revoke_mode();
                                let revokes_id = revokes_statement_id().trim().to_owned();
                                if is_revoke && revokes_id.is_empty() {
                                    status_msg
                                        .set("revoke requires the prior statement id".to_owned());
                                    return;
                                }
                                // Resolve the organization control verification
                                // method id + signing key from local storage.
                                let did_key_id = created()
                                    .iter()
                                    .find(|org| org.did == org_did)
                                    .map(|org| org.did_key_id.clone())
                                    .unwrap_or_else(|| format!("{org_did}#did-key-1"));
                                let secure_store =
                                    crate::secure_key_store::default_secure_key_store("inkson");
                                let control_key = match load_organization_control_key(
                                    secure_store.as_ref(),
                                    &org_did,
                                ) {
                                    Ok(Some(key)) => key,
                                    Ok(None) => {
                                        status_msg.set(
                                            "organization control key not found on this device"
                                                .to_owned(),
                                        );
                                        return;
                                    }
                                    Err(err) => {
                                        status_msg.set(format!(
                                            "could not load organization control key: {err}"
                                        ));
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
                                    organization_did: org_did.clone(),
                                    verification_method: did_key_id.clone(),
                                    relationship: relationship_value,
                                    status: status_value,
                                    control_scopes: scopes.clone(),
                                    issued_at,
                                    revokes_statement_id: is_revoke
                                        .then(|| revokes_id.clone()),
                                };
                                // Sign the organization-side statement proof with
                                // the organization control key (NOT the login /
                                // device signer).
                                let signed = match sign_organization_statement(
                                    &statement_input,
                                    &control_key,
                                ) {
                                    Ok(payload) => payload,
                                    Err(err) => {
                                        status_msg
                                            .set(format!("organization signing failed: {err}"));
                                        return;
                                    }
                                };

                                // Feed the SAME fields plus the signed proof into
                                // the ck.realm.organization builder; it
                                // reconstructs an identical payload so the
                                // canonical signing bytes — and the proof — stay
                                // valid on the wire.
                                let authorization =
                                    crate::operation::ck_ops::RealmOrganizationAuthorizationInput {
                                        issuer: org_did.clone(),
                                        issuer_role:
                                            cokret_sdk::models::RealmOrganizationIssuerRole::OrganizationDid,
                                        verification_method: did_key_id.clone(),
                                        delegation_ref: None,
                                        executed_by: None,
                                        signed_at: issued_at,
                                        proof: signed.authorization.proof.clone(),
                                    };
                                let builder =
                                    match crate::operation::ck_ops::realm_organization_statement(
                                        &realm_id,
                                        &actor,
                                        &statement_id,
                                        &org_did,
                                        relationship_value,
                                        status_value,
                                        scopes,
                                        issued_at,
                                        authorization,
                                        is_revoke.then(|| revokes_id.clone()),
                                    ) {
                                        Ok(builder) => builder,
                                        Err(err) => {
                                            status_msg
                                                .set(format!("statement build failed: {err}"));
                                            return;
                                        }
                                    };
                                let event = match builder.build_sdk_event("inkson") {
                                    Ok(event) => event,
                                    Err(err) => {
                                        status_msg.set(format!("event build failed: {err}"));
                                        return;
                                    }
                                };

                                busy.set(true);
                                status_msg.set(if is_revoke {
                                    "revoking organization binding…".to_owned()
                                } else {
                                    "binding organization…".to_owned()
                                });
                                spawn(async move {
                                    match crate::views::helpers::with_authed_api(
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
                                            status_msg.set(format!(
                                                "submitted ck.realm.organization: event_id={}",
                                                short_protocol_id(&resp.event_id)
                                            ));
                                        }
                                        Err(err) => {
                                            status_msg.set(format!(
                                                "submit failed: {}",
                                                err.display()
                                            ));
                                        }
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        if revoke_mode() {
                            "Revoke binding"
                        } else {
                            "Bind organization"
                        }
                    }
                }
            }
            if !status_msg().is_empty() {
                div { class: "muted", "data-testid": "org-bind-status", "{status_msg}" }
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
        let dto = dto_from_hint("did:webvh:hint.example:orgs:org1");
        assert_eq!(dto.phase, OrgRelationshipPhase::DeclaredHint);
        assert!(dto.statement_id.is_none());
        assert!(dto.relationship.is_empty());
        assert!(dto.control_scopes.is_empty());
        // The DID is preserved verbatim; no fabricated display name.
        assert_eq!(dto.organization_did, "did:webvh:hint.example:orgs:org1");
    }
}
