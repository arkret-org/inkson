use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::api::is_auth_expired_error;
use crate::config::LocalConfigStore;
use crate::local_state::LocalStateStore;
use crate::models::{RealmTreeNode, RealmTreeNodeKind};
use crate::routes::Route;
use crate::ui::button::{Button, ButtonVariant};
use crate::ui::input::Input;
use crate::ui::label::Label;
use crate::ui::select::{Select, SelectOption};
use crate::ui::textarea::Textarea;
use crate::views::helpers::{authed_api, persist_config, short_protocol_id};

const DISCOVERABILITY_OPTIONS: [(&str, &str, &str); 6] = [
    (
        "public",
        "Public",
        "Findable in Search. Existence and join surface can be broadly disclosed.",
    ),
    (
        "listed",
        "Listed",
        "Visible in Search, but still separate from how people join or what history they see.",
    ),
    (
        "restricted",
        "Restricted",
        "Directory presence is limited to principals that already satisfy server-side policy.",
    ),
    (
        "unlisted",
        "Unlisted",
        "Not browseable in Search. Entry depends on a direct link or explicit reference.",
    ),
    (
        "invite_only",
        "Invite only",
        "Existence is disclosed only to specifically invited principals.",
    ),
    (
        "secret",
        "Secret",
        "The Realm should not disclose that it exists to unauthorized viewers.",
    ),
];

const JOIN_RULE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "public",
        "Public",
        "Anyone who can see the Realm can join without a separate approval step.",
    ),
    (
        "invite",
        "Invite",
        "Joining requires a member or admin to grant admission explicitly.",
    ),
    (
        "knock",
        "Knock",
        "Applicants can request entry and wait for review.",
    ),
    (
        "restricted",
        "Restricted",
        "Joining depends on policy or claims, even if the Realm is discoverable.",
    ),
];

const HISTORY_VISIBILITY_OPTIONS: [(&str, &str, &str); 5] = [
    (
        "world_readable",
        "World readable",
        "Past history is readable without joining. Use only with intentionally open Realms.",
    ),
    (
        "shared",
        "Shared",
        "New members can read the pre-join history that is meant to be shared with the whole Realm.",
    ),
    (
        "invited",
        "Invited",
        "History is visible only from the point an invite made the principal eligible.",
    ),
    (
        "joined",
        "Joined",
        "History starts when the principal actually becomes a member.",
    ),
    (
        "restricted",
        "Restricted",
        "Past history stays tightly scoped; new members see only what policy re-discloses.",
    ),
];

// Spec realm-and-space.md §2.3 — `encryption_profile` enum on the
// Realm create event. `create-locked`, so this choice is permanent for
// the lifetime of the Realm.
const ENCRYPTION_PROFILE_OPTIONS: [(&str, &str, &str); 3] = [
    (
        "mls_rfc9420",
        "MLS (metadata + content E2EE)",
        "Recommended. Metadata and content use e2ee_required floors backed by MLS.",
    ),
    (
        "none",
        "No encryption",
        "Plaintext content visible to the server. Use for public / broadcast Realms where confidentiality is not required.",
    ),
    (
        "external",
        "External provider",
        "Encryption is delegated to a federated provider declared in policy. Pick this only if you know what you're doing.",
    ),
];

// Spec realm-and-space.md §2.3 — `security_class`. `high_assurance`
// automatically locks `federation_policy` to one of
// `{closed, restricted, quarantine}`; client UI hint reflects this.
const SECURITY_CLASS_OPTIONS: [(&str, &str, &str); 2] = [
    (
        "standard",
        "Standard",
        "Default posture. Federation policy can be open or restricted per Realm settings.",
    ),
    (
        "high_assurance",
        "High assurance",
        "Tightened defaults: federation is forced to restricted/closed/quarantine, audit signals are recorded.",
    ),
];

// Spec realm-and-space.md §2.3 — `federation_policy` reducer-derived
// from `ck.realm.policy` events but seeded at create time. `open` is
// forbidden when security_class=high_assurance.
const FEDERATION_POLICY_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "open",
        "Open",
        "Any peer can interact. Not allowed when security_class=high_assurance.",
    ),
    (
        "restricted",
        "Restricted",
        "Allow-list of peers (governance / org-vetted). Default for high_assurance.",
    ),
    (
        "closed",
        "Closed",
        "No federation at all. Use for fully internal Realms.",
    ),
    (
        "quarantine",
        "Quarantine",
        "Inbound is accepted but held for review. Outbound is blocked.",
    ),
];

// Spec realm-and-space.md §2.3 — `notary_profile`. Create-locked.
// `single_did` is the dev / single-operator default; the others are
// for production deployments with multiple notary principals.
const ANCHOR_PROFILE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "single_did",
        "Single DID",
        "One principal signs seals. Simplest setup; default.",
    ),
    (
        "threshold",
        "Threshold",
        "k-of-n signature; configure the participating DIDs in policy.",
    ),
    (
        "open_set",
        "Open set",
        "Any holder of the notary capability may sign.",
    ),
    (
        "mixed",
        "Mixed",
        "Combination of the above — configure via policy.",
    ),
];

// Spec realm-and-space.md §2.3 — `digest_algorithm`. Create-locked.
// `sha256` is the universal default; other choices target hardened
// or interop-with-other-hash-systems deployments.
const HASH_PROFILE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "sha256",
        "SHA-256",
        "Default. Interoperable everywhere in Cokret v1.",
    ),
    (
        "sha512",
        "SHA-512",
        "Wider digest. Choose only if your deployment policy requires it.",
    ),
    (
        "sha3_256",
        "SHA3-256",
        "Keccak family. Use for FIPS-compatible deployments that mandate SHA-3.",
    ),
    (
        "blake3",
        "BLAKE3",
        "Faster on modern CPUs. Use only when all peers support BLAKE3.",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SetupSection {
    Overview,
    /// Realm bootstrap flow; the form creates a Realm and emits
    /// `ck.realm.create`.
    Realms,
    /// Phase 3 — `ck.space.create` form: pick a Realm, pick a kind,
    /// optionally pick a parent Space. The Space lives inside the
    /// Realm and inherits all security semantics from it.
    NewSpace,
}

impl SetupSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "" => Self::Realms,
            "overview" => Self::Overview,
            "realms" => Self::Realms,
            "new-space" => Self::NewSpace,
            _ => Self::Overview,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Realms => "realms",
            Self::NewSpace => "new-space",
        }
    }
}

// Spec realm-and-space.md §3.2 — `kind` enum for Space. v1 catalogue
// is `space` (generic) / `project` / `folder` / `board` / `list`;
// profiles may register additional kinds.
const SPACE_KIND_OPTIONS: [(&str, &str, &str); 5] = [
    ("space", "Space (generic)", ""),
    (
        "project",
        "Project",
        "Top-level scope for a piece of work; usually contains boards / lists.",
    ),
    (
        "folder",
        "Folder",
        "Pure navigation container. Holds child Spaces / Flows but isn't a workflow.",
    ),
    (
        "board",
        "Board",
        "Kanban / pipeline view. Cells track flow placement (rank cas-register).",
    ),
    (
        "list",
        "List",
        "Ordered list view. Useful for backlog / triage / queue surfaces.",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NewRealmStep {
    Basics,
    Boundary,
    Seed,
    Done,
}

const NEW_REALM_STEPS: [NewRealmStep; 4] = [
    NewRealmStep::Basics,
    NewRealmStep::Boundary,
    NewRealmStep::Seed,
    NewRealmStep::Done,
];

impl NewRealmStep {
    fn label(self) -> &'static str {
        match self {
            Self::Basics => "Basics",
            Self::Boundary => "Boundary",
            Self::Seed => "Seed",
            Self::Done => "Done",
        }
    }

    fn subtitle(self) -> &'static str {
        match self {
            Self::Basics => "name and intent",
            Self::Boundary => "three policy axes",
            Self::Seed => "initial members and create",
            Self::Done => "open created realm",
        }
    }

    fn number(self) -> &'static str {
        match self {
            Self::Basics => "1",
            Self::Boundary => "2",
            Self::Seed => "3",
            Self::Done => "4",
        }
    }

    fn next(self) -> Self {
        match self {
            Self::Basics => Self::Boundary,
            Self::Boundary => Self::Seed,
            Self::Seed | Self::Done => Self::Done,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Basics | Self::Boundary => Self::Basics,
            Self::Seed => Self::Boundary,
            Self::Done => Self::Seed,
        }
    }
}

fn plaintext_services_for_policy(service_did: &str) -> Vec<String> {
    let service_did = service_did.trim();
    if service_did.is_empty() {
        Vec::new()
    } else {
        vec![service_did.to_owned()]
    }
}

fn parse_seed_members(seed_members: &str) -> Vec<String> {
    let mut members = Vec::new();

    let push_unique = |value: &str, members: &mut Vec<String>| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return;
        }
        let normalized = crate::identity_handle::normalize_user_handle_display(trimmed)
            .unwrap_or_else(|| trimmed.to_owned());
        if !members.iter().any(|existing| existing == &normalized) {
            members.push(normalized);
        }
    };

    for candidate in seed_members.split([',', '\n', '\r', '\t', ';']) {
        push_unique(candidate, &mut members);
    }

    members
}

fn policy_combination_hint(
    discoverability: &str,
    join_rule: &str,
    history_visibility: &str,
) -> Option<(&'static str, &'static str, &'static str)> {
    if discoverability == "secret"
        && (join_rule == "public" || history_visibility == "world_readable")
    {
        return Some((
            "error",
            "Combination invalid",
            "A secret Space cannot also advertise public admission or world-readable history.",
        ));
    }

    if discoverability == "invite_only" && join_rule == "public" {
        return Some((
            "warning",
            "Combination is contradictory",
            "Invite-only discovery paired with public join usually means the discovery model is underspecified.",
        ));
    }

    if matches!(discoverability, "invite_only" | "secret") && history_visibility == "world_readable"
    {
        return Some((
            "warning",
            "History leaks more than existence",
            "If history is world-readable, the Space behaves more openly than its discovery setting suggests.",
        ));
    }

    None
}

#[component]
pub fn SetupPanel(
    base_url: String,
    plaintext_service_did: String,
    token: Signal<String>,
    account_did: Signal<String>,
    device_id: Signal<String>,
    config_store: Signal<LocalConfigStore>,
    state_store: Signal<LocalStateStore>,
    realm_tree_nodes: Signal<Vec<RealmTreeNode>>,
    mut selected_realm_id: Signal<String>,
    new_space_context_node: Signal<String>,
    mut status: Signal<String>,
    section: Option<String>,
) -> Element {
    let active_section = SetupSection::from_slug(section.as_deref());
    let has_session = !token().trim().is_empty();
    let navigator = use_navigator();

    let mut create_step = use_signal(|| NewRealmStep::Basics);
    let mut seed_members = use_signal(String::new);
    let mut realm_title = use_signal(String::new);
    let mut realm_summary = use_signal(String::new);
    let mut realm_discoverability = use_signal(|| "listed".to_owned());
    let mut realm_policy_join_rule = use_signal(|| "invite".to_owned());
    let mut realm_policy_history_visibility = use_signal(|| "shared".to_owned());
    // Spec realm-and-space.md §2.3 — `encryption_profile` and
    // `security_class` are Realm create-locked fields. UI default is
    // `mls_rfc9420` + `standard` (the safe / common case); the form
    // exposes both as user choices because they cannot be changed
    // after the Realm is created.
    let mut realm_encryption_profile = use_signal(|| "mls_rfc9420".to_owned());
    let mut realm_security_class = use_signal(|| "standard".to_owned());
    // Spec realm-and-space.md §2.3 advanced create-locked fields. UI
    // collapses these by default since they're hardly ever changed
    // from the safe defaults (`restricted` / `single_did` / `sha256`).
    let mut realm_federation_policy = use_signal(|| "restricted".to_owned());
    let mut realm_notary_profile = use_signal(|| "single_did".to_owned());
    let mut realm_digest_algorithm = use_signal(|| "sha256".to_owned());
    // Phase 3 — `ck.space.create` form state. The Space inherits all
    // security from its home Realm. The home Realm is supplied by the
    // sidebar row that opened this flow, not by an in-form picker.
    let mut new_space_realm_id = use_signal(String::new);
    let mut new_space_title = use_signal(String::new);
    let mut new_space_summary = use_signal(String::new);
    let mut new_space_kind = use_signal(|| "space".to_owned());
    // Phase 3+ (M-SPACE-PARENT-1) — `parent_space_id` + `default_realm_id`
    // per spec realm-and-space.md §3.2. Empty string = root (omit
    // parent_space_id) for the parent picker; empty default_realm_id means
    // "inherit from parent / home Realm".
    let mut new_space_parent_id = use_signal(String::new);
    let mut new_space_default_realm_id = use_signal(String::new);
    let mut new_space_context_seen = use_signal(String::new);
    let mut new_space_state = use_signal(|| "Draft not created yet".to_owned());
    let mut new_space_created_id = use_signal(String::new);
    let mut realm_state = use_signal(|| "Draft not created yet".to_owned());
    let mut created_realm_id = use_signal(String::new);
    // S6 (docs/user-flows-key-lifecycle.md §9, key-management §7.11) — recovery
    // soft-gate for encrypted-Realm creation. Creating an e2ee Realm produces
    // MLS material that is unrecoverable if the device is lost and no recovery
    // path is configured. The gate prompts the user to set up the Recovery Key
    // first; `recovery_gate_acknowledged` lets a personal_node user override.
    let mut pending_recovery_gate = use_signal(|| false);
    let mut recovery_gate_acknowledged = use_signal(|| false);

    let realm_discoverability_selected = use_memo(move || Some(realm_discoverability()));
    let realm_policy_join_rule_selected = use_memo(move || Some(realm_policy_join_rule()));
    let realm_policy_history_visibility_selected =
        use_memo(move || Some(realm_policy_history_visibility()));
    let realm_encryption_profile_selected = use_memo(move || Some(realm_encryption_profile()));
    let realm_security_class_selected = use_memo(move || Some(realm_security_class()));
    let realm_federation_policy_selected = use_memo(move || Some(realm_federation_policy()));
    let realm_notary_profile_selected = use_memo(move || Some(realm_notary_profile()));
    let realm_digest_algorithm_selected = use_memo(move || Some(realm_digest_algorithm()));
    let new_space_kind_selected = use_memo(move || Some(new_space_kind()));
    let new_space_parent_id_selected = use_memo(move || Some(new_space_parent_id()));
    let new_space_default_realm_id_selected = use_memo(move || Some(new_space_default_realm_id()));

    let selected_realm_value = selected_realm_id();
    let has_selected_realm = !selected_realm_value.trim().is_empty();
    let active_create_step = create_step();
    let title_value = realm_title();
    let summary_value = realm_summary();
    let discoverability_value = realm_discoverability();
    let join_rule_value = realm_policy_join_rule();
    let history_visibility_value = realm_policy_history_visibility();
    let encryption_profile_value = realm_encryption_profile();
    let security_class_value = realm_security_class();
    let federation_policy_value = realm_federation_policy();
    let notary_profile_value = realm_notary_profile();
    let digest_algorithm_value = realm_digest_algorithm();
    let federation_policy_open_forbidden = security_class_value == "high_assurance";
    // M-UX-CONTEXT-1: the sidebar's per-row "+" action sets
    // `new_space_context_node` to the clicked Realm / Space and routes
    // to the NewSpace section. The form no longer exposes a Realm
    // picker, so every explicit sidebar context change must update the
    // hidden realm_id / parent_space_id used by submission.
    if active_section == SetupSection::NewSpace {
        let selected_context = new_space_context_node();
        let selected_context = selected_context.trim().to_owned();
        let selected_fallback = selected_realm_id();
        let selected_fallback = selected_fallback.trim().to_owned();
        let context_key = if selected_context.is_empty() {
            selected_fallback.clone()
        } else {
            selected_context.clone()
        };
        if !context_key.is_empty() && new_space_context_seen() != context_key {
            if let Some(node) = realm_tree_nodes()
                .into_iter()
                .find(|node| node.id == context_key)
            {
                new_space_context_seen.set(context_key);
                new_space_created_id.set(String::new());
                new_space_state.set("Draft not created yet".to_owned());

                match node.kind {
                    RealmTreeNodeKind::Realm => {
                        new_space_realm_id.set(node.id);
                        new_space_parent_id.set(String::new());
                    }
                    RealmTreeNodeKind::Space => {
                        new_space_realm_id.set(node.projection_realm_id().to_owned());
                        new_space_parent_id.set(node.id);
                    }
                }
            } else if let Some(body) = state_store
                .read()
                .load()
                .realm_tree_projections
                .get(&context_key)
                .cloned()
            {
                new_space_context_seen.set(context_key.clone());
                new_space_created_id.set(String::new());
                new_space_state.set("Draft not created yet".to_owned());

                let kind = match body
                    .get("__kind")
                    .and_then(|kind| kind.as_str())
                    .or_else(|| body.get("schema").and_then(|schema| schema.as_str()))
                {
                    Some("space") | Some("ck.schema.space.v1") => "space",
                    _ => "realm",
                };
                if kind == "realm" {
                    new_space_realm_id.set(context_key);
                    new_space_parent_id.set(String::new());
                } else {
                    // For a Space row, the new child lives in the
                    // same home Realm; the clicked Space becomes
                    // the parent.
                    let realm = body
                        .get("realm_id")
                        .and_then(|realm| realm.as_str())
                        .unwrap_or(&selected_fallback)
                        .to_owned();
                    new_space_realm_id.set(realm);
                    new_space_parent_id.set(context_key);
                }
            } else if context_key.starts_with("ck:realm:") {
                new_space_context_seen.set(context_key.clone());
                new_space_created_id.set(String::new());
                new_space_state.set("Draft not created yet".to_owned());
                new_space_realm_id.set(context_key);
                new_space_parent_id.set(String::new());
            } else if context_key.starts_with("ck:space:") && !selected_fallback.is_empty() {
                new_space_context_seen.set(context_key.clone());
                new_space_created_id.set(String::new());
                new_space_state.set("Draft not created yet".to_owned());
                new_space_realm_id.set(selected_fallback);
                new_space_parent_id.set(context_key);
            }
        }
    }

    let new_space_realm_id_value = new_space_realm_id();
    let new_space_title_value = new_space_title();
    let new_space_summary_value = new_space_summary();
    let new_space_kind_value = new_space_kind();
    let _new_space_parent_id_value = new_space_parent_id();
    let _new_space_default_realm_id_value = new_space_default_realm_id();
    let new_space_state_value = new_space_state();
    let new_space_created_id_value = new_space_created_id();
    let new_space_created_id_label = short_protocol_id(&new_space_created_id_value);
    // Every persisted projection is either a Realm or a Space; the
    // tag is recorded under `__kind` ("realm" | "space") when we
    // save it. Legacy projections without the tag are treated as
    // Realms (the only thing yougen used to create).
    let projections_snapshot: Vec<(String, Value)> = state_store
        .read()
        .load()
        .realm_tree_projections
        .iter()
        .map(|(id, body)| (id.clone(), body.clone()))
        .collect();
    let projection_kind = |body: &Value| -> &'static str {
        match body
            .get("__kind")
            .and_then(|kind| kind.as_str())
            .or_else(|| body.get("schema").and_then(|schema| schema.as_str()))
        {
            Some("space") | Some("ck.schema.space.v1") => "space",
            _ => "realm",
        }
    };
    let projection_realm_id = |id: &str, body: &Value| -> String {
        body.get("realm_id")
            .and_then(|realm_id| realm_id.as_str())
            .or_else(|| {
                body.get("summary")
                    .and_then(|summary| summary.get("realm_id"))
                    .and_then(|realm_id| realm_id.as_str())
            })
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| id.to_owned())
    };
    let projection_title =
        |id: &str, body: &Value| -> String { crate::realm_tree::projection_title(id, body) };
    let available_realms: Vec<(String, String)> = projections_snapshot
        .iter()
        .filter(|(_, body)| projection_kind(body) == "realm")
        .map(|(id, body)| (id.clone(), projection_title(id, body)))
        .collect();
    // Parent picker = every Space already inside the selected Realm,
    // plus a "(root)" sentinel. Realms themselves can't be parents
    // per spec §2.1 (Realms don't have parent/child).
    let parent_candidates: Vec<(String, String)> = projections_snapshot
        .iter()
        .filter(|(_, body)| {
            projection_kind(body) == "space"
                && projection_realm_id("", body) == new_space_realm_id_value
        })
        .map(|(id, body)| (id.clone(), projection_title(id, body)))
        .collect();
    let new_space_ready =
        !new_space_title_value.trim().is_empty() && !new_space_realm_id_value.trim().is_empty();
    let new_space_can_submit = has_session && new_space_ready;
    let seed_members_value = seed_members();
    let realm_state_value = realm_state();
    let created_realm_id_value = created_realm_id();
    let parsed_seed_members = parse_seed_members(&seed_members_value);
    let seed_member_count = parsed_seed_members.len();
    let has_created_realm = !created_realm_id_value.trim().is_empty();
    let created_realm_id_label = short_protocol_id(&created_realm_id_value);
    let current_visibility_hint = policy_combination_hint(
        &discoverability_value,
        &join_rule_value,
        &history_visibility_value,
    );
    let current_policy_error = matches!(current_visibility_hint, Some(("error", _, _)));
    let basics_ready = !title_value.trim().is_empty();
    let boundary_ready = !current_policy_error;
    let can_advance_step = match active_create_step {
        NewRealmStep::Basics => basics_ready,
        NewRealmStep::Boundary => boundary_ready,
        NewRealmStep::Seed => basics_ready && boundary_ready,
        NewRealmStep::Done => has_created_realm,
    };
    let can_create_realm = has_session && basics_ready && boundary_ready;

    rsx! {
        div { class: "timeline", "data-testid": "setup-panel",
            if pending_recovery_gate() {
                crate::ui::dialog::Dialog {
                    open: true,
                    on_open_change: move |open: bool| {
                        if !open {
                            pending_recovery_gate.set(false);
                        }
                    },
                    "data-testid": "encrypted-realm-recovery-gate",
                    "aria-label": "Set up recovery before creating an encrypted Realm",
                    div { class: "modal event",
                        div { class: "modal-head event-head",
                            h3 { "Set up recovery first" }
                            span { class: "muted", "encrypted Realm" }
                        }
                        div { class: "modal-body",
                            div { class: "muted",
                                "This Realm is end-to-end encrypted. If you lose this device and have no Recovery Key or backup configured, its contents are permanently unrecoverable. Set up your 24-word Recovery Key and back up your keys before creating it."
                            }
                            div { class: "muted",
                                "data-testid": "encrypted-realm-recovery-gate-override-hint",
                                "If you continue without recovery, press Create realm again to proceed at your own risk."
                            }
                        }
                        div { class: "modal-foot actions",
                            Link {
                                class: "primary",
                                "data-testid": "encrypted-realm-recovery-gate-setup",
                                to: Route::SettingsRecovery,
                                onclick: move |_| pending_recovery_gate.set(false),
                                "Set up Recovery Key"
                            }
                            Button {
                                variant: ButtonVariant::Secondary,
                                "data-testid": "encrypted-realm-recovery-gate-override",
                                onclick: move |_| {
                                    // personal_node override: accept single-point-of-failure
                                    // risk for this session and let the next Create proceed.
                                    recovery_gate_acknowledged.set(true);
                                    pending_recovery_gate.set(false);
                                },
                                "Continue without recovery"
                            }
                        }
                    }
                }
            }
            if active_section == SetupSection::Overview {
                div { class: "event", "data-testid": "workspace-setup-map",
                    div { class: "event-head",
                        span { "Setup Surfaces" }
                        span { "single-purpose entrypoints" }
                    }
                    div { class: "metric-grid",
                        div { class: "metric",
                            strong { "New Realm" }
                            span { "security-boundary bootstrap" }
                            Link {
                                class: "secondary",
                                to: Route::SetupSection { section: SetupSection::Realms.slug().to_owned() },
                                "Open New Realm"
                            }
                        }
                        div { class: "metric",
                            strong { "New Space" }
                            span { "navigation container inside a Realm" }
                            div { class: "muted",
                                "Hover a Realm or Space in the left sidebar and click the inline + — that's the canonical entry, because it pre-fills the parent context for you. The link below opens the form blank (you'll have to pick a Realm manually)."
                            }
                            Link {
                                class: "secondary",
                                to: Route::SetupSection { section: SetupSection::NewSpace.slug().to_owned() },
                                "Open blank form"
                            }
                        }
                        div { class: "metric",
                            strong { "Onboarding" }
                            span { "identity bootstrap" }
                            Link { class: "secondary", to: Route::Onboarding, "Open Onboarding" }
                        }
                        div { class: "metric",
                            strong { "Search" }
                            span { "actors / handles / realms" }
                            Link { class: "secondary", to: Route::Directory, "Open Search" }
                        }
                        div { class: "metric",
                            strong { "Realm timeline" }
                            span { "after bootstrap" }
                            if has_selected_realm {
                                Link {
                                    class: "secondary",
                                    to: Route::Realm { realm_id: selected_realm_value.clone() },
                                    "Open Current Realm"
                                }
                            } else {
                                Link { class: "secondary", to: Route::Timeline, "Open Timeline" }
                            }
                        }
                    }
                }

                div { class: "event", "data-testid": "workspace-setup-checklist",
                    div { class: "event-head",
                        span { "What Moved" }
                        span { "IA cleanup" }
                    }
                    div { class: "actions",
                        span { class: "badge", "Onboarding = identity bootstrap" }
                        span { class: "badge", "Search = discovery and people" }
                        span { class: "badge", "New Realm = security-boundary bootstrap" }
                        span { class: "badge", "Settings = recovery and operations" }
                    }
                }
            }

            if active_section == SetupSection::Realms {
                div { class: "setup-shell new-realm-shell", "data-testid": "realm-lifecycle-flow",
                    div { class: "setup-column",
                        div { class: "event new-realm-hero", "data-testid": "realm-setup-guide",
                            div { class: "event-head",
                                span { "New Realm" }
                            }
                            h2 { class: "settings-content-title", "Create a Realm" }
                            div { class: "muted",
                                "A Realm is the security / sync / E2EE boundary. The recommended mode is MLS with metadata_encryption_floor=e2ee_required and content_encryption_floor=e2ee_required."
                            }
                        }

                        div { class: "event new-realm-stepper",
                            div { class: "event-head",
                                span { "Create steps" }
                                span { "{active_create_step.number()} / 4" }
                            }
                            div { class: "setup-step-list",
                                for step in NEW_REALM_STEPS {
                                    Button {
                                        variant: if active_create_step == step { ButtonVariant::Primary } else { ButtonVariant::Secondary },
                                        disabled: step == NewRealmStep::Done && !has_created_realm,
                                        onclick: move |_| create_step.set(step),
                                        span { class: "setup-step-index", "{step.number()}" }
                                        span { class: "setup-step-label",
                                            strong { "{step.label()}" }
                                            small { "{step.subtitle()}" }
                                        }
                                    }
                                }
                            }

                        if active_create_step == NewRealmStep::Basics {
                            div { class: "setup-step-panel",
                                div { class: "event-head",
                                    span { "Basics" }
                                    span { "required title" }
                                }
                                div { class: "workflow-form setup-form-grid",
                                    div { class: "setup-field",
                                        Label { html_for: "realm-title-input-input", "Realm title" }
                                        Input {
                                            id: "realm-title-input-input",
                                            "data-testid": "realm-title-input",
                                            value: "{title_value}",
                                            placeholder: "Engineering, Research, Design system...",
                                            oninput: move |event: FormEvent| realm_title.set(event.value())
                                        }
                                    }
                                    div { class: "setup-field setup-field-span-2",
                                        Label { html_for: "realm-summary-input-input", "Summary" }
                                        Textarea {
                                            id: "realm-summary-input-input",
                                            "data-testid": "realm-summary-input",
                                            value: "{summary_value}",
                                            rows: "3",
                                            placeholder: "What this Realm is for.",
                                            oninput: move |event: FormEvent| realm_summary.set(event.value())
                                        }
                                    }
                                }
                                div { class: "actions setup-nav-actions",
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "new-realm-next-button",
                                        disabled: !can_advance_step,
                                        onclick: move |_| create_step.set(active_create_step.next()),
                                        "Next: Boundary"
                                    }
                                }
                            }
                        }

                        if active_create_step == NewRealmStep::Boundary {
                            div { class: "setup-step-panel",
                                div { class: "event-head",
                                    span { "Boundary" }
                                    span { "three independent axes" }
                                }
                                div { class: "setup-axis-grid",
                                    div { class: "metric directory-axis-card",
                                        strong { "Discoverability" }
                                        div { class: "workflow-form setup-field",
                                            label { "Who can discover that this Realm exists?" }
                                            Select::<String> {
                                                "data-testid": "realm-discoverability-input",
                                                value: Some(realm_discoverability_selected.into()),
                                                on_value_change: move |v: Option<String>| {
                                                    if let Some(v) = v {
                                                        realm_discoverability.set(v);
                                                    }
                                                },
                                                for (i, (option_value, label, _)) in DISCOVERABILITY_OPTIONS.iter().enumerate() {
                                                    SelectOption::<String> {
                                                        index: i,
                                                        value: option_value.to_string(),
                                                        text_value: "{label}",
                                                        "{label}"
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "{DISCOVERABILITY_OPTIONS.iter().find(|(value, _, _)| *value == discoverability_value).map(|(_, _, hint)| *hint).unwrap_or(\"Discovery posture is not set.\")}"
                                            }
                                        }
                                    }
                                    div { class: "metric directory-axis-card",
                                        strong { "Join rule" }
                                        div { class: "workflow-form setup-field",
                                            label { "How does a principal become a member?" }
                                            Select::<String> {
                                                "data-testid": "realm-policy-join-rule-input",
                                                value: Some(realm_policy_join_rule_selected.into()),
                                                on_value_change: move |v: Option<String>| {
                                                    if let Some(v) = v {
                                                        realm_policy_join_rule.set(v);
                                                    }
                                                },
                                                for (i, (option_value, label, _)) in JOIN_RULE_OPTIONS.iter().enumerate() {
                                                    SelectOption::<String> {
                                                        index: i,
                                                        value: option_value.to_string(),
                                                        text_value: "{label}",
                                                        "{label}"
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "{JOIN_RULE_OPTIONS.iter().find(|(value, _, _)| *value == join_rule_value).map(|(_, _, hint)| *hint).unwrap_or(\"Join path is not set.\")}"
                                            }
                                        }
                                    }
                                    div { class: "metric directory-axis-card",
                                        strong { "History visibility" }
                                        div { class: "workflow-form setup-field",
                                            label { "What history can new members read?" }
                                            Select::<String> {
                                                "data-testid": "realm-policy-history-visibility-input",
                                                value: Some(realm_policy_history_visibility_selected.into()),
                                                on_value_change: move |v: Option<String>| {
                                                    if let Some(v) = v {
                                                        realm_policy_history_visibility.set(v);
                                                    }
                                                },
                                                for (i, (option_value, label, _)) in HISTORY_VISIBILITY_OPTIONS.iter().enumerate() {
                                                    SelectOption::<String> {
                                                        index: i,
                                                        value: option_value.to_string(),
                                                        text_value: "{label}",
                                                        "{label}"
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "{HISTORY_VISIBILITY_OPTIONS.iter().find(|(value, _, _)| *value == history_visibility_value).map(|(_, _, hint)| *hint).unwrap_or(\"History scope is not set.\")}"
                                            }
                                        }
                                    }
                                    // Spec realm-and-space.md §2.3:
                                    // encryption_profile + security_class are
                                    // create-locked Realm fields. Surface
                                    // both here so the user makes the choice
                                    // intentionally — there's no edit later.
                                    div { class: "metric directory-axis-card",
                                        strong { "Encryption profile" }
                                        div { class: "workflow-form setup-field",
                                            label { "How is content protected at rest and in transit?" }
                                            Select::<String> {
                                                "data-testid": "realm-encryption-profile-input",
                                                value: Some(realm_encryption_profile_selected.into()),
                                                on_value_change: move |v: Option<String>| {
                                                    if let Some(v) = v {
                                                        realm_encryption_profile.set(v);
                                                    }
                                                },
                                                for (i, (option_value, label, _)) in ENCRYPTION_PROFILE_OPTIONS.iter().enumerate() {
                                                    SelectOption::<String> {
                                                        index: i,
                                                        value: option_value.to_string(),
                                                        text_value: "{label}",
                                                        "{label}"
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "{ENCRYPTION_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == encryption_profile_value).map(|(_, _, hint)| *hint).unwrap_or(\"Encryption profile is not set.\")}"
                                            }
                                            if crate::api::encryption_profile_uses_recommended_floor(&encryption_profile_value) {
                                                div { class: "muted",
                                                    "Recommended floor: metadata_encryption_floor=e2ee_required and content_encryption_floor=e2ee_required."
                                                }
                                            } else {
                                                div { class: "inline-warn", "data-testid": "realm-encryption-floor-warning",
                                                    span { class: "body",
                                                        strong { "Encryption floor is below the recommended mode." }
                                                        " Use MLS if this Realm may hold private metadata or content."
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "Locked at creation — encryption_profile cannot be changed afterwards (spec realm-and-space.md §2.3)."
                                            }
                                        }
                                    }
                                    div { class: "metric directory-axis-card",
                                        strong { "Security class" }
                                        div { class: "workflow-form setup-field",
                                            label { "Posture for federation and audit defaults." }
                                            Select::<String> {
                                                "data-testid": "realm-security-class-input",
                                                value: Some(realm_security_class_selected.into()),
                                                on_value_change: move |v: Option<String>| {
                                                    if let Some(v) = v {
                                                        realm_security_class.set(v);
                                                    }
                                                },
                                                for (i, (option_value, label, _)) in SECURITY_CLASS_OPTIONS.iter().enumerate() {
                                                    SelectOption::<String> {
                                                        index: i,
                                                        value: option_value.to_string(),
                                                        text_value: "{label}",
                                                        "{label}"
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "{SECURITY_CLASS_OPTIONS.iter().find(|(value, _, _)| *value == security_class_value).map(|(_, _, hint)| *hint).unwrap_or(\"Security class is not set.\")}"
                                            }
                                        }
                                    }
                                }

                                // Spec realm-and-space.md §2.3 advanced
                                // fields — collapsed by default. All
                                // three are create-locked. Defaults
                                // (restricted / single_did / sha256)
                                // suit the dev + small-deployment cases;
                                // production operators tweak as needed.
                                details { class: "setup-advanced",
                                    "data-testid": "realm-advanced-config",
                                    summary { class: "setup-advanced-summary",
                                        "Advanced (federation policy / seal profile / hash profile)"
                                    }
                                    div { class: "setup-axis-grid setup-advanced-grid",
                                        div { class: "metric directory-axis-card",
                                            strong { "Federation policy" }
                                            div { class: "workflow-form setup-field",
                                                label { "How does this Realm interoperate with other deployments?" }
                                                Select::<String> {
                                                    "data-testid": "realm-federation-policy-input",
                                                    value: Some(realm_federation_policy_selected.into()),
                                                    on_value_change: move |v: Option<String>| {
                                                        if let Some(v) = v {
                                                            realm_federation_policy.set(v);
                                                        }
                                                    },
                                                    for (i, (option_value, label, _)) in FEDERATION_POLICY_OPTIONS.iter().enumerate() {
                                                        SelectOption::<String> {
                                                            index: i,
                                                            value: option_value.to_string(),
                                                            text_value: "{label}",
                                                            disabled: federation_policy_open_forbidden && *option_value == "open",
                                                            "{label}"
                                                        }
                                                    }
                                                }
                                                div { class: "muted",
                                                    "{FEDERATION_POLICY_OPTIONS.iter().find(|(value, _, _)| *value == federation_policy_value).map(|(_, _, hint)| *hint).unwrap_or(\"Federation policy is not set.\")}"
                                                }
                                                if federation_policy_open_forbidden {
                                                    div { class: "muted",
                                                        "high_assurance requires federation_policy ∈ {{restricted, closed, quarantine}} (spec realm-and-space.md §2.3)."
                                                    }
                                                }
                                            }
                                        }
                                        div { class: "metric directory-axis-card",
                                            strong { "Seal profile" }
                                            div { class: "workflow-form setup-field",
                                                label { "Who signs durable seals for this Realm?" }
                                                Select::<String> {
                                                    "data-testid": "realm-seal-profile-input",
                                                    value: Some(realm_notary_profile_selected.into()),
                                                    on_value_change: move |v: Option<String>| {
                                                        if let Some(v) = v {
                                                            realm_notary_profile.set(v);
                                                        }
                                                    },
                                                    for (i, (option_value, label, _)) in ANCHOR_PROFILE_OPTIONS.iter().enumerate() {
                                                        SelectOption::<String> {
                                                            index: i,
                                                            value: option_value.to_string(),
                                                            text_value: "{label}",
                                                            "{label}"
                                                        }
                                                    }
                                                }
                                                div { class: "muted",
                                                    "{ANCHOR_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == notary_profile_value).map(|(_, _, hint)| *hint).unwrap_or(\"Seal profile is not set.\")}"
                                                }
                                            }
                                        }
                                        div { class: "metric directory-axis-card",
                                            strong { "Hash profile" }
                                            div { class: "workflow-form setup-field",
                                                label { "Digest algorithm for canonical hashing." }
                                                Select::<String> {
                                                    "data-testid": "realm-hash-profile-input",
                                                    value: Some(realm_digest_algorithm_selected.into()),
                                                    on_value_change: move |v: Option<String>| {
                                                        if let Some(v) = v {
                                                            realm_digest_algorithm.set(v);
                                                        }
                                                    },
                                                    for (i, (option_value, label, _)) in HASH_PROFILE_OPTIONS.iter().enumerate() {
                                                        SelectOption::<String> {
                                                            index: i,
                                                            value: option_value.to_string(),
                                                            text_value: "{label}",
                                                            "{label}"
                                                        }
                                                    }
                                                }
                                                div { class: "muted",
                                                    "{HASH_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == digest_algorithm_value).map(|(_, _, hint)| *hint).unwrap_or(\"Hash profile is not set.\")}"
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some((tone, heading, body)) = current_visibility_hint {
                                    div { class: if tone == "error" { "inline-error" } else { "inline-warn" },
                                        span { class: "body",
                                            strong { "{heading}" }
                                            " {body}"
                                        }
                                    }
                                }

                                div { class: "actions setup-nav-actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "new-realm-back-button",
                                        onclick: move |_| create_step.set(active_create_step.previous()),
                                        "Back"
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "new-realm-next-button",
                                        disabled: !can_advance_step,
                                        onclick: move |_| create_step.set(active_create_step.next()),
                                        "Next: Seed"
                                    }
                                }
                            }
                        }

                        if active_create_step == NewRealmStep::Seed {
                            div { class: "setup-step-panel",
                                div { class: "event-head",
                                    span { "Seed members" }
                                    span { "optional" }
                                }
                                div { class: "workflow-form setup-form-grid",
                                    div { class: "setup-field setup-field-span-2",
                                        Label { html_for: "seed-members-input-input", "Initial members" }
                                        Textarea {
                                            id: "seed-members-input-input",
                                            "data-testid": "seed-members-input",
                                            value: "{seed_members_value}",
                                            rows: "4",
                                            placeholder: "alice:example.com\nbob:example.com",
                                            oninput: move |event: FormEvent| seed_members.set(event.value())
                                        }
                                        div { class: "muted", "One handle (user:domain.com) or DID per line, or comma-separated." }
                                    }
                                    div { class: "setup-field setup-field-span-2",
                                        label { "Seed preview" }
                                        if seed_member_count == 0 {
                                            div { class: "muted", "No extra seed members." }
                                        } else {
                                            div { class: "setup-chip-wrap",
                                                for member in parsed_seed_members.iter().take(8) {
                                                    {
                                                        let member_label = short_protocol_id(member);
                                                        rsx! {
                                                            span { class: "badge blue mono", title: "{member}", "{member_label}" }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        div { class: "muted", "{seed_member_count} principal(s) will be included in the bootstrap request." }
                                    }
                                }
                                div { class: "actions setup-nav-actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "new-realm-back-button",
                                        onclick: move |_| create_step.set(active_create_step.previous()),
                                        "Back"
                                    }
                                    Button {
                                        variant: ButtonVariant::Primary,
                                        "data-testid": "create-realm-button",
                                        disabled: !can_create_realm,
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                // S6 soft-gate: block encrypted-Realm creation when
                                                // no recovery path is configured, unless the user has
                                                // explicitly overridden via the gate dialog.
                                                if crate::security_state::encryption_profile_is_encrypted(
                                                    &realm_encryption_profile(),
                                                ) && !recovery_gate_acknowledged()
                                                {
                                                    let actor_now = account_did();
                                                    let recovery_ready = {
                                                        let store = state_store.read();
                                                        crate::views::recovery::recovery_options_configured(
                                                            &store, &actor_now,
                                                        ) || crate::components::mls_recovery_backup_configured(
                                                            &store, &actor_now,
                                                        )
                                                    };
                                                    if !recovery_ready {
                                                        pending_recovery_gate.set(true);
                                                        return;
                                                    }
                                                }
                                                let api_token = token();
                                                let base = base.clone();
                                                let backup_trigger_signal =
                                                    crate::components::try_needs_mls_backup_signal();
                                                let title = realm_title();
                                                let summary = realm_summary();
                                                let discoverability = realm_discoverability();
                                                let join_rule = realm_policy_join_rule();
                                                let history_visibility = realm_policy_history_visibility();
                                                let encryption_profile = realm_encryption_profile();
                                                let security_class = realm_security_class();
                                                let federation_policy = realm_federation_policy();
                                                let notary_profile = realm_notary_profile();
                                                let digest_algorithm = realm_digest_algorithm();
                                                let seed_text = seed_members();
                                                let actor = account_did();
                                                let device = device_id();
                                                let configured_plaintext_service_did =
                                                    plaintext_service_did.clone();
                                                spawn(async move {
                                                    let invitees = parse_seed_members(&seed_text);
                                                    match authed_api(&base, api_token.clone()) {
                                                        Ok(api) => {
                                                            let mut plaintext_services = plaintext_services_for_policy(
                                                                &configured_plaintext_service_did,
                                                            );
                                                            if let Ok(description) = api.describe().await {
                                                                let service_did = description.service_did.as_str().trim();
                                                                if !service_did.is_empty()
                                                                    && !plaintext_services
                                                                        .iter()
                                                                        .any(|existing| existing == service_did)
                                                                {
                                                                    plaintext_services.push(service_did.to_owned());
                                                                }
                                                            }
                                                            // Spec realm.schema.json requires
                                                            // trust_domain on the create event.
                                                            // sync_engine caches the server's
                                                            // advertised value in
                                                            // state_store.server_trust_domain
                                                            // after describe; if it isn't set
                                                            // yet we ask the API to fall back
                                                            // to the describe response.
                                                            let cached_trust_domain = state_store
                                                                .read()
                                                                .load()
                                                                .server_trust_domain
                                                                .clone();
                                                            let trust_domain = match cached_trust_domain {
                                                                Some(value) if !value.trim().is_empty() => value,
                                                                _ => match api.describe().await {
                                                                    Ok(desc) => desc.trust_domain.as_str().to_owned(),
                                                                    Err(_) => String::new(),
                                                                },
                                                            };
                                                            match api.create_realm(
                                                                &actor,
                                                                &title,
                                                                Some(&summary),
                                                                &discoverability,
                                                                &join_rule,
                                                                &history_visibility,
                                                                &encryption_profile,
                                                                &security_class,
                                                                &federation_policy,
                                                                &notary_profile,
                                                                &digest_algorithm,
                                                                &trust_domain,
                                                                invitees.clone(),
                                                                plaintext_services.clone(),
                                                            ).await {
                                                            Ok(realm) => {
                                                                // R15: ck.realm.create now returns
                                                                // RealmCreateOutcome with the new
                                                                // `ck:realm:*` id under `realm_id`.
                                                                let realm_id = realm.realm_id.clone();
                                                                selected_realm_id.set(realm_id.clone());
                                                                created_realm_id.set(realm_id.clone());
                                                                // Optimistic sidebar update goes
                                                                // through the canonical store —
                                                                // the Realm tree Signal is derived
                                                                // from `state_store.realm_tree_projections`
                                                                // by RouterView's derive effect, so
                                                                // the `save_realm_tree_projection`
                                                                // below is the single write the
                                                                // sidebar picks up.
                                                                let mut projection_members = Vec::new();
                                                                if !actor.trim().is_empty() {
                                                                    projection_members.push(actor.clone());
                                                                }
                                                                for invitee in &invitees {
                                                                    if !projection_members.iter().any(|member| member == invitee) {
                                                                        projection_members.push(invitee.clone());
                                                                    }
                                                                }
                                                                let projection_admins = if actor.trim().is_empty() {
                                                                    Vec::new()
                                                                } else {
                                                                    vec![actor.clone()]
                                                                };
                                                                let mut projection_body = json!({
                                                                        // Yougen-local schema tag — used by the
                                                                        // sidebar (M-SIDEBAR-TIER-1) to split
                                                                        // Realms from Spaces. Legacy projections
                                                                        // without the tag default to "realm".
                                                                        "__kind": "realm",
                                                                        "owner": actor.clone(),
                                                                        "admins": projection_admins.clone(),
                                                                        "members": projection_members.clone(),
                                                                        "encryption_profile": encryption_profile.clone(),
                                                                        "plaintext_visible_services": plaintext_services.clone(),
                                                                        "summary": {
                                                                            "title": title.clone(),
                                                                            "summary": summary.clone(),
                                                                            "category": "collaboration",
                                                                            "tags": [],
                                                                            "discoverability": discoverability.clone(),
                                                                            "encryption_profile": encryption_profile.clone(),
                                                                            "plaintext_visible_services": plaintext_services.clone(),
                                                                            "owner": actor.clone(),
                                                                            "admins": projection_admins,
                                                                            "members": projection_members,
                                                                        },
                                                                        "timeline": {
                                                                            "events": []
                                                                        }
                                                                    });
                                                                if crate::api::encryption_profile_uses_recommended_floor(
                                                                    &encryption_profile,
                                                                ) {
                                                                    projection_body["content_encryption_floor"] =
                                                                        json!(crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR);
                                                                    projection_body["metadata_encryption_floor"] =
                                                                        json!(crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR);
                                                                    projection_body["summary"]["content_encryption_floor"] =
                                                                        json!(crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR);
                                                                    projection_body["summary"]["metadata_encryption_floor"] =
                                                                        json!(crate::api::RECOMMENDED_REALM_ENCRYPTION_FLOOR);
                                                                }
                                                                state_store.write().save_realm_tree_projection(
                                                                    realm_id.clone(),
                                                                    projection_body,
                                                                );

                                                                let mut initial_mls_backup_id = None;
                                                                if crate::security_state::encryption_profile_is_encrypted(
                                                                    &encryption_profile,
                                                                ) {
                                                                    let secure = crate::secure_key_store::default_secure_key_store("yougen");
                                                                    let (snapshot, creator_genesis_summary) = {
                                                                        let mut store = state_store.write();
                                                                        match crate::mls::runtime::ensure_creator_mls_snapshot(
                                                                            &mut store,
                                                                            secure.as_ref(),
                                                                            &realm_id,
                                                                            &actor,
                                                                            &device,
                                                                        ) {
                                                                            Ok(summary) => {
                                                                                (store.mls_snapshot_for(&realm_id), summary)
                                                                            }
                                                                            Err(err) => {
                                                                                let message = format!(
                                                                                    "created {}; MLS initial group setup failed: {}",
                                                                                    realm_id,
                                                                                    err.user_message()
                                                                                );
                                                                                realm_state.set(message.clone());
                                                                                status.set(message);
                                                                                return;
                                                                            }
                                                                        }
                                                                    };
                                                                    // Emit the one-time ck.mls.genesis for the
                                                                    // freshly-created creator group at epoch 0,
                                                                    // BEFORE any ck.mls.commit can bump the epoch.
                                                                    // A duplicate (mls_genesis_already_exists) is
                                                                    // treated as success. Failure is non-fatal:
                                                                    // soland lazily defaults a never-seen group to
                                                                    // epoch 0, so commits still work; we just leave
                                                                    // the genesis_emitted flag unset to retry later
                                                                    // via the kanban encrypted-write path.
                                                                    let genesis_event = creator_genesis_summary
                                                                        .as_ref()
                                                                        .and_then(|genesis_summary| {
                                                                            let store = state_store.read();
                                                                            if store.mls_genesis_emitted_for(&realm_id) {
                                                                                return None;
                                                                            }
                                                                            match crate::views::kanban::build_creator_mls_genesis_event(
                                                                                &store,
                                                                                &realm_id,
                                                                                &actor,
                                                                                &device,
                                                                                Some(genesis_summary),
                                                                            ) {
                                                                                Ok(event) => event,
                                                                                Err(err) => {
                                                                                    tracing::warn!(
                                                                                        error = %err,
                                                                                        realm = %realm_id,
                                                                                        "building ck.mls.genesis event failed",
                                                                                    );
                                                                                    None
                                                                                }
                                                                            }
                                                                        });
                                                                    if let Some(genesis_event) = genesis_event {
                                                                        match api.submit_event_envelope(&genesis_event).await {
                                                                            Ok(_) => {
                                                                                state_store.write().mark_mls_genesis_emitted(realm_id.clone());
                                                                            }
                                                                            Err(err) => {
                                                                                let text = err.to_string();
                                                                                if text.contains("mls_genesis_already_exists") {
                                                                                    state_store.write().mark_mls_genesis_emitted(realm_id.clone());
                                                                                } else {
                                                                                    tracing::warn!(
                                                                                        error = %text,
                                                                                        realm = %realm_id,
                                                                                        "ck.mls.genesis submit failed; soland will default epoch 0 and the kanban write path will retry",
                                                                                    );
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    if let Some(snapshot) = snapshot {
                                                                        // §7.10: a brand-new Realm has no prior series, so
                                                                        // this resolves to a genesis envelope — and it seeds
                                                                        // the series-tail cache so post-commit continuous
                                                                        // uploads chain successors without an extra read.
                                                                        match crate::components::upload_mls_history_backup_now(
                                                                            &api,
                                                                            &base,
                                                                            &actor,
                                                                            &device,
                                                                            &realm_id,
                                                                            &snapshot,
                                                                        )
                                                                        .await
                                                                        {
                                                                            Ok(backup_id) => {
                                                                                initial_mls_backup_id = Some(backup_id);
                                                                            }
                                                                            Err(err) => {
                                                                                tracing::warn!(
                                                                                    error = %err,
                                                                                    realm = %realm_id,
                                                                                    "initial MLS history backup upload failed"
                                                                                );
                                                                            }
                                                                        }
                                                                    }
                                                                }

                                                                let mut steps = vec![format!("created {}", realm_id)];
                                                                if invitees.is_empty() {
                                                                    steps.push("seeded owner only".to_owned());
                                                                } else {
                                                                    steps.push(format!("seeded {} member(s)", invitees.len()));
                                                                }
                                                                steps.push(format!(
                                                                    "canonical policy {} / {} / {}",
                                                                    discoverability,
                                                                    join_rule,
                                                                    history_visibility
                                                                ));
                                                                if !plaintext_services.is_empty() {
                                                                    steps.push(format!(
                                                                        "plaintext services {}",
                                                                        plaintext_services.len()
                                                                    ));
                                                                }
                                                                if let Some(backup_id) = initial_mls_backup_id {
                                                                    steps.push(format!(
                                                                        "MLS ready; history backup {}",
                                                                        short_protocol_id(&backup_id)
                                                                    ));
                                                                } else if crate::security_state::encryption_profile_is_encrypted(
                                                                    &encryption_profile,
                                                                ) {
                                                                    steps.push("MLS ready locally".to_owned());
                                                                }
                                                                if crate::api::encryption_profile_uses_recommended_floor(
                                                                    &encryption_profile,
                                                                ) {
                                                                    steps.push("metadata/content floor e2ee_required".to_owned());
                                                                }

                                                                let message = steps.join(" · ");
                                                                realm_state.set(message.clone());
                                                                status.set(message);
                                                                create_step.set(NewRealmStep::Done);
                                                                if crate::security_state::encryption_profile_is_encrypted(
                                                                    &encryption_profile,
                                                                ) && let Some(signal) = backup_trigger_signal {
                                                                    // Realm bootstrap creates the account MLS secret
                                                                    // before the first encrypted message/card write,
                                                                    // so trigger the recovery-passphrase prompt here
                                                                    // instead of waiting for a later write hook.
                                                                    crate::components::maybe_flag_mls_backup_after_encrypted_write(
                                                                        base.clone(),
                                                                        api_token.clone(),
                                                                        actor.clone(),
                                                                        signal,
                                                                    )
                                                                    .await;
                                                                }
                                                            }
                                                            Err(error) => {
                                                                let message = if is_auth_expired_error(&error) {
                                                                    // The short-lived principal bearer may have
                                                                    // simply rolled over between background-poller
                                                                    // ticks. Try the same silent re-mint every
                                                                    // other path uses before wiping the session
                                                                    // and bouncing to login.
                                                                    if crate::session::refresh_current_bearer()
                                                                        .await
                                                                        .is_some()
                                                                    {
                                                                        "Session refreshed — retry creating the Realm.".to_owned()
                                                                    } else {
                                                                        token.set(String::new());
                                                                        persist_config(
                                                                            config_store,
                                                                            base.clone(),
                                                                            actor.clone(),
                                                                            device.clone(),
                                                                            String::new(),
                                                                        );
                                                                        let _ = navigator.push(Route::Login);
                                                                        "Session expired. Sign in again before creating a Realm.".to_owned()
                                                                    }
                                                                } else {
                                                                    format!("create failed: {error}")
                                                                };
                                                                realm_state.set(message.clone());
                                                                status.set(message);
                                                            }
                                                        }
                                                        }
                                                        Err(error) => {
                                                            let message = format!("invalid server URL: {error}");
                                                            realm_state.set(message.clone());
                                                            status.set(message);
                                                        }
                                                    }
                                                });
                                            }
                                        },
                                        "Create Realm"
                                    }
                                }
                            }
                        }

                        if active_create_step == NewRealmStep::Done {
                            div { class: "setup-step-panel", "data-testid": "realm-setup-done",
                                div { class: "event-head",
                                    span { "Done" }
                                    span { "next context" }
                                }
                                if has_created_realm {
                                    div { class: "setup-summary-list",
                                        div { class: "setup-summary-row",
                                            strong { "Created Realm" }
                                            span { class: "mono", title: "{created_realm_id_value}", "data-testid": "selected-realm-id", "{created_realm_id_label}" }
                                        }
                                        div { class: "setup-summary-row setup-summary-row-stack",
                                            strong { "Bootstrap state" }
                                            span { class: "muted", "{realm_state_value}" }
                                        }
                                    }
                                    div { class: "actions setup-nav-actions",
                                        Link {
                                            class: "primary",
                                            to: Route::Realm { realm_id: created_realm_id_value.clone() },
                                            "Open Realm"
                                        }
                                    }
                                } else {
                                    div { class: "muted", "Create a Realm before opening the next context." }
                                }
                            }
                        }
                        }
                    }
                }

            }

            if active_section == SetupSection::NewSpace {
                div { class: "setup-shell new-space-shell", "data-testid": "space-create-flow",
                    div { class: "setup-column",
                        div { class: "event new-space-hero",
                            div { class: "event-head",
                                span { "New Space" }
                                span { "navigation container" }
                            }
                            h2 { class: "settings-content-title", "Create a Space inside a Realm" }
                            div { class: "muted",
                                "A Space is a product-structure container (project / folder / board / list). It lives inside a Realm and inherits all security from it — no separate membership, encryption, or federation decisions."
                            }
                        }

                        div { class: "event",
                            div { class: "event-head",
                                span { "Basics" }
                                span { "title + kind" }
                            }
                            div { class: "workflow-form setup-form-grid",
                                div { class: "setup-field",
                                    Label { html_for: "new-space-title-input-input", "Space title" }
                                    Input {
                                        id: "new-space-title-input-input",
                                        "data-testid": "new-space-title-input",
                                        required: true,
                                        "aria-required": "true",
                                        value: "{new_space_title_value}",
                                        placeholder: "Backlog, Roadmap, Onboarding...",
                                        oninput: move |event: FormEvent| new_space_title.set(event.value())
                                    }
                                }
                                div { class: "setup-field",
                                    label { "Kind" }
                                    Select::<String> {
                                        "data-testid": "new-space-kind-input",
                                        value: Some(new_space_kind_selected.into()),
                                        on_value_change: move |v: Option<String>| {
                                            if let Some(v) = v {
                                                new_space_kind.set(v);
                                            }
                                        },
                                        for (i, (option_value, label, _)) in SPACE_KIND_OPTIONS.iter().enumerate() {
                                            SelectOption::<String> {
                                                index: i,
                                                value: option_value.to_string(),
                                                text_value: "{label}",
                                                "{label}"
                                            }
                                        }
                                    }
                                    if let Some(kind_hint) = SPACE_KIND_OPTIONS
                                        .iter()
                                        .find(|(value, _, _)| *value == new_space_kind_value)
                                        .map(|(_, _, hint)| *hint)
                                        .filter(|hint| !hint.is_empty())
                                    {
                                        div { class: "muted", "{kind_hint}" }
                                    }
                                }
                                div { class: "setup-field setup-field-span-2",
                                    Label { html_for: "new-space-summary-input-input", "Summary" }
                                    Textarea {
                                        id: "new-space-summary-input-input",
                                        "data-testid": "new-space-summary-input",
                                        value: "{new_space_summary_value}",
                                        rows: "3",
                                        placeholder: "Optional description.",
                                        oninput: move |event: FormEvent| new_space_summary.set(event.value())
                                    }
                                }
                                // Spec realm-and-space.md §3.2 — optional
                                // parent. Picker is filtered by realm_id
                                // (Realms aren't valid parents per §2.1;
                                // cross-Realm parents are valid but live
                                // under `default_realm_id`).
                                div { class: "setup-field setup-field-span-2",
                                    label { "Parent Space (optional)" }
                                    if new_space_realm_id_value.trim().is_empty() {
                                        div { class: "muted", "Choose New Space from a Realm or Space row in the sidebar to set the home Realm." }
                                    } else if parent_candidates.is_empty() {
                                        div { class: "muted", "No sibling Spaces in this Realm yet — leave at root." }
                                    } else {
                                        Select::<String> {
                                            "data-testid": "new-space-parent-input",
                                            value: Some(new_space_parent_id_selected.into()),
                                            on_value_change: move |v: Option<String>| {
                                                if let Some(v) = v {
                                                    new_space_parent_id.set(v);
                                                }
                                            },
                                            SelectOption::<String> {
                                                index: 0usize,
                                                value: "".to_string(),
                                                text_value: "(root — no parent)",
                                                "(root — no parent)"
                                            }
                                            for (i, (id, title)) in parent_candidates.iter().enumerate() {
                                                {
                                                    let id_label = short_protocol_id(id);
                                                    rsx! {
                                                        SelectOption::<String> {
                                                            index: i + 1,
                                                            value: id.to_string(),
                                                            text_value: "{title} ({id_label})",
                                                            "{title} ({id_label})"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            // Spec realm-and-space.md §3.2 — `default_realm_id`
                            // points new resources created from this Space at
                            // a different Realm. Most users leave this empty
                            // (= inherit home Realm). Folded as advanced.
                            details { class: "setup-advanced",
                                "data-testid": "new-space-advanced",
                                summary { class: "setup-advanced-summary",
                                    "Advanced (cross-Realm default for new resources)"
                                }
                                div { class: "workflow-form setup-form-grid",
                                    div { class: "setup-field setup-field-span-2",
                                        label { "default_realm_id" }
                                        if available_realms.is_empty() {
                                            div { class: "muted", "Need at least one Realm to point at." }
                                        } else {
                                            Select::<String> {
                                                "data-testid": "new-space-default-realm-ref-input",
                                                value: Some(new_space_default_realm_id_selected.into()),
                                                on_value_change: move |v: Option<String>| {
                                                    if let Some(v) = v {
                                                        new_space_default_realm_id.set(v);
                                                    }
                                                },
                                                SelectOption::<String> {
                                                    index: 0usize,
                                                    value: "".to_string(),
                                                    text_value: "(inherit — use home Realm)",
                                                    "(inherit — use home Realm)"
                                                }
                                                for (i, (id, title)) in available_realms.iter().enumerate() {
                                                    {
                                                        let id_label = short_protocol_id(id);
                                                        rsx! {
                                                            SelectOption::<String> {
                                                                index: i + 1,
                                                                value: id.to_string(),
                                                                text_value: "{title} ({id_label})",
                                                                "{title} ({id_label})"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        div { class: "muted",
                                            "New Flows / Morphs / Views created from this Space land in this Realm by default. Doesn't grant access — the user still needs membership."
                                        }
                                    }
                                }
                            }
                            div { class: "actions setup-nav-actions",
                                Button {
                                    variant: ButtonVariant::Primary,
                                    "data-testid": "new-space-submit-button",
                                    disabled: !new_space_can_submit,
                                    onclick: {
                                        let base_url = base_url.clone();
                                        move |_| {
                                        let api_token = token();
                                        let base = base_url.clone();
                                        let realm_id = new_space_realm_id();
                                        let title = new_space_title();
                                        let summary = new_space_summary();
                                        let kind = new_space_kind();
                                        let parent_id = new_space_parent_id();
                                        let default_realm_id = new_space_default_realm_id();
                                        let actor = account_did();
                                        new_space_state.set("Submitting ck.space.create...".to_owned());
                                        spawn(async move {
                                            match authed_api(&base, api_token) {
                                                Ok(api) => {
                                                    let summary_opt = if summary.trim().is_empty() {
                                                        None
                                                    } else {
                                                        Some(summary.as_str())
                                                    };
                                                    let parent_opt = if parent_id.trim().is_empty() {
                                                        None
                                                    } else {
                                                        Some(parent_id.as_str())
                                                    };
                                                    let default_realm_opt = if default_realm_id.trim().is_empty() {
                                                        None
                                                    } else {
                                                        Some(default_realm_id.as_str())
                                                    };
                                                    match api.create_space_under_realm(
                                                        &realm_id,
                                                        &actor,
                                                        &title,
                                                        summary_opt,
                                                        &kind,
                                                        parent_opt,
                                                        default_realm_opt,
                                                    ).await {
                                                        Ok(space) => {
                                                            // Persist a tagged Space projection so
                                                            // the sidebar (M-SIDEBAR-TIER-1) can
                                                            // classify it without re-fetching.
                                                            // `__kind` is yougen-local metadata —
                                                            // server-projected entries use the
                                                            // canonical `schema` field, but for the
                                                            // optimistic local write here we use the
                                                            // simpler marker.
                                                            let mut projection_body = json!({
                                                                "__kind": "space",
                                                                "realm_id": realm_id.clone(),
                                                                "kind": kind.clone(),
                                                                "summary": {
                                                                    "title": title.clone(),
                                                                    "summary": summary.clone(),
                                                                    "kind": kind.clone(),
                                                                },
                                                                "timeline": { "events": [] }
                                                            });
                                                            if let Some(parent) = parent_opt {
                                                                projection_body["parent_space_id"] = json!(parent);
                                                            }
                                                            if let Some(default_realm) = default_realm_opt {
                                                                projection_body["default_realm_id"] = json!(default_realm);
                                                            }
                                                            state_store.write().save_realm_tree_projection(
                                                                space.space_id.clone(),
                                                                projection_body,
                                                            );
                                                            new_space_created_id.set(space.space_id.clone());
                                                            new_space_state.set(format!(
                                                                "Created Space {} (kind={}) inside {}{}",
                                                                space.space_id,
                                                                kind,
                                                                realm_id,
                                                                parent_opt.map(|p| format!(" under {p}")).unwrap_or_default(),
                                                            ));
                                                        }
                                                        Err(error) => {
                                                            new_space_state.set(format!("create_space failed: {error}"));
                                                        }
                                                    }
                                                }
                                                Err(error) => {
                                                    new_space_state.set(format!("invalid base URL: {error}"));
                                                }
                                            }
                                        });
                                        }
                                    },
                                    "Create Space"
                                }
                            }
                        }
                    }

                    div { class: "setup-column setup-summary-column",
                        div { class: "event new-space-summary",
                            div { class: "event-head",
                                span { "Outcome" }
                                span { "spec realm-and-space.md §3" }
                            }
                            div { class: "setup-summary-row",
                                strong { "Created Space" }
                                span { class: "mono", "data-testid": "new-space-created-id",
                                    if !new_space_created_id_value.trim().is_empty() {
                                        "{new_space_created_id_label}"
                                    } else {
                                        "not created yet"
                                    }
                                }
                            }
                            div { class: "setup-summary-row setup-summary-row-stack",
                                strong { "Status" }
                                span { class: "muted", "{new_space_state_value}" }
                            }
                            div { class: "setup-summary-row setup-summary-row-stack",
                                strong { "Wire shape" }
                                span { class: "muted",
                                    "ck.space.create event + optional parent_space_id / default_realm_id. Lifecycle actions below dispatch ck.space.archive / restore / tombstone."
                                }
                            }
                        }

                        // Spec realm-and-space.md §3.4 — Space lifecycle
                        // (archive / restore / tombstone). Disabled
                        // until a Space has been created in this session;
                        // server enforces the state-machine transitions.
                        div { class: "event",
                            "data-testid": "space-lifecycle-panel",
                            div { class: "event-head",
                                span { "Lifecycle actions" }
                                span { "archive / restore / tombstone" }
                            }
                            if new_space_created_id_value.trim().is_empty() {
                                div { class: "muted",
                                    "Create a Space above to enable lifecycle actions on it."
                                }
                            } else {
                                div { class: "actions",
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "space-lifecycle-archive",
                                        title: "Set state to archived; server doesn't cascade.",
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let api_token = token();
                                                let base = base.clone();
                                                let actor = account_did();
                                                let space_id = new_space_created_id();
                                                let realm_id = new_space_realm_id();
                                                new_space_state.set("Submitting ck.space.archive...".to_owned());
                                                spawn(async move {
                                                    match authed_api(&base, api_token) {
                                                        Ok(api) => match api.change_space_lifecycle(
                                                            &space_id, &realm_id, &actor, "ck.space.archive",
                                                        ).await {
                                                            Ok(()) => new_space_state.set(format!(
                                                                "Archived {}",
                                                                short_protocol_id(&space_id)
                                                            )),
                                                            Err(error) => new_space_state.set(format!("archive failed: {error}")),
                                                        },
                                                        Err(error) => new_space_state.set(format!("invalid base URL: {error}")),
                                                    }
                                                });
                                            }
                                        },
                                        "Archive"
                                    }
                                    Button {
                                        variant: ButtonVariant::Secondary,
                                        "data-testid": "space-lifecycle-restore",
                                        title: "Move archived → active; only valid from archived.",
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let api_token = token();
                                                let base = base.clone();
                                                let actor = account_did();
                                                let space_id = new_space_created_id();
                                                let realm_id = new_space_realm_id();
                                                new_space_state.set("Submitting ck.space.restore...".to_owned());
                                                spawn(async move {
                                                    match authed_api(&base, api_token) {
                                                        Ok(api) => match api.change_space_lifecycle(
                                                            &space_id, &realm_id, &actor, "ck.space.restore",
                                                        ).await {
                                                            Ok(()) => new_space_state.set(format!(
                                                                "Restored {}",
                                                                short_protocol_id(&space_id)
                                                            )),
                                                            Err(error) => new_space_state.set(format!("restore failed: {error}")),
                                                        },
                                                        Err(error) => new_space_state.set(format!("invalid base URL: {error}")),
                                                    }
                                                });
                                            }
                                        },
                                        "Restore"
                                    }
                                    Button {
                                        variant: ButtonVariant::Destructive,
                                        "data-testid": "space-lifecycle-tombstone",
                                        title: "Irreversible. Server rejects if live child Spaces / placement Flows exist.",
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let api_token = token();
                                                let base = base.clone();
                                                let actor = account_did();
                                                let space_id = new_space_created_id();
                                                let realm_id = new_space_realm_id();
                                                new_space_state.set("Submitting ck.space.tombstone...".to_owned());
                                                spawn(async move {
                                                    match authed_api(&base, api_token) {
                                                        Ok(api) => match api.change_space_lifecycle(
                                                            &space_id, &realm_id, &actor, "ck.space.tombstone",
                                                        ).await {
                                                            Ok(()) => new_space_state.set(format!(
                                                                "Tombstoned {} (irreversible)",
                                                                short_protocol_id(&space_id)
                                                            )),
                                                            Err(error) => new_space_state.set(format!("tombstone failed: {error}")),
                                                        },
                                                        Err(error) => new_space_state.set(format!("invalid base URL: {error}")),
                                                    }
                                                });
                                            }
                                        },
                                        "Tombstone"
                                    }
                                }
                                div { class: "muted",
                                    "Tombstone is irreversible — server rejects with space_has_live_dependents if any child Space or placement Flow is still live (spec §3.4)."
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
