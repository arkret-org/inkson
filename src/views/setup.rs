use dioxus::prelude::*;
use dioxus_router::Link;
use dioxus_router::hooks::use_navigator;
use serde_json::{Value, json};

use crate::api::is_auth_expired_error;
use crate::components::PermissionPillRow;
use crate::config::LocalConfigStore;
use crate::local_state::LocalStateStore;
use crate::routes::Route;
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
        "The Space should not disclose that it exists to unauthorized viewers.",
    ),
];

const JOIN_RULE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "public",
        "Public",
        "Anyone who can see the Space can join without a separate approval step.",
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
        "Past history is readable without joining. Use only with intentionally open Spaces.",
    ),
    (
        "shared",
        "Shared",
        "New members can read the pre-join history that is meant to be shared with the whole Space.",
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
        "MLS (end-to-end)",
        "Recommended. Messages are encrypted with MLS; the server only sees ciphertext.",
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
// from `cx.realm.policy` events but seeded at create time. `open` is
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

// Spec realm-and-space.md §2.3 — `anchor_profile`. Create-locked.
// `single_did` is the dev / single-operator default; the others are
// for production deployments with multiple anchorer principals.
const ANCHOR_PROFILE_OPTIONS: [(&str, &str, &str); 4] = [
    (
        "single_did",
        "Single DID",
        "One principal signs anchors. Simplest setup; default.",
    ),
    (
        "threshold",
        "Threshold",
        "k-of-n signature; configure the participating DIDs in policy.",
    ),
    (
        "open_set",
        "Open set",
        "Any holder of the anchorer capability may sign.",
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
        "Default. Interoperable everywhere in Contrix v1.",
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
    /// Realm bootstrap flow (legacy slug `spaces` for URL stability —
    /// the form actually creates a Realm; the wire event is
    /// `cx.realm.create`).
    Spaces,
    /// Phase 3 — `cx.space.create` form: pick a Realm, pick a kind,
    /// optionally pick a parent Space. The Space lives inside the
    /// Realm and inherits all security semantics from it.
    NewSpace,
}

impl SetupSection {
    fn from_slug(slug: Option<&str>) -> Self {
        match slug.unwrap_or_default() {
            "" => Self::Spaces,
            "overview" => Self::Overview,
            // Canonical slug for the Realm bootstrap surface — the
            // form actually creates a Realm (cx.realm.create), so the
            // URL should say "realms". `spaces` is kept as a legacy
            // alias for any bookmark / external link that was minted
            // before the rename and would otherwise 404.
            "realms" | "spaces" => Self::Spaces,
            "new-space" => Self::NewSpace,
            _ => Self::Overview,
        }
    }

    fn slug(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Spaces => "realms",
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
enum NewSpaceStep {
    Basics,
    Boundary,
    Seed,
    Done,
}

const NEW_SPACE_STEPS: [NewSpaceStep; 4] = [
    NewSpaceStep::Basics,
    NewSpaceStep::Boundary,
    NewSpaceStep::Seed,
    NewSpaceStep::Done,
];

impl NewSpaceStep {
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
    mut selected_space: Signal<String>,
    mut status: Signal<String>,
    section: Option<String>,
) -> Element {
    let active_section = SetupSection::from_slug(section.as_deref());
    let has_session = !token().trim().is_empty();
    let navigator = use_navigator();

    let mut create_step = use_signal(|| NewSpaceStep::Basics);
    let mut seed_members = use_signal(String::new);
    let mut space_title = use_signal(String::new);
    let mut space_summary = use_signal(String::new);
    let mut space_discoverability = use_signal(|| "listed".to_owned());
    let mut space_policy_join_rule = use_signal(|| "invite".to_owned());
    let mut space_policy_history_visibility = use_signal(|| "shared".to_owned());
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
    let mut realm_anchor_profile = use_signal(|| "single_did".to_owned());
    let mut realm_digest_algorithm = use_signal(|| "sha256".to_owned());
    // Phase 3 — `cx.space.create` form state. The Space inherits all
    // security from its home Realm, so the only choices are which
    // Realm to live in, the human-visible metadata, and `kind`.
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
    let mut new_space_state = use_signal(|| "Draft not created yet".to_owned());
    let mut new_space_created_id = use_signal(String::new);
    let mut space_state = use_signal(|| "Draft not created yet".to_owned());
    let mut created_space_id = use_signal(String::new);

    let selected_space_id = selected_space();
    let has_selected_space = !selected_space_id.trim().is_empty();
    let active_create_step = create_step();
    let title_value = space_title();
    let summary_value = space_summary();
    let discoverability_value = space_discoverability();
    let join_rule_value = space_policy_join_rule();
    let history_visibility_value = space_policy_history_visibility();
    let encryption_profile_value = realm_encryption_profile();
    let security_class_value = realm_security_class();
    let federation_policy_value = realm_federation_policy();
    let anchor_profile_value = realm_anchor_profile();
    let digest_algorithm_value = realm_digest_algorithm();
    let federation_policy_open_forbidden = security_class_value == "high_assurance";
    // M-UX-CONTEXT-1: the sidebar's per-row "+" action sets
    // `selected_space` to the clicked Realm / Space and routes to
    // the NewSpace section. When the user lands here with an empty
    // form AND a selected row, pre-fill realm_id (always) and
    // parent_space_id (when the source row is a Space). Guarded by
    // "form realm_id is empty" so subsequent edits aren't clobbered.
    if active_section == SetupSection::NewSpace && new_space_realm_id().is_empty() {
        let selected = selected_space();
        let selected = selected.trim();
        if !selected.is_empty()
            && let Some(body) = state_store
                .read()
                .load()
                .space_projections
                .get(selected)
                .cloned()
        {
            let kind = match body
                .get("__kind")
                .and_then(|kind| kind.as_str())
                .or_else(|| body.get("schema").and_then(|schema| schema.as_str()))
            {
                Some("space") | Some("cx.schema.space.v1") => "space",
                _ => "realm",
            };
            if kind == "realm" {
                new_space_realm_id.set(selected.to_owned());
            } else {
                // For a Space row, the new sibling/child lives in
                // the same home Realm; the clicked Space becomes
                // the parent.
                let realm = body
                    .get("realm_id")
                    .and_then(|realm| realm.as_str())
                    .unwrap_or(selected)
                    .to_owned();
                new_space_realm_id.set(realm);
                new_space_parent_id.set(selected.to_owned());
            }
        }
    }

    let new_space_realm_id_value = new_space_realm_id();
    let new_space_title_value = new_space_title();
    let new_space_summary_value = new_space_summary();
    let new_space_kind_value = new_space_kind();
    let new_space_parent_id_value = new_space_parent_id();
    let new_space_default_realm_id_value = new_space_default_realm_id();
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
        .space_projections
        .iter()
        .map(|(id, body)| (id.clone(), body.clone()))
        .collect();
    let projection_kind = |body: &Value| -> &'static str {
        match body
            .get("__kind")
            .and_then(|kind| kind.as_str())
            .or_else(|| body.get("schema").and_then(|schema| schema.as_str()))
        {
            Some("space") | Some("cx.schema.space.v1") => "space",
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
    let projection_title = |id: &str, body: &Value| -> String {
        body.get("summary")
            .and_then(|summary| summary.get("title"))
            .and_then(|title| title.as_str())
            .unwrap_or(id)
            .to_owned()
    };
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
    let space_state_value = space_state();
    let created_space_id_value = created_space_id();
    let parsed_seed_members = parse_seed_members(&seed_members_value);
    let seed_member_count = parsed_seed_members.len();
    let has_created_space = !created_space_id_value.trim().is_empty();
    let created_space_id_label = short_protocol_id(&created_space_id_value);
    let current_visibility_hint = policy_combination_hint(
        &discoverability_value,
        &join_rule_value,
        &history_visibility_value,
    );
    let current_policy_error = matches!(current_visibility_hint, Some(("error", _, _)));
    let basics_ready = !title_value.trim().is_empty();
    let boundary_ready = !current_policy_error;
    let can_advance_step = match active_create_step {
        NewSpaceStep::Basics => basics_ready,
        NewSpaceStep::Boundary => boundary_ready,
        NewSpaceStep::Seed => basics_ready && boundary_ready,
        NewSpaceStep::Done => has_created_space,
    };
    let can_create_space = has_session && basics_ready && boundary_ready;

    rsx! {
        div { class: "timeline", "data-testid": "setup-panel",
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
                                to: Route::SetupSection { section: SetupSection::Spaces.slug().to_owned() },
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
                            span { "actors / handles / spaces" }
                            Link { class: "secondary", to: Route::Directory, "Open Search" }
                        }
                        div { class: "metric",
                            strong { "Space timeline" }
                            span { "after bootstrap" }
                            if has_selected_space {
                                Link {
                                    class: "secondary",
                                    to: Route::Space { space_id: selected_space_id.clone() },
                                    "Open Current Space"
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

            if active_section == SetupSection::Spaces {
                div { class: "setup-shell new-space-shell", "data-testid": "space-lifecycle-flow",
                    div { class: "setup-column",
                        div { class: "event new-space-hero", "data-testid": "space-setup-guide",
                            div { class: "event-head",
                                span { "New Realm" }
                                span { "security boundary" }
                            }
                            h2 { class: "settings-content-title", "Create a Realm" }
                            div { class: "muted",
                                "A Realm is the security / sync / E2EE boundary. Discoverability, join rule, history visibility, encryption profile and security class are independent decisions — encryption_profile and security_class are create-locked, so pick deliberately."
                            }
                            PermissionPillRow {
                                discoverability: Some(discoverability_value.clone()),
                                join_rule: Some(join_rule_value.clone()),
                                history_visibility: Some(history_visibility_value.clone()),
                            }
                        }

                        div { class: "event new-space-stepper",
                            div { class: "event-head",
                                span { "Create steps" }
                                span { "{active_create_step.number()} / 4" }
                            }
                            div { class: "setup-step-list",
                                for step in NEW_SPACE_STEPS {
                                    button {
                                        class: if active_create_step == step { "primary" } else { "secondary" },
                                        disabled: step == NewSpaceStep::Done && !has_created_space,
                                        onclick: move |_| create_step.set(step),
                                        span { class: "setup-step-index", "{step.number()}" }
                                        span { class: "setup-step-label",
                                            strong { "{step.label()}" }
                                            small { "{step.subtitle()}" }
                                        }
                                    }
                                }
                            }
                        }

                        if active_create_step == NewSpaceStep::Basics {
                            div { class: "event",
                                div { class: "event-head",
                                    span { "Basics" }
                                    span { "required title" }
                                }
                                div { class: "workflow-form setup-form-grid",
                                    div { class: "setup-field",
                                        label { "Realm title" }
                                        input {
                                            "data-testid": "space-title-input",
                                            value: "{title_value}",
                                            placeholder: "Engineering, Research, Design system...",
                                            oninput: move |event| space_title.set(event.value())
                                        }
                                    }
                                    div { class: "setup-field setup-field-span-2",
                                        label { "Summary" }
                                        textarea {
                                            "data-testid": "space-summary-input",
                                            value: "{summary_value}",
                                            rows: "3",
                                            placeholder: "What this Realm is for.",
                                            oninput: move |event| space_summary.set(event.value())
                                        }
                                    }
                                }
                                div { class: "actions setup-nav-actions",
                                    button {
                                        class: "primary",
                                        "data-testid": "new-space-next-button",
                                        disabled: !can_advance_step,
                                        onclick: move |_| create_step.set(active_create_step.next()),
                                        "Next: Boundary"
                                    }
                                }
                            }
                        }

                        if active_create_step == NewSpaceStep::Boundary {
                            div { class: "event",
                                div { class: "event-head",
                                    span { "Boundary" }
                                    span { "three independent axes" }
                                }
                                div { class: "setup-axis-grid",
                                    div { class: "metric directory-axis-card",
                                        strong { "Discoverability" }
                                        div { class: "workflow-form setup-field",
                                            label { "Who can discover that this Realm exists?" }
                                            select {
                                                "data-testid": "space-discoverability-input",
                                                value: "{discoverability_value}",
                                                onchange: move |event| space_discoverability.set(event.value()),
                                                for (option_value, label, _) in DISCOVERABILITY_OPTIONS {
                                                    option {
                                                        value: "{option_value}",
                                                        selected: discoverability_value == option_value,
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
                                            select {
                                                "data-testid": "space-policy-join-rule-input",
                                                value: "{join_rule_value}",
                                                onchange: move |event| space_policy_join_rule.set(event.value()),
                                                for (option_value, label, _) in JOIN_RULE_OPTIONS {
                                                    option {
                                                        value: "{option_value}",
                                                        selected: join_rule_value == option_value,
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
                                            select {
                                                "data-testid": "space-policy-history-visibility-input",
                                                value: "{history_visibility_value}",
                                                onchange: move |event| space_policy_history_visibility.set(event.value()),
                                                for (option_value, label, _) in HISTORY_VISIBILITY_OPTIONS {
                                                    option {
                                                        value: "{option_value}",
                                                        selected: history_visibility_value == option_value,
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
                                            select {
                                                "data-testid": "realm-encryption-profile-input",
                                                value: "{encryption_profile_value}",
                                                onchange: move |event| realm_encryption_profile.set(event.value()),
                                                for (option_value, label, _) in ENCRYPTION_PROFILE_OPTIONS {
                                                    option {
                                                        value: "{option_value}",
                                                        selected: encryption_profile_value == option_value,
                                                        "{label}"
                                                    }
                                                }
                                            }
                                            div { class: "muted",
                                                "{ENCRYPTION_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == encryption_profile_value).map(|(_, _, hint)| *hint).unwrap_or(\"Encryption profile is not set.\")}"
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
                                            select {
                                                "data-testid": "realm-security-class-input",
                                                value: "{security_class_value}",
                                                onchange: move |event| realm_security_class.set(event.value()),
                                                for (option_value, label, _) in SECURITY_CLASS_OPTIONS {
                                                    option {
                                                        value: "{option_value}",
                                                        selected: security_class_value == option_value,
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
                                        "Advanced (federation policy / anchor profile / hash profile)"
                                    }
                                    div { class: "setup-axis-grid setup-advanced-grid",
                                        div { class: "metric directory-axis-card",
                                            strong { "Federation policy" }
                                            div { class: "workflow-form setup-field",
                                                label { "How does this Realm interoperate with other deployments?" }
                                                select {
                                                    "data-testid": "realm-federation-policy-input",
                                                    value: "{federation_policy_value}",
                                                    onchange: move |event| realm_federation_policy.set(event.value()),
                                                    for (option_value, label, _) in FEDERATION_POLICY_OPTIONS {
                                                        option {
                                                            value: "{option_value}",
                                                            selected: federation_policy_value == option_value,
                                                            disabled: federation_policy_open_forbidden && option_value == "open",
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
                                            strong { "Anchor profile" }
                                            div { class: "workflow-form setup-field",
                                                label { "Who signs durable anchors for this Realm?" }
                                                select {
                                                    "data-testid": "realm-anchor-profile-input",
                                                    value: "{anchor_profile_value}",
                                                    onchange: move |event| realm_anchor_profile.set(event.value()),
                                                    for (option_value, label, _) in ANCHOR_PROFILE_OPTIONS {
                                                        option {
                                                            value: "{option_value}",
                                                            selected: anchor_profile_value == option_value,
                                                            "{label}"
                                                        }
                                                    }
                                                }
                                                div { class: "muted",
                                                    "{ANCHOR_PROFILE_OPTIONS.iter().find(|(value, _, _)| *value == anchor_profile_value).map(|(_, _, hint)| *hint).unwrap_or(\"Anchor profile is not set.\")}"
                                                }
                                            }
                                        }
                                        div { class: "metric directory-axis-card",
                                            strong { "Hash profile" }
                                            div { class: "workflow-form setup-field",
                                                label { "Digest algorithm for canonical hashing." }
                                                select {
                                                    "data-testid": "realm-hash-profile-input",
                                                    value: "{digest_algorithm_value}",
                                                    onchange: move |event| realm_digest_algorithm.set(event.value()),
                                                    for (option_value, label, _) in HASH_PROFILE_OPTIONS {
                                                        option {
                                                            value: "{option_value}",
                                                            selected: digest_algorithm_value == option_value,
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
                                    button {
                                        class: "secondary",
                                        "data-testid": "new-space-back-button",
                                        onclick: move |_| create_step.set(active_create_step.previous()),
                                        "Back"
                                    }
                                    button {
                                        class: "primary",
                                        "data-testid": "new-space-next-button",
                                        disabled: !can_advance_step,
                                        onclick: move |_| create_step.set(active_create_step.next()),
                                        "Next: Seed"
                                    }
                                }
                            }
                        }

                        if active_create_step == NewSpaceStep::Seed {
                            div { class: "event",
                                div { class: "event-head",
                                    span { "Seed members" }
                                    span { "optional" }
                                }
                                div { class: "workflow-form setup-form-grid",
                                    div { class: "setup-field setup-field-span-2",
                                        label { "Initial members" }
                                        textarea {
                                            "data-testid": "seed-members-input",
                                            value: "{seed_members_value}",
                                            rows: "4",
                                            placeholder: "alice:example.com\nbob:example.com",
                                            oninput: move |event| seed_members.set(event.value())
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
                                    button {
                                        class: "secondary",
                                        "data-testid": "new-space-back-button",
                                        onclick: move |_| create_step.set(active_create_step.previous()),
                                        "Back"
                                    }
                                    button {
                                        class: "primary",
                                        "data-testid": "create-space-button",
                                        disabled: !can_create_space,
                                        onclick: {
                                            let base = base_url.clone();
                                            move |_| {
                                                let api_token = token();
                                                let base = base.clone();
                                                let title = space_title();
                                                let summary = space_summary();
                                                let discoverability = space_discoverability();
                                                let join_rule = space_policy_join_rule();
                                                    let history_visibility = space_policy_history_visibility();
                                                    let encryption_profile = realm_encryption_profile();
                                                    let security_class = realm_security_class();
                                                    let federation_policy = realm_federation_policy();
                                                    let anchor_profile = realm_anchor_profile();
                                                    let digest_algorithm = realm_digest_algorithm();
                                                    let seed_text = seed_members();
                                                    let actor = account_did();
                                                    let device = device_id();
                                                let configured_plaintext_service_did =
                                                    plaintext_service_did.clone();
                                                spawn(async move {
                                                    let invitees = parse_seed_members(&seed_text);
                                                    match authed_api(&base, api_token) {
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
                                                                &anchor_profile,
                                                                &digest_algorithm,
                                                                &trust_domain,
                                                                invitees.clone(),
                                                                plaintext_services.clone(),
                                                            ).await {
                                                            Ok(space) => {
                                                                selected_space.set(space.space_id.clone());
                                                                created_space_id.set(space.space_id.clone());
                                                                // Optimistic sidebar update goes
                                                                // through the canonical store —
                                                                // the `spaces` Signal is derived
                                                                // from `state_store.space_projections`
                                                                // by RouterView's derive effect, so
                                                                // the `save_space_projection`
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
                                                                state_store.write().save_space_projection(
                                                                    space.space_id.clone(),
                                                                    json!({
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
                                                                    }),
                                                                );

                                                                let mut steps = vec![format!("created {}", space.space_id)];
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

                                                                let message = steps.join(" · ");
                                                                space_state.set(message.clone());
                                                                status.set(message);
                                                                create_step.set(NewSpaceStep::Done);
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
                                                                space_state.set(message.clone());
                                                                status.set(message);
                                                            }
                                                        }
                                                        }
                                                        Err(error) => {
                                                            let message = format!("invalid server URL: {error}");
                                                            space_state.set(message.clone());
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

                        if active_create_step == NewSpaceStep::Done {
                            div { class: "event", "data-testid": "space-setup-done",
                                div { class: "event-head",
                                    span { "Done" }
                                    span { "next context" }
                                }
                                if has_created_space {
                                    div { class: "setup-summary-list",
                                        div { class: "setup-summary-row",
                                            strong { "Created Realm" }
                                            span { class: "mono", title: "{created_space_id_value}", "{created_space_id_label}" }
                                        }
                                        div { class: "setup-summary-row setup-summary-row-stack",
                                            strong { "Bootstrap state" }
                                            span { class: "muted", "{space_state_value}" }
                                        }
                                    }
                                    div { class: "actions setup-nav-actions",
                                        button {
                                            class: "secondary",
                                            "data-testid": "new-space-back-button",
                                            onclick: move |_| create_step.set(active_create_step.previous()),
                                            "Back"
                                        }
                                        Link {
                                            class: "primary",
                                            to: Route::Space { space_id: created_space_id_value.clone() },
                                            "Open Realm"
                                        }
                                        Link {
                                            class: "secondary",
                                            to: Route::SpaceAdmin { space_id: created_space_id_value.clone() },
                                            "Open Realm Admin"
                                        }
                                    }
                                } else {
                                    div { class: "muted", "Create a Realm before opening the next context." }
                                    div { class: "actions setup-nav-actions",
                                        button {
                                            class: "primary",
                                            "data-testid": "new-space-back-button",
                                            onclick: move |_| create_step.set(NewSpaceStep::Seed),
                                            "Back to Seed"
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "setup-column setup-review-column",
                        div { class: "event",
                            div { class: "event-head",
                                span { "Review" }
                                span { "current draft" }
                            }
                            div { class: "setup-summary-list",
                                div { class: "setup-summary-row",
                                    strong { "Title" }
                                    span { if title_value.trim().is_empty() { "Required" } else { "{title_value}" } }
                                }
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { "Policy" }
                                    PermissionPillRow {
                                        discoverability: Some(discoverability_value.clone()),
                                        join_rule: Some(join_rule_value.clone()),
                                        history_visibility: Some(history_visibility_value.clone()),
                                    }
                                }
                                div { class: "setup-summary-row",
                                    strong { "Seed members" }
                                    span { "{seed_member_count}" }
                                }
                                div { class: "setup-summary-row",
                                    strong { "Created Realm" }
                                    span { class: "mono", "data-testid": "selected-space-id",
                                        if has_created_space { "{created_space_id_label}" } else { "not created yet" }
                                    }
                                }
                                div { class: "setup-summary-row setup-summary-row-stack",
                                    strong { "Bootstrap state" }
                                    span { class: "muted", "{space_state_value}" }
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
                                span { "Home Realm" }
                                span { "required" }
                            }
                            div { class: "workflow-form setup-form-grid",
                                div { class: "setup-field setup-field-span-2",
                                    label { "Pick which Realm this Space lives in" }
                                    if available_realms.is_empty() {
                                        div { class: "inline-warn",
                                            span { class: "body",
                                                strong { "No Realms yet — create one first" }
                                                " Use "
                                                Link {
                                                    to: Route::SetupSection { section: SetupSection::Spaces.slug().to_owned() },
                                                    "New Realm"
                                                }
                                                " then come back."
                                            }
                                        }
                                    } else {
                                        select {
                                            "data-testid": "new-space-realm-input",
                                            value: "{new_space_realm_id_value}",
                                            onchange: move |event| new_space_realm_id.set(event.value()),
                                            option { value: "", "— pick a Realm —" }
                                            for (id, title) in &available_realms {
                                                {
                                                    let id_label = short_protocol_id(id);
                                                    rsx! {
                                                        option {
                                                            value: "{id}",
                                                            selected: new_space_realm_id_value == *id,
                                                            "{title} ({id_label})"
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        div { class: "event",
                            div { class: "event-head",
                                span { "Basics" }
                                span { "title + kind" }
                            }
                            div { class: "workflow-form setup-form-grid",
                                div { class: "setup-field",
                                    label { "Space title" }
                                    input {
                                        "data-testid": "new-space-title-input",
                                        required: true,
                                        "aria-required": "true",
                                        value: "{new_space_title_value}",
                                        placeholder: "Backlog, Roadmap, Onboarding...",
                                        oninput: move |event| new_space_title.set(event.value())
                                    }
                                }
                                div { class: "setup-field",
                                    label { "Kind" }
                                    select {
                                        "data-testid": "new-space-kind-input",
                                        value: "{new_space_kind_value}",
                                        onchange: move |event| new_space_kind.set(event.value()),
                                        for (option_value, label, _) in SPACE_KIND_OPTIONS {
                                            option {
                                                value: "{option_value}",
                                                selected: new_space_kind_value == option_value,
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
                                    label { "Summary" }
                                    textarea {
                                        "data-testid": "new-space-summary-input",
                                        value: "{new_space_summary_value}",
                                        rows: "3",
                                        placeholder: "Optional description.",
                                        oninput: move |event| new_space_summary.set(event.value())
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
                                        div { class: "muted", "Pick a Realm above to see candidate parents." }
                                    } else if parent_candidates.is_empty() {
                                        div { class: "muted", "No sibling Spaces in this Realm yet — leave at root." }
                                    } else {
                                        select {
                                            "data-testid": "new-space-parent-input",
                                            value: "{new_space_parent_id_value}",
                                            onchange: move |event| new_space_parent_id.set(event.value()),
                                            option { value: "", "(root — no parent)" }
                                            for (id, title) in &parent_candidates {
                                                {
                                                    let id_label = short_protocol_id(id);
                                                    rsx! {
                                                        option {
                                                            value: "{id}",
                                                            selected: new_space_parent_id_value == *id,
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
                                            select {
                                                "data-testid": "new-space-default-realm-ref-input",
                                                value: "{new_space_default_realm_id_value}",
                                                onchange: move |event| new_space_default_realm_id.set(event.value()),
                                                option { value: "", "(inherit — use home Realm)" }
                                                for (id, title) in &available_realms {
                                                    {
                                                        let id_label = short_protocol_id(id);
                                                        rsx! {
                                                            option {
                                                                value: "{id}",
                                                                selected: new_space_default_realm_id_value == *id,
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
                                button {
                                    class: "primary",
                                    "data-testid": "new-space-submit-button",
                                    disabled: !new_space_can_submit,
                                    onclick: move |_| {
                                        let api_token = token();
                                        let base = base_url.clone();
                                        let realm_id = new_space_realm_id();
                                        let title = new_space_title();
                                        let summary = new_space_summary();
                                        let kind = new_space_kind();
                                        let parent_id = new_space_parent_id();
                                        let default_realm_id = new_space_default_realm_id();
                                        let actor = account_did();
                                        new_space_state.set("Submitting cx.space.create...".to_owned());
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
                                                            state_store.write().save_space_projection(
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
                                    "cx.space.create event + optional parent_space_id / default_realm_id. Lifecycle actions below dispatch cx.space.archive / restore / tombstone."
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
                                    button {
                                        class: "secondary",
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
                                                new_space_state.set("Submitting cx.space.archive...".to_owned());
                                                spawn(async move {
                                                    match authed_api(&base, api_token) {
                                                        Ok(api) => match api.change_space_lifecycle(
                                                            &space_id, &realm_id, &actor, "cx.space.archive",
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
                                    button {
                                        class: "secondary",
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
                                                new_space_state.set("Submitting cx.space.restore...".to_owned());
                                                spawn(async move {
                                                    match authed_api(&base, api_token) {
                                                        Ok(api) => match api.change_space_lifecycle(
                                                            &space_id, &realm_id, &actor, "cx.space.restore",
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
                                    button {
                                        class: "secondary danger",
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
                                                new_space_state.set("Submitting cx.space.tombstone...".to_owned());
                                                spawn(async move {
                                                    match authed_api(&base, api_token) {
                                                        Ok(api) => match api.change_space_lifecycle(
                                                            &space_id, &realm_id, &actor, "cx.space.tombstone",
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
