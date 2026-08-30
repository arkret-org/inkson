//! Pure realm-tree / projection / field-extraction helpers.
//!
//! R28-B extracted this cluster out of `crate::app` (which was a single
//! 12k-line module). Everything here is UI-free: no Dioxus signals, no
//! `rsx!`, no component dependencies — just `serde_json::Value` parsing
//! and [`RealmTreeNode`] hierarchy math. Keeping it in its own module
//! makes the projection/realm-tree logic unit-testable in isolation
//! (see the `tests` submodule below).

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{SchemaId, event_kind_str};
use serde::Serialize;
use serde_json::Value;

use crate::models::{RealmTreeNode, RealmTreeNodeKind};

/// A flattened, depth-annotated row in the rendered Realm tree.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RealmTreeItem {
    pub(crate) node: RealmTreeNode,
    pub(crate) depth: usize,
    pub(crate) descendant_count: usize,
}

/// Caller-supplied fields for an optimistic Realm projection body.
///
/// A named struct rather than a positional argument list because every
/// field here is a `String`/`Vec<String>`, which made the old constructor
/// trivially easy to call with two arguments swapped.
pub(crate) struct RealmProjectionInput {
    pub owner: String,
    pub admins: Vec<String>,
    pub members: Vec<String>,
    pub title: String,
    pub summary: String,
    pub discoverability: String,
    /// Wire value the user picked from `ENCRYPTION_PROFILE_OPTIONS`
    /// (e.g. `mls_rfc9420`). Written through verbatim — the optimistic
    /// body must match exactly what the user chose.
    pub encryption_profile: String,
    /// Effective Realm content capability selected at creation time. The
    /// optimistic projection is authoritative for local writes until account
    /// sync replaces it, so omitting this field would silently downgrade
    /// shared-history content to the `mls_rfc9420` scheme.
    pub content_scheme: String,
    /// Initial history access selected at creation time.
    pub history_access: String,
    pub plaintext_visible_services: Vec<String>,
    pub collaboration_role: Option<arkret_sdk::CollaborationRealmRole>,
    /// Recommended content/metadata floor (e.g. `e2ee_required`), or `None`
    /// to omit the floor keys entirely. The caller decides this via
    /// [`crate::event_builders::encryption_profile_uses_recommended_floor`] so the
    /// "which profile recommends which floor" rule stays single-sourced in
    /// `crate::api` instead of being duplicated here.
    pub encryption_floor: Option<String>,
}

/// Caller-supplied fields for an optimistic Space projection body.
pub(crate) struct SpaceProjectionInput {
    pub realm_id: String,
    pub kind: String,
    pub title: String,
    pub summary: String,
    pub parent_space_id: Option<String>,
    pub default_realm_id: Option<String>,
}

/// Optimistic local Realm/Space projection body written to the sidebar
/// store the instant a create succeeds, before the authoritative sync
/// projection lands.
///
/// Internally tagged on `__kind` (the inkson-local Realm/Space marker read
/// by [`projection_tree_node_kind`]). Each variant flattens its own typed body, so a Realm can
/// never carry Space-only fields and a Space can never carry Realm-only fields —
/// the discriminant and the field set can't disagree. The tag lives at
/// `__kind` rather than `kind` because `kind` is already the Space's own
/// space-kind field.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "__kind", rename_all = "snake_case")]
pub(crate) enum OptimisticRealmTreeProjection {
    Realm(Box<RealmProjectionBody>),
    Space(Box<SpaceProjectionBody>),
}

impl OptimisticRealmTreeProjection {
    pub(crate) fn realm(input: RealmProjectionInput) -> Self {
        let RealmProjectionInput {
            owner,
            admins,
            members,
            title,
            summary,
            discoverability,
            encryption_profile,
            content_scheme,
            history_access,
            plaintext_visible_services,
            collaboration_role,
            encryption_floor,
        } = input;
        let durability_policy = (content_scheme == "mls_exporter_aead_v1")
            .then_some(arkret_sdk::DurabilityPolicy::None);
        // Realm metadata is mirrored at the body top level *and* under
        // `summary` because the two have different readers, and neither set
        // covers the other:
        //
        //   * top level only — `security_state::strand_projection_security_state` walks `[],
        //     object, strand, body, fields, scope, …` and never descends into `summary`, and
        //     `state::realm_tree_snapshot` reads `projection["member_roster_entries"]` flat;
        //   * `summary` first — `explicit_realm_title` and `extract_parent_space_id` /
        //     `extract_child_space_ids` prefer it, because that is where the *server* sync
        //     projection puts these fields. Matching that shape is the point of an optimistic body:
        //     the authoritative projection replaces this value in place, and the same extractors
        //     must keep working across the swap.
        //
        // This is unrelated to the "MUST NOT double-write" rule in
        // `event_builders::assert_realm_candidate_matches_closed_schema`. That
        // one governs the authored `ak.realm.create` `payload.object`, which is
        // validated against the closed `ak.schema.realm_genesis.v1` and rejects
        // unknown members. Nothing here is authored or sent: this body is an
        // inkson-local projection tagged `__kind`, never a wire payload.
        Self::Realm(Box::new(RealmProjectionBody {
            owner: owner.clone(),
            admins: admins.clone(),
            members: members.clone(),
            encryption_profile: encryption_profile.clone(),
            content_scheme: content_scheme.clone(),
            durability_policy,
            history_access: history_access.clone(),
            plaintext_visible_services: plaintext_visible_services.clone(),
            collaboration_role,
            content_encryption_floor: encryption_floor.clone(),
            metadata_encryption_floor: encryption_floor.clone(),
            summary: RealmProjectionSummary {
                title,
                summary,
                category: "collaboration",
                tags: Vec::new(),
                discoverability,
                encryption_profile,
                content_scheme,
                durability_policy,
                history_access,
                plaintext_visible_services,
                owner,
                admins,
                members,
                content_encryption_floor: encryption_floor.clone(),
                metadata_encryption_floor: encryption_floor,
            },
            event_feed: ProjectionEventFeed::default(),
        }))
    }

    pub(crate) fn space(input: SpaceProjectionInput) -> Self {
        let SpaceProjectionInput {
            realm_id,
            kind,
            title,
            summary,
            parent_space_id,
            default_realm_id,
        } = input;
        Self::Space(Box::new(SpaceProjectionBody {
            realm_id,
            space_kind: kind.clone(),
            parent_space_id,
            default_realm_id,
            summary: SpaceProjectionSummary {
                title,
                summary,
                space_kind: kind,
            },
            event_feed: ProjectionEventFeed::default(),
        }))
    }

    pub(crate) fn into_value(self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct RealmProjectionBody {
    owner: String,
    admins: Vec<String>,
    members: Vec<String>,
    encryption_profile: String,
    content_scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    durability_policy: Option<arkret_sdk::DurabilityPolicy>,
    history_access: String,
    plaintext_visible_services: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    collaboration_role: Option<arkret_sdk::CollaborationRealmRole>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encryption_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_encryption_floor: Option<String>,
    summary: RealmProjectionSummary,
    #[serde(rename = "timeline")]
    event_feed: ProjectionEventFeed,
}

#[derive(Clone, Debug, Serialize)]
struct RealmProjectionSummary {
    title: String,
    summary: String,
    category: &'static str,
    tags: Vec<String>,
    discoverability: String,
    encryption_profile: String,
    content_scheme: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    durability_policy: Option<arkret_sdk::DurabilityPolicy>,
    history_access: String,
    plaintext_visible_services: Vec<String>,
    owner: String,
    admins: Vec<String>,
    members: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_encryption_floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata_encryption_floor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SpaceProjectionBody {
    realm_id: String,
    #[serde(rename = "kind")]
    space_kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_realm_id: Option<String>,
    summary: SpaceProjectionSummary,
    #[serde(rename = "timeline")]
    event_feed: ProjectionEventFeed,
}

#[derive(Clone, Debug, Serialize)]
struct SpaceProjectionSummary {
    title: String,
    summary: String,
    #[serde(rename = "kind")]
    space_kind: String,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ProjectionEventFeed {
    events: Vec<Value>,
}

pub(crate) fn non_empty_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| non_empty_string(value.get(*key)))
}

fn state_event_values(body: &Value) -> impl Iterator<Item = &Value> {
    body.get("state")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            body.get("state")
                .and_then(|state| state.get("events"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
}

fn projected_state_event_values(body: &Value) -> impl Iterator<Item = &Value> {
    body.get("state_after")
        .and_then(|state| state.get("events"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(state_event_values(body))
}

/// Return the create-locked control purpose only when the accepted Realm
/// genesis carries both normative PCR markers. A bare `purpose` string or a
/// profile ref by itself is not enough to classify a Realm as control-plane.
pub(crate) fn realm_projection_control_purpose(body: &Value) -> Option<&str> {
    projected_state_event_values(body)
        .filter(|event| {
            event
                .get("kind")
                .or_else(|| event.get("type"))
                .and_then(Value::as_str)
                == Some(arkret_sdk::EventKind::RealmCreate.as_str())
        })
        .find_map(|event| {
            let object = event
                .pointer("/payload/object")
                .or_else(|| event.pointer("/content/object"))?;
            let purpose = object.get("purpose").and_then(Value::as_str)?;
            let is_control_purpose =
                matches!(purpose, "principal_control" | "managed_agent_control");
            let has_control_profile = object
                .get("schema_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter().any(|value| {
                        value.as_str() == Some(arkret_wire::ProfileId::PRINCIPAL_CONTROL_REALM_V1)
                    })
                });
            (is_control_purpose && has_control_profile).then_some(purpose)
        })
}

pub(crate) fn realm_projection_is_principal_control(body: &Value) -> bool {
    realm_projection_control_purpose(body).is_some()
}

/// Resolve the exact immutable group binding from one accepted MLS Genesis.
/// Both fields are read from the same signed Event so a partial projection can
/// never splice an optimistic `content_scheme` together with an unrelated
/// materialized `durability_policy`.
pub(crate) fn realm_projection_group_genesis_binding(
    body: &Value,
) -> Option<arkret_sdk::MlsGroupGenesisBinding> {
    let mut resolved = None;
    for event in projected_state_event_values(body).filter(|event| {
        event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)
            == Some(event_kind_str::MLS_GENESIS)
    }) {
        let binding = event
            .pointer("/payload/governance_binding")
            .or_else(|| event.pointer("/content/governance_binding"))?;
        let content_scheme = serde_json::from_value::<arkret_wire::ContentScheme>(
            binding.get("content_scheme")?.clone(),
        )
        .ok()?;
        let durability_policy = match binding
            .get("durability_policy")
            .filter(|value| !value.is_null())
        {
            Some(value) => {
                Some(serde_json::from_value::<arkret_wire::DurabilityPolicy>(value.clone()).ok()?)
            }
            None => None,
        };
        let candidate = arkret_sdk::MlsGroupGenesisBinding {
            content_scheme,
            durability_policy,
        };
        candidate.validate().ok()?;
        match resolved.as_ref() {
            Some(current) if current != &candidate => return None,
            Some(_) => {}
            None => resolved = Some(candidate),
        }
    }
    resolved
}

/// Replace only the cached MLS Genesis carrier with the exact canonical Event
/// obtained from a complete accepted-history read. Genesis is immutable, so a
/// stale or optimistic copy is not compatibility state and must not survive.
pub(crate) fn replace_realm_projection_mls_genesis(
    body: &mut Value,
    accepted_genesis: Value,
) -> bool {
    let before = body.clone();
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    for container_name in ["state_after", "state"] {
        let Some(events) = object
            .get_mut(container_name)
            .and_then(|container| container.get_mut("events"))
            .and_then(Value::as_array_mut)
        else {
            continue;
        };
        events.retain(|event| {
            event
                .get("kind")
                .or_else(|| event.get("type"))
                .and_then(Value::as_str)
                != Some(event_kind_str::MLS_GENESIS)
        });
    }
    let state = object
        .entry("state")
        .or_insert_with(|| serde_json::json!({"events": []}));
    if !state.is_object() {
        *state = serde_json::json!({"events": []});
    }
    let state_object = state
        .as_object_mut()
        .expect("state was replaced with a JSON object");
    let events = state_object
        .entry("events")
        .or_insert_with(|| Value::Array(Vec::new()));
    if !events.is_array() {
        *events = Value::Array(Vec::new());
    }
    let events = events
        .as_array_mut()
        .expect("events was replaced with a JSON array");
    events.push(accepted_genesis);
    *body != before
}

/// Resolve the Realm's immutable content scheme from the accepted MLS Genesis.
/// An explicit top-level value remains available only for pre-Genesis local
/// authoring. A canonical create Event cannot carry this field and is never a
/// defaulting source.
pub(crate) fn realm_projection_content_scheme(body: &Value) -> Option<String> {
    if let Some(binding) = realm_projection_group_genesis_binding(body) {
        return Some(
            match binding.content_scheme {
                arkret_wire::ContentScheme::MlsRfc9420 => "mls_rfc9420",
                arkret_wire::ContentScheme::MlsExporterAeadV1 => "mls_exporter_aead_v1",
            }
            .to_owned(),
        );
    }

    let null = Value::Null;
    for container in [
        body,
        body.get("summary").unwrap_or(&null),
        body.get("object").unwrap_or(&null),
        body.get("realm").unwrap_or(&null),
        body.get("metadata").unwrap_or(&null),
    ] {
        if let Some(scheme) = string_field(container, &["content_scheme"]) {
            return Some(scheme);
        }
    }

    None
}

/// Resolve one Circle's create-locked content scheme from its accepted
/// `ak.circle.create` Event in the parent Realm projection. Circle MLS groups
/// are independent from the Realm group, so the parent Realm scheme is never
/// used as a fallback.
pub(crate) fn circle_projection_content_scheme(body: &Value, circle_id: &str) -> Option<String> {
    circle_projection_object(body, circle_id)?
        .content_scheme
        .map(|scheme| scheme.as_str().to_owned())
}

/// Resolve one Circle's create-locked durability profile from the same
/// accepted create Event as its content scheme.
pub(crate) fn circle_projection_durability_policy(
    body: &Value,
    circle_id: &str,
) -> Option<arkret_wire::DurabilityPolicy> {
    circle_projection_object(body, circle_id)?.durability_policy
}

fn circle_projection_object(body: &Value, circle_id: &str) -> Option<arkret_sdk::Circle> {
    projected_state_event_values(body)
        .filter(|event| {
            event
                .get("kind")
                .or_else(|| event.get("type"))
                .and_then(Value::as_str)
                == Some(arkret_sdk::EventKind::CircleCreate.as_str())
        })
        .find_map(|event| {
            let payload = event.get("payload").or_else(|| event.get("content"))?;
            let object: arkret_sdk::Circle =
                serde_json::from_value(payload.get("object")?.clone()).ok()?;
            let projected_id = match object.id.as_ref() {
                Some(id) => id.clone(),
                None => {
                    let event_id = event
                        .get("event_id")
                        .and_then(Value::as_str)
                        .and_then(|value| arkret_sdk::EventId::new(value.to_owned()).ok())?;
                    arkret_sdk::CircleId::from_event_id(&event_id)
                }
            };
            (projected_id.as_str() == circle_id).then_some(object)
        })
}

fn nested_string_field(value: &Value, parent: &str, keys: &[&str]) -> Option<String> {
    value
        .get(parent)
        .and_then(|nested| string_field(nested, keys))
}

fn explicit_realm_title(body: &Value) -> Option<String> {
    nested_string_field(
        body,
        "summary",
        &["title", "realm_title", "realm_label", "name"],
    )
    .or_else(|| string_field(body, &["title", "realm_title", "realm_label", "name"]))
    .or_else(|| nested_string_field(body, "realm_preview", &["title", "name"]))
    .or_else(|| nested_string_field(body, "preview", &["title", "name"]))
    .or_else(|| nested_string_field(body, "realm", &["title", "name"]))
    .or_else(|| {
        body.pointer("/state_at_window_start/realm_metadata")
            .and_then(|metadata| string_field(metadata, &["title", "name"]))
    })
    .or_else(|| {
        state_event_values(body)
            .filter(|event| {
                event.get("kind").and_then(Value::as_str)
                    == Some(arkret_sdk::EventKind::RealmCreate.as_str())
            })
            .find_map(|event| {
                event.get("payload").and_then(|payload| {
                    string_field(payload, &["realm_title", "title"])
                        .or_else(|| nested_string_field(payload, "object", &["title"]))
                })
            })
    })
}

fn explicit_realm_summary(body: &Value) -> Option<String> {
    nested_string_field(body, "summary", &["summary", "description"])
        .or_else(|| string_field(body, &["realm_summary", "description"]))
        .or_else(|| {
            body.pointer("/state_at_window_start/realm_metadata")
                .and_then(|metadata| string_field(metadata, &["summary", "description"]))
        })
        .or_else(|| {
            state_event_values(body)
                .filter(|event| {
                    event.get("kind").and_then(Value::as_str)
                        == Some(arkret_sdk::EventKind::RealmCreate.as_str())
                })
                .find_map(|event| {
                    event.get("payload").and_then(|payload| {
                        string_field(payload, &["realm_summary", "summary"])
                            .or_else(|| nested_string_field(payload, "object", &["summary"]))
                    })
                })
        })
}

pub(crate) fn projection_title(id: &str, body: &Value) -> String {
    explicit_realm_title(body)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| nested_string_field(summary, "strand", &["title", "name"]))
        })
        .unwrap_or_else(|| id.to_owned())
}

pub(crate) fn projection_with_title_hint(
    id: &str,
    body: &Value,
    title_hint: Option<&str>,
) -> Value {
    let Some(title) = title_hint.map(str::trim).filter(|title| !title.is_empty()) else {
        return body.clone();
    };
    if explicit_realm_title(body).is_some() {
        return body.clone();
    }

    let mut next = body.clone();
    if !next.is_object() {
        next = serde_json::json!({});
    }
    let Some(object) = next.as_object_mut() else {
        return serde_json::json!({});
    };
    let summary = object
        .entry("summary".to_owned())
        .or_insert_with(|| serde_json::json!({}));
    if !summary.is_object() {
        *summary = serde_json::json!({});
    }
    let Some(summary_object) = summary.as_object_mut() else {
        return next;
    };
    summary_object.insert("title".to_owned(), Value::String(title.to_owned()));
    object
        .entry("__title_hint_source".to_owned())
        .or_insert_with(|| Value::String(format!("invite:{id}")));
    next
}

pub(crate) fn string_array_field(value: &Value, keys: &[&str]) -> Vec<String> {
    keys.iter()
        .filter_map(|key| value.get(*key))
        .flat_map(|field| {
            field
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|item| item.as_str())
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

pub(crate) fn extract_parent_space_id(space_id: &str, body: &Value) -> Option<String> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    for container in [
        summary,
        body,
        body.get("hierarchy").unwrap_or(&Value::Null),
        body.get("relationships").unwrap_or(&Value::Null),
    ] {
        if let Some(parent) = string_field(
            container,
            &[
                "parent_space_id",
                "parent_id",
                "parent",
                "space_parent_id",
                "root_space_id",
            ],
        )
        .filter(|parent| parent != space_id && parent.starts_with("ak:space:"))
        {
            return Some(parent);
        }
    }

    state_event_values(body).find_map(|event| {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str)?;
        if kind != event_kind_str::SPACE_PARENT {
            return None;
        }
        for container in [
            event.get("payload").unwrap_or(&Value::Null),
            event.get("content").unwrap_or(&Value::Null),
            event,
        ] {
            if let Some(parent) = string_field(
                container,
                &["parent_space_id", "parent_id", "parent", "target_parent_id"],
            )
            .filter(|parent| parent != space_id && parent.starts_with("ak:space:"))
            {
                return Some(parent);
            }
        }
        None
    })
}

pub(crate) fn extract_child_space_ids(space_id: &str, body: &Value) -> Vec<String> {
    let summary = body.get("summary").unwrap_or(&Value::Null);
    let mut children = Vec::new();
    for container in [
        summary,
        body,
        body.get("hierarchy").unwrap_or(&Value::Null),
        body.get("relationships").unwrap_or(&Value::Null),
    ] {
        children.extend(string_array_field(
            container,
            &[
                "child_space_ids",
                "children",
                "child_ids",
                "space_child_ids",
            ],
        ));
    }

    for event in state_event_values(body) {
        let kind = event
            .get("kind")
            .or_else(|| event.get("type"))
            .and_then(Value::as_str);
        if kind != Some(arkret_sdk::EventKind::SpaceParent.as_str()) {
            continue;
        }
        let payload = event
            .get("payload")
            .or_else(|| event.get("content"))
            .and_then(|payload| {
                serde_json::from_value::<arkret_sdk::SpaceParentPayload>(payload.clone()).ok()
            });
        if let Some(payload) = payload
            && payload
                .parent_space_id
                .as_ref()
                .map(arkret_sdk::SpaceId::as_str)
                == Some(space_id)
        {
            children.push(payload.space_id.to_string());
        }
    }

    children
        .into_iter()
        .filter(|child| child != space_id && child.starts_with("ak:space:"))
        .collect()
}

pub(crate) fn realm_tree_parent_id(node: &RealmTreeNode) -> Option<&str> {
    node.parent_space_id
        .as_deref()
        .filter(|parent| !parent.trim().is_empty())
        .or_else(|| {
            (node.kind == RealmTreeNodeKind::Space)
                .then(|| node.realm_id.trim())
                .filter(|realm_id| !realm_id.is_empty())
        })
}

pub(crate) fn normalize_realm_tree_hierarchy(nodes: &mut [RealmTreeNode]) {
    let known: BTreeSet<String> = nodes.iter().map(|node| node.id.clone()).collect();
    let mut child_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for node in nodes.iter() {
        if let Some(parent) = realm_tree_parent_id(node)
            .filter(|parent| known.contains(*parent) && *parent != node.id.as_str())
        {
            child_map
                .entry(parent.to_owned())
                .or_default()
                .insert(node.id.clone());
        }

        for child in node
            .child_space_ids
            .iter()
            .filter(|child| known.contains(*child) && *child != &node.id)
        {
            child_map
                .entry(node.id.clone())
                .or_default()
                .insert(child.clone());
        }
    }

    for node in nodes.iter_mut() {
        node.child_space_ids = child_map
            .remove(&node.id)
            .map(|children| children.into_iter().collect())
            .unwrap_or_default();
    }
}

pub(crate) fn descendant_node_ids(nodes: &[RealmTreeNode], root_node_id: &str) -> Vec<String> {
    if root_node_id.trim().is_empty() {
        return Vec::new();
    }

    let known: BTreeSet<&str> = nodes.iter().map(|node| node.id.as_str()).collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        if let Some(parent) = realm_tree_parent_id(node)
            .filter(|parent| known.contains(*parent) && *parent != node.id.as_str())
        {
            child_map.entry(parent).or_default().push(node.id.as_str());
        }
        for child in node
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != node.id.as_str())
        {
            child_map.entry(node.id.as_str()).or_default().push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_unstable();
        children.dedup();
    }
    let mut result = Vec::new();
    let mut visited = BTreeSet::new();
    let mut stack = vec![root_node_id];
    while let Some(node_id) = stack.pop() {
        if !visited.insert(node_id.to_owned()) {
            continue;
        }
        result.push(node_id.to_owned());
        if let Some(children) = child_map.get(node_id) {
            for child in children.iter().rev() {
                stack.push(child);
            }
        }
    }
    result
}

#[cfg(test)]
pub(crate) fn realm_tree_items(nodes: &[RealmTreeNode]) -> Vec<RealmTreeItem> {
    realm_tree_items_with_pinned_realms(nodes, &BTreeSet::new())
}

pub(crate) fn realm_tree_items_with_pinned_realms(
    nodes: &[RealmTreeNode],
    pinned_realm_ids: &BTreeSet<String>,
) -> Vec<RealmTreeItem> {
    // Direct conversations are addressable only through the contact/direct
    // resolver. Keep this defensive filter at the final navigation projection
    // as well as at sync ingestion so stale local snapshots cannot leak a DM
    // Realm into the ordinary Collaboration sidebar.
    let visible_nodes: Vec<RealmTreeNode> = nodes
        .iter()
        .filter(|node| !realm_tree_node_is_direct_conversation(node))
        .cloned()
        .collect();
    let nodes = visible_nodes.as_slice();
    let order: BTreeMap<&str, usize> = nodes
        .iter()
        .enumerate()
        .map(|(idx, node)| (node.id.as_str(), idx))
        .collect();
    let known: BTreeSet<&str> = nodes.iter().map(|node| node.id.as_str()).collect();
    let by_id: BTreeMap<&str, &RealmTreeNode> =
        nodes.iter().map(|node| (node.id.as_str(), node)).collect();
    let mut child_map: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for node in nodes {
        if let Some(parent) = realm_tree_parent_id(node)
            .filter(|parent| known.contains(*parent) && *parent != node.id.as_str())
        {
            child_map.entry(parent).or_default().push(node.id.as_str());
        }
        for child in node
            .child_space_ids
            .iter()
            .map(String::as_str)
            .filter(|child| known.contains(*child) && *child != node.id.as_str())
        {
            child_map.entry(node.id.as_str()).or_default().push(child);
        }
    }
    for children in child_map.values_mut() {
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        children.dedup();
    }
    let mut roots: Vec<&str> = nodes
        .iter()
        .filter(|node| {
            realm_tree_parent_id(node)
                .map(|parent| !known.contains(parent))
                .unwrap_or(true)
        })
        .map(|node| node.id.as_str())
        .collect();
    roots.sort_by_key(|id| {
        let is_pinned_collaboration_realm = by_id.get(id).copied().is_some_and(|node| {
            realm_tree_node_is_collaboration_pin_candidate(node, pinned_realm_ids)
        });
        (
            usize::from(!is_pinned_collaboration_realm),
            order.get(id).copied().unwrap_or(usize::MAX),
        )
    });

    fn push_item<'a>(
        id: &'a str,
        depth: usize,
        by_id: &BTreeMap<&'a str, &'a RealmTreeNode>,
        child_map: &BTreeMap<&'a str, Vec<&'a str>>,
        order: &BTreeMap<&'a str, usize>,
        visited: &mut BTreeSet<String>,
        items: &mut Vec<RealmTreeItem>,
    ) {
        if !visited.insert(id.to_owned()) {
            return;
        }
        let Some(node) = by_id.get(id).copied() else {
            return;
        };
        items.push(RealmTreeItem {
            node: node.clone(),
            depth,
            descendant_count: descendant_node_ids(
                &by_id.values().copied().cloned().collect::<Vec<_>>(),
                id,
            )
            .len()
            .saturating_sub(1),
        });
        let mut children: Vec<&str> = child_map.get(id).cloned().unwrap_or_default();
        children.sort_by_key(|child| order.get(child).copied().unwrap_or(usize::MAX));
        for child in children {
            push_item(child, depth + 1, by_id, child_map, order, visited, items);
        }
    }

    let mut items = Vec::new();
    let mut visited = BTreeSet::new();
    for root in roots {
        push_item(
            root,
            0,
            &by_id,
            &child_map,
            &order,
            &mut visited,
            &mut items,
        );
    }
    for node in nodes {
        if !visited.contains(&node.id) {
            push_item(
                &node.id,
                0,
                &by_id,
                &child_map,
                &order,
                &mut visited,
                &mut items,
            );
        }
    }
    items
}

fn realm_tree_node_is_collaboration_pin_candidate(
    node: &RealmTreeNode,
    pinned_realm_ids: &BTreeSet<String>,
) -> bool {
    node.kind == RealmTreeNodeKind::Realm
        && pinned_realm_ids.contains(node.id.as_str())
        && !realm_tree_node_is_direct_conversation(node)
}

pub(crate) fn realm_tree_node_is_direct_conversation(node: &RealmTreeNode) -> bool {
    node.direct_conversation
}

#[cfg(test)]
pub fn realm_tree_nodes_from_sync_realms(realms: &BTreeMap<String, Value>) -> Vec<RealmTreeNode> {
    realm_tree_nodes_from_sync_realms_with_roles(realms, &BTreeMap::new())
}

pub fn realm_tree_nodes_from_sync_realms_with_roles(
    realms: &BTreeMap<String, Value>,
    collaboration_roles: &BTreeMap<String, arkret_sdk::CollaborationRealmRole>,
) -> Vec<RealmTreeNode> {
    let mut previews: Vec<RealmTreeNode> = realms
        .iter()
        .filter(|(id, body)| {
            is_realm_or_space_projection_id(id)
                && !projection_looks_like_strand(body)
                && !realm_projection_is_principal_control(body)
                && collaboration_roles.get(*id)
                    != Some(&arkret_sdk::CollaborationRealmRole::DirectConversation)
        })
        .map(|(id, body)| {
            let summary = body.get("summary").unwrap_or(&Value::Null);
            let title = projection_title(id, body);
            let description = explicit_realm_summary(body);
            let tags = summary
                .get("tags")
                .and_then(Value::as_array)
                .map(|tags| {
                    tags.iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned)
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default();
            let kind = projection_tree_node_kind(id, body);
            let realm_id = match kind {
                RealmTreeNodeKind::Realm => id.clone(),
                RealmTreeNodeKind::Space => projection_home_realm_id(body).unwrap_or_default(),
            };
            let parent_space_id = extract_parent_space_id(id, body);
            let direct_conversation = collaboration_roles.get(id)
                == Some(&arkret_sdk::CollaborationRealmRole::DirectConversation);
            RealmTreeNode {
                id: id.clone(),
                title,
                description,
                tags,
                public: true,
                category: summary
                    .get("category")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                direct_conversation,
                parent_space_id,
                child_space_ids: extract_child_space_ids(id, body),
                kind,
                realm_id,
            }
        })
        .collect();
    normalize_realm_tree_hierarchy(&mut previews);
    previews
}

pub(crate) fn is_realm_or_space_projection_id(id: &str) -> bool {
    id.starts_with("ak:realm:") || id.starts_with("ak:space:")
}

pub(crate) fn projection_tree_node_kind(id: &str, body: &Value) -> RealmTreeNodeKind {
    // Classify Realm vs Space. Wire signals:
    // - `__kind` (inkson-local tag from optimistic save)
    // - `schema` (server projection — ak.schema.realm.v1 vs ak.schema.space.v1)
    // - id prefix (`ak:realm:*` vs `ak:space:*`)
    match body
        .get("__kind")
        .and_then(Value::as_str)
        .or_else(|| body.get("schema").and_then(Value::as_str))
    {
        Some("space") | Some(SchemaId::SPACE_V1) => RealmTreeNodeKind::Space,
        Some("realm") | Some(SchemaId::REALM_V1) => RealmTreeNodeKind::Realm,
        _ if id.starts_with("ak:space:") => RealmTreeNodeKind::Space,
        _ if id.starts_with("ak:realm:") => RealmTreeNodeKind::Realm,
        _ => RealmTreeNodeKind::Realm,
    }
}

pub(crate) fn projection_home_realm_id(body: &Value) -> Option<String> {
    body.get("realm_id")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("summary")
                .and_then(|summary| summary.get("realm_id"))
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|realm_id| !realm_id.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn server_set_contains_realm_id(server_set: &BTreeSet<String>, realm_id: &str) -> bool {
    server_set.contains(realm_id)
}

pub fn full_sync_projection_keep_set(
    server_set: &BTreeSet<String>,
    cached: &BTreeMap<String, Value>,
) -> BTreeSet<String> {
    let mut keep = server_set.clone();
    for (id, body) in cached {
        if should_retain_projection_after_full_sync(id, body, server_set) {
            keep.insert(id.clone());
        }
    }
    keep
}

pub fn should_retain_projection_after_full_sync(
    id: &str,
    body: &Value,
    server_set: &BTreeSet<String>,
) -> bool {
    if server_set.contains(id) {
        return true;
    }
    // Realm creation writes this local-only discriminant only after the
    // server accepts the create transaction. A catch-up full sync can race
    // the server's account projection and omit that newly accepted Realm for
    // a few frames. Preserve the optimistic body until an authoritative body
    // replaces it (and therefore removes `__kind`); otherwise the first local
    // encrypted write loses its effective policy fields and silently falls
    // back to the default content scheme.
    if id.starts_with("ak:realm:") && body.get("__kind").and_then(Value::as_str) == Some("realm") {
        return true;
    }
    if !id.starts_with("ak:space:")
        || projection_tree_node_kind(id, body) != RealmTreeNodeKind::Space
    {
        return false;
    }
    projection_home_realm_id(body)
        .as_deref()
        .is_some_and(|realm_id| server_set_contains_realm_id(server_set, realm_id))
}

pub(crate) fn projection_looks_like_strand(body: &Value) -> bool {
    // Real Space projections embed their primary strand under
    // `summary.strand` (with `strand_id` etc. inside it) — so peeking into
    // `summary` to spot a strand is a false positive. Only the body's own
    // top-level `strand_id` / `strand` / `tracks` / `kind`, or a
    // `summary.category` that is itself a strand category, identify a
    // strand-as-node projection.
    body.get("strand_id").is_some()
        || body.get("strand").is_some()
        || body.get("tracks").is_some()
        || matches!(
            body.get("kind").and_then(Value::as_str),
            Some(event_kind_str::STRAND_CREATE | "discussion" | "strand")
        )
        || matches!(
            body.get("summary")
                .and_then(|summary| summary.get("category"))
                .and_then(Value::as_str),
            Some("discussion" | "strand" | "card" | "announce" | "support" | "activity")
        )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn preview(id: &str, name: &str, parent: Option<&str>) -> RealmTreeNode {
        let kind = if id.starts_with("ak:space:") {
            RealmTreeNodeKind::Space
        } else {
            RealmTreeNodeKind::Realm
        };
        RealmTreeNode {
            id: id.to_owned(),
            title: name.to_owned(),
            description: None,
            tags: Default::default(),
            public: true,
            category: None,
            direct_conversation: false,
            parent_space_id: parent.map(ToOwned::to_owned),
            child_space_ids: Vec::new(),
            kind,
            realm_id: if kind == RealmTreeNodeKind::Realm {
                id.to_owned()
            } else {
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned()
            },
        }
    }

    #[test]
    fn sync_projection_title_accepts_invite_title_aliases() {
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            "ak:realm:ASeIBHNVQyeIcU4aBIt2t2BF_ikuVMH0kNru_HgO_gG1".to_owned(),
            json!({
                "realm_title": "Launch Planning",
                "summary": {}
            }),
        )]));

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].title, "Launch Planning");
    }

    #[test]
    fn sync_projection_reads_canonical_window_start_realm_metadata() {
        let id = "ak:realm:AVWVGlDqGwJJ7DILnxJ4oq7JGdtoXGIQaK4PoiEf2yBZ";
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            id.to_owned(),
            json!({
                "summary": {"joined_member_count": 1},
                "state_at_window_start": {
                    "actor_profiles": {},
                    "realm_metadata": {
                        "title": "Architecture",
                        "summary": "System design"
                    },
                    "e2ee_epoch": null
                }
            }),
        )]));

        assert_eq!(nodes[0].title, "Architecture");
        assert_eq!(nodes[0].description.as_deref(), Some("System design"));
    }

    #[test]
    fn sync_projection_recovers_title_from_canonical_realm_create_state_event() {
        let id = "ak:realm:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3";
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            id.to_owned(),
            json!({
                "summary": {"joined_member_count": 1},
                "state": {"events": [{
                    "kind": "ak.realm.create",
                    "payload": {"object": {
                        "title": "Recovered title",
                        "summary": "Recovered summary"
                    }}
                }]}
            }),
        )]));

        assert_eq!(nodes[0].title, "Recovered title");
        assert_eq!(nodes[0].description.as_deref(), Some("Recovered summary"));
    }

    #[test]
    fn content_scheme_prefers_immutable_mls_genesis_over_projection_hints() {
        let projection = json!({
            "object": {"content_scheme": "mls_rfc9420"},
            "state_after": {"events": [
                {
                    "kind": "ak.realm.create",
                    "payload": {"object": {"content_scheme": "mls_rfc9420"}}
                },
                {
                    "kind": "ak.realm.policy_bundle",
                    "payload": {"value": {"content_scheme": "mls_rfc9420"}}
                },
                {
                    "kind": "ak.mls.genesis",
                    "payload": {"governance_binding": {
                        "content_scheme": "mls_exporter_aead_v1",
                        "durability_policy": "none"
                    }}
                }
            ]}
        });

        assert_eq!(
            realm_projection_content_scheme(&projection).as_deref(),
            Some("mls_exporter_aead_v1")
        );
    }

    #[test]
    fn content_scheme_never_uses_forbidden_create_payload_fallback() {
        let projection = json!({
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"content_scheme": "mls_exporter_aead_v1"}}
            }]}
        });

        assert_eq!(realm_projection_content_scheme(&projection), None);
    }

    #[test]
    fn content_scheme_remains_pending_until_accepted_genesis_is_visible() {
        let accepted_default = json!({
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
            }]}
        });
        let transient_projection = json!({
            "member_roster_entries_limited": false,
            "member_roster_entries": []
        });

        assert_eq!(realm_projection_content_scheme(&accepted_default), None);
        assert_eq!(
            realm_projection_content_scheme(&transient_projection),
            None,
            "neither create nor a roster-only frame may guess a content wire scheme"
        );
    }

    #[test]
    fn group_genesis_binding_never_splices_materialized_fields() {
        let projection = json!({
            "content_scheme": "mls_exporter_aead_v1",
            "durability_policy": "none",
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
            }]}
        });

        assert_eq!(realm_projection_group_genesis_binding(&projection), None);
    }

    #[test]
    fn canonical_genesis_replaces_stale_projection_copy() {
        let mut projection = json!({
            "state_after": {"events": [{
                "event_id": "ak:event:stale",
                "kind": "ak.mls.genesis",
                "payload": {"governance_binding": {"content_scheme": "mls_rfc9420"}}
            }]},
            "state": {"events": [{"kind": "ak.realm.create", "payload": {"object": {}}}]}
        });
        let accepted = json!({
            "event_id": "ak:event:accepted",
            "kind": "ak.mls.genesis",
            "payload": {"governance_binding": {
                "content_scheme": "mls_exporter_aead_v1",
                "durability_policy": "none"
            }}
        });

        assert!(replace_realm_projection_mls_genesis(
            &mut projection,
            accepted
        ));
        assert!(
            projection["state_after"]["events"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            realm_projection_group_genesis_binding(&projection),
            Some(arkret_sdk::MlsGroupGenesisBinding {
                content_scheme: arkret_wire::ContentScheme::MlsExporterAeadV1,
                durability_policy: Some(arkret_wire::DurabilityPolicy::None),
            })
        );
    }

    #[test]
    fn projection_title_hint_fills_missing_summary_title() {
        let id = "ak:realm:AcsFZ3o2tOdN3EFpNceeLV-aI3jZkB9S34_4YIwJ5DLy";
        let body = json!({
            "summary": {
                "strand": {"title": "General strand"}
            }
        });

        let patched = projection_with_title_hint(id, &body, Some("Invited Realm"));
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(id.to_owned(), patched)]));

        assert_eq!(nodes[0].title, "Invited Realm");
    }

    #[test]
    fn projection_title_hint_does_not_override_server_title() {
        let id = "ak:realm:ARELvWOpF6BRrks3DlbQy-9XIE6aAQQumDQp7fA4ApeM";
        let body = json!({
            "summary": {"title": "Server Realm"}
        });

        let patched = projection_with_title_hint(id, &body, Some("Invite Label"));
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(id.to_owned(), patched)]));

        assert_eq!(nodes[0].title, "Server Realm");
    }

    #[test]
    fn optimistic_realm_projection_serializes_typed_encryption_floor() {
        let body = OptimisticRealmTreeProjection::realm(RealmProjectionInput {
            owner: "did:web:alice.example".to_owned(),
            admins: vec!["did:web:alice.example".to_owned()],
            members: vec![
                "did:web:alice.example".to_owned(),
                "did:web:bob.example".to_owned(),
            ],
            title: "Launch".to_owned(),
            summary: "Launch planning".to_owned(),
            discoverability: "restricted".to_owned(),
            encryption_profile: "mls_rfc9420".to_owned(),
            content_scheme: "mls_exporter_aead_v1".to_owned(),
            history_access: "all_history_for_current_members".to_owned(),
            plaintext_visible_services: vec!["directory".to_owned()],
            collaboration_role: None,
            encryption_floor: Some("e2ee_required".to_owned()),
        })
        .into_value();

        assert_eq!(body["__kind"], "realm");
        assert_eq!(body["encryption_profile"], "mls_rfc9420");
        assert_eq!(body["content_encryption_floor"], "e2ee_required");
        assert_eq!(body["metadata_encryption_floor"], "e2ee_required");
        assert_eq!(body["summary"]["content_encryption_floor"], "e2ee_required");
        assert_eq!(
            body["summary"]["metadata_encryption_floor"],
            "e2ee_required"
        );
        assert_eq!(body["content_scheme"], "mls_exporter_aead_v1");
        assert_eq!(body["summary"]["content_scheme"], "mls_exporter_aead_v1");
        assert_eq!(body["durability_policy"], "none");
        assert_eq!(body["summary"]["durability_policy"], "none");
        assert_eq!(body["history_access"], "all_history_for_current_members");
        assert_eq!(
            body["summary"]["history_access"],
            "all_history_for_current_members"
        );
        assert_eq!(body["timeline"]["events"], json!([]));
    }

    #[test]
    fn optimistic_realm_projection_omits_plaintext_floor() {
        let body = OptimisticRealmTreeProjection::realm(RealmProjectionInput {
            owner: "did:web:alice.example".to_owned(),
            admins: vec!["did:web:alice.example".to_owned()],
            members: vec!["did:web:alice.example".to_owned()],
            title: "Public".to_owned(),
            summary: String::new(),
            discoverability: "public".to_owned(),
            encryption_profile: "none".to_owned(),
            content_scheme: "mls_rfc9420".to_owned(),
            history_access: "since_join".to_owned(),
            plaintext_visible_services: Vec::new(),
            collaboration_role: None,
            encryption_floor: None,
        })
        .into_value();

        assert_eq!(body["encryption_profile"], "none");
        assert!(body.get("content_encryption_floor").is_none());
        assert!(body.get("metadata_encryption_floor").is_none());
        assert!(body["summary"].get("content_encryption_floor").is_none());
        assert!(body["summary"].get("metadata_encryption_floor").is_none());
        assert!(body.get("durability_policy").is_none());
        assert!(body["summary"].get("durability_policy").is_none());
    }

    #[test]
    fn optimistic_space_projection_serializes_optional_parent_links() {
        let body = OptimisticRealmTreeProjection::space(SpaceProjectionInput {
            realm_id: "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            kind: "collection".to_owned(),
            title: "Specs".to_owned(),
            summary: "Spec work".to_owned(),
            parent_space_id: Some("ak:space:parent".to_owned()),
            default_realm_id: Some(
                "ak:realm:A-acoX0-9_g-lyPSEFQ3Dcqq43BtmQvHsFu10frgX6Zc".to_owned(),
            ),
        })
        .into_value();

        assert_eq!(body["__kind"], "space");
        assert_eq!(
            body["realm_id"],
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
        assert_eq!(body["kind"], "collection");
        assert_eq!(body["parent_space_id"], "ak:space:parent");
        assert_eq!(
            body["default_realm_id"],
            "ak:realm:A-acoX0-9_g-lyPSEFQ3Dcqq43BtmQvHsFu10frgX6Zc"
        );
        assert_eq!(body["summary"]["kind"], "collection");
        assert_eq!(body["timeline"]["events"], json!([]));
    }

    #[test]
    fn realm_tree_uses_parent_links_for_nested_spaces() {
        let spaces = vec![
            preview(
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "Root",
                None,
            ),
            preview("ak:space:child", "Child", None),
            preview("ak:space:deep", "Deep", Some("ak:space:child")),
        ];

        let items = realm_tree_items(&spaces);

        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0].node.id,
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
        assert_eq!(items[0].depth, 0);
        assert_eq!(items[0].descendant_count, 2);
        assert_eq!(items[1].node.id, "ak:space:child");
        assert_eq!(items[1].depth, 1);
        assert_eq!(items[2].node.id, "ak:space:deep");
        assert_eq!(items[2].depth, 2);
    }

    #[test]
    fn pinned_realms_sort_before_unpinned_roots_without_splitting_subtrees() {
        let mut a_child = preview("ak:space:a-child", "A child", None);
        a_child.realm_id = "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk".to_owned();
        let mut b_child = preview("ak:space:b-child", "B child", None);
        b_child.realm_id = "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned();
        let nodes = vec![
            preview(
                "ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk",
                "A",
                None,
            ),
            a_child,
            preview(
                "ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo",
                "B",
                None,
            ),
            b_child,
        ];
        let pinned =
            BTreeSet::from(["ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo".to_owned()]);

        let items = realm_tree_items_with_pinned_realms(&nodes, &pinned);
        let ids: Vec<_> = items
            .iter()
            .map(|item| (item.node.id.as_str(), item.depth))
            .collect();

        assert_eq!(
            ids,
            vec![
                ("ak:realm:AF-jk6ju8IdjVa7Gf0eeCnOu9EHYKDaY47I98_7lPyfo", 0),
                ("ak:space:b-child", 1),
                ("ak:realm:ASN5uMi28AEbWgFm2GmchqhztuhBSoOzWPAht4VgFoXk", 0),
                ("ak:space:a-child", 1),
            ]
        );
    }

    #[test]
    fn ordinary_navigation_omits_direct_conversation_realms_even_when_pinned() {
        let mut dm = preview(
            "ak:realm:AXXj-3yEyHv7Kyo7niHWuUuucolddHsvAd2DXS2jtgDA",
            "DM",
            None,
        );
        dm.direct_conversation = true;
        let nodes = vec![
            dm,
            preview(
                "ak:realm:AWG6UBspWdU4JTNRCHibEMTsPmT7o6cbDYSeoEcQkMQw",
                "Work",
                None,
            ),
            preview(
                "ak:realm:Ai5i4v2IpgBcXOnqXG0qYJ4y_Zz5Xs359i6Ubynu-D1s",
                "Later",
                None,
            ),
        ];
        let pinned = BTreeSet::from([
            "ak:realm:AXXj-3yEyHv7Kyo7niHWuUuucolddHsvAd2DXS2jtgDA".to_owned(),
            "ak:realm:Ai5i4v2IpgBcXOnqXG0qYJ4y_Zz5Xs359i6Ubynu-D1s".to_owned(),
        ]);

        let items = realm_tree_items_with_pinned_realms(&nodes, &pinned);
        let ids: Vec<_> = items.iter().map(|item| item.node.id.as_str()).collect();

        assert_eq!(
            ids,
            vec![
                "ak:realm:Ai5i4v2IpgBcXOnqXG0qYJ4y_Zz5Xs359i6Ubynu-D1s",
                "ak:realm:AWG6UBspWdU4JTNRCHibEMTsPmT7o6cbDYSeoEcQkMQw"
            ]
        );
    }

    #[test]
    fn direct_conversation_role_uses_typed_sync_projection_not_category_or_tags() {
        let realm_id = "ak:realm:AXqScWrSVbMRHSSnD37HwS-fgoTGt3HbHkvBV3SttpCU";
        let strong = realm_tree_nodes_from_sync_realms_with_roles(
            &BTreeMap::from([(
                realm_id.to_owned(),
                json!({"summary": {"title": "Conversation"}}),
            )]),
            &BTreeMap::from([(
                realm_id.to_owned(),
                arkret_sdk::CollaborationRealmRole::DirectConversation,
            )]),
        );
        assert!(
            strong.is_empty(),
            "typed direct-conversation Realms must stay out of ordinary navigation"
        );

        let genesis_only = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            realm_id.to_owned(),
            json!({
                "state": {
                    "events": [{
                        "kind": "ak.realm.create",
                        "payload": {
                            "object": {
                                "collaboration_role": "direct_conversation"
                            }
                        }
                    }]
                }
            }),
        )]));
        assert!(
            !realm_tree_node_is_direct_conversation(&genesis_only[0]),
            "untyped Event payload probes must not drive MLS classification"
        );

        let heuristic_only = realm_tree_nodes_from_sync_realms(&BTreeMap::from([(
            realm_id.to_owned(),
            json!({"summary": {"category": "direct_conversation", "tags": ["dm"]}}),
        )]));
        assert!(!realm_tree_node_is_direct_conversation(&heuristic_only[0]));
    }

    #[test]
    fn principal_control_realms_are_excluded_from_product_navigation() {
        let pcr_id = "ak:realm:Ac9iLS6pVSDjqFeDeJjvUhbtREpxQ8IWem2mi64wrqDq";
        let collaboration_id = "ak:realm:AXqScWrSVbMRHSSnD37HwS-fgoTGt3HbHkvBV3SttpCU";
        let nodes = realm_tree_nodes_from_sync_realms(&BTreeMap::from([
            (
                pcr_id.to_owned(),
                json!({
                    "state": {
                        "events": [{
                            "kind": "ak.realm.create",
                            "payload": {
                                "object": {
                                    "purpose": "principal_control",
                                    "schema_refs": ["ak.profile.principal_control_realm.v1"]
                                }
                            }
                        }]
                    }
                }),
            ),
            (
                collaboration_id.to_owned(),
                json!({"summary": {"title": "Product Realm"}}),
            ),
        ]));

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, collaboration_id);
    }

    #[test]
    fn principal_control_classification_requires_purpose_and_profile() {
        let purpose_only = json!({
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {"purpose": "principal_control"}}
            }]}
        });
        let profile_only = json!({
            "state": {"events": [{
                "kind": "ak.realm.create",
                "payload": {"object": {
                    "purpose": "collaboration",
                    "schema_refs": ["ak.profile.principal_control_realm.v1"]
                }}
            }]}
        });

        assert!(!realm_projection_is_principal_control(&purpose_only));
        assert!(!realm_projection_is_principal_control(&profile_only));
    }

    #[test]
    fn descendant_node_ids_walks_full_subtree_and_ignores_unknown_root() {
        let spaces = vec![
            preview(
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "Root",
                None,
            ),
            preview("ak:space:child", "Child", None),
            preview("ak:space:deep", "Deep", Some("ak:space:child")),
            RealmTreeNode {
                realm_id: "ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo".to_owned(),
                ..preview(
                    "ak:realm:ALxDZio2znRUoLNW5_OmFXNttc8yHs8Jw8_b6vk0QYXo",
                    "Other",
                    None,
                )
            },
        ];

        assert_eq!(
            descendant_node_ids(
                &spaces,
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
            ),
            vec![
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
                "ak:space:child".to_owned(),
                "ak:space:deep".to_owned(),
            ]
        );
        // An unknown (but non-blank) root has no descendants, so the walk
        // is just the root id itself.
        assert_eq!(
            descendant_node_ids(&spaces, "ak:space:missing"),
            vec!["ak:space:missing".to_owned()]
        );
        // A blank root short-circuits to an empty walk.
        assert!(descendant_node_ids(&spaces, "   ").is_empty());
    }

    #[test]
    fn normalize_realm_tree_hierarchy_rebuilds_children_from_parent_links() {
        let mut spaces = vec![
            preview(
                "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "Root",
                None,
            ),
            preview("ak:space:child", "Child", None),
            preview("ak:space:deep", "Deep", Some("ak:space:child")),
            // Parent points at an unknown id — must be dropped, not panic.
            preview("ak:space:orphan", "Orphan", Some("ak:space:ghost")),
        ];

        normalize_realm_tree_hierarchy(&mut spaces);

        let root = spaces
            .iter()
            .find(|s| s.id == "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY")
            .expect("root");
        let child = spaces
            .iter()
            .find(|s| s.id == "ak:space:child")
            .expect("child");
        let orphan = spaces
            .iter()
            .find(|s| s.id == "ak:space:orphan")
            .expect("orphan");

        assert_eq!(root.child_space_ids, vec!["ak:space:child".to_owned()]);
        assert_eq!(child.child_space_ids, vec!["ak:space:deep".to_owned()]);
        assert!(orphan.child_space_ids.is_empty());
    }

    #[test]
    fn extract_parent_space_id_prefers_summary_and_event_signals() {
        // Summary-level parent link.
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({"summary": {"parent_space_id": "ak:space:root"}})
            ),
            Some("ak:space:root".to_owned())
        );
        // `ak.space.parent` state event.
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({
                    "state": [{
                        "kind": "ak.space.parent",
                        "payload": {"parent_space_id": "ak:space:root"}
                    }]
                })
            ),
            Some("ak:space:root".to_owned())
        );
        // Self-reference and non-Space ids are rejected.
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({"summary": {"parent_space_id": "ak:space:child"}})
            ),
            None
        );
        assert_eq!(
            extract_parent_space_id(
                "ak:space:child",
                &json!({"summary": {"parent_space_id": "ak:strand:AfgHwnXHiCs7a-wo4z0oefee77xm8izLuvRq5QV231-4"}})
            ),
            None
        );
    }

    #[test]
    fn realm_projection_encryption_state_uses_profile_and_visibility() {
        assert!(crate::security_state::realm_projection_is_encrypted(
            &json!({
                "summary": {"encryption_profile": "mls_rfc9420"}
            })
        ));
        assert!(crate::security_state::realm_projection_is_encrypted(
            &json!({
                "plaintext_visibility": {"default": "encrypted"}
            })
        ));
        assert!(!crate::security_state::realm_projection_is_encrypted(
            &json!({
                "encryption_profile": "none"
            })
        ));
        assert!(!crate::security_state::realm_projection_is_encrypted(
            &json!({
                "summary": {"title": "Projection without encryption metadata"}
            })
        ));
        assert!(crate::security_state::realm_projection_is_encrypted(
            &json!({
                "state_at_window_start": {
                    "e2ee_epoch": {"epoch": 0, "key_ref": "mock-key:realm"}
                }
            })
        ));
        assert!(!crate::security_state::realm_projection_is_encrypted(
            &json!({
                "state_at_window_start": {"e2ee_epoch": null}
            })
        ));
        assert!(crate::security_state::realm_projection_is_encrypted(
            &json!({
                "state_at_window_start": {"e2ee_epoch": null},
                "state": {"events": [{
                    "kind": "ak.realm.create",
                    "payload": {"object": {"encryption_profile": "mls_rfc9420"}}
                }]}
            })
        ));
    }

    #[test]
    fn is_realm_or_space_projection_id_matches_realm_and_space_prefixes() {
        assert!(is_realm_or_space_projection_id(
            "ak:realm:AQ_DYndfRLGXFTmGil1KY2oQW2AKjYbSN9mi4f-HASKg"
        ));
        assert!(is_realm_or_space_projection_id("ak:space:abc"));
        assert!(!is_realm_or_space_projection_id(
            "ak:strand:ARLfbkLnSkVpiiEUORJ1StQffis7S7-xfOV6V1_PuAPg"
        ));
        assert!(!is_realm_or_space_projection_id("realm:abc"));
    }

    #[test]
    fn sync_projection_parses_realm_and_space_hierarchy_fields() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({
                "schema": "ak.schema.realm.v1",
                "summary": {
                    "title": "Root",
                    "summary": "Root Realm"
                }
            }),
        );
        spaces.insert(
            "ak:space:child".to_owned(),
            json!({
                "schema": "ak.schema.space.v1",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {
                    "title": "Child",
                    "summary": "Child Space"
                }
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);
        let root = previews
            .iter()
            .find(|node| node.id == "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY")
            .expect("root preview");
        let child = previews
            .iter()
            .find(|node| node.id == "ak:space:child")
            .expect("child preview");

        assert_eq!(root.child_space_ids, vec!["ak:space:child".to_owned()]);
        assert_eq!(child.parent_space_id, None);
        assert_eq!(root.kind, RealmTreeNodeKind::Realm);
        assert_eq!(child.kind, RealmTreeNodeKind::Space);
    }

    #[test]
    fn sync_projection_marks_schema_space_with_home_realm() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({
                "schema": "ak.schema.realm.v1",
                "summary": {"title": "Root"}
            }),
        );
        spaces.insert(
            "ak:space:child".to_owned(),
            json!({
                "schema": "ak.schema.space.v1",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {"title": "Child"}
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);
        let child = previews
            .iter()
            .find(|node| node.id == "ak:space:child")
            .expect("child preview");

        assert_eq!(child.kind, RealmTreeNodeKind::Space);
        assert_eq!(
            child.realm_id,
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
        assert_eq!(child.parent_space_id, None);

        let items = realm_tree_items(&previews);
        let child_item = items
            .iter()
            .find(|item| item.node.id == "ak:space:child")
            .expect("child tree item");
        assert_eq!(child_item.depth, 1);
    }

    #[test]
    fn sync_projection_filters_strand_entries_out_of_realm_tree() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({
                "schema": "ak.schema.realm.v1",
                "summary": {
                    "title": "Root",
                    "summary": "Root Realm"
                }
            }),
        );
        spaces.insert(
            "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU".to_owned(),
            json!({
                "strand_id": "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU",
                "summary": {
                    "title": "Should not be a node"
                }
            }),
        );
        spaces.insert(
            "ak:space:strand-projection".to_owned(),
            json!({
                "strand_id": "ak:strand:AHJT0IVSFPGYRqWgOGcbtadQgIfN5QfHj6vRKazew2F8",
                "summary": {
                    "title": "Strand projection",
                    "category": "discussion"
                }
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].id,
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"
        );
    }

    /// Regression: soland inlines the primary strand under `summary.strand`
    /// for legitimate Spaces (so the client can render the room title
    /// without joining a separate fanout). A previous filter treated
    /// any `summary.strand` as a strand-as-tree-node projection and dropped the
    /// Space from the sidebar entirely. Only top-level `strand*`/`tracks`
    /// or a strand-shaped `summary.category` should reject a `ak:space:`.
    #[test]
    fn sync_projection_keeps_real_space_with_inlined_primary_strand() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:space:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j".to_owned(),
            json!({
                "ephemeral": [],
                "realm_id": "ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
                "strands": [{
                    "strand_id": "ak:strand:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
                    "title": "Arkret Demo Realm",
                }],
                "summary": {
                    "category": "collaboration",
                    "title": "Arkret Demo Realm",
                    "summary": "Shared demo Space served by soland",
                    "tags": ["demo"],
                    "strand": {
                        "strand_id": "ak:strand:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j",
                        "title": "Arkret Demo Realm",
                        "tracks": { "discussion": { "enabled": true } },
                    },
                },
                "timeline": { "events": [], "limited": false },
                "unread": { "highlight_count": 0, "notification_count": 0 },
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].id,
            "ak:space:AcbFC8Nil95DfV11kMMMvRtzRdEC3g-tFtBE8_VQQ74j"
        );
        assert_eq!(previews[0].title, "Arkret Demo Realm");
        assert_eq!(previews[0].category.as_deref(), Some("collaboration"));
    }

    #[test]
    fn sync_projection_keeps_realm_ids_from_account_subscribe() {
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:realm:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE".to_owned(),
            json!({
                "bottom_cells": [],
                "ephemeral": [],
                "strands": [{
                    "strand_id": "ak:strand:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE",
                    "kind": "discussion",
                    "title": "Test"
                }],
                "state": [],
                "state_after": {
                    "events": [{
                        "strand_id": "ak:strand:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE",
                        "kind": "discussion",
                        "title": "Test"
                    }]
                },
                "summary": {
                    "category": null,
                    "strand": {
                        "strand_id": "ak:strand:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE",
                        "kind": "discussion",
                        "title": "Test"
                    },
                    "summary": null,
                    "tags": [],
                    "title": "Test"
                },
                "timeline": {"events": [], "limited": false},
                "unread": {"highlight_count": 0, "notification_count": 0}
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(
            previews[0].id,
            "ak:realm:ARDR2oN-Bh8J55KxFHM6s_izSsUg0-1gh3XfOjfjJ9HE"
        );
        assert_eq!(previews[0].title, "Test");
        assert_eq!(previews[0].kind, RealmTreeNodeKind::Realm);
    }

    #[test]
    fn full_sync_keep_set_preserves_local_space_under_joined_realm() {
        let mut server_set = BTreeSet::new();
        server_set.insert("ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned());

        let mut cached = BTreeMap::new();
        cached.insert(
            "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY".to_owned(),
            json!({"summary": {"title": "Root"}}),
        );
        cached.insert(
            "ak:space:child".to_owned(),
            json!({
                "__kind": "space",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {"title": "Child"}
            }),
        );
        cached.insert(
            "ak:space:stale".to_owned(),
            json!({
                "__kind": "space",
                "realm_id": "ak:realm:ARqzW2I_OXIxwHkOIvi8k8VhtCj9leT2DmU_Ul-1pvdM",
                "summary": {"title": "Stale"}
            }),
        );

        let keep = full_sync_projection_keep_set(&server_set, &cached);

        assert!(keep.contains("ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY"));
        assert!(keep.contains("ak:space:child"));
        assert!(!keep.contains("ak:space:stale"));
    }

    #[test]
    fn full_sync_keep_set_preserves_acknowledged_optimistic_realm() {
        let server_set =
            BTreeSet::from(["ak:realm:APCEv_eZJS-G3Rl9hDcbEIFNJxcYpqP2nkoGb6FOPmVc".to_owned()]);
        let cached = BTreeMap::from([
            (
                "ak:realm:ADcY1l6arU8aWTG833dzn0XOnraiPVcEnyYyorj3d24Q".to_owned(),
                json!({
                    "__kind": "realm",
                    "content_scheme": "mls_exporter_aead_v1",
                    "history_access": "all_history_for_current_members"
                }),
            ),
            (
                "ak:realm:AJIK0c_n94vFOvyinK1wQTDDmt5QyZdwqgEiYhO3X-RI".to_owned(),
                json!({"summary": {"title": "Stale authoritative projection"}}),
            ),
        ]);

        let keep = full_sync_projection_keep_set(&server_set, &cached);

        assert!(keep.contains("ak:realm:APCEv_eZJS-G3Rl9hDcbEIFNJxcYpqP2nkoGb6FOPmVc"));
        assert!(keep.contains("ak:realm:ADcY1l6arU8aWTG833dzn0XOnraiPVcEnyYyorj3d24Q"));
        assert!(!keep.contains("ak:realm:AJIK0c_n94vFOvyinK1wQTDDmt5QyZdwqgEiYhO3X-RI"));
    }

    #[test]
    fn realm_tree_nodes_from_sync_realms_filters_strand_like_projections() {
        // The sync engine relies on `realm_tree_nodes_from_sync_realms`
        // (rather than the retired client-side merge filter) to keep
        // strand-like projections out of the sidebar — verify that here.
        let mut spaces = BTreeMap::new();
        spaces.insert(
            "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU".to_owned(),
            json!({
                "strand_id": "ak:strand:AsLgUd73PSI9_dWVG49ZfkmPc0yCUf4zdrfGlSidlNnU",
                "summary": {"title": "Discussion", "category": "discussion"}
            }),
        );
        spaces.insert(
            "ak:space:real".to_owned(),
            json!({
                "schema": "ak.schema.space.v1",
                "realm_id": "ak:realm:AF1tN8pT6JU9QaRZjiH8Ax0gutpLcVCArGxc-0fzdavY",
                "summary": {"title": "Real Space"}
            }),
        );

        let previews = realm_tree_nodes_from_sync_realms(&spaces);

        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0].id, "ak:space:real");
    }
}
