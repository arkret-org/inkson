//! Yougen-side wrappers for the Cokret object model objects.
//!
//! Re-exports the SDK's canonical types and provides minimal builders that
//! turn them into [`crate::operation::EventEnvelope`] write actions. The
//! goal is a single place for `views/*` to construct `ck.morph.*`,
//! `ck.relation.*`, and `ck.container.*` operations without each call site
//! re-discovering the SDK's struct layout.

pub use cokret_sdk::{Morph, RealmId, Relation, RelationProfile};
use serde_json::{Value, json};

use crate::operation::OperationBuilder;

/// Build a `ck.morph.create` operation. Body shape mirrors
/// `models/morph.md` §3 (typed Morph object).
pub fn build_morph_create(
    space_id: &str,
    actor: &str,
    morph: &Morph,
) -> anyhow::Result<OperationBuilder> {
    let value = serde_json::to_value(morph)?;
    Ok(OperationBuilder::new(space_id, actor, "ck.morph.create")
        .target_ref(space_id)
        .body(json!({"morph": value})))
}

/// Build a `ck.morph.update` operation. `patch` is a JSON object of fields to
/// set/replace; the reducer applies these against the existing Morph state.
///
/// `ck.morph.update` falls onto the generic `object_patch_payload`
/// (`required:["target_ref","patch"]`, `additionalProperties:false`): the
/// target Morph is single-sourced by `target_ref`, so we do NOT emit a
/// separate `morph_id` field — that would trip the reducer's
/// `schema_violation` gate.
pub fn build_morph_update(
    space_id: &str,
    actor: &str,
    morph_id: &str,
    patch: Value,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "ck.morph.update")
        .target_ref(morph_id)
        .body(json!({"target_ref": morph_id, "patch": patch}))
}

/// Build a `ck.relation.create` operation. `kind` is a registered
/// `relation_kind` (e.g. `ck.relation.parent_of`); `from_ref` and `to_ref` are
/// the typed-id endpoints.
///
/// Body shape follows `relation_create_payload`
/// (`additionalProperties:false`): the legal field set is `relation` |
/// (`kind`,`from_ref`,`to_ref`) | `rank`. The relation id is NOT a payload
/// field — it is routed via the operation's `target_ref`, so we no longer
/// emit a top-level `relation_id`. The previous `source`/`target` names were
/// not in the schema and would have been rejected with `schema_violation`.
pub fn build_relation_create(
    space_id: &str,
    actor: &str,
    relation_id: &str,
    kind: &str,
    from_ref: &str,
    to_ref: &str,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "ck.relation.create")
        .target_ref(relation_id)
        .body(json!({
            "kind": kind,
            "from_ref": from_ref,
            "to_ref": to_ref,
        }))
}

/// Build a `ck.relation.tombstone` operation by id.
pub fn build_relation_delete(space_id: &str, actor: &str, relation_id: &str) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "ck.relation.tombstone")
        .target_ref(relation_id)
        .body(json!({"relation_id": relation_id}))
}

/// Build a `ck.container.move_item` operation. Payload shape mirrors
/// `container_position_payload`: `container_ref`, `source_ref`, `target_ref`,
/// and the new ordering `rank`.
pub fn build_container_move_item(
    space_id: &str,
    actor: &str,
    container_ref: &str,
    source_ref: &str,
    target_ref: &str,
    rank: &str,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "ck.container.move_item")
        .target_ref(container_ref)
        .body(json!({
            "container_ref": container_ref,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "rank": rank,
        }))
}

/// Build a `ck.container.rebalance` operation. The required position fields
/// remain at top level; `items` carries optional profile-specific batch detail.
pub fn build_container_rebalance(
    space_id: &str,
    actor: &str,
    container_ref: &str,
    source_ref: &str,
    target_ref: &str,
    rank: &str,
    new_order: Vec<(String, String)>,
) -> OperationBuilder {
    let items: Vec<Value> = new_order
        .into_iter()
        .map(|(item_ref, rank)| json!({"item_ref": item_ref, "rank": rank}))
        .collect();
    OperationBuilder::new(space_id, actor, "ck.container.rebalance")
        .target_ref(container_ref)
        .body(json!({
            "container_ref": container_ref,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "rank": rank,
            "items": items,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn morph_update_emits_canonical_kind() {
        let op = build_morph_update(
            "ck:space:s1",
            "did:web:alice",
            "ck:morph:abc",
            json!({"morph_type": "task"}),
        )
        .build("node");
        assert_eq!(op.kind, "ck.morph.update");
        assert_eq!(op.payload["target_ref"], "ck:morph:abc");
        assert!(
            op.payload.get("morph_id").is_none(),
            "morph_id is not an object_patch_payload field"
        );
        assert_eq!(op.payload["patch"]["morph_type"], "task");
    }

    #[test]
    fn relation_create_carries_kind_and_endpoints() {
        let op = build_relation_create(
            "ck:space:s1",
            "did:web:alice",
            "ck:relation:r1",
            "ck.relation.parent_of",
            "ck:flow:f1",
            "ck:flow:f2",
        )
        .build("node");
        assert_eq!(op.kind, "ck.relation.create");
        // relation id is routed via target_ref, not a payload field.
        assert_eq!(op.local_target_ref(), Some("ck:relation:r1"));
        assert!(
            op.payload.get("relation_id").is_none(),
            "relation_id is not a relation_create_payload field"
        );
        assert_eq!(op.payload["kind"], "ck.relation.parent_of");
        assert_eq!(op.payload["from_ref"], "ck:flow:f1");
        assert_eq!(op.payload["to_ref"], "ck:flow:f2");
    }

    #[test]
    fn container_move_item_uses_spec_position_payload() {
        let op = build_container_move_item(
            "ck:space:s1",
            "did:web:alice",
            "ck:space:0196419b-0000-7000-8000-000000000001",
            "ck:flow:f1",
            "ck:flow:f1",
            "r0",
        )
        .build("node");
        assert_eq!(op.kind, "ck.container.move_item");
        assert_eq!(
            op.local_target_ref(),
            Some("ck:space:0196419b-0000-7000-8000-000000000001")
        );
        assert_eq!(
            op.payload["container_ref"],
            "ck:space:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(op.payload["source_ref"], "ck:flow:f1");
        assert_eq!(op.payload["target_ref"], "ck:flow:f1");
        assert_eq!(op.payload["rank"], "r0");
    }

    #[test]
    fn container_rebalance_flattens_items() {
        let op = build_container_rebalance(
            "ck:space:s1",
            "did:web:alice",
            "ck:space:0196419b-0000-7000-8000-000000000001",
            "ck:flow:f1",
            "ck:flow:f2",
            "r1",
            vec![
                ("ck:flow:f1".to_owned(), "r0".to_owned()),
                ("ck:flow:f2".to_owned(), "r1".to_owned()),
            ],
        )
        .build("node");
        assert_eq!(op.kind, "ck.container.rebalance");
        assert_eq!(
            op.payload["container_ref"],
            "ck:space:0196419b-0000-7000-8000-000000000001"
        );
        assert_eq!(op.payload["target_ref"], "ck:flow:f2");
        assert_eq!(op.payload["rank"], "r1");
        assert_eq!(op.payload["items"][0]["item_ref"], "ck:flow:f1");
        assert_eq!(op.payload["items"][1]["rank"], "r1");
    }
}
