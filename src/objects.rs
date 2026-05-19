//! Yougen-side wrappers for the Contrix object model objects.
//!
//! Re-exports the SDK's canonical types and provides minimal builders that
//! turn them into [`crate::operation::EventEnvelope`] write actions. The
//! goal is a single place for `views/*` to construct `cx.morph.*`,
//! `cx.relation.*`, and `cx.container.*` operations without each call site
//! re-discovering the SDK's struct layout.

pub use contrix_sdk::Morph;
pub use contrix_sdk::{Place, PlaceId, Relation, RelationProfile, SpaceId};

use serde_json::{Value, json};

use crate::operation::OperationBuilder;

/// Build a `cx.morph.create` operation. Body shape mirrors
/// `models/morph.md` §3 (typed Morph object).
pub fn build_morph_create(
    space_id: &str,
    actor: &str,
    morph: &Morph,
) -> anyhow::Result<OperationBuilder> {
    let value = serde_json::to_value(morph)?;
    Ok(OperationBuilder::new(space_id, actor, "cx.morph.create")
        .target_ref(space_id)
        .body(json!({"morph": value})))
}

/// Build a `cx.morph.update` operation. `patch` is a JSON object of fields to
/// set/replace; the reducer applies these against the existing Morph state.
pub fn build_morph_update(
    space_id: &str,
    actor: &str,
    morph_id: &str,
    patch: Value,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.morph.update")
        .target_ref(morph_id)
        .body(json!({"morph_id": morph_id, "patch": patch}))
}

/// Build a `cx.relation.create` operation. `kind` is a registered
/// `relation_kind` (e.g. `cx.relation.parent_of`); `source` and `target` are
/// typed-id strings.
pub fn build_relation_create(
    space_id: &str,
    actor: &str,
    relation_id: &str,
    kind: &str,
    source: &str,
    target: &str,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.relation.create")
        .target_ref(relation_id)
        .body(json!({
            "relation_id": relation_id,
            "kind": kind,
            "source": source,
            "target": target,
        }))
}

/// Build a `cx.relation.delete` operation by id.
pub fn build_relation_delete(space_id: &str, actor: &str, relation_id: &str) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.relation.delete")
        .target_ref(relation_id)
        .body(json!({"relation_id": relation_id}))
}

/// Build a `cx.container.move_item` operation. `parent_place_id` is the
/// containing Place (board / list / container); `item_ref` is the typed-id of
/// the moved object; `rank` is the new ordering rank (`encoding.md` §10.3).
pub fn build_container_move_item(
    space_id: &str,
    actor: &str,
    parent_place_id: &str,
    item_ref: &str,
    rank: &str,
) -> OperationBuilder {
    OperationBuilder::new(space_id, actor, "cx.container.move_item")
        .target_ref(parent_place_id)
        .body(json!({
            "parent_place_id": parent_place_id,
            "item_ref": item_ref,
            "rank": rank,
        }))
}

/// Build a `cx.container.rebalance` operation, batched form of `move_item`.
pub fn build_container_rebalance(
    space_id: &str,
    actor: &str,
    parent_place_id: &str,
    new_order: Vec<(String, String)>,
) -> OperationBuilder {
    let items: Vec<Value> = new_order
        .into_iter()
        .map(|(item_ref, rank)| json!({"item_ref": item_ref, "rank": rank}))
        .collect();
    OperationBuilder::new(space_id, actor, "cx.container.rebalance")
        .target_ref(parent_place_id)
        .body(json!({
            "parent_place_id": parent_place_id,
            "items": items,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn morph_update_emits_canonical_kind() {
        let op = build_morph_update(
            "cx:space:s1",
            "did:web:alice",
            "cx:morph:abc",
            json!({"morph_type": "task"}),
        )
        .build("node");
        assert_eq!(op.kind, "cx.morph.update");
        assert_eq!(op.payload["morph_id"], "cx:morph:abc");
        assert_eq!(op.payload["patch"]["morph_type"], "task");
    }

    #[test]
    fn relation_create_carries_kind_and_endpoints() {
        let op = build_relation_create(
            "cx:space:s1",
            "did:web:alice",
            "cx:relation:r1",
            "cx.relation.parent_of",
            "cx:flow:f1",
            "cx:flow:f2",
        )
        .build("node");
        assert_eq!(op.kind, "cx.relation.create");
        assert_eq!(op.payload["kind"], "cx.relation.parent_of");
        assert_eq!(op.payload["source"], "cx:flow:f1");
        assert_eq!(op.payload["target"], "cx:flow:f2");
    }

    #[test]
    fn container_move_item_targets_parent_place() {
        let op = build_container_move_item(
            "cx:space:s1",
            "did:web:alice",
            "cx:place:list1",
            "cx:flow:f1",
            "r0",
        )
        .build("node");
        assert_eq!(op.kind, "cx.container.move_item");
        assert_eq!(op.local_target_ref(), Some("cx:place:list1"));
        assert_eq!(op.payload["rank"], "r0");
    }

    #[test]
    fn container_rebalance_flattens_items() {
        let op = build_container_rebalance(
            "cx:space:s1",
            "did:web:alice",
            "cx:place:list1",
            vec![
                ("cx:flow:f1".to_owned(), "r0".to_owned()),
                ("cx:flow:f2".to_owned(), "r1".to_owned()),
            ],
        )
        .build("node");
        assert_eq!(op.kind, "cx.container.rebalance");
        assert_eq!(op.payload["items"][0]["item_ref"], "cx:flow:f1");
        assert_eq!(op.payload["items"][1]["rank"], "r1");
    }
}
