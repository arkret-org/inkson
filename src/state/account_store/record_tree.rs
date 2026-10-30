//! A persistent binary Patricia tree authenticates the complete record set.
//! Only the root hash is stored: hydration rebuilds it from bounded KV pages.
//! An update hashes at most 256 branches and shares every unaffected subtree.
use std::sync::Arc;

#[derive(Clone, Default)]
pub(super) struct Tree(Option<Arc<Node>>);
struct Node {
    digest: [u8; 32],
    value: NodeValue,
}
enum NodeValue {
    Leaf {
        key: [u8; 32],
    },
    Branch {
        bit: u16,
        left: Arc<Node>,
        right: Arc<Node>,
    },
}
fn hash(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(field);
    }
    arkret_sdk::canonical::sha256_bytes(bytes)
}
fn right(key: &[u8; 32], bit: u16) -> bool {
    key[bit as usize / 8] & (0x80 >> (bit % 8)) != 0
}
fn leaf(key: [u8; 32], value: [u8; 32]) -> Arc<Node> {
    Arc::new(Node {
        digest: hash(b"inkson.account.v1/leaf\0", &[&key, &value]),
        value: NodeValue::Leaf { key },
    })
}
fn branch(bit: u16, left: Arc<Node>, right: Arc<Node>) -> Arc<Node> {
    Arc::new(Node {
        digest: hash(
            b"inkson.account.v1/branch\0",
            &[&bit.to_be_bytes(), &left.digest, &right.digest],
        ),
        value: NodeValue::Branch { bit, left, right },
    })
}
fn found_key(mut node: &Node, key: &[u8; 32]) -> [u8; 32] {
    loop {
        match &node.value {
            NodeValue::Leaf { key, .. } => return *key,
            NodeValue::Branch {
                bit,
                left,
                right: child,
            } => {
                node = if right(key, *bit) { child } else { left };
            }
        }
    }
}
fn first_difference(a: &[u8; 32], b: &[u8; 32]) -> u16 {
    for (index, (a, b)) in a.iter().zip(b).enumerate() {
        let different = a ^ b;
        if different != 0 {
            return index as u16 * 8 + different.leading_zeros() as u16;
        }
    }
    unreachable!("different record keys must differ in one bit")
}
fn add_at(node: Arc<Node>, new: Arc<Node>, key: &[u8; 32], at: u16) -> Arc<Node> {
    if let NodeValue::Branch {
        bit,
        left,
        right: child,
    } = &node.value
        && *bit < at
    {
        return if right(key, *bit) {
            branch(*bit, left.clone(), add_at(child.clone(), new, key, at))
        } else {
            branch(*bit, add_at(left.clone(), new, key, at), child.clone())
        };
    }
    if right(key, at) {
        branch(at, node, new)
    } else {
        branch(at, new, node)
    }
}
fn replace(node: Arc<Node>, key: &[u8; 32], value: Option<[u8; 32]>) -> Option<Arc<Node>> {
    match &node.value {
        NodeValue::Leaf { key: current, .. } => {
            if current == key {
                value.map(|value| leaf(*key, value))
            } else {
                Some(node)
            }
        }
        NodeValue::Branch {
            bit,
            left,
            right: child,
        } => {
            if right(key, *bit) {
                Some(match replace(child.clone(), key, value) {
                    Some(child) => branch(*bit, left.clone(), child),
                    None => left.clone(),
                })
            } else {
                Some(match replace(left.clone(), key, value) {
                    Some(left) => branch(*bit, left, child.clone()),
                    None => child.clone(),
                })
            }
        }
    }
}
impl Tree {
    pub(super) fn set(&mut self, key: [u8; 32], value: Option<[u8; 32]>) {
        self.0 = match self.0.take() {
            None => value.map(|value| leaf(key, value)),
            Some(node) => {
                let existing = found_key(&node, &key);
                if let Some(value) = value
                    && existing != key
                {
                    Some(add_at(
                        node,
                        leaf(key, value),
                        &key,
                        first_difference(&existing, &key),
                    ))
                } else {
                    replace(node, &key, value)
                }
            }
        };
    }
    pub(super) fn digest(&self) -> String {
        hex::encode(self.0.as_ref().map_or_else(
            || hash(b"inkson.account.v1/empty\0", &[]),
            |node| node.digest,
        ))
    }
}
impl std::fmt::Debug for Tree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("AccountRecordTree")
            .field(&self.digest())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_root_is_independent_of_insertion_order_and_old_cuts_remain_immutable() {
        let keys = (0u32..1000)
            .map(|i| arkret_sdk::canonical::sha256_bytes(i.to_le_bytes()))
            .collect::<Vec<_>>();
        let mut a = Tree::default();
        let mut b = Tree::default();
        for key in &keys {
            a.set(*key, Some(*key));
        }
        for key in keys.iter().rev() {
            b.set(*key, Some(*key));
        }
        assert_eq!(a.digest(), b.digest());
        let original = a.clone();
        for key in keys.iter().step_by(3) {
            a.set(*key, None);
        }
        assert_ne!(a.digest(), original.digest());
        assert_eq!(b.digest(), original.digest());
        for key in keys.iter().step_by(3) {
            a.set(*key, Some(*key));
        }
        assert_eq!(a.digest(), original.digest());
    }
}
